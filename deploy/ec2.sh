#!/usr/bin/env bash
# Host the control plane on one EC2 instance, behind Caddy with HTTPS.
#
#   deploy/ec2.sh create     launch the instance once: key pair, security group, Elastic IP
#   deploy/ec2.sh deploy     copy this working tree to it and (re)build the stack, with its
#                            signing key in AWS KMS and secrets in AWS Secrets Manager
#                            (created the first time)
#   deploy/ec2.sh status     instance state and the public URL
#   deploy/ec2.sh ssh        open a shell on the instance
#   deploy/ec2.sh stop       stop it between reviews (the URL stays the same)
#   deploy/ec2.sh start      start it again and load the model
#   deploy/ec2.sh destroy    terminate it and delete everything `create` made
#
# Uses the AWS CLI's normal credentials, so set AWS_PROFILE to choose an account.
# The audit log is signed in AWS KMS with alias/scp-demo-audit, an Ed25519 key that never
# leaves KMS. Every other secret lives in AWS Secrets Manager under scp-demo/: the HMAC
# key, the admin token, and an Anthropic API key if you store one there. The instance
# uses them with its own role, which can sign with that key, read those secrets, and
# nothing else.
# The site is served at the host names in deploy/ec2.env, if any, and always at
# <public-ip>.sslip.io, a public DNS name that resolves to that IP, so it works before
# any domain is set up. Caddy gets an HTTPS certificate for each name.
set -euo pipefail

NAME=scp-demo
REGION=${AWS_REGION:-eu-north-1}
# The free-tier eligible type with room for the model (2.9 GB loaded), the app and image
# builds; the next one down has 4 GB. On a paid plan, SCP_INSTANCE_TYPE=c7g.xlarge
# (4 vCPU, ARM) answers about twice as fast.
INSTANCE_TYPE=${SCP_INSTANCE_TYPE:-m7i-flex.large}
DISK_GB=40
KEY_FILE=${SCP_KEY_FILE:-$HOME/.ssh/$NAME.pem}
REMOTE_DIR=sovereign-control-plane
SECRETS_PREFIX="$NAME/"
# Also set in deploy/docker-compose.ec2.yml, where the control plane reads it.
KMS_ALIAS="alias/$NAME-audit"
COMPOSE="docker compose -f docker-compose.yml -f deploy/docker-compose.ec2.yml"
ROOT=$(cd "$(dirname "$0")/.." && pwd)

if [[ -f $ROOT/deploy/ec2.env ]]; then
  # shellcheck source=/dev/null
  source "$ROOT/deploy/ec2.env"
fi
DOMAINS=${SCP_DOMAINS:-}

aws() { command aws --region "$REGION" "$@"; }
log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# retry <tries> <command...>: run every 5 seconds until it succeeds, or give up.
retry() {
  local tries=$1
  shift
  for ((i = 0; i < tries; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 5
  done
  return 1
}

instance_id() {
  aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$NAME" \
    "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[0].InstanceId' --output text
}

elastic_ip() {
  aws ec2 describe-addresses --filters "Name=tag:Name,Values=$NAME" \
    --query 'Addresses[0].PublicIp' --output text
}

host_name() {
  local ip
  ip=$(elastic_ip)
  [[ $ip != None && -n $ip ]] || die "no Elastic IP tagged $NAME; run create first"
  echo "${ip//./-}.sslip.io"
}

# The name to show and check: the first own domain, or else the sslip.io name.
primary_host() {
  if [[ -n $DOMAINS ]]; then echo "${DOMAINS%% *}"; else host_name; fi
}

# Every name Caddy serves. The sslip.io name stays, so links sent before a domain was
# added keep working.
site_address() {
  local names
  names="$DOMAINS $(host_name)"
  names=${names# }
  echo "${names// /, }"
}

# Caddy's certificate request fails for a name that does not point here, and repeated
# failures are rate-limited by the certificate authority, so check before deploying.
check_dns() {
  local ip name
  ip=$(elastic_ip)
  for name in $DOMAINS; do
    # Resolved from the root servers, not a caching resolver, so a stale record cached
    # before the A record was added does not block the deploy. The root servers are asked
    # of 1.1.1.1, because some routers' resolvers return none and the trace stops there.
    dig +trace +nodnssec @1.1.1.1 "$name" A | awk '$4 == "A" {print $5}' | grep -qx "$ip" ||
      die "$name does not resolve to $ip yet; add a DNS A record, or remove it from deploy/ec2.env"
  done
}

ssh_to() {
  ssh -i "$KEY_FILE" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
    "ubuntu@$(elastic_ip)" "$@"
}

create() {
  [[ $(instance_id) == None || -z $(instance_id) ]] || die "an instance tagged $NAME already exists"

  if [[ ! -f $KEY_FILE ]]; then
    log "creating key pair $NAME (private key: $KEY_FILE)"
    mkdir -p "$(dirname "$KEY_FILE")"
    aws ec2 create-key-pair --key-name "$NAME" --key-type ed25519 \
      --tag-specifications "ResourceType=key-pair,Tags=[{Key=Name,Value=$NAME}]" \
      --query KeyMaterial --output text >"$KEY_FILE"
    chmod 400 "$KEY_FILE"
  fi

  local vpc sg my_ip ami root_device
  vpc=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true \
    --query 'Vpcs[0].VpcId' --output text)
  sg=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=$NAME" "Name=vpc-id,Values=$vpc" \
    --query 'SecurityGroups[0].GroupId' --output text)
  if [[ $sg == None ]]; then
    log "creating security group $NAME in $vpc"
    sg=$(aws ec2 create-security-group --group-name "$NAME" --vpc-id "$vpc" \
      --description "sovereign control plane demo: HTTPS for everyone, SSH for the operator" \
      --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=$NAME}]" \
      --query GroupId --output text)
    my_ip=$(curl -fsS https://checkip.amazonaws.com)
    aws ec2 authorize-security-group-ingress --group-id "$sg" \
      --ip-permissions \
      "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$my_ip/32,Description=operator}]" \
      "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0,Description=http-redirect-and-acme}]" \
      "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0,Description=https}]" \
      >/dev/null
  fi

  # The latest Ubuntu 24.04 image for the instance's CPU architecture.
  local arch
  arch=$(aws ec2 describe-instance-types --instance-types "$INSTANCE_TYPE" \
    --query 'InstanceTypes[0].ProcessorInfo.SupportedArchitectures[0]' --output text)
  if [[ $arch == x86_64 ]]; then arch=amd64; fi
  ami=$(aws ec2 describe-images --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-$arch-server-*" \
    Name=state,Values=available \
    --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)
  root_device=$(aws ec2 describe-images --image-ids "$ami" \
    --query 'Images[0].RootDeviceName' --output text)

  log "launching $INSTANCE_TYPE from $ami"
  local id
  id=$(aws ec2 run-instances --image-id "$ami" --instance-type "$INSTANCE_TYPE" \
    --key-name "$NAME" --security-group-ids "$sg" \
    --block-device-mappings \
    "DeviceName=$root_device,Ebs={VolumeSize=$DISK_GB,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}" \
    --metadata-options HttpTokens=required,HttpEndpoint=enabled,HttpPutResponseHopLimit=2 \
    --user-data "file://$ROOT/deploy/ec2-user-data.sh" \
    --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
    "ResourceType=volume,Tags=[{Key=Name,Value=$NAME}]" \
    --query 'Instances[0].InstanceId' --output text)
  aws ec2 wait instance-running --instance-ids "$id"

  # A fixed address, so the URL survives a stop and start.
  local alloc
  alloc=$(aws ec2 allocate-address --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=$NAME}]" \
    --query AllocationId --output text)
  aws ec2 associate-address --instance-id "$id" --allocation-id "$alloc" >/dev/null
  log "instance $id is running at $(elastic_ip)"
  log "next: deploy/ec2.sh deploy"
}

deploy() {
  check_dns
  local host site
  host=$(primary_host)
  site=$(site_address)
  log "waiting for SSH and Docker on $(elastic_ip)"
  retry 120 ssh_to 'cloud-init status --wait && docker compose version' ||
    die "the instance did not become ready within 10 minutes"

  log "copying the working tree"
  # Never copied: local secrets (.env), local audit data and keys, build output. The
  # server's own .env, which holds only the host names, is excluded so it is kept.
  rsync -az --delete -e "ssh -i $KEY_FILE -o StrictHostKeyChecking=accept-new" \
    --exclude .git --exclude .env --exclude data --exclude .venv \
    --exclude .playwright-mcp --exclude ui/node_modules --exclude ui/dist \
    --exclude __pycache__ --exclude .pytest_cache --exclude .ruff_cache \
    --exclude '*.egg-info' --exclude .DS_Store \
    "$ROOT/" "ubuntu@$(elastic_ip):$REMOTE_DIR/"

  ssh_to "cat >$REMOTE_DIR/.env" <<<"SITE_ADDRESS=\"$site\"
AWS_REGION=$REGION"

  local key_arn
  # Assigned on its own line, so a failed lookup stops the deploy under `set -e`.
  key_arn=$(ensure_kms_key)
  ensure_instance_role "$key_arn"
  log "building the image"
  ssh_to "cd $REMOTE_DIR && sudo $COMPOSE build control-plane"
  ensure_secrets

  log "building and starting the stack for: $site"
  ssh_to "cd $REMOTE_DIR && sudo $COMPOSE up -d --build --remove-orphans"

  wait_and_warm_up "$host"
  remove_key_files
}

# The instance's role: it can sign with the audit key, read this deployment's secrets, and
# nothing else.
ensure_instance_role() {
  local key_arn=$1 id account
  id=$(instance_id)
  account=$(aws sts get-caller-identity --query Account --output text)
  if ! aws iam get-role --role-name "$NAME" >/dev/null 2>&1; then
    log "creating role $NAME"
    aws iam create-role --role-name "$NAME" --tags "Key=Name,Value=$NAME" \
      --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
      >/dev/null
  fi
  aws iam put-role-policy --role-name "$NAME" --policy-name read-secrets --policy-document \
    "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"secretsmanager:GetSecretValue\",\"Resource\":\"arn:aws:secretsmanager:$REGION:$account:secret:$SECRETS_PREFIX*\"}]}"
  aws iam put-role-policy --role-name "$NAME" --policy-name sign-audit-log --policy-document \
    "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:Sign\",\"kms:GetPublicKey\"],\"Resource\":\"$key_arn\"}]}"
  if ! aws iam get-instance-profile --instance-profile-name "$NAME" >/dev/null 2>&1; then
    aws iam create-instance-profile --instance-profile-name "$NAME" >/dev/null
    aws iam add-role-to-instance-profile --instance-profile-name "$NAME" --role-name "$NAME"
  fi
  if [[ $(aws ec2 describe-iam-instance-profile-associations \
    --filters "Name=instance-id,Values=$id" "Name=state,Values=associated" \
    --query 'IamInstanceProfileAssociations[0].AssociationId' --output text) == None ]]; then
    log "giving instance $id the role $NAME"
    # A new instance profile takes a few seconds before it can be used.
    retry 24 aws ec2 associate-iam-instance-profile --instance-id "$id" \
      --iam-instance-profile "Name=$NAME" || die "could not give the instance its role"
  fi
  # The containers reach the role's credentials through IMDSv2, one network hop further.
  aws ec2 modify-instance-metadata-options --instance-id "$id" --http-tokens required \
    --http-endpoint enabled --http-put-response-hop-limit 2 >/dev/null
}

# The audit log's signing key, created once. Prints its ARN. Its private half never
# leaves KMS; the control plane reads the public half at startup.
ensure_kms_key() {
  local arn
  if arn=$(aws kms describe-key --key-id "$KMS_ALIAS" --query KeyMetadata.Arn --output text 2>&1); then
    printf '%s' "$arn"
    return 0
  fi
  # Anything but "not found" (no permission, no network) must not create a second key.
  [[ $arn == *NotFoundException* ]] || die "could not look up $KMS_ALIAS: $arn"
  log "creating the audit signing key $KMS_ALIAS in AWS KMS"
  arn=$(aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY \
    --description "$NAME audit log signing key" --query KeyMetadata.Arn --output text)
  aws kms create-alias --alias-name "$KMS_ALIAS" --target-key-id "$arn"
  printf '%s' "$arn"
}

# Each secret is created once. The HMAC key comes from the server's data volume if it
# has one, so earlier records keep their meaning. An existing secret is never overwritten
# here; change one in Secrets Manager, then deploy.
ensure_secrets() {
  ensure_secret admin-token new_token
  ensure_secret evidence-hmac-key export_key hmac
}

ensure_secret() {
  local name=$SECRETS_PREFIX$1 value
  shift
  aws secretsmanager describe-secret --secret-id "$name" >/dev/null 2>&1 && return 0
  log "creating secret $name"
  value=$("$@") || die "could not produce a value for $name"
  [[ -n $value ]] || die "empty value for $name"
  # printf is a shell builtin, so the value never appears in a process list.
  printf '%s' "$value" | aws secretsmanager create-secret --name "$name" \
    --secret-string file:///dev/stdin --tags "Key=Name,Value=$NAME" >/dev/null
}

new_token() { openssl rand -base64 32 | tr -d '\n'; }

# The key on the server's data volume, or a new one, printed by the control plane's image.
export_key() {
  ssh_to "cd $REMOTE_DIR && sudo $COMPOSE run --rm --no-deps -T control-plane \
    python -m control_plane.audit.keys export $1 --data-dir /app/data"
}

# Once the stack runs on KMS and the secrets, the private keys leave the server's disk.
# The HMAC key is compared first, so nothing is deleted that Secrets Manager does not hold.
remove_key_files() {
  local on_server stored
  on_server=$(ssh_to "cd $REMOTE_DIR && sudo $COMPOSE exec -T control-plane sh -c \
    'test -f data/keys/evidence_hmac.key && base64 -w0 data/keys/evidence_hmac.key || true'")
  stored=$(aws secretsmanager get-secret-value --secret-id "${SECRETS_PREFIX}evidence-hmac-key" \
    --query SecretString --output text)
  if [[ -n $on_server && $on_server != "$stored" ]]; then
    die "the HMAC key in Secrets Manager differs from the server's; no key file removed"
  fi
  ssh_to "cd $REMOTE_DIR && sudo $COMPOSE exec -T control-plane \
    rm -f data/keys/audit_signing.key data/keys/evidence_hmac.key"
  log "the server holds no private key: signing is in KMS, the HMAC key in Secrets Manager"
}

# Wait for the stack, then load the model so the first prompt is not slow.
wait_and_warm_up() {
  local host=$1
  log "waiting for https://$host/healthz"
  retry 120 curl -fsS --max-time 10 "https://$host/healthz" ||
    die "no healthy answer over HTTPS within 10 minutes; see: deploy/ec2.sh ssh"
  log "loading the model into memory (waits for the first download)"
  ssh_to "cd $REMOTE_DIR && sudo $COMPOSE exec -T control-plane python scripts/warm_model.py"
  log "up: https://$host"
}

start() {
  local id
  id=$(instance_id)
  aws ec2 start-instances --instance-ids "$id" >/dev/null
  aws ec2 wait instance-running --instance-ids "$id"
  wait_and_warm_up "$(primary_host)"
}

status() {
  local id
  id=$(instance_id)
  [[ $id != None && -n $id ]] || { echo "no instance tagged $NAME"; return; }
  aws ec2 describe-instances --instance-ids "$id" \
    --query 'Reservations[0].Instances[0].[InstanceId,InstanceType,State.Name]' --output text
  echo "https://$(primary_host)"
  [[ -z $DOMAINS ]] || echo "https://$(host_name)"
}

destroy() {
  read -r -p "Terminate $NAME, delete its Elastic IP, security group and key pair, and schedule its audit signing key for deletion? Type $NAME: " answer
  [[ $answer == "$NAME" ]] || die "not confirmed"
  local id alloc
  id=$(instance_id)
  if [[ $id != None && -n $id ]]; then
    aws ec2 terminate-instances --instance-ids "$id" >/dev/null
    aws ec2 wait instance-terminated --instance-ids "$id"
  fi
  alloc=$(aws ec2 describe-addresses --filters "Name=tag:Name,Values=$NAME" \
    --query 'Addresses[0].AllocationId' --output text)
  [[ $alloc == None ]] || aws ec2 release-address --allocation-id "$alloc"
  aws ec2 delete-security-group --group-name "$NAME" || true
  aws ec2 delete-key-pair --key-name "$NAME" || true
  rm -f "$KEY_FILE"
  local key
  if key=$(aws kms describe-key --key-id "$KMS_ALIAS" --query KeyMetadata.KeyId --output text 2>/dev/null); then
    aws kms delete-alias --alias-name "$KMS_ALIAS"
    # The longest wait KMS allows. Verifying old logs needs only the public key.
    aws kms schedule-key-deletion --key-id "$key" --pending-window-in-days 30 >/dev/null
    log "the audit signing key is deleted in 30 days; aws kms cancel-key-deletion undoes it"
  fi
  log "destroyed"
}

case "${1:-}" in
  create) create ;;
  deploy) deploy ;;
  status) status ;;
  ssh) shift; ssh_to "$@" ;;
  stop) aws ec2 stop-instances --instance-ids "$(instance_id)" >/dev/null && log "stopping" ;;
  start) start ;;
  destroy) destroy ;;
  *) sed -n '2,/^set -euo pipefail$/{/^#/p;}' "$0"; exit 1 ;;
esac
