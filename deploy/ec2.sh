#!/usr/bin/env bash
# Host the control plane on one EC2 instance, behind Caddy with HTTPS.
#
#   deploy/ec2.sh create     launch the instance once: key pair, security group, Elastic IP
#   deploy/ec2.sh deploy     copy this working tree to it and (re)build the stack
#   deploy/ec2.sh status     instance state and the public URL
#   deploy/ec2.sh ssh        open a shell on the instance
#   deploy/ec2.sh stop       stop it between reviews (the URL stays the same)
#   deploy/ec2.sh start      start it again and load the model
#   deploy/ec2.sh destroy    terminate it and delete everything `create` made
#
# Uses the AWS CLI's normal credentials, so set AWS_PROFILE to choose an account.
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
    # before the A record was added does not block the deploy.
    dig +trace +nodnssec "$name" A | awk '$4 == "A" {print $5}' | grep -qx "$ip" ||
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
    --metadata-options HttpTokens=required,HttpEndpoint=enabled \
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

  log "building and starting the stack for: $site"
  ssh_to "cat >$REMOTE_DIR/.env" <<<"SITE_ADDRESS=\"$site\""
  ssh_to "cd $REMOTE_DIR && sudo $COMPOSE up -d --build --remove-orphans"

  wait_and_warm_up "$host"
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
  read -r -p "Terminate $NAME and delete its Elastic IP, security group and key pair? Type $NAME: " answer
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
  *) sed -n '2,13p' "$0"; exit 1 ;;
esac
