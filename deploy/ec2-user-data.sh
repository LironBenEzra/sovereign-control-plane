#!/bin/bash
# Runs once, as root, when the EC2 instance first boots (cloud-init user data).
set -euxo pipefail

# Swap as headroom for the model, the app and image builds in 8 GB of memory.
fallocate -l 4G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >>/etc/fstab

# Docker Engine with the Compose and Buildx plugins, from Docker's own install script.
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu
