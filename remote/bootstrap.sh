#!/usr/bin/env bash
# Invoked over SSH using sudo -S; password goes to stdin, never argv or a file.
set -euo pipefail
set +x
umask 077
fail() { printf 'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"%s"}\n' "$1"; exit 1; }
trap 'fail BOOTSTRAP_FAILED' ERR
[[ $EUID == 0 && ($# == 1 || $# == 2) ]] || fail ROOT_INSTALLER_REQUIRED
DEPLOY_USER="$1"
RECOVERY_ROLE="${2:-stack}"
[[ $RECOVERY_ROLE == stack || $RECOVERY_ROLE == infisical ]] || fail INVALID_RECOVERY_ROLE
# sudo consumes a password line only when authentication is required. Framing
# handles both password-required and NOPASSWD, without persisting either input.
IFS= read -r INPUT_HEADER || fail RECOVERY_REQUEST_REQUIRED
if [[ $INPUT_HEADER != STREAMS_INPUT_V1 ]]; then
    IFS= read -r INPUT_HEADER || fail RECOVERY_REQUEST_REQUIRED
fi
[[ $INPUT_HEADER == STREAMS_INPUT_V1 ]] || fail RECOVERY_REQUEST_REQUIRED
unset INPUT_HEADER
IFS= read -r REQUEST_JSON || fail RECOVERY_REQUEST_REQUIRED
[[ ${#REQUEST_JSON} -le 1048576 ]] || fail RECOVERY_REQUEST_TOO_LARGE
[[ $DEPLOY_USER =~ ^[a-z_][a-z0-9_-]*$ ]] || fail INVALID_DEPLOYMENT_USER
[[ $(id -u "$DEPLOY_USER") == 1000 && $(id -g "$DEPLOY_USER") == 1000 ]] || fail DEPLOYMENT_UID_GID_REQUIRED
DEPLOY_HOME=$(getent passwd "$DEPLOY_USER" | cut -d: -f6)
[[ $DEPLOY_HOME =~ ^/[A-Za-z0-9/_-]+$ ]] || fail UNSUPPORTED_HOME
[[ $(uname -m) == x86_64 ]] || fail UBUNTU_AMD64_REQUIRED
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || fail UBUNTU_2404_REQUIRED
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUNNER_HOME="$DEPLOY_HOME/.local/share/streams-aio-recovery"
TARGET_HOME="$DEPLOY_HOME/streams-aio"
ENTRY_POINT=recover.py
if [[ $RECOVERY_ROLE == infisical ]]; then
    RUNNER_HOME="$DEPLOY_HOME/.local/share/streams-aio-infisical-recovery"
    TARGET_HOME=/opt/infisical
    ENTRY_POINT=infisical_server.py
fi
export STREAMS_RECOVERY_USER="$DEPLOY_USER"
python3 "$HERE/probe.py" --fresh --role "$RECOVERY_ROLE" --runner "$RUNNER_HOME" --target "$TARGET_HOME" >/dev/null
exec 9>"$RUNNER_HOME/setup.lock"
flock -n 9 || fail RECOVERY_ALREADY_RUNNING
printf '%s\n' 'RECOVERY_EVENT {"stage":"DEPENDENCIES","status":"RUNNING"}'
apt-get update -qq
apt-get install -y -qq git gh curl ca-certificates python3-venv acl age
if ! command -v docker >/dev/null; then
    for package in docker.io docker-compose docker-compose-v2 podman-docker containerd runc; do
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
            fail CONFLICTING_DOCKER_PACKAGE
        fi
    done
    install -m 0755 -d /etc/apt/keyrings
    curl --fail --silent --show-error --location https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    tee /etc/apt/sources.list.d/docker.sources >/dev/null <<'APT'
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
APT
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
docker compose version >/dev/null || fail COMPOSE_PLUGIN_REQUIRED
getent group docker >/dev/null || fail DOCKER_GROUP_REQUIRED
usermod -aG docker "$DEPLOY_USER"
python3 -m venv "$RUNNER_HOME/venv"
"$RUNNER_HOME/venv/bin/python" -m pip install --quiet -r "$HERE/requirements-new-vm.txt"
printf '%s\n' 'RECOVERY_EVENT {"stage":"DEPENDENCIES","status":"PASS"}'
printf '%s' "$REQUEST_JSON" | "$RUNNER_HOME/venv/bin/python" -B "$HERE/$ENTRY_POINT" \
    --target "$TARGET_HOME" --state-home "$RUNNER_HOME" --config-stdin
unset REQUEST_JSON
