#!/bin/sh
# One-time setup for the web remote (remote.joe-nas.net) and its passkey login
# (remote.joe-nas.net/auth). Run as joseph:  sudo sh /home/claude/nas/system/remote/setup.sh
#
# In order, stopping at the first error:
#   1. nasremote user + its sudoers allowlist (checked with visudo)
#   2. the firewall rule that keeps claude off the remote's port, then the service
#   3. Authelia: OMV compose file, secrets, config and your user, all in a
#      folder claude can't read; prints a password for your Bitwarden once
#   4. builds and installs the remote (nas-remote-update: you review the code)
#   5. adds both sites to Caddy and starts everything
# Safe to run again: steps already done are skipped.
set -eu

REPO=/home/claude/nas/system
AUTHELIA_IMAGE=authelia/authelia:4.39.28
CFG=/opt/docker/compose/authelia/config
BACKUP=/mnt/storage/backup/remote-setup-$(date +%Y%m%d-%H%M)

[ "$(id -u)" -eq 0 ] || { echo "run it with sudo" >&2; exit 1; }
[ -x /var/lib/nasbuild/.cargo/bin/cargo ] || { echo "nasbuild has no Rust yet (see the earlier rustup step)" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
compose() {  # compose <stack> <args...>, with OMV's env files
  d=/opt/docker/compose/$1; shift
  set -- -f "$d/$(basename "$d").yml" --project-directory "$d" --env-file /opt/docker/compose/global.env "$@"
  [ -s "$d/$(basename "$d").env" ] && set -- --env-file "$d/$(basename "$d").env" "$@"
  docker compose "$@"
}

step "1. nasremote user and its sudoers allowlist"
id nasremote >/dev/null 2>&1 || adduser --system --group --no-create-home --home /nonexistent nasremote
visudo -cf "$REPO/remote/nas-remote.sudoers"
install -m 0440 -o root -g root "$REPO/remote/nas-remote.sudoers" /etc/sudoers.d/nas-remote

step "2. firewall rule (claude can't reach 127.0.0.1:8765) and services"
install -m 0644 -o root -g root "$REPO/remote/nas-remote-fw.service" "$REPO/remote/nas-remote.service" /etc/systemd/system/
install -m 0755 -o root -g root "$REPO/remote/nas-remote-update" /usr/local/sbin/nas-remote-update
systemctl daemon-reload
systemctl enable --now nas-remote-fw
iptables -C OUTPUT -o lo -p tcp --dport 8765 -m owner --uid-owner claude -j REJECT
echo "rule in place"

step "3. Authelia (passkey login)"
if ! omv-rpc -u admin Compose getFileList '{"start":0,"limit":-1}' | grep -q '"name": *"authelia"'; then
  python3 - "$REPO/remote/authelia.yml" <<'PY'
import json, subprocess, sys
body = open(sys.argv[1]).read()
f = {"uuid": "fa4b1c66-ef79-11e5-87a0-0002b3a176b4", "name": "authelia", "description": "passkey login for remote.joe-nas.net",
     "body": body, "env": "", "override": "", "showenv": False, "showoverride": False}
subprocess.run(["omv-rpc", "-u", "admin", "Compose", "setFile", json.dumps(f)], check=True, capture_output=True)
PY
  echo "OMV compose file 'authelia' created"
fi
install -d -m 0700 -o root -g root "$CFG" "$CFG/secrets"
for s in jwt session storage; do
  [ -s "$CFG/secrets/$s" ] || { openssl rand -hex 64 > "$CFG/secrets/$s"; chmod 600 "$CFG/secrets/$s"; }
done
install -m 0600 -o root -g root "$REPO/remote/authelia-configuration.yml" "$CFG/configuration.yml"
if [ ! -s "$CFG/users.yml" ]; then
  docker pull -q "$AUTHELIA_IMAGE" >/dev/null
  pw=$(openssl rand -base64 30 | tr -d '/+=' | cut -c1-32)
  hash=$(docker run --rm "$AUTHELIA_IMAGE" authelia crypto hash generate argon2 --password "$pw" | sed -n 's/^Digest: //p')
  [ -n "$hash" ] || { echo "couldn't hash the password" >&2; exit 1; }
  cat > "$CFG/users.yml" <<EOF
users:
  joseph:
    displayname: Joseph
    password: '$hash'
    email: joseph@joe-nas.net
EOF
  chmod 600 "$CFG/users.yml"
  printf '\n  Your Authelia password (save it in Bitwarden now, it is not shown again):\n\n      %s\n\n' "$pw"
  printf '  You need it once, to add the passkey. Press Enter when saved. '
  read -r _
fi
docker run --rm -v "$CFG:/config" \
  -e AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=/config/secrets/jwt \
  -e AUTHELIA_SESSION_SECRET_FILE=/config/secrets/session \
  -e AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=/config/secrets/storage \
  "$AUTHELIA_IMAGE" authelia validate-config --config /config/configuration.yml
compose authelia up -d

step "4. build and install the remote (review the code it shows you)"
/usr/local/sbin/nas-remote-update
systemctl enable --now nas-remote

step "5. Caddy: add remote.joe-nas.net (Authelia at /auth)"
mkdir -p "$BACKUP"
if ! omv-rpc -u admin Compose getFile '{"uuid":"2cd0ea95-1cf9-4937-a645-c138ad98091d"}' | grep -q '@remote'; then
  python3 "$REPO/remote/caddy-add-remote.py" "$BACKUP" --apply
fi
compose caddy up -d --force-recreate
sleep 3
if docker logs --since 30s caddy 2>&1 | grep -qi '"level":"error"'; then
  echo "Caddy logged errors; check: sudo docker logs caddy" >&2
fi

step "done"
cat <<EOF
Next:
  1. sudo claude-audit --accept     (new sudoers file and services)
  2. On the iPhone, open https://remote.joe-nas.net, sign in as joseph with the
     password, then Register a passkey. Authelia asks for a one-time code; see it with:
       sudo tail -n 20 $CFG/notification.txt
  3. Open https://remote.joe-nas.net, Share → Add to Home Screen.
EOF
