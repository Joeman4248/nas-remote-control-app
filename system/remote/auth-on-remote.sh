#!/bin/bash
# Move the Authelia login from auth.joe-nas.net to remote.joe-nas.net/auth, so the
# iPhone home-screen app never leaves its own origin (iOS shows browser buttons
# for any other address and keeps them after the login).
#
#   sudo bash auth-on-remote.sh            # dry run: shows both diffs
#   sudo bash auth-on-remote.sh --apply
#
# The passkey is tied to the login's address, so it must be registered again
# afterwards (steps printed at the end).
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
CFG=/opt/docker/compose/authelia/config
AUTHELIA_IMAGE=authelia/authelia:4.39.28
BACKUP=/home/claude/backups/$(date +%Y%m%d-%H%M)-auth-on-remote
APPLY=0; [ "${1:-}" = --apply ] && APPLY=1

[ "$(id -u)" -eq 0 ] || { echo "run it with sudo" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
compose() {  # compose <stack> <args...>, with OMV's env files
  d=/opt/docker/compose/$1; shift
  set -- -f "$d/$(basename "$d").yml" --project-directory "$d" --env-file /opt/docker/compose/global.env "$@"
  [ -s "$d/$(basename "$d").env" ] && set -- --env-file "$d/$(basename "$d").env" "$@"
  docker compose "$@"
}

step "1. Authelia config"
diff -u "$CFG/configuration.yml" "$REPO/remote/authelia-configuration.yml" || true
docker run --rm -v "$REPO/remote/authelia-configuration.yml:/config/configuration.yml:ro" -v "$CFG/secrets:/config/secrets:ro" \
  -e AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=/config/secrets/jwt \
  -e AUTHELIA_SESSION_SECRET_FILE=/config/secrets/session \
  -e AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=/config/secrets/storage \
  "$AUTHELIA_IMAGE" authelia validate-config --config /config/configuration.yml

step "2. Caddy"
python3 "$REPO/remote/caddy-add-remote.py" "$BACKUP" --auth-on-remote $([ $APPLY = 1 ] && echo --apply)

[ $APPLY = 1 ] || { printf '\n(dry run: pass --apply to install)\n'; exit 0; }

step "3. install and restart"
install -d -m 0700 -o root -g root "$BACKUP"
install -m 0600 -o root -g root "$CFG/configuration.yml" "$BACKUP/authelia-configuration.yml"
install -m 0600 -o root -g root "$REPO/remote/authelia-configuration.yml" "$CFG/configuration.yml"
compose authelia up -d --force-recreate
compose caddy up -d --force-recreate
sleep 5
docker logs --since 30s authelia 2>&1 | grep -i 'level=error' && echo "Authelia logged errors" >&2 || true
docker logs --since 30s caddy 2>&1 | grep -i '"level":"error"' && echo "Caddy logged errors" >&2 || true
code=$(curl -s -o /dev/null -w '%{http_code}' --resolve remote.joe-nas.net:443:127.0.0.1 https://remote.joe-nas.net/auth/api/health)
echo "remote.joe-nas.net/auth/api/health: $code (want 200)"
echo "old files backed up in $BACKUP"

step "done"
cat <<EOF
Next, on the iPhone:
  1. Open https://remote.joe-nas.net, sign in as joseph with the Authelia
     password (Bitwarden), then Register a passkey. The one-time code:
       sudo tail -n 20 $CFG/notification.txt
  2. Delete the old auth.joe-nas.net passkey from Bitwarden.
EOF
