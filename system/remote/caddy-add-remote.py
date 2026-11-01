#!/usr/bin/env python3
"""Add auth.joe-nas.net (Authelia) and remote.joe-nas.net (the web remote,
behind Authelia) to the OMV-managed Caddy compose file, then show the diff.

    caddy-add-remote.py BACKUP_DIR [--apply]

Without --apply it only prints the diff. Changes go through omv-rpc like every
compose edit (hand edits get overwritten by OMV); recreate the caddy stack
afterwards for them to take effect.
"""
import difflib
import json
import os
import subprocess
import sys

UUID = "2cd0ea95-1cf9-4937-a645-c138ad98091d"  # OMV compose file "caddy"

MATCHERS = """\
        @auth      host auth.joe-nas.net
        @remote    host remote.joe-nas.net
"""

# route keeps the written order: strip any client-sent identity headers first,
# then ask Authelia, which sets Remote-User only after a passkey login.
HANDLES = """\
        handle @auth {
          reverse_proxy localhost:9091
        }
        handle @remote {
          route {
            request_header -Remote-User
            request_header -Remote-Groups
            request_header -Remote-Name
            request_header -Remote-Email
            forward_auth localhost:9091 {
              uri /api/authz/forward-auth
              copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
            }
            reverse_proxy 127.0.0.1:8765
          }
        }
"""


def rpc(method, params):
    out = subprocess.run(["sudo", "-n", "/usr/sbin/omv-rpc", "-u", "admin", "Compose", method, json.dumps(params)],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else None


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    backup_dir, apply = sys.argv[1], "--apply" in sys.argv[2:]
    f = rpc("getFile", {"uuid": UUID})
    old = f["body"]
    if "@remote" in old:
        sys.exit("caddy already has @remote; nothing to do")
    anchor_m = "        @librewolf host librewolf.joe-nas.net\n"
    anchor_h = "        handle {\n          abort\n        }\n"
    if anchor_m not in old or anchor_h not in old:
        sys.exit("caddy compose body doesn't look as expected; nothing changed")
    new = old.replace(anchor_m, anchor_m + MATCHERS).replace(anchor_h, HANDLES + anchor_h)
    sys.stdout.writelines(difflib.unified_diff(old.splitlines(True), new.splitlines(True), "caddy (now)", "caddy (new)"))
    if not apply:
        print("\n(dry run: pass --apply to save it)")
        return
    os.makedirs(backup_dir, exist_ok=True)
    with open(os.path.join(backup_dir, "caddy.yml.body"), "w") as b:
        b.write(old)  # the body only; the env (Cloudflare token) is left untouched and not copied
    f["body"] = new
    rpc("setFile", f)
    print(f"\nsaved; old body backed up in {backup_dir}")


if __name__ == "__main__":
    main()
