#!/usr/bin/env python3
"""Add remote.joe-nas.net (the web remote, behind Authelia at /auth on the same
host) to the OMV-managed Caddy compose file, then show the diff.

    caddy-add-remote.py BACKUP_DIR [--apply]
    caddy-add-remote.py BACKUP_DIR --auth-on-remote [--apply]   # convert the
        2026-10-31 layout (Authelia on auth.joe-nas.net) to the current one

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

# Authelia lives at /auth on the remote's own host: the iPhone home-screen app
# shows browser buttons for any other address. Strip client-sent identity
# headers first; everything but /auth asks Authelia, which sets Remote-User only
# after a passkey login. auth.joe-nas.net (the old login) just redirects.
AUTH_HANDLE = """\
        handle @auth {
          redir https://remote.joe-nas.net{uri}
        }
"""
REMOTE_HANDLE = """\
        handle @remote {
          request_header -Remote-User
          request_header -Remote-Groups
          request_header -Remote-Name
          request_header -Remote-Email
          @authelia path /auth /auth/*
          handle @authelia {
            reverse_proxy localhost:9091
          }
          handle {
            forward_auth localhost:9091 {
              uri /auth/api/authz/forward-auth
              copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
            }
            reverse_proxy 127.0.0.1:8765
          }
        }
"""
HANDLES = AUTH_HANDLE + REMOTE_HANDLE

# the 2026-10-31 layout, replaced by --auth-on-remote
OLD_HANDLES = """\
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
    if "--auth-on-remote" in sys.argv[2:]:
        if REMOTE_HANDLE in old:
            sys.exit("caddy already serves Authelia at remote.joe-nas.net/auth; nothing to do")
        if OLD_HANDLES not in old:
            sys.exit("caddy's @auth/@remote blocks don't look as expected; nothing changed")
        save(f, old, old.replace(OLD_HANDLES, HANDLES), backup_dir, apply)
        return
    if "@remote" in old:
        sys.exit("caddy already has @remote; nothing to do")
    anchor_m = "        @librewolf host librewolf.joe-nas.net\n"
    anchor_h = "        handle {\n          abort\n        }\n"
    if anchor_m not in old or anchor_h not in old:
        sys.exit("caddy compose body doesn't look as expected; nothing changed")
    save(f, old, old.replace(anchor_m, anchor_m + MATCHERS).replace(anchor_h, HANDLES + anchor_h), backup_dir, apply)


def save(f, old, new, backup_dir, apply):
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
