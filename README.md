# nas-remote

A small web app for running a home NAS from a phone: one screen of big buttons, one per thing you'd otherwise SSH in for. It's built for one specific box (Debian 12 + OpenMediaVault 7, a Docker media stack, an AI agent with a restricted account). It's published as an example, not as a drop-in product.

- **Server:** Rust, std plus serde/serde_json/toml, no web framework (`remote/`). Runs as its own unprivileged user on 127.0.0.1 and does everything through `sudo -n` with an exact allowlist (`system/remote/nas-remote.sudoers`).
- **Login:** Caddy forward-auth to Authelia with passkey-only login (`system/remote/authelia*.yml`). The app trusts the `Remote-User` header, so a firewall rule keeps other local users off its port (`nas-remote-fw.service`).
- **Extra Face ID:** the riskiest actions (root grants for the agent, installing a new app version) also need a second WebAuthn check done by the app itself (`remote/src/stepup.rs`). Challenges are single-use and bound to the exact action.
- **Buttons:** defined in `system/buttons.toml`. A button either runs a command, which the sudoers file must allow exactly, or calls a flow built into `remote/src/screens.rs`.
- **Self-update:** `nas-remote-update` copies the source somewhere root-only, shows the diff, and installs only that exact copy after Face ID.

Screens: elevation for the agent (`claude-elevate` profiles), the agent's audit findings, Docker containers and stacks (update, restart, logs, prune), SMART/RAID disk health, VPN (gluetun) and Tailscale status, apt packages, and the agent's Remote Control session.

Mirrored from a private admin repo, so the history here is only snapshots.
