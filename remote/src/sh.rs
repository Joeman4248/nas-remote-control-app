//! Running commands. Everything goes through `sudo -n` as the nasremote user,
//! so what this app can do is exactly what system/remote/nas-remote.sudoers
//! allows, nothing more.

use std::process::{Command, Stdio};

/// Run a command (with sudo unless NAS_REMOTE_SUDO=0, for testing) and return
/// stdout followed by stderr, trimmed. Never fails: errors come back as text.
pub fn sh(cmd: &[&str]) -> String {
    let use_sudo = std::env::var("NAS_REMOTE_SUDO").map(|v| v != "0").unwrap_or(true);
    let mut c = if use_sudo {
        let mut c = Command::new("sudo");
        c.arg("-n").args(cmd);
        c
    } else {
        let mut c = Command::new(cmd[0]);
        c.args(&cmd[1..]);
        c
    };
    match c.stdin(Stdio::null()).output() {
        Ok(out) => {
            let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&out.stderr));
            s.trim().to_string()
        }
        Err(e) => format!("{}: {e}", cmd[0]),
    }
}

/// Like sh, but as another (non-root) user: sudo -n -u <user> <cmd>.
pub fn sh_as(user: &str, cmd: &[&str]) -> String {
    if std::env::var("NAS_REMOTE_SUDO").is_ok_and(|v| v == "0") {
        return sh(cmd);
    }
    let mut c = vec!["-u", user];
    c.extend_from_slice(cmd);
    sh(&c)
}

/// Like sh, but without sudo (for commands any user can run, like apt list).
pub fn plain(cmd: &[&str]) -> String {
    match Command::new(cmd[0]).args(&cmd[1..]).env("LC_ALL", "C.UTF-8").stdin(Stdio::null()).output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(e) => format!("{}: {e}", cmd[0]),
    }
}

pub fn lines(s: &str) -> Vec<String> {
    s.lines().map(str::to_string).collect()
}
