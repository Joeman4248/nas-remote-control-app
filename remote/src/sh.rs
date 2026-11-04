//! Running commands. Everything goes through `sudo -n` as the nasremote user,
//! so what this app can do is exactly what system/remote/nas-remote.sudoers
//! allows, nothing more.

use crate::jobs::Live;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

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

/// Like sh, but each line of output goes to `live` as it comes, so the page can
/// show it. restic prints its progress every 2 s (RESTIC_PROGRESS_FPS, kept
/// through sudo by env_keep); a run of progress lines collapses to the newest.
pub fn sh_live(cmd: &[&str], live: &Live) -> String {
    let use_sudo = std::env::var("NAS_REMOTE_SUDO").map(|v| v != "0").unwrap_or(true);
    let mut c = if use_sudo { Command::new("sudo") } else { Command::new(cmd[0]) };
    if use_sudo { c.arg("-n").args(cmd); } else { c.args(&cmd[1..]); }
    let mut child = match c.env("RESTIC_PROGRESS_FPS", "0.5").stdin(Stdio::null())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(ch) => ch,
        Err(e) => return format!("{}: {e}", cmd[0]),
    };
    let out: Live = Arc::new(Mutex::new(vec![]));
    let reader = |r: Box<dyn Read + Send>| {
        let (out, live) = (out.clone(), live.clone());
        std::thread::spawn(move || {
            for chunk in BufReader::new(r).split(b'\n') {
                let Ok(chunk) = chunk else { break };
                for l in String::from_utf8_lossy(&chunk).split('\r').map(str::trim_end).filter(|l| !l.is_empty()) {
                    for store in [&out, &live] {
                        let mut v = store.lock().unwrap();
                        if is_progress(l) && v.last().is_some_and(|p| is_progress(p)) { v.pop(); }
                        v.push(l.to_string());
                    }
                }
            }
        })
    };
    let threads = [reader(Box::new(child.stdout.take().unwrap())), reader(Box::new(child.stderr.take().unwrap()))];
    for t in threads { let _ = t.join(); }
    let _ = child.wait();
    let v = out.lock().unwrap();
    v.join("\n").trim().to_string()
}

/// restic's progress line: "[0:12] 40.00%  2 / 5 packs".
fn is_progress(l: &str) -> bool {
    l.strip_prefix('[').and_then(|r| r.split_once("] ")).is_some_and(|(t, _)| t.contains(':') && t.chars().all(|c| c.is_ascii_digit() || c == ':'))
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
