//! What the page shows and what buttons do.
//!
//! The page posts an "act" and gets back one of:
//!   {type: "screen",  act, title, lines, buttons, back}  a screen to navigate to
//!   {type: "result",  title, lines}                      output to read, then Back
//!   {type: "confirm", title, lines, yes, act}            Yes/No; Yes re-posts act confirmed
//!   {type: "job",     id, title, msg}                    poll /api/job until it's one of the above
//!   {type: "faceid",  title, lines, yes, act, challenge, allow}  Yes runs a passkey check (Full grants)
//!   {type: "register", title, lines, challenge, user}    set up that passkey (needs the setup code)
//! Acts: "open:<screen>[:<arg>]", "btn:<index in buttons.toml>:<container or empty>",
//! "grant:<profile>:<minutes>", "audit:accept", "update:<id of the reviewed copy>",
//! "watch:<backup unit>".

use crate::config::{fill, Button, Config};
use crate::jobs::{Jobs, Live};
use crate::sh::{lines, plain, sh, sh_as, sh_live};
use crate::stepup::{StepUp, RP_ID};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const UPDATE: &str = "/usr/local/sbin/nas-remote-update";
const AUDIT_REPORT: &str = "/var/lib/claude-audit/report";
const SIGN_OUT_URL: &str = "https://remote.joe-nas.net/auth/logout?rd=https%3A%2F%2Fremote.joe-nas.net%2F";
/// These share gluetun's network: restart gluetun first, then the rest (see joe-nas skill).
const GLUETUN_STACK: [&str; 4] = ["gluetun", "qbittorrent", "portmanager", "librewolf"];

pub struct App {
    pub cfg: Config,
    pub jobs: Jobs,
    pub stepup: StepUp,
}

const PROFILES: [(&str, &str); 5] = [("read", "read any file or log"), ("docker", "any docker command"),
    ("packages", "apt / nala / dpkg"), ("disks", "SMART, RAID, mount, fsck"), ("full", "everything (root)")];

/// Minutes the web remote may grant per profile (must match nas-remote.sudoers).
fn grant_minutes(profile: &str) -> &'static [&'static str] {
    if profile == "full" { &["15", "30"] } else { &["10", "15", "30", "60"] }
}

// ---------------------------------------------------------------------------
// Response builders. A line is [text, colour]; colour is "", green, red or dim.

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
}

fn line(text: impl Into<String>, colour: &str) -> Value {
    json!([text.into(), colour])
}

fn plain_lines(text: &str) -> Vec<Value> {
    text.lines().map(|l| line(l, "")).collect()
}

fn screen(act: &str, title: &str, lines: Vec<Value>, buttons: Vec<Value>, back: Option<&str>) -> Value {
    json!({"type": "screen", "act": act, "title": title, "lines": lines, "buttons": buttons, "back": back})
}

fn result(title: &str, lines: Vec<Value>) -> Value {
    let lines = if lines.is_empty() { vec![line("(no output)", "dim")] } else { lines };
    json!({"type": "result", "title": title, "lines": lines})
}

fn button(label: &str, style: &str, act: String) -> Value {
    json!({"label": label, "style": style, "act": act})
}

// ---------------------------------------------------------------------------
// Status readers

pub struct Container {
    pub name: String,
    pub status: String,
    pub healthy: bool,
    /// exited or never started: fine, some stacks are off on purpose
    pub stopped: bool,
}

impl Container {
    pub fn problem(&self) -> bool {
        !self.healthy && !self.stopped
    }
}

/// All containers: problems first, then running, then stopped.
pub fn containers() -> Vec<Container> {
    let mut rows: Vec<Container> = sh(&["docker", "ps", "-a", "--format", "{{.Names}}|{{.Status}}"])
        .lines()
        .filter_map(|l| l.split_once('|'))
        .map(|(name, status)| {
            // "Up 2 hours" or "Up 2 hours (healthy)"; anything else in brackets is a problem
            let rest = status.strip_suffix("(healthy)").unwrap_or(status);
            let healthy = status.starts_with("Up ") && !rest.contains('(');
            let stopped = status.starts_with("Exited") || status.starts_with("Created");
            Container { name: name.into(), status: status.into(), healthy, stopped }
        })
        .collect();
    rows.sort_by(|a, b| (!a.problem(), a.stopped, &a.name).cmp(&(!b.problem(), b.stopped, &b.name)));
    rows
}

/// Which Steam container runs (see steam-mode): "steam_stream" (steam2),
/// "steam_monitor" (steam) or "steam_off".
fn steam_mode() -> &'static str {
    let running = |n: &str| sh(&["docker", "inspect", "-f", "{{.State.Running}}", n]).trim() == "true";
    if running("steam2") { "steam_stream" } else if running("steam") { "steam_monitor" } else { "steam_off" }
}

/// (profile or None, until "19:05", left "9min") from claude-elevate status, whose
/// second line is the timer: "Thu 2026-10-29 19:05:01 CDT  9min  <last run or ->".
fn claude_status() -> Option<(String, String, String)> {
    let out = sh(&["/usr/local/sbin/claude-elevate", "status"]);
    let mut it = out.lines();
    let first = it.next().unwrap_or("");
    let profile = first.strip_prefix("elevated: ")?.to_string();
    let t: Vec<&str> = it.next().unwrap_or("").split_whitespace().collect();
    let until = t.get(2).map(|s| s.chars().take(5).collect()).unwrap_or_default();
    let weekday = |s: &str| ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].contains(&s);
    let left = t.iter().skip(4).take_while(|s| **s != "-" && !weekday(s)).cloned().collect::<Vec<_>>().join(" ");
    Some((profile, until, left))
}

/// Who ended the last elevation, from claude-elevate's journal lines.
fn last_end() -> String {
    let log = sh(&["journalctl", "-t", "claude-elevate", "-n", "30", "-o", "short-iso", "--no-pager"]);
    let today = plain(&["date", "+%F"]);
    let rows: Vec<(&str, &str, &str)> = log
        .lines()
        .filter_map(|l| {
            let (ts, rest) = l.split_once(' ')?;
            let msg = rest.split_once("]: ")?.1;
            (ts.len() >= 16).then(|| (&ts[..10], &ts[11..16], msg))
        })
        .collect();
    for (i, (day, hm, msg)) in rows.iter().enumerate().rev() {
        if !msg.contains("revoked by") && !msg.contains("expired") {
            continue;
        }
        let profile = rows[..i]
            .iter()
            .rev()
            .find_map(|r| r.2.split_once("granted '").and_then(|(_, p)| p.split_once('\'')).map(|(p, _)| p))
            .map(|p| format!(" ({p})"))
            .unwrap_or_default();
        let when = if *day == today { hm.to_string() } else { format!("{} {hm}", &day[5..]) };
        if msg.contains("expired") {
            return format!("expired at {when}{profile}");
        }
        let who = msg.rsplit(' ').next().unwrap_or("?");
        return format!("revoked by {who} at {when}{profile}");
    }
    "no elevation in the recent log".into()
}

fn profile_text(p: &str) -> &str {
    match p {
        "read" => "can read any file or log as root",
        "disks" => "disk tools as root",
        "packages" => "can install packages (effectively root)",
        "docker" => "any docker command",
        "full" => "FULL ROOT",
        other => other,
    }
}

fn audit_report() -> Option<String> {
    std::fs::read_to_string(AUDIT_REPORT).ok()
}

/// The top line: audit · docker, plus alerts.
/// (Elevation isn't here: the main screen shows it.)
pub fn header() -> Value {
    let audit = match audit_report() {
        Some(r) if r.trim().is_empty() => line("audit: clear", "green"),
        Some(_) => line("audit: findings", "red"),
        None => line("audit: ?", "red"),
    };
    let c = containers();
    // stopped containers don't count: only running ones that aren't healthy
    let (up, off) = (c.iter().filter(|c| c.healthy).count(), c.iter().filter(|c| c.stopped).count());
    let ok = !c.iter().any(Container::problem);
    let docker = format!("docker {up}/{}{}", c.len() - off, if off > 0 { format!(" · {off} off") } else { String::new() });
    let mut parts = vec![audit, line(docker, if ok { "green" } else { "red" })];
    parts.extend(alerts().into_iter().map(|a| line(a, "red")));
    json!(parts)
}

/// Problems worth shouting about in the header: a degraded or rebuilding
/// array, or storage over 90% full. Empty when all is well.
fn alerts() -> Vec<String> {
    let mut out = vec![];
    let mdstat = std::fs::read_to_string("/proc/mdstat").unwrap_or_default();
    if mdstat.contains("recovery") || mdstat.contains("resync") {
        out.push("RAID rebuilding".into());
    } else if mdstat.lines().any(|l| l.trim_end().ends_with(']') && l.contains("[") && l.rsplit('[').next().is_some_and(|b| b.contains('_'))) {
        out.push("RAID DEGRADED".into());
    }
    let pct: u32 = plain(&["df", "--output=pcent", "/mnt/storage"]).lines().nth(1).unwrap_or("").trim().trim_end_matches('%').parse().unwrap_or(0);
    if pct >= 90 {
        out.push(format!("storage {pct}%"));
    }
    if let Some(a) = remote_control_alert() {
        out.push(a.into());
    }
    out
}

// ---- Claude Remote Control (claude-remote.service: tmux session "claude") ----

const CLAUDE_UID: &str = "1002";
const ATTACH: &str = "sudo -iu claude tmux attach -t claude";
/// Seconds claude may go without any connection to Anthropic before the header says so.
const OFFLINE_AFTER: u64 = 180;
static LAST_ONLINE: AtomicU64 = AtomicU64::new(0);

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h {}m", s / 3600, s / 60 % 60),
        s => format!("{}d {}h", s / 86400, s / 3600 % 24),
    }
}

/// systemctl show for claude-remote: (active, since unix secs, restarts).
fn remote_control_unit() -> (bool, u64, String) {
    let out = plain(&["systemctl", "show", "claude-remote", "--timestamp=unix",
                      "-p", "ActiveState", "-p", "ActiveEnterTimestamp", "-p", "NRestarts"]);
    let get = |k: &str| out.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").to_string();
    let since = get("ActiveEnterTimestamp=").trim_start_matches('@').parse().unwrap_or(0);
    (get("ActiveState=") == "active", since, get("NRestarts="))
}

/// claude's processes: (bridge running, ages in seconds of the session processes).
fn remote_control_procs() -> (bool, Vec<u64>) {
    let ps = plain(&["ps", "-u", "claude", "-o", "etimes=,args="]);
    let bridge = ps.lines().any(|l| l.contains("claude remote-control"));
    let sessions = ps.lines().filter(|l| l.contains("--sdk-url"))
        .filter_map(|l| l.split_whitespace().next()?.parse().ok()).collect();
    (bridge, sessions)
}

/// Open connections from claude to port 443 (Anthropic). ss shows the owner's uid without sudo.
fn claude_connections() -> usize {
    plain(&["ss", "-Htne", "state", "established", "( dport = :443 )"])
        .lines().filter(|l| l.split_whitespace().any(|w| w == format!("uid:{CLAUDE_UID}"))).count()
}

/// The header line when Remote Control is down, or has had no connection for a few minutes.
fn remote_control_alert() -> Option<&'static str> {
    if !remote_control_unit().0 {
        return Some("Remote Control down");
    }
    let t = now();
    if claude_connections() > 0 || LAST_ONLINE.load(Ordering::Relaxed) == 0 {
        LAST_ONLINE.store(t, Ordering::Relaxed);
    }
    (t.saturating_sub(LAST_ONLINE.load(Ordering::Relaxed)) > OFFLINE_AFTER).then_some("Remote Control offline")
}

/// What Remote Control prints in its tmux window (wrapped lines joined), blank lines dropped.
fn remote_control_pane() -> Vec<String> {
    sh_as("claude", &["tmux", "capture-pane", "-p", "-J", "-t", "claude"])
        .lines().map(str::trim_end).filter(|l| !l.trim().is_empty()).map(String::from).collect()
}

fn claude_version() -> String {
    std::fs::read_link("/home/claude/.local/bin/claude").ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "?".into())
}

/// The restic repositories: (id for backup-verify, button name, what the screen says).
/// Their buttons are on screens backup_<id> in buttons.toml.
const BACKUP_REPOS: [(&str, &str, &[&str]); 3] = [
    ("usb", "USB SSD", &["The whole OS drive (NVMe): /, /boot/efi and the", "disk layout. usb-backup, nightly 04:07.",
                         "On the USB SSD nas-backup, restic-os.", "Keeps 14 daily, 8 weekly, 12 monthly."]),
    ("local", "Local", &["Compose files, app settings and databases.", "r2-backup, nightly 03:17, with R2.",
                         "/var/backups/restic-local on the NVMe."]),
    ("r2", "R2", &["Same as Local, off-site in Cloudflare R2.", "r2-backup, nightly 03:17.",
                   "No Check Data here: it would download everything."]),
];
/// The service that writes a repo: usb-backup for usb, r2-backup for local and r2.
fn backup_unit(repo: &str) -> &'static str {
    if repo == "usb" { "usb-backup" } else { "r2-backup" }
}

/// How long a backup service has been running, None when it isn't.
fn backup_running(unit: &str) -> Option<u64> {
    let s = plain(&["systemctl", "show", unit, "--timestamp=unix", "-p", "ActiveState", "-p", "ExecMainStartTimestamp"]);
    let get = |k: &str| s.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").to_string();
    (get("ActiveState=") == "activating")
        .then(|| now().saturating_sub(get("ExecMainStartTimestamp=").trim_start_matches('@').parse().unwrap_or(0)))
}

/// Lines saying a backup is running and what waits for it.
fn backup_busy_lines(unit: &str, secs: u64) -> Vec<Value> {
    vec![line(format!("{unit} is running ({}).", age(secs)), ""),
         line("Check and Back Up Now wait until it's done:", "dim"),
         line("a check would lock the backup out. Watch shows it live.", "dim")]
}

const BACKUP_UNITS: [(&str, &str); 2] = [("r2-backup", "R2 + Local"), ("usb-backup", "USB SSD")];
const USB_BACKUP_UUID: &str = "f728a9c8-1c4b-4cfc-a444-4b12fee86ffb";

/// Last run and next run of the two backup services, and the USB drive. Needs no sudo.
fn backup_lines() -> Vec<Value> {
    let timers: Vec<Value> = serde_json::from_str(&plain(&["systemctl", "list-timers", "r2-backup.timer", "usb-backup.timer", "-o", "json"]))
        .unwrap_or_default();
    let t = now();
    let mut out = vec![];
    for (unit, name) in BACKUP_UNITS {
        let (text, colour) = backup_status(unit);
        out.push(line(format!("{name}: {text}"), colour));
        if unit == "usb-backup" {
            let mnt = plain(&["findmnt", "-rn", "-S", &format!("UUID={USB_BACKUP_UUID}"), "-o", "AVAIL,SIZE"]);
            out.push(match mnt.split_whitespace().collect::<Vec<_>>().as_slice() {
                [avail, size] => line(format!("  drive plugged in, {avail} free of {size}"), "dim"),
                _ => line("  drive not plugged in (or not mounted)", "red"),
            });
        }
        let next = timers.iter().find(|x| x["unit"] == format!("{unit}.timer")).and_then(|x| x["next"].as_u64()).unwrap_or(0);
        out.push(line(if next == 0 { "  next run: not scheduled".to_string() } else {
            format!("  next run in {}", age((next / 1_000_000).saturating_sub(t)))
        }, if next == 0 { "red" } else { "dim" }));
    }
    out
}

/// A backup service's last or current run, and its colour. Needs no sudo.
fn backup_status(unit: &str) -> (String, &'static str) {
    let t = now();
    let s = plain(&["systemctl", "show", unit, "--timestamp=unix", "-p", "ActiveState", "-p", "Result",
                    "-p", "ExecMainStatus", "-p", "ExecMainStartTimestamp", "-p", "ExecMainExitTimestamp",
                    "-p", "ConditionResult", "-p", "ConditionTimestamp"]);
    let get = |k: &str| s.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").to_string();
    let ts = |k: &str| get(k).trim_start_matches('@').parse::<u64>().unwrap_or(0);
    let (start, exit, cond) = (ts("ExecMainStartTimestamp="), ts("ExecMainExitTimestamp="), ts("ConditionTimestamp="));
    if get("ActiveState=") == "activating" {
        (format!("running for {}", age(t.saturating_sub(start))), "")
    } else if get("ConditionResult=") == "no" && cond > 0 {
        (format!("skipped {} ago (drive not mounted)", age(t.saturating_sub(cond))), "red")
    } else if start == 0 {
        ("no run since boot".into(), "dim")
    } else if get("Result=") != "success" && get("ExecMainStatus=") == "3" {
        // restic: snapshot saved, but some files couldn't be read
        (format!("partly saved {} ago (unreadable files)", age(t.saturating_sub(exit))), "red")
    } else if get("Result=") != "success" {
        (format!("FAILED {} ago (exit {})", age(t.saturating_sub(exit.max(start))), get("ExecMainStatus=")), "red")
    } else {
        (format!("ok {} ago, took {}", age(t.saturating_sub(exit)), age(exit.saturating_sub(start))), "green")
    }
}

/// The current (or last) run's journal, from its "Starting ..." line on.
fn backup_log(unit: &str) -> Vec<String> {
    let out = lines(&sh(&["journalctl", "-u", unit, "-n", "15", "-o", "cat", "--no-pager"]));
    let from = out.iter().rposition(|l| l.starts_with("Starting ")).unwrap_or(0);
    out[from..].to_vec()
}

/// Follow a backup service until it finishes: its journal is the live lines.
/// restic in the backup scripts prints progress every 10 s (RESTIC_PROGRESS_FPS).
fn watch_backup(title: String, unit: &str, live: Live) -> Value {
    let start = now();
    let mut seen = false;
    loop {
        let running = backup_running(unit).is_some();
        seen |= running;
        let log = backup_log(unit);
        if !running && (seen || now() - start > 5) {
            let (text, colour) = backup_status(unit);
            let mut l = vec![line(text, colour), line("", "")];
            l.extend(log.iter().map(|x| line(x.as_str(), "")));
            return result(&title, l);
        }
        *live.lock().unwrap() = log;
        if now() - start > 4 * 3600 {
            return result(&title, vec![line("Still running after 4 hours; stopped watching.", "red")]);
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// SMART summary per drive, plus the array and the SSD cache.
fn disk_health() -> Vec<Value> {
    let mut out = vec![];
    let disks: Vec<String> = plain(&["lsblk", "-dnpo", "NAME,TYPE"])
        .lines()
        .filter_map(|l| l.split_once(' ').filter(|(_, t)| t.trim() == "disk").map(|(n, _)| n.to_string()))
        .filter(|n| n.starts_with("/dev/sd") || n.starts_with("/dev/nvme"))
        .collect();
    for dev in disks {
        let (title, facts, ok) = smart_summary(&dev, &sh(&["/usr/sbin/smartctl", "-i", "-H", "-A", &dev]));
        out.push(line(title, if ok { "green" } else { "red" }));
        out.push(line(format!("  {facts}"), if ok { "" } else { "red" }));
    }
    out.push(line("", ""));
    let mdstat = std::fs::read_to_string("/proc/mdstat").unwrap_or_default();
    for l in mdstat.lines().filter(|l| l.starts_with("md")) {
        let state = mdstat.lines().skip_while(|x| *x != l).nth(1).and_then(|n| n.rsplit_once(' ')).map(|(_, b)| b.to_string()).unwrap_or_default();
        let ok = !state.contains('_') && !mdstat.contains("recovery") && !mdstat.contains("resync");
        let name = l.split_whitespace().take(4).collect::<Vec<_>>().join(" ");
        out.push(line(format!("RAID {name} {state}{}", if ok { " in sync" } else { "" }), if ok { "green" } else { "red" }));
    }
    if let Ok(st) = std::fs::read_to_string("/sys/block/bcache0/bcache/state") {
        let st = st.trim().to_string();
        out.push(line(format!("SSD cache: {st}"), if st == "clean" || st == "dirty" { "green" } else { "red" }));
    }
    out
}

/// A filesystem on a USB disk: what nas-drive mounts and ejects (never the array or the NVMe).
struct UsbPart {
    dev: String,
    name: String,
    fs: String,
    size: String,
    mnt: Option<String>,
}

impl UsbPart {
    fn free(&self) -> Option<String> {
        let m = self.mnt.as_deref()?;
        Some(plain(&["df", "-h", "--output=avail", m]).lines().nth(1).unwrap_or("?").trim().to_string())
    }
}

fn usb_parts() -> Vec<UsbPart> {
    // a flat list (no NAME column = no tree): partitions point at their disk through pkname
    let v: Value = serde_json::from_str(&plain(&["lsblk", "-Jpo", "PATH,PKNAME,TRAN,FSTYPE,LABEL,SIZE,MOUNTPOINT"])).unwrap_or_default();
    let all = v["blockdevices"].as_array().cloned().unwrap_or_default();
    let usb: Vec<&Value> = all.iter().filter(|d| d["tran"] == "usb").map(|d| &d["path"]).collect();
    all.iter()
        .filter(|d| usb.contains(&&d["path"]) || usb.contains(&&d["pkname"]))
        .filter_map(|d| {
            let s = |k: &str| d[k].as_str().unwrap_or("").to_string();
            let (fs, dev, label) = (s("fstype"), s("path"), s("label"));
            (!fs.is_empty() && fs != "swap").then(|| UsbPart {
                name: if label.is_empty() { dev.trim_start_matches("/dev/").to_string() } else { label },
                dev, fs, size: s("size"), mnt: d["mountpoint"].as_str().map(String::from),
            })
        })
        .collect()
}

fn container_ids() -> Vec<(String, String)> {
    sh(&["docker", "ps", "-a", "--format", "{{.Names}}|{{.ID}}"])
        .lines()
        .filter_map(|l| l.split_once('|'))
        .map(|(n, id)| (n.into(), id.into()))
        .collect()
}

fn compose_project(name: &str) -> String {
    sh(&["docker", "inspect", "-f", "{{index .Config.Labels \"com.docker.compose.project\"}}", name])
}

fn compose_projects() -> Vec<String> {
    let mut p: Vec<String> = sh(&["docker", "ps", "-a", "--format", "{{.Label \"com.docker.compose.project\"}}"])
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    p.sort();
    p.dedup();
    p
}

/// gluetun's stack first and in order, then everything else sorted.
fn gluetun_first(names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = GLUETUN_STACK.iter().filter(|g| names.iter().any(|n| n == *g)).map(|g| g.to_string()).collect();
    let mut rest: Vec<String> = names.iter().filter(|n| !GLUETUN_STACK.contains(&n.as_str())).cloned().collect();
    rest.sort();
    out.extend(rest);
    out
}

/// Debian sets no reboot-required flag: compare the running kernel with the newest installed.
fn reboot_needed() -> Option<(String, String)> {
    let running = plain(&["uname", "-r"]);
    let key = |v: &str| v.split(|c| ".+-".contains(c)).map(|x| x.parse::<i64>().unwrap_or(-1)).collect::<Vec<_>>();
    let newest = std::fs::read_dir("/boot")
        .ok()?
        .filter_map(|e| e.ok()?.file_name().to_str()?.strip_prefix("vmlinuz-").map(String::from))
        .max_by_key(|v| key(v))?;
    (newest != running).then_some((running, newest))
}

fn upgradable() -> Vec<String> {
    plain(&["apt", "list", "--upgradable"])
        .lines()
        .filter(|l| l.contains("[upgradable"))
        .map(|l| {
            let name = l.split('/').next().unwrap_or(l);
            let version = l.split_whitespace().nth(1).unwrap_or("");
            format!("{name}  {version}")
        })
        .collect()
}

fn minutes_since_apt_update() -> Option<u64> {
    let m = std::fs::metadata("/var/cache/apt/pkgcache.bin").ok()?.modified().ok()?;
    Some(m.elapsed().ok()?.as_secs() / 60)
}

// ---------------------------------------------------------------------------
// Jobs: these run on a job thread and return a result

fn update_stacks(title: String, stacks: Vec<String>) -> Value {
    let before = container_ids();
    let mut errors = vec![];
    for p in &stacks {
        for l in sh(&["omv-compose-update", p]).lines() {
            let low = l.to_lowercase();
            if low.contains("error") || low.contains("denied") || low.contains("exiting") {
                errors.push(line(format!("{p}: {l}"), ""));
            }
        }
    }
    let after = container_ids();
    let mut changed: Vec<&str> = after.iter().filter(|a| !before.contains(a)).map(|a| a.0.as_str()).collect();
    changed.sort();
    let mut out = vec![if changed.is_empty() {
        line("Already up to date.", "green")
    } else {
        line(format!("Updated: {}", changed.join(", ")), "green")
    }];
    if !errors.is_empty() {
        out.push(line("", ""));
        out.push(line("Problems:", "red"));
        let skip = errors.len().saturating_sub(20);
        out.extend(errors.into_iter().skip(skip));
    }
    result(&title, out)
}

fn restart(title: String, names: Vec<String>) -> Value {
    let done: Vec<String> = names.iter().map(|n| sh(&["docker", "restart", n])).collect();
    result(&title, vec![line(format!("Restarted: {}", done.join(" ")), "green")])
}

// ---------------------------------------------------------------------------
// The app

impl App {
    pub fn new(cfg: Config) -> Arc<App> {
        Arc::new(App { cfg, jobs: Jobs::default(), stepup: StepUp::new(crate::state_dir()) })
    }

    /// Answer one act from the page. `faceid` is a passkey assertion, for Full grants.
    pub fn act(&self, act: &str, confirmed: bool, faceid: &Value) -> Value {
        let parts: Vec<&str> = act.splitn(3, ':').collect();
        match parts.as_slice() {
            ["open", "grant"] => self.grant_screen(),
            ["open", "grant", profile] => self.grant_minutes_screen(profile),
            ["grant", profile, mins] => self.grant(profile, mins, faceid),
            ["update", id] => self.update_install(id, faceid),
            ["audit", "accept"] => {
                if !confirmed {
                    return json!({"type": "confirm", "title": "Audit", "yes": "Accept", "act": act,
                                  "lines": [["Accept these findings as your own changes?", ""]]});
                }
                result("Audit", plain_lines(&sh(&["/usr/local/sbin/claude-audit", "--accept"])))
            }
            ["open", "main"] => self.main_screen(),
            ["open", "docker"] => self.docker_screen(),
            ["open", "docker_all"] => self.docker_all_screen(),
            ["open", "container", name] => self.container_screen(name),
            ["open", "packages"] => self.packages_screen(),
            ["open", "audit"] => audit_screen(),
            ["open", "vpn"] => self.vpn_screen(),
            ["open", "claude_remote"] => self.claude_remote_screen(),
            ["open", "backups"] => self.backups_screen(),
            ["open", "drives"] => self.drives_screen(),
            ["open", "drive", dev] => self.drive_screen(dev),
            ["open", "backup", repo] => self.backup_repo_screen(repo),
            ["watch", unit] => self.watch(unit),
            ["btn", i, arg] => match i.parse::<usize>().ok().and_then(|i| self.cfg.buttons.get(i).map(|b| (i, b))) {
                Some((i, b)) => self.press(i, b, arg, confirmed),
                _ => result("Error", vec![line("No such button.", "red")]),
            },
            _ => result("Error", vec![line(format!("Unknown action {act:?}."), "red")]),
        }
    }

    /// The buttons from buttons.toml for a screen, with their when-conditions.
    fn buttons(&self, screen: &str, arg: &str, holds: impl Fn(&str) -> bool) -> Vec<Value> {
        self.cfg
            .on(screen)
            .filter(|(_, b)| b.when.as_deref().is_none_or(&holds))
            .map(|(i, b)| button(&b.label, &b.style, format!("btn:{i}:{arg}")))
            .collect()
    }

    // ---- screens ----

    fn main_screen(&self) -> Value {
        let lines = match claude_status() {
            None => vec![line("claude-elevate: off", "green"), line(last_end(), "dim")],
            Some((p, until, left)) => vec![
                line(if left.is_empty() { format!("claude-elevate: {p}") } else { format!("claude-elevate: {p} · {left} left") }, "red"),
                line(format!("{}{}", profile_text(&p), if until.is_empty() { String::new() } else { format!(", until {until}") }), "red"),
            ],
        };
        // Quit on the web = sign out (the page can't close itself)
        let steam = steam_mode();
        let mut v = screen("open:main", "joe-nas", lines, self.buttons("main", "", |w| !w.starts_with("steam_") || w == steam), Some("Quit"));
        v["quit_url"] = json!(SIGN_OUT_URL);
        v
    }

    fn docker_screen(&self) -> Value {
        let mut buttons = vec![button("All", "BTN", "open:docker_all".into())];
        buttons.extend(containers().iter().map(|c| {
            let style = if c.healthy { "GOOD" } else if c.stopped { "OFF" } else { "BAD" };
            button(&c.name, style, format!("open:container:{}", c.name))
        }));
        screen("open:docker", "Docker", vec![], buttons, Some("Back"))
    }

    fn docker_all_screen(&self) -> Value {
        let c = containers();
        let running = c.iter().filter(|c| c.status.starts_with("Up")).count();
        let mut lines = vec![line(format!("{running} running, {} stopped", c.len() - running), ""), line("", "")];
        lines.extend(
            sh(&["docker", "system", "df"])
                .lines()
                .filter(|l| l.starts_with("TYPE") || l.starts_with("Images") || l.starts_with("Containers"))
                .map(|l| line(l, "")),
        );
        screen("open:docker_all", "Docker › All", lines, self.buttons("docker_all", "", |_| true), Some("Back"))
    }

    fn container_screen(&self, name: &str) -> Value {
        let act = format!("open:container:{name}");
        let info = sh(&[
            "docker",
            "inspect",
            "-f",
            "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.StartedAt}}|\
             {{.Config.Image}}|{{index .Config.Labels \"org.opencontainers.image.version\"}}",
            name,
        ]);
        let f: Vec<&str> = info.split('|').collect();
        let [state, health, started, image, version] = f.as_slice() else {
            return result(name, vec![line(format!("{name} not found"), "red")]);
        };
        let good = *state == "running" && (health.is_empty() || *health == "healthy");
        let stopped = matches!(*state, "exited" | "created");
        let colour = if good { "green" } else if stopped { "dim" } else { "red" };
        let mut lines = vec![
            line(if health.is_empty() { state.to_string() } else { format!("{state} · {health}") }, colour),
            line(format!("since {} UTC", started.get(..16).unwrap_or(started).replace('T', " ")), ""),
            line(if version.is_empty() { image.to_string() } else { format!("{image}  ({version})") }, ""),
        ];
        if GLUETUN_STACK.contains(&name) {
            lines.extend([
                line("", ""),
                line("Shares gluetun's network: restarting restarts the", ""),
                line("whole VPN stack, gluetun first.", ""),
            ]);
        }
        let buttons = self.buttons("container", name, |w| if w == "running" { !stopped } else { w == "stopped" && stopped });
        screen(&act, name, lines, buttons, Some("Back"))
    }

    fn drives_screen(&self) -> Value {
        let parts = usb_parts();
        let mut lines: Vec<Value> = parts.iter().map(|p| {
            let state = p.free().map_or("not mounted".into(), |f| format!("{f} free"));
            line(format!("{}  {} {}  {state}", p.name, p.size, p.fs), if p.mnt.is_some() { "green" } else { "" })
        }).collect();
        if lines.is_empty() {
            lines.push(line("No USB drives plugged in.", "dim"));
        }
        let mut buttons: Vec<Value> = parts.iter()
            .map(|p| button(&p.name, if p.mnt.is_some() { "GOOD" } else { "OFF" }, format!("open:drive:{}", p.dev)))
            .collect();
        let (any_mounted, any_unmounted) = (parts.iter().any(|p| p.mnt.is_some()), parts.iter().any(|p| p.mnt.is_none()));
        buttons.extend(self.buttons("drives", "", |w| match w {
            "any_mounted" => any_mounted,
            "any_unmounted" => any_unmounted,
            _ => true,
        }));
        screen("open:drives", "Drives", lines, buttons, Some("Back"))
    }

    fn drive_screen(&self, dev: &str) -> Value {
        // gone (ejected or unplugged): back to the list
        let Some(p) = usb_parts().into_iter().find(|p| p.dev == dev) else {
            return self.drives_screen();
        };
        let mounted = p.mnt.is_some();
        let lines = vec![
            match (&p.mnt, p.free()) {
                (Some(m), Some(f)) => line(format!("mounted at {m} ({f} free)"), "green"),
                _ => line("not mounted", "dim"),
            },
            line(format!("{} · {} · {}", p.size, p.fs, p.dev), ""),
        ];
        let buttons = self.buttons("drive", dev, |w| if w == "mounted" { mounted } else { w == "unmounted" && !mounted });
        screen(&format!("open:drive:{dev}"), &format!("Drives › {}", p.name), lines, buttons, Some("Back"))
    }

    fn vpn_screen(&self) -> Value {
        let health = sh(&["docker", "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", "gluetun"]);
        let qbit = sh(&["docker", "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", "qbittorrent"]);
        let logs = sh(&["docker", "logs", "--tail", "5000", "gluetun"]);
        let ip = logs.lines().rev().find_map(|l| l.split_once("Public IP address is ").map(|(_, r)| {
            // "1.2.3.4 (Switzerland, Zurich, Zürich - source: ipinfo)"
            let r = r.split(" - source").next().unwrap_or(r);
            if r.contains('(') && !r.contains(')') { format!("{r})") } else { r.to_string() }
        }));
        let port = logs.lines().rev().find_map(|l| l.split_once("port forwarded is ").map(|(_, r)| r.trim().to_string()));
        let colour = |h: &str| if h == "healthy" || h == "running" { "green" } else { "red" };
        let lines = vec![
            line(format!("VPN (gluetun): {health}"), colour(&health)),
            line(format!("Public IP: {}", ip.unwrap_or_else(|| "unknown".into())), ""),
            line(format!("Forwarded port: {}", port.unwrap_or_else(|| "none".into())), ""),
            line(format!("qBittorrent: {qbit}"), colour(&qbit)),
            line("", ""),
        ];
        let lines = [lines, tailscale_lines()].concat();
        screen("open:vpn", "VPN", lines, self.buttons("vpn", "gluetun", |_| true), Some("Back"))
    }

    fn claude_remote_screen(&self) -> Value {
        let (active, since, restarts) = remote_control_unit();
        let (bridge, sessions) = remote_control_procs();
        let conns = claude_connections();
        let pane = remote_control_pane();
        let ok = |good: bool| if good { "green" } else { "red" };
        let mut lines = vec![if active {
            line(format!("Service: up {} · {restarts} restarts", age(now().saturating_sub(since))), "green")
        } else {
            line("Service: not running", "red")
        }];
        lines.push(line(if bridge { "Remote Control: running" } else { "Remote Control: not running" }, ok(bridge)));
        // its own status line, e.g. "·✔︎· Connected · nas · main"
        match pane.iter().find(|l| !l.starts_with('[') && l.contains(" · ")) {
            Some(s) => lines.push(line(s.trim_start_matches(['·', '✔', '\u{fe0e}', ' ']).to_string(), ok(s.contains("Connected") && !s.contains("Disconnected")))),
            None => lines.push(line("Status: can't read its screen", "red")),
        }
        lines.push(line(format!("Connections to Anthropic: {conns}"), ok(conns > 0)));
        lines.push(line(match sessions.len() {
            0 => "Sessions: none running".to_string(),
            n => format!("Sessions: {n} running ({})", sessions.iter().map(|s| age(*s)).collect::<Vec<_>>().join(", ")),
        }, ""));
        lines.push(line(format!("Claude Code {}", claude_version()), ""));
        lines.push(line("", ""));
        lines.push(line("Attach over SSH as joseph:", "dim"));
        lines.push(line(ATTACH, ""));
        lines.push(line("Detach with Ctrl-b then d (Ctrl-c stops it)", "dim"));
        let errors: Vec<&String> = pane.iter().filter(|l| l.starts_with('[')).collect();
        if !errors.is_empty() {
            lines.push(line("", ""));
            lines.push(line("Recent messages:", "dim"));
            // two lines at most each on a phone
            lines.extend(errors[errors.len().saturating_sub(4)..].iter().map(|l| {
                let short: String = l.chars().take(70).collect();
                line(if short.len() < l.len() { format!("{short}…") } else { short }, "dim")
            }));
        }
        // copied on the page itself, no round trip
        let mut buttons = vec![json!({"label": "Copy Attach Command", "style": "BTN", "copy": ATTACH})];
        buttons.extend(self.buttons("claude_remote", "", |_| true));
        screen("open:claude_remote", "Claude Remote", lines, buttons, Some("Back"))
    }

    fn backups_screen(&self) -> Value {
        let mut buttons: Vec<Value> = BACKUP_REPOS.iter()
            .map(|(r, name, ..)| button(name, "BTN", format!("open:backup:{r}"))).collect();
        for (unit, name) in BACKUP_UNITS {
            if backup_running(unit).is_some() {
                buttons.push(button(&format!("Watch {name}"), "GOOD", format!("watch:{unit}")));
            }
        }
        buttons.extend(self.buttons("backups", "", |_| true));
        screen("open:backups", "Backups", backup_lines(), buttons, Some("Back"))
    }

    fn backup_repo_screen(&self, repo: &str) -> Value {
        let Some((r, name, what)) = BACKUP_REPOS.iter().find(|(r, ..)| *r == repo) else {
            return result("Backups", vec![line(format!("No backup named {repo:?}."), "red")]);
        };
        let mut lines: Vec<Value> = what.iter().map(|l| line(*l, "")).collect();
        let unit = backup_unit(r);
        let running = backup_running(unit);
        let mut buttons = vec![];
        if let Some(secs) = running {
            lines.push(line("", ""));
            lines.extend(backup_busy_lines(unit, secs));
            buttons.push(button("Watch", "GOOD", format!("watch:{unit}")));
        }
        buttons.extend(self.buttons(&format!("backup_{r}"), "", |w| w == "idle" && running.is_none()));
        screen(&format!("open:backup:{r}"), &format!("Backups › {name}"), lines, buttons, Some("Back"))
    }

    /// A backup service's run, live, until it finishes.
    fn watch(&self, unit: &str) -> Value {
        let Some((unit, name)) = BACKUP_UNITS.iter().find(|(u, _)| *u == unit) else {
            return result("Backups", vec![line(format!("No backup named {unit:?}."), "red")]);
        };
        let title = format!("Backups › {name}");
        json!({"type": "job", "title": title, "msg": format!("{unit} running..."),
               "id": self.jobs.start_live(move |live| watch_backup(title, unit, live))})
    }

    fn packages_screen(&self) -> Value {
        let pk = upgradable();
        let mut lines = if pk.is_empty() {
            vec![line("Everything is up to date.", "green")]
        } else {
            let mut l = vec![line(format!("{} updates available", pk.len()), "red")];
            l.extend(pk.iter().map(|p| line(p, "")));
            l
        };
        if let Some(m) = minutes_since_apt_update() {
            let ago = if m < 60 { format!("{m} min") } else if m < 48 * 60 { format!("{} h", m / 60) } else { format!("{} days", m / 1440) };
            lines.push(line(format!("checked {ago} ago"), "dim"));
        }
        let reboot = reboot_needed();
        if let Some((running, newest)) = &reboot {
            lines.push(line("", ""));
            lines.push(line(format!("Reboot needed: running {running}, installed {newest}"), "red"));
        }
        let buttons = self.buttons("packages", "", |w| w == "reboot_needed" && reboot.is_some());
        screen("open:packages", "Packages", lines, buttons, Some("Back"))
    }

    // ---- claude grants ----

    fn grant_screen(&self) -> Value {
        let lines = PROFILES.iter().map(|(n, d)| line(format!("{n:<9}{d}"), "")).collect();
        let buttons = PROFILES.iter()
            .map(|(n, _)| button(&capitalize(n), if *n == "full" { "DANGER" } else { "BTN" }, format!("open:grant:{n}")))
            .collect();
        screen("open:grant", "Elevate Claude", lines, buttons, Some("Back"))
    }

    fn grant_minutes_screen(&self, profile: &str) -> Value {
        if !PROFILES.iter().any(|(n, _)| *n == profile) {
            return result("Elevate Claude", vec![line("No such profile.", "red")]);
        }
        let style = if profile == "full" { "DANGER" } else { "BTN" };
        let buttons = grant_minutes(profile).iter().map(|m| button(&format!("{m} min"), style, format!("grant:{profile}:{m}"))).collect();
        screen(&format!("open:grant:{profile}"), &format!("Elevate Claude › {profile}"), vec![line("For how long?", "")], buttons, Some("Back"))
    }

    /// Run claude-elevate. Full needs the extra Face ID: first answer is a
    /// Face ID screen; the page comes back with the passkey assertion.
    fn grant(&self, profile: &str, mins: &str, faceid: &Value) -> Value {
        let t = "Elevate Claude";
        if !PROFILES.iter().any(|(n, _)| *n == profile) || !grant_minutes(profile).contains(&mins) {
            return result(t, vec![line("Not a grant the web remote can give.", "red")]);
        }
        let act = format!("grant:{profile}:{mins}");
        if profile == "full" {
            if !self.stepup.registered() {
                return self.register_screen();
            }
            if faceid.is_null() {
                return json!({"type": "faceid", "title": t, "act": act, "yes": "Confirm With Face ID",
                              "challenge": self.stepup.challenge(&act), "allow": self.stepup.credential_ids(), "rp": RP_ID,
                              "lines": [[format!("Give claude full root for {mins} minutes?"), ""]]});
            }
            if let Err(e) = self.stepup.verify(faceid, &act) {
                return result(t, vec![line("Not granted", "red"), line(e, "")]);
            }
        }
        result(t, plain_lines(&sh(&["/usr/local/sbin/claude-elevate", mins, profile])))
    }

    /// Update App: nas-remote-update copies claude's repo somewhere root-only and
    /// shows the diff; installing it needs the Face ID, bound to that exact copy.
    fn update_app(&self) -> Value {
        let t = "Update App";
        if !self.stepup.registered() {
            return self.register_screen();
        }
        let out = sh(&[UPDATE, "--stage"]);
        let Some((diff, id)) = out.rsplit_once("\nid: ").filter(|(_, id)| id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit())) else {
            return if out == "Already the newest version." { result(t, vec![line(out, "green")]) } else { result(t, plain_lines(&out)) };
        };
        let act = format!("update:{id}");
        let mut ls = vec![line(diff_summary(diff), ""), line("Read it all, then Install. The remote restarts after.", "dim"), line("", "")];
        ls.extend(diff_lines(diff));
        json!({"type": "faceid", "title": t, "act": act, "yes": "Install With Face ID", "lines": ls,
               "challenge": self.stepup.challenge(&act), "allow": self.stepup.credential_ids(), "rp": RP_ID})
    }

    fn update_install(&self, id: &str, faceid: &Value) -> Value {
        let t = "Update App";
        if let Err(e) = self.stepup.verify(faceid, &format!("update:{id}")) {
            return result(t, vec![line("Not installed", "red"), line(e, "")]);
        }
        let id = id.to_string();
        json!({"type": "job", "title": t, "msg": "Building and installing (a minute or two)...",
               "id": self.jobs.start(move || result(t, plain_lines(&sh(&[UPDATE, "--apply", &id]))))})
    }

    fn register_screen(&self) -> Value {
        if let Err(e) = self.stepup.setup_code() {
            return result("Face ID for Full", vec![line(format!("Can't create the setup code: {e}"), "red")]);
        }
        json!({"type": "register", "title": "Face ID for Full", "challenge": self.stepup.challenge("register"),
               "rp": RP_ID, "user": "joseph",
               "lines": [["Full grants need their own passkey, checked by the remote.", ""], ["", ""],
                         ["1. Get the setup code on the NAS:", ""],
                         [format!("   sudo cat {}", self.stepup.code_path().display()), "dim"],
                         ["2. Enter code, then Set up Face ID.", ""],
                         ["   Save it in Passwords (iCloud) for Face ID every time.", "dim"]]})
    }

    // ---- buttons ----

    fn press(&self, i: usize, b: &Button, arg: &str, confirmed: bool) -> Value {
        let title = match b.screen.as_str() {
            "container" => arg.to_string(),
            "vpn" => "VPN".into(),
            "claude_remote" => "Claude Remote".into(),
            "docker_all" => "Docker › All".into(),
            "packages" => "Packages".into(),
            "backups" => "Backups".into(),
            "drives" => "Drives".into(),
            s if s.starts_with("backup_") => BACKUP_REPOS.iter().find(|(r, ..)| s[7..] == **r)
                .map(|(_, n, _)| format!("Backups › {n}")).unwrap_or_else(|| b.label.clone()),
            _ => b.label.clone(),
        };
        // a drive button names its USB partition; it must still be one
        let label = if b.screen == "drive" {
            match usb_parts().into_iter().find(|p| p.dev == arg) {
                Some(p) => p.name,
                None => return result("Drives", vec![line(format!("No USB drive at {arg:?} any more."), "red")]),
            }
        } else {
            String::new()
        };
        let title = if label.is_empty() { title } else { format!("Drives › {label}") };
        if b.screen != "drive" && (b.screen == "container" || !arg.is_empty()) && !containers().iter().any(|c| c.name == arg) {
            return result(&title, vec![line(format!("No container named {arg:?}."), "red")]);
        }
        // the page may be older than the backup's start
        if let Some(repo) = b.screen.strip_prefix("backup_").filter(|_| b.when.as_deref() == Some("idle")) {
            let unit = backup_unit(repo);
            if let Some(secs) = backup_running(unit) {
                return result(&title, backup_busy_lines(unit, secs));
            }
        }
        let act = format!("btn:{i}:{arg}");
        // a Yes/No first, when the button has one and it hasn't been answered
        let ask = |vars: &[(&str, &str)], extra: Vec<Value>| -> Option<Value> {
            if confirmed || b.confirm.is_empty() {
                return None;
            }
            let mut lines: Vec<Value> = b.confirm.iter().map(|l| line(fill(l, vars), "")).collect();
            lines.extend(extra);
            Some(json!({"type": "confirm", "title": title, "lines": lines,
                        "yes": b.yes.as_deref().unwrap_or("Yes"), "act": act}))
        };
        let job = |msg: &str, work: Box<dyn FnOnce() -> Value + Send>| -> Value {
            json!({"type": "job", "id": self.jobs.start(work), "title": title, "msg": msg})
        };
        let live_job = |msg: &str, work: Box<dyn FnOnce(Live) -> Value + Send>| -> Value {
            json!({"type": "job", "id": self.jobs.start_live(work), "title": title, "msg": msg})
        };

        let Some(does) = b.does.as_deref() else {
            // a plain command from buttons.toml
            if let Some(q) = ask(&[("name", arg), ("label", &label)], vec![]) {
                return q;
            }
            let cmd: Vec<String> = b.run.iter().map(|a| fill(a, &[("name", arg)])).collect();
            let (show_total, t) = (b.show.as_deref() == Some("total"), title.clone());
            return live_job(b.wait.as_deref().unwrap_or("Working..."), Box::new(move |live| {
                let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
                let out = sh_live(&args, &live);
                let total: Vec<Value> = out.lines().filter(|l| l.starts_with("Total")).map(|l| line(l, "")).collect();
                result(&t, if show_total && !total.is_empty() { total } else { plain_lines(&out) })
            }));
        };

        let t = title.clone();
        match does {
            "open_docker" => self.docker_screen(),
            "open_packages" => self.packages_screen(),
            "open_audit" => audit_screen(),
            "open_vpn" => self.vpn_screen(),
            "open_claude_remote" => self.claude_remote_screen(),
            "open_backups" => self.backups_screen(),
            "open_drives" => self.drives_screen(),
            "backup_now" => {
                let unit = backup_unit(b.screen.strip_prefix("backup_").unwrap_or(""));
                ask(&[], vec![]).unwrap_or_else(|| match sh(&["systemctl", "start", "--no-block", unit]) {
                    out if out.is_empty() => self.watch(unit),
                    out => result(&title, plain_lines(&out)),
                })
            }
            "remote_control_pane" => result(&title, remote_control_pane().iter().map(|l| line(l.as_str(), "")).collect()),
            "disk_health" => job(b.wait.as_deref().unwrap_or("Working..."), Box::new(move || result(&t, disk_health()))),
            "grant" => self.grant_screen(),
            "update_app" => self.update_app(),
            "update_stack" => {
                let p = compose_project(arg);
                ask(&[("project", &p)], vec![])
                    .unwrap_or_else(|| job("Updating...", Box::new(move || update_stacks(t, vec![p]))))
            }
            "update_all" => {
                let stacks = compose_projects();
                ask(&[("count", &stacks.len().to_string())], vec![])
                    .unwrap_or_else(|| job("Updating every stack...", Box::new(move || update_stacks(t, stacks))))
            }
            "restart_container" => {
                let targets: Vec<String> = if GLUETUN_STACK.contains(&arg) {
                    GLUETUN_STACK.iter().map(|s| s.to_string()).collect()
                } else {
                    vec![arg.to_string()]
                };
                ask(&[("targets", &targets.join(", "))], vec![])
                    .unwrap_or_else(|| job("Restarting...", Box::new(move || restart(t, targets))))
            }
            "stop_container" => {
                // stopping gluetun takes its network away: stop the stack, gluetun last
                let targets: Vec<String> = if arg == "gluetun" {
                    GLUETUN_STACK.iter().rev().map(|s| s.to_string()).collect()
                } else {
                    vec![arg.to_string()]
                };
                ask(&[("targets", &targets.join(", "))], vec![]).unwrap_or_else(|| {
                    job("Stopping...", Box::new(move || {
                        let mut cmd = vec!["docker", "stop"];
                        cmd.extend(targets.iter().map(String::as_str));
                        result(&t, plain_lines(&sh(&cmd)))
                    }))
                })
            }
            "restart_all" => {
                let running: Vec<String> = containers().into_iter().filter(|c| c.status.starts_with("Up")).map(|c| c.name).collect();
                let order = gluetun_first(&running);
                ask(&[("count", &order.len().to_string())], vec![])
                    .unwrap_or_else(|| job("Restarting everything...", Box::new(move || restart(t, order))))
            }
            "start_stopped" => {
                let stopped: Vec<String> = containers().into_iter().filter(|c| !c.status.starts_with("Up")).map(|c| c.name).collect();
                if stopped.is_empty() {
                    return result(&title, vec![line("Nothing is stopped.", "green")]);
                }
                ask(&[("list", &stopped.join(", "))], vec![]).unwrap_or_else(|| {
                    job("Starting...", Box::new(move || {
                        let mut cmd = vec!["docker", "start"];
                        cmd.extend(stopped.iter().map(String::as_str));
                        result(&t, plain_lines(&sh(&cmd)))
                    }))
                })
            }
            "upgrade" => ask(&[], vec![]).unwrap_or_else(|| {
                live_job("Upgrading... this can take a few minutes", Box::new(move |live| {
                    let out = lines(&sh_live(&["omv-upgrade"], &live));
                    let mut l: Vec<Value> = out.iter().filter(|l| l.contains(" upgraded,")).map(|l| line(l, "")).collect();
                    l.push(line("", ""));
                    l.extend(out[out.len().saturating_sub(30)..].iter().map(|x| line(x, "")));
                    result(&t, l)
                }))
            }),
            "check_updates" => job("Checking for updates...", Box::new(move || {
                sh(&["apt-get", "update", "-q"]);
                App::packages_after_check()
            })),
            "cleanup" => {
                let gone: Vec<String> = sh(&["apt-get", "-s", "autoremove"])
                    .lines()
                    .filter_map(|l| l.strip_prefix("Remv ").and_then(|r| r.split_whitespace().next()).map(String::from))
                    .collect();
                if gone.is_empty() {
                    return result(&title, vec![line("Nothing to remove.", "green")]);
                }
                let extra = gone.iter().take(20).map(|g| line(g, "")).collect();
                ask(&[("count", &gone.len().to_string())], extra).unwrap_or_else(|| {
                    job("Removing...", Box::new(move || {
                        let out = lines(&sh(&["apt-get", "-y", "autoremove"]));
                        sh(&["apt-get", "clean"]);
                        result(&t, out[out.len().saturating_sub(10)..].iter().map(|x| line(x, "")).collect())
                    }))
                })
            }
            "reboot" => ask(&[], vec![]).unwrap_or_else(|| {
                let out = sh(&["systemctl", "reboot"]);
                result(&title, vec![line(if out.is_empty() { "Rebooting...".into() } else { out }, "")])
            }),
            other => result(&title, vec![line(format!("This app doesn't know {other:?}."), "red")]),
        }
    }

    /// After apt-get update: the Packages screen with fresh data. Needs no App
    /// (runs on the job thread), so it rebuilds the buttons from the installed file.
    fn packages_after_check() -> Value {
        match Config::load(&crate::buttons_path()) {
            Ok(cfg) => App { cfg, jobs: Jobs::default(), stepup: StepUp::new(crate::state_dir()) }.packages_screen(),
            Err(e) => result("Packages", vec![line(e, "red")]),
        }
    }
}

fn audit_screen() -> Value {
    let (lines, buttons) = match audit_report() {
        Some(r) if r.trim().is_empty() => (vec![line("All clear: claude has nothing beyond its allowlist.", "green")], vec![]),
        Some(r) => {
            let mut l: Vec<Value> = r.lines().filter(|x| x.starts_with("- ")).map(|x| line(x, "red")).collect();
            l.extend([line("", ""), line("Accept only if these are your own changes.", "")]);
            (l, vec![button("Accept", "DANGER", "audit:accept".into())])
        }
        None => (vec![line("Can't read the audit report.", "red")], vec![]),
    };
    screen("open:audit", "Audit", lines, buttons, Some("Back"))
}

/// Tailscale (native, tailscaled): state, address, route, devices. Needs no sudo.
fn tailscale_lines() -> Vec<Value> {
    let Ok(d) = serde_json::from_str::<Value>(&plain(&["tailscale", "status", "--json"])) else {
        return vec![line("Tailscale: not answering", "red")];
    };
    let me = &d["Self"];
    let state = d["BackendState"].as_str().unwrap_or("?");
    if state != "Running" || me["Online"] != true {
        return vec![line(format!("Tailscale: {}", state.to_lowercase()), "red")];
    }
    let strs = |v: &Value| -> Vec<String> { v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect() };
    let ip = strs(&me["TailscaleIPs"]).into_iter().find(|a| a.contains('.')).unwrap_or_else(|| "?".into());
    let routes = strs(&me["PrimaryRoutes"]).join(", ");
    let expiry = match me["KeyExpiry"].as_str() {
        Some(e) => format!("key expires {}", e.get(..10).unwrap_or(e)),
        None => "key never expires".into(),
    };
    let mut peers: Vec<&Value> = d["Peer"].as_object().into_iter().flat_map(|m| m.values()).collect();
    peers.sort_by_key(|p| p["Online"] != true);
    let devices: Vec<String> = peers.iter().map(|p| {
        let host = p["HostName"].as_str().unwrap_or("?");
        let name = if host == "localhost" { p["OS"].as_str().unwrap_or(host) } else { host };
        format!("{name} {}", if p["Online"] == true { "●" } else { "○" })
    }).collect();
    vec![
        line(format!("Tailscale: online · {ip}"), "green"),
        line(format!("{} · {expiry}", if routes.is_empty() { "no subnet route".into() } else { routes }), ""),
        line(format!("Devices: {}", if devices.is_empty() { "none".into() } else { devices.join(", ") }), ""),
    ]
}

/// "3 files, +40 -12 lines" for a unified diff.
fn diff_summary(diff: &str) -> String {
    let files = diff.lines().filter(|l| l.starts_with("+++ ")).count();
    let add = diff.lines().filter(|l| l.starts_with('+') && !l.starts_with("+++ ")).count();
    let del = diff.lines().filter(|l| l.starts_with('-') && !l.starts_with("--- ")).count();
    format!("{files} file{} changed, +{add} -{del} lines", if files == 1 { "" } else { "s" })
}

/// A unified diff, coloured: added green, removed red.
fn diff_lines(diff: &str) -> Vec<Value> {
    diff.lines().filter(|l| !l.starts_with("diff ")).map(|l| {
        let c = if l.starts_with("+++ ") || l.starts_with("--- ") || l.starts_with("@@") { "dim" }
                else if l.starts_with('+') { "green" } else if l.starts_with('-') { "red" } else { "" };
        line(l, c)
    }).collect()
}

/// One drive from `smartctl -i -H -A`: ("sda  MODEL", "PASSED · 0 bad · 31°C · 4.3 yrs", ok).
fn smart_summary(dev: &str, s: &str) -> (String, String, bool) {
    let field = |key: &str| s.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string());
    let attr = |id: &str| -> Option<u64> {
        s.lines().map(|l| l.split_whitespace().collect::<Vec<_>>()).find(|t| t.len() >= 10 && t[0] == id).and_then(|t| {
            t[9].chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()
        })
    };
    let num = |v: Option<String>| {
        v.and_then(|v| v.replace(',', "").chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u64>().ok())
    };
    let model = field("Device Model:").or_else(|| field("Model Number:")).unwrap_or_else(|| "?".into());
    let passed = s.contains("PASSED") || s.contains("SMART Health Status: OK");
    let nvme = dev.contains("nvme");
    let bad = if nvme {
        num(field("Media and Data Integrity Errors:")).unwrap_or(0)
    } else {
        [attr("5"), attr("197"), attr("198")].iter().flatten().sum()
    };
    let temp = if nvme { num(field("Temperature:")) } else { attr("194") };
    let hours = if nvme { num(field("Power On Hours:")) } else { attr("9") };
    let mut facts = vec![if passed { "PASSED".to_string() } else { "FAILING or unreadable".to_string() }, format!("{bad} bad")];
    if let Some(t) = temp {
        facts.push(format!("{t}°C"));
    }
    if let Some(h) = hours {
        facts.push(format!("{:.1} yrs", h as f64 / 8766.0));
    }
    if nvme {
        if let Some(u) = field("Percentage Used:") {
            facts.push(format!("{u} worn"));
        }
    }
    (format!("{}  {model}", dev.trim_start_matches("/dev/")), facts.join(" · "), passed && bad == 0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn smart_summary_ata_and_nvme() {
        let ata = "Device Model:     ST4000NE001-2MA101\nSMART overall-health self-assessment test result: PASSED\n\
  5 Reallocated_Sector_Ct   0x0033   200   200   140    Pre-fail  Always       -       0\n\
  9 Power_On_Hours          0x0032   049   049   000    Old_age   Always       -       37346\n\
194 Temperature_Celsius     0x0022   157   157   000    Old_age   Always       -       38 (Min/Max 14/50)\n\
197 Current_Pending_Sector  0x0032   200   200   000    Old_age   Always       -       2";
        let (t, f, ok) = super::smart_summary("/dev/sda", ata);
        assert_eq!(t, "sda  ST4000NE001-2MA101");
        assert_eq!(f, "PASSED · 2 bad · 38°C · 4.3 yrs");
        assert!(!ok);
        let nvme = "Model Number:                       Samsung SSD 980\nSMART overall-health self-assessment test result: PASSED\n\
Temperature:                        34 Celsius\nPercentage Used:                    11%\nPower On Hours:                     4,030\n\
Media and Data Integrity Errors:    0";
        let (t, f, ok) = super::smart_summary("/dev/nvme0n1", nvme);
        assert_eq!((t.as_str(), f.as_str(), ok), ("nvme0n1  Samsung SSD 980", "PASSED · 0 bad · 34°C · 0.5 yrs · 11% worn", true));
    }
}
