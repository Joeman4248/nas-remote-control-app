//! Which containers run an older image than their registry has. For each image the
//! registry is asked for the tag's current digest (a HEAD request through curl: nothing
//! is pulled, and Docker Hub doesn't count it against the pull limit) and that is compared
//! with the digests of the image the container runs. Checked every 6 hours and from
//! Docker › All › Check Updates; the last result is kept in the state dir.

use crate::sh::{plain, sh};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

const EVERY: u64 = 6 * 3600;
const ACCEPT: &str = "Accept: application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json";

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum State {
    Current,
    Update,
    Unknown(String),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Image {
    pub image: String,
    pub containers: Vec<String>,
    pub state: State,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Report {
    pub checked: u64,
    pub images: Vec<Image>,
}

impl Report {
    /// Containers with a newer image waiting, sorted.
    pub fn stale(&self) -> Vec<String> {
        let mut v: Vec<String> = self.images.iter().filter(|i| i.state == State::Update)
            .flat_map(|i| i.containers.clone()).collect();
        v.sort();
        v
    }
}

static REPORT: Mutex<Option<Report>> = Mutex::new(None);
static CHECKING: Mutex<()> = Mutex::new(());

fn file() -> String {
    format!("{}/updates.json", crate::state_dir())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn latest() -> Option<Report> {
    REPORT.lock().unwrap().clone()
}

/// Load the last report, then check whenever it's older than 6 hours.
pub fn start() {
    if let Some(r) = std::fs::read_to_string(file()).ok().and_then(|t| serde_json::from_str::<Report>(&t).ok()) {
        *REPORT.lock().unwrap() = Some(r);
    }
    std::thread::spawn(|| loop {
        if latest().is_none_or(|r| now().saturating_sub(r.checked) >= EVERY) {
            check();
        }
        std::thread::sleep(Duration::from_secs(600));
    });
}

/// Check now (waits for a check already running instead of starting a second one).
pub fn check() -> Option<Report> {
    let _one = CHECKING.lock().unwrap();
    let r = run()?;
    let _ = std::fs::write(file(), serde_json::to_string(&r).unwrap_or_default());
    *REPORT.lock().unwrap() = Some(r.clone());
    Some(r)
}

/// Check again in the background (after an update changed what runs).
pub fn recheck_soon() {
    std::thread::spawn(check);
}

fn run() -> Option<Report> {
    let names: Vec<String> = sh(&["docker", "ps", "-a", "--format", "{{.Names}}"]).lines().map(String::from).collect();
    if names.is_empty() {
        return None; // docker unreachable: keep the last report
    }
    let mut args = vec!["docker", "inspect", "-f", "{{.Name}}|{{.Config.Image}}|{{.Image}}"];
    args.extend(names.iter().map(String::as_str));
    // image name -> (containers, image ids they run)
    let mut by_image: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    for l in sh(&args).lines() {
        let f: Vec<&str> = l.split('|').collect();
        if let [name, image, id] = f.as_slice() {
            let e = by_image.entry(image.to_string()).or_default();
            e.0.push(name.trim_start_matches('/').to_string());
            if !e.1.contains(&id.to_string()) {
                e.1.push(id.to_string());
            }
        }
    }
    let images = std::thread::scope(|s| {
        let hs: Vec<_> = by_image.into_iter().map(|(image, (containers, ids))| s.spawn(move || {
            let local: Vec<String> = ids.iter()
                .flat_map(|id| sh(&["docker", "inspect", "-f", "{{range .RepoDigests}}{{.}} {{end}}", id])
                    .split_whitespace().filter_map(|d| d.split_once('@').map(|x| x.1.to_string())).collect::<Vec<_>>())
                .collect();
            let state = if local.is_empty() {
                State::Unknown("built here, no registry digest".into())
            } else {
                match remote_digest(&image) {
                    Ok(d) if local.contains(&d) => State::Current,
                    Ok(_) => State::Update,
                    Err(e) => State::Unknown(e),
                }
            };
            Image { image, containers, state }
        })).collect();
        hs.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    Some(Report { checked: now(), images })
}

/// "lscr.io/linuxserver/plex:latest" -> ("lscr.io", "linuxserver/plex", "latest")
fn split(image: &str) -> (String, String, String) {
    let image = image.split('@').next().unwrap_or(image);
    let (name, tag) = match image.rsplit_once(':') {
        Some((n, t)) if !t.contains('/') => (n, t),
        _ => (image, "latest"),
    };
    let first = name.split('/').next().unwrap_or("");
    if name.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost") {
        (first.into(), name[first.len() + 1..].into(), tag.into())
    } else if name.contains('/') {
        ("registry-1.docker.io".into(), name.into(), tag.into())
    } else {
        ("registry-1.docker.io".into(), format!("library/{name}"), tag.into())
    }
}

/// HEAD the manifest; (status, headers of the last response, lower-case names).
fn head(url: &str, token: Option<&str>) -> (u32, BTreeMap<String, String>) {
    let auth = token.map(|t| format!("Authorization: Bearer {t}"));
    // trusted: lscr.io redirects to ghcr.io, and the (anonymous) token must follow
    let mut cmd = vec!["curl", "-sSI", "--location-trusted", "-m", "20", "-H", ACCEPT];
    if let Some(a) = &auth {
        cmd.extend(["-H", a.as_str()]);
    }
    cmd.push(url);
    let out = plain(&cmd);
    let last = out.split("\r\n\r\n").filter(|b| b.starts_with("HTTP/")).last().unwrap_or("");
    let mut lines = last.lines();
    let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).unwrap_or(0);
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())).collect();
    (status, headers)
}

fn remote_digest(image: &str) -> Result<String, String> {
    let (reg, repo, tag) = split(image);
    let url = format!("https://{reg}/v2/{repo}/manifests/{tag}");
    let (mut status, mut h) = head(&url, None);
    if status == 401 {
        // anonymous pull token from the realm the registry names
        let www = h.get("www-authenticate").cloned().unwrap_or_default();
        let field = |k: &str| www.split(&format!("{k}=\"")).nth(1).and_then(|r| r.split('"').next()).unwrap_or("").to_string();
        let token_url = format!("{}?service={}&scope=repository:{repo}:pull", field("realm"), field("service"));
        let v: serde_json::Value = serde_json::from_str(&plain(&["curl", "-sS", "-m", "20", &token_url])).unwrap_or_default();
        let token = v["token"].as_str().or(v["access_token"].as_str()).unwrap_or("").to_string();
        (status, h) = head(&url, Some(&token));
    }
    match (status, h.get("docker-content-digest")) {
        (200, Some(d)) => Ok(d.clone()),
        (0, _) => Err(format!("{reg} unreachable")),
        (s, _) => Err(format!("{reg} answered {s}")),
    }
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn names() {
        let t = |s: &str| { let (a, b, c) = split(s); format!("{a} {b} {c}") };
        assert_eq!(t("qmcgaw/gluetun"), "registry-1.docker.io qmcgaw/gluetun latest");
        assert_eq!(t("redis:7"), "registry-1.docker.io library/redis 7");
        assert_eq!(t("lscr.io/linuxserver/plex:latest"), "lscr.io linuxserver/plex latest");
        assert_eq!(t("ghcr.io/linuxserver/librewolf"), "ghcr.io linuxserver/librewolf latest");
        assert_eq!(t("localhost:5000/x:1"), "localhost:5000 x 1");
    }
}
