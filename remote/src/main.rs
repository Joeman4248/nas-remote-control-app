//! nas-remote: the nas app's buttons as a web page at remote.joe-nas.net.
//!
//! Caddy sends every request through Authelia (passkey / Face ID) first and
//! passes the signed-in user as Remote-User. This server listens on localhost
//! only, and a firewall rule keeps the claude user off its port, so the only
//! way in is through that login. It runs as the nasremote user; every command
//! goes through sudo, limited to system/remote/nas-remote.sudoers.
//!
//!   GET  /             the page
//!   POST /api/act      {"act": "...", "confirmed": bool} → a screen/result/confirm/job
//!   POST /api/register {"code", "clientDataJSON", "attestationObject"} → set up the Full passkey
//!   GET  /api/job?id=  a job's result, or {"type": "running"}
//!
//! `nas-remote --check` only validates buttons.toml (NAS_BUTTONS) and exits.

mod config;
mod http;
mod jobs;
mod screens;
mod sh;
mod stepup;

use serde_json::{json, Value};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

const PAGE: &str = include_str!("../static/index.html");
const ICON: &[u8] = include_bytes!("../static/apple-touch-icon.png"); // drawn from static/icon.svg

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

pub fn state_dir() -> String {
    env_or("NAS_REMOTE_STATE", "/var/lib/nas-remote")
}

pub fn buttons_path() -> String {
    env_or("NAS_BUTTONS", "/usr/local/share/nas/buttons.toml")
}

fn main() {
    let addr = env_or("NAS_REMOTE_ADDR", "127.0.0.1:8765");
    let user = env_or("NAS_REMOTE_USER", "joseph");
    let cfg = config::Config::load(&buttons_path()).unwrap_or_else(|e| {
        eprintln!("nas-remote: {e}");
        std::process::exit(1)
    });
    if std::env::args().nth(1).as_deref() == Some("--check") {
        return println!("{}: {} buttons, ok", buttons_path(), cfg.buttons.len());
    }
    let app = screens::App::new(cfg);
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("nas-remote: can't listen on {addr}: {e}");
        std::process::exit(1)
    });
    eprintln!("nas-remote: listening on {addr} for {user}");
    let user: Arc<str> = user.into();
    for stream in listener.incoming().flatten() {
        let (app, user) = (app.clone(), user.clone());
        thread::spawn(move || handle(stream, &app, &user));
    }
}

fn handle(stream: TcpStream, app: &screens::App, user: &str) {
    let Some(req) = http::read_request(&stream) else {
        return http::respond(&stream, "400 Bad Request", "text/plain", b"bad request");
    };
    // Only through Authelia: Caddy sets Remote-User after a passkey login.
    if req.header("remote-user") != Some(user) {
        return http::respond(&stream, "403 Forbidden", "text/plain", b"sign in at auth.joe-nas.net");
    }
    let reply = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => return http::respond(&stream, "200 OK", "text/html; charset=utf-8", PAGE.as_bytes()),
        ("GET", "/apple-touch-icon.png" | "/favicon.ico") => return http::respond(&stream, "200 OK", "image/png", ICON),
        // a custom header can't be sent cross-site without CORS, which this server never allows
        ("POST", "/api/act") if req.header("x-nas-remote") == Some("1") => {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let act = body["act"].as_str().unwrap_or("open:main");
            with_header(app.act(act, body["confirmed"].as_bool().unwrap_or(false), &body["faceid"]))
        }
        ("POST", "/api/register") if req.header("x-nas-remote") == Some("1") => {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let lines = match app.stepup.register(&body) {
                Ok(()) => json!([["Face ID for Full is set up.", "green"], ["", ""], ["Full grants now ask for it.", ""]]),
                Err(e) => json!([["Not set up", "red"], [e, ""]]),
            };
            with_header(json!({"type": "result", "title": "Face ID for Full", "lines": lines}))
        }
        ("GET", "/api/job") => match req.query.get("id").and_then(|i| i.parse().ok()).map(|id| app.jobs.poll(id)) {
            Some(Some(Some(done))) => with_header(done),
            Some(Some(None)) => json!({"type": "running"}),
            _ => with_header(json!({"type": "result", "title": "Gone",
                                    "lines": [["That job's result is no longer here.", "dim"]]})),
        },
        _ => return http::respond(&stream, "404 Not Found", "text/plain", b"not found"),
    };
    http::respond(&stream, "200 OK", "application/json", reply.to_string().as_bytes());
}

/// Every screen carries a fresh header line.
fn with_header(mut v: Value) -> Value {
    v["header"] = screens::header();
    v
}
