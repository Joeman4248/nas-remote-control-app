//! Just enough HTTP/1.1 for one page and a small JSON API behind Caddy:
//! one request per connection, then close.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 16 * 1024;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>, // names lowercased
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

pub fn read_request(stream: &TcpStream) -> Option<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut headers = HashMap::new();
    let mut total = line.len();
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h).ok()?;
        total += n;
        if n == 0 || total > MAX_HEADER_BYTES {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY_BYTES {
        return None;
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body).ok()?;

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (target, HashMap::new()),
    };
    Some(Request { method, path, query, headers, body })
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn respond(mut stream: &TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}
