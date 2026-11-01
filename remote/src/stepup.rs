//! The extra Face ID for Full grants: the remote checks a passkey itself, on
//! top of the Authelia login, so an unlocked phone with an open session isn't
//! enough to give claude root.
//!
//! The passkey is its own credential for remote.joe-nas.net. Registering it
//! needs a setup code from a file only root (and this service) can read, so
//! someone holding a web session can't add a passkey of their own.
//!
//! Plain WebAuthn, ES256 only (what iCloud Keychain and Bitwarden use):
//!   register: clientDataJSON + attestationObject (CBOR) → store the P-256 key
//!   verify:   clientDataJSON + authenticatorData + signature → check it

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const RP_ID: &str = "remote.joe-nas.net";
const ORIGIN: &str = "https://remote.joe-nas.net";
const CHALLENGE_LIFE: Duration = Duration::from_secs(120);

#[derive(Serialize, Deserialize, Clone)]
struct Credential {
    id: String,  // base64url credential id
    key: String, // base64url SEC1 public key (0x04 || x || y)
}

pub struct StepUp {
    dir: PathBuf,
    challenges: Mutex<HashMap<String, (Instant, String)>>, // challenge → (issued, what it's for)
}

impl StepUp {
    pub fn new(dir: impl Into<PathBuf>) -> StepUp {
        StepUp { dir: dir.into(), challenges: Mutex::new(HashMap::new()) }
    }

    fn creds_path(&self) -> PathBuf {
        self.dir.join("credentials.json")
    }

    pub fn code_path(&self) -> PathBuf {
        self.dir.join("setup-code")
    }

    fn creds(&self) -> Vec<Credential> {
        std::fs::read(self.creds_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn registered(&self) -> bool {
        !self.creds().is_empty()
    }

    pub fn credential_ids(&self) -> Vec<String> {
        self.creds().into_iter().map(|c| c.id).collect()
    }

    /// A fresh single-use challenge bound to `purpose` (an act, or "register").
    pub fn challenge(&self, purpose: &str) -> String {
        let c = b64url_encode(&random_bytes(32));
        let mut map = self.challenges.lock().unwrap();
        map.retain(|_, (t, _)| t.elapsed() < CHALLENGE_LIFE);
        map.insert(c.clone(), (Instant::now(), purpose.to_string()));
        c
    }

    fn take_challenge(&self, c: &str, purpose: &str) -> bool {
        match self.challenges.lock().unwrap().remove(c) {
            Some((t, p)) => t.elapsed() < CHALLENGE_LIFE && p == purpose,
            None => false,
        }
    }

    /// The setup code, created on first ask; joseph reads it with sudo.
    pub fn setup_code(&self) -> std::io::Result<()> {
        if self.code_path().exists() {
            return Ok(());
        }
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let digits: String = random_bytes(8).iter().map(|b| char::from(b'0' + b % 10)).collect();
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(self.code_path())?;
        writeln!(f, "{digits}")
    }

    fn client_data(&self, v: &Value, kind: &str, purpose: &str) -> Result<Vec<u8>, String> {
        let raw = b64url_decode(v["clientDataJSON"].as_str().unwrap_or("")).ok_or("bad clientDataJSON")?;
        let cd: Value = serde_json::from_slice(&raw).map_err(|_| "bad clientDataJSON")?;
        if cd["type"] != kind {
            return Err("wrong ceremony type".into());
        }
        if cd["origin"] != ORIGIN {
            return Err("wrong origin".into());
        }
        if !self.take_challenge(cd["challenge"].as_str().unwrap_or(""), purpose) {
            return Err("challenge expired or not for this button; try again".into());
        }
        Ok(raw)
    }

    /// Store a new passkey; needs the setup code.
    pub fn register(&self, v: &Value) -> Result<(), String> {
        let code = std::fs::read_to_string(self.code_path()).map_err(|_| "no setup code yet")?;
        if v["code"].as_str().map(str::trim) != Some(code.trim()) {
            return Err("wrong setup code".into());
        }
        self.client_data(v, "webauthn.create", "register")?;
        let att = b64url_decode(v["attestationObject"].as_str().unwrap_or("")).ok_or("bad attestationObject")?;
        let auth = cbor::map_get(&cbor::parse(&att)?, "authData").and_then(cbor::bytes).ok_or("no authData")?;
        check_auth_data(&auth)?;
        if auth[32] & 0x40 == 0 || auth.len() < 55 {
            return Err("no credential in the response".into());
        }
        let id_len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
        let id = auth.get(55..55 + id_len).ok_or("short authData")?;
        let cose = cbor::parse(&auth[55 + id_len..])?;
        let (kty, alg, crv) = (cbor::int_key(&cose, 1), cbor::int_key(&cose, 3), cbor::int_key(&cose, -1));
        if (kty.and_then(cbor::int), alg.and_then(cbor::int), crv.and_then(cbor::int)) != (Some(2), Some(-7), Some(1)) {
            return Err("only ES256 (P-256) passkeys are supported".into());
        }
        let x = cbor::int_key(&cose, -2).and_then(cbor::bytes).ok_or("no x")?;
        let y = cbor::int_key(&cose, -3).and_then(cbor::bytes).ok_or("no y")?;
        let key = [&[4u8][..], &x, &y].concat();
        VerifyingKey::from_sec1_bytes(&key).map_err(|_| "bad public key")?;
        let mut creds = self.creds();
        creds.push(Credential { id: b64url_encode(id), key: b64url_encode(&key) });
        let tmp = self.dir.join("credentials.json.new");
        std::fs::write(&tmp, serde_json::to_vec(&creds).unwrap()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, self.creds_path()).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(self.code_path()); // one use
        Ok(())
    }

    /// Check a Face ID assertion made for exactly this act.
    pub fn verify(&self, v: &Value, purpose: &str) -> Result<(), String> {
        let id = v["id"].as_str().unwrap_or("");
        let cred = self.creds().into_iter().find(|c| c.id == id).ok_or("unknown passkey")?;
        let client = self.client_data(v, "webauthn.get", purpose)?;
        let auth = b64url_decode(v["authenticatorData"].as_str().unwrap_or("")).ok_or("bad authenticatorData")?;
        check_auth_data(&auth)?;
        let sig = b64url_decode(v["signature"].as_str().unwrap_or("")).ok_or("bad signature")?;
        let sig = Signature::from_der(&sig).map_err(|_| "bad signature")?;
        let key = VerifyingKey::from_sec1_bytes(&b64url_decode(&cred.key).unwrap_or_default()).map_err(|_| "bad stored key")?;
        let signed = [auth.as_slice(), Sha256::digest(&client).as_slice()].concat();
        key.verify(&signed, &sig).map_err(|_| "Face ID check failed".to_string())
    }
}

/// rpIdHash must be ours; the user must have been present and verified (Face ID).
fn check_auth_data(auth: &[u8]) -> Result<(), String> {
    if auth.len() < 37 {
        return Err("short authenticatorData".into());
    }
    if auth[..32] != *Sha256::digest(RP_ID.as_bytes()).as_slice() {
        return Err("passkey is for another site".into());
    }
    if auth[32] & 0x01 == 0 || auth[32] & 0x04 == 0 {
        return Err("Face ID (user verification) didn't happen".into());
    }
    Ok(())
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("/dev/urandom");
    b
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let vals: Vec<u32> = s
        .bytes()
        .map(|c| B64.iter().position(|&b| b == c).or(match c { b'+' => Some(62), b'/' => Some(63), _ => None }))
        .collect::<Option<Vec<usize>>>()?
        .into_iter()
        .map(|v| v as u32)
        .collect();
    let mut out = vec![];
    for chunk in vals.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, v)| n | v << (18 - 6 * i));
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

/// Just enough CBOR for WebAuthn attestation objects and COSE keys.
mod cbor {
    #[derive(Debug, Clone)]
    #[allow(dead_code)] // arrays are parsed (to step over them) but never read
    pub enum Item {
        Int(i64),
        Bytes(Vec<u8>),
        Text(String),
        Array(Vec<Item>),
        Map(Vec<(Item, Item)>),
        Other,
    }

    pub fn parse(data: &[u8]) -> Result<Item, String> {
        let mut pos = 0;
        item(data, &mut pos)
    }

    fn take<'a>(d: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], String> {
        let s = d.get(*pos..*pos + n).ok_or("short CBOR")?;
        *pos += n;
        Ok(s)
    }

    fn item(d: &[u8], pos: &mut usize) -> Result<Item, String> {
        let first = take(d, pos, 1)?[0];
        let (major, info) = (first >> 5, first & 31);
        let len = match info {
            0..=23 => info as u64,
            24 => take(d, pos, 1)?[0] as u64,
            25 => u16::from_be_bytes(take(d, pos, 2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(take(d, pos, 4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(take(d, pos, 8)?.try_into().unwrap()),
            _ => return Err("unsupported CBOR".into()),
        };
        Ok(match major {
            0 => Item::Int(len as i64),
            1 => Item::Int(-1 - len as i64),
            2 => Item::Bytes(take(d, pos, len as usize)?.to_vec()),
            3 => Item::Text(String::from_utf8_lossy(take(d, pos, len as usize)?).into_owned()),
            4 => Item::Array((0..len).map(|_| item(d, pos)).collect::<Result<_, _>>()?),
            5 => Item::Map((0..len).map(|_| Ok((item(d, pos)?, item(d, pos)?))).collect::<Result<_, String>>()?),
            6 => item(d, pos)?, // tag: keep the tagged item
            _ => Item::Other,
        })
    }

    pub fn map_get(m: &Item, key: &str) -> Option<Item> {
        match m {
            Item::Map(kv) => kv.iter().find(|(k, _)| matches!(k, Item::Text(t) if t == key)).map(|(_, v)| v.clone()),
            _ => None,
        }
    }

    pub fn int_key(m: &Item, key: i64) -> Option<Item> {
        match m {
            Item::Map(kv) => kv.iter().find(|(k, _)| matches!(k, Item::Int(i) if *i == key)).map(|(_, v)| v.clone()),
            _ => None,
        }
    }

    pub fn bytes(i: Item) -> Option<Vec<u8>> {
        match i {
            Item::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn int(i: Item) -> Option<i64> {
        match i {
            Item::Int(n) => Some(n),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    #[test]
    fn base64url_round_trip() {
        for n in 0..40 {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(b64url_decode(&b64url_encode(&data)).unwrap(), data);
        }
        assert_eq!(b64url_encode(b"hello"), "aGVsbG8");
    }

    /// A full register + verify round trip with a software authenticator.
    #[test]
    fn register_and_verify() {
        let dir = std::env::temp_dir().join(format!("stepup-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = StepUp::new(&dir);
        s.setup_code().unwrap();
        let code = std::fs::read_to_string(s.code_path()).unwrap();

        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
        let (x, y) = (&point.as_bytes()[1..33], &point.as_bytes()[33..65]);
        let rp = Sha256::digest(RP_ID.as_bytes()).to_vec();
        let cred_id = vec![1u8, 2, 3, 4];

        // attestationObject = {"fmt": "none", "attStmt": {}, "authData": ...}
        let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        cose.extend(x);
        cose.extend([0x22, 0x58, 0x20]);
        cose.extend(y);
        let mut auth = rp.clone();
        auth.push(0x45); // UP | UV | AT
        auth.extend([0, 0, 0, 0]);
        auth.extend([0u8; 16]);
        auth.extend([0, 4]);
        auth.extend(&cred_id);
        auth.extend(&cose);
        let mut att = vec![0xa3, 0x63];
        att.extend(b"fmt");
        att.extend([0x64]);
        att.extend(b"none");
        att.extend([0x67]);
        att.extend(b"attStmt");
        att.push(0xa0);
        att.extend([0x68]);
        att.extend(b"authData");
        att.extend([0x59, (auth.len() >> 8) as u8, auth.len() as u8]);
        att.extend(&auth);

        let ch = s.challenge("register");
        let cd = format!(r#"{{"type":"webauthn.create","challenge":"{ch}","origin":"{ORIGIN}"}}"#);
        let reg = serde_json::json!({"code": code.trim(), "clientDataJSON": b64url_encode(cd.as_bytes()),
                                     "attestationObject": b64url_encode(&att)});
        s.register(&reg).unwrap();
        assert!(s.registered() && !s.code_path().exists());

        let assert_for = |purpose: &str, sign_purpose: &str| {
            let ch = s.challenge(sign_purpose);
            let cd = format!(r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{ORIGIN}"}}"#);
            let mut a = rp.clone();
            a.push(0x05);
            a.extend([0, 0, 0, 1]);
            let signed = [a.as_slice(), Sha256::digest(cd.as_bytes()).as_slice()].concat();
            let sig: Signature = sk.sign(&signed);
            let v = serde_json::json!({"id": b64url_encode(&cred_id), "clientDataJSON": b64url_encode(cd.as_bytes()),
                                       "authenticatorData": b64url_encode(&a), "signature": b64url_encode(&sig.to_der().to_bytes())});
            s.verify(&v, purpose)
        };
        assert!(assert_for("grant:full:15", "grant:full:15").is_ok());
        assert!(assert_for("grant:full:30", "grant:full:15").is_err(), "a challenge for one act can't be used for another");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
