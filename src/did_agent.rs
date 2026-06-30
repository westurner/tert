//! ssh-agent-style Ed25519 `did:key` signing agent (Rust counterpart of
//! `tert.did_agent`).
//!
//! The agent holds the private key (a 32-byte Ed25519 seed) in memory only and
//! signs requests over a Unix domain socket, so the private key is never written
//! to disk. The wire protocol matches the Python implementation:
//!
//! ```text
//! PING           -> OK pong
//! DID            -> OK did:key:z6Mk...
//! PUBKEY         -> OK <base64 public key>
//! SIGN <base64>  -> OK <base64 signature>
//! <other>        -> ERR <message>
//! ```

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::{did_key_from_pubkey, pubkey_from_seed, sign, verify, SEED_BYTES};

pub const DEFAULT_SOCK_ENV: &str = "DID_AGENT_SOCK";
pub const SEED_ENV: &str = "DID_AGENT_SEED";

// --- base64 (standard alphabet, dependency-free) ---------------------------

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 encoding with padding.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn b64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard base64 decoding (ignores padding). Returns None on invalid input.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut vals: Vec<u32> = Vec::new();
    for c in text.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        vals.push(b64_value(c)?);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let n = (chunk[0] << 18)
            | (chunk[1] << 12)
            | (chunk.get(2).copied().unwrap_or(0) << 6)
            | chunk.get(3).copied().unwrap_or(0);
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if t.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

// --- seed handling ---------------------------------------------------------

/// Generate a fresh random 32-byte seed from the OS CSPRNG.
pub fn generate_seed() -> io::Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(&mut seed)?;
    Ok(seed)
}

/// Decode a 32-byte seed from base64 or hex text.
pub fn decode_seed(text: &str) -> Option<[u8; 32]> {
    let t = text.trim();
    if let Some(b) = base64_decode(t) {
        if b.len() == SEED_BYTES {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            return Some(s);
        }
    }
    if let Some(b) = hex_decode(t) {
        if b.len() == SEED_BYTES {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            return Some(s);
        }
    }
    None
}

/// Resolve the agent seed from env (`DID_AGENT_SEED`), a seed file, or generate.
pub fn load_seed(seed_file: Option<&str>) -> io::Result<([u8; 32], &'static str)> {
    if let Ok(text) = std::env::var(SEED_ENV) {
        if let Some(seed) = decode_seed(&text) {
            return Ok((seed, "env"));
        }
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid DID_AGENT_SEED"));
    }
    if let Some(path) = seed_file {
        let text = std::fs::read_to_string(path)?;
        let seed = decode_seed(&text)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seed file"))?;
        return Ok((seed, "file"));
    }
    Ok((generate_seed()?, "ephemeral"))
}

// --- agent core ------------------------------------------------------------

/// Holds an Ed25519 seed in memory and signs with it.
pub struct DidAgent {
    seed: [u8; 32],
    pubkey: [u8; 32],
    did: String,
}

impl DidAgent {
    pub fn new(seed: [u8; 32]) -> DidAgent {
        let pubkey = pubkey_from_seed(&seed);
        let did = did_key_from_pubkey(&pubkey);
        DidAgent { seed, pubkey, did }
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn pubkey(&self) -> [u8; 32] {
        self.pubkey
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        sign(&self.seed, data)
    }

    pub fn verify(&self, data: &[u8], sig: &[u8; 64]) -> bool {
        verify(&self.pubkey, data, sig)
    }
}

/// Process a single protocol request line and return the response line.
pub fn handle_line(agent: &DidAgent, line: &str) -> String {
    let line = line.trim();
    if line.is_empty() {
        return "ERR empty request".to_string();
    }
    let mut parts = line.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("").to_uppercase();
    let arg = parts.next().unwrap_or("");

    match cmd.as_str() {
        "PING" => "OK pong".to_string(),
        "DID" => format!("OK {}", agent.did()),
        "PUBKEY" => format!("OK {}", base64_encode(&agent.pubkey())),
        "SIGN" => {
            if arg.is_empty() {
                return "ERR SIGN requires base64 data".to_string();
            }
            match base64_decode(arg) {
                Some(data) => format!("OK {}", base64_encode(&agent.sign(&data))),
                None => "ERR invalid base64".to_string(),
            }
        }
        other => format!("ERR unknown command: {}", other),
    }
}

// --- server ----------------------------------------------------------------

fn handle_conn(stream: UnixStream, agent: &DidAgent) -> io::Result<()> {
    let reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_line(agent, &line);
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

/// Run the agent server on `path`. If `stop` is provided, the loop exits when it
/// becomes true. The socket is created with owner-only (0600) permissions.
pub fn serve(path: &str, agent: DidAgent, stop: Option<Arc<AtomicBool>>) -> io::Result<()> {
    if Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let agent = Arc::new(agent);

    loop {
        if let Some(ref s) = stop {
            if s.load(Ordering::Relaxed) {
                break;
            }
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).ok();
                let agent = Arc::clone(&agent);
                std::thread::spawn(move || {
                    let _ = handle_conn(stream, &agent);
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                let _ = std::fs::remove_file(path);
                return Err(e);
            }
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}

// --- client ----------------------------------------------------------------

/// Client for a running agent.
pub struct DidAgentClient {
    pub sock_path: String,
}

impl DidAgentClient {
    pub fn new(sock_path: impl Into<String>) -> DidAgentClient {
        DidAgentClient {
            sock_path: sock_path.into(),
        }
    }

    /// Resolve from `DID_AGENT_SOCK` if no explicit path is given.
    pub fn from_env(sock_path: Option<String>) -> io::Result<DidAgentClient> {
        let path = sock_path
            .or_else(|| std::env::var(DEFAULT_SOCK_ENV).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no agent socket configured"))?;
        Ok(DidAgentClient::new(path))
    }

    fn request(&self, line: &str) -> io::Result<String> {
        let mut stream = UnixStream::connect(&self.sock_path)?;
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        let response = response.trim_end().to_string();
        if let Some(rest) = response.strip_prefix("OK ") {
            Ok(rest.to_string())
        } else if response == "OK" {
            Ok(String::new())
        } else {
            let msg = response.strip_prefix("ERR ").unwrap_or(&response).to_string();
            Err(io::Error::new(io::ErrorKind::Other, msg))
        }
    }

    pub fn ping(&self) -> io::Result<String> {
        self.request("PING")
    }

    pub fn did(&self) -> io::Result<String> {
        self.request("DID")
    }

    pub fn pubkey(&self) -> io::Result<Vec<u8>> {
        let b64 = self.request("PUBKEY")?;
        base64_decode(&b64).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad base64"))
    }

    pub fn sign(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let b64 = self.request(&format!("SIGN {}", base64_encode(data)))?;
        base64_decode(&b64).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad base64"))
    }
}

// --- CLI -------------------------------------------------------------------

/// Default agent socket path in a per-user runtime directory.
pub fn default_sock_path() -> String {
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    format!("{}/tert-did-agent-{}.sock", runtime, std::process::id())
}

/// CLI entry point for the `did-agent` binary.
///
/// Usage: `did-agent [serve|did|pubkey|sign|ping] [DATA] [--sock PATH] [--seed-file FILE] [--print-env]`
pub fn cli_main(args: &[String]) -> i32 {
    let mut action = "serve".to_string();
    let mut data: Option<String> = None;
    let mut sock: Option<String> = None;
    let mut seed_file: Option<String> = None;
    let mut print_env = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sock" => {
                i += 1;
                sock = args.get(i).cloned();
            }
            "--seed-file" => {
                i += 1;
                seed_file = args.get(i).cloned();
            }
            "--print-env" => print_env = true,
            "serve" | "did" | "pubkey" | "sign" | "ping" => action = args[i].clone(),
            other if !other.starts_with("--") => data = Some(args[i].clone()),
            other => {
                eprintln!("error: unknown option {}", other);
                return 2;
            }
        }
        i += 1;
    }

    if action == "serve" {
        let (seed, source) = match load_seed(seed_file.as_deref()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {}", e);
                return 1;
            }
        };
        let agent = DidAgent::new(seed);
        let sock_path = sock
            .or_else(|| std::env::var(DEFAULT_SOCK_ENV).ok())
            .unwrap_or_else(default_sock_path);
        if print_env {
            println!("{}={}; export {};", DEFAULT_SOCK_ENV, sock_path, DEFAULT_SOCK_ENV);
            println!("# did: {}", agent.did());
        } else {
            eprintln!("did-agent listening on {}", sock_path);
            eprintln!("did: {} (seed source: {})", agent.did(), source);
        }
        match serve(&sock_path, agent, None) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {}", e);
                1
            }
        }
    } else {
        let client = match DidAgentClient::from_env(sock) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: {}", e);
                return 1;
            }
        };
        let result = match action.as_str() {
            "ping" => client.ping(),
            "did" => client.did(),
            "pubkey" => client.pubkey().map(|p| base64_encode(&p)),
            "sign" => client
                .sign(data.unwrap_or_default().as_bytes())
                .map(|s| base64_encode(&s)),
            _ => Ok(String::new()),
        };
        match result {
            Ok(out) => {
                println!("{}", out);
                0
            }
            Err(e) => {
                eprintln!("error: {}", e);
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    const FIXED_SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    ];

    #[test]
    fn test_base64_roundtrip() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
        }
    }

    #[test]
    fn test_base64_known() {
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_decode_seed_base64_and_hex() {
        let b64 = base64_encode(&FIXED_SEED);
        assert_eq!(decode_seed(&b64).unwrap(), FIXED_SEED);
        let hex: String = FIXED_SEED.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(decode_seed(&hex).unwrap(), FIXED_SEED);
        assert!(decode_seed("nope").is_none());
    }

    #[test]
    fn test_agent_did_consistent() {
        let agent = DidAgent::new(FIXED_SEED);
        assert!(agent.did().starts_with("did:key:z6Mk"));
        assert_eq!(agent.did(), "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7");
    }

    #[test]
    fn test_handle_line_ping_did_pubkey() {
        let agent = DidAgent::new(FIXED_SEED);
        assert_eq!(handle_line(&agent, "PING"), "OK pong");
        assert_eq!(handle_line(&agent, "ping"), "OK pong");
        assert_eq!(handle_line(&agent, "DID"), format!("OK {}", agent.did()));
        let resp = handle_line(&agent, "PUBKEY");
        assert_eq!(base64_decode(&resp[3..]).unwrap(), agent.pubkey().to_vec());
    }

    #[test]
    fn test_handle_line_sign() {
        let agent = DidAgent::new(FIXED_SEED);
        let data = b"hello agent";
        let resp = handle_line(&agent, &format!("SIGN {}", base64_encode(data)));
        let sig = base64_decode(&resp[3..]).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        assert!(verify(&agent.pubkey(), data, &sig_arr));
    }

    #[test]
    fn test_handle_line_errors() {
        let agent = DidAgent::new(FIXED_SEED);
        assert!(handle_line(&agent, "SIGN").starts_with("ERR"));
        assert!(handle_line(&agent, "SIGN @@@").starts_with("ERR"));
        assert!(handle_line(&agent, "BOGUS").starts_with("ERR unknown command"));
        assert!(handle_line(&agent, "   ").starts_with("ERR"));
    }

    #[test]
    fn test_server_client_roundtrip() {
        let dir = std::env::temp_dir();
        let sock = dir.join(format!("tert-did-agent-test-{}.sock", std::process::id()));
        let sock_str = sock.to_string_lossy().to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = Arc::clone(&stop);
        let sock_srv = sock_str.clone();
        let handle = std::thread::spawn(move || {
            let agent = DidAgent::new(FIXED_SEED);
            serve(&sock_srv, agent, Some(stop_srv)).unwrap();
        });

        // Wait for the socket to appear.
        for _ in 0..200 {
            if Path::new(&sock_str).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let client = DidAgentClient::new(sock_str.clone());
        assert_eq!(client.ping().unwrap(), "pong");
        let agent = DidAgent::new(FIXED_SEED);
        assert_eq!(client.did().unwrap(), agent.did());
        assert_eq!(client.pubkey().unwrap(), agent.pubkey().to_vec());

        let data = b"sign over the socket";
        let sig = client.sign(data).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        assert!(verify(&agent.pubkey(), data, &sig_arr));

        // Socket has owner-only permissions.
        let mode = std::fs::metadata(&sock_str).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0);

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }
}
