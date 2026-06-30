//! tert fetch - download a URL with a selectable strategy, logging and
//! verifying the active TLS crypto configuration and CA certificate bundle.
//!
//! This is the Rust counterpart of `tert.fetch` (Python). The `curl` and `wget`
//! strategies shell out to the respective binaries; the native `rust` strategy
//! is a stub for now (see [`Strategy::Rust`]). For every strategy the crypto
//! configuration (TLS backend + CA bundle path/size/cert-count) is discovered
//! and verifiable so the trust anchors of a download can be audited.

use std::path::Path;
use std::process::Command;

use regex::Regex;

/// Common system CA bundle locations, in priority order.
pub const CA_BUNDLE_CANDIDATES: &[&str] = &[
    "/etc/pki/tls/certs/ca-bundle.crt",        // Fedora / RHEL (OpenSSL default)
    "/etc/ssl/certs/ca-certificates.crt",      // Debian / Ubuntu / Alpine
    "/etc/ssl/cert.pem",                       // OpenBSD / macOS / OpenSSL
    "/etc/pki/tls/cert.pem",                   // RHEL alternate
    "/etc/ssl/ca-bundle.pem",                  // openSUSE
    "/usr/local/share/certs/ca-root-nss.crt",  // FreeBSD
];

/// PEM certificate boundary marker.
const PEM_CERT_MARKER: &str = "-----BEGIN CERTIFICATE-----";

/// Recognised TLS backend tokens, longest/most-specific first.
const TLS_BACKENDS: &[&str] = &[
    "LibreSSL",
    "BoringSSL",
    "OpenSSL",
    "GnuTLS",
    "wolfSSL",
    "mbedTLS",
    "Schannel",
    "SecureTransport",
    "rustls",
    "NSS",
];

/// A download strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Curl,
    Wget,
    /// Native rustls-based downloader (stub; not yet implemented).
    Rust,
}

impl Strategy {
    /// Parse a strategy name.
    pub fn from_name(name: &str) -> Option<Strategy> {
        match name {
            "curl" => Some(Strategy::Curl),
            "wget" => Some(Strategy::Wget),
            "rust" => Some(Strategy::Rust),
            _ => None,
        }
    }

    /// Canonical strategy name.
    pub fn name(&self) -> &'static str {
        match self {
            Strategy::Curl => "curl",
            Strategy::Wget => "wget",
            Strategy::Rust => "rust",
        }
    }

    /// The downloader executable name, if this strategy uses one.
    pub fn executable_name(&self) -> Option<&'static str> {
        match self {
            Strategy::Curl => Some("curl"),
            Strategy::Wget => Some("wget"),
            Strategy::Rust => None,
        }
    }

    /// Environment variables consulted for an explicit CA bundle, in order.
    pub fn ca_bundle_env_vars(&self) -> &'static [&'static str] {
        match self {
            Strategy::Curl => &["CURL_CA_BUNDLE", "SSL_CERT_FILE"],
            Strategy::Wget => &["SSL_CERT_FILE"],
            Strategy::Rust => &["SSL_CERT_FILE"],
        }
    }
}

/// The TLS crypto configuration a strategy would use for an HTTPS fetch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CryptoConfig {
    pub strategy: String,
    pub available: bool,
    pub downloader_path: Option<String>,
    pub downloader_version: Option<String>,
    pub tls_backend: Option<String>,
    pub ca_bundle_path: Option<String>,
    pub ca_bundle_source: String,
    pub ca_bundle_exists: bool,
    pub ca_bundle_size: Option<u64>,
    pub ca_bundle_cert_count: Option<usize>,
    pub ca_bundle_sha256: Option<String>,
    pub notes: Vec<String>,
}

/// Count `BEGIN CERTIFICATE` markers in a PEM bundle's text.
pub fn count_pem_certificates(text: &str) -> usize {
    text.matches(PEM_CERT_MARKER).count()
}

/// Return the canonical TLS backend name found in a `--version` string.
pub fn detect_tls_backend(version_text: &str) -> Option<String> {
    let lowered = version_text.to_lowercase();
    for name in TLS_BACKENDS {
        if lowered.contains(&name.to_lowercase()) {
            return Some((*name).to_string());
        }
    }
    None
}

/// Discover the CA bundle path for a strategy.
///
/// Returns `(path, source)` where `source` is `env:<NAME>`, `candidate`, or
/// `none`. An env var wins even when the path does not exist, so a
/// misconfigured override is surfaced by verification rather than masked.
///
/// `get_env` and `path_exists` are injected for testability.
pub fn discover_ca_bundle<E, P>(
    env_vars: &[&str],
    get_env: E,
    candidates: &[&str],
    path_exists: P,
) -> (Option<String>, String)
where
    E: Fn(&str) -> Option<String>,
    P: Fn(&str) -> bool,
{
    for name in env_vars {
        if let Some(value) = get_env(name) {
            if !value.is_empty() {
                return (Some(value), format!("env:{}", name));
            }
        }
    }
    for cand in candidates {
        if path_exists(cand) {
            return (Some((*cand).to_string()), "candidate".to_string());
        }
    }
    (None, "none".to_string())
}

/// Verify a crypto configuration. Returns the list of problems (empty == ok).
pub fn verify_crypto_config(cfg: &CryptoConfig) -> Vec<String> {
    let mut problems = Vec::new();
    if cfg.tls_backend.is_none() {
        problems.push("TLS backend could not be determined".to_string());
    }
    match &cfg.ca_bundle_path {
        None => problems.push("no CA certificate bundle configured".to_string()),
        Some(path) => {
            if !cfg.ca_bundle_exists {
                problems.push(format!("CA bundle path does not exist: {}", path));
            } else if cfg.ca_bundle_size == Some(0) || cfg.ca_bundle_size.is_none() {
                problems.push(format!("CA bundle is empty: {}", path));
            } else if cfg.ca_bundle_cert_count == Some(0) {
                problems.push(format!("CA bundle contains no certificates: {}", path));
            }
        }
    }
    problems
}

/// True when the crypto configuration is fully verified.
pub fn crypto_config_ok(cfg: &CryptoConfig) -> bool {
    verify_crypto_config(cfg).is_empty()
}

/// Read a `--version` string from a downloader executable.
fn read_version_text(exe: &str) -> Option<String> {
    let out = Command::new(exe).arg("--version").output().ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
}

/// Best-effort lookup of an executable on `PATH`.
fn which(exe: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(exe);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Discover the full crypto configuration for a strategy on this host.
pub fn crypto_config(strategy: Strategy) -> CryptoConfig {
    let mut cfg = CryptoConfig {
        strategy: strategy.name().to_string(),
        ..Default::default()
    };

    if let Some(exe_name) = strategy.executable_name() {
        if let Some(exe) = which(exe_name) {
            cfg.downloader_path = Some(exe.clone());
            cfg.available = true;
            if let Some(version_text) = read_version_text(&exe) {
                cfg.downloader_version =
                    version_text.lines().next().map(|s| s.trim().to_string());
                cfg.tls_backend = detect_tls_backend(&version_text);
            }
        }
    }

    let (path, source) = discover_ca_bundle(
        strategy.ca_bundle_env_vars(),
        |name| std::env::var(name).ok(),
        CA_BUNDLE_CANDIDATES,
        |p| Path::new(p).is_file(),
    );
    cfg.ca_bundle_source = source;
    if let Some(ref p) = path {
        if Path::new(p).is_file() {
            cfg.ca_bundle_exists = true;
            if let Ok(meta) = std::fs::metadata(p) {
                cfg.ca_bundle_size = Some(meta.len());
            }
            if let Ok(text) = std::fs::read_to_string(p) {
                cfg.ca_bundle_cert_count = Some(count_pem_certificates(&text));
            }
            cfg.ca_bundle_sha256 = sha256_file(p);
        }
    }
    cfg.ca_bundle_path = path;

    if strategy == Strategy::Rust {
        cfg.tls_backend = Some("rustls".to_string());
        cfg.notes
            .push("native rust fetch strategy is a stub; not yet implemented".to_string());
        cfg.notes.push(
            "planned: rustls with rustls-native-certs over the system CA bundle".to_string(),
        );
    }

    cfg
}

/// Outcome of a fetch attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOutcome {
    pub url: String,
    pub dest: String,
    pub strategy: String,
    pub crypto_ok: bool,
    pub crypto_problems: Vec<String>,
    pub downloaded: bool,
    pub sha256: Option<String>,
    pub provenance_path: Option<String>,
    pub tls_version: Option<String>,
    pub tls_cipher: Option<String>,
}

/// Extract `(tls_version, tls_cipher)` from downloader verbose output.
///
/// Recognises curl's `SSL connection using <version> / <cipher>` line and falls
/// back to generic TLS-version / cipher patterns. Returns `(None, None)` for
/// non-TLS transfers such as `file://`.
pub fn parse_tls_info(text: &str) -> (Option<String>, Option<String>) {
    static CONN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static VER: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static CIPH: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let conn = CONN.get_or_init(|| {
        Regex::new(r"SSL connection using (\S+)\s*/\s*([A-Za-z0-9_\-]+)").unwrap()
    });
    if let Some(c) = conn.captures(text) {
        return (Some(c[1].to_string()), Some(c[2].to_string()));
    }
    let ver = VER.get_or_init(|| {
        Regex::new(r"\b(TLSv1\.[0-3]|TLSv1|TLS1\.[0-3]|SSLv3)\b").unwrap()
    });
    let ciph = CIPH.get_or_init(|| {
        Regex::new(r"(?:cipher|Cipher|ciphersuite)[\s:=]+[\x22\x27]?([A-Za-z0-9_]+(?:[-_][A-Za-z0-9]+)*)").unwrap()
    });
    let version = ver.captures(text).map(|c| c[1].to_string());
    let cipher = ciph.captures(text).map(|c| c[1].to_string());
    (version, cipher)
}

/// Errors that can occur while fetching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    UnknownStrategy(String),
    CryptoUnverified(Vec<String>),
    NotImplemented(String),
    DownloaderUnavailable(String),
    DownloadFailed(String),
    SigningFailed(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::UnknownStrategy(s) => write!(f, "unknown fetch strategy: {}", s),
            FetchError::CryptoUnverified(p) => {
                write!(f, "crypto configuration could not be verified: {}", p.join("; "))
            }
            FetchError::NotImplemented(s) => write!(f, "{}", s),
            FetchError::DownloaderUnavailable(s) => write!(f, "downloader unavailable: {}", s),
            FetchError::DownloadFailed(s) => write!(f, "download failed: {}", s),
            FetchError::SigningFailed(s) => write!(f, "provenance signing failed: {}", s),
        }
    }
}

impl std::error::Error for FetchError {}

/// Build the argv for a strategy's download command (no process is spawned).
///
/// Returns `None` for the stub `rust` strategy.
pub fn build_download_command(
    strategy: Strategy,
    url: &str,
    part: &str,
    cfg: &CryptoConfig,
) -> Option<Vec<String>> {
    match strategy {
        Strategy::Curl => {
            let mut cmd = vec![
                "curl".to_string(),
                "-fsSL".to_string(),
                "-v".to_string(),
                "--proto".to_string(),
                "=https,http,file".to_string(),
            ];
            if let Some(ref ca) = cfg.ca_bundle_path {
                if cfg.ca_bundle_exists {
                    cmd.push("--cacert".to_string());
                    cmd.push(ca.clone());
                }
            }
            cmd.push("-o".to_string());
            cmd.push(part.to_string());
            cmd.push(url.to_string());
            Some(cmd)
        }
        Strategy::Wget => {
            let mut cmd = vec!["wget".to_string(), "-q".to_string(), "-O".to_string(), part.to_string()];
            if let Some(ref ca) = cfg.ca_bundle_path {
                if cfg.ca_bundle_exists {
                    cmd.push(format!("--ca-certificate={}", ca));
                }
            }
            cmd.push(url.to_string());
            Some(cmd)
        }
        Strategy::Rust => None,
    }
}

/// Download `url` to `dest` using the given strategy after verifying crypto.
///
/// The native `rust` strategy is a stub and returns
/// [`FetchError::NotImplemented`].
pub fn fetch(
    strategy: Strategy,
    url: &str,
    dest: &str,
    verify: bool,
) -> Result<FetchOutcome, FetchError> {
    fetch_opts(strategy, url, dest, verify, None)
}

/// Options for writing a DID-signed provenance sidecar after a fetch.
pub struct SignOptions<'a> {
    pub signer: &'a dyn crate::vc::Signer,
    pub cryptosuite: &'a str,
}

/// Build an unsigned VC/PROV provenance document for a completed fetch.
pub fn build_provenance(
    url: &str,
    dest: &str,
    sha256: Option<&str>,
    bytes: Option<u64>,
    strategy: &str,
    cfg: &CryptoConfig,
    tls_version: Option<&str>,
    tls_cipher: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/prov"
        ],
        "type": ["VerifiableCredential", "prov:Entity"],
        "credentialSubject": {
            "type": "prov:Entity",
            "url": url,
            "dest": dest,
            "sha256": sha256,
            "bytes": bytes,
            "strategy": strategy,
            "tls_backend": cfg.tls_backend,
            "tls_version": tls_version,
            "tls_cipher": tls_cipher,
            "ca_bundle_path": cfg.ca_bundle_path,
            "ca_bundle_sha256": cfg.ca_bundle_sha256,
            "ca_bundle_cert_count": cfg.ca_bundle_cert_count,
        }
    })
}

/// Download `url` to `dest`, optionally writing a DID-signed provenance sidecar
/// (`<dest>.prov.json`).
pub fn fetch_opts(
    strategy: Strategy,
    url: &str,
    dest: &str,
    verify: bool,
    sign: Option<SignOptions>,
) -> Result<FetchOutcome, FetchError> {
    let cfg = crypto_config(strategy);
    let problems = verify_crypto_config(&cfg);
    let crypto_ok = problems.is_empty();

    if verify && !crypto_ok {
        return Err(FetchError::CryptoUnverified(problems));
    }

    if strategy == Strategy::Rust {
        return Err(FetchError::NotImplemented(
            "the rust fetch strategy is not yet implemented (stub)".to_string(),
        ));
    }

    let part = format!("{}.part", dest);
    let cmd = build_download_command(strategy, url, &part, &cfg)
        .ok_or_else(|| FetchError::NotImplemented("no command for strategy".to_string()))?;

    let exe_name = strategy
        .executable_name()
        .ok_or_else(|| FetchError::DownloaderUnavailable(strategy.name().to_string()))?;
    if which(exe_name).is_none() {
        return Err(FetchError::DownloaderUnavailable(exe_name.to_string()));
    }

    let output = Command::new(&cmd[0])
        .args(&cmd[1..])
        .output()
        .map_err(|e| FetchError::DownloadFailed(e.to_string()))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let (tls_version, tls_cipher) = parse_tls_info(&stderr);
    if !output.status.success() {
        let _ = std::fs::remove_file(&part);
        return Err(FetchError::DownloadFailed(format!(
            "{} exited with {:?}",
            exe_name,
            output.status.code()
        )));
    }
    std::fs::rename(&part, dest).map_err(|e| FetchError::DownloadFailed(e.to_string()))?;

    let sha256 = sha256_file(dest);
    let bytes = std::fs::metadata(dest).ok().map(|m| m.len());

    let mut outcome = FetchOutcome {
        url: url.to_string(),
        dest: dest.to_string(),
        strategy: strategy.name().to_string(),
        crypto_ok,
        crypto_problems: problems,
        downloaded: true,
        sha256: sha256.clone(),
        provenance_path: None,
        tls_version: tls_version.clone(),
        tls_cipher: tls_cipher.clone(),
    };

    if let Some(opts) = sign {
        let prov = build_provenance(
            url,
            dest,
            sha256.as_deref(),
            bytes,
            strategy.name(),
            &cfg,
            tls_version.as_deref(),
            tls_cipher.as_deref(),
        );
        let signed = crate::vc::sign_document(&prov, opts.signer, opts.cryptosuite, None)
            .map_err(|e| FetchError::SigningFailed(e.to_string()))?;
        let sidecar = format!("{}.prov.json", dest);
        let text = serde_json::to_string_pretty(&signed)
            .map_err(|e| FetchError::SigningFailed(e.to_string()))?;
        std::fs::write(&sidecar, format!("{}\n", text))
            .map_err(|e| FetchError::SigningFailed(e.to_string()))?;
        outcome.provenance_path = Some(sidecar);
    }

    Ok(outcome)
}

/// Compute the lowercase hex sha256 of a file using `std` only.
fn sha256_file(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    Some(sha256_hex(&data))
}

/// Minimal, dependency-free SHA-256 (FIPS 180-4) over a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = String::with_capacity(64);
    for word in &h {
        out.push_str(&format!("{:08x}", word));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_CERT_PEM: &str = concat!(
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
    );

    #[test]
    fn test_strategy_from_name() {
        assert_eq!(Strategy::from_name("curl"), Some(Strategy::Curl));
        assert_eq!(Strategy::from_name("wget"), Some(Strategy::Wget));
        assert_eq!(Strategy::from_name("rust"), Some(Strategy::Rust));
        assert_eq!(Strategy::from_name("bogus"), None);
    }

    #[test]
    fn test_count_pem_certificates() {
        assert_eq!(count_pem_certificates(TWO_CERT_PEM), 2);
        assert_eq!(count_pem_certificates(""), 0);
    }

    #[test]
    fn test_detect_tls_backend() {
        assert_eq!(
            detect_tls_backend("curl 8.15.0 libcurl/8.15.0 OpenSSL/3.5.4").as_deref(),
            Some("OpenSSL")
        );
        assert_eq!(
            detect_tls_backend("GNU Wget2 2.2.1 +ssl/gnutls").as_deref(),
            Some("GnuTLS")
        );
        assert_eq!(detect_tls_backend("no tls here"), None);
    }

    #[test]
    fn test_discover_ca_bundle_env_wins() {
        let (path, source) = discover_ca_bundle(
            &["CURL_CA_BUNDLE", "SSL_CERT_FILE"],
            |name| match name {
                "CURL_CA_BUNDLE" => Some("/a.pem".to_string()),
                "SSL_CERT_FILE" => Some("/b.pem".to_string()),
                _ => None,
            },
            &[],
            |_| false,
        );
        assert_eq!(path.as_deref(), Some("/a.pem"));
        assert_eq!(source, "env:CURL_CA_BUNDLE");
    }

    #[test]
    fn test_discover_ca_bundle_candidate() {
        let (path, source) = discover_ca_bundle(
            &["SSL_CERT_FILE"],
            |_| None,
            &["/missing.pem", "/present.pem"],
            |p| p == "/present.pem",
        );
        assert_eq!(path.as_deref(), Some("/present.pem"));
        assert_eq!(source, "candidate");
    }

    #[test]
    fn test_discover_ca_bundle_none() {
        let (path, source) =
            discover_ca_bundle(&["SSL_CERT_FILE"], |_| None, &["/missing.pem"], |_| false);
        assert_eq!(path, None);
        assert_eq!(source, "none");
    }

    #[test]
    fn test_verify_ok() {
        let cfg = CryptoConfig {
            strategy: "curl".to_string(),
            tls_backend: Some("OpenSSL".to_string()),
            ca_bundle_path: Some("/x".to_string()),
            ca_bundle_exists: true,
            ca_bundle_size: Some(100),
            ca_bundle_cert_count: Some(2),
            ..Default::default()
        };
        assert!(verify_crypto_config(&cfg).is_empty());
        assert!(crypto_config_ok(&cfg));
    }

    #[test]
    fn test_verify_problems() {
        let cfg = CryptoConfig {
            strategy: "curl".to_string(),
            ..Default::default()
        };
        let problems = verify_crypto_config(&cfg);
        assert!(problems.iter().any(|p| p.contains("TLS backend")));
        assert!(problems.iter().any(|p| p.contains("no CA certificate bundle")));
    }

    #[test]
    fn test_verify_bundle_empty() {
        let cfg = CryptoConfig {
            strategy: "curl".to_string(),
            tls_backend: Some("OpenSSL".to_string()),
            ca_bundle_path: Some("/x".to_string()),
            ca_bundle_exists: true,
            ca_bundle_size: Some(0),
            ..Default::default()
        };
        let problems = verify_crypto_config(&cfg);
        assert!(problems.iter().any(|p| p.contains("empty")));
    }

    #[test]
    fn test_build_curl_command_includes_cacert() {
        let cfg = CryptoConfig {
            ca_bundle_path: Some("/ca.pem".to_string()),
            ca_bundle_exists: true,
            ..Default::default()
        };
        let cmd = build_download_command(Strategy::Curl, "https://x/y", "/tmp/y.part", &cfg).unwrap();
        assert_eq!(cmd[0], "curl");
        assert!(cmd.iter().any(|a| a == "--cacert"));
        assert!(cmd.iter().any(|a| a == "/ca.pem"));
        assert_eq!(cmd.last().unwrap(), "https://x/y");
    }

    #[test]
    fn test_build_wget_command_includes_cacert() {
        let cfg = CryptoConfig {
            ca_bundle_path: Some("/ca.pem".to_string()),
            ca_bundle_exists: true,
            ..Default::default()
        };
        let cmd = build_download_command(Strategy::Wget, "https://x/y", "/tmp/y.part", &cfg).unwrap();
        assert_eq!(cmd[0], "wget");
        assert!(cmd.iter().any(|a| a.starts_with("--ca-certificate=")));
        assert_eq!(cmd.last().unwrap(), "https://x/y");
    }

    #[test]
    fn test_build_rust_command_is_none() {
        let cfg = CryptoConfig::default();
        assert!(build_download_command(Strategy::Rust, "https://x", "/tmp/x.part", &cfg).is_none());
    }

    #[test]
    fn test_parse_tls_info_curl_line() {
        let text = "* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 / X25519MLKEM768\n";
        let (v, c) = parse_tls_info(text);
        assert_eq!(v.as_deref(), Some("TLSv1.3"));
        assert_eq!(c.as_deref(), Some("TLS_AES_128_GCM_SHA256"));
    }

    #[test]
    fn test_parse_tls_info_none() {
        let (v, c) = parse_tls_info("plain file, no tls");
        assert_eq!(v, None);
        assert_eq!(c, None);
    }

    #[test]
    fn test_rust_fetch_is_stub() {
        // verify=false so it gets past crypto verification to the stub guard.
        let err = fetch(Strategy::Rust, "https://x", "/tmp/x", false).unwrap_err();
        match err {
            FetchError::NotImplemented(_) => {}
            other => panic!("expected NotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn test_rust_crypto_config_has_stub_notes() {
        let cfg = crypto_config(Strategy::Rust);
        assert_eq!(cfg.strategy, "rust");
        assert!(!cfg.available);
        assert_eq!(cfg.tls_backend.as_deref(), Some("rustls"));
        assert!(cfg.notes.iter().any(|n| n.contains("stub")));
    }

    #[test]
    fn test_sha256_hex_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_fetch_with_signed_provenance_via_file_url() {
        // Requires curl; download a file:// URL and write a signed sidecar.
        if which("curl").is_none() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("tert-fetch-sign-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let src = dir.join("src.txt");
        std::fs::write(&src, b"signed payload").unwrap();
        let dest = dir.join("out.txt");
        let url = format!("file://{}", src.display());

        let seed: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let key = crate::vc::FileKey::new(seed);
        let opts = SignOptions {
            signer: &key,
            cryptosuite: crate::vc::DEFAULT_CRYPTOSUITE,
        };
        // No crypto verification for file:// (no TLS); verify=false.
        let outcome = fetch_opts(
            Strategy::Curl,
            &url,
            dest.to_str().unwrap(),
            false,
            Some(opts),
        )
        .unwrap();
        assert!(outcome.downloaded);
        let prov_path = outcome.provenance_path.unwrap();
        let text = std::fs::read_to_string(&prov_path).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(crate::vc::verify_document(&doc));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
