//! Sign and verify Verifiable Credential (VC) / YAML-LD documents (Rust
//! counterpart of `tert.vc`).
//!
//! - Deterministic canonicalization (JCS-style subset: sorted keys, compact,
//!   `ensure_ascii`) producing bytes identical to the Python implementation.
//! - A pluggable cryptosuite abstraction:
//!     * `eddsa-jcs-2022`    - Ed25519 over canonical JSON
//!     * `mldsa-87-p256`     - ML-DSA-87 (FIPS 204) + ECDSA-P256 hybrid
//!     * `merkle-tree-certs` - Merkle Tree Certificates (signed tree head +
//!       inclusion proof; see `crate::pq`)
//! - JSON and YAML (YAML-LD) document IO via serde.

use serde_json::{json, Map, Value};

use crate::crypto::{pubkey_from_did_key, sign as ed_sign, verify as ed_verify};
use crate::did_agent::{base64_decode, base64_encode, DidAgentClient};

pub const DEFAULT_CRYPTOSUITE: &str = "eddsa-jcs-2022";

#[derive(Debug)]
pub enum VcError {
    NotObject,
    UnknownCryptosuite(String),
    UnsupportedStub(String),
    NoKey(String),
    Io(String),
    Parse(String),
}

impl std::fmt::Display for VcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VcError::NotObject => write!(f, "document is not a JSON object"),
            VcError::UnknownCryptosuite(s) => write!(f, "unknown cryptosuite: {}", s),
            VcError::UnsupportedStub(s) => write!(f, "{}", s),
            VcError::NoKey(s) => write!(f, "{}", s),
            VcError::Io(s) => write!(f, "{}", s),
            VcError::Parse(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for VcError {}

// --- canonicalization (matches Python json.dumps ensure_ascii) -------------

fn escape_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (0x20..=0x7e).contains(&(c as u32)) => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xffff {
                    out.push_str(&format!("\\u{:04x}", cp));
                } else {
                    let v = cp - 0x10000;
                    let hi = 0xd800 + (v >> 10);
                    let lo = 0xdc00 + (v & 0x3ff);
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
                }
            }
        }
    }
    out.push('"');
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => escape_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_string(k, out);
                out.push(':');
                write_value(&m[*k], out);
            }
            out.push('}');
        }
    }
}

/// Deterministic canonical JSON bytes used as the signing payload.
pub fn canonicalize(value: &Value) -> Vec<u8> {
    let mut s = String::new();
    write_value(value, &mut s);
    s.into_bytes()
}

// --- signers ---------------------------------------------------------------

/// A signing key: produces a `did:key` and Ed25519 signatures.
pub trait Signer {
    fn did(&self) -> Result<String, VcError>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, VcError>;
    /// The raw 32-byte Ed25519 seed, when the backend can expose it. Required
    /// to derive the ML-DSA-87 / P-256 component keys for `mldsa-87-p256`;
    /// agent-backed signers return `None`.
    fn key_seed(&self) -> Option<[u8; 32]> {
        None
    }
}

/// Signs with an in-memory Ed25519 seed (loaded from / stored to disk).
pub struct FileKey {
    seed: [u8; 32],
    did: String,
}

impl FileKey {
    pub fn new(seed: [u8; 32]) -> FileKey {
        let pk = crate::crypto::pubkey_from_seed(&seed);
        let did = crate::crypto::did_key_from_pubkey(&pk);
        FileKey { seed, did }
    }

    /// Load (or create) a base64 seed file under `keys_dir` (matches Python).
    pub fn load_or_create(keys_dir: &str) -> Result<FileKey, VcError> {
        std::fs::create_dir_all(keys_dir).map_err(|e| VcError::Io(e.to_string()))?;
        let key_path = std::path::Path::new(keys_dir).join("did_ed25519.key");
        let seed = if key_path.exists() {
            let text = std::fs::read_to_string(&key_path).map_err(|e| VcError::Io(e.to_string()))?;
            let bytes = base64_decode(text.trim())
                .ok_or_else(|| VcError::Io("invalid key file".to_string()))?;
            if bytes.len() != 32 {
                return Err(VcError::Io("key file is not 32 bytes".to_string()));
            }
            let mut s = [0u8; 32];
            s.copy_from_slice(&bytes);
            s
        } else {
            let s = crate::did_agent::generate_seed().map_err(|e| VcError::Io(e.to_string()))?;
            std::fs::write(&key_path, base64_encode(&s)).map_err(|e| VcError::Io(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
            s
        };
        Ok(FileKey::new(seed))
    }
}

impl Signer for FileKey {
    fn did(&self) -> Result<String, VcError> {
        Ok(self.did.clone())
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, VcError> {
        Ok(ed_sign(&self.seed, data).to_vec())
    }
    fn key_seed(&self) -> Option<[u8; 32]> {
        Some(self.seed)
    }
}

/// Signs through a running did-agent (private key never leaves the agent).
pub struct AgentSigner {
    client: DidAgentClient,
}

impl AgentSigner {
    pub fn new(sock_path: String) -> AgentSigner {
        AgentSigner {
            client: DidAgentClient::new(sock_path),
        }
    }
}

impl Signer for AgentSigner {
    fn did(&self) -> Result<String, VcError> {
        self.client.did().map_err(|e| VcError::Io(e.to_string()))
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, VcError> {
        self.client.sign(data).map_err(|e| VcError::Io(e.to_string()))
    }
}

// --- cryptosuites ----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cryptosuite {
    EddsaJcs2022,
    MldsaP256,
    MerkleTreeCerts,
}

pub const CRYPTOSUITES: [Cryptosuite; 3] = [
    Cryptosuite::EddsaJcs2022,
    Cryptosuite::MldsaP256,
    Cryptosuite::MerkleTreeCerts,
];

impl Cryptosuite {
    pub fn name(&self) -> &'static str {
        match self {
            Cryptosuite::EddsaJcs2022 => "eddsa-jcs-2022",
            Cryptosuite::MldsaP256 => "mldsa-87-p256",
            Cryptosuite::MerkleTreeCerts => "merkle-tree-certs",
        }
    }

    pub fn available(&self) -> bool {
        // All three cryptosuites are now implemented.
        true
    }

    pub fn from_name(name: &str) -> Result<Cryptosuite, VcError> {
        match name {
            "eddsa-jcs-2022" => Ok(Cryptosuite::EddsaJcs2022),
            "mldsa-87-p256" => Ok(Cryptosuite::MldsaP256),
            "merkle-tree-certs" => Ok(Cryptosuite::MerkleTreeCerts),
            other => Err(VcError::UnknownCryptosuite(other.to_string())),
        }
    }

    fn sign(&self, payload: &[u8], signer: &dyn Signer) -> Result<String, VcError> {
        match self {
            Cryptosuite::EddsaJcs2022 => Ok(base64_encode(&signer.sign(payload)?)),
            Cryptosuite::MldsaP256 => {
                let seed = signer.key_seed().ok_or_else(|| {
                    VcError::NoKey(
                        "cryptosuite 'mldsa-87-p256' needs a file key seed; agent signing is \
                         not supported for hybrid post-quantum keys"
                            .to_string(),
                    )
                })?;
                let key = crate::pq::HybridKey::from_seed(&seed)
                    .map_err(VcError::UnsupportedStub)?;
                let blob = key.sign(&seed, payload).map_err(VcError::UnsupportedStub)?;
                Ok(base64_encode(&blob))
            }
            Cryptosuite::MerkleTreeCerts => {
                // Issue a single-certificate batch: build a one-leaf Merkle
                // tree, sign its head, and emit the (empty) inclusion proof.
                let issuer = signer.did()?;
                let issuer_b = issuer.as_bytes();
                let batch: u32 = 0;
                let assertions = vec![payload.to_vec()];
                let tree = crate::pq::MerkleTree::build(issuer_b, batch, &assertions);
                let root = tree.root();
                let proof = tree.inclusion_proof(0).unwrap_or_default();
                let signing_input = crate::pq::treehead_signing_input(
                    issuer_b,
                    batch,
                    tree.size() as u64,
                    &root,
                );
                let treehead_sig = signer.sign(&signing_input)?;
                let blob = crate::pq::encode_mtc(
                    issuer_b,
                    batch,
                    tree.size() as u64,
                    0,
                    &root,
                    &treehead_sig,
                    &proof,
                );
                Ok(base64_encode(&blob))
            }
        }
    }

    fn verify(&self, payload: &[u8], proof_value: &str, issuer_did: &str) -> Result<bool, VcError> {
        match self {
            Cryptosuite::EddsaJcs2022 => {
                let pk = match pubkey_from_did_key(issuer_did) {
                    Some(pk) => pk,
                    None => return Ok(false),
                };
                let sig = match base64_decode(proof_value) {
                    Some(s) if s.len() == 64 => s,
                    _ => return Ok(false),
                };
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&sig);
                Ok(ed_verify(&pk, payload, &sig_arr))
            }
            Cryptosuite::MldsaP256 => {
                let blob = match base64_decode(proof_value) {
                    Some(b) => b,
                    None => return Ok(false),
                };
                Ok(crate::pq::hybrid_verify(&blob, payload))
            }
            Cryptosuite::MerkleTreeCerts => {
                let blob = match base64_decode(proof_value) {
                    Some(b) => b,
                    None => return Ok(false),
                };
                let dec = match crate::pq::decode_mtc(&blob) {
                    Some(d) => d,
                    None => return Ok(false),
                };
                // The certificate's issuer must match the embedded batch issuer.
                if dec.issuer != issuer_did.as_bytes() {
                    return Ok(false);
                }
                // 1) The inclusion proof must reproduce the certified tree head.
                if crate::pq::mtc_recompute_root(&dec, payload) != dec.root {
                    return Ok(false);
                }
                // 2) The batch signature over that tree head must verify.
                let pk = match pubkey_from_did_key(issuer_did) {
                    Some(pk) => pk,
                    None => return Ok(false),
                };
                if dec.treehead_sig.len() != 64 {
                    return Ok(false);
                }
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&dec.treehead_sig);
                let signing_input = crate::pq::treehead_signing_input(
                    &dec.issuer,
                    dec.batch,
                    dec.tree_size,
                    &dec.root,
                );
                Ok(ed_verify(&pk, &signing_input, &sig_arr))
            }
        }
    }
}

// --- document signing / verification ---------------------------------------

fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Sign a VC document with a `DataIntegrityProof` over canonical JSON.
pub fn sign_document(
    doc: &Value,
    signer: &dyn Signer,
    cryptosuite: &str,
    created: Option<&str>,
) -> Result<Value, VcError> {
    let suite = Cryptosuite::from_name(cryptosuite)?;
    let obj = doc.as_object().ok_or(VcError::NotObject)?;
    let mut base: Map<String, Value> = obj.clone();
    base.remove("proof");
    let did = signer.did()?;
    base.insert("issuer".to_string(), Value::String(did.clone()));

    let payload = canonicalize(&Value::Object(base.clone()));
    let proof_value = suite.sign(&payload, signer)?;

    let fragment = did.strip_prefix("did:key:").unwrap_or(&did);
    let proof = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": suite.name(),
        "created": created.map(|s| s.to_string()).unwrap_or_else(now_iso),
        "proofPurpose": "assertionMethod",
        "verificationMethod": format!("{}#{}", did, fragment),
        "proofValue": proof_value,
    });

    let mut out = base;
    out.insert("proof".to_string(), proof);
    Ok(Value::Object(out))
}

/// Verify the `DataIntegrityProof` on a VC document.
pub fn verify_document(doc: &Value) -> bool {
    let obj = match doc.as_object() {
        Some(o) => o,
        None => return false,
    };
    let proof = match obj.get("proof").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return false,
    };
    let proof_value = match proof.get("proofValue").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return false,
    };
    let suite = match proof
        .get("cryptosuite")
        .and_then(|v| v.as_str())
        .and_then(|n| Cryptosuite::from_name(n).ok())
    {
        Some(s) => s,
        None => return false,
    };
    let issuer = match obj.get("issuer").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return false,
    };
    let mut base = obj.clone();
    base.remove("proof");
    let payload = canonicalize(&Value::Object(base));
    suite.verify(&payload, proof_value, issuer).unwrap_or(false)
}

// --- JSON / YAML / TOML IO -------------------------------------------------

/// Provisional TOML embedding for W3C VCs: the credential lives under this
/// top-level TOML table (matches the Python `tert.vc.TOML_VC_SECTION`).
pub const TOML_VC_SECTION: &str = "verifiableCredential";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocFormat {
    Json,
    Yaml,
    Toml,
}

pub fn detect_format(path: &str) -> DocFormat {
    let lower = path.to_lowercase();
    if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        DocFormat::Yaml
    } else if lower.ends_with(".toml") {
        DocFormat::Toml
    } else {
        DocFormat::Json
    }
}

fn toml_escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn toml_key(k: &str, out: &mut String) {
    let bare = !k.is_empty()
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare {
        out.push_str(k);
    } else {
        toml_escape(k, out);
    }
}

fn toml_value(v: &Value, out: &mut String) -> Result<(), VcError> {
    match v {
        Value::Null => return Err(VcError::Parse("TOML cannot represent a null value".to_string())),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => toml_escape(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                toml_value(x, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, val)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                toml_key(k, out);
                out.push_str(" = ");
                toml_value(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Emit a VC as TOML under the provisional `[verifiableCredential]` table.
/// Nested objects are written as inline tables so there are no sub-table
/// ordering constraints and the document round-trips through any TOML parser.
fn dump_toml(doc: &Value) -> Result<String, VcError> {
    let obj = doc.as_object().ok_or(VcError::NotObject)?;
    let mut out = String::new();
    out.push('[');
    out.push_str(TOML_VC_SECTION);
    out.push_str("]\n");
    for (k, v) in obj {
        toml_key(k, &mut out);
        out.push_str(" = ");
        toml_value(v, &mut out)?;
        out.push('\n');
    }
    Ok(out)
}

fn load_toml(text: &str) -> Result<Value, VcError> {
    let parsed: Value = toml::from_str(text).map_err(|e| VcError::Parse(e.to_string()))?;
    if let Some(obj) = parsed.as_object() {
        if let Some(inner) = obj.get(TOML_VC_SECTION) {
            if inner.is_object() {
                return Ok(inner.clone());
            }
        }
    }
    Ok(parsed)
}

pub fn load_document(path: &str) -> Result<(Value, DocFormat), VcError> {
    let text = std::fs::read_to_string(path).map_err(|e| VcError::Io(e.to_string()))?;
    let fmt = detect_format(path);
    let value: Value = match fmt {
        DocFormat::Json => serde_json::from_str(&text).map_err(|e| VcError::Parse(e.to_string()))?,
        DocFormat::Yaml => serde_yaml::from_str(&text).map_err(|e| VcError::Parse(e.to_string()))?,
        DocFormat::Toml => load_toml(&text)?,
    };
    Ok((value, fmt))
}

pub fn dump_document(doc: &Value, fmt: DocFormat) -> Result<String, VcError> {
    match fmt {
        DocFormat::Json => serde_json::to_string_pretty(doc).map_err(|e| VcError::Parse(e.to_string())),
        DocFormat::Yaml => serde_yaml::to_string(doc).map_err(|e| VcError::Parse(e.to_string())),
        DocFormat::Toml => dump_toml(doc),
    }
}

// --- CLI -------------------------------------------------------------------

fn resolve_signer(sock: Option<String>, keys_dir: Option<String>) -> Result<Box<dyn Signer>, VcError> {
    let sock = sock.or_else(|| std::env::var("DID_AGENT_SOCK").ok());
    if let Some(sock) = sock {
        let signer = AgentSigner::new(sock);
        // Probe the agent so a dead socket falls through to the file key.
        if signer.did().is_ok() {
            return Ok(Box::new(signer));
        }
    }
    if let Some(dir) = keys_dir {
        return Ok(Box::new(FileKey::load_or_create(&dir)?));
    }
    Err(VcError::NoKey(
        "no signing key available (run a did-agent or pass --keys-dir)".to_string(),
    ))
}

/// CLI entry point for the `vc` binary / `tert vc` subcommand.
pub fn cli_main(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: vc <sign|verify|cryptosuites> ...");
        return 2;
    }
    match args[0].as_str() {
        "cryptosuites" => {
            let as_json = args.iter().any(|a| a == "--json");
            if as_json {
                let rows: Vec<Value> = CRYPTOSUITES
                    .iter()
                    .map(|s| json!({"name": s.name(), "available": s.available()}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&Value::Array(rows)).unwrap());
            } else {
                for s in CRYPTOSUITES.iter() {
                    println!("{:<20} {}", s.name(), if s.available() { "available" } else { "stub" });
                }
            }
            0
        }
        "sign" => {
            let mut file = None;
            let mut cryptosuite = DEFAULT_CRYPTOSUITE.to_string();
            let mut sock = None;
            let mut keys_dir = None;
            let mut output = None;
            let mut fmt_override = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--cryptosuite" => { i += 1; cryptosuite = args.get(i).cloned().unwrap_or_default(); }
                    "--sock" => { i += 1; sock = args.get(i).cloned(); }
                    "--keys-dir" => { i += 1; keys_dir = args.get(i).cloned(); }
                    "-o" | "--output" => { i += 1; output = args.get(i).cloned(); }
                    "--format" => { i += 1; fmt_override = args.get(i).cloned(); }
                    other if !other.starts_with('-') => file = Some(args[i].clone()),
                    other => { eprintln!("error: unknown option {}", other); return 2; }
                }
                i += 1;
            }
            let file = match file { Some(f) => f, None => { eprintln!("error: a file is required"); return 2; } };
            let (doc, in_fmt) = match load_document(&file) {
                Ok(v) => v,
                Err(e) => { eprintln!("error: {}", e); return 1; }
            };
            let signer = match resolve_signer(sock, keys_dir) {
                Ok(s) => s,
                Err(e) => { eprintln!("error: {}", e); return 1; }
            };
            let signed = match sign_document(&doc, signer.as_ref(), &cryptosuite, None) {
                Ok(v) => v,
                Err(e) => { eprintln!("error: {}", e); return 2; }
            };
            let out_fmt = match fmt_override.as_deref() {
                Some("yaml") => DocFormat::Yaml,
                Some("json") => DocFormat::Json,
                Some("toml") => DocFormat::Toml,
                _ => in_fmt,
            };
            let text = match dump_document(&signed, out_fmt) {
                Ok(t) => t,
                Err(e) => { eprintln!("error: {}", e); return 1; }
            };
            match output {
                Some(path) => {
                    if let Err(e) = std::fs::write(&path, format!("{}\n", text.trim_end())) {
                        eprintln!("error: {}", e);
                        return 1;
                    }
                }
                None => println!("{}", text),
            }
            0
        }
        "verify" => {
            let file = match args.get(1) {
                Some(f) => f,
                None => { eprintln!("error: a file is required"); return 2; }
            };
            let (doc, _) = match load_document(file) {
                Ok(v) => v,
                Err(e) => { eprintln!("error: {}", e); return 1; }
            };
            let ok = verify_document(&doc);
            println!("verify: {}", if ok { "OK" } else { "FAILED" });
            if ok { 0 } else { 1 }
        }
        other => {
            eprintln!("error: unknown action {}", other);
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    ];

    #[test]
    fn test_canonicalize_sorts_and_compacts() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(canonicalize(&v), b"{\"a\":2,\"b\":1}".to_vec());
    }

    #[test]
    fn test_canonicalize_escapes_non_ascii() {
        let v = json!({"k": "café"});
        assert_eq!(canonicalize(&v), b"{\"k\":\"caf\\u00e9\"}".to_vec());
    }

    #[test]
    fn test_sign_and_verify() {
        let key = FileKey::new(FIXED_SEED);
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {"id": "urn:example:1", "name": "Ada", "count": 3}
        });
        let signed = sign_document(&doc, &key, DEFAULT_CRYPTOSUITE, None).unwrap();
        assert_eq!(signed["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert!(verify_document(&signed));
    }

    #[test]
    fn test_verify_detects_tamper() {
        let key = FileKey::new(FIXED_SEED);
        let doc = json!({"credentialSubject": {"name": "Ada"}});
        let mut signed = sign_document(&doc, &key, DEFAULT_CRYPTOSUITE, None).unwrap();
        signed["credentialSubject"]["name"] = json!("Eve");
        assert!(!verify_document(&signed));
    }

    #[test]
    fn test_mldsa_p256_sign_and_verify() {
        let key = FileKey::new(FIXED_SEED);
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {"id": "urn:example:1", "name": "Ada", "count": 3}
        });
        let signed = sign_document(&doc, &key, "mldsa-87-p256", None).unwrap();
        assert_eq!(signed["proof"]["cryptosuite"], "mldsa-87-p256");
        assert!(verify_document(&signed));
    }

    #[test]
    fn test_mldsa_p256_detects_tamper() {
        let key = FileKey::new(FIXED_SEED);
        let doc = json!({"credentialSubject": {"name": "Ada"}});
        let mut signed = sign_document(&doc, &key, "mldsa-87-p256", None).unwrap();
        signed["credentialSubject"]["name"] = json!("Eve");
        assert!(!verify_document(&signed));
    }

    #[test]
    fn test_merkle_tree_certs_sign_and_verify() {
        let key = FileKey::new(FIXED_SEED);
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {"id": "urn:example:1", "name": "Ada"}
        });
        let signed = sign_document(&doc, &key, "merkle-tree-certs", None).unwrap();
        assert_eq!(signed["proof"]["cryptosuite"], "merkle-tree-certs");
        assert!(verify_document(&signed));
    }

    #[test]
    fn test_merkle_tree_certs_detects_tamper() {
        let key = FileKey::new(FIXED_SEED);
        let doc = json!({"credentialSubject": {"name": "Ada"}});
        let mut signed = sign_document(&doc, &key, "merkle-tree-certs", None).unwrap();
        signed["credentialSubject"]["name"] = json!("Eve");
        assert!(!verify_document(&signed));
    }

    #[test]
    fn test_cryptosuite_availability() {
        assert!(Cryptosuite::EddsaJcs2022.available());
        assert!(Cryptosuite::MldsaP256.available());
        assert!(Cryptosuite::MerkleTreeCerts.available());
    }

    // Cross-language interop: this document was signed by the Python tert.vc
    // implementation (FIXED_SEED, created fixed). Rust must verify it, proving
    // the canonicalization and Ed25519 proofs are byte-compatible.
    #[test]
    fn test_verify_python_signed_document() {
        let text = include_str!("../tests/fixtures/vc_interop.json");
        let doc: Value = serde_json::from_str(text).unwrap();
        assert!(verify_document(&doc));
    }

    // Cross-language interop for the post-quantum suites: these documents were
    // signed by the pure-Python tert.pq implementation (hybrid ML-DSA-87 +
    // ECDSA-P256, and Merkle Tree Certificates). Rust must verify them, proving
    // the FIPS 204 / P-256 / Merkle wire encodings are byte-compatible.
    #[test]
    fn test_verify_python_signed_mldsa_p256() {
        let text = include_str!("../tests/fixtures/vc_mldsa_interop.json");
        let doc: Value = serde_json::from_str(text).unwrap();
        assert_eq!(doc["proof"]["cryptosuite"], "mldsa-87-p256");
        assert!(verify_document(&doc));
    }

    #[test]
    fn test_verify_python_signed_merkle_tree_certs() {
        let text = include_str!("../tests/fixtures/vc_mtc_interop.json");
        let doc: Value = serde_json::from_str(text).unwrap();
        assert_eq!(doc["proof"]["cryptosuite"], "merkle-tree-certs");
        assert!(verify_document(&doc));
    }

    #[test]
    fn test_toml_roundtrip() {
        let key = FileKey::new(FIXED_SEED);
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {"id": "urn:example:1", "name": "Ada", "count": 3}
        });
        let signed = sign_document(&doc, &key, DEFAULT_CRYPTOSUITE, None).unwrap();
        let text = dump_document(&signed, DocFormat::Toml).unwrap();
        assert!(text.starts_with("[verifiableCredential]"));
        assert!(text.contains("\"@context\""));
        let reparsed: Value = load_toml(&text).unwrap();
        assert_eq!(reparsed, signed);
        assert!(verify_document(&reparsed));
    }

    #[test]
    fn test_all_formats_same_signature() {
        let key = FileKey::new(FIXED_SEED);
        let doc = json!({"credentialSubject": {"name": "Ada", "n": 7}});
        let signed = sign_document(&doc, &key, DEFAULT_CRYPTOSUITE, None).unwrap();
        for fmt in [DocFormat::Json, DocFormat::Yaml, DocFormat::Toml] {
            let text = dump_document(&signed, fmt).unwrap();
            let reparsed: Value = match fmt {
                DocFormat::Json => serde_json::from_str(&text).unwrap(),
                DocFormat::Yaml => serde_yaml::from_str(&text).unwrap(),
                DocFormat::Toml => load_toml(&text).unwrap(),
            };
            assert!(verify_document(&reparsed), "format {:?} failed to verify", fmt);
        }
    }

    // The Python-signed TOML fixture (provisional [verifiableCredential] table)
    // must verify in Rust too.
    #[test]
    fn test_verify_python_signed_toml() {
        let text = include_str!("../tests/fixtures/vc_interop.toml");
        let doc = load_toml(text).unwrap();
        assert!(verify_document(&doc));
    }
}
