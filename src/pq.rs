//! Post-quantum and classical primitives backing two Data Integrity
//! cryptosuites:
//!
//!   * `mldsa-87-p256`     - a hybrid (composite) signature: ML-DSA-87
//!     (FIPS 204, lattice post-quantum) **and** ECDSA-P256. A verifier must
//!     accept *both* component signatures, so the construction is secure as
//!     long as either algorithm remains unbroken. This mirrors the IETF
//!     composite-signature approach for the post-quantum transition.
//!
//!   * `merkle-tree-certs` - Merkle Tree Certificates, the design Cloudflare
//!     and Let's Encrypt are deploying for a post-quantum WebPKI
//!     (draft-davidben-tls-merkle-tree-certs). Certificates are issued in
//!     *batches*: the issuer arranges the per-credential assertions into a
//!     Merkle tree and signs only the tree head (the "landmark"). Each
//!     credential then carries a signatureless *inclusion proof* (the sibling
//!     hashes along its path to the head) instead of its own signature. A
//!     verifier recomputes the tree head from the assertion + proof and checks
//!     the single batch signature over that head.
//!
//! The heavy cryptography (ML-DSA-87, ECDSA-P256, SHA-256) uses audited
//! pure-Rust crates; the Merkle tree, domain separation, and wire encodings are
//! implemented here.

use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer as _, Verifier as _};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

// --- deterministic RNG -----------------------------------------------------

/// A deterministic CSPRNG (SHA-256 in counter mode) used to derive key
/// material reproducibly from a 32-byte seed. Reproducible key generation lets
/// a `keys_dir` seed file map to a stable ML-DSA-87 / P-256 keypair.
pub struct SeededRng {
    key: [u8; 32],
    counter: u64,
    buffer: [u8; 32],
    pos: usize,
}

impl SeededRng {
    pub fn new(seed: &[u8], domain: &[u8]) -> SeededRng {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(seed);
        let key: [u8; 32] = h.finalize().into();
        let mut rng = SeededRng {
            key,
            counter: 0,
            buffer: [0u8; 32],
            pos: 32,
        };
        rng.refill();
        rng
    }

    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(self.key);
        h.update(self.counter.to_le_bytes());
        self.buffer = h.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            if self.pos == self.buffer.len() {
                self.refill();
            }
            let take = (self.buffer.len() - self.pos).min(dest.len() - i);
            dest[i..i + take].copy_from_slice(&self.buffer[self.pos..self.pos + take]);
            self.pos += take;
            i += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeededRng {}

// --- small binary writer/reader -------------------------------------------

fn put_u16(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u16).to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u16(out, b.len());
    out.extend_from_slice(b);
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_be_bytes(a))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
}

// ===========================================================================
// mldsa-87-p256 hybrid signatures
// ===========================================================================

const HYBRID_MAGIC: &[u8; 4] = b"MLP1";

/// A hybrid key pair derived deterministically from a 32-byte seed.
pub struct HybridKey {
    p256_sk: SigningKey,
    p256_pk: VerifyingKey,
    mldsa_sk: ml_dsa_87::PrivateKey,
    mldsa_pk: ml_dsa_87::PublicKey,
}

impl HybridKey {
    /// Deterministically derive both component keys from `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Result<HybridKey, String> {
        // P-256: derive a scalar from the seed; retry on the (negligible)
        // chance it is zero or >= the group order.
        let mut p256_sk = None;
        for ctr in 0u8..16 {
            let mut h = Sha256::new();
            h.update(b"tert-mldsa-87-p256/p256");
            h.update(seed);
            h.update([ctr]);
            let scalar: [u8; 32] = h.finalize().into();
            if let Ok(sk) = SigningKey::from_slice(&scalar) {
                p256_sk = Some(sk);
                break;
            }
        }
        let p256_sk = p256_sk.ok_or_else(|| "failed to derive P-256 key".to_string())?;
        let p256_pk = *p256_sk.verifying_key();

        // ML-DSA-87: seed a deterministic RNG and run FIPS 204 key generation.
        let mut rng = SeededRng::new(seed, b"tert-mldsa-87-p256/ml-dsa-87");
        let (mldsa_pk, mldsa_sk) = ml_dsa_87::try_keygen_with_rng(&mut rng)
            .map_err(|e| format!("ML-DSA-87 keygen failed: {}", e))?;

        Ok(HybridKey {
            p256_sk,
            p256_pk,
            mldsa_sk,
            mldsa_pk,
        })
    }

    /// Sign `msg` with both algorithms and return a self-describing blob
    /// carrying both public keys and both signatures.
    pub fn sign(&self, seed: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>, String> {
        let p256_sig: P256Signature = self
            .p256_sk
            .try_sign(msg)
            .map_err(|e| format!("P-256 signing failed: {}", e))?;
        let mut rng = SeededRng::new(seed, b"tert-mldsa-87-p256/sign");
        let mldsa_sig = self
            .mldsa_sk
            .try_sign_with_rng(&mut rng, msg, &[])
            .map_err(|e| format!("ML-DSA-87 signing failed: {}", e))?;

        let p256_pk = self.p256_pk.to_encoded_point(true);
        let mldsa_pk = self.mldsa_pk.clone().into_bytes();

        let mut out = Vec::new();
        out.extend_from_slice(HYBRID_MAGIC);
        put_bytes(&mut out, p256_pk.as_bytes());
        put_bytes(&mut out, &mldsa_pk);
        put_bytes(&mut out, &p256_sig.to_bytes());
        put_bytes(&mut out, &mldsa_sig);
        Ok(out)
    }
}

/// Verify a hybrid blob over `msg`. Both component signatures must be valid.
pub fn hybrid_verify(blob: &[u8], msg: &[u8]) -> bool {
    let mut r = Reader::new(blob);
    match r.take(4) {
        Some(m) if m == HYBRID_MAGIC => {}
        _ => return false,
    }
    let p256_pk_b = match r.bytes() {
        Some(b) => b,
        None => return false,
    };
    let mldsa_pk_b = match r.bytes() {
        Some(b) => b,
        None => return false,
    };
    let p256_sig_b = match r.bytes() {
        Some(b) => b,
        None => return false,
    };
    let mldsa_sig_b = match r.bytes() {
        Some(b) => b,
        None => return false,
    };

    // P-256 component.
    let p256_pk = match VerifyingKey::from_sec1_bytes(p256_pk_b) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let p256_sig = match P256Signature::from_slice(p256_sig_b) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if p256_pk.verify(msg, &p256_sig).is_err() {
        return false;
    }

    // ML-DSA-87 component.
    if mldsa_pk_b.len() != ml_dsa_87::PK_LEN || mldsa_sig_b.len() != ml_dsa_87::SIG_LEN {
        return false;
    }
    let mut pk_arr = [0u8; ml_dsa_87::PK_LEN];
    pk_arr.copy_from_slice(mldsa_pk_b);
    let mldsa_pk = match ml_dsa_87::PublicKey::try_from_bytes(pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let mut sig_arr = [0u8; ml_dsa_87::SIG_LEN];
    sig_arr.copy_from_slice(mldsa_sig_b);
    mldsa_pk.verify(msg, &sig_arr, &[])
}

// ===========================================================================
// merkle-tree-certs (draft-davidben-tls-merkle-tree-certs)
// ===========================================================================

const MTC_MAGIC: &[u8; 4] = b"MTC1";

// Domain-separation distinguishers for tree-node hashing (mirrors the draft's
// HashEmpty / HashNode / HashAssertion split).
const D_EMPTY: u8 = 0;
const D_NODE: u8 = 1;
const D_ASSERTION: u8 = 2;

/// Hash of an empty subtree.
fn hash_empty(issuer: &[u8], batch: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([D_EMPTY]);
    h.update((issuer.len() as u32).to_be_bytes());
    h.update(issuer);
    h.update(batch.to_be_bytes());
    h.finalize().into()
}

/// Leaf hash binding an assertion to its batch and position.
fn hash_assertion(issuer: &[u8], batch: u32, index: u64, assertion: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([D_ASSERTION]);
    h.update((issuer.len() as u32).to_be_bytes());
    h.update(issuer);
    h.update(batch.to_be_bytes());
    h.update(index.to_be_bytes());
    h.update((assertion.len() as u32).to_be_bytes());
    h.update(assertion);
    h.finalize().into()
}

/// Internal node hash over its two children.
fn hash_node(issuer: &[u8], batch: u32, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([D_NODE]);
    h.update((issuer.len() as u32).to_be_bytes());
    h.update(issuer);
    h.update(batch.to_be_bytes());
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Merkle tree over a batch of assertions (RFC 6962-style: lone nodes are
/// promoted unchanged) with MTC domain separation.
pub struct MerkleTree {
    issuer: Vec<u8>,
    batch: u32,
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Build a tree from already-canonicalized assertions.
    pub fn build(issuer: &[u8], batch: u32, assertions: &[Vec<u8>]) -> MerkleTree {
        let leaves: Vec<[u8; 32]> = assertions
            .iter()
            .enumerate()
            .map(|(i, a)| hash_assertion(issuer, batch, i as u64, a))
            .collect();
        MerkleTree {
            issuer: issuer.to_vec(),
            batch,
            leaves,
        }
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    /// The signed-over tree head (root). Empty batches hash to `hash_empty`.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return hash_empty(&self.issuer, self.batch);
        }
        self.root_of(&self.leaves)
    }

    fn root_of(&self, level: &[[u8; 32]]) -> [u8; 32] {
        if level.len() == 1 {
            return level[0];
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(hash_node(&self.issuer, self.batch, &level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(level[i]); // promote lone node
                i += 1;
            }
        }
        self.root_of(&next)
    }

    /// Inclusion proof for leaf `index`: the sibling hash at each level paired
    /// with a flag indicating whether the sibling sits on the right.
    pub fn inclusion_proof(&self, index: usize) -> Option<Vec<(bool, [u8; 32])>> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut proof = Vec::new();
        let mut level = self.leaves.clone();
        let mut idx = index;
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    if i == idx {
                        proof.push((true, level[i + 1])); // sibling is on the right
                    } else if i + 1 == idx {
                        proof.push((false, level[i])); // sibling is on the left
                    }
                    next.push(hash_node(&self.issuer, self.batch, &level[i], &level[i + 1]));
                    i += 2;
                } else {
                    // lone node is promoted; no sibling recorded
                    next.push(level[i]);
                    i += 1;
                }
            }
            idx /= 2;
            level = next;
        }
        Some(proof)
    }
}

/// Recompute a tree head from an assertion and its inclusion proof.
fn fold_inclusion(
    issuer: &[u8],
    batch: u32,
    index: u64,
    assertion: &[u8],
    proof: &[(bool, [u8; 32])],
) -> [u8; 32] {
    let mut node = hash_assertion(issuer, batch, index, assertion);
    for (sibling_on_right, sibling) in proof {
        node = if *sibling_on_right {
            hash_node(issuer, batch, &node, sibling)
        } else {
            hash_node(issuer, batch, sibling, &node)
        };
    }
    node
}

/// Bytes the issuer signs to certify a batch tree head (the "landmark").
pub fn treehead_signing_input(issuer: &[u8], batch: u32, tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"MerkleTreeCRT:treehead:v1");
    v.extend_from_slice(&(issuer.len() as u32).to_be_bytes());
    v.extend_from_slice(issuer);
    v.extend_from_slice(&batch.to_be_bytes());
    v.extend_from_slice(&tree_size.to_be_bytes());
    v.extend_from_slice(root);
    v
}

/// Encode a Merkle Tree Certificate proof value: the signed tree head plus the
/// inclusion proof needed to tie a single assertion to it.
#[allow(clippy::too_many_arguments)]
pub fn encode_mtc(
    issuer: &[u8],
    batch: u32,
    tree_size: u64,
    index: u64,
    root: &[u8; 32],
    treehead_sig: &[u8],
    proof: &[(bool, [u8; 32])],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MTC_MAGIC);
    put_bytes(&mut out, issuer);
    out.extend_from_slice(&batch.to_be_bytes());
    out.extend_from_slice(&tree_size.to_be_bytes());
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(root);
    put_bytes(&mut out, treehead_sig);
    put_u16(&mut out, proof.len());
    for (right, hash) in proof {
        out.push(if *right { 1 } else { 0 });
        out.extend_from_slice(hash);
    }
    out
}

/// A decoded Merkle Tree Certificate proof.
pub struct DecodedMtc {
    pub issuer: Vec<u8>,
    pub batch: u32,
    pub tree_size: u64,
    pub index: u64,
    pub root: [u8; 32],
    pub treehead_sig: Vec<u8>,
    pub proof: Vec<(bool, [u8; 32])>,
}

pub fn decode_mtc(blob: &[u8]) -> Option<DecodedMtc> {
    let mut r = Reader::new(blob);
    match r.take(4) {
        Some(m) if m == MTC_MAGIC => {}
        _ => return None,
    }
    let issuer = r.bytes()?.to_vec();
    let batch = r.u32()?;
    let tree_size = r.u64()?;
    let index = r.u64()?;
    let mut root = [0u8; 32];
    root.copy_from_slice(r.take(32)?);
    let treehead_sig = r.bytes()?.to_vec();
    let n = r.u16()?;
    let mut proof = Vec::with_capacity(n);
    for _ in 0..n {
        let dir = r.take(1)?[0];
        let mut h = [0u8; 32];
        h.copy_from_slice(r.take(32)?);
        proof.push((dir == 1, h));
    }
    Some(DecodedMtc {
        issuer,
        batch,
        tree_size,
        index,
        root,
        treehead_sig,
        proof,
    })
}

/// Verify a decoded MTC against an assertion: recompute the tree head from the
/// inclusion proof and confirm it matches the certified root. (The batch
/// signature over the root is checked separately by the caller, which holds the
/// issuer's verification key.)
pub fn mtc_recompute_root(dec: &DecodedMtc, assertion: &[u8]) -> [u8; 32] {
    fold_inclusion(&dec.issuer, dec.batch, dec.index, assertion, &dec.proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    #[test]
    fn test_seeded_rng_is_deterministic() {
        let mut a = SeededRng::new(&SEED, b"x");
        let mut b = SeededRng::new(&SEED, b"x");
        let mut ba = [0u8; 100];
        let mut bb = [0u8; 100];
        a.fill_bytes(&mut ba);
        b.fill_bytes(&mut bb);
        assert_eq!(ba, bb);
        let mut c = SeededRng::new(&SEED, b"y");
        let mut bc = [0u8; 100];
        c.fill_bytes(&mut bc);
        assert_ne!(ba, bc);
    }

    #[test]
    fn test_hybrid_keygen_is_deterministic() {
        let k1 = HybridKey::from_seed(&SEED).unwrap();
        let k2 = HybridKey::from_seed(&SEED).unwrap();
        assert_eq!(
            k1.p256_pk.to_encoded_point(true).as_bytes(),
            k2.p256_pk.to_encoded_point(true).as_bytes()
        );
        assert_eq!(
            k1.mldsa_pk.clone().into_bytes(),
            k2.mldsa_pk.clone().into_bytes()
        );
    }

    #[test]
    fn test_hybrid_sign_and_verify() {
        let key = HybridKey::from_seed(&SEED).unwrap();
        let msg = b"the quick brown fox";
        let blob = key.sign(&SEED, msg).unwrap();
        assert!(hybrid_verify(&blob, msg));
        assert!(!hybrid_verify(&blob, b"a different message"));
    }

    #[test]
    fn test_hybrid_rejects_tampered_blob() {
        let key = HybridKey::from_seed(&SEED).unwrap();
        let msg = b"hello";
        let mut blob = key.sign(&SEED, msg).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(!hybrid_verify(&blob, msg));
    }

    #[test]
    fn test_merkle_single_leaf_root_is_leaf() {
        let issuer = b"did:key:zABC";
        let assertions = vec![b"cert-0".to_vec()];
        let tree = MerkleTree::build(issuer, 7, &assertions);
        assert_eq!(tree.size(), 1);
        let proof = tree.inclusion_proof(0).unwrap();
        assert!(proof.is_empty());
        assert_eq!(
            fold_inclusion(issuer, 7, 0, b"cert-0", &proof),
            tree.root()
        );
    }

    #[test]
    fn test_merkle_inclusion_proofs_all_indices() {
        let issuer = b"did:key:zABC";
        // Deliberately non-power-of-two to exercise lone-node promotion.
        let assertions: Vec<Vec<u8>> = (0..5).map(|i| format!("cert-{}", i).into_bytes()).collect();
        let tree = MerkleTree::build(issuer, 3, &assertions);
        let root = tree.root();
        for (i, a) in assertions.iter().enumerate() {
            let proof = tree.inclusion_proof(i).unwrap();
            assert_eq!(
                fold_inclusion(issuer, 3, i as u64, a, &proof),
                root,
                "inclusion proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_merkle_wrong_assertion_fails() {
        let issuer = b"did:key:zABC";
        let assertions: Vec<Vec<u8>> = (0..4).map(|i| format!("cert-{}", i).into_bytes()).collect();
        let tree = MerkleTree::build(issuer, 1, &assertions);
        let root = tree.root();
        let proof = tree.inclusion_proof(2).unwrap();
        assert_ne!(fold_inclusion(issuer, 1, 2, b"forged", &proof), root);
    }

    #[test]
    fn test_mtc_encode_decode_roundtrip() {
        let issuer = b"did:key:zABC";
        let assertions: Vec<Vec<u8>> = (0..3).map(|i| format!("cert-{}", i).into_bytes()).collect();
        let tree = MerkleTree::build(issuer, 9, &assertions);
        let root = tree.root();
        let proof = tree.inclusion_proof(1).unwrap();
        let blob = encode_mtc(issuer, 9, 3, 1, &root, b"sig-bytes", &proof);
        let dec = decode_mtc(&blob).unwrap();
        assert_eq!(dec.issuer, issuer);
        assert_eq!(dec.batch, 9);
        assert_eq!(dec.tree_size, 3);
        assert_eq!(dec.index, 1);
        assert_eq!(dec.root, root);
        assert_eq!(dec.treehead_sig, b"sig-bytes");
        assert_eq!(mtc_recompute_root(&dec, &assertions[1]), root);
    }
}
