//! Minimal, dependency-free Ed25519 + did:key primitives (Rust counterpart of
//! `tert.crypto`).
//!
//! - SHA-512 (FIPS 180-4) and Ed25519 (RFC 8032) using only `std`.
//! - `did:key` encoding for Ed25519 public keys (multicodec `0xed01` +
//!   base58btc multibase, yielding a `z6Mk...` identifier).
//!
//! The Ed25519 implementation is a direct port of the public-domain TweetNaCl
//! reference (Bernstein et al.). It is intentionally simple, not fast: it signs
//! small provenance documents. Interoperability with the Python `tert.crypto`
//! implementation (which is validated against OpenSSL) is asserted by a shared
//! fixed test vector.

pub const SEED_BYTES: usize = 32;
pub const PUBKEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;

// --- SHA-512 ---------------------------------------------------------------

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// SHA-512 over a byte slice.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u128).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA512_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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

    let mut out = [0u8; 64];
    for i in 0..8 {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

// --- Ed25519 field arithmetic (TweetNaCl port, value-semantics) ------------

type Gf = [i64; 16];

const GF0: Gf = [0; 16];
const GF1: Gf = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const D: Gf = [
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079,
    0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203,
];
const D2: Gf = [
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2,
    0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406,
];
const X: Gf = [
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231,
    0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
];
const Y: Gf = [
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
];
const SQRTM1: Gf = [
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099,
    0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83,
];
const L: [i64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
    0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

fn sel25519(p: Gf, q: Gf, b: i64) -> (Gf, Gf) {
    let c = !(b - 1);
    let mut pp = p;
    let mut qq = q;
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        pp[i] = p[i] ^ t;
        qq[i] = q[i] ^ t;
    }
    (pp, qq)
}

fn pack25519(n: Gf) -> [u8; 32] {
    let mut t = n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    for _ in 0..2 {
        let mut m = [0i64; 16];
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        let (nt, _nm) = sel25519(t, m, 1 - b);
        t = nt;
    }
    let mut o = [0u8; 32];
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
    }
    o
}

fn unpack25519(n: &[u8; 32]) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = n[2 * i] as i64 + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
    o
}

fn fa(a: Gf, b: Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn fz(a: Gf, b: Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

fn fm(a: Gf, b: Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = [0i64; 16];
    o[..16].copy_from_slice(&t[..16]);
    car25519(&mut o);
    car25519(&mut o);
    o
}

fn fs(a: Gf) -> Gf {
    fm(a, a)
}

fn inv25519(input: Gf) -> Gf {
    let mut c = input;
    for a in (0..=253).rev() {
        c = fs(c);
        if a != 2 && a != 4 {
            c = fm(c, input);
        }
    }
    c
}

fn pow2523(input: Gf) -> Gf {
    let mut c = input;
    for a in (0..=250).rev() {
        c = fs(c);
        if a != 1 {
            c = fm(c, input);
        }
    }
    c
}

// --- Ed25519 group operations ----------------------------------------------

type Point = [Gf; 4];

fn point_add(p: Point, q: Point) -> Point {
    let a = fm(fz(p[1], p[0]), fz(q[1], q[0]));
    let b = fm(fa(p[0], p[1]), fa(q[0], q[1]));
    let c = fm(fm(p[3], q[3]), D2);
    let dd = fm(p[2], q[2]);
    let d = fa(dd, dd);
    let e = fz(b, a);
    let f = fz(d, c);
    let g = fa(d, c);
    let h = fa(b, a);
    [fm(e, f), fm(h, g), fm(g, f), fm(e, h)]
}

fn cswap(p: &mut Point, q: &mut Point, b: i64) {
    for i in 0..4 {
        let (np, nq) = sel25519(p[i], q[i], b);
        p[i] = np;
        q[i] = nq;
    }
}

fn scalarmult(q_in: Point, s: &[u8; 32]) -> Point {
    let mut p: Point = [GF0, GF1, GF1, GF0];
    let mut q = q_in;
    for i in (0..256).rev() {
        let b = ((s[i >> 3] >> (i & 7)) & 1) as i64;
        cswap(&mut p, &mut q, b);
        q = point_add(q, p);
        p = point_add(p, p);
        cswap(&mut p, &mut q, b);
    }
    p
}

fn scalarbase(s: &[u8; 32]) -> Point {
    let q: Point = [X, Y, GF1, fm(X, Y)];
    scalarmult(q, s)
}

fn par25519(a: Gf) -> u8 {
    pack25519(a)[0] & 1
}

fn pack_point(p: Point) -> [u8; 32] {
    let zi = inv25519(p[2]);
    let tx = fm(p[0], zi);
    let ty = fm(p[1], zi);
    let mut r = pack25519(ty);
    r[31] ^= par25519(tx) << 7;
    r
}

fn ct_eq_32(x: &[u8], y: &[u8]) -> bool {
    let mut d = 0u8;
    for i in 0..32 {
        d |= x[i] ^ y[i];
    }
    d == 0
}

fn neq25519(a: Gf, b: Gf) -> bool {
    !ct_eq_32(&pack25519(a), &pack25519(b))
}

fn unpackneg(p: &[u8; 32]) -> Option<Point> {
    let mut r: Point = [GF0, GF0, GF1, GF0];
    r[1] = unpack25519(p);
    let mut num = fs(r[1]);
    let mut den = fm(num, D);
    num = fz(num, r[2]);
    den = fa(r[2], den);
    let den2 = fs(den);
    let den4 = fs(den2);
    let den6 = fm(den4, den2);
    let mut t = fm(den6, num);
    t = fm(t, den);
    t = pow2523(t);
    t = fm(t, num);
    t = fm(t, den);
    t = fm(t, den);
    r[0] = fm(t, den);
    let mut chk = fs(r[0]);
    chk = fm(chk, den);
    if neq25519(chk, num) {
        r[0] = fm(r[0], SQRTM1);
    }
    chk = fs(r[0]);
    chk = fm(chk, den);
    if neq25519(chk, num) {
        return None;
    }
    if par25519(r[0]) == (p[31] >> 7) {
        r[0] = fz(GF0, r[0]);
    }
    r[3] = fm(r[0], r[1]);
    Some(r)
}

fn modl(r: &mut [u8; 32], x: &mut [i64; 64]) {
    for i in (32..64).rev() {
        let mut carry = 0i64;
        let mut j = i - 32;
        while j < i - 12 {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
            j += 1;
        }
        x[j] += carry;
        x[i] = 0;
    }
    let mut carry = 0i64;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * L[j];
    }
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
}

fn reduce(r: &mut [u8; 64]) {
    let mut x = [0i64; 64];
    for i in 0..64 {
        x[i] = r[i] as i64;
    }
    for byte in r.iter_mut() {
        *byte = 0;
    }
    let mut r32 = [0u8; 32];
    modl(&mut r32, &mut x);
    r[..32].copy_from_slice(&r32);
}

// --- Public Ed25519 API ----------------------------------------------------

/// Derive the 32-byte Ed25519 public key from a 32-byte seed.
pub fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let mut d = sha512(seed);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    let scalar: [u8; 32] = d[0..32].try_into().unwrap();
    pack_point(scalarbase(&scalar))
}

/// Sign `msg` with the Ed25519 key derived from `seed` (64-byte signature).
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let pk = pubkey_from_seed(seed);
    let mut d = sha512(seed);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    let mut buf = Vec::with_capacity(32 + msg.len());
    buf.extend_from_slice(&d[32..64]);
    buf.extend_from_slice(msg);
    let mut r = sha512(&buf);
    reduce(&mut r);
    let r_scalar: [u8; 32] = r[0..32].try_into().unwrap();

    let rr = pack_point(scalarbase(&r_scalar));

    let mut hbuf = Vec::with_capacity(64 + msg.len());
    hbuf.extend_from_slice(&rr);
    hbuf.extend_from_slice(&pk);
    hbuf.extend_from_slice(msg);
    let mut h = sha512(&hbuf);
    reduce(&mut h);

    let mut x = [0i64; 64];
    for i in 0..32 {
        x[i] = r[i] as i64;
    }
    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += (h[i] as i64) * (d[j] as i64);
        }
    }
    let mut s = [0u8; 32];
    modl(&mut s, &mut x);

    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&rr);
    sig[32..64].copy_from_slice(&s);
    sig
}

/// Verify a 64-byte Ed25519 signature. Returns true iff valid.
pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let q = match unpackneg(pk) {
        Some(q) => q,
        None => return false,
    };
    let mut hbuf = Vec::with_capacity(64 + msg.len());
    hbuf.extend_from_slice(&sig[0..32]);
    hbuf.extend_from_slice(pk);
    hbuf.extend_from_slice(msg);
    let mut h = sha512(&hbuf);
    reduce(&mut h);
    let h_scalar: [u8; 32] = h[0..32].try_into().unwrap();
    let p = scalarmult(q, &h_scalar);
    let s_scalar: [u8; 32] = sig[32..64].try_into().unwrap();
    let p2 = point_add(p, scalarbase(&s_scalar));
    let t = pack_point(p2);
    ct_eq_32(&sig[0..32], &t)
}

// --- base58btc / multibase / did:key ---------------------------------------

const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Encode bytes as base58btc (Bitcoin alphabet), without a multibase prefix.
pub fn base58btc_encode(data: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for &byte in data {
        if byte == 0 {
            out.push('1');
        } else {
            break;
        }
    }
    for &d in digits.iter().rev() {
        out.push(B58_ALPHABET[d as usize] as char);
    }
    out
}

/// Encode bytes as multibase base58btc (`z` prefix).
pub fn multibase_base58btc(data: &[u8]) -> String {
    format!("z{}", base58btc_encode(data))
}

/// Return the `did:key` identifier for an Ed25519 public key.
pub fn did_key_from_pubkey(pk: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(2 + PUBKEY_BYTES);
    buf.extend_from_slice(&ED25519_MULTICODEC);
    buf.extend_from_slice(pk);
    format!("did:key:{}", multibase_base58btc(&buf))
}

/// Decode a base58btc string (no multibase prefix) back to bytes.
pub fn base58btc_decode(text: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for ch in text.chars() {
        let val = B58_ALPHABET.iter().position(|&c| c as char == ch)?;
        let mut carry = val as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out: Vec<u8> = Vec::new();
    for ch in text.chars() {
        if ch == '1' {
            out.push(0);
        } else {
            break;
        }
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
    Some(out)
}

/// Extract the Ed25519 public key from a `did:key` identifier.
pub fn pubkey_from_did_key(did: &str) -> Option<[u8; 32]> {
    let rest = did.strip_prefix("did:key:z")?;
    let raw = base58btc_decode(rest)?;
    if raw.len() != 2 + PUBKEY_BYTES || raw[0] != 0xed || raw[1] != 0x01 {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[2..]);
    Some(pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared interop vector (must match tests/test_crypto_vector.py).
    const FIXED_SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    ];
    const MESSAGE: &[u8] = b"tert interop vector";
    const EXPECTED_PUBKEY_HEX: &str =
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const EXPECTED_SIG_HEX: &str = concat!(
        "9fb183d7857702b7d322421901c85e8c9aea7f7d355824164f7e06e394e7f262",
        "71f9793b55d8406efdc95c00defb04a0e90b6c9b60640688c8e04a9dc4ba7701"
    );
    const EXPECTED_DID: &str = "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7";

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_sha512_known_vectors() {
        assert_eq!(
            to_hex(&sha512(b"")),
            concat!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
        assert_eq!(
            to_hex(&sha512(b"abc")),
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn test_pubkey_vector() {
        assert_eq!(to_hex(&pubkey_from_seed(&FIXED_SEED)), EXPECTED_PUBKEY_HEX);
    }

    #[test]
    fn test_signature_vector() {
        assert_eq!(to_hex(&sign(&FIXED_SEED, MESSAGE)), EXPECTED_SIG_HEX);
    }

    #[test]
    fn test_did_vector() {
        assert_eq!(did_key_from_pubkey(&pubkey_from_seed(&FIXED_SEED)), EXPECTED_DID);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let msg = b"some provenance document";
        let pk = pubkey_from_seed(&FIXED_SEED);
        let sig = sign(&FIXED_SEED, msg);
        assert!(verify(&pk, msg, &sig));
    }

    #[test]
    fn test_verify_rejects_tampered_message() {
        let pk = pubkey_from_seed(&FIXED_SEED);
        let sig = sign(&FIXED_SEED, b"hello");
        assert!(!verify(&pk, b"hell0", &sig));
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let pk = pubkey_from_seed(&FIXED_SEED);
        let mut sig = sign(&FIXED_SEED, b"hello");
        sig[0] ^= 0x01;
        assert!(!verify(&pk, b"hello", &sig));
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let mut other = FIXED_SEED;
        other[0] ^= 0xff;
        let pk = pubkey_from_seed(&other);
        let sig = sign(&FIXED_SEED, b"hello");
        assert!(!verify(&pk, b"hello", &sig));
    }

    #[test]
    fn test_base58_known_vector() {
        assert_eq!(base58btc_encode(b"hello world"), "StV1DL6CwTryKyV");
    }

    #[test]
    fn test_did_prefix_is_z6mk() {
        let did = did_key_from_pubkey(&pubkey_from_seed(&FIXED_SEED));
        assert!(did.starts_with("did:key:z6Mk"));
    }

    #[test]
    fn test_did_key_roundtrip() {
        let pk = pubkey_from_seed(&FIXED_SEED);
        let did = did_key_from_pubkey(&pk);
        assert_eq!(pubkey_from_did_key(&did), Some(pk));
        assert_eq!(pubkey_from_did_key("did:web:example.com"), None);
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Loads the SAME fixture as tests/test_crypto_vector.py and checks every
    // vector, guaranteeing the Python and Rust implementations agree on one
    // shared data set.
    #[test]
    fn test_shared_interop_vectors() {
        let text = include_str!("../tests/fixtures/crypto_vectors.json");
        let vectors: serde_json::Value = serde_json::from_str(text).unwrap();
        let arr = vectors.as_array().unwrap();
        assert!(arr.len() >= 5);
        for vec in arr {
            let seed_bytes = hex_to_bytes(vec["seed_hex"].as_str().unwrap());
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            let msg = vec["message_utf8"].as_str().unwrap().as_bytes();
            let pk = pubkey_from_seed(&seed);
            assert_eq!(to_hex(&pk), vec["pubkey_hex"].as_str().unwrap());
            assert_eq!(to_hex(&sign(&seed, msg)), vec["sig_hex"].as_str().unwrap());
            assert_eq!(did_key_from_pubkey(&pk), vec["did"].as_str().unwrap());

            let sig_bytes = hex_to_bytes(vec["sig_hex"].as_str().unwrap());
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&sig_bytes);
            assert!(verify(&pk, msg, &sig));
        }
    }
}
