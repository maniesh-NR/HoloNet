//! holo-crypto — hand-written, std-only cryptographic primitives.
//!
//! Everything here is implemented from the specifications and validated
//! against official test vectors:
//! - SHA-256 / SHA-1 / MD5 (FIPS 180-4, RFC 1321)
//! - BLAKE2s (RFC 7693) — unkeyed hash + native keyed MAC
//! - HMAC-SHA256 (RFC 4231) and HMAC-SHA1
//! - HKDF-SHA256 / HKDF-SHA1 (RFC 5869)
//! - ChaCha20 (RFC 8439 §2), Poly1305 (RFC 8439 §2.5),
//!   ChaCha20-Poly1305 AEAD (RFC 8439 §2.8), XChaCha20 (draft-irtf-cfrg-xchacha)
//! - AES-128/192/256 encryption (FIPS-197) + GCM (NIST SP 800-38D)
//! - AES-CFB128 stream mode (NIST SP 800-38A §6.3) — PRIVATE primitive,
//!   mechanically enforced by the `cfb_usage_audit` test (record-0003 A2-C4)
//! - RSA signature VERIFICATION — RSASSA-PKCS1-v1_5 + RSASSA-PSS, SHA-256
//!   (RFC 8017 §8.1.2/§8.2.2/§9.1/§9.2) — over the hand-written `bignum`
//!   module (little-endian u64 limbs, CIOS Montgomery multiplication)
//! - OpenSSL `EVP_BytesToKey` (the classic Shadowsocks password KDF)
//!
//! Design notes for future sessions (the pitfalls that cost time before):
//! - Poly1305 uses 3×u64 limbs with u128 schoolbook products and the
//!   reduction identity 2^130 ≡ 5 (mod p); the accumulator stays < 2^128
//!   between blocks, so no final reduction is needed before adding `s`.
//! - The RFC 8439 §2.8.2 AEAD tag vector validates ChaCha20 keystream,
//!   Poly1305, the pad16 framing AND AAD handling end-to-end in one test.
//! - The AES S-box is *generated* (GF(2^8) inverse + affine transform),
//!   never transcribed — transcription errors are invisible until GCM breaks.
#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

pub mod sha256 {
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

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        // padded message
        let mut msg = data.to_vec();
        let bitlen = (data.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bitlen.to_be_bytes());

        for block in msg.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[4 * i],
                    block[4 * i + 1],
                    block[4 * i + 2],
                    block[4 * i + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
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
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }

    pub fn hex(data: &[u8]) -> String {
        crate::to_hex(&digest(data))
    }
}

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-4) — needed for HKDF-SHA1 (the Shadowsocks subkey KDF)
// ---------------------------------------------------------------------------

pub mod sha1 {
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        let mut msg = data.to_vec();
        let bitlen = (data.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bitlen.to_be_bytes());

        for block in msg.chunks(64) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[4 * i],
                    block[4 * i + 1],
                    block[4 * i + 2],
                    block[4 * i + 3],
                ]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
            for t in 0..80 {
                let (f, k) = match t {
                    0..=19 => ((b & c) | ((!b) & d), 0x5a827999u32),
                    20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                    _ => (b ^ c ^ d, 0xca62c1d6),
                };
                let tmp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[t]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = tmp;
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }
        let mut out = [0u8; 20];
        for i in 0..5 {
            out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// MD5 (RFC 1321) — only used by EVP_BytesToKey (Shadowsocks password KDF)
// ---------------------------------------------------------------------------

pub mod md5 {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut h: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
        let mut msg = data.to_vec();
        let bitlen = (data.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bitlen.to_le_bytes()); // MD5 pads length little-endian

        for block in msg.chunks(64) {
            let mut m = [0u32; 16];
            for i in 0..16 {
                m[i] = u32::from_le_bytes([
                    block[4 * i],
                    block[4 * i + 1],
                    block[4 * i + 2],
                    block[4 * i + 3],
                ]);
            }
            let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
            for i in 0..64 {
                let (f, g) = match i {
                    0..=15 => ((b & c) | ((!b) & d), i),
                    16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                    32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                    _ => (c ^ (b | (!d)), (7 * i) % 16),
                };
                let tmp = d;
                d = c;
                c = b;
                let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
                b = b.wrapping_add(sum.rotate_left(S[i]));
                a = tmp;
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
        }
        let mut out = [0u8; 16];
        for i in 0..4 {
            out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_le_bytes());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// HMAC (RFC 2104 / vectors RFC 4231)
// ---------------------------------------------------------------------------

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hmac_bytes(
        &|d| sha256::digest(d).to_vec(),
        32,
        64,
        key,
        data,
    ));
    out
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&hmac_bytes(
        &|d| sha1::digest(d).to_vec(),
        20,
        64,
        key,
        data,
    ));
    out
}

fn hmac_bytes<F>(hash: &F, out_len: usize, block: usize, key: &[u8], data: &[u8]) -> Vec<u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let mut k = vec![0u8; block];
    if key.len() > block {
        let d = hash(key);
        k[..d.len()].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = ipad;
    inner.extend_from_slice(data);
    let ih = hash(&inner);
    let mut outer = opad;
    outer.extend_from_slice(&ih);
    hash(&outer)[..out_len].to_vec()
}

// ---------------------------------------------------------------------------
// HKDF (RFC 5869)
// ---------------------------------------------------------------------------

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let prk = hmac_sha256(salt, ikm);
    expand(&|k, d| hmac_sha256(k, d).to_vec(), 32, &prk, info, out_len)
}

/// Bare HKDF-SHA256 **expand phase** (RFC 5869 §2.3): a caller-supplied PRK
/// is stretched into `out_len` bytes of OKM with `info`. The TLS 1.3 key
/// schedule (see the `tls13` module below) works in exactly this shape —
/// HKDF-Extract is applied separately with per-stage salts and the `info`
/// blob is an encoded HkdfLabel — so it needs the expand half of
/// [`hkdf_sha256`] on its own. Implemented by the crate's one private
/// `expand` helper shared with `hkdf_sha256`/`hkdf_sha1` (no duplicated
/// HKDF logic).
pub fn hkdf_sha256_expand(prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    expand(&|k, d| hmac_sha256(k, d).to_vec(), 32, prk, info, out_len)
}

/// HKDF-SHA1 — the Shadowsocks AEAD session-subkey KDF (info = "ss-subkey").
pub fn hkdf_sha1(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let prk = hmac_sha1(salt, ikm);
    expand(&|k, d| hmac_sha1(k, d).to_vec(), 20, &prk, info, out_len)
}

fn expand<F>(hmac_fn: &F, hlen: usize, prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8>
where
    F: Fn(&[u8], &[u8]) -> Vec<u8>,
{
    assert!(out_len <= 255 * hlen, "hkdf: requested too much output");
    let mut okm = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < out_len {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_fn(prk, &input);
        okm.extend_from_slice(&t);
        counter += 1;
    }
    okm.truncate(out_len);
    okm
}

// ---------------------------------------------------------------------------
// TLS 1.3 key schedule (RFC 8446 §7.1)
// ---------------------------------------------------------------------------

/// TLS 1.3 key-schedule helpers (RFC 8446 §7.1), SHA-256 only (Hash.length
/// = 32). RFC 8446 §7.1 defines, verbatim:
///
/// ```text
///    HKDF-Expand-Label(Secret, Label, Context, Length) =
///         HKDF-Expand(Secret, HkdfLabel, Length)
///
///    Where HkdfLabel is specified as:
///
///    struct {
///        uint16 length = Length;
///        opaque label<7..255> = "tls13 " + Label;
///        opaque context<0..255> = Context;
///    } HkdfLabel;
///
///    Derive-Secret(Secret, Label, Messages) =
///         HKDF-Expand-Label(Secret, Label,
///                           Transcript-Hash(Messages), Hash.length)
/// ```
///
/// ("0" in the schedule diagram is a string of Hash.length zero bytes;
/// HKDF-Extract takes Salt from the current secret state and IKM from the
/// new secret — RFC 8446 §7.1.) Every function here is validated against
/// the official RFC 8448 §3 "Simple 1-RTT Handshake" trace in the tests.
pub mod tls13 {
    use super::hkdf_sha256_expand;

    /// The `"tls13 "` prefix RFC 8446 §7.1 prepends to every label. The
    /// RFC's labels are all ASCII and carry no trailing NUL byte (§7.1).
    pub const LABEL_PREFIX: &[u8] = b"tls13 ";

    /// Encode the `HkdfLabel` struct of RFC 8446 §7.1 exactly as it goes on
    /// the wire (it *is* the HKDF-Expand `info` argument):
    ///
    /// ```text
    ///    struct {
    ///        uint16 length = Length;
    ///        opaque label<7..255> = "tls13 " + Label;
    ///        opaque context<0..255> = Context;
    ///    } HkdfLabel;
    /// ```
    ///
    /// Layout: u16be(out_len) || u8(6 + label.len()) || "tls13 " || label
    /// || u8(context.len()) || context. The label field must satisfy its
    /// <7..255> bound (i.e. `label` is non-empty) and `context` its
    /// <0..255> bound.
    pub fn encode_hkdf_label(label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
        assert!(
            out_len <= u16::MAX as usize,
            "tls13: HkdfLabel.length does not fit in uint16"
        );
        let full_label_len = LABEL_PREFIX.len() + label.len();
        assert!(
            (7..=255).contains(&full_label_len),
            "tls13: label field must be 7..255 bytes (\"tls13 \" + Label)"
        );
        assert!(context.len() <= 255, "tls13: context too long for HkdfLabel");
        let mut out = Vec::with_capacity(4 + full_label_len + context.len());
        out.extend_from_slice(&(out_len as u16).to_be_bytes());
        out.push(full_label_len as u8);
        out.extend_from_slice(LABEL_PREFIX);
        out.extend_from_slice(label);
        out.push(context.len() as u8);
        out.extend_from_slice(context);
        out
    }

    /// HKDF-Expand-Label (RFC 8446 §7.1): HKDF-Expand(Secret, HkdfLabel,
    /// Length) with the HkdfLabel wire encoding from [`encode_hkdf_label`].
    pub fn hkdf_expand_label(
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        out_len: usize,
    ) -> Vec<u8> {
        let info = encode_hkdf_label(label, context, out_len);
        hkdf_sha256_expand(secret, &info, out_len)
    }

    /// Derive-Secret (RFC 8446 §7.1): HKDF-Expand-Label(Secret, Label,
    /// Transcript-Hash(Messages), Hash.length) — so the output is always
    /// Hash.length = 32 bytes of SHA-256 output.
    ///
    /// NOTE: `transcript_hash` is the ALREADY-HASHED transcript. The caller
    /// computes it with [`crate::sha256::digest`] over the concatenation of
    /// the indicated handshake messages (type + length fields included,
    /// record layer headers excluded — RFC 8446 §7.1 Transcript-Hash). The
    /// tests pin this end-to-end against the RFC 8448 §3 trace, which
    /// publishes both the raw messages and the resulting hashes.
    pub fn derive_secret(secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        hkdf_expand_label(secret, label, transcript_hash, 32)
    }
}

// ---------------------------------------------------------------------------
// BLAKE2s (RFC 7693)
// ---------------------------------------------------------------------------

/// BLAKE2s — the 32-bit BLAKE2 hash/MAC (RFC 7693), landed as the S1b
/// primitive for the S2 WireGuard transport (Noise-IK hashing and the
/// keyed-MAC construction). Rotations are RIGHT (`rotate_right`, R1..R4
/// = 16, 12, 8, 7) — RFC 7693 §3.1 `>>>`, NOT the ChaCha family's left
/// rotations.
pub mod blake2s {
    /// Initialization vector (RFC 7693 §2.6 — the SHA-256 IV).
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// Message-word schedule SIGMA (RFC 7693 §2.7), taken from the §2.7
    /// table AND cross-checked verbatim against the `sigma[10][16]` table
    /// of the blake2s.c reference source in RFC Appendix D — two
    /// independent in-document sources, never a from-memory transcription
    /// (record-0003 A1-F5 / D-0020: one mis-transcribed SIGMA[3][8] killed
    /// the crashed session's orphan while its short-input KATs still
    /// passed). Guarded mechanically in the test module: the row
    /// permutation check (structure), the full Appendix B round trace
    /// (function, round-exact), and the Appendix E self-test (function,
    /// 48 digests including keyed and lengths ≥ 31 bytes).
    pub(crate) const SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    /// One-shot BLAKE2s (RFC 7693 §3.3). `key` up to 32 bytes (empty =
    /// unkeyed); `out_len` 1..=32. When keyed, the zero-padded key block
    /// is d[0]; non-final blocks get t = (i+1)*64 over the global block
    /// index (key block included), the final block gets t = ll (+64 when
    /// keyed); an unkeyed empty message hashes one all-zero block, t = 0.
    pub fn hash(key: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
        assert!(key.len() <= 32, "blake2s: key too long");
        assert!((1..=32).contains(&out_len), "blake2s: bad out_len");
        let ll = data.len() as u64;
        let kk = key.len();
        let mut h = IV;
        // Parameter block p[0] = 0x0101kknn (RFC 7693 §2.5, §3.3).
        h[0] ^= 0x0101_0000 ^ ((kk as u32) << 8) ^ (out_len as u32);

        let keyed = kk > 0;
        let data_blocks = if data.is_empty() { 0 } else { (data.len() + 63) / 64 };
        let mut block = [0u8; 64];

        if keyed {
            block[..kk].copy_from_slice(key); // zero-padded to bb (§3.3)
            if data_blocks == 0 {
                // keyed empty message: the key block IS the final block.
                compress(&mut h, &block, ll + 64, true, None);
            } else {
                compress(&mut h, &block, 64, false, None);
            }
        }
        for (j, chunk) in data.chunks(64).enumerate() {
            block = [0u8; 64];
            block[..chunk.len()].copy_from_slice(chunk);
            let last = j + 1 == data_blocks;
            let t: u64 = if last {
                ll + if keyed { 64 } else { 0 }
            } else {
                (((keyed as usize) + j + 1) * 64) as u64
            };
            compress(&mut h, &block, t, last, None);
        }
        if !keyed && data_blocks == 0 {
            compress(&mut h, &[0u8; 64], 0, true, None);
        }

        // First out_len bytes of h, little-endian (§3.3).
        let mut out = Vec::with_capacity(out_len);
        for word in h.iter() {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(out_len);
        out
    }

    /// Unkeyed BLAKE2s-256.
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let v = hash(&[], data, 32);
        v.try_into().unwrap()
    }

    /// Unkeyed BLAKE2s-256 as lowercase hex.
    pub fn hex(data: &[u8]) -> String {
        crate::to_hex(&digest(data))
    }

    /// Keyed BLAKE2s-256 — RFC 7693's native MAC construction (the
    /// WireGuard `BLAKE2s(key, ..)` shape; keys are 32 bytes).
    pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let v = hash(key, data, 32);
        v.try_into().unwrap()
    }

    /// Compression function F (RFC 7693 §3.2). `trace` collects v[0..15]
    /// before round 0 and after each of the 10 rounds — the exact shape
    /// of the RFC's Appendix B trace; production passes `None`, so the
    /// trace test exercises the one and only compression code path.
    fn compress(
        h: &mut [u32; 8],
        block: &[u8; 64],
        t: u64,
        last: bool,
        mut trace: Option<&mut Vec<[u32; 16]>>,
    ) {
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= t as u32; // low word of the offset counter
        v[13] ^= (t >> 32) as u32; // high word
        if last {
            v[14] = !v[14]; // f0 = ~0
        }
        if let Some(tr) = trace.as_deref_mut() {
            tr.push(v);
        }
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
        }
        for r in 0..10 {
            let s = SIGMA[r];
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
            if let Some(tr) = trace.as_deref_mut() {
                tr.push(v);
            }
        }
        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    /// Mixing function G (RFC 7693 §3.1) — rotations are RIGHT.
    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }

    /// Test-only: F over one block, returning (h', the 11 traced v states).
    #[cfg(test)]
    pub(crate) fn compress_round_trace(
        h: &[u32; 8],
        block: &[u8; 64],
        t: u64,
        last: bool,
    ) -> ([u32; 8], Vec<[u32; 16]>) {
        let mut hh = *h;
        let mut states = Vec::with_capacity(11);
        compress(&mut hh, block, t, last, Some(&mut states));
        (hh, states)
    }
}

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439)
// ---------------------------------------------------------------------------

pub mod chacha20 {
    /// One ChaCha20 block: 64 bytes of keystream for (key, counter, nonce).
    pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
        let mut st = [0u32; 16];
        st[0] = 0x61707865;
        st[1] = 0x3320646e;
        st[2] = 0x79622d32;
        st[3] = 0x6b206574;
        for i in 0..8 {
            st[4 + i] =
                u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        st[12] = counter;
        for i in 0..3 {
            st[13 + i] = u32::from_le_bytes([
                nonce[4 * i],
                nonce[4 * i + 1],
                nonce[4 * i + 2],
                nonce[4 * i + 3],
            ]);
        }
        let init = st;
        for _ in 0..10 {
            quarter(&mut st, 0, 4, 8, 12);
            quarter(&mut st, 1, 5, 9, 13);
            quarter(&mut st, 2, 6, 10, 14);
            quarter(&mut st, 3, 7, 11, 15);
            quarter(&mut st, 0, 5, 10, 15);
            quarter(&mut st, 1, 6, 11, 12);
            quarter(&mut st, 2, 7, 8, 13);
            quarter(&mut st, 3, 4, 9, 14);
        }
        let mut out = [0u8; 64];
        for i in 0..16 {
            out[4 * i..4 * i + 4].copy_from_slice(&st[i].wrapping_add(init[i]).to_le_bytes());
        }
        out
    }

    pub(crate) fn quarter(st: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        st[a] = st[a].wrapping_add(st[b]);
        st[d] ^= st[a];
        st[d] = st[d].rotate_left(16);
        st[c] = st[c].wrapping_add(st[d]);
        st[b] ^= st[c];
        st[b] = st[b].rotate_left(12);
        st[a] = st[a].wrapping_add(st[b]);
        st[d] ^= st[a];
        st[d] = st[d].rotate_left(8);
        st[c] = st[c].wrapping_add(st[d]);
        st[b] ^= st[c];
        st[b] = st[b].rotate_left(7);
    }

    /// XOR `data` with the ChaCha20 keystream starting at `counter`.
    /// (RFC 8439 §2.5.2 layout: RFC 8439 nonces are 12 bytes.)
    pub fn xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
        let mut ctr = counter;
        for chunk in data.chunks_mut(64) {
            let ks = block(key, ctr, nonce);
            for (b, k) in chunk.iter_mut().zip(ks.iter()) {
                *b ^= *k;
            }
            ctr = ctr.wrapping_add(1);
        }
    }
}

/// HChaCha20 (draft-irtf-cfrg-xchacha §2.2): derive a 32-byte subkey from a
/// 16-byte nonce. No final addition of the initial state; output words
/// 0..3 and 12..15 serialized little-endian.
pub fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut st = [0u32; 16];
    st[0] = 0x61707865;
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;
    for i in 0..8 {
        st[4 + i] =
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for i in 0..4 {
        st[12 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }
    for _ in 0..10 {
        chacha20::quarter(&mut st, 0, 4, 8, 12);
        chacha20::quarter(&mut st, 1, 5, 9, 13);
        chacha20::quarter(&mut st, 2, 6, 10, 14);
        chacha20::quarter(&mut st, 3, 7, 11, 15);
        chacha20::quarter(&mut st, 0, 5, 10, 15);
        chacha20::quarter(&mut st, 1, 6, 11, 12);
        chacha20::quarter(&mut st, 2, 7, 8, 13);
        chacha20::quarter(&mut st, 3, 4, 9, 14);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&st[i].to_le_bytes());
        out[16 + 4 * i..20 + 4 * i].copy_from_slice(&st[12 + i].to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Poly1305 (RFC 8439 §2.5)
// ---------------------------------------------------------------------------

pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // RFC 8439 clamp: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff as ONE
    // 128-bit number over the little-endian key bytes (this clears bytes
    // 3,7,11,15 low nibbles and bytes 4,8,12 high bits — verified against
    // the RFC 8439 §2.5.2 worked example "Clamped r: 806d5400e52447c0…").
    let r128 = u128::from_le_bytes(key[0..16].try_into().unwrap())
        & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;
    let r0 = r128 as u64;
    let r1 = (r128 >> 64) as u64;
    let s = u128::from_le_bytes(key[16..32].try_into().unwrap());

    // accumulator: h = h0 + h1·2^64 + h2·2^128, h < 2^130 and h < p between
    // blocks (h2 ≤ 3). p = 2^130 − 5, so only 2^130 (and higher powers that
    // reduce to it) may be folded — NEVER 2^128.
    let (mut h0, mut h1, mut h2): (u64, u64, u64) = (0, 0, 0);

    let mut i = 0;
    while i < msg.len() {
        let l = (msg.len() - i).min(16);
        let full = l == 16;
        // RFC 8439: n = le128(block) + 2^128 for full blocks; for a final
        // partial block n = le128(block || 0x01 || zeros).
        let (n0, n1, top) = if full {
            (
                u64::from_le_bytes(msg[i..i + 8].try_into().unwrap()),
                u64::from_le_bytes(msg[i + 8..i + 16].try_into().unwrap()),
                1u64,
            )
        } else {
            let mut pad = [0u8; 16];
            pad[..l].copy_from_slice(&msg[i..i + l]);
            pad[l] = 1;
            (
                u64::from_le_bytes(pad[0..8].try_into().unwrap()),
                u64::from_le_bytes(pad[8..16].try_into().unwrap()),
                0u64,
            )
        };
        // h += n + top·2^128 (exact limb-wise add)
        let (a, c1) = h0.overflowing_add(n0);
        h0 = a;
        let (b, c2) = h1.overflowing_add(n1);
        let (b, c3) = b.overflowing_add(c1 as u64);
        h1 = b;
        h2 += top + c2 as u64 + c3 as u64; // h2 ≤ 6 here

        // h = (h * r) mod p — schoolbook, 3 limbs × 2 limbs → 4+ limbs.
        // r < 2^127 (new clamp), so the top column can exceed 64 bits.
        let a0 = h0 as u128;
        let a1 = h1 as u128;
        let a2 = h2 as u128;
        let (r0b, r1b) = (r0 as u128, r1 as u128);
        let p00 = a0 * r0b;
        let c0 = p00 >> 64;
        let c1w = a0 * r1b + a1 * r0b + c0; // < 2^128
        let c2w = a1 * r1b + a2 * r0b + (c1w >> 64); // < 2^128
        let c3w = a2 * r1b + (c2w >> 64); // < 2^66 → may exceed 64 bits
        let s0 = p00 as u64;
        let s1 = c1w as u64;
        let s2 = c2w as u64;
        let s3 = (c3w & u64::MAX as u128) as u64;
        let hi3 = (c3w >> 64) as u64; // ≤ 3

        // fold mod p, only at 2^130 (≡ 5):
        //   s3·2^192 ≡ 5·s3·2^62 and hi3·2^256 ≡ 5·hi3·2^126 (mod p).
        // Each folded term can reach ~2^129, so it is split by position
        // into a part inside `lo` (< 2^128) and carries into `hi`.
        let mut lo: u128 = (s0 as u128) | ((s1 as u128) << 64);
        let mut hi: u128 = s2 as u128;

        // term 1: 5·s3·2^62
        let u = 5u128 * (s3 as u128); // < 2^67
        let pa = (u & 3) << 62; // < 2^64
        let w = u >> 2; // < 2^65
        let w_lo = w & u64::MAX as u128;
        let w_hi = w >> 64; // ≤ 1
        let (l1, c1) = lo.overflowing_add(pa);
        let (l2, c2) = l1.overflowing_add(w_lo << 64);
        lo = l2;
        hi += w_hi + c1 as u128 + c2 as u128;

        // term 2: 20·hi3·2^124 (= 5·hi3·2^126; hi3 ≤ 3 → < 2^128)
        let v = 20u128 * (hi3 as u128); // ≤ 60
        let (l3, c3) = lo.overflowing_add((v & 15) << 124);
        lo = l3;
        hi += (v >> 4) + c3 as u128;

        // now value = lo + hi·2^128 ≡ prod (mod p)
        while hi > 3 {
            let t = hi >> 2; // 2^130 units → ×5
            hi &= 3;
            let add = 5 * t;
            let (nl, ov) = lo.overflowing_add(add);
            lo = nl;
            if ov {
                hi += 1;
            }
        }
        // value = lo + hi·2^128 with hi ≤ 3 → value < 4·2^128 = 2^130.
        // p = 2^130 − 5 → value ≥ p only when hi == 3 and lo ≥ 2^128 − 5.
        if hi == 3 && lo >= u128::MAX - 4 {
            lo = lo.wrapping_add(5); // value − p
            hi = 0;
        }
        h0 = lo as u64;
        h1 = (lo >> 64) as u64;
        h2 = hi as u64;
        i += 16;
    }

    // h < p (fully reduced). tag = (h + s) mod 2^128.
    let tag = ((h0 as u128) | ((h1 as u128) << 64)).wrapping_add(s);
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)
// ---------------------------------------------------------------------------

pub const POLY_TAG: usize = 16;

/// AEAD-encrypt: returns ciphertext || tag.
pub fn aead_chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let pk = poly_key(key, nonce);
    let mut ct = plaintext.to_vec();
    chacha20::xor(key, 1, nonce, &mut ct);
    let tag = poly1305(&pk, &mac_data(aad, &ct));
    let mut out = ct;
    out.extend_from_slice(&tag);
    out
}

/// AEAD-decrypt: constant-time tag check, then plaintext (without tag).
pub fn aead_chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if ct_and_tag.len() < POLY_TAG {
        return Err("aead: truncated ciphertext");
    }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - POLY_TAG);
    let pk = poly_key(key, nonce);
    let expect = poly1305(&pk, &mac_data(aad, ct));
    if !ct_eq(&expect, tag) {
        return Err("aead: tag mismatch");
    }
    let mut pt = ct.to_vec();
    chacha20::xor(key, 1, nonce, &mut pt);
    Ok(pt)
}

/// XChaCha20-Poly1305: 24-byte nonce. First 16 bytes → HChaCha20 subkey;
/// effective nonce = 0x00000000 || nonce[16..24].
pub fn aead_xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut sub = [0u8; 32];
    sub.copy_from_slice(&hchacha20(key, nonce[0..16].try_into().unwrap()));
    let n12 = zero_prefixed_nonce(&nonce[16..24]);
    aead_chacha20poly1305_encrypt(&sub, &n12, aad, plaintext)
}

pub fn aead_xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut sub = [0u8; 32];
    sub.copy_from_slice(&hchacha20(key, nonce[0..16].try_into().unwrap()));
    let n12 = zero_prefixed_nonce(&nonce[16..24]);
    aead_chacha20poly1305_decrypt(&sub, &n12, aad, ct_and_tag)
}

fn zero_prefixed_nonce(last8: &[u8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(last8);
    n
}

fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let blk = chacha20::block(key, 0, nonce);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&blk[..32]);
    pk
}

/// RFC 8439 §2.8 MAC input: aad || pad16 || ct || pad16 || le64(len_aad) || le64(len_ct)
fn mac_data(aad: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(aad.len() + ct.len() + 32);
    m.extend_from_slice(aad);
    m.extend(PAD16[aad.len() % 16..].iter().copied());
    m.extend_from_slice(ct);
    m.extend(PAD16[ct.len() % 16..].iter().copied());
    m.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    m.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    m
}

const PAD16: [u8; 16] = [0u8; 16];

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// AES (FIPS-197) — encryption only (GCM needs no block decryption)
// ---------------------------------------------------------------------------

pub mod aes {
    /// S-box generated from the GF(2^8) inverse + FIPS-197 affine transform
    /// (computed once, then cached — never transcribed by hand).
    fn sbox() -> &'static [u8; 256] {
        static SBOX: std::sync::OnceLock<[u8; 256]> = std::sync::OnceLock::new();
        SBOX.get_or_init(|| {
            let mut inv = [0u8; 256];
            for a in 1..256u16 {
                for b in 1..256u16 {
                    if gf_mul(a as u8, b as u8) == 1 {
                        inv[a as usize] = b as u8;
                        break;
                    }
                }
            }
            let mut box_ = [0u8; 256];
            for x in 0..256usize {
                let v = inv[x];
                let s = v
                    ^ v.rotate_left(1)
                    ^ v.rotate_left(2)
                    ^ v.rotate_left(3)
                    ^ v.rotate_left(4)
                    ^ 0x63;
                box_[x] = if x == 0 { 0x63 } else { s };
            }
            box_
        })
    }

    fn gf_mul(a: u8, b: u8) -> u8 {
        let mut a = a;
        let mut b = b;
        let mut p = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    pub fn xtime(x: u8) -> u8 {
        let hi = x & 0x80;
        let r = x << 1;
        if hi != 0 {
            r ^ 0x1b
        } else {
            r
        }
    }

    pub struct Aes {
        pub round_keys: Vec<[u8; 16]>, // Nr+1 round keys
    }

    impl Aes {
        pub fn new(key: &[u8]) -> Aes {
            assert!(matches!(key.len(), 16 | 24 | 32), "aes: key size");
            let nk = key.len() / 4;
            let nr = nk + 6;
            let sbox = sbox();
            let mut w = [[0u8; 4]; 60]; // max 4*(Nr+1) words
            for i in 0..nk {
                w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
            }
            const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
            for i in nk..(4 * (nr + 1)) {
                let mut temp = w[i - 1];
                if i % nk == 0 {
                    // RotWord([a0,a1,a2,a3]) = [a1,a2,a3,a0], then SubWord
                    temp.rotate_left(1);
                    for b in temp.iter_mut() {
                        *b = sbox[*b as usize];
                    }
                    temp[0] ^= RCON[i / nk - 1];
                } else if nk > 6 && i % nk == 4 {
                    for b in temp.iter_mut() {
                        *b = sbox[*b as usize];
                    }
                }
                for j in 0..4 {
                    w[i][j] = w[i - nk][j] ^ temp[j];
                }
            }
            let mut round_keys = Vec::with_capacity(nr + 1);
            for r in 0..=(nr) {
                let mut rk = [0u8; 16];
                for i in 0..4 {
                    rk[4 * i..4 * i + 4].copy_from_slice(&w[4 * r + i]);
                }
                round_keys.push(rk);
            }
            Aes { round_keys }
        }

        pub fn encrypt_block(&self, block: &mut [u8; 16]) {
            let sbox = sbox();
            let nr = self.round_keys.len() - 1;
            add_round_key(block, &self.round_keys[0]);
            for r in 1..nr {
                // SubBytes
                for b in block.iter_mut() {
                    *b = sbox[*b as usize];
                }
                // ShiftRows
                shift_rows(block);
                // MixColumns
                mix_columns(block);
                add_round_key(block, &self.round_keys[r]);
            }
            for b in block.iter_mut() {
                *b = sbox[*b as usize];
            }
            shift_rows(block);
            add_round_key(block, &self.round_keys[nr]);
        }
    }

    fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
        for i in 0..16 {
            state[i] ^= rk[i];
        }
    }

    /// State is column-major: state[r + 4c] is row r, column c.
    fn shift_rows(state: &mut [u8; 16]) {
        let s = *state;
        // row 1: shift left 1
        for r in 1..4usize {
            for c in 0..4usize {
                state[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
            }
        }
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let col = [
                state[4 * c],
                state[4 * c + 1],
                state[4 * c + 2],
                state[4 * c + 3],
            ];
            state[4 * c] = gf_mul(col[0], 2) ^ gf_mul(col[1], 3) ^ col[2] ^ col[3];
            state[4 * c + 1] = col[0] ^ gf_mul(col[1], 2) ^ gf_mul(col[2], 3) ^ col[3];
            state[4 * c + 2] = col[0] ^ col[1] ^ gf_mul(col[2], 2) ^ gf_mul(col[3], 3);
            state[4 * c + 3] = gf_mul(col[0], 3) ^ col[1] ^ col[2] ^ gf_mul(col[3], 2);
        }
    }
}

// ---------------------------------------------------------------------------
// AES-GCM (NIST SP 800-38D)
// ---------------------------------------------------------------------------

pub mod gcm {
    use super::aes::Aes;
    use super::{ct_eq, POLY_TAG};

    const BLOCK: usize = 16;

    /// GF(2^128) multiplication per NIST SP 800-38D §6.3 (reflected-bit form).
    pub(crate) fn gmult(x: [u64; 2], y: [u64; 2]) -> [u64; 2] {
        let mut z = [0u64; 2];
        let mut v = y;
        for i in 0..128usize {
            // bit i of X counted from the MSB
            let bit = if i < 64 {
                (x[0] >> (63 - i)) & 1
            } else {
                (x[1] >> (127 - i)) & 1
            };
            if bit == 1 {
                z[0] ^= v[0];
                z[1] ^= v[1];
            }
            // V = V >> 1, with R = 0xe1 || 0^120 applied when LSB was set
            let lsb = v[1] & 1;
            v[1] = (v[1] >> 1) | ((v[0] & 1) << 63);
            v[0] >>= 1;
            if lsb == 1 {
                v[0] ^= 0xe100000000000000;
            }
        }
        z
    }

    fn be_blocks(data: &[u8]) -> Vec<[u64; 2]> {
        let padded = BLOCK - (data.len() % BLOCK);
        let mut d = data.to_vec();
        if padded != BLOCK {
            d.extend(std::iter::repeat(0u8).take(padded));
        }
        d.chunks(BLOCK)
            .map(|c| {
                [
                    u64::from_be_bytes(c[0..8].try_into().unwrap()),
                    u64::from_be_bytes(c[8..16].try_into().unwrap()),
                ]
            })
            .collect()
    }

    fn ghash(h: [u64; 2], aad: &[u8], ct: &[u8]) -> [u64; 2] {
        let mut y = [0u64; 2];
        for b in be_blocks(aad).into_iter().chain(be_blocks(ct)) {
            y[0] ^= b[0];
            y[1] ^= b[1];
            y = gmult(y, h);
        }
        // length block: bit lengths of aad and ct (big-endian u64s)
        let aad_bits = (aad.len() as u64) * 8;
        let ct_bits = (ct.len() as u64) * 8;
        let lb = [aad_bits, ct_bits];
        y[0] ^= lb[0];
        y[1] ^= lb[1];
        gmult(y, h)
    }

    fn inc32(b: &mut [u8; 16]) {
        let mut ctr = u32::from_be_bytes(b[12..16].try_into().unwrap());
        ctr = ctr.wrapping_add(1);
        b[12..16].copy_from_slice(&ctr.to_be_bytes());
    }

    pub fn encrypt(key: &[u8], iv: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let aes = Aes::new(key);
        // H = E(K, 0^128)
        let hblk = enc_block(&aes, &[0u8; 16]);
        let h = [
            u64::from_be_bytes(hblk[0..8].try_into().unwrap()),
            u64::from_be_bytes(hblk[8..16].try_into().unwrap()),
        ];
        // J0 = IV || 0x00000001 (IV is 96 bits)
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        // CTR from inc32(J0)
        let mut ctr = j0;
        let mut ct = Vec::with_capacity(pt.len() + POLY_TAG);
        for chunk in pt.chunks(BLOCK) {
            inc32(&mut ctr);
            let ks = enc_block(&aes, &ctr);
            for (i, b) in chunk.iter().enumerate() {
                ct.push(b ^ ks[i]);
            }
        }
        let s = ghash(h, aad, &ct);
        // tag = E(K, J0) XOR S
        let e0 = enc_block(&aes, &j0);
        let s_bytes = [
            e0[0] ^ (s[0] >> 56) as u8,
            e0[1] ^ (s[0] >> 48) as u8,
            e0[2] ^ (s[0] >> 40) as u8,
            e0[3] ^ (s[0] >> 32) as u8,
            e0[4] ^ (s[0] >> 24) as u8,
            e0[5] ^ (s[0] >> 16) as u8,
            e0[6] ^ (s[0] >> 8) as u8,
            e0[7] ^ s[0] as u8,
            e0[8] ^ (s[1] >> 56) as u8,
            e0[9] ^ (s[1] >> 48) as u8,
            e0[10] ^ (s[1] >> 40) as u8,
            e0[11] ^ (s[1] >> 32) as u8,
            e0[12] ^ (s[1] >> 24) as u8,
            e0[13] ^ (s[1] >> 16) as u8,
            e0[14] ^ (s[1] >> 8) as u8,
            e0[15] ^ s[1] as u8,
        ];
        ct.extend_from_slice(&s_bytes);
        ct
    }

    pub fn decrypt(
        key: &[u8],
        iv: &[u8; 12],
        aad: &[u8],
        ct_tag: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if ct_tag.len() < POLY_TAG {
            return Err("gcm: truncated");
        }
        let (ct, tag) = ct_tag.split_at(ct_tag.len() - POLY_TAG);
        let aes = Aes::new(key);
        let hblk = enc_block(&aes, &[0u8; 16]);
        let h = [
            u64::from_be_bytes(hblk[0..8].try_into().unwrap()),
            u64::from_be_bytes(hblk[8..16].try_into().unwrap()),
        ];
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        // tag' = E(J0) ⊕ GHASH(H, aad, ct) — computed over the ciphertext
        // itself (never re-encrypt: that would double-apply CTR).
        let s = ghash(h, aad, ct);
        let e0 = enc_block(&aes, &j0);
        let mut expect = [0u8; 16];
        for i in 0..16 {
            let sb = if i < 8 {
                e0[i] ^ ((s[0] >> (56 - 8 * i)) as u8)
            } else {
                e0[i] ^ ((s[1] >> (120 - 8 * i)) as u8)
            };
            expect[i] = sb;
        }
        if !ct_eq(&expect, tag) {
            return Err("gcm: tag mismatch");
        }
        // CTR-decrypt with the same keystream as encryption
        let mut ctr = j0;
        let mut pt = Vec::with_capacity(ct.len());
        for chunk in ct.chunks(BLOCK) {
            inc32(&mut ctr);
            let ks = enc_block(&aes, &ctr);
            for (i, b) in chunk.iter().enumerate() {
                pt.push(b ^ ks[i]);
            }
        }
        Ok(pt)
    }

    fn enc_block(aes: &Aes, b: &[u8; 16]) -> [u8; 16] {
        let mut blk = *b;
        aes.encrypt_block(&mut blk);
        blk
    }
}

// ---------------------------------------------------------------------------
// AES-CFB128 (NIST SP 800-38A §6.3, Appendix F.3) — PRIVATE stream primitive
// ---------------------------------------------------------------------------
//
// Record-0003 A2-C4 (mechanical usage enforcement): raw CFB encrypt/decrypt
// types are NOT `pub` outside the authenticated wrapper module. CFB128 is
// unauthenticated and byte-malleable by design, so until a pub authenticated
// wrapper exists nothing outside this single-file crate may even name the
// primitive. Enforcement has two halves, verifiable independently:
// - compile failure: `cfb128` and its functions are `pub(crate)` — invisible
//   to every other crate in the workspace, so any external use cannot link;
// - CI audit: the `cfb_usage_audit` test at the bottom of this file fails if
//   ANY other workspace .rs file references `cfb` at all.
// A future consumer gets access ONLY through a pub wrapper API that itself
// authenticates; enabling one means extending that audit's allowlist with a
// justification comment + a DECISIONS.md record — the visible, journaled
// path (same discipline as holo-util's rand_split_audit).
pub(crate) mod cfb128 {
    use super::aes::Aes;

    fn enc_block(aes: &Aes, b: &[u8; 16]) -> [u8; 16] {
        let mut blk = *b;
        aes.encrypt_block(&mut blk);
        blk
    }

    // S1 scope = primitive + enforcement; the consumer (the authenticated
    // wrapper) arrives later, so a non-test build legitimately sees these
    // two functions as dead code. It is the cfb_usage_audit test — not
    // reachability — that keeps usage honest.
    #[cfg_attr(not(test), allow(dead_code))]
    /// CFB128 encryption in place (SP 800-38A §6.3): O = E_K(C_prev);
    /// C_i = P_i XOR leftmost_bytes(O). Stream mode — arbitrary lengths;
    /// a partial final block consumes only its own bytes of the keystream
    /// block. AES *encryption* is used in both directions; `iv` seeds the
    /// 16-byte feedback register.
    pub(crate) fn encrypt(aes: &Aes, iv: &[u8; 16], data: &mut [u8]) {
        let mut prev = *iv;
        for chunk in data.chunks_mut(16) {
            let out = enc_block(aes, &prev);
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= out[i];
            }
            // chunk now holds C_i — feed it back (full blocks only; a
            // partial final chunk ends the loop).
            if chunk.len() == 16 {
                prev.copy_from_slice(chunk);
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    /// CFB128 decryption in place: P_i = C_i XOR E_K(C_{i-1}). The feedback
    /// is the *received* ciphertext, so it must be captured BEFORE the
    /// in-place XOR overwrites the block with plaintext.
    pub(crate) fn decrypt(aes: &Aes, iv: &[u8; 16], data: &mut [u8]) {
        let mut prev = *iv;
        for chunk in data.chunks_mut(16) {
            let out = enc_block(aes, &prev);
            if chunk.len() == 16 {
                prev.copy_from_slice(chunk); // still C_i here — snapshot first
            }
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= out[i];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EVP_BytesToKey (OpenSSL) — the Shadowsocks password KDF (MD5, count=1)
// ---------------------------------------------------------------------------

pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut input = prev.clone();
        input.extend_from_slice(password);
        prev = md5::digest(&input).to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

pub fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

pub fn from_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        let hi = (b[i] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (b[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

// ---------------------------------------------------------------------------
// tests — official vectors
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Minimal big-integer arithmetic (support layer for RSA, below)
// ---------------------------------------------------------------------------

/// Minimal big-unsigned-integer arithmetic over little-endian `Vec<u64>`
/// limbs, with Montgomery multiplication (CIOS) and modular exponentiation.
/// Octet-string conversion follows RFC 8017 §4.1/§4.2 (`os2ip`/`i2osp`,
/// big-endian). Limb vectors are kept trimmed — the integer zero is the
/// EMPTY vector.
///
/// CONSTANT-TIME STATUS — RECORDED DECISION (A3-C6/F13 bar): every operation
/// in this module processes PUBLIC data only — signatures, public keys, the
/// exponent e, message hashes and salts are all attacker-visible in the
/// verification path — so variable-time behaviour (bit-branching `mont_pow`,
/// the data-dependent final subtraction, the operand-shape-dependent `rem`)
/// is an ACCEPTED RISK for this stage, not an oversight. No secret-operand
/// operation is in scope here. A future consumer that routes SECRET operands
/// through this module (e.g. S2 client-side operations holding RSA private
/// keys) MUST treat constant-time execution as its own requirement; this
/// code does not provide it.
pub mod bignum {
    use std::cmp::Ordering;

    /// Drop leading (most significant) zero limbs.
    fn trim(mut v: Vec<u64>) -> Vec<u64> {
        while v.last() == Some(&0) {
            v.pop();
        }
        v
    }

    /// RFC 8017 §4.2 OS2IP: big-endian octet string → integer (limbs LE).
    pub fn os2ip(bytes: &[u8]) -> Vec<u64> {
        let mut out = vec![0u64; (bytes.len() + 7) / 8];
        for (i, b) in bytes.iter().rev().enumerate() {
            out[i / 8] |= (*b as u64) << (8 * (i % 8));
        }
        out
    }

    /// RFC 8017 §4.1 I2OSP: integer → big-endian octet string of exactly
    /// `len` octets; `Err` ("integer too large") when the value does not fit.
    pub fn i2osp(x: &[u64], len: usize) -> Result<Vec<u8>, &'static str> {
        if bit_len(x).div_ceil(8) > len {
            return Err("i2osp: integer too large");
        }
        let mut out = vec![0u8; len];
        for (i, b) in out.iter_mut().rev().enumerate() {
            *b = if i / 8 < x.len() {
                (x[i / 8] >> (8 * (i % 8))) as u8
            } else {
                0
            };
        }
        Ok(out)
    }

    /// Number of significant bits (0 for the zero integer).
    pub fn bit_len(x: &[u64]) -> usize {
        match x.iter().rposition(|&l| l != 0) {
            None => 0,
            Some(top) => 64 * top + (64 - x[top].leading_zeros() as usize),
        }
    }

    /// Three-way compare (operands are trimmed first, so leading zero limbs
    /// and the empty-vector zero compare correctly).
    pub fn cmp(a: &[u64], b: &[u64]) -> Ordering {
        let (a, b) = (trim(a.to_vec()), trim(b.to_vec()));
        if a.len() != b.len() {
            return a.len().cmp(&b.len());
        }
        for i in (0..a.len()).rev() {
            if a[i] != b[i] {
                return a[i].cmp(&b[i]);
            }
        }
        Ordering::Equal
    }

    /// a + b.
    pub fn add(a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = a.len().max(b.len()) + 1;
        let mut out = Vec::with_capacity(n);
        let mut carry = 0u64;
        for i in 0..n {
            let x = *a.get(i).unwrap_or(&0) as u128;
            let y = *b.get(i).unwrap_or(&0) as u128;
            let s = x + y + carry as u128;
            out.push(s as u64);
            carry = (s >> 64) as u64;
        }
        trim(out)
    }

    /// a − b. Returns `None` on underflow (a < b) — the documented choice:
    /// callers that cannot underflow (`rem`, the Montgomery final subtract)
    /// use guarded/`expect` calls, verification code maps it to errors.
    pub fn sub(a: &[u64], b: &[u64]) -> Option<Vec<u64>> {
        if cmp(a, b) == Ordering::Less {
            return None;
        }
        let n = a.len().max(b.len());
        let mut out = Vec::with_capacity(n);
        let mut borrow = 0u64;
        for i in 0..n {
            let x = *a.get(i).unwrap_or(&0);
            let y = *b.get(i).unwrap_or(&0);
            let (d1, br1) = x.overflowing_sub(y);
            let (d2, br2) = d1.overflowing_sub(borrow);
            out.push(d2);
            borrow = (br1 as u64) | (br2 as u64);
        }
        debug_assert_eq!(borrow, 0, "sub: inputs checked, borrow must cancel");
        Some(trim(out))
    }

    /// Schoolbook multiplication with u128 products. No u128 overflow is
    /// possible: the accumulate step is bounded by (2^64−1)² + 2·(2^64−1)
    /// = 2^128 − 1 (same argument as Poly1305 above).
    pub fn mul(a: &[u64], b: &[u64]) -> Vec<u64> {
        if a.is_empty() || b.is_empty() {
            return Vec::new();
        }
        let mut out = vec![0u64; a.len() + b.len()];
        for (i, &ai) in a.iter().enumerate() {
            let mut carry: u128 = 0;
            for (j, &bj) in b.iter().enumerate() {
                let cur = (out[i + j] as u128) + (ai as u128) * (bj as u128) + carry;
                out[i + j] = cur as u64;
                carry = cur >> 64;
            }
            let mut idx = i + b.len();
            while carry > 0 {
                let cur = (out[idx] as u128) + carry;
                out[idx] = cur as u64;
                carry = cur >> 64;
                idx += 1;
            }
        }
        trim(out)
    }

    /// a mod m via MSB-first binary long division, O(bits(a)·limbs(m)).
    /// Used once per `modpow` call for base reduction — not on hot loops.
    /// `m` must be nonzero.
    pub fn rem(a: &[u64], m: &[u64]) -> Vec<u64> {
        let m = trim(m.to_vec());
        debug_assert!(!m.is_empty(), "rem: zero modulus");
        let a = trim(a.to_vec());
        if cmp(&a, &m) == Ordering::Less {
            return a;
        }
        let mut r: Vec<u64> = Vec::new();
        for i in (0..bit_len(&a)).rev() {
            let bit = (a[i / 64] >> (i % 64)) & 1;
            // r = 2·r + bit (MSB-first shift-add)
            let mut carry = bit;
            for limb in r.iter_mut() {
                let next = (*limb << 1) | carry;
                carry = *limb >> 63;
                *limb = next;
            }
            if carry != 0 {
                r.push(carry);
            }
            r = trim(r);
            if cmp(&r, &m) != Ordering::Less {
                r = sub(&r, &m).expect("rem: r < 2m ⇒ single subtract cannot underflow");
            }
        }
        r
    }

    /// Montgomery context number n0′ = −n⁻¹ mod 2^64 for an odd modulus
    /// (read from n[0] once per modulus). Newton iteration on the low bits:
    /// if x ≡ n0⁻¹ (mod 2^m) then x·(2 − n0·x) ≡ n0⁻¹ (mod 2^2m); seed
    /// x = 1 (correct mod 2 because n0 is odd) and double the precision six
    /// times to reach mod 2^64, then negate.
    pub fn montgomery_context(n: &[u64]) -> u64 {
        let n0 = *n.first().expect("montgomery_context: empty modulus");
        debug_assert!(n0 & 1 == 1, "Montgomery requires an odd modulus");
        let mut x: u64 = 1;
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
        }
        x.wrapping_neg()
    }

    /// Coarse Integrated Operand Scanning (CIOS) Montgomery multiplication
    /// (Koç/Acar/Kaliski): returns a·b·R⁻¹ mod n for a, b < n, with
    /// R = 2^(64·k) and k = limbs of the (odd, normalized) modulus n.
    /// Every per-limb accumulation runs in u128 with the carry split by
    /// shift/mask, so nothing overflows (max intermediate
    /// (2^64−1)² + 2·(2^64−1) = 2^128 − 1).
    ///
    /// FINAL-CARRY-LIMB PITFALL (documented): after the last outer
    /// iteration the accumulator T — kept as k+1 limbs, with t[k+1] as the
    /// extra carry slot a naive k-limb layout loses — satisfies T < 2n and
    /// may still be ≥ n. Exactly ONE conditional subtraction of n brings it
    /// below n; T < 2n is what makes a single subtract sufficient.
    pub fn mont_mul(a: &[u64], b: &[u64], n: &[u64], n0p: u64) -> Vec<u64> {
        let k = n.len();
        debug_assert!(k > 0, "mont_mul: empty modulus");
        debug_assert!(n[k - 1] != 0, "mont_mul: modulus must be normalized");
        debug_assert!(n[0] & 1 == 1, "mont_mul: modulus must be odd");
        let ap = trim(a.to_vec());
        let bp = trim(b.to_vec());
        debug_assert!(cmp(&ap, n) == Ordering::Less, "a >= n");
        debug_assert!(cmp(&bp, n) == Ordering::Less, "b >= n");
        let at = |i: usize| *ap.get(i).unwrap_or(&0);
        let bt = |i: usize| *bp.get(i).unwrap_or(&0);

        let mut t = vec![0u64; k + 2];
        for i in 0..k {
            // product-and-accumulate: t += a·b[i]
            let mut c: u64 = 0;
            let bi = bt(i);
            for j in 0..k {
                let v = (at(j) as u128) * (bi as u128) + (t[j] as u128) + (c as u128);
                t[j] = v as u64;
                c = (v >> 64) as u64;
            }
            let v = (t[k] as u128) + (c as u128);
            t[k] = v as u64;
            t[k + 1] = (v >> 64) as u64;

            // reduction: t += m·n, then shift one whole limb down
            let m = t[0].wrapping_mul(n0p);
            let v = (t[0] as u128) + (m as u128) * (n[0] as u128);
            t[0] = v as u64;
            let mut c2 = (v >> 64) as u64;
            for j in 1..k {
                let v = (t[j] as u128) + (m as u128) * (n[j] as u128) + (c2 as u128);
                t[j - 1] = v as u64;
                c2 = (v >> 64) as u64;
            }
            let v = (t[k] as u128) + (c2 as u128);
            t[k - 1] = v as u64;
            c2 = (v >> 64) as u64;
            t[k] = t[k + 1] + c2; // both ≤ 1 ⇒ no overflow
            t[k + 1] = 0;
        }

        // T = t[0..=k] is < 2n: subtract n once if T ≥ n. (T == 0 compares
        // Less because n[k−1] ≠ 0, so the zero case never "subtracts".)
        let mut ge = Ordering::Equal;
        for i in (0..=k).rev() {
            let ti = t[i];
            let ni = if i < k { n[i] } else { 0 };
            if ti != ni {
                ge = ti.cmp(&ni);
                break;
            }
        }
        if ge != Ordering::Less {
            let mut borrow = 0u64;
            for i in 0..=k {
                let ni = if i < k { n[i] } else { 0 };
                let (d1, b1) = t[i].overflowing_sub(ni);
                let (d2, b2) = d1.overflowing_sub(borrow);
                t[i] = d2;
                borrow = (b1 as u64) | (b2 as u64);
            }
            debug_assert_eq!(borrow, 0, "T < 2n ⇒ single subtract must cancel");
        }
        trim(t[..k].to_vec())
    }

    /// x + x mod n for x < n (helper for building R mod n / R² mod n:
    /// x < n ⇒ 2x < 2n, one conditional subtraction suffices).
    fn double_mod(x: &[u64], n: &[u64]) -> Vec<u64> {
        let s = add(x, x);
        if cmp(&s, n) == Ordering::Less {
            s
        } else {
            sub(&s, n).expect("double_mod: s < 2n ⇒ single subtract cannot underflow")
        }
    }

    /// Modular exponentiation base^exp mod modulus, MSB-first square-and-
    /// multiply over Montgomery form (the task-spec API name). `ctx` is the
    /// Montgomery context number `montgomery_context(n)` — computed once per
    /// modulus by the caller (see `modpow` for the one-call convenience
    /// wrapper). `base` may be any size (reduced first); `exp` is walked
    /// bit-by-bit with a plain branch — see the module-level constant-time
    /// note (public-operand operation, ACCEPTED RISK). Requirements: modulus
    /// odd and > 1 (any RSA modulus n = p·q of odd primes qualifies).
    pub fn mont_pow(x: &[u64], e: &[u64], n: &[u64], ctx: u64) -> Vec<u64> {
        let n = trim(n.to_vec());
        debug_assert!(!n.is_empty(), "mont_pow: zero modulus");
        debug_assert!(n[0] & 1 == 1, "mont_pow: odd modulus required (Montgomery)");
        if n == vec![1u64] {
            return Vec::new(); // x mod 1 == 0
        }
        let e = trim(e.to_vec());
        if e.is_empty() {
            return vec![1u64]; // anything^0 == 1 mod n, n > 1
        }
        let x_r = rem(x, &n);
        let k = n.len();
        let n0p = ctx;
        // R mod n and R² mod n, by 64·k doublings each.
        let mut r_mod_n = vec![1u64];
        for _ in 0..64 * k {
            r_mod_n = double_mod(&r_mod_n, &n);
        }
        let mut r2_mod_n = r_mod_n.clone();
        for _ in 0..64 * k {
            r2_mod_n = double_mod(&r2_mod_n, &n);
        }
        let x_mont = mont_mul(&x_r, &r2_mod_n, &n, n0p);
        let mut acc = mont_mul(&[1u64], &r2_mod_n, &n, n0p); // 1 in Montgomery form
        for i in (0..bit_len(&e)).rev() {
            acc = mont_mul(&acc, &acc, &n, n0p);
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                acc = mont_mul(&acc, &x_mont, &n, n0p);
            }
        }
        // Leave Montgomery form: acc·1·R⁻¹ mod n.
        let mut one = vec![0u64; k];
        one[0] = 1;
        mont_mul(&acc, &one, &n, n0p)
    }

    /// Convenience wrapper: `modpow(base, exp, modulus)` computes the
    /// Montgomery context itself and delegates to `mont_pow`. Kept because
    /// the RSA verify path (§8.1.2/§8.2.2 step 2b, RSAVP1) uses it.
    pub fn modpow(base: &[u64], exp: &[u64], modulus: &[u64]) -> Vec<u64> {
        let n = trim(modulus.to_vec());
        debug_assert!(!n.is_empty(), "modpow: zero modulus");
        mont_pow(base, exp, &n, montgomery_context(&n))
    }
}

// ---------------------------------------------------------------------------
// RSA signature verification — RSASSA-PKCS1-v1_5 + RSASSA-PSS, SHA-256 only
// (RFC 8017 §8.1.2, §8.2.2, §9.1, §9.2). Verify-only by design: the HoloNet
// engine never signs, so no CRT / private-key code exists here.
// ---------------------------------------------------------------------------

pub mod rsa {
    use super::bignum;
    use super::sha256;
    use crate::ct_eq;
    use std::cmp::Ordering;

    /// hLen for SHA-256.
    const H_LEN: usize = 32;
    /// EMSA-PSS trailer field octet (RFC 8017 §9.1 note 1, step 12 / step 4).
    const PSS_TRAILER: u8 = 0xbc;

    /// DER encoding T of the SHA-256 DigestInfo WITHOUT the hash octets —
    /// RFC 8017 §9.2 note 1: "SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65
    /// 03 04 02 01 05 00 04 20 || H". Copied verbatim from the fetched RFC
    /// text and cross-checked byte-for-byte against a hand-assembled
    /// SEQUENCE{SEQUENCE{OID 2.16.840.1.101.3.4.2.1, NULL}, OCTET STRING(32)}
    /// in the Python cross-check (bignum_report.md).
    pub const DIGEST_INFO_SHA256: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20,
    ];

    /// tLen = len(T): 19 prefix bytes + 32 hash bytes.
    const T_LEN: usize = DIGEST_INFO_SHA256.len() + H_LEN;

    /// Common §8.1.2/§8.2.2 step 1 length checking + RSAVP1 (§5.2.2) range
    /// check: non-empty odd modulus, signature exactly k octets,
    /// representative s < n. Returns (n, s, k).
    fn public_key_checks(
        n: &[u8],
        sig: &[u8],
    ) -> Result<(Vec<u64>, Vec<u64>, usize), &'static str> {
        if n.is_empty() {
            return Err("rsa: empty modulus");
        }
        if n[n.len() - 1] & 1 == 0 {
            return Err("rsa: modulus must be odd");
        }
        if sig.len() != n.len() {
            return Err("rsa: signature length != modulus length");
        }
        let n_big = bignum::os2ip(n);
        let s = bignum::os2ip(sig);
        if bignum::cmp(&s, &n_big) != Ordering::Less {
            return Err("rsa: signature representative out of range");
        }
        Ok((n_big, s, n.len()))
    }

    /// RSASSA-PKCS1-v1_5-VERIFY (RFC 8017 §8.2.2) for SHA-256. `n`/`e` are
    /// the big-endian modulus/exponent, `message_hash` is H = Hash(M) (32
    /// bytes; the caller hashes, §9.2 step 1 embeds it in DigestInfo), and
    /// `sig` is S. Distinct error string per failure stage.
    pub fn verify_pkcs1_v1_5_sha256(
        n: &[u8],
        e: &[u8],
        message_hash: &[u8],
        sig: &[u8],
    ) -> Result<(), &'static str> {
        let (n_big, s, k) = public_key_checks(n, sig)?;
        if message_hash.len() != H_LEN {
            return Err("rsa: expected a 32-byte SHA-256 message hash");
        }
        // §8.2.2 step 2b: RSAVP1 — m = s^e mod n.
        let m = bignum::modpow(&s, &bignum::os2ip(e), &n_big);
        // §8.2.2 step 2c: EM = I2OSP(m, k).
        let em = bignum::i2osp(&m, k).map_err(|_| "rsa: integer too large")?;
        // §8.2.2 step 3: EM' = EMSA-PKCS1-V1_5-ENCODE(M, k) (§9.2):
        //   EM = 0x00 || 0x01 || PS (0xff × (k − tLen − 3), ≥ 8) || 0x00 || T
        if k < T_LEN + 11 {
            return Err("rsa: modulus too short for PKCS#1 v1.5");
        }
        let mut em_prime = Vec::with_capacity(k);
        em_prime.push(0x00);
        em_prime.push(0x01);
        em_prime.extend(std::iter::repeat(0xff).take(k - T_LEN - 3));
        em_prime.push(0x00);
        em_prime.extend_from_slice(&DIGEST_INFO_SHA256);
        em_prime.extend_from_slice(message_hash);
        debug_assert_eq!(em_prime.len(), k);
        // §8.2.2 step 4: compare EM and EM' (constant-time byte compare).
        if ct_eq(&em, &em_prime) {
            Ok(())
        } else {
            Err("rsa: PKCS#1 v1.5 encoded message mismatch")
        }
    }

    /// RSASSA-PSS-VERIFY (RFC 8017 §8.1.2) with EMSA-PSS-VERIFY (§9.1.2) and
    /// MGF1-SHA256, for SHA-256. `salt_len` is the sLen parameter — the
    /// verifier must be configured with the signer's salt length (typical:
    /// hLen = 32 or 0). `message_hash` is H = Hash(M) (32 bytes). Distinct
    /// error string per failure stage.
    pub fn verify_pss_sha256(
        n: &[u8],
        e: &[u8],
        salt_len: usize,
        message_hash: &[u8],
        sig: &[u8],
    ) -> Result<(), &'static str> {
        let (n_big, s, _k) = public_key_checks(n, sig)?;
        if message_hash.len() != H_LEN {
            return Err("rsa: expected a 32-byte SHA-256 message hash");
        }
        // §8.1.2 step 2b: RSAVP1 — m = s^e mod n.
        let m = bignum::modpow(&s, &bignum::os2ip(e), &n_big);
        // §8.1.2 step 2c: EM = I2OSP(m, emLen), emLen = ⌈(modBits − 1)/8⌉ —
        // emLen is k − 1 when modBits − 1 is divisible by 8, k otherwise.
        let mod_bits = bignum::bit_len(&n_big);
        let em_bits = mod_bits - 1;
        let em_len = em_bits.div_ceil(8);
        let em = bignum::i2osp(&m, em_len).map_err(|_| "rsa: integer too large")?;

        // EMSA-PSS-VERIFY (§9.1.2), hLen = 32:
        // step 3: emLen ≥ hLen + sLen + 2.
        if em_len < H_LEN + salt_len + 2 {
            return Err("rsa/pss: encoded message too short for salt length");
        }
        // step 4: rightmost octet is the 0xbc trailer.
        if em[em_len - 1] != PSS_TRAILER {
            return Err("rsa/pss: bad trailer byte (not 0xbc)");
        }
        // step 5: maskedDB = leftmost emLen − hLen − 1 octets, H the next 32.
        let db_len = em_len - H_LEN - 1;
        let h = &em[db_len..db_len + H_LEN];
        // step 6: the leftmost 8·emLen − emBits bits of maskedDB must be zero.
        let top_bits = 8 * em_len - em_bits;
        debug_assert!(top_bits < 8);
        if top_bits > 0 && em[0] >> (8 - top_bits) != 0 {
            return Err("rsa/pss: leftmost bits of maskedDB not zero");
        }
        // steps 7–8: DB = maskedDB xor MGF1(H, emLen − hLen − 1).
        let db_mask = mgf1_sha256(h, db_len);
        let mut db: Vec<u8> = em[..db_len]
            .iter()
            .zip(db_mask)
            .map(|(x, y)| x ^ y)
            .collect();
        // step 9: set the same leftmost bits of DB to zero.
        if top_bits > 0 {
            db[0] &= 0xff >> top_bits;
        }
        // step 10: the emLen − hLen − sLen − 2 leftmost octets are zero and
        // the octet at position emLen − hLen − sLen − 1 (leftmost = 1) is 0x01.
        let ps_len = em_len - H_LEN - salt_len - 2;
        if db[..ps_len].iter().any(|&b| b != 0) {
            return Err("rsa/pss: DB padding zeros corrupted");
        }
        if db[ps_len] != 0x01 {
            return Err("rsa/pss: DB separator byte (0x01) missing");
        }
        // step 11: salt = last sLen octets of DB.
        let salt = &db[db_len - salt_len..];
        // steps 12–13: H' = Hash(0x00…00 (8 octets) || mHash || salt).
        let mut m_prime = Vec::with_capacity(8 + H_LEN + salt_len);
        m_prime.extend_from_slice(&[0u8; 8]);
        m_prime.extend_from_slice(message_hash);
        m_prime.extend_from_slice(salt);
        let h_prime = sha256::digest(&m_prime);
        // step 14: H = H' ?
        if ct_eq(&h_prime, h) {
            Ok(())
        } else {
            Err("rsa/pss: recomputed H' does not match H")
        }
    }

    /// MGF1 with SHA-256 (RFC 8017 B.2.1): plain SHA-256 over
    /// `seed || counter` (32-bit big-endian counter), concatenated and
    /// truncated — NOT HMAC.
    fn mgf1_sha256(seed: &[u8], mask_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(mask_len + H_LEN);
        let mut counter: u32 = 0;
        while out.len() < mask_len {
            let mut input = Vec::with_capacity(seed.len() + 4);
            input.extend_from_slice(seed);
            input.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&sha256::digest(&input));
            counter = counter.wrapping_add(1);
        }
        out.truncate(mask_len);
        out
    }
}


    #[test]
    fn sha256_vectors() {
        assert_eq!(
            sha256::hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256::hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // two-block message
        assert_eq!(
            sha256::hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(
            to_hex(&sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            to_hex(&sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn md5_vectors() {
        assert_eq!(
            to_hex(&md5::digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            to_hex(&md5::digest(b"")),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            to_hex(&md5::digest(b"The quick brown fox jumps over the lazy dog")),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231() {
        // TC2: key "Jefe", data "what do ya want for nothing?" (verified vs
        // Python hmac/hashlib — the reference value below is authoritative)
        let t = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&t),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // TC1: key 0x0b x 20, data "Hi There"
        let t1 = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            to_hex(&t1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869_tc1() {
        let okm = hkdf_sha256(
            &from_hex("000102030405060708090a0b0c"),
            &[0x0b; 22],
            &from_hex("f0f1f2f3f4f5f6f7f8f9"),
            42,
        );
        assert_eq!(
            to_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_sha1_sanity() {
        // HKDF-SHA1 has no memorized vector here; assert determinism + length
        let a = hkdf_sha1(b"salt", b"ikm", b"ss-subkey", 32);
        let b = hkdf_sha1(b"salt", b"ikm", b"ss-subkey", 32);
        assert_eq!(a.len(), 32);
        assert_eq!(a, b);
        assert_ne!(a, hkdf_sha1(b"salt", b"ikm", b"other", 32));
    }

    #[test]
    fn chacha20_rfc8439_2_5_2() {
        // NOTE: RFC 7539 §2.4.2 printed a different ciphertext for this
        // example; RFC 8439 corrected it. Verified against OpenSSL and a
        // from-spec pure-Python implementation: 6e2e359a…0d6981 is correct.
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut ct = pt.to_vec();
        chacha20::xor(&key, 1, &nonce, &mut ct);
        assert_eq!(to_hex(&ct[..16]), "6e2e359a2568f98041ba0728dd0d6981");
        // decrypts back
        chacha20::xor(&key, 1, &nonce, &mut ct);
        assert_eq!(ct.as_slice(), &pt[..]);
    }

    #[test]
    fn poly1305_rfc8439_2_4_2() {
        let key = from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key);
        let tag = poly1305(&key_arr, b"Cryptographic Forum Research Group");
        // Verified verbatim against RFC 8439 §2.5.2 (rfc-editor.org):
        assert_eq!(to_hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn poly1305_block_boundaries() {
        // exercise every block length 0..=47 — must decrypt-consistently and
        // never panic (the limb/2^128 edge cases live at block boundaries)
        let mut key = [0u8; 32];
        key[..32].copy_from_slice(&from_hex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        ));
        for l in 0..48usize {
            let msg: Vec<u8> = (0..l).map(|i| (i * 37 + 11) as u8).collect();
            let t1 = poly1305(&key, &msg);
            let mut m2 = msg.clone();
            m2.push(0);
            let t2 = poly1305(&key, &m2[..l]); // same logical message via buffer
            assert_eq!(t1, t2, "length {}", l);
        }
    }

    #[test]
    fn aead_rfc8439_2_8_2() {
        // Validates ChaCha20 keystream + Poly1305 + pad16 + AAD, end-to-end.
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let out = aead_chacha20poly1305_encrypt(&key, &nonce, &aad, pt);
        let (ct, tag) = out.split_at(out.len() - 16);
        assert_eq!(ct.len(), pt.len());
        assert_eq!(to_hex(tag), "1ae10b594f09e26a7e902ecbd0600691");
        let back = aead_chacha20poly1305_decrypt(&key, &nonce, &aad, &out).unwrap();
        assert_eq!(back.as_slice(), &pt[..]);
    }

    #[test]
    fn aead_tamper_and_truncate() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let out = aead_chacha20poly1305_encrypt(&key, &nonce, b"hdr", b"payload here");
        let mut bad = out.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(aead_chacha20poly1305_decrypt(&key, &nonce, b"hdr", &bad).is_err());
        // wrong AAD → auth failure
        assert!(aead_chacha20poly1305_decrypt(&key, &nonce, b"hdr2", &out).is_err());
        // truncated → error, not panic
        assert!(aead_chacha20poly1305_decrypt(&key, &nonce, b"hdr", &out[..10]).is_err());
    }

    #[test]
    fn xchacha20_roundtrip() {
        let key = [42u8; 32];
        let nonce: [u8; 24] = core::array::from_fn(|i| i as u8);
        let pt: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
        let ct = aead_xchacha20poly1305_encrypt(&key, &nonce, b"aad", &pt);
        let back = aead_xchacha20poly1305_decrypt(&key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(back, pt);
        // tamper → fail
        let mut bad = ct.clone();
        let last = bad.len() - 3;
        bad[last] ^= 1;
        assert!(aead_xchacha20poly1305_decrypt(&key, &nonce, b"aad", &bad).is_err());
    }

    #[test]
    fn hchacha20_draft_xchacha_2_2_1() {
        // draft-irtf-cfrg-xchacha-03 §2.2.1 (verbatim from the IETF
        // archive): key = 00..1f, nonce = 00000009 0000004a 00000000
        // 31415927 → subkey = words 0..3 and 12..15 of the final state,
        // each serialized little-endian.
        let key: [u8; 32] = from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .try_into()
        .unwrap();
        let nonce: [u8; 16] = from_hex("000000090000004a0000000031415927")
            .try_into()
            .unwrap();
        let sub = hchacha20(&key, &nonce);
        assert_eq!(
            to_hex(&sub),
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
        );
    }

    #[test]
    fn xchacha20_draft_a_2_1_keystream() {
        // draft-irtf-cfrg-xchacha-03 A.2.1 (block counter = 0): composed
        // exactly as the draft's §2.3.1 pseudocode — subkey = HChaCha20 over
        // IV[0..16], inner nonce = 4 NUL bytes || IV[16..24], keystream from
        // counter 0. NOTE: this vector's IV ends ...54 55 56 58 (0x58, not
        // 0x57) — transcribed verbatim, not from memory.
        let key: [u8; 32] = from_hex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .try_into()
        .unwrap();
        let iv24: [u8; 24] =
            from_hex("404142434445464748494a4b4c4d4e4f5051525354555658")
                .try_into()
                .unwrap();
        let sub = hchacha20(&key, iv24[0..16].try_into().unwrap());
        let mut n12 = [0u8; 12];
        n12[4..12].copy_from_slice(&iv24[16..24]);
        // 256 bytes = the draft's first four keystream rows (000–0ff)
        let want = from_hex(
            "1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9a\
             adec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d\
             29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4\
             cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25",
        );
        for (i, want_block) in want.chunks(64).enumerate() {
            let ks = chacha20::block(&sub, i as u32, &n12);
            assert_eq!(&ks[..], want_block, "keystream block {}", i);
        }
    }

    #[test]
    fn aead_xchacha20poly1305_draft_a_1() {
        // draft-irtf-cfrg-xchacha-03 A.1: the RFC 8439 §2.8.2 example lifted
        // to a 24-byte IV. Asserts ciphertext AND tag AND the published
        // intermediate Poly1305 key (= block 0 of subkey/inner-nonce), which
        // pins every layer of the construction at once.
        let key: [u8; 32] = from_hex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .try_into()
        .unwrap();
        let iv: [u8; 24] =
            from_hex("404142434445464748494a4b4c4d4e4f5051525354555657")
                .try_into()
                .unwrap();
        let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
        let pt: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sub = hchacha20(&key, iv[0..16].try_into().unwrap());
        let mut n12 = [0u8; 12];
        n12[4..12].copy_from_slice(&iv[16..24]);
        assert_eq!(
            to_hex(&poly_key(&sub, &n12)),
            "7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5"
        );
        let out = aead_xchacha20poly1305_encrypt(&key, &iv, &aad, pt);
        let (ct, tag) = out.split_at(out.len() - 16);
        assert_eq!(
            to_hex(ct),
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"
        );
        assert_eq!(to_hex(tag), "c0875924c1c7987947deafd8780acf49");
        let back = aead_xchacha20poly1305_decrypt(&key, &iv, &aad, &out).unwrap();
        assert_eq!(back.as_slice(), pt);
    }

    #[test]
    fn aes128_fips197_c1() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f");
        let aes = aes::Aes::new(&key);
        let mut blk = from_hex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        aes.encrypt_block(&mut blk);
        assert_eq!(to_hex(&blk), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    fn gcm_nist_aes256_tc3_tc4() {
        // NIST GCM test cases 3 & 4 (AES-256, all-zero key and IV)
        let key = [0u8; 32];
        let iv = [0u8; 12];
        // TC3: empty plaintext
        let out3 = gcm::encrypt(&key, &iv, b"", b"");
        assert_eq!(to_hex(&out3), "530f8afbc74536b9a963b4f1c4cb738b");
        // TC4: 16 zero bytes
        let out4 = gcm::encrypt(&key, &iv, b"", &[0u8; 16]);
        assert_eq!(
            to_hex(&out4),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
        let back = gcm::decrypt(&key, &iv, b"", &out4).unwrap();
        assert_eq!(back, vec![0u8; 16]);
    }

    #[test]
    fn gcm_roundtrip_multi_block_and_tamper() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let iv: [u8; 12] = core::array::from_fn(|i| (i * 3 + 1) as u8);
        let aad = b"associated data";
        // multi-block, non-aligned lengths exercise GHASH padding paths
        for l in [0usize, 1, 15, 16, 17, 31, 32, 100, 4096] {
            let pt: Vec<u8> = (0..l).map(|i| (i * 13 + 7) as u8).collect();
            let ct = gcm::encrypt(&key, &iv, aad, &pt);
            assert_eq!(ct.len(), pt.len() + 16, "len {}", l);
            let back = gcm::decrypt(&key, &iv, aad, &ct).unwrap();
            assert_eq!(back, pt, "roundtrip len {}", l);
        }
        let ct = gcm::encrypt(&key, &iv, aad, b"hello world");
        let mut bad = ct.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(gcm::decrypt(&key, &iv, aad, &bad).is_err());
        assert!(gcm::decrypt(&key, &iv, b"other aad", &ct).is_err());
    }

    // -----------------------------------------------------------------------
    // CFB128 (NIST SP 800-38A Appendix F.3) — vector source: pdftotext of
    // nistspecialpublication800-38a.pdf, transcribed verbatim from
    // sections F.3.13–F.3.17; every tuple independently re-verified in
    // BOTH directions with OpenSSL 3.5.7 (`openssl enc -aes-{n}-cfb`,
    // per-segment checks via prefix-stream technique — command transcript
    // in the run report).
    // -----------------------------------------------------------------------

    /// The four SP 800-38A Appendix F plaintext blocks shared by all
    /// CFB128 examples (F.3.13 through F.3.18).
    #[cfg(test)]
    const SP800_38A_PT4: [&str; 4] = [
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    ];

    /// Shared F.3 runner: each of the 4 segments is encrypted AND decrypted
    /// in its own call, feeding the previous ciphertext back as the IV
    /// (exactly the chaining the NIST example models); finally the whole
    /// 4-block message in one call must match the concatenation of the
    /// four expected ciphertexts (multi-block chunking path).
    #[cfg(test)]
    fn cfb128_kat(key: &[u8], iv: &[u8; 16], cts: &[&str; 4]) {
        let aes = aes::Aes::new(key);
        let mut prev = *iv;
        let mut want = String::new();
        for (i, pt) in SP800_38A_PT4.iter().enumerate() {
            let mut buf = from_hex(pt);
            cfb128::encrypt(&aes, &prev, &mut buf);
            assert_eq!(to_hex(&buf), cts[i], "F.3 encrypt segment #{}", i + 1);
            cfb128::decrypt(&aes, &prev, &mut buf);
            assert_eq!(to_hex(&buf), *pt, "F.3 decrypt segment #{}", i + 1);
            prev = from_hex(cts[i]).try_into().unwrap();
            want.push_str(cts[i]);
        }
        let mut whole = Vec::new();
        for pt in SP800_38A_PT4.iter() {
            whole.extend_from_slice(&from_hex(pt));
        }
        cfb128::encrypt(&aes, iv, &mut whole);
        assert_eq!(to_hex(&whole), want, "F.3 four-block single-stream");
    }

    /// F.3.13 CFB128-AES128.Encrypt / F.3.14 CFB128-AES128.Decrypt
    #[test]
    fn cfb128_sp800_38a_aes128() {
        cfb128_kat(
            &from_hex("2b7e151628aed2a6abf7158809cf4f3c"),
            &from_hex("000102030405060708090a0b0c0d0e0f")
                .try_into()
                .unwrap(),
            &[
                "3b3fd92eb72dad20333449f8e83cfb4a",
                "c8a64537a0b3a93fcde3cdad9f1ce58b",
                "26751f67a3cbb140b1808cf187a4f4df",
                "c04b05357c5d1c0eeac4c66f9ff7f2e6",
            ],
        );
    }

    /// F.3.15 CFB128-AES192.Encrypt / F.3.16 CFB128-AES192.Decrypt
    #[test]
    fn cfb128_sp800_38a_aes192() {
        cfb128_kat(
            &from_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
            &from_hex("000102030405060708090a0b0c0d0e0f")
                .try_into()
                .unwrap(),
            &[
                "cdc80d6fddf18cab34c25909c99a4174",
                "67ce7f7f81173621961a2b70171d3d7a",
                "2e1e8a1dd59b88b1c8e60fed1efac4c9",
                "c05f9f9ca9834fa042ae8fba584b09ff",
            ],
        );
    }

    /// F.3.17 CFB128-AES256.Encrypt / F.3.18 CFB128-AES256.Decrypt
    #[test]
    fn cfb128_sp800_38a_aes256() {
        cfb128_kat(
            &from_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            &from_hex("000102030405060708090a0b0c0d0e0f")
                .try_into()
                .unwrap(),
            &[
                "dc7e84bfda79164b7ecd8486985d3860",
                "39ffed143b28b1c832113c6331e5407b",
                "df10132415e54b92a13ed0a8267ae2f9",
                "75a385741ab9cef82031623d55b1e471",
            ],
        );
    }

    /// Stream-mode roundtrips at awkward lengths (1, 15, 17, 31, 33 —
    /// partial final blocks of 1..15 bytes), plus an OpenSSL 3.5.7
    /// cross-check constant for one odd length: the 17-byte input is
    /// F.3.13's block #1 plus the first byte of block #2, and its
    /// ciphertext is `openssl enc -aes-128-cfb -K
    /// 2b7e151628aed2a6abf7158809cf4f3c -iv 000102030405060708090a0b0c0d0e0f`
    /// over that input (the first 16 bytes must equal the F.3.13 block #1
    /// ciphertext; the 17th byte continues the stream). xxd is absent in
    /// the sandbox, so the OpenSSL transcript used python3 bytes.fromhex /
    /// od -An -tx1 for hex conversion — full transcript in the run report.
    #[test]
    fn cfb128_stream_arbitrary_lengths() {
        let key = from_hex("2b7e151628aed2a6abf7158809cf4f3c");
        let aes = aes::Aes::new(&key);
        let iv: [u8; 16] = from_hex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        for l in [1usize, 15, 17, 31, 33] {
            let pt: Vec<u8> = (0..l).map(|i| (i * 13 + 7) as u8).collect();
            let mut buf = pt.clone();
            cfb128::encrypt(&aes, &iv, &mut buf);
            assert_eq!(buf.len(), l, "ct length {}", l);
            cfb128::decrypt(&aes, &iv, &mut buf);
            assert_eq!(buf, pt, "roundtrip len {}", l);
        }
        let mut buf = from_hex("6bc1bee22e409f96e93d7e117393172aae");
        cfb128::encrypt(&aes, &iv, &mut buf);
        assert_eq!(
            to_hex(&buf),
            "3b3fd92eb72dad20333449f8e83cfb4ac8",
            "17-byte OpenSSL cross-check"
        );
    }

    #[test]
    fn evp_bytes_to_key_shape() {
        let k = evp_bytes_to_key(b"password", 32);
        assert_eq!(k.len(), 32);
        let k2 = evp_bytes_to_key(b"password", 32);
        assert_eq!(k, k2);
        assert_ne!(k, evp_bytes_to_key(b"Password", 32));
        // longer than one MD5 block: chains correctly
        let k3 = evp_bytes_to_key(b"password", 48);
        assert_eq!(k3.len(), 48);
        assert_eq!(&k3[..32], &k[..]);
    }

    #[test]
    fn ct_eq_and_hex() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert_eq!(to_hex(&[0x01, 0xff]), "01ff");
        assert_eq!(from_hex("01ff"), vec![0x01, 0xff]);
    }

    // -----------------------------------------------------------------------
    // BLAKE2s (RFC 7693)
    // -----------------------------------------------------------------------

    #[test]
    fn blake2s_sigma_rows_are_permutations() {
        for (r, row) in blake2s::SIGMA.iter().enumerate() {
            let mut seen = [false; 16];
            for &v in row {
                assert!(v < 16, "SIGMA[{r}] value {v} out of range");
                assert!(!seen[v], "SIGMA[{r}] duplicates {v}");
                seen[v] = true;
            }
            assert!(seen.iter().all(|&s| s), "SIGMA[{r}] is not a permutation");
        }
    }

    /// RFC 7693 Appendix B: the unkeyed BLAKE2s-256 trace of "abc",
    /// replayed v[16]-state by v[16]-state — before round 0 and after each
    /// of the 10 rounds, then the final h[8]. A wrong SIGMA row or G
    /// rotation diverges at the exact round where it first acts.
    #[test]
    fn blake2s_rfc7693_appendix_b_trace() {
        fn words<const N: usize>(s: &str) -> [u32; N] {
            let mut out = [0u32; N];
            for (w, t) in out.iter_mut().zip(s.split_whitespace()) {
                *w = u32::from_str_radix(t, 16).unwrap();
            }
            out
        }
        let expected = [
            words::<16>("6B08E647 BB67AE85 3C6EF372 A54FF53A 510E527F 9B05688C 1F83D9AB 5BE0CD19 6A09E667 BB67AE85 3C6EF372 A54FF53A 510E527C 9B05688C E07C2654 5BE0CD19"),
            words::<16>("16A3242E D7B5E238 CE8CE24B 927AEDE1 A7B430D9 93A4A14E A44E7C31 41D4759B 95BF33D3 9A99C181 608A3A6B B666383E 7A8DD50F BE378ED7 353D1EE6 3BB44C6B"),
            words::<16>("3AE30FE3 0982A96B E88185B4 3E339B16 F24338CD 0E66D326 E005ED0C D591A277 180B1F3A FCF43914 30DB62D6 4847831C 7F00C58E FB847886 C544E836 524AB0E2"),
            words::<16>("7A3BE783 997546C1 D45246DF EDB5F821 7F98A742 10E864E2 D4AB70D0 C63CB1AB 6038DA9E 414594B0 F2C218B5 8DA0DCB7 D7CD7AF5 AB4909DF 85031A52 C4EDFC98"),
            words::<16>("2A8B8CB7 1ACA82B2 14045D7F CC7258ED 383CF67C E090E7F9 3025D276 57D04DE4 994BACF0 F0982759 F17EE300 D48FC2D5 DC854C10 523898A9 C03A0F89 47D6CD88"),
            words::<16>("C4AA2DDB 111343A3 D54A700A 574A00A9 857D5A48 B1E11989 6F5C52DF DD2C53A3 678E5F8E 9718D4E9 622CB684 92976076 0E41A517 359DC2BE 87A87DDD 643F9CEC"),
            words::<16>("3453921C D7595EE1 592E776D 3ED6A974 4D997CB3 DE9212C3 35ADF5C9 9916FD65 96562E89 4EAD0792 EBFC2712 2385F5B2 F34600FB D7BC20FB EB452A7B ECE1AA40"),
            words::<16>("BE851B2D A85F6358 81E6FC3B 0BB28000 FA55A33A 87BE1FAD 4119370F 1E2261AA A1318FD3 F4329816 071783C2 6E536A8D 9A81A601 E7EC80F1 ACC09948 F849A584"),
            words::<16>("07E5B85A 069CC164 F9DE3141 A56F4680 9E440AD2 9AB659EA 3C84B971 21DBD9CF 46699F8C 765257EC AF1D998C 75E4C3B6 523878DC 30715015 397FEE81 4F1FA799"),
            words::<16>("435148C4 A5AA2D11 4B354173 D543BC9E BDA2591C BF1D2569 4FCB3120 707ADA48 565B3FDE 32C9C916 EAF4A1AB B1018F28 8078D978 68ADE4B5 9778FDA3 2863B92E"),
            words::<16>("D9C994AA CFEC3AA6 700D0AB2 2C38670E AF6A1F66 1D023EF3 1D9EC27D 945357A5 3E9FFEBD 969FE811 EF485E21 A632797A DEEF082E AF3D80E1 4E86829B 4DEAFD3A"),
        ];
        // h before F = the first 8 words of the (i=0) trace state — the
        // RFC prints v[0..8] = h after the parameter-block XOR.
        let h: [u32; 8] = expected[0][..8].try_into().unwrap();
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        let (h_final, states) = blake2s::compress_round_trace(&h, &block, 3, true);
        assert_eq!(states.len(), 11);
        for (i, st) in states.iter().enumerate() {
            assert_eq!(st, &expected[i], "Appendix B trace diverges at state i={i}");
        }
        let expect_h: [u32; 8] =
            words::<8>("8C5E8C50 E2147C32 A32BA7E1 2F45EB4E 208B4537 293AD69E 4C9B994D 82596786");
        assert_eq!(h_final, expect_h);
        assert_eq!(
            blake2s::hex(b"abc"),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
    }

    /// Official BLAKE2s KAT, unkeyed (D-0020 orphan's expectations,
    /// re-verified this run against Python hashlib.blake2s AND OpenSSL
    /// 3.5.7 `dgst -blake2s256`). Input = bytes 0..len-1.
    #[test]
    fn blake2s_kat_unkeyed() {
        let cases: &[(usize, &str)] = &[
            (0, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
            (1, "e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea"),
            (3, "e8f91c6ef232a041452ab0e149070cdd7dd1769e75b3a5921be37876c45c9900"),
            (64, "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e"),
            (65, "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472"),
            (127, "f18417b39d617ab1c18fdf91ebd0fc6d5516bb34cf39364037bce81fa04cecb1"),
            (128, "1fa877de67259d19863a2a34bcc6962a2b25fcbf5cbecd7ede8f1fa36688a796"),
            (255, "f03f5789d3336b80d002d59fdf918bdb775b00956ed5528e86aa994acb38fe2d"),
        ];
        for (len, expect) in cases {
            let input: Vec<u8> = (0u8..(*len as u8)).collect();
            assert_eq!(&blake2s::hex(&input), expect, "blake2s unkeyed inlen {len}");
        }
    }

    /// Official BLAKE2s KAT, keyed with 00..1f — pins the RFC 7693 §3.3
    /// keyed counter semantics (final block t = ll + bb, key block first).
    #[test]
    fn blake2s_kat_keyed() {
        let key: Vec<u8> = (0u8..32).collect();
        let key: &[u8; 32] = key[..].try_into().unwrap();
        let cases: &[(usize, &str)] = &[
            (0, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"),
            (1, "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"),
            (3, "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b"),
            (64, "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"),
            (65, "21fe0ceb0052be7fb0f004187cacd7de67fa6eb0938d927677f2398c132317a8"),
            (127, "ddbfea75cc467882eb3483ce5e2e756a4f4701b76b445519e89f22d60fa86e06"),
            (128, "0c311f38c35a4fb90d651c289d486856cd1413df9b0677f53ece2cd9e477c60a"),
            (255, "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"),
        ];
        for (len, expect) in cases {
            let input: Vec<u8> = (0u8..(*len as u8)).collect();
            let out = blake2s::mac(key, &input);
            assert_eq!(&to_hex(&out), expect, "blake2s keyed inlen {len}");
        }
    }

    /// RFC 7693 Appendix E `blake2s_selftest()`: 4 output lengths × 6
    /// input lengths × (unkeyed + keyed with keylen == outlen); the grand
    /// hash of all 48 digests must equal `blake2s_res`. This is the RFC's
    /// own exhaustive functional vector — it covers empty input, 3, 64,
    /// 65, 255 and 1024 bytes (multi-block, partial final block, the
    /// ≥31-byte inputs that exposed the orphan's SIGMA[3][8] defect) in
    /// both unkeyed and keyed modes.
    #[test]
    fn blake2s_selftest_rfc7693_appendix_e() {
        // Deterministic sequence generator (Appendix E, Fibonacci):
        fn selftest_seq(out: &mut [u8], seed: u32) {
            let mut a = 0xDEAD4BADu32.wrapping_mul(seed);
            let mut b = 1u32;
            for slot in out.iter_mut() {
                let t = a.wrapping_add(b);
                a = b;
                b = t;
                *slot = (t >> 24) as u8;
            }
        }
        let md_len = [16usize, 20, 28, 32];
        let in_len = [0usize, 3, 64, 65, 255, 1024];
        let mut ctx_input = Vec::new();
        for &outlen in &md_len {
            for &inlen in &in_len {
                let mut input = vec![0u8; inlen];
                selftest_seq(&mut input, inlen as u32);
                let md = blake2s::hash(&[], &input, outlen);
                ctx_input.extend_from_slice(&md);
                let mut key = vec![0u8; outlen];
                selftest_seq(&mut key, outlen as u32);
                let md = blake2s::hash(&key, &input, outlen);
                ctx_input.extend_from_slice(&md);
            }
        }
        assert_eq!(
            blake2s::hex(&ctx_input),
            "6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe",
            "RFC 7693 Appendix E blake2s grand hash of hashes"
        );
    }

    // -----------------------------------------------------------------------
    // TLS 1.3 key schedule (RFC 8446 §7.1, trace RFC 8448 §3)
    //
    // Every hex string below was extracted mechanically (whitespace-stripped)
    // from the fetched https://www.rfc-editor.org/rfc/rfc8448.txt §3 "Simple
    // 1-RTT Handshake" transcript — never transcribed from memory. The trace
    // step names in the comments are the literal "{server}/{client} ..." step
    // titles of the RFC; the page numbers are the RFC's own page breaks.
    // -----------------------------------------------------------------------

    /// RFC 8446 §7.1 HkdfLabel wire structure. RFC 8448 §3 prints the exact
    /// `info` blobs fed to HKDF-Expand — each one IS an encoded HkdfLabel —
    /// so the structure is checked against official bytes, not hand-built
    /// ones. The bare HKDF-Expand half is pinned against RFC 5869 §A.1 TC1.
    #[test]
    fn tls13_rfc8446_7_1_expand_label_structure() {
        // RFC 8448 §3 "{server} derive secret for handshake "tls13 derived":"
        // (p.5): info (49 octets) = HkdfLabel(32, "tls13 derived", SHA256("")).
        // The empty-transcript hash is also published there ("hash (32
        // octets):  e3 b0 ...").
        let empty_hash = sha256::digest(b"");
        assert_eq!(
            to_hex(&empty_hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let enc = tls13::encode_hkdf_label(b"derived", &empty_hash, 32);
        assert_eq!(
            to_hex(&enc),
            "00200d746c733133206465726976656420\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // RFC 8448 §3 "{server} derive secret "tls13 c hs traffic":" (pp.5-6):
        // info (54 octets) = HkdfLabel(32, "tls13 c hs traffic",
        // Transcript-Hash(ClientHello..ServerHello)).
        let th_ch_sh = from_hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let enc2 = tls13::encode_hkdf_label(b"c hs traffic", &th_ch_sh, 32);
        assert_eq!(
            to_hex(&enc2),
            "002012746c7331332063206873207472616666696320\
             860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
        );
        // RFC 8448 §3 "{server} calculate finished "tls13 finished":" (p.8):
        // info (18 octets) = HkdfLabel(32, "tls13 finished", "").
        let enc3 = tls13::encode_hkdf_label(b"finished", &[], 32);
        assert_eq!(to_hex(&enc3), "00200e746c7331332066696e697368656400");
        // Bare expand phase (RFC 5869 §A.1 TC1): PRK = HMAC-Hash(Salt, IKM)
        // with the §A.1 13-octet salt 000102030405060708090a0b0c (same salt
        // the existing hkdf_sha256_rfc5869_tc1 test uses), expanded directly
        // to the §A.1 OKM.
        let prk = hmac_sha256(&from_hex("000102030405060708090a0b0c"), &[0x0b; 22]);
        let okm = hkdf_sha256_expand(&prk, &from_hex("f0f1f2f3f4f5f6f7f8f9"), 42);
        assert_eq!(
            to_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }

    /// RFC 8448 §3 "Simple 1-RTT Handshake": the full SHA-256 secret chain
    /// replayed through the tls13 helpers. HKDF-Extract steps are plain
    /// HMAC-SHA256 per RFC 5869 §2.2 (RFC 8446 §7.1 draws Extract with Salt
    /// on top, IKM on the left; "0" = Hash.length zero bytes).
    #[test]
    fn tls13_rfc8448_secret_chain() {
        // {server} extract secret "early" (p.4): salt = 0, IKM = 0.
        let zeros = [0u8; 32];
        let early = hmac_sha256(&zeros, &zeros);
        assert_eq!(
            to_hex(&early),
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
        );

        // {server} derive secret for handshake "tls13 derived" (p.5):
        // hash = SHA-256("") (empty transcript), expanded = 6f26….
        let empty_hash = sha256::digest(b"");
        let derived_hs = tls13::derive_secret(&early, b"derived", &empty_hash);
        assert_eq!(
            to_hex(&derived_hs),
            "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
        );

        // {server} extract secret "handshake" (p.5): salt = derived_hs,
        // IKM = the (EC)DHE shared secret published in the trace.
        let ecdhe = from_hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let handshake = hmac_sha256(&derived_hs, &ecdhe);
        assert_eq!(
            to_hex(&handshake),
            "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
        );

        // {server} derive secret "tls13 c hs traffic" (pp.5-6) and
        // "{server} derive secret "tls13 s hs traffic" (p.6): both over
        // Transcript-Hash(ClientHello..ServerHello), recomputed from the raw
        // messages published in §3 and cross-checked against the published
        // "hash (32 octets):  86 0c …".
        let ch = from_hex(
            "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283\
             024dece7000006130113031302010000910000000b0009000006736572766572ff01\
             000100000a00140012001d0017001800190100010101020103010400230000003300\
             260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d541369\
             1e529aaf2c002b0003020304000d0020001e04030503060302030804080508060401\
             0501060102010402050206020202002d00020101001c00024001",
        );
        assert_eq!(ch.len(), 196, "RFC 8448 §3: ClientHello (196 octets)");
        let sh = from_hex(
            "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772e\
             d3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e1\
             56d6cc253b833df1dd69b1b04e751f0f002b00020304",
        );
        assert_eq!(sh.len(), 90, "RFC 8448 §3: ServerHello (90 octets)");
        let th_ch_sh = sha256::digest(&[&ch[..], &sh[..]].concat());
        assert_eq!(
            to_hex(&th_ch_sh),
            "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8",
            "recomputed TH(ClientHello..ServerHello) == published hash"
        );
        let c_hs = tls13::derive_secret(&handshake, b"c hs traffic", &th_ch_sh);
        assert_eq!(
            to_hex(&c_hs),
            "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
        );
        let s_hs = tls13::derive_secret(&handshake, b"s hs traffic", &th_ch_sh);
        assert_eq!(
            to_hex(&s_hs),
            "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
        );

        // {server} derive secret for master "tls13 derived" (p.6):
        // PRK = handshake secret, hash = SHA-256("") again.
        let derived_ms = tls13::derive_secret(&handshake, b"derived", &empty_hash);
        assert_eq!(
            to_hex(&derived_ms),
            "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"
        );

        // {server} extract secret "master" (p.6): salt = derived_ms, IKM = 0.
        let master = hmac_sha256(&derived_ms, &zeros);
        assert_eq!(
            to_hex(&master),
            "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
        );

        // {server} send handshake record (pp.8-10): payload (657 octets) =
        // EncryptedExtensions || Certificate || CertificateVerify || Finished
        // — the server flight, verbatim.
        let srv_flight = from_hex(
            "080000240022000a00140012001d00170018001901000101010201030104001c\
             00024001000000000b0001b9000001b50001b0308201ac30820115a003020102\
             020102300d06092a864886f70d01010b0500300e310c300a0603550403130372\
             7361301e170d3136303733303031323335395a170d3236303733303031323335\
             395a300e310c300a0603550403130372736130819f300d06092a864886f70d01\
             0101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c\
             0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19e\
             aa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e2\
             2a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a\
             8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304\
             023000300b0603551d0f0404030205a0300d06092a864886f70d01010b050003\
             81810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594\
             365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd\
             335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb\
             2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b4\
             2b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f82\
             4cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef78\
             0c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671\
             459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda\
             65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4de\
             da4ab42c309572cb7fffee5454b78f0718",
        );
        assert_eq!(
            srv_flight.len(),
            657,
            "RFC 8448 §3: server flight payload (657 octets)"
        );
        // Transcript-Hash(ClientHello..server Finished) recomputed from the
        // raw messages and cross-checked against the hash RFC 8448 §3
        // publishes in the "tls13 c ap traffic" step (p.10).
        let th_srv_fin = sha256::digest(&[&ch[..], &sh[..], &srv_flight[..]].concat());
        assert_eq!(
            to_hex(&th_srv_fin),
            "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13",
            "recomputed TH(ClientHello..server Finished) == published hash"
        );
        let c_ap = tls13::derive_secret(&master, b"c ap traffic", &th_srv_fin);
        assert_eq!(
            to_hex(&c_ap),
            "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
        );
        let s_ap = tls13::derive_secret(&master, b"s ap traffic", &th_srv_fin);
        assert_eq!(
            to_hex(&s_ap),
            "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
        );
        let exp_master = tls13::derive_secret(&master, b"exp master", &th_srv_fin);
        assert_eq!(
            to_hex(&exp_master),
            "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"
        );

        // {server} calculate finished "tls13 finished" (p.8): finished_key =
        // HKDF-Expand-Label(s_hs, "finished", "", 32) per RFC 8446 §4.4.4
        // ("finished_key = HKDF-Expand-Label(BaseKey, "finished", "",
        // Hash.length)").
        let s_finished_key = tls13::hkdf_expand_label(&s_hs, b"finished", &[], 32);
        assert_eq!(
            to_hex(&s_finished_key),
            "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"
        );
        // verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context,
        // Certificate*, CertificateVerify*)) (RFC 8446 §4.4.4); the server
        // Finished handshake context is "ClientHello ... later of
        // EncryptedExtensions/CertificateRequest" (RFC 8446 §4.4 table) plus
        // Certificate/CertificateVerify — here ClientHello..CertificateVerify.
        let th_to_cert_verify =
            sha256::digest(&[&ch[..], &sh[..], &srv_flight[..srv_flight.len() - 36]].concat());
        let s_verify = hmac_sha256(&s_finished_key, &th_to_cert_verify);
        assert_eq!(
            to_hex(&s_verify),
            "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
        );

        // {client} calculate finished "tls13 finished" (pp.12-13):
        // finished_key = Expand-Label(c_hs, "finished", "", 32);
        // verify_data = HMAC(finished_key, Transcript-Hash(ClientHello..
        // server Finished)) — the client Finished handshake context is
        // "ClientHello ... later of server Finished/EndOfEarlyData"
        // (RFC 8446 §4.4 table).
        let c_finished_key = tls13::hkdf_expand_label(&c_hs, b"finished", &[], 32);
        assert_eq!(
            to_hex(&c_finished_key),
            "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"
        );
        let c_verify = hmac_sha256(&c_finished_key, &th_srv_fin);
        assert_eq!(
            to_hex(&c_verify),
            "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
        );

        // {client} construct a Finished handshake message (p.13):
        // Finished (36 octets) — the client flight's handshake message.
        let cli_finished = from_hex(
            "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2\
             edd5ce61",
        );
        assert_eq!(
            cli_finished.len(),
            36,
            "RFC 8448 §3: Finished (36 octets)"
        );

        // {client} derive secret "tls13 res master" (p.13): PRK = master
        // secret, over Transcript-Hash(ClientHello..client Finished),
        // recomputed and cross-checked against the published "hash (32
        // octets):  20 91 …".
        let th_cli_fin =
            sha256::digest(&[&ch[..], &sh[..], &srv_flight[..], &cli_finished[..]].concat());
        assert_eq!(
            to_hex(&th_cli_fin),
            "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d",
            "recomputed TH(ClientHello..client Finished) == published hash"
        );
        let res_master = tls13::derive_secret(&master, b"res master", &th_cli_fin);
        assert_eq!(
            to_hex(&res_master),
            "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"
        );
    }

    /// One Derive-Secret checked end-to-end INCLUDING the transcript hashing
    /// step: RFC 8448 §3 publishes both the raw ClientHello (196 octets) and
    /// ServerHello (90 octets) handshake messages AND the resulting
    /// transcript hash, so we hash the concatenated messages ourselves with
    /// `sha256::digest` and drive Derive-Secret from the recomputed hash.
    #[test]
    fn tls13_derive_secret_matches_rfc8448() {
        // RFC 8448 §3 "{client} construct a ClientHello handshake message:"
        // (p.3), ClientHello (196 octets), verbatim:
        let ch = from_hex(
            "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283\
             024dece7000006130113031302010000910000000b0009000006736572766572ff01\
             000100000a00140012001d0017001800190100010101020103010400230000003300\
             260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d541369\
             1e529aaf2c002b0003020304000d0020001e04030503060302030804080508060401\
             0501060102010402050206020202002d00020101001c00024001",
        );
        assert_eq!(ch.len(), 196, "RFC 8448 §3: ClientHello (196 octets)");
        // RFC 8448 §3 "{server} construct a ServerHello handshake message:"
        // (p.4), ServerHello (90 octets), verbatim:
        let sh = from_hex(
            "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772e\
             d3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e1\
             56d6cc253b833df1dd69b1b04e751f0f002b00020304",
        );
        assert_eq!(sh.len(), 90, "RFC 8448 §3: ServerHello (90 octets)");

        // Recompute Transcript-Hash(ClientHello..ServerHello) and check it
        // against the hash RFC 8448 §3 publishes in the "tls13 c hs traffic"
        // step (pp.5-6), "hash (32 octets):  86 0c …".
        let th = sha256::digest(&[&ch[..], &sh[..]].concat());
        assert_eq!(
            to_hex(&th),
            "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8",
            "recomputed transcript hash must equal RFC 8448 §3 published hash"
        );

        // Rebuild the handshake secret through the chain (early → derived →
        // Extract with the published ECDHE IKM, all values from §3), then
        // Derive-Secret from OUR hash and compare with the published
        // "tls13 c hs traffic" expanded value.
        let zeros = [0u8; 32];
        let early = hmac_sha256(&zeros, &zeros);
        let empty_hash = sha256::digest(b"");
        let derived_hs = tls13::derive_secret(&early, b"derived", &empty_hash);
        let ecdhe = from_hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let handshake = hmac_sha256(&derived_hs, &ecdhe);
        let c_hs = tls13::derive_secret(&handshake, b"c hs traffic", &th);
        assert_eq!(
            to_hex(&c_hs),
            "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
        );
    }

// ---------------------------------------------------------------------------
// Workspace grep-audit — record-0003 A2-C4 mechanical enforcement (cfb half)
// ---------------------------------------------------------------------------

/// The raw CFB128 primitive must stay private (record-0003 A2-C4: raw CFB
/// encrypt/decrypt types are not pub outside the authenticated wrapper
/// module). Compile-failure half: `cfb128` and its functions are
/// `pub(crate)` in this single-file crate, so no other crate can name them
/// at all. This test is the audit half: ANY `cfb` reference (case-
/// insensitive) in any other workspace .rs file fails CI. When the pub
/// authenticated wrapper arrives, its consumer files extend ALLOWLIST
/// below — each entry with a justification comment and a DECISIONS.md
/// record, the visible journaled path (same pattern as holo-util's
/// rand_split_audit, gate-0001 A2-C3).
#[cfg(test)]
mod cfb_audit {
    use std::path::{Path, PathBuf};

    /// Paths relative to the workspace root where `cfb` may legitimately
    /// appear. Exactly one entry: this file (primitive + KAT tests + this
    /// audit). Extend ONLY with a justification + DECISIONS.md record.
    const ALLOWLIST: &[&str] = &["crates/holo-crypto/src/lib.rs"];

    fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => return,
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue; // hidden dirs (.git, .cargo)
            }
            if p.is_dir() {
                if name == "target" {
                    continue; // build artifacts
                }
                collect_rs(&p, out);
            } else if name.ends_with(".rs") {
                out.push(p);
            }
        }
    }

    /// No exemptions beyond the allowlist — not even integration-test
    /// directories: an unauthenticated raw-CFB reference is a violation
    /// wherever it lives.
    #[test]
    fn cfb_usage_audit() {
        // manifest dir = <root>/crates/holo-crypto → workspace root is two
        // ancestors up; keeps the audit correct in any checkout path.
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest
            .ancestors()
            .nth(2)
            .expect("workspace root above crates/<name>")
            .to_path_buf();

        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        // Guard against scanning the wrong (empty) root: the workspace has
        // 17 .rs files today and must only grow.
        assert!(
            files.len() >= 15,
            "workspace scan found only {} .rs files — wrong root?",
            files.len()
        );

        let mut hits: Vec<String> = Vec::new();
        for f in &files {
            let rel = f
                .strip_prefix(&root)
                .expect("scanned path is under root")
                .to_string_lossy()
                .replace('\\', "/");
            if ALLOWLIST.contains(&rel.as_str()) {
                continue;
            }
            let src = match std::fs::read_to_string(f) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for (i, line) in src.lines().enumerate() {
                if line.to_lowercase().contains("cfb") {
                    hits.push(format!("{}:{}: matched \"cfb\"", rel, i + 1));
                }
            }
        }

        assert!(
            hits.is_empty(),
            "cfb-usage violation (record-0003 A2-C4): raw CFB128 is private to \
             crates/holo-crypto/src/lib.rs and may only be exposed through a pub \
             authenticated wrapper API. Offenders:\n  {}\nIf a consumer is genuinely \
             needed, extend the audit ALLOWLIST with a justification comment and \
             a DECISIONS.md record — never reach around the wrapper.",
            hits.join("\n  ")
        );
    }

}
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // bignum + RSA (RFC 8017 §8.1.2 / §8.2.2 / §9.1 / §9.2)
    //
    // Ground truth (generated BEFORE the implementation was frozen):
    // /home/z/my-project/scratch/rsa_ground_truth.py — Python 3.12 big
    // ints + OpenSSL 3.5.7 cross-check; FULL transcript in
    // /home/z/my-project/scratch/bignum_report.md.
    //
    // DEVIATION NOTE (recorded): the task pointed at an "RFC 8017 §A.1.1
    // example 1024-bit key" — RFC 8017 §A.1.1 ("RSA Public Key Syntax")
    // defines ASN.1 SYNTAX only and contains no key material (verified by
    // grep on the fetched rfc8017.txt; same for rfc3447/rfc2437). The
    // "never transcribe constants from memory" rule is honoured by
    // GENERATING the test key deterministically (sha256-seeded candidate
    // scan + fixed-basis Miller-Rabin in the ground-truth script; p and q
    // confirmed with `openssl prime`), and requiring the Python pow()
    // signatures to be byte-identical with OpenSSL 3.5.7 signatures before
    // embedding (v1.5: `pkeyutl` over the raw DigestInfo + `dgst -sha256
    // -sign`; PSS: an OpenSSL-produced PSS signature is decoded by the same
    // Python EMSA-PSS-VERIFY and its recovered salt checked).
    //
    // Key facts: n is 1023 bits → k = 128 octets = 16 u64 limbs; PSS runs
    // with emBits = 1022, emLen = 128 (the leftmost 2 bits are checked).
    // Test hash h1 = bytes 0..31 (000102…1f); PSS salt = 32 × 0xA5.
    // All hex below is big-endian, as produced by the ground-truth run.

    /// deterministic test modulus n = p·q (see ground-truth script)
    const RSA_N: &str = "4000000000000000000000000000000000000000000000000000000000000000\
    163981027bdb16cc22cc6ece7114cdfe22bcb1d41feb80dec7d8ae2a4bcba87b\
    01ed8391a59c3c6d945f356eacf709e9741d39a14b6636182c32302ff8295fd9\
    c3326cd222ba3435c91c58c5257cfa26d74b8113979b087189066b0410c8fe35";

    const RSA_E: &str = "010001";

    /// Test hash h1 = bytes 0..31 (the pre-hashed message; the verify API
    /// takes H directly, RFC 8017 §8.2.2 step 1 / §9.2 step 1).
    const RSA_MHASH: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// PKCS#1 v1.5 signature over EM(h1) — Python pow(em, d, n),
    /// byte-identical to the OpenSSL 3.5.7 `pkeyutl` raw-DigestInfo signature
    const RSA_SIG_PKCS15: &str = "06235b6053193a407370e3e89295b1bd5af82adefb9852df0d04e3e481b57b13\
    a51ea8dcc65a0eb4b8475459afc119a60ec376782e34acf531170b65d21c0671\
    c29fa954a7c88dec29fdb913cdd9ca597f00374c46927c36af86d0b29c1984cb\
    824739217598d27869dfca8c6e38e3c6ffe479cf96addf42624b066b2918f317";

    /// RSA_SIG_PKCS15 with the last byte's LSB flipped (s′ = s+1 < n)
    const RSA_SIG_PKCS15_FLIP: &str = "06235b6053193a407370e3e89295b1bd5af82adefb9852df0d04e3e481b57b13\
    a51ea8dcc65a0eb4b8475459afc119a60ec376782e34acf531170b65d21c0671\
    c29fa954a7c88dec29fdb913cdd9ca597f00374c46927c36af86d0b29c1984cb\
    824739217598d27869dfca8c6e38e3c6ffe479cf96addf42624b066b2918f316";

    /// PSS signature over EMSA-PSS(h1, salt = 32 × 0xA5) — Python
    /// pow(em, d, n); roundtrip-decoded to recover exactly that salt
    const RSA_SIG_PSS: &str = "2435a8ff3b7710ff47cbd6379925e4a5e0dda7ed2f537084c308f9ec3442a913\
    f9f0685faa76a681533ceeeae8c69ec3d0bd53afbccdd2e54ed0285cfe8fb7b2\
    be0a36a5b5c504bd4fd567edbf70b89e7185b5196ce73db420ba65e9f5d6f490\
    a236da7ae44a0a9880b5cdb923ba4104ee4bf9942e78f08afc55d3c7e511e1c9";

    /// EMSA-PKCS1-v1_5 encoding of h1 (what sig^e mod n must equal)
    const RSA_EM_PKCS15: &str = "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
    ffffffffffffffffffffffff003031300d060960864801650304020105000420\
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// sha256("wrong hash") — a valid but different digest.
    const RSA_WRONG_HASH: &str = "e385e5689bb882cc7f9fb31c192bcc5010b61d4dc38390080af8be3a3783c5fe";
    #[test]
    fn bignum_os2ip_i2osp_roundtrip() {
        // roundtrip arbitrary byte strings of every length 0..70
        for len in 0..70usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 89 + 7) as u8).collect();
            let x = bignum::os2ip(&bytes);
            assert_eq!(bignum::i2osp(&x, len).unwrap(), bytes, "roundtrip len {len}");
        }
        // leading zero octets do not change the value
        assert_eq!(bignum::os2ip(&[0x00, 0x00, 0x01, 0x00]), bignum::os2ip(&[0x01, 0x00]));
        // i2osp zero-pads and rejects oversized values ("integer too large")
        let x = bignum::os2ip(&from_hex("0001ff"));
        assert_eq!(bignum::i2osp(&x, 8).unwrap(), vec![0, 0, 0, 0, 0, 0, 1, 0xff]);
        assert_eq!(bignum::i2osp(&x, 1).unwrap_err(), "i2osp: integer too large");
        assert_eq!(bignum::i2osp(&bignum::os2ip(&[]), 5).unwrap(), vec![0u8; 5]);
        // add/sub sanity — sub is Option, None on underflow (documented)
        let a = bignum::os2ip(&from_hex("01ffffffffffffffff"));
        let sum = bignum::add(&a, &bignum::os2ip(&[0x02]));
        assert_eq!(
            to_hex(&bignum::i2osp(&sum, 9).unwrap()),
            "020000000000000001"
        );
        let diff = bignum::sub(&sum, &bignum::os2ip(&[0x02])).unwrap();
        assert_eq!(
            to_hex(&bignum::i2osp(&diff, 9).unwrap()),
            "01ffffffffffffffff"
        );
        assert!(bignum::sub(&bignum::os2ip(&[0x02]), &sum).is_none());
        // cmp
        assert_eq!(bignum::cmp(&a, &sum), std::cmp::Ordering::Less);
        assert_eq!(bignum::cmp(&sum, &a), std::cmp::Ordering::Greater);
        assert_eq!(bignum::cmp(&sum, &sum), std::cmp::Ordering::Equal);
    }

    #[test]
    fn bignum_mul_schoolbook_vs_python() {
        // products computed independently with Python 3 big ints
        // (x*y hex values in the cross-check transcript)
        let cases: [(&str, &str, &str); 4] = [
            (
                "01",
                "ffffffffffffffff",
                "ffffffffffffffff",
            ),
            (
                "deadbeefcafebabe0123456789abcdef",
                "0123456789abcdefdeadbeefcafebabe",
                "fd5bdeeeb2a01e4069a26f490b6e279038f0d670e5ea427eb689f4ea447d62",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000\
                16df6978f2a93e8aac2d6940a30ef7a2f7ec96fbb0e138b71dabdb21ad8dbc25",
                "8000000000000000000000000000000000000000000000000000000000000000\
                1593988c050cef0d996b745c3f1aa4594d8cccac8ef5c90672058132ea0994d1",
                "4000000000000000000000000000000000000000000000000000000000000000\
                163981027bdb16cc22cc6ece7114cdfe22bcb1d41feb80dec7d8ae2a4bcba87b\
                01ed8391a59c3c6d945f356eacf709e9741d39a14b6636182c32302ff8295fd9\
                c3326cd222ba3435c91c58c5257cfa26d74b8113979b087189066b0410c8fe35",
            ),
            (
                "7fffffffffffffffffffffffffffffff",
                "fffffffffffffffffffffffffffffffe",
                "7ffffffffffffffffffffffffffffffe00000000000000000000000000000002",
            ),
        ];
        for (i, (x, y, xy)) in cases.iter().enumerate() {
            let prod = bignum::mul(&bignum::os2ip(&from_hex(x)), &bignum::os2ip(&from_hex(y)));
            let want = from_hex(xy);
            assert_eq!(
                bignum::i2osp(&prod, want.len()).unwrap(),
                want,
                "mul case {} ({} × {})",
                i,
                x,
                y
            );
        }
    }

    #[test]
    fn montgomery_cios_matches_plain_modmul() {
        let n = bignum::os2ip(&from_hex(RSA_N));
        // Python: n0' = -n^-1 mod 2^64 = fd932e3d99fb1be3
        let n0p = bignum::montgomery_context(&n);
        assert_eq!(n0p, 0xfd932e3d99fb1be3);
        // mont_mul computes x·y·R⁻¹ mod n; the expected values are
        // (x·y·R⁻¹) mod n with R = 2^1024, computed in Python by the
        // ground-truth script (which also simulates this CIOS limb-for-limb
        // and confirms T < 2n for every tuple). The three tuples are
        // sha256-seeded pseudo-random operands < n (limbs 1..3, exercising
        // the short-operand padding paths); n0' below is the Python value.
        let cases: [(&str, &str, &str); 3] = [
            (
                "f8cfab9ce960960379109c89fdc1748a0c9ff087a452d39f4a0be41660da530a",
                "e0042490088cfb1775a7a4dd84462a2d62cdd3a20aad4d3ec09b2cb02e816017",
                "060ecf6174d0af311df9116b49d739aa0f144203e0f931461197e07d8d047096\
                acb8667499bef66c54da01b453f632f862473f15d536e05fe43d592c5402f3ea\
                ea3fce9f6f3a4d53dff0c3e8aead09942df97cae7f67d3b3cf737c2bde553db5\
                ad5ed0f4600f115d691306ffa804bd46d96fbad1d63d36f9f3a63b18930298d6",
            ),
            (
                "08d33327959093d32a8136413ff469ce037bebb0753acd4ae563cd9dc248cb25",
                "151bb76f1f4cfa9186d0eb65ce4733532bc7289a23c5f05137eaa033783fd860",
                "01169f50239264500bc260459a8b83cef2e6ac26019b7b908717b86a3479601d\
                f5b1702545f5c442b18e54075add4f0aabfc147e2c25bfb8fe6db904fea8d9fe\
                4db64582e2930357f6f0144130f7450897a59c13a4bad9267df7ad3ec8881e45\
                40045a1da39b43dbb9638153f72b54b8fa6069472e24356617e0746d17925675",
            ),
            (
                "2d566f4eb9dc25cba5fe21d959b5e975f43c78a82878278a946d5cb0d6e919f5",
                "21170acadb726c53b48fb7bd84c9ac4adde4a7c86b2d100258595b898db1d42c",
                "21404b58e41648b3a991e0ff6730a47d2da47a164c6e9673f0d496a95932224f\
                dd0176b0d085593b9fc1b331b4d009ce06c7f57fc83032990aac002b565fbc58\
                3667f733fe6f244b7609af59f45d2c6a83c442c0d61346e952c552c955b756e8\
                a6c8a8fcfa53cf0571cff7e9080bcfe382608eb2ad18c9f224ae08ef65f836f8",
            ),
        ];
        for (i, (x, y, expected)) in cases.iter().enumerate() {
            let xl = bignum::os2ip(&from_hex(x));
            let yl = bignum::os2ip(&from_hex(y));
            let got = bignum::mont_mul(&xl, &yl, &n, n0p);
            assert_eq!(
                bignum::i2osp(&got, 128).unwrap(),
                from_hex(expected),
                "montgomery case {} (x={}, y={})",
                i,
                x,
                y
            );
        }
    }

    /// n − 1 (the EDGEX value from the cross-check).
    const RSA_N_MINUS_1: &str = "4000000000000000000000000000000000000000000000000000000000000000\
    163981027bdb16cc22cc6ece7114cdfe22bcb1d41feb80dec7d8ae2a4bcba87b\
    01ed8391a59c3c6d945f356eacf709e9741d39a14b6636182c32302ff8295fd9\
    c3326cd222ba3435c91c58c5257cfa26d74b8113979b087189066b0410c8fe34";
    /// (n−1)·(n−1)·R⁻¹ mod n — the EDGE expected result.
    const RSA_EDGE_RESULT: &str = "00f0045e4d3294d2f2ea696c292f44610f513aaaf3ae6aa57109b03eb10f0b25\
    eb6d8816f76be707e80edd2d0dd1c79d2ab0db1efbcab190725ee33ead804b12\
    a0bb732af655df48b2a43d153a7240413c1b15fed41a29c216ba50d085553ad0\
    503261f67404d7d5bad475cfefeeae6a382a1e7a00c7556eddd715f142741fbd";
    /// (n−1)·2·R⁻¹ mod n — the NOEDGE expected result.
    const RSA_NOEDGE_RESULT: &str = "3e1ff743659ad65a1a2b2d27ada1773de15d8aaa18a32ab51dec9f829de1e9b4\
    3f5e70d48d0348bc52aeb47455713ec3cd5afb9628561dbde31ae7acf0cb1255\
    c0769d3bb8f07ddc2f16bb4438128966fbe70da3a331e293febd8e8eed7eea39\
    22cda8e53ab0848a53736d25459f9d5266f7441f960c5d93cd583f218be0bebb";

    #[test]
    fn montgomery_cios_final_carry_edge() {
        // Pairs chosen so the Python CIOS simulation in the ground-truth
        // script (which mirrors this implementation limb-for-limb) confirms
        // the FINAL-CARRY-LIMB branch:
        //   EDGE:    x = y = n−1 → the k+1-limb accumulator BEFORE the final
        //            conditional subtract is
        //            T = 40f0045e4d3294d2f2ea696c292f44610f513aaaf3ae6aa57109b03eb10f0b2601a709197346fdd40adb4bfb7ee6959b4d6d8cf31bb6326f3a379168f94bf38da2a8f6bc9bf21bb647037283e7694a2ab0384fa01f805fda42ec81007d7e9aaa1364cec896bf0c0b83f0ce95156ba8910f759f8d98625de066dd80f5533d1df2
        //            (T ≥ n ⇒ the single final subtraction fires);
        //   NOEDGE:  x = n−1, y = 2 → T < n, no subtraction.
        // Both results equal Python's (x·y·R⁻¹) mod n.
        let n = bignum::os2ip(&from_hex(RSA_N));
        let n0p = bignum::montgomery_context(&n);
        let edge = bignum::mont_mul(
            &bignum::os2ip(&from_hex(RSA_N_MINUS_1)),
            &bignum::os2ip(&from_hex(RSA_N_MINUS_1)),
            &n,
            n0p,
        );
        assert_eq!(
            bignum::i2osp(&edge, 128).unwrap(),
            from_hex(RSA_EDGE_RESULT),
            "edge case: product ≥ n must survive the final subtract"
        );
        let noedge = bignum::mont_mul(
            &bignum::os2ip(&from_hex(RSA_N_MINUS_1)),
            &bignum::os2ip(&[0x02]),
            &n,
            n0p,
        );
        assert_eq!(
            bignum::i2osp(&noedge, 128).unwrap(),
            from_hex(RSA_NOEDGE_RESULT),
            "no-edge case: T < n, unchanged by the final subtract"
        );
    }

    #[test]
    fn rsa_pkcs1_v1_5_sha256_verify_rfc8017_key() {
        // Test-name note: RFC 8017 ships no example key (§A.1.1 is ASN.1
        // syntax only — see DEVIATION NOTE above); the embedded key/signature
        // pair is the deterministically generated one whose Python and
        // OpenSSL 3.5.7 signatures are byte-identical (PKCS#1 v1.5 is
        // deterministic).
        let n = from_hex(RSA_N);
        let e = from_hex(RSA_E);
        let mhash = from_hex(RSA_MHASH);
        let sig = from_hex(RSA_SIG_PKCS15);
        rsa::verify_pkcs1_v1_5_sha256(&n, &e, &mhash, &sig).unwrap();
        // direct primitive cross-check (exercises the spec-named API):
        // mont_pow(sig, e, n, ctx) must I2OSP to the exact EMSA-PKCS1-v1_5
        // encoding computed by Python (00 01 ff… 00 ||
        // 3031300d060960864801650304020105000420 || h1)
        let n_big = bignum::os2ip(&n);
        let ctx = bignum::montgomery_context(&n_big);
        let m = bignum::mont_pow(&bignum::os2ip(&sig), &bignum::os2ip(&e), &n_big, ctx);
        assert_eq!(
            bignum::i2osp(&m, n.len()).unwrap(),
            from_hex(RSA_EM_PKCS15),
            "modpow(sig, e, n) must decode to the Python-computed EM"
        );
    }

    #[test]
    fn rsa_pkcs1_v1_5_rejects_bitflip_and_wrong_hash() {
        let n = from_hex(RSA_N);
        let e = from_hex(RSA_E);
        let mhash = from_hex(RSA_MHASH);
        // last signature byte flipped (…aed4bc → …aed4bd): s changes ⇒ the
        // recovered EM cannot match ⇒ rejected at the EM-compare stage
        assert_eq!(
            rsa::verify_pkcs1_v1_5_sha256(&n, &e, &mhash, &from_hex(RSA_SIG_PKCS15_FLIP))
                .unwrap_err(),
            "rsa: PKCS#1 v1.5 encoded message mismatch"
        );
        // same signature against a different (valid) hash: EM' differs
        assert_eq!(
            rsa::verify_pkcs1_v1_5_sha256(&n, &e, &from_hex(RSA_WRONG_HASH), &from_hex(RSA_SIG_PKCS15))
                .unwrap_err(),
            "rsa: PKCS#1 v1.5 encoded message mismatch"
        );
    }

    #[test]
    fn rsa_pss_sha256_verify_fixed_salt() {
        let n = from_hex(RSA_N);
        let e = from_hex(RSA_E);
        let mhash = from_hex(RSA_MHASH);
        let sig = from_hex(RSA_SIG_PSS);
        // fixed salt = 32 × 0xA5, emBits = 1022: the Python pow() signature
        // roundtrip-decodes (public-key math) to exactly salt a5×32, and the
        // same Python EMSA-PSS-VERIFY also accepts an OpenSSL 3.5.7-produced
        // PSS signature (recovered salt, 32 bytes) — see ground truth.
        rsa::verify_pss_sha256(&n, &e, 32, &mhash, &sig).unwrap();
        // any corrupted signature must be rejected (stage unspecified)
        let mut bad = sig.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        assert!(rsa::verify_pss_sha256(&n, &e, 32, &mhash, &bad).is_err());
    }

    #[test]
    fn rsa_pss_rejects_wrong_salt_len() {
        // Distinct error per §9.1.2 stage, exactly as recorded in the
        // ground truth: the real DB is 62 zero octets, 0x01, salt.
        let n = from_hex(RSA_N);
        let e = from_hex(RSA_E);
        let mhash = from_hex(RSA_MHASH);
        let sig = from_hex(RSA_SIG_PSS);
        // sLen = 31: ps_len grows to 63 so the 0x01 lands inside the
        // checked-zero region
        assert_eq!(
            rsa::verify_pss_sha256(&n, &e, 31, &mhash, &sig).unwrap_err(),
            "rsa/pss: DB padding zeros corrupted"
        );
        // sLen = 33: ps_len shrinks to 61, DB[61] = 0x00 ≠ 0x01
        assert_eq!(
            rsa::verify_pss_sha256(&n, &e, 33, &mhash, &sig).unwrap_err(),
            "rsa/pss: DB separator byte (0x01) missing"
        );
        // sLen = 0: the whole DB including 0x01 must be zero ⇒ fails early
        assert_eq!(
            rsa::verify_pss_sha256(&n, &e, 0, &mhash, &sig).unwrap_err(),
            "rsa/pss: DB padding zeros corrupted"
        );
        // sLen = 200: emLen < hLen + sLen + 2 ⇒ length stage
        assert_eq!(
            rsa::verify_pss_sha256(&n, &e, 200, &mhash, &sig).unwrap_err(),
            "rsa/pss: encoded message too short for salt length"
        );
    }

    #[test]
    fn rsa_rejects_wrong_sig_length() {
        let n = from_hex(RSA_N);
        let e = from_hex(RSA_E);
        let mhash = from_hex(RSA_MHASH);
        let sig = from_hex(RSA_SIG_PKCS15);
        let sig_pss = from_hex(RSA_SIG_PSS);
        // §8.2.2 / §8.1.2 step 1: S must be exactly k = 128 octets
        assert_eq!(
            rsa::verify_pkcs1_v1_5_sha256(&n, &e, &mhash, &sig[..127]).unwrap_err(),
            "rsa: signature length != modulus length"
        );
        let mut long = sig.clone();
        long.push(0x00);
        assert_eq!(
            rsa::verify_pkcs1_v1_5_sha256(&n, &e, &mhash, &long).unwrap_err(),
            "rsa: signature length != modulus length"
        );
        assert_eq!(
            rsa::verify_pss_sha256(&n, &e, 32, &mhash, &sig_pss[..127]).unwrap_err(),
            "rsa: signature length != modulus length"
        );
        assert_eq!(
            rsa::verify_pss_sha256(&n, &e, 32, &mhash, &long).unwrap_err(),
            "rsa: signature length != modulus length"
        );
        // RSAVP1 §5.2.2 range check: s = n is in-range-length but out of
        // range ⇒ distinct error
        assert_eq!(
            rsa::verify_pkcs1_v1_5_sha256(&n, &e, &mhash, &n).unwrap_err(),
            "rsa: signature representative out of range"
        );
        assert_eq!(
            rsa::verify_pss_sha256(&n, &e, 32, &mhash, &n).unwrap_err(),
            "rsa: signature representative out of range"
        );
    }
}
