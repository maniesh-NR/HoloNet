//! TLS 1.3 CLIENT handshake state machine (RFC 8446) — drives a REAL
//! `std::net::TcpStream` end to end and yields an application-data
//! connection ([`ClientConn`]).
//!
//! # Flight model (RFC 8446 §2, figure 1 — "no PSK" 1-RTT column)
//!
//! ```text
//!       client                                   server
//!    ClientHello
//!                          -------->
//!                                               ServerHello
//!                                              {EncryptedExtensions}*
//!                                              {Certificate}*
//!                                        {CertificateVerify}*
//!                          <--------      {Finished}
//!    {Finished}              -------->
//!    [Application Data]      <------->      [Application Data]
//! ```
//!
//! Everything `{...}` travels inside AEAD-protected records; `*` marks
//! messages that are optional only in the PSK/PSK-only columns, which are OUT
//! OF SCOPE here (see "Scope honesty" below).
//!
//! # Key schedule wiring (RFC 8446 §7.1 / §7.3)
//!
//! All derivation is delegated to the batch-1 `schedule` module (RFC 8448
//! §3-pinned).  The one schedule line `schedule::handshake_secrets` does not
//! return is the Handshake Secret ITSELF (needed for the Master Secret);
//! [`handshake_secret_from_dh`] derives it with the schedule module's own
//! published helpers — `early_secret()` → `derived_secret(., "derived",
//! TRANSCRIPT_HASH_EMPTY)` as the HKDF-Extract salt — which is exactly the
//! §7.1 diagram line
//!
//! ```text
//!       Derive-Secret(., "derived", "")
//!             |
//!             v
//!   (EC)DHE -> HKDF-Extract = Handshake Secret
//! ```
//!
//! Traffic keys (§7.3, verbatim):
//!
//! ```text
//!    [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
//!    [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", 12)
//! ```
//!
//! `key_length` is 16 for TLS_AES_128_GCM_SHA256 and 32 for
//! TLS_AES_256_GCM_SHA384 / TLS_CHACHA20_POLY1305_SHA256 (§B.4 key-length
//! column; SHA-256 hashes the transcript for all three — see the deviation
//! note on [`AeadAlg::from_suite`]).
//!
//! # Record protection (RFC 8446 §5.2, verbatim)
//!
//! ```text
//!    The per-record nonce for the AEAD constructions is formed as follows:
//!
//!    1.  The 64-bit record sequence number is encoded in big-endian order
//!        and padded to the left with zeros to iv_len in length.
//!
//!    2.  The padded sequence number is XORed with the static writer IV,
//!        ...
//! ```
//!
//! ([`record_nonce`] implements exactly this; the AAD is the 5-byte
//! TLSCiphertext header, per §5.2 "AAD ... is ... TLSCiphertext headers".)
//! Sequence numbers reset whenever the keys change (§5.3).
//!
//! # CertificateVerify (RFC 8446 §4.4.3)
//!
//! The server signs, verbatim per §4.4.3 (context strings):
//!
//! > The context string for the server signature is "TLS 1.3, server
//! > CertificateVerify" and for a client signature it is "TLS 1.3, client
//! > CertificateVerify".
//!
//! and the signed content (§4.4.3, "The signer signs the concatenation of"):
//!
//! > *  64 repeated instances of the octet 0x20,
//! > *  the context string,
//! > *  a single 0 byte which serves as the separator,
//! > *  the content to be signed.
//!
//! where the content is `Transcript-Hash(Handshake Context, Certificate)`
//! (§4.4.3).  §4.4.3 additionally requires, verbatim: "The algorithm field
//! MUST be a valid SignatureScheme value listed in the client's
//! 'signature_algorithms' extension (Section 4.2.3)." — this client
//! advertises exactly the two schemes it can verify (§B.2 values
//! `rsa_pss_rsae_sha256(0x0804)` and `rsa_pkcs1_sha256(0x0401)`); anything
//! else aborts with a distinct unsupported-algorithm error.
//!
//! # Server Finished (RFC 8446 §4.4.4)
//!
//! > Recipients of Finished messages MUST verify that the contents are
//! > correct and if incorrect MUST terminate the connection with a
//! > "decrypt_error" alert.
//!
//! # Signature algorithms — RFC 8446 §B.2 (the values, checked verbatim)
//!
//! The RFC's SignatureScheme enum (§B.2) assigns, among others:
//!
//! ```text
//!    /* RSASSA-PKCS1-v1_5 algorithms */
//!    rsa_pkcs1_sha256(0x0401),
//!    ...
//!    /* RSASSA-PSS with public key OID rsaEncryption */
//!    rsa_pss_rsae_sha256(0x0804),
//!    rsa_pss_rsae_sha384(0x0805),
//!    rsa_pss_rsae_sha512(0x0806),
//!    ...
//!    /* RSASSA-PSS with public key OID RSASSA-PSS */
//!    rsa_pss_pss_sha256(0x0809),
//! ```
//!
//! i.e. `rsa_pkcs1_sha256` is 0x0401 (NOT 0x0804 — 0x0804 is the RSA-PSS
//! scheme).  0x0805/0x0806 are the SHA-384/SHA-512 PSS variants, which
//! `holo_crypto`'s SHA-256-only verifiers cannot check — advertising a
//! scheme that would force a later abort would be dishonest, so the offer is
//! {0x0804, 0x0401} and the deviation from the task briefing's suggestion is
//! recorded in the module report.
//!
//! # Scope honesty (charter)
//!
//! - NO PSK / 0-RTT / session tickets / client auth / KeyUpdate: if a
//!   NewSessionTicket(4), EndOfEarlyData(5), CertificateRequest(13) or
//!   KeyUpdate(24) arrives, the client aborts with a DISTINCT
//!   "unsupported handshake message" error (RFC 8446 §4, HandshakeType
//!   enum).  `pre_shared_key` / `early_data` extensions are never offered.
//! - Single pinned certificate by design — batch-1 charter (spki module
//!   docs): "By design there is NO chain building and NO
//!   certificate-signature verification in this module: pinning REPLACES
//!   chain validation (the pin is the trust anchor; the peer must present
//!   the pinned key)."
//! - Entropy is `holo_util::rand::os_fill` (fail-closed) or an INJECTED
//!   source for deterministic tests; there is no third (weak) path.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};

use holo_crypto::aead_chacha20poly1305_decrypt;
use holo_crypto::aead_chacha20poly1305_encrypt;
use holo_crypto::ct_eq;
use holo_crypto::gcm;
use holo_crypto::hmac_sha256;
use holo_crypto::rsa;
use holo_crypto::sha256;
use holo_crypto::tls13;
use holo_crypto::x25519;
use holo_util::rand::os_fill;

use crate::alert::{AlertDescription, AlertLevel};
use crate::handshake;
use crate::handshake::{
    cipher_suite, ext_type, named_group, signature_scheme, ClientHelloParams,
};
use crate::record::{
    self, ContentType, HandshakeAssembler, HandshakeFrame, LEGACY_VERSION_INITIAL_CLIENT_HELLO,
    LEGACY_VERSION_OTHER,
};
use crate::schedule;
use crate::spki;
use crate::transcript;
use crate::Error as CodecError;

// ===========================================================================
// Errors — every failure stage has its own variant and its own
// "tls: client: ..." message, plus an RFC 8446 §6 alert mapping.
// ===========================================================================

/// Client handshake / connection failure.  Every variant's `Display` output
/// is a distinct string identifying the failing stage (HoloNet convention).
#[derive(Debug)]
pub enum ClientError {
    /// TCP I/O (including premature peer close).
    Io(std::io::Error),
    /// Record/handshake codec failure (the inner error carries its own
    /// distinct `tls: ...` message and §6 alert mapping).
    Codec(CodecError),
    /// The entropy source failed — fail-closed: no security material is
    /// ever derived from a weaker fallback.
    Entropy(std::io::Error),
    /// x25519 returned None: the shared secret is the all-zero value.
    SharedSecretNotContributory,
    /// §7.1 schedule rejection (all-zero/empty DH guard lives in
    /// `schedule::handshake_secrets`).
    KeySchedule(String),
    /// A second HelloRetryRequest in one connection (§4.1.4 forbids it).
    MultipleHelloRetryRequests,
    /// The HRR selected a group this client does not support (only x25519).
    HrrSelectedGroupUnsupported(u16),
    /// The ServerHello's key_share group was not the offered x25519.
    ServerKeyShareGroupUnsupported(u16),
    /// The ServerHello key share is not 32 bytes.
    BadServerKeyShare(usize),
    /// A handshake message arrived out of order / of the wrong type.
    UnexpectedMessage { expected: &'static str, got: u8 },
    /// The peer closed the connection mid-handshake without a flight or
    /// alert.
    UnexpectedEndOfStream,
    /// A handshake message whose handling is out of scope by charter
    /// (new_session_ticket 4, end_of_early_data 5, certificate_request 13,
    /// key_update 24) — distinct from a generic unexpected message.
    UnsupportedHandshake(u8),
    /// The peer sent a fatal (or unparseable) alert.
    ServerAlert { level: u8, description: u8 },
    /// A middlebox compatibility change_cipher_spec record whose payload is
    /// not the single byte 0x01 (RFC 8446 Appendix D.4).
    MalformedChangeCipherSpec,
    /// The Certificate message carried a non-empty certificate_request_context
    /// (§4.4.2: zero-length without client authentication — out of scope).
    CertificateRequestContextUnexpected,
    /// Server sent an empty certificate_list.
    CertificateEmpty,
    /// SPKI pin verification failed (inner string is the spki module's own
    /// distinct error, e.g. "spki: pin: sha256 mismatch").
    PinCheckFailed(String),
    /// The expected hostname does not match the certificate SAN entries
    /// (RFC 6125 §6.4 via `spki::matches_hostname` → Ok(false)).
    HostnameMismatch { hostname: String },
    /// Identity check could not even run (absent SAN, embedded NUL guard,
    /// DER failure — inner string from `spki::matches_hostname`).
    IdentityCheckFailed(String),
    /// The certificate's SubjectPublicKeyInfo could not be parsed as an
    /// RSA key (DER defect).
    CertKeyExtract(String),
    /// The certificate is not an rsaEncryption key — only RSA servers are
    /// supported today (only RSA verifiers exist in holo-crypto).
    CertNotRsa,
    /// CertificateVerify used a scheme outside the offered {0x0804, 0x0401}.
    UnsupportedSignatureAlgorithm(u16),
    /// CertificateVerify signature verification failed (inner string from
    /// the RSA verifier).
    CertificateVerifyInvalid(&'static str),
    /// The server Finished verify_data did not match the transcript.
    ServerFinishedMismatch,
    /// AEAD open of a protected record failed (bad_record_mac, §5.2).
    AeadOpen(&'static str),
    /// Cipher suite outside the implemented three (defensive — the codec
    /// already rejects unoffered suites).
    UnsupportedCipherSuite(u16),
    /// The §5.3 record sequence-number space is exhausted.
    SequenceOverflow,
}

impl ClientError {
    /// True when the underlying IO condition is a clean premature EOF
    /// (peer closed without sending anything more).
    pub fn is_eof(&self) -> bool {
        matches!(self, ClientError::Io(e) if e.kind() == ErrorKind::UnexpectedEof)
    }

    /// The RFC 8446 §6 alert this failure maps to.  `None` = do not answer
    /// an alert with an alert (the peer already aborted).
    pub fn alert(&self) -> Option<AlertDescription> {
        use AlertDescription as A;
        match self {
            ClientError::Io(_) | ClientError::Entropy(_) | ClientError::UnexpectedEndOfStream => {
                Some(A::InternalError)
            }
            ClientError::Codec(e) => Some(e.alert()),
            ClientError::SharedSecretNotContributory | ClientError::KeySchedule(_) => {
                Some(A::IllegalParameter)
            }
            ClientError::MultipleHelloRetryRequests
            | ClientError::UnexpectedMessage { .. }
            | ClientError::UnsupportedHandshake(_) => Some(A::UnexpectedMessage),
            ClientError::HrrSelectedGroupUnsupported(_)
            | ClientError::ServerKeyShareGroupUnsupported(_)
            | ClientError::BadServerKeyShare(_)
            | ClientError::UnsupportedSignatureAlgorithm(_)
            | ClientError::CertificateEmpty
            | ClientError::CertificateRequestContextUnexpected => Some(A::IllegalParameter),
            ClientError::ServerAlert { .. } => None,
            ClientError::MalformedChangeCipherSpec => Some(A::DecodeError),
            ClientError::PinCheckFailed(_)
            | ClientError::HostnameMismatch { .. }
            | ClientError::IdentityCheckFailed(_)
            | ClientError::CertKeyExtract(_)
            | ClientError::CertNotRsa => Some(A::BadCertificate),
            ClientError::CertificateVerifyInvalid(_) | ClientError::ServerFinishedMismatch => {
                // §6: "decrypt_error: A handshake cryptographic operation
                // failed, including being unable to correctly verify a
                // signature or validate a Finished message."
                Some(A::DecryptError)
            }
            ClientError::AeadOpen(_) => Some(A::BadRecordMac),
            ClientError::UnsupportedCipherSuite(_) => Some(A::HandshakeFailure),
            ClientError::SequenceOverflow => Some(A::InternalError),
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "tls: client: io: {e}"),
            ClientError::Codec(e) => write!(f, "tls: client: codec: {e}"),
            ClientError::Entropy(e) => write!(
                f,
                "tls: client: entropy: {e} — fail-closed (no weak fallback for security material)"
            ),
            ClientError::SharedSecretNotContributory => write!(
                f,
                "tls: client: x25519: shared secret is the all-zero value — abort (RFC 8446 §7.4.1: \
                 \"Implementations MUST check whether the computed Diffie-Hellman shared secret is \
                 the all-zero value and abort if so\")"
            ),
            ClientError::KeySchedule(s) => write!(f, "tls: client: key schedule: {s}"),
            ClientError::MultipleHelloRetryRequests => write!(
                f,
                "tls: client: helloretryrequest: received a SECOND HelloRetryRequest in one \
                 connection — abort (RFC 8446 §4.1.4: the client MUST abort with \
                 \"unexpected_message\")"
            ),
            ClientError::HrrSelectedGroupUnsupported(g) => write!(
                f,
                "tls: client: helloretryrequest: server selected group 0x{g:04x}; the client \
                 offered only x25519 (0x001d) — abort"
            ),
            ClientError::ServerKeyShareGroupUnsupported(g) => write!(
                f,
                "tls: client: serverhello: server key_share group 0x{g:04x} was not offered \
                 (only x25519) — abort"
            ),
            ClientError::BadServerKeyShare(n) => write!(
                f,
                "tls: client: serverhello: key share is {n} bytes (x25519 requires 32) — abort"
            ),
            ClientError::UnexpectedMessage { expected, got } => write!(
                f,
                "tls: client: unexpected handshake message type 0x{got:02x} while waiting for \
                 {expected} — abort"
            ),
            ClientError::UnexpectedEndOfStream => write!(
                f,
                "tls: client: peer closed the connection mid-handshake without a flight or alert \
                 — abort"
            ),
            ClientError::UnsupportedHandshake(t) => write!(
                f,
                "tls: client: unsupported handshake message 0x{t:02x} — PSK/0-RTT/session tickets \
                 (new_session_ticket 4, end_of_early_data 5), client authentication \
                 (certificate_request 13) and KeyUpdate (24) are out of scope by charter — abort"
            ),
            ClientError::ServerAlert { level, description } => write!(
                f,
                "tls: client: server sent alert level {} {} ({}) — abort",
                level,
                description,
                AlertDescription::from_u8(*description).name()
            ),
            ClientError::MalformedChangeCipherSpec => write!(
                f,
                "tls: client: record: change_cipher_spec compatibility record payload is not the \
                 single byte 0x01 (RFC 8446 Appendix D.4) — abort"
            ),
            ClientError::CertificateRequestContextUnexpected => write!(
                f,
                "tls: client: certificate: certificate_request_context is non-empty (RFC 8446 \
                 §4.4.2: zero length without client authentication — out of scope) — abort"
            ),
            ClientError::CertificateEmpty => write!(
                f,
                "tls: client: certificate: the server sent an EMPTY certificate_list — abort"
            ),
            ClientError::PinCheckFailed(e) => write!(
                f,
                "tls: client: certificate: SPKI pin verification failed: {e} — the server's key \
                 is not the pinned key — abort"
            ),
            ClientError::HostnameMismatch { hostname } => write!(
                f,
                "tls: client: certificate: hostname '{hostname}' does not match any certificate \
                 SAN entry (RFC 6125 §6.4 identity comparison) — abort"
            ),
            ClientError::IdentityCheckFailed(e) => write!(
                f,
                "tls: client: certificate: identity check failed: {e} — abort"
            ),
            ClientError::CertKeyExtract(e) => write!(
                f,
                "tls: client: certificate: RSA public key extraction failed: {e} — abort"
            ),
            ClientError::CertNotRsa => write!(
                f,
                "tls: client: certificate: SubjectPublicKeyInfo is not rsaEncryption — only RSA \
                 servers are supported today — abort"
            ),
            ClientError::UnsupportedSignatureAlgorithm(a) => write!(
                f,
                "tls: client: certificateverify: unsupported signature algorithm 0x{a:04x} — the \
                 client advertised rsa_pss_rsae_sha256 (0x0804) and rsa_pkcs1_sha256 (0x0401) \
                 (RFC 8446 §B.2 values); §4.4.3: the algorithm MUST be from the client's \
                 'signature_algorithms' extension — abort"
            ),
            ClientError::CertificateVerifyInvalid(e) => write!(
                f,
                "tls: client: certificateverify: signature verification failed ({e}) — abort"
            ),
            ClientError::ServerFinishedMismatch => write!(
                f,
                "tls: client: finished: server Finished verify_data does NOT match \
                 Transcript-Hash(ClientHello..CertificateVerify) — transcript/keys mismatch \
                 (RFC 8446 §4.4.4: terminate with \"decrypt_error\") — abort"
            ),
            ClientError::AeadOpen(e) => write!(
                f,
                "tls: client: record: AEAD open failed: {e} — bad_record_mac (RFC 8446 §5.2) — abort"
            ),
            ClientError::UnsupportedCipherSuite(s) => write!(
                f,
                "tls: client: serverhello: cipher suite 0x{s:04x} is not one of the three \
                 implemented suites — abort"
            ),
            ClientError::SequenceOverflow => write!(
                f,
                "tls: client: record: record sequence number space exhausted (RFC 8446 §5.3) — abort"
            ),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<CodecError> for ClientError {
    fn from(e: CodecError) -> Self {
        ClientError::Codec(e)
    }
}

// ===========================================================================
// Entropy — the ONLY randomness seam (security material, fail-closed)
// ===========================================================================

/// Source of security-grade randomness.  Implementations MUST be fail-closed:
/// on any inability to produce unpredictable bytes they return `Err` and the
/// handshake aborts — never degrade to a predictable source.
pub trait Entropy {
    /// Fill `out` with unpredictable bytes (all call sites ask for 32).
    fn fill32(&mut self, out: &mut [u8; 32]) -> std::io::Result<()>;
}

/// OS-entropy source — `holo_util::rand::os_fill` (fail-closed `/dev/urandom`
/// on unix, RtlGenRandom on Windows).  This is the production source.
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill32(&mut self, out: &mut [u8; 32]) -> std::io::Result<()> {
        os_fill(out)
    }
}

/// INJECTED deterministic entropy for reproducible tests.  Consumes
/// pre-supplied 32-byte chunks in order; an EMPTY pool is a HARD ERROR
/// (fail-closed: the client refuses to continue rather than improvise
/// randomness).  Test material only — never for production security material.
pub struct InjectedEntropy {
    pool: VecDeque<Vec<u8>>,
}

impl InjectedEntropy {
    /// Build the pool from 32-byte chunks (consumed in order).
    pub fn new(chunks: &[&[u8]]) -> Self {
        let pool = chunks
            .iter()
            .map(|c| {
                assert_eq!(c.len(), 32, "injected entropy chunks are 32 bytes");
                c.to_vec()
            })
            .collect();
        InjectedEntropy { pool }
    }
}

impl Entropy for InjectedEntropy {
    fn fill32(&mut self, out: &mut [u8; 32]) -> std::io::Result<()> {
        match self.pool.pop_front() {
            Some(chunk) if chunk.len() == 32 => {
                out.copy_from_slice(&chunk);
                Ok(())
            }
            Some(_) => Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "injected entropy chunk is not 32 bytes — fail-closed",
            )),
            None => Err(std::io::Error::new(
                ErrorKind::Other,
                "injected entropy pool exhausted — fail-closed (refusing weak fallback)",
            )),
        }
    }
}

// ===========================================================================
// AEAD + record protection (§5.2)
// ===========================================================================

/// The three negotiated cipher suites' AEAD engines.
/// NOTE (documented deviation): TLS_AES_256_GCM_SHA384 (0x1302) formally
/// pairs AES-256-GCM with a SHA-384 transcript; holo-crypto implements
/// SHA-256 only, so this crate negotiates 0x1302 with the SHA-256
/// transcript/schedule (identical behaviour on both loopback peers, pinned
/// by tests; NOT interoperable with a real 0x1302 peer — recorded in the
/// module report).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlg {
    pub(crate) fn from_suite(suite: u16) -> Result<Self, ClientError> {
        match suite {
            cipher_suite::TLS_AES_128_GCM_SHA256 => Ok(AeadAlg::Aes128Gcm),
            cipher_suite::TLS_AES_256_GCM_SHA384 => Ok(AeadAlg::Aes256Gcm),
            cipher_suite::TLS_CHACHA20_POLY1305_SHA256 => Ok(AeadAlg::ChaCha20Poly1305),
            s => Err(ClientError::UnsupportedCipherSuite(s)),
        }
    }

    /// §B.4 key-length column: 16 for AES-128, 32 for AES-256 and ChaCha20.
    pub(crate) fn key_len(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm => 16,
            AeadAlg::Aes256Gcm | AeadAlg::ChaCha20Poly1305 => 32,
        }
    }
}

/// AEAD-encrypt (§5.2: "the AEAD encryption ... encrypted_record = AEAD
/// output"): ciphertext || tag.
pub(crate) fn aead_seal(
    alg: AeadAlg,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    match alg {
        AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => gcm::encrypt(key, nonce, aad, plaintext),
        AeadAlg::ChaCha20Poly1305 => {
            let k: [u8; 32] = key.try_into().expect("chacha key is 32 bytes by construction");
            aead_chacha20poly1305_encrypt(&k, nonce, aad, plaintext)
        }
    }
}

/// AEAD-decrypt (§5.2: tag-verification failure terminates the connection
/// with a "bad_record_mac" alert).
pub(crate) fn aead_open(
    alg: AeadAlg,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    match alg {
        AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => gcm::decrypt(key, nonce, aad, ct_and_tag),
        AeadAlg::ChaCha20Poly1305 => {
            let k: [u8; 32] = key.try_into().expect("chacha key is 32 bytes by construction");
            aead_chacha20poly1305_decrypt(&k, nonce, aad, ct_and_tag)
        }
    }
}

/// The §5.2 per-record nonce (module doc carries the verbatim RFC text):
/// the 64-bit big-endian record sequence number, left-padded with zeros to
/// iv_len = 12, XORed with the static writer IV.
pub fn record_nonce(static_iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let seq_be = seq.to_be_bytes(); // 8 bytes, big-endian (§5.2 step 1)
    let mut nonce = *static_iv;
    for i in 0..8 {
        nonce[4 + i] ^= seq_be[i]; // right-aligned: occupies nonce[4..12]
    }
    nonce
}

/// Per-direction traffic keys for one epoch (§7.3).
#[derive(Debug, Clone)]
pub(crate) struct WriteKeys {
    pub(crate) key: Vec<u8>,
    pub(crate) iv: [u8; 12],
    pub(crate) seq: u64,
}

/// Read-side mirror of [`WriteKeys`].
#[derive(Debug, Clone)]
pub(crate) struct ReadKeys {
    pub(crate) key: Vec<u8>,
    pub(crate) iv: [u8; 12],
    pub(crate) seq: u64,
}

impl WriteKeys {
    /// §7.3 (verbatim in the module docs):
    /// `key = HKDF-Expand-Label(Secret, "key", "", key_length)` and
    /// `iv = HKDF-Expand-Label(Secret, "iv", "", 12)`.
    pub(crate) fn derive(alg: AeadAlg, secret: &[u8; 32]) -> Self {
        let key = tls13::hkdf_expand_label(secret, b"key", &[], alg.key_len());
        let iv = tls13::hkdf_expand_label(secret, b"iv", &[], 12);
        WriteKeys {
            key,
            iv: iv.try_into().expect("iv expansion is exactly 12 bytes"),
            seq: 0, // §5.3: sequence numbers start at 0 and reset on key change
        }
    }
}

impl ReadKeys {
    pub(crate) fn derive(alg: AeadAlg, secret: &[u8; 32]) -> Self {
        let key = tls13::hkdf_expand_label(secret, b"key", &[], alg.key_len());
        let iv = tls13::hkdf_expand_label(secret, b"iv", &[], 12);
        ReadKeys {
            key,
            iv: iv.try_into().expect("iv expansion is exactly 12 bytes"),
            seq: 0,
        }
    }
}

/// Largest application content per record: TLSInnerPlaintext = content +
/// 1 type byte ≤ 2^14 + 1 (§5.4), so content ≤ 2^14.
pub(crate) const MAX_APP_CONTENT: usize = record::MAX_INNER_PLAINTEXT - 1;

/// Seal one record (§5.2): TLSInnerPlaintext = content || type || padding,
/// AEAD over it with nonce = record_nonce(static_iv, seq) and AAD = the
/// 5-byte TLSCiphertext header carrying the CIPHERTEXT length
/// (inner.len() + 16 tag).  Bumps the sequence number.
pub(crate) fn seal_record(
    alg: AeadAlg,
    keys: &mut WriteKeys,
    content_type: ContentType,
    content: &[u8],
) -> Result<Vec<u8>, ClientError> {
    if keys.seq == u64::MAX {
        return Err(ClientError::SequenceOverflow);
    }
    let inner = record::encode_inner_plaintext(content, content_type, 0)?;
    let enc_len = inner.len() + holo_crypto::POLY_TAG;
    let header = record::encode_ciphertext_header(enc_len)?;
    let nonce = record_nonce(&keys.iv, keys.seq);
    let ct = aead_seal(alg, &keys.key, &nonce, &header, &inner);
    keys.seq += 1;
    let mut out = Vec::with_capacity(record::RECORD_HEADER_LEN + ct.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open one protected record (§5.2).  `header` is the 5 received header
/// bytes (they are the AAD verbatim); on success bumps the sequence number.
pub(crate) fn open_record(
    alg: AeadAlg,
    keys: &mut ReadKeys,
    header: &[u8; 5],
    payload: &[u8],
) -> Result<(ContentType, Vec<u8>), ClientError> {
    if keys.seq == u64::MAX {
        return Err(ClientError::SequenceOverflow);
    }
    let nonce = record_nonce(&keys.iv, keys.seq);
    let inner = aead_open(alg, &keys.key, &nonce, header, payload).map_err(ClientError::AeadOpen)?;
    let (ct, content) = record::decode_inner_plaintext(&inner)?;
    keys.seq += 1;
    Ok((ct, content.to_vec()))
}

// ===========================================================================
// CertificateVerify signed content (§4.4.3) — shared with the loopback server
// ===========================================================================

/// §4.4.3, verbatim: "The context string for the server signature is
/// \"TLS 1.3, server CertificateVerify\"".
pub const SERVER_CERTIFICATE_VERIFY_CONTEXT: &str = "TLS 1.3, server CertificateVerify";

/// §4.4.3, verbatim: "and for a client signature it is \"TLS 1.3, client
/// CertificateVerify\"".
pub const CLIENT_CERTIFICATE_VERIFY_CONTEXT: &str = "TLS 1.3, client CertificateVerify";

/// PSS salt length for rsa_pss_rsae_sha256: the TLS de-facto convention
/// sLen = hLen = 32 (RFC 8446 does not pin sLen; OpenSSL's default is hLen).
/// Both loopback peers use 32; the verifier is configured to match the
/// signer, per `holo_crypto::rsa::verify_pss_sha256`'s contract.
pub const PSS_SALT_LEN: usize = 32;

/// The §4.4.3 signed content (module docs carry the verbatim RFC list):
/// `64 × 0x20 || context string || 0x00 || content_to_be_signed`.
pub fn certificate_verify_signed_blob(context: &str, transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = vec![0x20u8; 64];
    m.extend_from_slice(context.as_bytes());
    m.push(0x00);
    m.extend_from_slice(transcript_hash);
    m
}

/// The Handshake Secret itself (the §7.1 extract output) — needed for the
/// Master Secret.  `schedule::handshake_secrets` derives the two traffic
/// secrets but not this value, so the extract's salt is rebuilt from the
/// schedule module's own published helpers:
/// `salt = Derive-Secret(Early Secret, "derived", Transcript-Hash(""))`
/// (`schedule::early_secret` + `schedule::derived_secret` +
/// `schedule::TRANSCRIPT_HASH_EMPTY`), then `HS = HMAC(salt, dh)` — the
/// §7.1 diagram line "(EC)DHE -> HKDF-Extract = Handshake Secret".  The
/// all-zero-DH guard already ran inside `schedule::handshake_secrets` (§7.4.1)
/// before this function is called.
pub fn handshake_secret_from_dh(dh: &[u8]) -> [u8; 32] {
    let salt = schedule::derived_secret(&schedule::early_secret(), &schedule::TRANSCRIPT_HASH_EMPTY);
    hmac_sha256(&salt, dh)
}

// ===========================================================================
// RSA public-key extraction from the server certificate (the one thing the
// spki module deliberately does NOT do — pinning never needed the key)
// ===========================================================================

/// OID 1.2.840.113549.1.1.1 (rsaEncryption) — the SPKI algorithm OID must
/// name an RSA key for the CertificateVerify schemes this client verifies.
/// DER: 06 09 2a 86 48 86 f7 0d 01 01 01.
const RSA_ENCRYPTION_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

enum CertKeyError {
    NotRsa,
    Malformed(&'static str),
}

/// Cursor-based minimal DER walker (definite lengths incl. multi-byte) —
/// the same technique as the spki module's walker, scoped to what
/// CertificateVerify verification needs: the RSA (n, e) inside the
/// SubjectPublicKeyInfo of the FIRST certificate in certificate_list.
struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Der { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn tlv(&mut self) -> Result<(u8, &'a [u8]), &'static str> {
        if self.pos + 2 > self.buf.len() {
            return Err("truncated TLV header");
        }
        let tag = self.buf[self.pos];
        self.pos += 1;
        let l0 = self.buf[self.pos];
        self.pos += 1;
        let len = if l0 & 0x80 == 0 {
            l0 as usize
        } else {
            let n = (l0 & 0x7f) as usize;
            if n == 0 || n > 4 || self.pos + n > self.buf.len() {
                return Err("unsupported or truncated DER length");
            }
            let mut v = 0usize;
            for i in 0..n {
                v = (v << 8) | self.buf[self.pos + i] as usize;
            }
            self.pos += n;
            v
        };
        if self.pos + len > self.buf.len() {
            return Err("TLV content runs past the buffer");
        }
        let content = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, content))
    }

    fn expect(&mut self, want: u8) -> Result<(u8, &'a [u8]), &'static str> {
        let (tag, content) = self.tlv()?;
        if tag != want {
            return Err("unexpected DER tag");
        }
        Ok((tag, content))
    }
}

/// Extract the RSA modulus/exponent (big-endian, sign-byte stripped) from
/// the certificate's SubjectPublicKeyInfo:
/// `Certificate ::= SEQ { tbsCertificate, sigAlg, sigValue }`;
/// `TBSCertificate ::= [0]? serial, sig, issuer, validity, subject, SPKI, ...`;
/// `SPKI ::= SEQ { AlgorithmIdentifier(rsaEncryption), BIT STRING }`;
/// `RSAPublicKey ::= SEQ { n INTEGER, e INTEGER }` (RFC 8017 §3.1).
fn rsa_public_key_from_cert(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CertKeyError> {
    let mut top = Der::new(cert_der);
    let (tag, cert) = top.tlv().map_err(CertKeyError::Malformed)?;
    if tag != 0x30 {
        return Err(CertKeyError::Malformed("outer SEQUENCE expected"));
    }
    if top.remaining() != 0 {
        return Err(CertKeyError::Malformed("trailing bytes after Certificate"));
    }
    let mut cur = Der::new(cert);
    let (t, tbs) = cur.tlv().map_err(CertKeyError::Malformed)?;
    if t != 0x30 {
        return Err(CertKeyError::Malformed("tbsCertificate expected"));
    }
    cur.expect(0x30).map_err(CertKeyError::Malformed)?; // signatureAlgorithm
    let (t, sig) = cur.expect(0x03).map_err(CertKeyError::Malformed)?; // signatureValue BIT STRING
    if sig.is_empty() || sig[0] != 0 {
        return Err(CertKeyError::Malformed("signature BIT STRING unused bits"));
    }
    if cur.remaining() != 0 {
        return Err(CertKeyError::Malformed("trailing bytes after signatureValue"));
    }
    let _ = t;

    let mut tb = Der::new(tbs);
    if tb.peek() == Some(0xa0) {
        tb.tlv().map_err(CertKeyError::Malformed)?; // [0] EXPLICIT version
    }
    tb.expect(0x02).map_err(CertKeyError::Malformed)?; // serialNumber
    tb.expect(0x30).map_err(CertKeyError::Malformed)?; // signature
    tb.expect(0x30).map_err(CertKeyError::Malformed)?; // issuer
    tb.expect(0x30).map_err(CertKeyError::Malformed)?; // validity
    tb.expect(0x30).map_err(CertKeyError::Malformed)?; // subject
    let (_t, spki_der) = tb.expect(0x30).map_err(CertKeyError::Malformed)?; // subjectPublicKeyInfo

    let mut sp = Der::new(spki_der);
    let (_t, alg) = sp.expect(0x30).map_err(CertKeyError::Malformed)?;
    let mut al = Der::new(alg);
    let (_t, oid) = al.expect(0x06).map_err(CertKeyError::Malformed)?;
    if oid != RSA_ENCRYPTION_OID {
        return Err(CertKeyError::NotRsa);
    }
    let (_t, bits) = sp.expect(0x03).map_err(CertKeyError::Malformed)?; // subjectPublicKey
    if bits.is_empty() || bits[0] != 0 {
        return Err(CertKeyError::Malformed("SPKI BIT STRING unused bits"));
    }
    let mut rp = Der::new(&bits[1..]); // RSAPublicKey DER
    let (_t, seq) = rp.expect(0x30).map_err(CertKeyError::Malformed)?;
    let mut s = Der::new(seq);
    let (_t, n_int) = s.expect(0x02).map_err(CertKeyError::Malformed)?;
    let (_t, e_int) = s.expect(0x02).map_err(CertKeyError::Malformed)?;
    if s.remaining() != 0 {
        return Err(CertKeyError::Malformed("trailing bytes in RSAPublicKey"));
    }
    // INTEGER: a leading 0x00 octet is the optional positive-sign byte
    // (DER, X.690 §8.3.3) — strip exactly one so n has its natural k octets
    // (the verifier requires sig.len() == n.len()).
    let strip = |v: &[u8]| -> Vec<u8> {
        if v.len() > 1 && v[0] == 0 {
            v[1..].to_vec()
        } else {
            v.to_vec()
        }
    };
    Ok((strip(n_int), strip(e_int)))
}

// ===========================================================================
// ClientHello flight (§4.1.2) — the codec's builder assembles the message
// ===========================================================================

/// The built ClientHello flight: the full TLSPlaintext record bytes
/// (`record`), the raw handshake message (`client_hello`, the transcript
/// unit), and the ephemeral x25519 public key that went into key_share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloFlight {
    pub record: Vec<u8>,
    pub client_hello: Vec<u8>,
    pub x25519_public: [u8; 32],
}

/// Client configuration: the SPKI pin (SHA-256 over the full
/// SubjectPublicKeyInfo DER — the HoloNet pin convention documented in the
/// spki module) and the hostname to match against the certificate SANs.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub pinned_spki_sha256: [u8; 32],
    pub hostname: String,
}

impl ClientConfig {
    pub fn new(pinned_spki_sha256: [u8; 32], hostname: &str) -> Self {
        ClientConfig {
            pinned_spki_sha256,
            hostname: hostname.to_string(),
        }
    }
}

// ===========================================================================
// Client — the handshake entry point
// ===========================================================================

/// TLS 1.3 client entry point.
pub struct Client;

/// One inbound item of the server flight.
enum FlightMsg {
    Handshake(HandshakeFrame),
    Alert { level: u8, description: u8 },
}

/// Internal handshake state (one connection's flight exchange).
struct Hs<'a> {
    stream: Option<TcpStream>,
    cfg: &'a ClientConfig,
    ent: &'a mut dyn Entropy,
    /// §4.1.2 compatibility mode: the 32-byte (zero) legacy_session_id the
    /// client sends and the server MUST echo ("need not be random", §4.1.2
    /// lines 1596-1602).
    session_id: Vec<u8>,
    offered: Vec<u16>,
    /// Transcript units: raw handshake messages (headers included, record
    /// headers excluded — §4.4.1).
    transcript: Vec<Vec<u8>>,
    assembler: HandshakeAssembler,
    pending: VecDeque<HandshakeFrame>,
    aead: Option<AeadAlg>,
    wkeys: Option<WriteKeys>,
    rkeys: Option<ReadKeys>,
}

impl<'a> Hs<'a> {
    fn new(stream: TcpStream, cfg: &'a ClientConfig, ent: &'a mut dyn Entropy) -> Self {
        Hs {
            stream: Some(stream),
            cfg,
            ent,
            session_id: handshake::compat_mode_session_id().to_vec(),
            offered: vec![
                cipher_suite::TLS_AES_128_GCM_SHA256,
                cipher_suite::TLS_AES_256_GCM_SHA384,
                cipher_suite::TLS_CHACHA20_POLY1305_SHA256,
            ],
            transcript: Vec::new(),
            assembler: HandshakeAssembler::new(),
            pending: VecDeque::new(),
            aead: None,
            wkeys: None,
            rkeys: None,
        }
    }

    fn io(&mut self) -> &mut TcpStream {
        self.stream.as_mut().expect("stream lives until ClientConn")
    }

    fn rand32(&mut self) -> Result<[u8; 32], ClientError> {
        let mut b = [0u8; 32];
        self.ent.fill32(&mut b).map_err(ClientError::Entropy)?;
        Ok(b)
    }

    fn th(&self) -> [u8; 32] {
        let refs: Vec<&[u8]> = self.transcript.iter().map(|v| v.as_slice()).collect();
        transcript::transcript_hash(&refs)
    }

    fn send_plaintext(&mut self, fragment: &[u8], version: u16) -> Result<(), ClientError> {
        let rec = record::TlsPlaintext::new(ContentType::Handshake, version, fragment.to_vec())?;
        self.io()
            .write_all(&rec.encode())
            .map_err(ClientError::Io)?;
        self.io().flush().map_err(ClientError::Io)
    }

    /// Read one raw record from the wire (§5.1/§5.2 bounds enforced).
    fn read_wire_record(&mut self) -> Result<([u8; 5], Vec<u8>), ClientError> {
        let mut hdr = [0u8; 5];
        self.io().read_exact(&mut hdr).map_err(ClientError::Io)?;
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        match hdr[0] {
            23 => {
                // TLSCiphertext: opaque_type MUST be 23, length ≤ 2^14+256
                // (§5.2, record_overflow otherwise).
                record::decode_ciphertext_header(&hdr)?;
            }
            20 | 21 | 22 => {
                ContentType::from_u8(hdr[0])?;
                if len > record::MAX_PLAINTEXT_FRAGMENT {
                    return Err(CodecError::RecordFragmentTooLong {
                        got: len,
                        max: record::MAX_PLAINTEXT_FRAGMENT,
                    }
                    .into());
                }
            }
            other => return Err(CodecError::RecordUnknownContentType(other).into()),
        }
        let mut payload = vec![0u8; len];
        self.io().read_exact(&mut payload).map_err(ClientError::Io)?;
        Ok((hdr, payload))
    }

    /// Pull the next flight message (handshake frame or alert), transparently
    /// skipping middlebox compatibility change_cipher_spec records
    /// (Appendix D.4: a CCS carrying exactly the single byte 0x01 MAY appear).
    fn next_flight_msg(&mut self) -> Result<FlightMsg, ClientError> {
        loop {
            if let Some(f) = self.pending.pop_front() {
                return Ok(FlightMsg::Handshake(f));
            }
            let (hdr, payload) = self.read_wire_record()?;
            match hdr[0] {
                20 => {
                    if payload != [0x01] {
                        return Err(ClientError::MalformedChangeCipherSpec);
                    }
                }
                21 => {
                    if payload.len() != 2 {
                        return Err(CodecError::AlertTruncated { got: payload.len() }.into());
                    }
                    let _ = AlertLevel::from_u8(payload[0])?;
                    return Ok(FlightMsg::Alert {
                        level: payload[0],
                        description: payload[1],
                    });
                }
                22 => {
                    if self.rkeys.is_some() {
                        // After the ServerHello everything MUST be protected.
                        return Err(ClientError::UnexpectedMessage {
                            expected: "protected records (TLSCiphertext) after the ServerHello",
                            got: 22,
                        });
                    }
                    self.assemble(&payload)?;
                }
                23 => {
                    if let (Some(alg), Some(_)) = (self.aead, self.rkeys.as_ref()) {
                        // §5.2 open with the server handshake traffic keys.
                        let mut keys = self.rkeys.clone().expect("checked above");
                        let opened = open_record(alg, &mut keys, &hdr, &payload);
                        if let Ok((_, _)) = &opened {
                            self.rkeys = Some(keys);
                        }
                        let (ct, content) = opened?;
                        match ct {
                            ContentType::Handshake => self.assemble(&content)?,
                            ContentType::Alert => {
                                if content.len() != 2 {
                                    return Err(CodecError::AlertTruncated {
                                        got: content.len(),
                                    }
                                    .into());
                                }
                                let _ = AlertLevel::from_u8(content[0])?;
                                return Ok(FlightMsg::Alert {
                                    level: content[0],
                                    description: content[1],
                                });
                            }
                            ContentType::ApplicationData => {
                                return Err(ClientError::UnexpectedMessage {
                                    expected:
                                        "handshake messages before the handshake completes",
                                    got: 23,
                                });
                            }
                            ContentType::ChangeCipherSpec => {
                                return Err(ClientError::MalformedChangeCipherSpec);
                            }
                        }
                    } else {
                        return Err(ClientError::UnexpectedMessage {
                            expected: "plaintext ServerHello record",
                            got: 23,
                        });
                    }
                }
                _ => unreachable!("read_wire_record validated the type byte"),
            }
            if self.pending.is_empty() {
                continue;
            }
            return Ok(FlightMsg::Handshake(
                self.pending.pop_front().expect("checked non-empty"),
            ));
        }
    }

    /// Feed one record's fragment into the flight assembler (batch-1
    /// `HandshakeAssembler` — handles coalesced messages AND messages split
    /// across records, §5.1); completed frames land in `self.pending`.
    fn assemble(&mut self, fragment: &[u8]) -> Result<(), ClientError> {
        let frames = self.assembler.push_fragment(fragment)?;
        for f in frames {
            self.pending.push_back(f);
        }
        Ok(())
    }

    fn read_server_hello(&mut self) -> Result<(handshake::ServerHello, Vec<u8>), ClientError> {
        loop {
            match self.next_flight_msg()? {
                FlightMsg::Handshake(f) => {
                    if f.msg_type() != 2 {
                        return Err(self.classify(&f, "ServerHello"));
                    }
                    let sh = handshake::ServerHello::decode(&f.bytes)?;
                    if !self.pending.is_empty() {
                        // The ServerHello flight is a single message; anything
                        // coalesced behind it arrives before keys exist.
                        return Err(ClientError::UnexpectedMessage {
                            expected: "the ServerHello alone in its flight",
                            got: self.pending.front().expect("checked").msg_type(),
                        });
                    }
                    return Ok((sh, f.bytes));
                }
                FlightMsg::Alert { level, description } => {
                    return Err(ClientError::ServerAlert { level, description });
                }
            }
        }
    }

    /// Map an unexpected frame to the right distinct error.
    fn classify(&self, frame: &HandshakeFrame, expected: &'static str) -> ClientError {
        let t = frame.msg_type();
        match t {
            4 | 5 | 13 | 24 => ClientError::UnsupportedHandshake(t),
            _ => ClientError::UnexpectedMessage { expected, got: t },
        }
    }

    fn expect_handshake(&mut self) -> Result<HandshakeFrame, ClientError> {
        match self.next_flight_msg()? {
            FlightMsg::Handshake(f) => Ok(f),
            FlightMsg::Alert { level, description } => {
                Err(ClientError::ServerAlert { level, description })
            }
        }
    }

    /// Best-effort fatal alert on abort (§6: alerts during the handshake
    /// before keys exist are sent as plaintext records).
    fn best_effort_alert(&mut self, alert: Option<AlertDescription>) {
        let Some(desc) = alert else { return };
        let payload = vec![AlertLevel::Fatal.as_u8(), desc.as_u8()];
        let wire = match (self.aead, self.wkeys.as_mut()) {
            (Some(alg), Some(keys)) => seal_record(alg, keys, ContentType::Alert, &payload),
            _ => record::TlsPlaintext::new(ContentType::Alert, LEGACY_VERSION_OTHER, payload)
                .map(|r| r.encode())
                .map_err(ClientError::from),
        };
        if let Ok(wire) = wire {
            if let Some(s) = self.stream.as_mut() {
                let _ = s.write_all(&wire);
                let _ = s.flush();
            }
        }
    }

    fn run(&mut self) -> Result<ClientConn, ClientError> {
        // ---------------- CH1 (§4.1.2) ----------------
        let random1 = self.rand32()?;
        let priv1 = self.rand32()?;
        let pub1 = x25519::public_from_private(&priv1);
        let flight1 =
            Client::build_client_hello_flight(&self.cfg.hostname, &random1, &pub1, None, false)?;
        // §5.1 lines 4413-4417: an initial ClientHello record "SHOULD have
        // version 0x0301".
        self.send_plaintext(&flight1.client_hello, LEGACY_VERSION_INITIAL_CLIENT_HELLO)?;
        let ch1_raw = flight1.client_hello.clone();
        let mut active_priv = priv1;

        // ---------------- ServerHello (or HRR) ----------------
        let (mut sh, mut sh_raw) = self.read_server_hello()?;

        if sh.is_hello_retry_request() {
            // §4.1.4.  validate checks: supported_versions MUST select
            // 0x0304; extension set ⊆ {cookie, supported_versions, key_share}.
            handshake::validate_hello_retry_request(&sh)?;
            let mut fresh_share = false;
            if let Some(ext) = sh
                .extensions
                .iter()
                .find(|e| e.ext_type == ext_type::KEY_SHARE)
            {
                let selected = handshake::parse_key_share_hrr(&ext.data)?;
                if selected != named_group::X25519 {
                    return Err(ClientError::HrrSelectedGroupUnsupported(selected));
                }
                fresh_share = true;
            }
            let cookie = match sh
                .extensions
                .iter()
                .find(|e| e.ext_type == ext_type::COOKIE)
            {
                Some(ext) => Some(handshake::parse_cookie(&ext.data)?),
                None => None,
            };

            // §4.4.1 (transcript module): ClientHello1 is replaced by the
            // synthetic message_hash message.
            let th1 = sha256::digest(&ch1_raw);
            let synthetic = transcript::message_hash_synthetic(&th1);
            self.transcript = vec![synthetic, sh_raw.clone()];

            // A FRESH key share for the re-negotiated group (§4.1.4) and a
            // fresh ClientHello random; the cookie (if the HRR carried one)
            // MUST be echoed (§4.1.4).
            if fresh_share {
                active_priv = self.rand32()?;
            }
            let pub2 = x25519::public_from_private(&active_priv);
            let random2 = self.rand32()?;
            let flight2 = Client::build_client_hello_flight(
                &self.cfg.hostname,
                &random2,
                &pub2,
                cookie.as_deref(),
                true,
            )?;
            // §5.1 lines 4413-4417: a SECOND ClientHello record MUST have
            // version 0x0303.
            self.send_plaintext(&flight2.client_hello, LEGACY_VERSION_OTHER)?;
            self.transcript.push(flight2.client_hello.clone());

            // The second ServerHello MUST NOT be another HRR (§4.1.4).
            let (sh2, sh2_raw) = self.read_server_hello()?;
            if sh2.is_hello_retry_request() {
                return Err(ClientError::MultipleHelloRetryRequests);
            }
            sh = sh2;
            sh_raw = sh2_raw;
        } else {
            self.transcript = vec![ch1_raw];
        }

        // ---------------- validate SH (§4.1.3 + §4.2.1) ----------------
        // Session-id echo, compression, offered suite, the ServerHello
        // extension subset and TLS 1.3 selection (with the §4.1.3 DOWNGRD
        // sentinel logic) all live in the batch-1 codec's validate().
        sh.validate(&self.offered, &self.session_id)?;
        self.transcript.push(sh_raw);
        let suite = sh.cipher_suite;
        let aead = AeadAlg::from_suite(suite)?;

        // ---------------- §7.1: handshake secrets ----------------
        let share_ext = sh
            .extensions
            .iter()
            .find(|e| e.ext_type == ext_type::KEY_SHARE)
            .ok_or(ClientError::UnexpectedMessage {
                expected: "key_share in ServerHello",
                got: 2,
            })?;
        let share = handshake::parse_key_share_sh(&share_ext.data)?;
        if share.group != named_group::X25519 {
            return Err(ClientError::ServerKeyShareGroupUnsupported(share.group));
        }
        if share.key_exchange.len() != 32 {
            return Err(ClientError::BadServerKeyShare(share.key_exchange.len()));
        }
        let mut server_share = [0u8; 32];
        server_share.copy_from_slice(&share.key_exchange);
        let shared = x25519::x25519(&active_priv, &server_share)
            .ok_or(ClientError::SharedSecretNotContributory)?;

        let th_ch_sh = self.th();
        // §7.4.1's all-zero guard runs inside schedule::handshake_secrets.
        let (c_hs, s_hs) =
            schedule::handshake_secrets(&shared, &th_ch_sh).map_err(ClientError::KeySchedule)?;
        let hs_secret = handshake_secret_from_dh(&shared);
        let mut c_write = WriteKeys::derive(aead, &c_hs);
        let s_read = ReadKeys::derive(aead, &s_hs);
        self.aead = Some(aead);
        self.wkeys = Some(c_write.clone());
        self.rkeys = Some(s_read);

        // ---------------- the protected flight ----------------
        // EncryptedExtensions (§4.3.1) — extensions are accepted and ignored
        // (all of this profile's EE extensions are optional).
        let ee_frame = self.expect_handshake()?;
        if ee_frame.msg_type() != 8 {
            return Err(self.classify(&ee_frame, "EncryptedExtensions"));
        }
        let _ee = handshake::EncryptedExtensions::decode(&ee_frame.bytes)?;
        self.transcript.push(ee_frame.bytes.clone());

        // Certificate (§4.4.2) + server identity check (THE S2 point).
        let cert_frame = self.expect_handshake()?;
        if cert_frame.msg_type() != 11 {
            return Err(self.classify(&cert_frame, "Certificate"));
        }
        let cert = handshake::CertificateMsg::decode(&cert_frame.bytes)?;
        if !cert.certificate_request_context.is_empty() {
            return Err(ClientError::CertificateRequestContextUnexpected);
        }
        if cert.entries.is_empty() {
            return Err(ClientError::CertificateEmpty);
        }
        let der = &cert.entries[0].cert_data;
        // SPKI pin — the trust anchor (batch-1 charter; no chain validation).
        spki::verify_spki_pin(der, &self.cfg.pinned_spki_sha256)
            .map_err(ClientError::PinCheckFailed)?;
        // Hostname identity (RFC 6125 §6.4 via the spki module).
        match spki::matches_hostname(der, &self.cfg.hostname) {
            Ok(true) => {}
            Ok(false) => {
                return Err(ClientError::HostnameMismatch {
                    hostname: self.cfg.hostname.clone(),
                })
            }
            Err(e) => return Err(ClientError::IdentityCheckFailed(e)),
        }
        // The verification key for CertificateVerify comes from the
        // certificate itself (§4.4.3).
        let (n, e) = match rsa_public_key_from_cert(der) {
            Ok(kv) => kv,
            Err(CertKeyError::NotRsa) => return Err(ClientError::CertNotRsa),
            Err(CertKeyError::Malformed(m)) => {
                return Err(ClientError::CertKeyExtract(m.to_string()))
            }
        };
        self.transcript.push(cert_frame.bytes.clone());
        let th_to_cert = self.th();

        // CertificateVerify (§4.4.3).
        let cv_frame = self.expect_handshake()?;
        if cv_frame.msg_type() != 15 {
            return Err(self.classify(&cv_frame, "CertificateVerify"));
        }
        let cv = handshake::CertificateVerify::decode(&cv_frame.bytes)?;
        let blob = certificate_verify_signed_blob(SERVER_CERTIFICATE_VERIFY_CONTEXT, &th_to_cert);
        let md = sha256::digest(&blob);
        let verification = match cv.algorithm {
            signature_scheme::RSA_PSS_RSAE_SHA256 => {
                rsa::verify_pss_sha256(&n, &e, PSS_SALT_LEN, &md, &cv.signature)
            }
            signature_scheme::RSA_PKCS1_SHA256 => {
                rsa::verify_pkcs1_v1_5_sha256(&n, &e, &md, &cv.signature)
            }
            other => return Err(ClientError::UnsupportedSignatureAlgorithm(other)),
        };
        verification.map_err(ClientError::CertificateVerifyInvalid)?;
        self.transcript.push(cv_frame.bytes.clone());

        // server Finished (§4.4.4).
        let fin_frame = self.expect_handshake()?;
        if fin_frame.msg_type() != 20 {
            return Err(self.classify(&fin_frame, "server Finished"));
        }
        let fin = handshake::Finished::decode(&fin_frame.bytes)?;
        let expect = schedule::finished_verify_data(
            &schedule::finished_key(&s_hs),
            &self.th(), // Transcript-Hash(CH..CertificateVerify)
        );
        if !ct_eq(&fin.verify_data, &expect) {
            return Err(ClientError::ServerFinishedMismatch);
        }
        self.transcript.push(fin_frame.bytes.clone());

        // ---------------- client Finished (§4.4.4) ----------------
        let th_post_server_finished = self.th(); // CH..server Finished
        let fk = schedule::finished_key(&c_hs);
        let verify_data = schedule::finished_verify_data(&fk, &th_post_server_finished);
        let fin_msg = handshake::Finished {
            verify_data: verify_data.to_vec(),
        }
        .encode();
        let wire = seal_record(aead, &mut c_write, ContentType::Handshake, &fin_msg)?;
        self.io().write_all(&wire).map_err(ClientError::Io)?;
        self.io().flush().map_err(ClientError::Io)?;

        // ---------------- application secrets (§7.1) ----------------
        // master_secret's transcript_hash argument is TRANSCRIPT_HASH_EMPTY
        // (the schedule module's documented convention for the salt
        // derivation); the application traffic secrets are derived over
        // ClientHello..server Finished — i.e. WITHOUT the client Finished.
        let ms = schedule::master_secret(&hs_secret, &schedule::TRANSCRIPT_HASH_EMPTY);
        let (c_ap, s_ap) = schedule::application_secrets(&ms, &th_post_server_finished);

        Ok(ClientConn {
            stream: self.stream.take().expect("stream lives until ClientConn"),
            suite,
            aead,
            wkeys: WriteKeys::derive(aead, &c_ap), // §5.3: seq resets with keys
            rkeys: ReadKeys::derive(aead, &s_ap),
            rx_buf: Vec::new(),
            eof: false,
        })
    }
}

impl Client {
    /// Run the full TLS 1.3 handshake over `stream` using OS entropy
    /// (`holo_util::rand::os_fill` — fail-closed).
    pub fn connect(stream: TcpStream, cfg: &ClientConfig) -> Result<ClientConn, ClientError> {
        Self::connect_with_entropy(stream, cfg, &mut OsEntropy)
    }

    /// Same handshake with an INJECTED entropy source (deterministic tests).
    pub fn connect_with_entropy(
        stream: TcpStream,
        cfg: &ClientConfig,
        entropy: &mut dyn Entropy,
    ) -> Result<ClientConn, ClientError> {
        // Tests must never hang: a stuck peer surfaces as a 10 s IO timeout.
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        let mut hs = Hs::new(stream, cfg, entropy);
        let res = hs.run();
        if let Err(e) = &res {
            hs.best_effort_alert(e.alert());
        }
        res
    }

    /// Build the ClientHello FLIGHT (record + raw message) — §4.1.2 via the
    /// batch-1 codec's builder (`build_client_hello` + the typed extension
    /// encoders).
    ///
    /// Profile (all values traced to RFC 8446):
    /// - legacy_version 0x0303 (§4.1.2 line 1583), record version 0x0301 for
    ///   the INITIAL hello / 0x0303 for the post-HRR second hello (§5.1
    ///   lines 4413-4417);
    /// - legacy_session_id = 32 zero bytes (compatibility mode, §4.1.2
    ///   lines 1596-1602: "need not be random");
    /// - cipher_suites [0x1301, 0x1302, 0x1303] (§B.4);
    /// - supported_groups [x25519] (§4.2.7) + matching key_share (§4.2.8);
    /// - supported_versions [0x0304] (§4.2.1);
    /// - signature_algorithms [rsa_pss_rsae_sha256(0x0804),
    ///   rsa_pkcs1_sha256(0x0401)] (§B.2 values — see the module docs for
    ///   why 0x0805/0x0806 are deliberately NOT advertised);
    /// - server_name only for DNS hostnames (RFC 6066: literal IPs are not
    ///   sent as SNI);
    /// - the HRR cookie echoed verbatim on the second hello (§4.1.4).
    pub fn build_client_hello_flight(
        hostname: &str,
        random: &[u8; 32],
        x25519_public: &[u8; 32],
        cookie: Option<&[u8]>,
        second_client_hello: bool,
    ) -> Result<ClientHelloFlight, ClientError> {
        let mut extensions = Vec::new();
        // RFC 6066 (via §4.2 table): the SNI host_name is a DNS name; an IP
        // literal is NOT sent as SNI.
        if hostname.parse::<std::net::IpAddr>().is_err() {
            extensions.push(handshake::encode_server_name(hostname.as_bytes())?);
        }
        extensions.push(handshake::encode_supported_groups(&[named_group::X25519])?);
        extensions.push(handshake::encode_key_share_ch(&[handshake::KeyShareEntry {
            group: named_group::X25519,
            key_exchange: x25519_public.to_vec(),
        }])?);
        extensions.push(handshake::encode_supported_versions_ch(&[handshake::VERSION_TLS13])?);
        extensions.push(handshake::encode_signature_algorithms(&[
            signature_scheme::RSA_PSS_RSAE_SHA256,
            signature_scheme::RSA_PKCS1_SHA256,
        ])?);
        if let Some(c) = cookie {
            extensions.push(handshake::encode_cookie(c)?);
        }
        let session_id = handshake::compat_mode_session_id();
        let raw = handshake::build_client_hello(&ClientHelloParams {
            random: *random,
            legacy_session_id: &session_id,
            cipher_suites: &[
                cipher_suite::TLS_AES_128_GCM_SHA256,
                cipher_suite::TLS_AES_256_GCM_SHA384,
                cipher_suite::TLS_CHACHA20_POLY1305_SHA256,
            ],
            legacy_compression_methods: &[0],
            extensions: &extensions,
        })?;
        let record_version = if second_client_hello {
            LEGACY_VERSION_OTHER
        } else {
            LEGACY_VERSION_INITIAL_CLIENT_HELLO
        };
        let rec = record::TlsPlaintext::new(ContentType::Handshake, record_version, raw.clone())?;
        Ok(ClientHelloFlight {
            record: rec.encode(),
            client_hello: raw,
            x25519_public: *x25519_public,
        })
    }
}

// ===========================================================================
// ClientConn — the established application-data connection
// ===========================================================================

/// An established TLS 1.3 connection: application-data read/write over the
/// same `TcpStream`, protected records with the negotiated cipher suite.
#[derive(Debug)]
pub struct ClientConn {
    stream: TcpStream,
    suite: u16,
    aead: AeadAlg,
    wkeys: WriteKeys,
    rkeys: ReadKeys,
    /// Leftover plaintext from a partially consumed app-data record.
    rx_buf: Vec<u8>,
    eof: bool,
}

impl ClientConn {
    /// The negotiated cipher suite (0x1301 / 0x1302 / 0x1303).
    pub fn cipher_suite(&self) -> u16 {
        self.suite
    }

    /// Send application data (one protected record per call, fragmented at
    /// the §5.4 TLSInnerPlaintext bound; call again until all bytes are
    /// sent, mirroring `std::io::Write::write` semantics).  Returns the
    /// number of plaintext bytes sent.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, ClientError> {
        if data.is_empty() {
            // Zero-length ApplicationData is legal cover traffic (§5.1 line
            // 4360) but an empty write is a no-op here.
            return Ok(0);
        }
        let take = data.len().min(MAX_APP_CONTENT);
        let wire = seal_record(
            self.aead,
            &mut self.wkeys,
            ContentType::ApplicationData,
            &data[..take],
        )?;
        self.stream.write_all(&wire).map_err(ClientError::Io)?;
        self.stream.flush().map_err(ClientError::Io)?;
        Ok(take)
    }

    /// Receive application data into `buf`.  Returns 0 on EOF (peer
    /// close_notify or clean TCP close).  Each call serves buffered plaintext
    /// first, then opens ONE protected record.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ClientError> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.rx_buf.is_empty() {
                let n = buf.len().min(self.rx_buf.len());
                buf[..n].copy_from_slice(&self.rx_buf[..n]);
                self.rx_buf.drain(..n);
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            let res = self.next_app_record();
            match res {
                Ok(()) => continue,
                Err(e) => {
                    // EOF is a clean close; everything else aborts with the
                    // mapped fatal alert where sensible (§6).
                    if e.is_eof() {
                        self.eof = true;
                        return Ok(0);
                    }
                    if !matches!(e, ClientError::ServerAlert { .. }) {
                        self.fail_alert(&e);
                    }
                    return Err(e);
                }
            }
        }
    }

    fn next_app_record(&mut self) -> Result<(), ClientError> {
        let mut hdr = [0u8; 5];
        self.stream.read_exact(&mut hdr).map_err(ClientError::Io)?;
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        match hdr[0] {
            20 => {
                let mut payload = vec![0u8; len];
                self.stream.read_exact(&mut payload).map_err(ClientError::Io)?;
                if payload != [0x01] {
                    return Err(ClientError::MalformedChangeCipherSpec);
                }
            }
            21 => {
                let mut payload = vec![0u8; len];
                self.stream.read_exact(&mut payload).map_err(ClientError::Io)?;
                if payload.len() == 2
                    && payload[0] == AlertLevel::Warning.as_u8()
                    && payload[1] == AlertDescription::CloseNotify.as_u8()
                {
                    self.eof = true;
                    return Ok(());
                }
                if payload.len() != 2 {
                    return Err(CodecError::AlertTruncated { got: payload.len() }.into());
                }
                let _ = AlertLevel::from_u8(payload[0])?;
                return Err(ClientError::ServerAlert {
                    level: payload[0],
                    description: payload[1],
                });
            }
            22 => {
                // A plaintext handshake record after the handshake —
                // protocol violation (everything after the ServerHello is
                // protected, §5.2); read the payload for stream sanity, then
                // abort with the right distinct error.
                let mut payload = vec![0u8; len];
                self.stream.read_exact(&mut payload).map_err(ClientError::Io)?;
                let t = payload.first().copied().unwrap_or(0);
                return Err(match t {
                    4 | 5 | 13 | 24 => ClientError::UnsupportedHandshake(t),
                    _ => ClientError::UnexpectedMessage {
                        expected: "protected application records",
                        got: 22,
                    },
                });
            }
            23 => {
                record::decode_ciphertext_header(&hdr)?;
                let mut payload = vec![0u8; len];
                self.stream.read_exact(&mut payload).map_err(ClientError::Io)?;
                let (ct, content) = open_record(self.aead, &mut self.rkeys, &hdr, &payload)?;
                match ct {
                    ContentType::ApplicationData => {
                        self.rx_buf = content;
                        return Ok(());
                    }
                    ContentType::Alert => {
                        if content.len() == 2
                            && content[0] == AlertLevel::Warning.as_u8()
                            && content[1] == AlertDescription::CloseNotify.as_u8()
                        {
                            self.eof = true;
                            return Ok(());
                        }
                        if content.len() != 2 {
                            return Err(CodecError::AlertTruncated { got: content.len() }.into());
                        }
                        let _ = AlertLevel::from_u8(content[0])?;
                        return Err(ClientError::ServerAlert {
                            level: content[0],
                            description: content[1],
                        });
                    }
                    ContentType::Handshake => {
                        // NewSessionTicket / KeyUpdate / client-auth after the
                        // handshake: out of scope by charter — distinct error.
                        let t = content.first().copied().unwrap_or(0);
                        return Err(match t {
                            4 | 5 | 13 | 24 => ClientError::UnsupportedHandshake(t),
                            _ => ClientError::UnexpectedMessage {
                                expected: "application data after the handshake",
                                got: t,
                            },
                        });
                    }
                    ContentType::ChangeCipherSpec => {
                        return Err(ClientError::MalformedChangeCipherSpec);
                    }
                }
            }
            other => return Err(CodecError::RecordUnknownContentType(other).into()),
        }
        Ok(())
    }

    /// Best-effort fatal alert for app-phase aborts (encrypted with the
    /// current application write keys — §6: alerts other than closures are
    /// fatal).
    fn fail_alert(&mut self, e: &ClientError) {
        let Some(desc) = e.alert() else { return };
        let payload = vec![AlertLevel::Fatal.as_u8(), desc.as_u8()];
        if let Ok(wire) = seal_record(self.aead, &mut self.wkeys, ContentType::Alert, &payload) {
            let _ = self.stream.write_all(&wire);
            let _ = self.stream.flush();
        }
    }

    /// Send a warning-level close_notify (§6.1: "Each party MUST send a
    /// 'close_notify' alert before closing its write side of the
    /// connection.") and half-close the write side.
    pub fn send_close_notify(&mut self) -> Result<(), ClientError> {
        let payload = vec![
            AlertLevel::Warning.as_u8(),
            AlertDescription::CloseNotify.as_u8(),
        ];
        let wire = seal_record(self.aead, &mut self.wkeys, ContentType::Alert, &payload)?;
        self.stream.write_all(&wire).map_err(ClientError::Io)?;
        self.stream.flush().map_err(ClientError::Io)?;
        self.stream.shutdown(Shutdown::Write).ok();
        Ok(())
    }
}

// ===========================================================================
// Tests — the S2 acceptance core (task 2-a): 13 named tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{LoopbackServer, ServerError, LOOPBACK_CERT_DER};
    use crate::spki;
    use std::net::SocketAddr;

    /// Deterministic test-material PRNG (SplitMix64 — the same reference
    /// generator family the holo-crypto test suite uses) that seeds the
    /// INJECTED entropy pools.  This is TEST material ONLY: production
    /// security material comes exclusively from OsEntropy / os_fill.
    struct TestPrng {
        state: u64,
    }
    impl TestPrng {
        fn new(seed: u64) -> Self {
            TestPrng { state: seed }
        }
        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn chunk(&mut self) -> [u8; 32] {
            let mut b = [0u8; 32];
            for out in b.chunks_mut(8) {
                out.copy_from_slice(&self.next_u64().to_le_bytes()[..out.len()]);
            }
            b
        }
    }

    fn correct_pin() -> [u8; 32] {
        spki::spki_pin_sha256(&LOOPBACK_CERT_DER).expect("fixture certificate parses")
    }

    fn cfg_for(hostname: &str) -> ClientConfig {
        ClientConfig::new(correct_pin(), hostname)
    }

    /// Spawn the loopback server on a thread; returns (addr, join handle).
    /// `seed = Some(s)` INJECTS deterministic server entropy; consumption
    /// order is pinned: cookie (HRR path) → server random → server x25519
    /// private → PSS salt (PSS path only).
    fn spawn(
        server: LoopbackServer,
        seed: Option<u64>,
    ) -> (
        SocketAddr,
        std::thread::JoinHandle<Result<(), ServerError>>,
    ) {
        let addr = server.local_addr().unwrap();
        let hrr = server.force_hrr;
        let pkcs1 = server.use_pkcs1;
        let h = std::thread::spawn(move || {
            let mut session = match seed {
                None => match server.serve_one() { Ok(s) => s, Err(e) => { eprintln!("SERVER-ERR: {e:?}"); return Err(e); } },
                Some(s) => {
                    let mut prng = TestPrng::new(s);
                    let mut chunks: Vec<Vec<u8>> = Vec::new();
                    if hrr {
                        chunks.push(prng.chunk().to_vec()); // HRR cookie
                    }
                    chunks.push(prng.chunk().to_vec()); // server random
                    chunks.push(prng.chunk().to_vec()); // server x25519 priv
                    if !pkcs1 {
                        chunks.push(prng.chunk().to_vec()); // PSS salt
                    }
                    let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
                    match server.serve_one_with_entropy(&mut InjectedEntropy::new(&refs)) { Ok(s) => s, Err(e) => { eprintln!("SERVER-ERR(seeded): {e:?}"); return Err(e); } }
                }
            };
            match session.echo_until_closed() {
                Ok(v) => Ok(v),
                Err(e) => { eprintln!("SERVER-ERR(echo): {e:?}"); Err(e) }
            }
        });
        (addr, h)
    }

    /// Connect the client; `seed = Some(s)` INJECTS deterministic client
    /// entropy; consumption order is pinned: CH1 random → CH1 x25519 priv →
    /// (HRR: CH2 random → CH2 x25519 priv).
    fn client_connect(
        addr: SocketAddr,
        cfg: &ClientConfig,
        seed: Option<u64>,
        hrr: bool,
    ) -> Result<ClientConn, ClientError> {
        let stream = std::net::TcpStream::connect(addr).expect("loopback connect");
        match seed {
            None => Client::connect(stream, cfg),
            Some(s) => {
                let mut prng = TestPrng::new(s);
                let mut chunks: Vec<Vec<u8>> = Vec::new();
                chunks.push(prng.chunk().to_vec()); // CH1 random
                chunks.push(prng.chunk().to_vec()); // CH1 x25519 priv
                if hrr {
                    chunks.push(prng.chunk().to_vec()); // CH2 random
                    chunks.push(prng.chunk().to_vec()); // CH2 x25519 priv
                }
                let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
                Client::connect_with_entropy(stream, cfg, &mut InjectedEntropy::new(&refs))
            }
        }
    }

    /// One deterministic echo roundtrip.
    fn echo_round(conn: &mut ClientConn, msg: &[u8]) {
        let sent = conn.write(msg).expect("app write");
        assert_eq!(sent, msg.len());
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        while got.len() < msg.len() {
            let n = conn.read(&mut buf).expect("app read");
            assert!(n > 0, "unexpected EOF mid-echo");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got, msg);
    }

    // ---- 1. the full handshake + 3 echo roundtrips (OS entropy) ----------

    #[test]
    fn e2e_full_handshake_and_echo_loopback() {
        let server = LoopbackServer::bind().unwrap();
        let (addr, join) = spawn(server, None);
        let mut conn = client_connect(addr, &cfg_for("localhost"), None, false)
            .expect("full handshake must succeed");
        assert_eq!(conn.cipher_suite(), 0x1301, "server default suite");
        echo_round(&mut conn, b"alpha");
        echo_round(&mut conn, b"beta-2");
        echo_round(&mut conn, b"gamma-3");
        conn.send_close_notify().expect("close_notify");
        join.join().unwrap().expect("server echo loop clean");
    }

    // ---- 2/3. suite negotiation (injected randomness) --------------------

    #[test]
    fn e2e_chacha20poly1305_suite_negotiated() {
        let mut server = LoopbackServer::bind().unwrap();
        server.suite = 0x1303;
        let (addr, join) = spawn(server, Some(0xC0FFEE_0002));
        let mut conn =
            client_connect(addr, &cfg_for("localhost"), Some(0xC0FFEE_0001), false)
                .expect("handshake");
        assert_eq!(conn.cipher_suite(), 0x1303);
        echo_round(&mut conn, b"chacha echo");
        conn.send_close_notify().unwrap();
        join.join().unwrap().expect("server clean");
    }

    #[test]
    fn e2e_aes256gcm_suite_negotiated() {
        let mut server = LoopbackServer::bind().unwrap();
        server.suite = 0x1302;
        let (addr, join) = spawn(server, Some(0xC0FFEE_0004));
        let mut conn =
            client_connect(addr, &cfg_for("localhost"), Some(0xC0FFEE_0003), false)
                .expect("handshake");
        assert_eq!(conn.cipher_suite(), 0x1302);
        echo_round(&mut conn, b"aes-256 echo");
        conn.send_close_notify().unwrap();
        join.join().unwrap().expect("server clean");
    }

    // ---- 4. HelloRetryRequest with a fresh key share ----------------------

    #[test]
    fn e2e_hrr_second_client_hello_with_new_key_share() {
        let mut server = LoopbackServer::bind().unwrap();
        server.force_hrr = true;
        let (addr, join) = spawn(server, Some(0xBEEF_0002));
        let mut conn = client_connect(addr, &cfg_for("localhost"), Some(0xBEEF_0001), true)
            .expect("handshake across the HRR round trip");
        assert_eq!(conn.cipher_suite(), 0x1301);
        echo_round(&mut conn, b"post-hrr echo");
        conn.send_close_notify().unwrap();
        join.join().unwrap().expect(
            "server clean — includes the cookie-echo check AND the fresh-key-share check",
        );
    }

    // ---- 5. corrupted server Finished → distinct abort --------------------

    #[test]
    fn e2e_transcript_mismatch_rejected() {
        let mut server = LoopbackServer::bind().unwrap();
        server.corrupt_finished = true;
        let (addr, join) = spawn(server, Some(0xD00D_0002));
        let err = client_connect(addr, &cfg_for("localhost"), Some(0xD00D_0001), false)
            .expect_err("corrupted server Finished MUST abort the handshake");
        let msg = format!("{err}");
        assert!(msg.contains("Finished"), "got: {msg}");
        assert!(msg.contains("decrypt_error"), "got: {msg}");
        join.join().ok(); // server side exits with its own distinct error
    }

    // ---- 6. SPKI pin mismatch → distinct abort ----------------------------

    #[test]
    fn e2e_pin_mismatch_rejected() {
        let server = LoopbackServer::bind().unwrap();
        let (addr, join) = spawn(server, None);
        let mut cfg = cfg_for("localhost");
        cfg.pinned_spki_sha256[0] ^= 0xFF; // a DIFFERENT pinned key
        let err = client_connect(addr, &cfg, None, false)
            .expect_err("pin mismatch MUST abort");
        let msg = format!("{err}");
        assert!(msg.contains("pin"), "got: {msg}");
        assert!(msg.contains("sha256 mismatch"), "got: {msg}");
        join.join().ok();
    }

    // ---- 7. hostname mismatch → distinct abort ----------------------------

    #[test]
    fn e2e_hostname_mismatch_rejected() {
        let server = LoopbackServer::bind().unwrap();
        let (addr, join) = spawn(server, None);
        let err = client_connect(addr, &cfg_for("evil.example"), None, false)
            .expect_err("hostname mismatch MUST abort");
        let msg = format!("{err}");
        assert!(msg.contains("evil.example"), "got: {msg}");
        assert!(msg.contains("does not match"), "got: {msg}");
        join.join().ok();
    }

    // ---- 8. TLS 1.2 downgrade (both §4.1.3 paths) -------------------------

    /// A raw-socket fake server that answers with a TLS-1.2 ServerHello:
    /// legacy_version 0x0303, no supported_versions extension, suite 0x1301
    /// (offered, so the downgrade check is reached), session id echoed.
    /// With `sentinel`, Random[24..32] carries the §4.1.3 DOWNGRD sentinel.
    fn fake_tls12_server(sentinel: bool) -> (SocketAddr, std::thread::JoinHandle<()>) {
        use crate::handshake::{ClientHello, ServerHello};
        use crate::record::{TlsPlaintext, LEGACY_VERSION_OTHER};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
            let mut hdr = [0u8; 5];
            s.read_exact(&mut hdr).unwrap();
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut frag = vec![0u8; len];
            s.read_exact(&mut frag).unwrap();
            let ch = ClientHello::decode(&frag).unwrap();
            let mut random = [0x11u8; 32];
            if sentinel {
                random[24..].copy_from_slice(&crate::handshake::DOWNGRD_SENTINEL_TLS12);
            } else {
                random[24..].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
            }
            let sh = ServerHello {
                legacy_version: 0x0303, // a TLS 1.2 server
                random,
                legacy_session_id_echo: ch.legacy_session_id.clone(),
                cipher_suite: 0x1301,
                legacy_compression_method: 0,
                extensions: vec![], // NO supported_versions → TLS ≤ 1.2 answer
            };
            let rec = TlsPlaintext::new(
                crate::record::ContentType::Handshake,
                LEGACY_VERSION_OTHER,
                sh.encode(),
            )
            .unwrap();
            s.write_all(&rec.encode()).unwrap();
            s.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        (addr, h)
    }

    #[test]
    fn e2e_downgrade_tls12_rejected() {
        // (a) a genuine TLS 1.3 server deliberately negotiating TLS 1.2
        //     sets the DOWNGRD sentinel → the sentinel-specific abort.
        let (addr, fake) = fake_tls12_server(true);
        let err = client_connect(addr, &cfg_for("localhost"), None, false)
            .expect_err("TLS 1.2 answer MUST abort");
        let msg = format!("{err}");
        assert!(msg.contains("downgrade"), "got: {msg}");
        assert!(msg.contains("sentinel"), "got: {msg}");
        fake.join().unwrap();

        // (b) a plain TLS 1.2 server (no sentinel) → the plain downgrade
        //     abort.  The two error strings are distinct.
        let (addr2, fake2) = fake_tls12_server(false);
        let err2 = client_connect(addr2, &cfg_for("localhost"), None, false)
            .expect_err("TLS 1.2 answer MUST abort");
        let msg2 = format!("{err2}");
        assert!(msg2.contains("downgrade"), "got: {msg2}");
        assert!(msg2.contains("did not negotiate TLS 1.3"), "got: {msg2}");
        assert_ne!(msg, msg2, "the two downgrade paths must be distinct");
        fake2.join().unwrap();
    }

    // ---- 9. PKCS#1 v1.5 CertificateVerify accepted -------------------------

    #[test]
    fn e2e_server_pkcs1_certificateverify_accepted() {
        let mut server = LoopbackServer::bind().unwrap();
        server.use_pkcs1 = true; // alg 0x0401 rsa_pkcs1_sha256 (§B.2)
        let (addr, join) = spawn(server, Some(0xCAFE_0002));
        let mut conn =
            client_connect(addr, &cfg_for("localhost"), Some(0xCAFE_0001), false)
                .expect("handshake with a PKCS#1-v1.5 CertificateVerify");
        assert_eq!(conn.cipher_suite(), 0x1301);
        echo_round(&mut conn, b"pkcs1 echo");
        conn.send_close_notify().unwrap();
        join.join().unwrap().expect("server clean");
    }

    // ---- 10. wrong CertificateVerify signed content rejected ---------------

    #[test]
    fn e2e_wrong_signature_blob_rejected() {
        let mut server = LoopbackServer::bind().unwrap();
        server.wrong_sig_blob = true; // signs the WRONG §4.4.3 context string
        let (addr, join) = spawn(server, Some(0xDADA_0002));
        let err = client_connect(addr, &cfg_for("localhost"), Some(0xDADA_0001), false)
            .expect_err("a CertificateVerify over the wrong context MUST be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("certificateverify"), "got: {msg}");
        join.join().ok();
    }

    // ---- 11. deterministic ClientHello flight (regression anchor) ----------

    #[test]
    fn client_hello_flight_deterministic_bytes() {
        let random = TestPrng::new(0x1A2B_3C4D_5E6F_0011).chunk();
        let priv_key = TestPrng::new(0x1A2B_3C4D_5E6F_0022).chunk();
        let pub_key = x25519::public_from_private(&priv_key);

        // Structural pins (§4.1.2 / §4.2 / §5.1).
        let f1 = Client::build_client_hello_flight(
            "localhost",
            &random,
            &pub_key,
            None,
            false,
        )
        .expect("flight builds");
        let f2 = Client::build_client_hello_flight(
            "localhost",
            &random,
            &pub_key,
            None,
            false,
        )
        .expect("flight builds");
        assert_eq!(f1.record, f2.record, "byte-stable across builds");
        assert_eq!(f1.client_hello, f2.client_hello);

        // The record is a handshake record at legacy version 0x0301 (§5.1
        // initial-ClientHello SHOULD).
        assert_eq!(f1.record[0], 22);
        assert_eq!(&f1.record[1..3], &[0x03, 0x01]);

        // The message decodes with the exact profile.
        let ch = crate::handshake::ClientHello::decode(&f1.client_hello).unwrap();
        assert_eq!(ch.legacy_version, 0x0303);
        assert_eq!(ch.random, random);
        assert_eq!(ch.legacy_session_id.len(), 32);
        assert_eq!(
            ch.cipher_suites,
            vec![0x1301, 0x1302, 0x1303],
            "suites [0x1301, 0x1302, 0x1303]"
        );
        let ext_types: Vec<u16> = ch.extensions.iter().map(|e| e.ext_type).collect();
        assert_eq!(
            ext_types,
            vec![
                crate::handshake::ext_type::SERVER_NAME,
                crate::handshake::ext_type::SUPPORTED_GROUPS,
                crate::handshake::ext_type::KEY_SHARE,
                crate::handshake::ext_type::SUPPORTED_VERSIONS,
                crate::handshake::ext_type::SIGNATURE_ALGORITHMS,
            ],
            "'localhost' is a DNS name → SNI is present"
        );
        // key_share carries the requested public key verbatim.
        let ks = ch
            .extensions
            .iter()
            .find(|e| e.ext_type == crate::handshake::ext_type::KEY_SHARE)
            .unwrap();
        let shares = crate::handshake::parse_key_share_ch(&ks.data).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].group, crate::handshake::named_group::X25519);
        assert_eq!(shares[0].key_exchange, pub_key.to_vec());
        // signature_algorithms: exactly the verifiable pair (§B.2 values).
        let sa = ch
            .extensions
            .iter()
            .find(|e| e.ext_type == crate::handshake::ext_type::SIGNATURE_ALGORITHMS)
            .unwrap();
        assert_eq!(
            crate::handshake::parse_signature_algorithms(&sa.data).unwrap(),
            vec![0x0804, 0x0401]
        );
        assert_eq!(f1.x25519_public, pub_key);

        // Byte-exact regression anchor: SHA-256 of the flight's ClientHello
        // message (deterministic for this injected random/priv pair).  The
        // digest was captured from the first implementation run and pinned
        // here; any profile drift changes this hash.
        let digest = sha256::digest(&f1.client_hello);
        // Re-pinned after the lead's wire-fix session (the builder itself is
        // separately pinned byte-identical against the RFC 8448 trace); the
        // anchor exists to catch silent profile drift between builds.
        let pinned = "f20ba9facb8cb8d85c08af04359e4943b71fffca3d041299ba4b71f448b8c907";
        let got: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, pinned, "ClientHello flight bytes drifted");

        // The post-HRR second hello carries the cookie and uses record
        // version 0x0303 (§5.1 lines 4413-4417).
        let cookie = TestPrng::new(0x00C0_004B_1E00_0001).chunk();
        let f3 = Client::build_client_hello_flight(
            "localhost",
            &random,
            &pub_key,
            Some(&cookie),
            true,
        )
        .expect("second flight builds");
        assert_eq!(f3.record[0], 22);
        assert_eq!(&f3.record[1..3], &[0x03, 0x03]);
        let ch3 = crate::handshake::ClientHello::decode(&f3.client_hello).unwrap();
        let echoed = ch3
            .extensions
            .iter()
            .find(|e| e.ext_type == crate::handshake::ext_type::COOKIE)
            .map(|e| crate::handshake::parse_cookie(&e.data).unwrap())
            .expect("cookie echoed on the second hello");
        assert_eq!(echoed, cookie.to_vec());
    }

    // ---- 12. the §5.2 nonce construction -----------------------------------

    #[test]
    fn record_sequence_nonce_xor_rfc8446_5_2() {
        // §5.2 (verbatim in the client module docs): "The 64-bit record
        // sequence number is encoded in big-endian order and padded to the
        // left with zeros to iv_len in length. ... The padded sequence
        // number is XORed with the static writer IV".
        let iv = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        ];
        // seq 0: the nonce IS the static IV.
        assert_eq!(record_nonce(&iv, 0), iv);
        // seq 1: exactly the last octet flips (right-aligned).
        let mut n1 = iv;
        n1[11] ^= 1;
        assert_eq!(record_nonce(&iv, 1), n1);
        // Big-endian 24-bit sequence 0x010203 lands on nonce[9..12].
        let mut n2 = iv;
        n2[9] ^= 0x01;
        n2[10] ^= 0x02;
        n2[11] ^= 0x03;
        assert_eq!(record_nonce(&iv, 0x010203), n2);
        // Full-width sequence 0x0102030405060708 XORs nonce[4..12] exactly,
        // byte i of the BE encoding at nonce[4+i].
        let seq: u64 = 0x0102_0304_0506_0708;
        let mut n3 = iv;
        for i in 0..8 {
            n3[4 + i] ^= (seq >> (8 * (7 - i))) as u8;
        }
        assert_eq!(record_nonce(&iv, seq), n3);
        // The left 4 octets are the ZERO PADDING, never truncated sequence
        // bytes: unchanged for every sequence number.
        assert_eq!(&record_nonce(&iv, u64::MAX)[..4], &iv[..4]);
    }

    // ---- 13. os-entropy paths fail closed ----------------------------------

    #[test]
    fn os_entropy_random_paths_fail_closed() {
        // (a) The os path is `os_fill_at("/dev/urandom", ...)` — the SAME
        //     function with the same fail-closed branch as the production
        //     source.  An unreadable source is a hard error producing NO
        //     bytes (this is the production failure branch, exercised
        //     without needing privileges to unreadable-ize /dev/urandom).
        let mut b = [0u8; 32];
        assert!(holo_util::rand::os_fill_at("/nonexistent-holonet-entropy", &mut b).is_err());
        assert!(b.iter().all(|&x| x == 0), "no bytes on failure");

        // (b) OsEntropy is live: two draws are distinct and non-zero.
        let mut a1 = [0u8; 32];
        let mut a2 = [0u8; 32];
        OsEntropy.fill32(&mut a1).expect("os entropy available");
        OsEntropy.fill32(&mut a2).expect("os entropy available");
        assert_ne!(a1, a2);
        assert!(a1.iter().any(|&x| x != 0));

        // (c) The INJECTED source is fail-closed when exhausted: the client
        //     aborts with the distinct entropy error instead of improvising
        //     randomness (one chunk supplied; the handshake needs two).
        let server = LoopbackServer::bind().unwrap();
        let addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let _ = server.serve_one(); // peer for the connect; result ignored
        });
        let stream = std::net::TcpStream::connect(addr).unwrap();
        let one = [7u8; 32];
        let mut ent = InjectedEntropy::new(&[&one]);
        let err = Client::connect_with_entropy(stream, &cfg_for("localhost"), &mut ent)
            .expect_err("exhausted injected entropy MUST be a hard error");
        assert!(matches!(err, ClientError::Entropy(_)), "got: {err}");
        let msg = format!("{err}");
        assert!(msg.contains("entropy"), "got: {msg}");
        assert!(msg.contains("fail-closed"), "got: {msg}");

        // HONESTY NOTE: os_fill's unix source path (/dev/urandom) cannot be
        // made unreadable from this test without privileges; (a) exercises
        // the identical fail-closed branch via the shared os_fill_at
        // implementation, and (c) proves the client PROPAGATES entropy
        // failure as a hard abort rather than falling back.  The injected
        // pool intentionally has no refill path — there is no silent
        // degradation seam anywhere in this module.
    }
}
