//! holo-tls — HoloNet TLS 1.3 client (RFC 8446) — pure std, no X.509 parser,
//! SPKI pinning only.
//!
//! This crate implements the parts of RFC 8446 a TLS 1.3-only client needs
//! BEFORE any cryptography is involved:
//!
//! - `record`     — the TLS 1.3 record layer (RFC 8446 §5.1, §5.2, §5.4):
//!                  TLSPlaintext/TLSCiphertext headers, the `2^14` fragment
//!                  bounds, the TLSInnerPlaintext content-type trailer and
//!                  zero padding, and handshake-message fragmentation /
//!                  coalescing in both directions (records that carry several
//!                  handshake messages, handshake messages that span records).
//! - `handshake`  — the handshake-message codec (RFC 8446 §4): u24-length
//!                  framing, ClientHello (§4.1.2) with its canonical builder,
//!                  ServerHello (§4.1.3) with HelloRetryRequest detection and
//!                  the downgrade-protection sentinels, the §4.2 extension
//!                  codecs (server_name, supported_groups,
//!                  signature_algorithms, supported_versions, cookie,
//!                  key_share; unknown extensions are kept raw for forward
//!                  compatibility), plus raw-body codecs for
//!                  EncryptedExtensions / Certificate / CertificateVerify /
//!                  Finished so the RFC 8448 traces can be decoded without an
//!                  X.509 parser.
//! - `transcript` — the Transcript-Hash (RFC 8446 §4.4.1): SHA-256 over the
//!                  concatenation of handshake messages, headers included,
//!                  record headers excluded.
//! - `alert`      — the alert codec (RFC 8446 §6): AlertLevel,
//!                  AlertDescription (all RFC 8446 names), 2-byte encode and
//!                  decode.
//! - `client`     — the TLS 1.3 CLIENT handshake state machine (S2): real
//!                  `std::net::TcpStream` flight exchange incl. the
//!                  HelloRetryRequest round trip, §5.2 record protection,
//!                  §7.1/§7.3 key-schedule wiring, SPKI-pin + hostname
//!                  identity checks, §4.4.3 CertificateVerify and §4.4.4
//!                  Finished verification, and application-data I/O.
//! - `server`     — the minimal loopback TEST server (S2, shipped test
//!                  infrastructure): full server flight over real loopback
//!                  TCP with deterministic-failure seams for the e2e tests.
//!
//! Everything is byte-exact and pinned against the official handshake traces
//! of RFC 8448 ("Example Handshake Traces for TLS 1.3").
//!
//! Wire format in one picture (RFC 8446 §5.1/§5.2/§5.4):
//!
//! ```text
//! TLSPlaintext   = type(1) | legacy_record_version(2) | length(2) | fragment
//! TLSCiphertext  = opaque_type(=23) | legacy_record_version(=0x0303) | length(2) | encrypted_record
//! TLSInnerPlaintext = content | content_type(1) | zeros(padding)   (inside the AEAD)
//! Handshake      = msg_type(1) | length(3, u24) | body
//! ```
//!
//! # Design invariants
//!
//! - `#![forbid(unsafe_code)]`, dependency set = `std` + `holo-crypto` only
//!   (project invariant D-0002: pure std).
//! - Every failure stage produces a distinct `tls: ...` error string (see
//!   [`Error`]), and each error knows which RFC 8446 §6 alert it maps to.
//! - Unknown extensions are preserved verbatim (RFC 8446 §4.1.3 keeps the
//!   ServerHello extension set deliberately small; the ClientHello must
//!   tolerate middlebox extensions such as RFC 8448's `record_size_limit`).
//! - Record `legacy_record_version` is parsed but never validated — RFC 8446
//!   §5.1: "This field is deprecated and MUST be ignored for all purposes."
//!
//! # Future drop-in modules
//!
//! Two more modules will be added by the lead as separate source files. The
//! declarations belong exactly at the marked spot below:
//!
//! ```ignore
//! pub mod spki;      // SPKI pinning (SubjectPublicKeyInfo, RFC 5280 §4.1.2.6)
//! pub mod schedule;  // TLS 1.3 key schedule (RFC 8446 §7.1) on top of holo-crypto
//! ```
//!
//! Nothing in this crate defines symbols named `spki` or `schedule`, so the
//! drop-in is a two-line diff.
#![forbid(unsafe_code)]

pub mod alert;
pub mod handshake;
pub mod record;
pub mod transcript;

/// Test-only byte-exact vectors from RFC 8448 (see module docs).
#[cfg(test)]
pub(crate) mod rfc8448;

// ---- drop-in point for lead-owned modules (create src/spki.rs and
// ---- src/schedule.rs, then uncomment the two lines below):
pub mod spki;
pub mod schedule;

// ---- S2 batch 2: client handshake state machine + loopback test server ----
/// TLS 1.3 client handshake state machine driving a real `std::net::TcpStream`
/// (RFC 8446): ClientHello/HelloRetryRequest/ServerHello flight, the §7.1 key
/// schedule wiring, §5.2 record protection, SPKI-pin + hostname server
/// identity checks, §4.4.3 CertificateVerify verification, §4.4.4 Finished
/// exchange, and the application-data `read`/`write` connection.
pub mod client;
/// Minimal TLS 1.3 loopback TEST server (holo-tls-internal test
/// infrastructure, shipped): echoes application data over real loopback TCP
/// for the crate's e2e tests, with deterministic-failure seams.
pub mod server;

use std::fmt;

/// Crate-wide error type. Every failure stage of the codec has its own
/// variant and therefore its own distinct `tls: ...` message, per the HoloNet
/// convention that error strings identify the failing stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // ---- record layer (RFC 8446 §5.1 / §5.2 / §5.4) ----
    /// Fewer than the 5 header bytes of a record were supplied.
    RecordHeaderTruncated { got: usize },
    /// First byte of a record is not a defined ContentType.
    RecordUnknownContentType(u8),
    /// Record fragment length exceeds the 2^14 bound of §5.1 (or the
    /// 2^14+256 bound of §5.2 for ciphertext records).
    RecordFragmentTooLong { got: usize, max: usize },
    /// Declared fragment length runs past the end of the supplied buffer.
    RecordFragmentMismatch { declared: usize, available: usize },
    /// TLSInnerPlaintext (content || type || padding) exceeds 2^14+1 (§5.4).
    InnerPlaintextTooLong { got: usize, max: usize },
    /// After AEAD-deprotection style scanning, no non-zero octet exists, so
    /// there is no inner content type (§5.4 — "unexpected_message").
    InnerPlaintextMissingType,
    /// The scanned inner content type is not one of the types carried inside
    /// protected records (alert / handshake / application_data).
    InnerPlaintextInvalidType(u8),
    /// A protected handshake or alert record has zero-length content (§5.4).
    InnerPlaintextEmptyHandshakeOrAlert,
    /// A handshake record arrived between the fragments of a split
    /// handshake message — §5.1 forbids interleaving.
    HandshakeInterleaved,
    /// Zero-length handshake record fragment (§5.1 forbids sending them).
    HandshakeZeroLengthFragment,

    // ---- handshake framing (RFC 8446 §4) ----
    /// Fewer than the 4 header bytes of a handshake message were supplied.
    HandshakeHeaderTruncated { got: usize },
    /// The u24 length of a handshake message exceeds the remaining bytes.
    HandshakeLengthExceedsBuffer { declared: usize, available: usize },
    /// Whole-buffer parse left unconsumed bytes after one message.
    HandshakeTrailingBytes(usize),
    /// Handshake type byte outside the RFC 8446 §4 enum.
    UnknownHandshakeType(u8),

    // ---- ClientHello (RFC 8446 §4.1.2) ----
    /// ClientHello.legacy_version is not 0x0303.
    ClientHelloLegacyVersion(u16),
    /// legacy_session_id longer than the 32-byte bound of §4.1.2.
    ClientHelloSessionIdTooLong(usize),
    /// cipher_suites is empty or has an odd byte count.
    ClientHelloCipherSuitesInvalid(usize),
    /// legacy_compression_methods is not exactly the single byte 0.
    ClientHelloCompressionInvalid,
    /// A fixed-size field of the ClientHello body ran past the end.
    ClientHelloTruncated { field: &'static str },

    // ---- extensions (RFC 8446 §4.2) ----
    /// The extension block length runs past the enclosing message.
    ExtensionBlockTruncated,
    /// More than one extension of the same type in one block (§4.2).
    ExtensionDuplicate(u16),
    /// A typed extension's data is too short / odd length for its structure.
    ExtensionTruncated { ext_type: u16, what: &'static str },

    // ---- ServerHello / HelloRetryRequest (RFC 8446 §4.1.3 / §4.1.4) ----
    /// A ServerHello carried an extension outside the §4.1.3 subset.
    ServerHelloUnknownExtension(u16),
    /// legacy_session_id_echo differs from the ClientHello value.
    ServerHelloSessionIdEchoMismatch,
    /// ServerHello selected a cipher suite the client did not offer.
    ServerHelloCipherSuiteNotOffered(u16),
    /// legacy_compression_method is not 0.
    ServerHelloCompressionInvalid(u8),
    /// A fixed-size field of the ServerHello body ran past the end.
    ServerHelloTruncated { field: &'static str },
    /// A HelloRetryRequest without the mandatory supported_versions (§4.1.4).
    HelloRetryMissingSupportedVersions,
    /// The 8-byte DOWNGRD sentinel was found in ServerHello.random[24..32].
    DowngradeSentinel([u8; 8]),
    /// No supported_versions selecting 0x0304 and no sentinel — a plain
    /// TLS 1.2 (or older) server answered a TLS 1.3-only client.
    DowngradeNoTls13,
    /// A fixed-size field of some other handshake body ran past the end.
    HandshakeBodyTruncated { field: &'static str },

    // ---- alerts (RFC 8446 §6) ----
    /// An alert is exactly two bytes; fewer were supplied.
    AlertTruncated { got: usize },
    /// AlertLevel byte outside {1, 2}.
    AlertUnknownLevel(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RecordHeaderTruncated { got } => write!(
                f,
                "tls: record: header truncated: got {got} bytes, need 5 (RFC 8446 §5.1)"
            ),
            Error::RecordUnknownContentType(b) => {
                write!(f, "tls: record: unknown content type 0x{b:02x} (RFC 8446 §5.1)")
            }
            Error::RecordFragmentTooLong { got, max } => write!(
                f,
                "tls: record: fragment length {got} exceeds maximum {max} — record_overflow (RFC 8446 §5.1: MUST NOT exceed 2^14)"
            ),
            Error::RecordFragmentMismatch { declared, available } => write!(
                f,
                "tls: record: fragment declares {declared} bytes but only {available} available"
            ),
            Error::InnerPlaintextTooLong { got, max } => write!(
                f,
                "tls: record: TLSInnerPlaintext length {got} exceeds maximum {max} (RFC 8446 §5.4: MUST NOT exceed 2^14+1)"
            ),
            Error::InnerPlaintextMissingType => write!(
                f,
                "tls: record: inner plaintext has no non-zero octet, no content type found — unexpected_message (RFC 8446 §5.4)"
            ),
            Error::InnerPlaintextInvalidType(b) => write!(
                f,
                "tls: record: inner content type 0x{b:02x} is not a valid protected record type"
            ),
            Error::InnerPlaintextEmptyHandshakeOrAlert => write!(
                f,
                "tls: record: zero-length handshake/alert inner content — unexpected_message (RFC 8446 §5.4)"
            ),
            Error::HandshakeInterleaved => write!(
                f,
                "tls: record: handshake messages MUST NOT be interleaved with other record types (RFC 8446 §5.1)"
            ),
            Error::HandshakeZeroLengthFragment => write!(
                f,
                "tls: record: zero-length handshake fragment (RFC 8446 §5.1: implementations MUST NOT send them)"
            ),

            Error::HandshakeHeaderTruncated { got } => write!(
                f,
                "tls: handshake: header truncated: got {got} bytes, need 4 (RFC 8446 §4)"
            ),
            Error::HandshakeLengthExceedsBuffer { declared, available } => write!(
                f,
                "tls: handshake: declared length {declared} exceeds remaining {available} bytes"
            ),
            Error::HandshakeTrailingBytes(n) => {
                write!(f, "tls: handshake: {n} trailing bytes after message")
            }
            Error::UnknownHandshakeType(b) => {
                write!(f, "tls: handshake: unknown handshake type {b} (RFC 8446 §4)")
            }

            Error::ClientHelloLegacyVersion(v) => write!(
                f,
                "tls: clienthello: legacy_version 0x{v:04x} must be 0x0303 (RFC 8446 §4.1.2)"
            ),
            Error::ClientHelloSessionIdTooLong(n) => write!(
                f,
                "tls: clienthello: legacy_session_id length {n} exceeds 32 (RFC 8446 §4.1.2)"
            ),
            Error::ClientHelloCipherSuitesInvalid(n) => write!(
                f,
                "tls: clienthello: cipher_suites byte length {n} is not a non-empty even number (RFC 8446 §4.1.2)"
            ),
            Error::ClientHelloCompressionInvalid => write!(
                f,
                "tls: clienthello: legacy_compression_methods must be exactly one byte, zero (RFC 8446 §4.1.2)"
            ),
            Error::ClientHelloTruncated { field } => {
                write!(f, "tls: clienthello: truncated {field}")
            }

            Error::ExtensionBlockTruncated => {
                write!(f, "tls: extensions: block length exceeds message body")
            }
            Error::ExtensionDuplicate(t) => write!(
                f,
                "tls: extensions: duplicate extension type 0x{t:04x} (RFC 8446 §4.2: no more than one of the same type)"
            ),
            Error::ExtensionTruncated { ext_type, what } => write!(
                f,
                "tls: extensions: extension 0x{ext_type:04x}: truncated {what}"
            ),

            Error::ServerHelloUnknownExtension(t) => write!(
                f,
                "tls: serverhello: unknown/unexpected extension type 0x{t:04x} (RFC 8446 §4.1.3: ServerHello extensions are a restricted subset)"
            ),
            Error::ServerHelloSessionIdEchoMismatch => write!(
                f,
                "tls: serverhello: legacy_session_id_echo does not match the ClientHello value — illegal_parameter (RFC 8446 §4.1.3)"
            ),
            Error::ServerHelloCipherSuiteNotOffered(s) => write!(
                f,
                "tls: serverhello: cipher suite 0x{s:04x} was not offered — illegal_parameter (RFC 8446 §4.1.3)"
            ),
            Error::ServerHelloCompressionInvalid(b) => write!(
                f,
                "tls: serverhello: legacy_compression_method must be 0, got {b}"
            ),
            Error::ServerHelloTruncated { field } => {
                write!(f, "tls: serverhello: truncated {field}")
            }
            Error::HelloRetryMissingSupportedVersions => write!(
                f,
                "tls: helloretryrequest: missing supported_versions extension (RFC 8446 §4.1.4)"
            ),
            Error::DowngradeSentinel(tail) => write!(
                f,
                "tls: downgrade: ServerHello.random[24..32] carries the RFC 8446 §4.1.3 DOWNGRD sentinel {} — a TLS 1.3 server negotiating TLS ≤ 1.2, abort with illegal_parameter",
                tail.iter().map(|b| format!("{b:02X} ")).collect::<String>().trim_end()
            ),
            Error::DowngradeNoTls13 => write!(
                f,
                "tls: downgrade: ServerHello did not negotiate TLS 1.3 (no supported_versions selecting 0x0304) — TLS 1.2-or-older server, abort"
            ),
            Error::HandshakeBodyTruncated { field } => {
                write!(f, "tls: handshake body: truncated {field}")
            }

            Error::AlertTruncated { got } => write!(
                f,
                "tls: alert: truncated: got {got} bytes, need 2 (RFC 8446 §6)"
            ),
            Error::AlertUnknownLevel(b) => {
                write!(f, "tls: alert: unknown alert level {b} (RFC 8446 §6)")
            }
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Which RFC 8446 §6 alert this failure maps to, when the connection
    /// should be aborted with a specific one. `None` = caller's choice
    /// (`internal_error` is the usual fallback).
    ///
    /// Mapping follows the normative sentences quoted in each variant's doc
    /// comment, plus RFC 8446 §6 note: syntax failures are "decode_error",
    /// semantically invalid values are "illegal_parameter".
    pub fn alert(&self) -> alert::AlertDescription {
        use alert::AlertDescription as A;
        match self {
            Error::RecordFragmentTooLong { .. } | Error::RecordHeaderTruncated { .. }
            | Error::RecordFragmentMismatch { .. } | Error::InnerPlaintextTooLong { .. } => A::RecordOverflow,
            Error::InnerPlaintextMissingType
            | Error::InnerPlaintextEmptyHandshakeOrAlert
            | Error::HandshakeInterleaved
            | Error::HandshakeZeroLengthFragment => A::UnexpectedMessage,
            Error::RecordUnknownContentType(_)
            | Error::InnerPlaintextInvalidType(_)
            | Error::HandshakeLengthExceedsBuffer { .. }
            | Error::HandshakeHeaderTruncated { .. }
            | Error::HandshakeTrailingBytes(_)
            | Error::UnknownHandshakeType(_)
            | Error::ClientHelloTruncated { .. }
            | Error::ExtensionBlockTruncated
            | Error::ExtensionTruncated { .. }
            | Error::ServerHelloTruncated { .. }
            | Error::HandshakeBodyTruncated { .. }
            | Error::AlertTruncated { .. } => A::DecodeError,
            Error::ClientHelloLegacyVersion(_)
            | Error::ClientHelloSessionIdTooLong(_)
            | Error::ClientHelloCipherSuitesInvalid(_)
            | Error::ClientHelloCompressionInvalid
            | Error::ExtensionDuplicate(_)
            | Error::ServerHelloUnknownExtension(_)
            | Error::ServerHelloSessionIdEchoMismatch
            | Error::ServerHelloCipherSuiteNotOffered(_)
            | Error::ServerHelloCompressionInvalid(_)
            | Error::HelloRetryMissingSupportedVersions
            | Error::DowngradeSentinel(_)
            | Error::DowngradeNoTls13
            | Error::AlertUnknownLevel(_) => A::IllegalParameter,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
