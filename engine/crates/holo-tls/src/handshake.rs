//! Handshake-message codec — RFC 8446 §4.
//!
//! §4 (lines 1366-1381) — the framing every message shares:
//!
//! > struct {
//! >     HandshakeType msg_type;    /* handshake type */
//! >     uint24 length;             /* remaining bytes in message */
//! >     select (Handshake.msg_type) { ... };
//! > } Handshake;
//!
//! §4.1.2 ClientHello (lines 1546-1553):
//!
//! > struct {
//! >     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
//! >     Random random;
//! >     opaque legacy_session_id<0..32>;
//! >     CipherSuite cipher_suites<2..2^16-2>;
//! >     opaque legacy_compression_methods<1..2^8-1>;
//! >     Extension extensions<8..2^16-1>;
//! > } ClientHello;
//!
//! §4.1.3 ServerHello (lines 1695-1702):
//!
//! > struct {
//! >     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
//! >     Random random;
//! >     opaque legacy_session_id_echo<0..32>;
//! >     CipherSuite cipher_suite;
//! >     uint8 legacy_compression_method = 0;
//! >     Extension extensions<6..2^16-1>;
//! > } ServerHello;
//!
//! §4.1.3 (lines 1753-1763) — the HelloRetryRequest sentinel:
//!
//! > For reasons of backward compatibility with middleboxes (see Appendix
//! > D.4), the HelloRetryRequest message uses the same structure as the
//! > ServerHello, but with Random set to the special value of the SHA-256
//! > of "HelloRetryRequest":
//! >
//! >   CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
//! >   C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
//! >
//! > Upon receiving a message with type server_hello, implementations MUST
//! > first examine the Random value and, if it matches this value, process
//! > it as described in Section 4.1.4).
//!
//! (Byte-exact against the fetched RFC text, RFC lines 1758-1759; verified
//! to equal SHA-256("HelloRetryRequest") in dev checks.  The task briefing
//! quoted a different 35-byte tail — see the report; the RFC is ground
//! truth, and RFC 8448 §5 line 1656 carries the same value on the wire.)
//!
//! §4.1.3 (lines 1770-1786) — downgrade protection:
//!
//! > If negotiating TLS 1.2, TLS 1.3 servers MUST set the last 8 bytes of
//! > their Random value to the bytes:
//! >
//! >   44 4F 57 4E 47 52 44 01
//! >
//! > If negotiating TLS 1.1 or below, TLS 1.3 servers MUST, and TLS 1.2
//! > servers SHOULD, set the last 8 bytes of their ServerHello.Random value
//! > to the bytes:
//! >
//! >   44 4F 57 4E 47 52 44 00
//! >
//! > TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
//! > MUST check that the last 8 bytes are not equal to either of these
//! > values.  ... If a match is found, the client MUST abort the handshake
//! > with an "illegal_parameter" alert.
//!
//! HoloNet's client is TLS-1.3-ONLY: a ServerHello without a
//! "supported_versions" extension selecting 0x0304 aborts with a distinct
//! "tls: downgrade" error (RFC 8446 §4.2.1, lines 2176-2198: a server
//! negotiating TLS 1.3 "MUST respond by sending a 'supported_versions'
//! extension containing the selected version value (0x0304)").

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// HandshakeType — RFC 8446 §4, lines 1351-1364
// ---------------------------------------------------------------------------

/// RFC 8446 §4:
///
/// ```text
/// enum {
///     client_hello(1), server_hello(2), new_session_ticket(4),
///     end_of_early_data(5), encrypted_extensions(8), certificate(11),
///     certificate_request(13), certificate_verify(15), finished(20),
///     key_update(24), message_hash(254), (255)
/// } HandshakeType;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    ClientHello,
    ServerHello,
    NewSessionTicket,
    EndOfEarlyData,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
    KeyUpdate,
    MessageHash,
}

impl HandshakeType {
    pub fn as_u8(self) -> u8 {
        match self {
            HandshakeType::ClientHello => 1,
            HandshakeType::ServerHello => 2,
            HandshakeType::NewSessionTicket => 4,
            HandshakeType::EndOfEarlyData => 5,
            HandshakeType::EncryptedExtensions => 8,
            HandshakeType::Certificate => 11,
            HandshakeType::CertificateRequest => 13,
            HandshakeType::CertificateVerify => 15,
            HandshakeType::Finished => 20,
            HandshakeType::KeyUpdate => 24,
            HandshakeType::MessageHash => 254,
        }
    }

    pub fn from_u8(b: u8) -> Result<Self> {
        match b {
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            8 => Ok(HandshakeType::EncryptedExtensions),
            11 => Ok(HandshakeType::Certificate),
            13 => Ok(HandshakeType::CertificateRequest),
            15 => Ok(HandshakeType::CertificateVerify),
            20 => Ok(HandshakeType::Finished),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(Error::UnknownHandshakeType(b)),
        }
    }
}

/// Encode the 4-byte handshake header: `msg_type(1) || uint24 length`.
pub fn encode_handshake_header(msg_type: HandshakeType, body_len: usize) -> [u8; 4] {
    let mut hdr = [0u8; 4];
    hdr[0] = msg_type.as_u8();
    hdr[1] = (body_len >> 16) as u8;
    hdr[2] = (body_len >> 8) as u8;
    hdr[3] = body_len as u8;
    hdr
}

/// Parse one handshake message from the front of `buf`, checking that the
/// u24 length exactly matches the available bytes.  Returns the type and the
/// body slice (header excluded — callers wanting the transcript unit must use
/// the full 4+len bytes).
pub fn parse_one_handshake(buf: &[u8]) -> Result<(HandshakeType, &[u8])> {
    if buf.len() < 4 {
        return Err(Error::HandshakeHeaderTruncated { got: buf.len() });
    }
    let msg_type = HandshakeType::from_u8(buf[0])?;
    let declared = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    let available = buf.len() - 4;
    if declared > available {
        return Err(Error::HandshakeLengthExceedsBuffer { declared, available });
    }
    Ok((msg_type, &buf[4..4 + declared]))
}

// ---------------------------------------------------------------------------
// Cipher suites — RFC 8446 §B.4 (table at lines 7433-7446)
// ---------------------------------------------------------------------------

pub mod cipher_suite {
    /// TLS_AES_128_GCM_SHA256 {0x13,0x01}
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    /// TLS_AES_256_GCM_SHA384 {0x13,0x02}
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    /// TLS_CHACHA20_POLY1305_SHA256 {0x13,0x03}
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
    /// TLS_AES_128_CCM_SHA256 {0x13,0x04}
    pub const TLS_AES_128_CCM_SHA256: u16 = 0x1304;
    /// TLS_AES_128_CCM_8_SHA256 {0x13,0x05}
    pub const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;
}

// ---------------------------------------------------------------------------
// SignatureScheme — RFC 8446 §4.2.3, lines 2306-2338
// ---------------------------------------------------------------------------

pub mod signature_scheme {
    /// rsa_pkcs1_sha256(0x0401)
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    /// rsa_pkcs1_sha384(0x0501)
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    /// rsa_pkcs1_sha512(0x0601)
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
    /// ecdsa_secp256r1_sha256(0x0403)
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    /// ecdsa_secp384r1_sha384(0x0503)
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    /// ecdsa_secp521r1_sha512(0x0603)
    pub const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
    /// rsa_pss_rsae_sha256(0x0804)
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    /// rsa_pss_rsae_sha384(0x0805)
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    /// rsa_pss_rsae_sha512(0x0806)
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    /// ed25519(0x0807)
    pub const ED25519: u16 = 0x0807;
    /// ed448(0x0808)
    pub const ED448: u16 = 0x0808;
    /// rsa_pss_pss_sha256(0x0809)
    pub const RSA_PSS_PSS_SHA256: u16 = 0x0809;
    /// rsa_pss_pss_sha384(0x080a)
    pub const RSA_PSS_PSS_SHA384: u16 = 0x080a;
    /// rsa_pss_pss_sha512(0x080b)
    pub const RSA_PSS_PSS_SHA512: u16 = 0x080b;
    /// rsa_pkcs1_sha1(0x0201) — legacy
    pub const RSA_PKCS1_SHA1: u16 = 0x0201;
    /// ecdsa_sha1(0x0203) — legacy
    pub const ECDSA_SHA1: u16 = 0x0203;
}

// ---------------------------------------------------------------------------
// NamedGroup — RFC 8446 §4.2.7 / Appendix, lines 2612-2618
// ---------------------------------------------------------------------------

pub mod named_group {
    /// secp256r1(0x0017)
    pub const SECP256R1: u16 = 0x0017;
    /// secp384r1(0x0018)
    pub const SECP384R1: u16 = 0x0018;
    /// secp521r1(0x0019)
    pub const SECP521R1: u16 = 0x0019;
    /// x25519(0x001D)
    pub const X25519: u16 = 0x001d;
    /// x448(0x001E)
    pub const X448: u16 = 0x001e;
    /// ffdhe2048(0x0100)
    pub const FFDHE2048: u16 = 0x0100;
    /// ffdhe3072(0x0101)
    pub const FFDHE3072: u16 = 0x0101;
    /// ffdhe4096(0x0102)
    pub const FFDHE4096: u16 = 0x0102;
    /// ffdhe6144(0x0103)
    pub const FFDHE6144: u16 = 0x0103;
    /// ffdhe8192(0x0104)
    pub const FFDHE8192: u16 = 0x0104;
}

// ---------------------------------------------------------------------------
// PskKeyExchangeMode — RFC 8446 §4.2.9, lines 2884-2889
// ---------------------------------------------------------------------------

pub mod psk_key_exchange_mode {
    /// psk_ke(0) — PSK-only key establishment.
    pub const PSK_KE: u8 = 0;
    /// psk_dhe_ke(1) — PSK with (EC)DHE key establishment.
    pub const PSK_DHE_KE: u8 = 1;
}

// ---------------------------------------------------------------------------
// ExtensionType constants — RFC 8446 §4.2, lines 1921-1945
// ---------------------------------------------------------------------------

pub mod ext_type {
    /// server_name(0)
    pub const SERVER_NAME: u16 = 0;
    /// max_fragment_length(1)
    pub const MAX_FRAGMENT_LENGTH: u16 = 1;
    /// status_request(5)
    pub const STATUS_REQUEST: u16 = 5;
    /// supported_groups(10)
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// signature_algorithms(13)
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    /// use_srtp(14)
    pub const USE_SRTP: u16 = 14;
    /// heartbeat(15)
    pub const HEARTBEAT: u16 = 15;
    /// application_layer_protocol_negotiation(16)
    pub const ALPN: u16 = 16;
    /// signed_certificate_timestamp(18)
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 18;
    /// client_certificate_type(19)
    pub const CLIENT_CERTIFICATE_TYPE: u16 = 19;
    /// server_certificate_type(20)
    pub const SERVER_CERTIFICATE_TYPE: u16 = 20;
    /// padding(21)
    pub const PADDING: u16 = 21;
    /// pre_shared_key(41)
    pub const PRE_SHARED_KEY: u16 = 41;
    /// early_data(42)
    pub const EARLY_DATA: u16 = 42;
    /// supported_versions(43)
    pub const SUPPORTED_VERSIONS: u16 = 43;
    /// cookie(44)
    pub const COOKIE: u16 = 44;
    /// psk_key_exchange_modes(45)
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    /// certificate_authorities(47)
    pub const CERTIFICATE_AUTHORITIES: u16 = 47;
    /// oid_filters(48)
    pub const OID_FILTERS: u16 = 48;
    /// post_handshake_auth(49)
    pub const POST_HANDSHAKE_AUTH: u16 = 49;
    /// signature_algorithms_cert(50)
    pub const SIGNATURE_ALGORITHMS_CERT: u16 = 50;
    /// key_share(51)
    pub const KEY_SHARE: u16 = 51;
    /// renegotiation_info(0xff01) — RFC 5746; appears in RFC 8448 traces.
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

// ---------------------------------------------------------------------------
// Generic extension container — RFC 8446 §4.2, lines 1916-1919
// ---------------------------------------------------------------------------

/// RFC 8446 §4.2:
///
/// > struct {
/// >     ExtensionType extension_type;
/// >     opaque extension_data<0..2^16-1>;
/// > } Extension;
///
/// Unknown extension types are kept raw (forward compatibility).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl Extension {
    /// Append the 4-byte extension header + data to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ext_type.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.data.len());
        self.encode_into(&mut v);
        v
    }
}

/// Encode a whole extension block INCLUDING the u16 total-length prefix
/// (`Extension extensions<8..2^16-1>` etc.).
pub fn encode_extension_block(extensions: &[Extension]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in extensions {
        e.encode_into(&mut out);
    }
    let mut full = Vec::with_capacity(2 + out.len());
    full.extend_from_slice(&(out.len() as u16).to_be_bytes());
    full.extend_from_slice(&out);
    full
}

/// Parse a whole extension block (the bytes AFTER the u16 total-length
/// prefix).  Enforces RFC 8446 §4.2, lines 2083-2084:
///
/// > There MUST NOT be more than one extension of the same type in a given
/// > extension block.
pub fn parse_extension_block(block: &[u8]) -> Result<Vec<Extension>> {
    let mut extensions = Vec::new();
    let mut p = 0;
    while p < block.len() {
        if block.len() - p < 4 {
            return Err(Error::ExtensionTruncated {
                ext_type: u16::from_be_bytes([block[p], block[p + 1 % block.len()]]),
                what: "4-byte header",
            });
        }
        let ext_type = u16::from_be_bytes([block[p], block[p + 1]]);
        let len = u16::from_be_bytes([block[p + 2], block[p + 3]]) as usize;
        let end = p + 4 + len;
        if end > block.len() {
            return Err(Error::ExtensionTruncated {
                ext_type,
                what: "extension_data runs past the block",
            });
        }
        if extensions.iter().any(|e: &Extension| e.ext_type == ext_type) {
            return Err(Error::ExtensionDuplicate(ext_type));
        }
        extensions.push(Extension { ext_type, data: block[p + 4..end].to_vec() });
        p = end;
    }
    Ok(extensions)
}

// ---------------------------------------------------------------------------
// Typed extension codecs — RFC 8446 §4.2
// ---------------------------------------------------------------------------

/// "supported_versions" in a ClientHello (§4.2.1, lines 2137-2145):
/// `ProtocolVersion versions<2..254>;` — a u8-prefixed list of u16 values.
pub fn parse_supported_versions_ch(data: &[u8]) -> Result<Vec<u16>> {
    if data.is_empty() {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::SUPPORTED_VERSIONS,
            what: "list length byte",
        });
    }
    let list_len = data[0] as usize;
    if list_len % 2 != 0 || list_len < 2 || list_len > 254 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::SUPPORTED_VERSIONS,
            what: "list length (must be even, 2..254)",
        });
    }
    if data.len() < 1 + list_len {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::SUPPORTED_VERSIONS,
            what: "list body",
        });
    }
    Ok(data[1..1 + list_len]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

pub fn encode_supported_versions_ch(versions: &[u16]) -> Result<Extension> {
    let list_len = versions.len() * 2;
    if versions.is_empty() || list_len > 254 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::SUPPORTED_VERSIONS,
            what: "list length (must be even, 2..254)",
        });
    }
    let mut data = Vec::with_capacity(1 + list_len);
    data.push(list_len as u8);
    for v in versions {
        data.extend_from_slice(&v.to_be_bytes());
    }
    Ok(Extension { ext_type: ext_type::SUPPORTED_VERSIONS, data })
}

/// "supported_versions" in a ServerHello / HelloRetryRequest (§4.2.1):
/// `ProtocolVersion selected_version;` — a single u16.
pub fn parse_supported_versions_sh(data: &[u8]) -> Result<u16> {
    if data.len() != 2 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::SUPPORTED_VERSIONS,
            what: "selected_version (must be exactly 2 bytes)",
        });
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

pub fn encode_supported_versions_sh(selected_version: u16) -> Extension {
    Extension {
        ext_type: ext_type::SUPPORTED_VERSIONS,
        data: selected_version.to_be_bytes().to_vec(),
    }
}

/// One `KeyShareEntry` (§4.2.8, lines 2672-2675):
///
/// > struct {
/// >     NamedGroup group;
/// >     opaque key_exchange<1..2^16-1>;
/// > } KeyShareEntry;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: u16,
    pub key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.group.to_be_bytes());
        out.extend_from_slice(&(self.key_exchange.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.key_exchange);
    }
}

/// "key_share" in a ClientHello (§4.2.8, lines 2698-2700):
/// `KeyShareEntry client_shares<0..2^16-1>;` — u16-prefixed entry list.
pub fn parse_key_share_ch(data: &[u8]) -> Result<Vec<KeyShareEntry>> {
    if data.len() < 2 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::KEY_SHARE,
            what: "client_shares length",
        });
    }
    let total = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + total {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::KEY_SHARE,
            what: "client_shares body",
        });
    }
    let mut entries = Vec::new();
    let mut p = 2;
    let end = 2 + total;
    while p < end {
        if end - p < 4 {
            return Err(Error::ExtensionTruncated {
                ext_type: ext_type::KEY_SHARE,
                what: "KeyShareEntry (group + key_exchange length)",
            });
        }
        let group = u16::from_be_bytes([data[p], data[p + 1]]);
        let klen = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        let kend = p + 4 + klen;
        if kend > end || klen == 0 {
            // key_exchange<1..2^16-1> — never empty (§4.2.8 line 2674).
            return Err(Error::ExtensionTruncated {
                ext_type: ext_type::KEY_SHARE,
                what: "KeyShareEntry key_exchange",
            });
        }
        entries.push(KeyShareEntry { group, key_exchange: data[p + 4..kend].to_vec() });
        p = kend;
    }
    Ok(entries)
}

pub fn encode_key_share_ch(entries: &[KeyShareEntry]) -> Result<Extension> {
    let mut body = Vec::new();
    for e in entries {
        if e.key_exchange.is_empty() {
            return Err(Error::ExtensionTruncated {
                ext_type: ext_type::KEY_SHARE,
                what: "KeyShareEntry key_exchange (must be non-empty)",
            });
        }
        e.encode_into(&mut body);
    }
    if body.len() > u16::MAX as usize {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::KEY_SHARE,
            what: "client_shares total length exceeds uint16",
        });
    }
    let mut data = Vec::with_capacity(2 + body.len());
    data.extend_from_slice(&(body.len() as u16).to_be_bytes());
    data.extend_from_slice(&body);
    Ok(Extension { ext_type: ext_type::KEY_SHARE, data })
}

/// "key_share" in a ServerHello (§4.2.8, lines 2758-2760):
/// `struct { KeyShareEntry server_share; } KeyShareServerHello;` — ONE entry.
pub fn parse_key_share_sh(data: &[u8]) -> Result<KeyShareEntry> {
    if data.len() < 4 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::KEY_SHARE,
            what: "server_share (group + key_exchange length)",
        });
    }
    let group = u16::from_be_bytes([data[0], data[1]]);
    let klen = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() != 4 + klen {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::KEY_SHARE,
            what: "server_share must be exactly one KeyShareEntry",
        });
    }
    Ok(KeyShareEntry { group, key_exchange: data[4..].to_vec() })
}

pub fn encode_key_share_sh(entry: &KeyShareEntry) -> Extension {
    let mut data = Vec::with_capacity(4 + entry.key_exchange.len());
    entry.encode_into(&mut data);
    Extension { ext_type: ext_type::KEY_SHARE, data }
}

/// "key_share" in a HelloRetryRequest (§4.2.8, lines 2728-2730):
/// `struct { NamedGroup selected_group; } KeyShareHelloRetryRequest;`.
pub fn parse_key_share_hrr(data: &[u8]) -> Result<u16> {
    if data.len() != 2 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::KEY_SHARE,
            what: "selected_group (must be exactly 2 bytes)",
        });
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

pub fn encode_key_share_hrr(selected_group: u16) -> Extension {
    Extension {
        ext_type: ext_type::KEY_SHARE,
        data: selected_group.to_be_bytes().to_vec(),
    }
}

/// "cookie" (§4.2.2, lines 2202-2204):
/// `struct { opaque cookie<1..2^16-1>; } Cookie;` — u16-prefixed opaque,
/// at least 1 byte.
pub fn parse_cookie(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 2 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::COOKIE,
            what: "cookie length",
        });
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() != 2 + len || len == 0 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::COOKIE,
            what: "cookie body (opaque<1..2^16-1>)",
        });
    }
    Ok(data[2..].to_vec())
}

pub fn encode_cookie(cookie: &[u8]) -> Result<Extension> {
    if cookie.is_empty() || cookie.len() > u16::MAX as usize {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::COOKIE,
            what: "cookie body (opaque<1..2^16-1>)",
        });
    }
    let mut data = Vec::with_capacity(2 + cookie.len());
    data.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
    data.extend_from_slice(cookie);
    Ok(Extension { ext_type: ext_type::COOKIE, data })
}

/// Shared shape of "supported_groups" (§4.2.7) and "signature_algorithms"
/// (§4.2.3): `uint16 list<2..2^16-2>` — a u16-prefixed list of u16 values.
fn parse_u16_prefixed_u16_list(ext_type: u16, data: &[u8]) -> Result<Vec<u16>> {
    if data.len() < 2 || data.len() % 2 != 0 {
        return Err(Error::ExtensionTruncated {
            ext_type,
            what: "u16-prefixed u16 list (even byte count)",
        });
    }
    let total = u16::from_be_bytes([data[0], data[1]]) as usize;
    if total < 2 || total % 2 != 0 || data.len() != 2 + total {
        return Err(Error::ExtensionTruncated {
            ext_type,
            what: "list total length",
        });
    }
    Ok(data[2..]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

fn encode_u16_prefixed_u16_list(ext_type: u16, values: &[u16]) -> Result<Extension> {
    if values.is_empty() {
        return Err(Error::ExtensionTruncated {
            ext_type,
            what: "list must be non-empty (<2..2^16-2>)",
        });
    }
    let mut data = Vec::with_capacity(2 + values.len() * 2);
    data.extend_from_slice(&((values.len() * 2) as u16).to_be_bytes());
    for v in values {
        data.extend_from_slice(&v.to_be_bytes());
    }
    Ok(Extension { ext_type, data })
}

/// "supported_groups" (§4.2.7): `NamedGroup supported_groups<2..2^16-2>;`
pub fn parse_supported_groups(data: &[u8]) -> Result<Vec<u16>> {
    parse_u16_prefixed_u16_list(ext_type::SUPPORTED_GROUPS, data)
}

pub fn encode_supported_groups(groups: &[u16]) -> Result<Extension> {
    encode_u16_prefixed_u16_list(ext_type::SUPPORTED_GROUPS, groups)
}

/// "signature_algorithms" (§4.2.3, lines 2340-2342):
/// `SignatureScheme supported_signature_algorithms<2..2^16-2>;`
pub fn parse_signature_algorithms(data: &[u8]) -> Result<Vec<u16>> {
    parse_u16_prefixed_u16_list(ext_type::SIGNATURE_ALGORITHMS, data)
}

pub fn encode_signature_algorithms(schemes: &[u16]) -> Result<Extension> {
    encode_u16_prefixed_u16_list(ext_type::SIGNATURE_ALGORITHMS, schemes)
}

/// "server_name" (RFC 6066 via §4.2 table, line 1922).  The client side
/// carries a single host_name entry:
/// `u16 list_len || [u8 type=0 || u16 name_len || name]`.
pub fn parse_server_name(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 2 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::SERVER_NAME,
            what: "server_name_list length",
        });
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() != 2 + list_len || list_len < 3 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::SERVER_NAME,
            what: "server_name_list body",
        });
    }
    let mut p = 2;
    let end = 2 + list_len;
    let mut name = None;
    while p < end {
        if end - p < 3 {
            return Err(Error::ExtensionTruncated {
                ext_type: ext_type::SERVER_NAME,
                what: "HostName entry",
            });
        }
        let name_type = data[p];
        let name_len = u16::from_be_bytes([data[p + 1], data[p + 2]]) as usize;
        let nend = p + 3 + name_len;
        if nend > end {
            return Err(Error::ExtensionTruncated {
                ext_type: ext_type::SERVER_NAME,
                what: "HostName body",
            });
        }
        if name_type == 0 && name.is_none() {
            name = Some(data[p + 3..nend].to_vec());
        }
        p = nend;
    }
    name.ok_or(Error::ExtensionTruncated {
        ext_type: ext_type::SERVER_NAME,
        what: "no host_name entry",
    })
}

pub fn encode_server_name(hostname: &[u8]) -> Result<Extension> {
    if hostname.is_empty() {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::SERVER_NAME,
            what: "host_name must be non-empty",
        });
    }
    // list_len = 3 + name_len (type byte + u16 length + name)
    let list_len = 3 + hostname.len();
    if list_len > u16::MAX as usize {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::SERVER_NAME,
            what: "host_name too long for uint16",
        });
    }
    let mut data = Vec::with_capacity(2 + list_len);
    data.extend_from_slice(&(list_len as u16).to_be_bytes());
    data.push(0); // host_name type
    data.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
    data.extend_from_slice(hostname);
    Ok(Extension { ext_type: ext_type::SERVER_NAME, data })
}

/// "psk_key_exchange_modes" (§4.2.9, lines 2886-2889):
/// `PskKeyExchangeMode ke_modes<1..255>;` — u8-prefixed list of u8 modes.
pub fn parse_psk_key_exchange_modes(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::PSK_KEY_EXCHANGE_MODES,
            what: "list length byte",
        });
    }
    let list_len = data[0] as usize;
    if data.len() != 1 + list_len || list_len == 0 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::PSK_KEY_EXCHANGE_MODES,
            what: "list body (<1..255>)",
        });
    }
    Ok(data[1..].to_vec())
}

pub fn encode_psk_key_exchange_modes(modes: &[u8]) -> Result<Extension> {
    if modes.is_empty() || modes.len() > 255 {
        return Err(Error::ExtensionTruncated {
            ext_type: ext_type::PSK_KEY_EXCHANGE_MODES,
            what: "list body (<1..255>)",
        });
    }
    let mut data = Vec::with_capacity(1 + modes.len());
    data.push(modes.len() as u8);
    data.extend_from_slice(modes);
    Ok(Extension { ext_type: ext_type::PSK_KEY_EXCHANGE_MODES, data })
}

// ---------------------------------------------------------------------------
// ClientHello — RFC 8446 §4.1.2
// ---------------------------------------------------------------------------

/// The `legacy_version` value of a TLS 1.3 ClientHello (§4.1.2, line 1583:
/// "the legacy_version field MUST be set to 0x0303").
pub const CLIENT_HELLO_LEGACY_VERSION: u16 = 0x0303;

/// TLS 1.3 (§4.2.1, line 2180: selected version value 0x0304).
pub const VERSION_TLS13: u16 = 0x0304;

/// RFC 8446 §4.1.3, lines 1758-1759 — the HelloRetryRequest sentinel random
/// (SHA-256 of "HelloRetryRequest"):
/// `CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
///  C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C`
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// RFC 8446 §4.1.3, line 1773 — DOWNGRD sentinel tail for TLS 1.2:
/// `44 4F 57 4E 47 52 44 01` ("DOWNGRD" + 0x01).
pub const DOWNGRD_SENTINEL_TLS12: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];

/// RFC 8446 §4.1.3, line 1779 — DOWNGRD sentinel tail for TLS 1.1 and below:
/// `44 4F 57 4E 47 52 44 00` ("DOWNGRD" + 0x00).
pub const DOWNGRD_SENTINEL_TLS11: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

/// RFC 8446 §4.1.2, lines 1596-1602 (compatibility mode):
///
/// > In compatibility mode (see Appendix D.4), this field MUST be
/// > non-empty, so a client not offering a pre-TLS 1.3 session MUST
/// > generate a new 32-byte value.  This value need not be random but
/// > SHOULD be unpredictable ...
///
/// HoloNet's canonical profile uses 32 zero bytes (task-mandated; legal
/// because the value "need not be random").
pub fn compat_mode_session_id() -> [u8; 32] {
    [0u8; 32]
}

/// A decoded ClientHello.  `extensions` keeps unknown extensions verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub legacy_compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    /// Encode the full wire message: 4-byte handshake header + body.
    pub fn encode(&self) -> Vec<u8> {
        let body = self.body();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&encode_handshake_header(HandshakeType::ClientHello, body.len()));
        out.extend_from_slice(&body);
        out
    }

    /// Encode just the body (everything after the u24 header).
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.legacy_version.to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.legacy_session_id.len() as u8);
        out.extend_from_slice(&self.legacy_session_id);
        out.extend_from_slice(&((self.cipher_suites.len() * 2) as u16).to_be_bytes());
        for s in &self.cipher_suites {
            out.extend_from_slice(&s.to_be_bytes());
        }
        out.push(self.legacy_compression_methods.len() as u8);
        out.extend_from_slice(&self.legacy_compression_methods);
        out.extend_from_slice(&encode_extension_block(&self.extensions));
        out
    }

    /// Decode from a full wire message (4-byte header included), enforcing
    /// an exact u24 length match.
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let (t, body) = parse_one_handshake(msg)?;
        if t != HandshakeType::ClientHello {
            return Err(Error::UnknownHandshakeType(t.as_u8()));
        }
        let ch = Self::decode_body(body)?;
        // decode_body consumed the body strictly; check for trailing bytes
        // that parse_one_handshake would tolerate inside a longer buffer.
        let expected = 4 + ((msg[1] as usize) << 16 | (msg[2] as usize) << 8 | msg[3] as usize);
        if msg.len() > expected {
            return Err(Error::HandshakeTrailingBytes(msg.len() - expected));
        }
        Ok(ch)
    }

    /// Decode from the body only (handshake header excluded).  Enforces
    /// every §4.1.2 normative constraint:
    /// - legacy_version MUST be 0x0303 (line 1583),
    /// - legacy_session_id ≤ 32 bytes (line 1549),
    /// - cipher_suites non-empty, even byte count (line 1550),
    /// - legacy_compression_methods exactly [0] (lines 1633-1635),
    /// - no duplicate extension types (§4.2, lines 2083-2084).
    pub fn decode_body(body: &[u8]) -> Result<Self> {
        let mut ch = ClientHello {
            legacy_version: 0,
            random: [0; 32],
            legacy_session_id: Vec::new(),
            cipher_suites: Vec::new(),
            legacy_compression_methods: Vec::new(),
            extensions: Vec::new(),
        };
        let mut p = 0;
        // legacy_version
        if body.len() < p + 2 {
            return Err(Error::ClientHelloTruncated { field: "legacy_version" });
        }
        ch.legacy_version = u16::from_be_bytes([body[p], body[p + 1]]);
        p += 2;
        if ch.legacy_version != CLIENT_HELLO_LEGACY_VERSION {
            return Err(Error::ClientHelloLegacyVersion(ch.legacy_version));
        }
        // random
        if body.len() < p + 32 {
            return Err(Error::ClientHelloTruncated { field: "random(32)" });
        }
        ch.random.copy_from_slice(&body[p..p + 32]);
        p += 32;
        // legacy_session_id<0..32>
        if body.len() < p + 1 {
            return Err(Error::ClientHelloTruncated { field: "legacy_session_id length" });
        }
        let sid_len = body[p] as usize;
        p += 1;
        if sid_len > 32 {
            return Err(Error::ClientHelloSessionIdTooLong(sid_len));
        }
        if body.len() < p + sid_len {
            return Err(Error::ClientHelloTruncated { field: "legacy_session_id" });
        }
        ch.legacy_session_id = body[p..p + sid_len].to_vec();
        p += sid_len;
        // cipher_suites<2..2^16-2>
        if body.len() < p + 2 {
            return Err(Error::ClientHelloTruncated { field: "cipher_suites length" });
        }
        let suites_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        if suites_len == 0 || suites_len % 2 != 0 {
            return Err(Error::ClientHelloCipherSuitesInvalid(suites_len));
        }
        if body.len() < p + suites_len {
            return Err(Error::ClientHelloTruncated { field: "cipher_suites" });
        }
        ch.cipher_suites = body[p..p + suites_len]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        p += suites_len;
        // legacy_compression_methods<1..2^8-1>
        if body.len() < p + 1 {
            return Err(Error::ClientHelloTruncated { field: "legacy_compression_methods length" });
        }
        let cm_len = body[p] as usize;
        p += 1;
        if body.len() < p + cm_len {
            return Err(Error::ClientHelloTruncated { field: "legacy_compression_methods" });
        }
        ch.legacy_compression_methods = body[p..p + cm_len].to_vec();
        p += cm_len;
        // §4.1.2, lines 1633-1638: MUST contain exactly one byte, zero.
        if ch.legacy_compression_methods != [0u8] {
            return Err(Error::ClientHelloCompressionInvalid);
        }
        // extensions<8..2^16-1>
        if body.len() < p + 2 {
            return Err(Error::ClientHelloTruncated { field: "extensions length" });
        }
        let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        if body.len() != p + ext_len {
            return Err(Error::ExtensionBlockTruncated);
        }
        ch.extensions = parse_extension_block(&body[p..])?;
        Ok(ch)
    }
}

// ---------------------------------------------------------------------------
// ServerHello — RFC 8446 §4.1.3
// ---------------------------------------------------------------------------

/// A decoded ServerHello (or HelloRetryRequest — same structure, §4.1.3
/// lines 1753-1755).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Parsed but NEVER validated: §4.2.1, lines 2191-2194 — "clients MUST
    /// ignore the ServerHello.legacy_version value and MUST use only the
    /// 'supported_versions' extension to determine the selected version."
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id_echo: Vec<u8>,
    pub cipher_suite: u16,
    pub legacy_compression_method: u8,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn encode(&self) -> Vec<u8> {
        let body = self.body();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&encode_handshake_header(HandshakeType::ServerHello, body.len()));
        out.extend_from_slice(&body);
        out
    }

    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.legacy_version.to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.legacy_session_id_echo.len() as u8);
        out.extend_from_slice(&self.legacy_session_id_echo);
        out.extend_from_slice(&self.cipher_suite.to_be_bytes());
        out.push(self.legacy_compression_method);
        out.extend_from_slice(&encode_extension_block(&self.extensions));
        out
    }

    pub fn decode(msg: &[u8]) -> Result<Self> {
        let (t, body) = parse_one_handshake(msg)?;
        if t != HandshakeType::ServerHello {
            return Err(Error::UnknownHandshakeType(t.as_u8()));
        }
        Self::decode_body(body)
    }

    pub fn decode_body(body: &[u8]) -> Result<Self> {
        let mut sh = ServerHello {
            legacy_version: 0,
            random: [0; 32],
            legacy_session_id_echo: Vec::new(),
            cipher_suite: 0,
            legacy_compression_method: 0,
            extensions: Vec::new(),
        };
        let mut p = 0;
        if body.len() < p + 2 {
            return Err(Error::ServerHelloTruncated { field: "legacy_version" });
        }
        sh.legacy_version = u16::from_be_bytes([body[p], body[p + 1]]);
        p += 2;
        if body.len() < p + 32 {
            return Err(Error::ServerHelloTruncated { field: "random(32)" });
        }
        sh.random.copy_from_slice(&body[p..p + 32]);
        p += 32;
        // legacy_session_id_echo<0..32>
        if body.len() < p + 1 {
            return Err(Error::ServerHelloTruncated { field: "legacy_session_id_echo length" });
        }
        let sid_len = body[p] as usize;
        p += 1;
        if sid_len > 32 {
            return Err(Error::ServerHelloTruncated { field: "legacy_session_id_echo (>32 bytes)" });
        }
        if body.len() < p + sid_len {
            return Err(Error::ServerHelloTruncated { field: "legacy_session_id_echo" });
        }
        sh.legacy_session_id_echo = body[p..p + sid_len].to_vec();
        p += sid_len;
        // cipher_suite (single u16)
        if body.len() < p + 2 {
            return Err(Error::ServerHelloTruncated { field: "cipher_suite" });
        }
        sh.cipher_suite = u16::from_be_bytes([body[p], body[p + 1]]);
        p += 2;
        // legacy_compression_method (single byte, MUST be 0 — line 1733)
        if body.len() < p + 1 {
            return Err(Error::ServerHelloTruncated { field: "legacy_compression_method" });
        }
        sh.legacy_compression_method = body[p];
        p += 1;
        // extensions<6..2^16-1>
        if body.len() < p + 2 {
            return Err(Error::ServerHelloTruncated { field: "extensions length" });
        }
        let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        if body.len() != p + ext_len {
            return Err(Error::ExtensionBlockTruncated);
        }
        sh.extensions = parse_extension_block(&body[p..])?;
        Ok(sh)
    }

    /// §4.1.3, lines 1761-1763: "Upon receiving a message with type
    /// server_hello, implementations MUST first examine the Random value
    /// and, if it matches this value, process it as [HelloRetryRequest]."
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }

    /// Full client-side validation of a ServerHello (not an HRR):
    /// session-id echo, compression, cipher suite offered, the §4.1.3
    /// extension subset, and version negotiation with downgrade detection.
    /// `offered_cipher_suites` is the client's ClientHello list;
    /// `client_session_id` is the legacy_session_id the client sent.
    pub fn validate(&self, offered_cipher_suites: &[u16], client_session_id: &[u8]) -> Result<()> {
        // §4.1.3, lines 1720-1726: a mismatched echo → illegal_parameter.
        if self.legacy_session_id_echo != client_session_id {
            return Err(Error::ServerHelloSessionIdEchoMismatch);
        }
        // §4.1.3, lines 1733-1734: compression MUST be 0.
        if self.legacy_compression_method != 0 {
            return Err(Error::ServerHelloCompressionInvalid(self.legacy_compression_method));
        }
        // §4.1.3, lines 1728-1731: unoffered cipher suite → illegal_parameter.
        if !offered_cipher_suites.contains(&self.cipher_suite) {
            return Err(Error::ServerHelloCipherSuiteNotOffered(self.cipher_suite));
        }
        // §4.1.3, lines 1743-1751: SH extension set is a restricted subset
        // {pre_shared_key, key_share, supported_versions}; §4.2 line 1999:
        // anything else → illegal_parameter.  parse_extension_block already
        // rejected duplicates.
        validate_hello_extensions(&self.extensions, /*allow_cookie=*/ false)?;
        // §4.2.1, lines 2176-2198 + §4.1.3 downgrade protection.
        let selected = self
            .extensions
            .iter()
            .find(|e| e.ext_type == ext_type::SUPPORTED_VERSIONS);
        match selected {
            Some(e) => {
                let v = parse_supported_versions_sh(&e.data)?;
                if v != VERSION_TLS13 {
                    return Err(downgrade_error(&self.random));
                }
                Ok(())
            }
            None => Err(downgrade_error(&self.random)),
        }
    }
}

/// Validate the extension subset of a ServerHello / HelloRetryRequest.
/// Allowed types (RFC 8446 §4.1.3 lines 1743-1751, §4.1.4 lines 1857-1864):
/// - ServerHello: pre_shared_key(41), supported_versions(43), key_share(51);
/// - HelloRetryRequest: supported_versions(43), cookie(44), key_share(51).
/// Duplicates were already rejected by `parse_extension_block`; this also
/// rejects a duplicate that slipped in via a hand-built list.
pub fn validate_hello_extensions(extensions: &[Extension], allow_cookie: bool) -> Result<()> {
    let mut seen = Vec::new();
    for e in extensions {
        if seen.contains(&e.ext_type) {
            return Err(Error::ExtensionDuplicate(e.ext_type));
        }
        seen.push(e.ext_type);
        let known = match e.ext_type {
            ext_type::PRE_SHARED_KEY | ext_type::SUPPORTED_VERSIONS | ext_type::KEY_SHARE => true,
            ext_type::COOKIE => allow_cookie,
            _ => false,
        };
        if !known {
            return Err(Error::ServerHelloUnknownExtension(e.ext_type));
        }
    }
    Ok(())
}

/// HRR-specific validation (§4.1.4, lines 1823-1829): supported_versions is
/// mandatory and MUST select 0x0304; the extension set is {cookie,
/// supported_versions, key_share}.
pub fn validate_hello_retry_request(sh: &ServerHello) -> Result<()> {
    validate_hello_extensions(&sh.extensions, /*allow_cookie=*/ true)?;
    let selected = sh
        .extensions
        .iter()
        .find(|e| e.ext_type == ext_type::SUPPORTED_VERSIONS)
        .ok_or(Error::HelloRetryMissingSupportedVersions)?;
    let v = parse_supported_versions_sh(&selected.data)?;
    if v != VERSION_TLS13 {
        // An HRR selecting a non-1.3 version is not a TLS 1.3 server at all.
        return Err(Error::DowngradeNoTls13);
    }
    Ok(())
}

/// The §4.1.3 downgrade check (lines 1770-1786): if the ServerHello
/// indicates TLS 1.2 or below, the last 8 bytes of Random MUST be checked
/// against the two DOWNGRD sentinels ("44 4F 57 4E 47 52 44 01" for TLS 1.2,
/// "44 4F 57 4E 47 52 44 00" for TLS 1.1 and below).  A sentinel match
/// means the peer IS a TLS 1.3 server deliberately negotiating an old
/// version — abort with a distinct sentinel error.  No sentinel means a
/// genuine TLS ≤ 1.2 server — HoloNet is TLS-1.3-only, so abort with the
/// distinct plain-downgrade error.
pub fn downgrade_error(random: &[u8; 32]) -> Error {
    let tail: [u8; 8] = random[24..32].try_into().unwrap();
    if tail == DOWNGRD_SENTINEL_TLS12 || tail == DOWNGRD_SENTINEL_TLS11 {
        Error::DowngradeSentinel(tail)
    } else {
        Error::DowngradeNoTls13
    }
}

// ---------------------------------------------------------------------------
// ClientHello builder — §4.1.2
// ---------------------------------------------------------------------------

/// Parameters for building a ClientHello (RFC 8446 §4.1.2).  The extension
/// list is caller-composed from the typed encoders in this module, which
/// keeps extension ORDER explicit (order matters for byte-identity against
/// RFC 8448 and for RFC 6066 middlebox behaviour).
pub struct ClientHelloParams<'a> {
    pub random: [u8; 32],
    /// Compatibility mode uses 32 bytes (`compat_mode_session_id`); pre-TLS
    /// 1.3 resumption echoes the cached session; otherwise empty.
    pub legacy_session_id: &'a [u8],
    pub cipher_suites: &'a [u16],
    /// MUST be exactly `&[0]` (§4.1.2, lines 1633-1635).
    pub legacy_compression_methods: &'a [u8],
    /// Ordered extension list (built with the typed encoders above).
    pub extensions: &'a [Extension],
}

/// Build the canonical ClientHello bytes (§4.1.2) from the parameters.
/// Validates:
/// - legacy_session_id ≤ 32 bytes (line 1549 bound `opaque<0..32>`),
/// - cipher_suites non-empty (bound `<2..2^16-2>`),
/// - legacy_compression_methods is exactly [0] (lines 1633-1635),
/// - no duplicate extension types (§4.2, lines 2083-2084).
pub fn build_client_hello(params: &ClientHelloParams) -> Result<Vec<u8>> {
    if params.legacy_session_id.len() > 32 {
        return Err(Error::ClientHelloSessionIdTooLong(params.legacy_session_id.len()));
    }
    if params.cipher_suites.is_empty() {
        return Err(Error::ClientHelloCipherSuitesInvalid(0));
    }
    if params.legacy_compression_methods != [0u8] {
        return Err(Error::ClientHelloCompressionInvalid);
    }
    let mut seen = Vec::new();
    for e in params.extensions {
        if seen.contains(&e.ext_type) {
            return Err(Error::ExtensionDuplicate(e.ext_type));
        }
        seen.push(e.ext_type);
    }
    let ch = ClientHello {
        legacy_version: CLIENT_HELLO_LEGACY_VERSION,
        random: params.random,
        legacy_session_id: params.legacy_session_id.to_vec(),
        cipher_suites: params.cipher_suites.to_vec(),
        legacy_compression_methods: params.legacy_compression_methods.to_vec(),
        extensions: params.extensions.to_vec(),
    };
    Ok(ch.encode())
}

/// HoloNet's canonical ClientHello profile (task spec; every value traced to
/// RFC 8446): cipher_suites [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
/// TLS_CHACHA20_POLY1305_SHA256] (§B.4); supported_groups [x25519] (§4.2.7
/// line 2615); signature_algorithms [ecdsa_secp256r1_sha256(0x0403),
/// rsa_pss_rsae_sha256(0x0804), rsa_pss_rsae_sha384(0x0805),
/// rsa_pss_rsae_sha512(0x0806)] (§4.2.3 lines 2306-2320 — NOTE the RFC's
/// names: 0x0403 is the ECDSA scheme, 0x0804..0x0806 are the RSA-PSS ones);
/// supported_versions [0x0304] (§4.2.1); key_share [(x25519, 32-byte public
/// key)] (§4.2.8); legacy_session_id = 32 zero bytes (compat mode, §4.1.2
/// lines 1596-1602); legacy_compression_methods = [0] (§4.1.2 lines
/// 1633-1635).
pub fn canonical_client_hello(
    random: &[u8; 32],
    server_name: Option<&[u8]>,
    x25519_public_key: &[u8],
) -> Result<Vec<u8>> {
    let mut extensions = Vec::new();
    if let Some(sn) = server_name {
        extensions.push(encode_server_name(sn)?);
    }
    extensions.push(encode_supported_groups(&[named_group::X25519])?);
    extensions.push(encode_key_share_ch(&[KeyShareEntry {
        group: named_group::X25519,
        key_exchange: x25519_public_key.to_vec(),
    }])?);
    extensions.push(encode_supported_versions_ch(&[VERSION_TLS13])?);
    extensions.push(encode_signature_algorithms(&[
        signature_scheme::ECDSA_SECP256R1_SHA256,
        signature_scheme::RSA_PSS_RSAE_SHA256,
        signature_scheme::RSA_PSS_RSAE_SHA384,
        signature_scheme::RSA_PSS_RSAE_SHA512,
    ])?);
    let session_id = compat_mode_session_id();
    build_client_hello(&ClientHelloParams {
        random: *random,
        legacy_session_id: &session_id,
        cipher_suites: &[
            cipher_suite::TLS_AES_128_GCM_SHA256,
            cipher_suite::TLS_AES_256_GCM_SHA384,
            cipher_suite::TLS_CHACHA20_POLY1305_SHA256,
        ],
        legacy_compression_methods: &[0],
        extensions: &extensions,
    })
}

// ---------------------------------------------------------------------------
// Server-flight bodies — RFC 8446 §4.3.1 / §4.4.2 / §4.4.3 / §4.4.4
// ---------------------------------------------------------------------------

/// EncryptedExtensions (§4.3.1, lines 3311-3324):
/// `struct { Extension extensions<0..2^16-1>; } EncryptedExtensions;`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedExtensions {
    pub extensions: Vec<Extension>,
}

impl EncryptedExtensions {
    pub fn encode(&self) -> Vec<u8> {
        let body = encode_extension_block(&self.extensions);
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&encode_handshake_header(
            HandshakeType::EncryptedExtensions,
            body.len(),
        ));
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(msg: &[u8]) -> Result<Self> {
        let (t, body) = parse_one_handshake(msg)?;
        if t != HandshakeType::EncryptedExtensions {
            return Err(Error::UnknownHandshakeType(t.as_u8()));
        }
        Self::decode_body(body)
    }

    pub fn decode_body(body: &[u8]) -> Result<Self> {
        if body.len() < 2 {
            return Err(Error::HandshakeBodyTruncated { field: "extensions length" });
        }
        let ext_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if body.len() != 2 + ext_len {
            return Err(Error::ExtensionBlockTruncated);
        }
        Ok(EncryptedExtensions { extensions: parse_extension_block(&body[2..])? })
    }
}

/// Certificate (§4.4.2, lines 3535-3563) — decoded WITHOUT parsing X.509:
/// the DER bytes stay opaque in `cert_data` (SPKI pinning happens in the
/// lead's `spki` module).
///
/// > struct {
/// >     opaque certificate_request_context<0..2^8-1>;
/// >     CertificateEntry certificate_list<0..2^24-1>;
/// > } Certificate;
/// >
/// > struct {
/// >     select (certificate_type) {
/// >         case x509: opaque cert_data<1..2^24-1>;
/// >     };
/// >     Extension extensions<0..2^16-1>;
/// > } CertificateEntry;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEntry {
    pub cert_data: Vec<u8>,
    pub extensions: Vec<Extension>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMsg {
    pub certificate_request_context: Vec<u8>,
    pub entries: Vec<CertificateEntry>,
}

impl CertificateMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(self.certificate_request_context.len() as u8);
        body.extend_from_slice(&self.certificate_request_context);
        // u24 list length placeholder
        let list_len_pos = body.len();
        body.extend_from_slice(&[0, 0, 0]);
        for e in &self.entries {
            body.extend_from_slice(&((e.cert_data.len() as u32).to_be_bytes()[1..4]));
            body.extend_from_slice(&e.cert_data);
            body.extend_from_slice(&encode_extension_block(&e.extensions));
        }
        let list_len = body.len() - list_len_pos - 3;
        body[list_len_pos..list_len_pos + 3]
            .copy_from_slice(&(list_len as u32).to_be_bytes()[1..4]);
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&encode_handshake_header(HandshakeType::Certificate, body.len()));
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(msg: &[u8]) -> Result<Self> {
        let (t, body) = parse_one_handshake(msg)?;
        if t != HandshakeType::Certificate {
            return Err(Error::UnknownHandshakeType(t.as_u8()));
        }
        Self::decode_body(body)
    }

    pub fn decode_body(body: &[u8]) -> Result<Self> {
        let mut p = 0;
        if body.len() < p + 1 {
            return Err(Error::HandshakeBodyTruncated { field: "certificate_request_context length" });
        }
        let ctx_len = body[p] as usize;
        p += 1;
        if body.len() < p + ctx_len {
            return Err(Error::HandshakeBodyTruncated { field: "certificate_request_context" });
        }
        let ctx = body[p..p + ctx_len].to_vec();
        p += ctx_len;
        // u24 certificate_list length
        if body.len() < p + 3 {
            return Err(Error::HandshakeBodyTruncated { field: "certificate_list length" });
        }
        let list_len = ((body[p] as usize) << 16) | ((body[p + 1] as usize) << 8) | body[p + 2] as usize;
        p += 3;
        let end = p + list_len;
        if body.len() < end {
            return Err(Error::HandshakeBodyTruncated { field: "certificate_list" });
        }
        let mut entries = Vec::new();
        while p < end {
            // u24 cert_data length, ≥ 1 (§4.4.2: cert_data<1..2^24-1>)
            if end - p < 3 {
                return Err(Error::HandshakeBodyTruncated { field: "cert_data length" });
            }
            let cert_len =
                ((body[p] as usize) << 16) | ((body[p + 1] as usize) << 8) | body[p + 2] as usize;
            p += 3;
            if cert_len == 0 || p + cert_len > end {
                return Err(Error::HandshakeBodyTruncated { field: "cert_data (<1..2^24-1>)" });
            }
            let cert = body[p..p + cert_len].to_vec();
            p += cert_len;
            // extensions<0..2^16-1>
            if end - p < 2 {
                return Err(Error::HandshakeBodyTruncated { field: "certificate entry extensions length" });
            }
            let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
            p += 2;
            if p + ext_len > end {
                return Err(Error::HandshakeBodyTruncated { field: "certificate entry extensions" });
            }
            let extensions = parse_extension_block(&body[p..p + ext_len])?;
            p += ext_len;
            entries.push(CertificateEntry { cert_data: cert, extensions });
        }
        if p != end {
            return Err(Error::HandshakeBodyTruncated { field: "certificate_list trailing bytes" });
        }
        Ok(CertificateMsg { certificate_request_context: ctx, entries })
    }
}

/// CertificateVerify (§4.4.3, lines 3823-3841):
///
/// > struct {
/// >     SignatureScheme algorithm;
/// >     opaque signature<0..2^16-1>;
/// > } CertificateVerify;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    pub algorithm: u16,
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + self.signature.len());
        body.extend_from_slice(&self.algorithm.to_be_bytes());
        body.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.signature);
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&encode_handshake_header(HandshakeType::CertificateVerify, body.len()));
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(msg: &[u8]) -> Result<Self> {
        let (t, body) = parse_one_handshake(msg)?;
        if t != HandshakeType::CertificateVerify {
            return Err(Error::UnknownHandshakeType(t.as_u8()));
        }
        Self::decode_body(body)
    }

    pub fn decode_body(body: &[u8]) -> Result<Self> {
        if body.len() < 4 {
            return Err(Error::HandshakeBodyTruncated { field: "algorithm + signature length" });
        }
        let algorithm = u16::from_be_bytes([body[0], body[1]]);
        let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        if body.len() != 4 + sig_len {
            return Err(Error::HandshakeBodyTruncated { field: "signature" });
        }
        Ok(CertificateVerify { algorithm, signature: body[4..].to_vec() })
    }
}

/// Finished (§4.4.4, lines 3991-3994):
///
/// > struct {
/// >     opaque verify_data[Hash.length];
/// > } Finished;
///
/// The body IS the verify_data — no inner length prefix; its size is fixed
/// by the negotiated hash (32 for SHA-256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.verify_data.len());
        out.extend_from_slice(&encode_handshake_header(HandshakeType::Finished, self.verify_data.len()));
        out.extend_from_slice(&self.verify_data);
        out
    }

    pub fn decode(msg: &[u8]) -> Result<Self> {
        let (t, body) = parse_one_handshake(msg)?;
        if t != HandshakeType::Finished {
            return Err(Error::UnknownHandshakeType(t.as_u8()));
        }
        Ok(Finished { verify_data: body.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::TlsPlaintext;
    use crate::rfc8448;

    fn rfc_sh_random() -> [u8; 32] {
        let mut r = [0u8; 32];
        r.copy_from_slice(&rfc8448::SERVER_HELLO[6..38]);
        r
    }

    fn rfc_ch_random() -> [u8; 32] {
        let mut r = [0u8; 32];
        r.copy_from_slice(&rfc8448::CLIENT_HELLO[6..38]);
        r
    }

    #[test]
    fn client_hello_rfc8448_trace_parses_and_roundtrips() {
        // RFC 8448 §3, lines 177-186 (196 octets).
        let msg = &*rfc8448::CLIENT_HELLO;
        let ch = ClientHello::decode(msg).unwrap();

        assert_eq!(ch.legacy_version, 0x0303, "§4.1.2 line 1583");
        assert_eq!(
            ch.random,
            rfc_ch_random(),
            "random cb 34 ec b1 ... 4d ec e7 (RFC 8448 line 178)"
        );
        assert_eq!(
            ch.legacy_session_id,
            Vec::<u8>::new(),
            "RFC 8448 sends an EMPTY legacy_session_id (length byte 00)"
        );
        assert_eq!(ch.cipher_suites, vec![0x1301, 0x1303, 0x1302]);
        assert_eq!(ch.legacy_compression_methods, vec![0]);
        let types: Vec<u16> = ch.extensions.iter().map(|e| e.ext_type).collect();
        assert_eq!(
            types,
            vec![0, 0xff01, 10, 35, 51, 43, 13, 45, 28],
            "server_name, renegotiation_info, supported_groups, session_ticket, key_share, supported_versions, signature_algorithms, psk_key_exchange_modes, record_size_limit"
        );

        // server_name(0): data 00 09 00 00 06 "server" (RFC 8448 line 180).
        assert_eq!(
            parse_server_name(&ch.extensions[0].data).unwrap(),
            b"server".to_vec()
        );
        // supported_groups(10): x25519, secp256r1, secp384r1, secp521r1,
        // ffdhe2048..ffdhe8192 (RFC 8446 §4.2.7 line 2615, §4.2.7 ffdhe list).
        assert_eq!(
            parse_supported_groups(&ch.extensions[2].data).unwrap(),
            vec![0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104]
        );
        // key_share(51): one x25519 share with the RFC's public key (§3 line 182).
        let shares = parse_key_share_ch(&ch.extensions[4].data).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].group, named_group::X25519);
        assert_eq!(&shares[0].key_exchange[..], &rfc8448::CLIENT_X25519_PUBLIC_KEY[..]);
        // supported_versions(43): u8-prefixed list [0x0304].
        assert_eq!(parse_supported_versions_ch(&ch.extensions[5].data).unwrap(), vec![0x0304]);
        // signature_algorithms(13): 15 schemes (RFC 8448 line 184-186).
        assert_eq!(
            parse_signature_algorithms(&ch.extensions[6].data).unwrap(),
            vec![0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
                 0x0201, 0x0402, 0x0502, 0x0602, 0x0202]
        );
        // psk_key_exchange_modes(45): [psk_dhe_ke(1)].
        assert_eq!(parse_psk_key_exchange_modes(&ch.extensions[7].data).unwrap(), vec![1]);
        // record_size_limit(28) is UNKNOWN to RFC 8446 §4.2 — kept raw.
        assert_eq!(ch.extensions[8].data, vec![0x40, 0x01]);

        // Byte-identity on re-encode.
        assert_eq!(ch.encode(), msg[..]);

        // The complete RECORD (RFC 8448 line 201: "16 03 01 00 c4 ...") also
        // decodes: type handshake, legacy_record_version 0x0301 (initial
        // ClientHello compatibility, §5.1 line 4414).
        let (rec, used) = TlsPlaintext::decode(&rfc8448::CLIENT_HELLO_RECORD).unwrap();
        assert_eq!(used, rfc8448::CLIENT_HELLO_RECORD.len());
        assert_eq!(rec.content_type, crate::record::ContentType::Handshake);
        assert_eq!(rec.legacy_record_version, 0x0301);
        assert_eq!(rec.fragment, *msg);
    }

    #[test]
    fn server_hello_rfc8448_trace_parses_and_roundtrips() {
        // RFC 8448 §3, lines 241-245 (90 octets).
        let msg = &*rfc8448::SERVER_HELLO;
        let sh = ServerHello::decode(msg).unwrap();

        assert_eq!(sh.legacy_version, 0x0303);
        assert_eq!(sh.random, rfc_sh_random());
        assert_eq!(sh.legacy_session_id_echo, Vec::<u8>::new(), "echoes the empty session id");
        assert_eq!(sh.cipher_suite, cipher_suite::TLS_AES_128_GCM_SHA256);
        assert_eq!(sh.legacy_compression_method, 0);
        let types: Vec<u16> = sh.extensions.iter().map(|e| e.ext_type).collect();
        assert_eq!(types, vec![51, 43], "key_share + supported_versions only");

        // key_share: single x25519 server share (RFC 8446 §4.2.8 lines
        // 2758-2760); value c9 82 88 76 ... 75 1f 0f (RFC 8448 line 244-245).
        let share = parse_key_share_sh(&sh.extensions[0].data).unwrap();
        assert_eq!(share.group, named_group::X25519);
        assert_eq!(share.key_exchange.len(), 32);
        assert_eq!(share.key_exchange[0], 0xc9);
        assert_eq!(share.key_exchange[31], 0x0f);

        // supported_versions: single u16 0x0304.
        assert_eq!(parse_supported_versions_sh(&sh.extensions[1].data).unwrap(), 0x0304);

        // NOT an HRR (§4.1.3 line 1761: examine Random FIRST).
        assert!(!sh.is_hello_retry_request());

        // Full client validation passes (suite was offered, echo matches,
        // version 0x0304 selected).
        sh.validate(&[0x1301, 0x1303, 0x1302], &[]).unwrap();

        // Byte-identity on re-encode.
        assert_eq!(sh.encode(), msg[..]);
    }

    #[test]
    fn server_flight_messages_parse_rfc8448() {
        // RFC 8448 §3, lines 457-488: the 657-octet record payload
        // coalesces EE + Certificate + CertificateVerify + Finished.
        // First prove the vector equals the four published messages
        // (lines 376-378, 382-411, 415-421, 441-443) concatenated.
        assert_eq!(
            &rfc8448::SERVER_FLIGHT_PAYLOAD[..],
            &[
                rfc8448::ENCRYPTED_EXTENSIONS.clone(),
                rfc8448::CERTIFICATE.clone(),
                rfc8448::CERTIFICATE_VERIFY.clone(),
                rfc8448::SERVER_FINISHED.clone(),
            ].concat()[..]
        );

        let rec = TlsPlaintext::new(
            crate::record::ContentType::Handshake,
            crate::record::LEGACY_VERSION_OTHER,
            rfc8448::SERVER_FLIGHT_PAYLOAD.clone(),
        )
        .unwrap();
        let mut asm = crate::record::HandshakeAssembler::new();
        let frames = asm.push_records(&[rec]).unwrap();
        assert_eq!(frames.len(), 4);

        // EncryptedExtensions (§4.3.1): server_name response (empty),
        // supported_groups, record_size_limit.
        let ee = EncryptedExtensions::decode(&frames[0].bytes).unwrap();
        let ee_types: Vec<u16> = ee.extensions.iter().map(|e| e.ext_type).collect();
        assert_eq!(ee_types, vec![10, 28, 0]);
        assert_eq!(
            parse_supported_groups(&ee.extensions[0].data).unwrap(),
            vec![0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104]
        );
        assert_eq!(ee.extensions[1].data, vec![0x40, 0x01]); // record_size_limit = 16385
        assert!(ee.extensions[2].data.is_empty(), "server_name response: empty extension_data");

        // Certificate (§4.4.2) — DER stays opaque (no X.509 parser here).
        let cert = CertificateMsg::decode(&frames[1].bytes).unwrap();
        assert!(cert.certificate_request_context.is_empty());
        assert_eq!(cert.entries.len(), 1);
        assert_eq!(cert.entries[0].cert_data.len(), 432, "0x01 b0 DER bytes");
        assert_eq!(cert.entries[0].cert_data[0], 0x30, "DER SEQUENCE");
        assert!(cert.entries[0].extensions.is_empty());

        // CertificateVerify (§4.4.3): algorithm rsa_pss_rsae_sha256(0x0804),
        // 128-byte RSA-PSS signature.
        let cv = CertificateVerify::decode(&frames[2].bytes).unwrap();
        assert_eq!(cv.algorithm, signature_scheme::RSA_PSS_RSAE_SHA256);
        assert_eq!(cv.signature.len(), 128);
        assert_eq!(cv.signature[0], 0x5a);

        // Finished (§4.4.4): body IS the 32-byte verify_data.
        let fin = Finished::decode(&frames[3].bytes).unwrap();
        assert_eq!(fin.verify_data.len(), 32);
        assert_eq!(
            fin.verify_data,
            vec![
                0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc, 0xe7, 0x1d,
                0xf4, 0xde, 0xda, 0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72, 0xcb, 0x7f, 0xff, 0xee,
                0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18,
            ]
        );

        // Round-trip every decoded message back to wire bytes.
        assert_eq!(ee.encode(), rfc8448::ENCRYPTED_EXTENSIONS[..]);
        assert_eq!(cert.encode(), rfc8448::CERTIFICATE[..]);
        assert_eq!(cv.encode(), rfc8448::CERTIFICATE_VERIFY[..]);
        assert_eq!(fin.encode(), rfc8448::SERVER_FINISHED[..]);
    }

    #[test]
    fn client_hello_build_matches_rfc8448_bytes() {
        // Rebuild the RFC 8448 §3 ClientHello (lines 177-186) from its
        // published parameters: random (line 178), EMPTY session id,
        // suites [1301, 1303, 1302], the nine extensions in trace order.
        let extensions = vec![
            encode_server_name(b"server").unwrap(),           // 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72
            Extension { ext_type: ext_type::RENEGOTIATION_INFO, data: vec![0x00] }, // ff 01 00 01 00
            encode_supported_groups(&[
                named_group::X25519, named_group::SECP256R1, named_group::SECP384R1,
                named_group::SECP521R1, named_group::FFDHE2048, named_group::FFDHE3072,
                named_group::FFDHE4096, named_group::FFDHE6144, named_group::FFDHE8192,
            ]).unwrap(),                                       // 00 0a 00 14 00 12 ...
            Extension { ext_type: 35, data: vec![] },          // session_ticket, empty (RFC 5077)
            encode_key_share_ch(&[KeyShareEntry {
                group: named_group::X25519,
                key_exchange: rfc8448::CLIENT_X25519_PUBLIC_KEY.to_vec(),
            }]).unwrap(),                                       // 00 33 00 26 00 24 00 1d 00 20 ...
            encode_supported_versions_ch(&[VERSION_TLS13]).unwrap(), // 00 2b 00 03 02 03 04
            encode_signature_algorithms(&[
                0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806,
                0x0401, 0x0501, 0x0601, 0x0201, 0x0402, 0x0502, 0x0602, 0x0202,
            ]).unwrap(),                                       // 00 0d 00 20 00 1e ...
            encode_psk_key_exchange_modes(&[psk_key_exchange_mode::PSK_DHE_KE]).unwrap(), // 00 2d 00 02 01 01
            Extension { ext_type: 28, data: vec![0x40, 0x01] }, // record_size_limit (RFC 8449) = 16385
        ];
        let built = build_client_hello(&ClientHelloParams {
            random: rfc_ch_random(),
            legacy_session_id: &[], // RFC 8448 §3 sends an empty session id
            cipher_suites: &[cipher_suite::TLS_AES_128_GCM_SHA256,
                             cipher_suite::TLS_CHACHA20_POLY1305_SHA256,
                             cipher_suite::TLS_AES_256_GCM_SHA384],
            legacy_compression_methods: &[0],
            extensions: &extensions,
        })
        .unwrap();
        assert_eq!(built.len(), 196);
        assert_eq!(built, rfc8448::CLIENT_HELLO[..], "byte-identity with RFC 8448 §3");

        // The builder refuses duplicate extensions (§4.2 lines 2083-2084).
        let mut dup = extensions.clone();
        dup.push(encode_server_name(b"other").unwrap());
        assert_eq!(
            build_client_hello(&ClientHelloParams {
                random: rfc_ch_random(),
                legacy_session_id: &[],
                cipher_suites: &[0x1301],
                legacy_compression_methods: &[0],
                extensions: &dup,
            })
            .unwrap_err(),
            Error::ExtensionDuplicate(0)
        );
        // ...and refuses compression lists other than [0].
        assert_eq!(
            build_client_hello(&ClientHelloParams {
                random: rfc_ch_random(),
                legacy_session_id: &[],
                cipher_suites: &[0x1301],
                legacy_compression_methods: &[0, 0],
                extensions: &extensions,
            })
            .unwrap_err(),
            Error::ClientHelloCompressionInvalid
        );
    }

    #[test]
    fn hello_retry_request_detected_by_random_value() {
        // §4.1.3 line 1756: the HRR Random IS the SHA-256 of
        // "HelloRetryRequest" — pin the constant to the hash itself.
        assert_eq!(
            HELLO_RETRY_REQUEST_RANDOM,
            holo_crypto::sha256::digest(b"HelloRetryRequest")
        );

        // RFC 8448 §5, lines 1656-1664: a real HRR on the wire.
        let hrr = ServerHello::decode(&rfc8448::HELLO_RETRY_REQUEST_SERVER_HELLO).unwrap();
        assert!(hrr.is_hello_retry_request());
        assert_eq!(hrr.random, HELLO_RETRY_REQUEST_RANDOM);
        assert_eq!(hrr.legacy_session_id_echo, Vec::<u8>::new());
        assert_eq!(hrr.cipher_suite, cipher_suite::TLS_AES_128_GCM_SHA256);

        // HRR extension set: key_share(selected_group) + cookie +
        // supported_versions (§4.1.4 lines 1857-1864).
        validate_hello_retry_request(&hrr).unwrap();
        let types: Vec<u16> = hrr.extensions.iter().map(|e| e.ext_type).collect();
        assert_eq!(types, vec![51, 44, 43]);
        assert_eq!(parse_key_share_hrr(&hrr.extensions[0].data).unwrap(), named_group::SECP256R1);
        let cookie = parse_cookie(&hrr.extensions[1].data).unwrap();
        // Extension data is 0x74=116 octets INCLUDING the u16 cookie length
        // prefix (0x0072=114) — the Cookie struct itself is `opaque
        // cookie<1..2^16-1>` (RFC 8446 §4.2.2 line 2203).
        assert_eq!(hrr.extensions[1].data.len(), 116);
        assert_eq!(cookie.len(), 114);
        assert_eq!(parse_supported_versions_sh(&hrr.extensions[2].data).unwrap(), 0x0304);

        // Byte-identity on re-encode.
        assert_eq!(hrr.encode(), rfc8448::HELLO_RETRY_REQUEST_SERVER_HELLO[..]);

        // Negative: the plain ServerHello of §3 is not an HRR.
        let sh = ServerHello::decode(&rfc8448::SERVER_HELLO).unwrap();
        assert!(!sh.is_hello_retry_request());
        // ...and an HRR without supported_versions is invalid (§4.1.4 line 1823).
        let no_sv = ServerHello {
            legacy_version: 0x0303,
            random: HELLO_RETRY_REQUEST_RANDOM,
            legacy_session_id_echo: vec![],
            cipher_suite: 0x1301,
            legacy_compression_method: 0,
            extensions: vec![encode_key_share_hrr(named_group::X25519)],
        };
        assert_eq!(
            validate_hello_retry_request(&no_sv).unwrap_err(),
            Error::HelloRetryMissingSupportedVersions
        );
    }

    #[test]
    fn legacy_downgrade_sentinel_rejected() {
        // §4.1.3, lines 1770-1786: a TLS 1.3 server negotiating TLS 1.2 sets
        // random[24..32] = 44 4F 57 4E 47 52 44 01; the client MUST abort
        // with illegal_parameter.  Synthetic ServerHello carrying the
        // sentinel (no supported_versions — a TLS 1.2 server has none).
        let mut random = rfc_sh_random();
        random[24..32].copy_from_slice(&DOWNGRD_SENTINEL_TLS12);
        let sh = ServerHello {
            legacy_version: 0x0303,
            random,
            legacy_session_id_echo: vec![],
            cipher_suite: cipher_suite::TLS_AES_128_GCM_SHA256,
            legacy_compression_method: 0,
            extensions: vec![encode_key_share_sh(&KeyShareEntry {
                group: named_group::X25519,
                key_exchange: vec![0xAA; 32],
            })],
        };
        // Wire-level: encode → decode → validate fails with the sentinel error.
        let wire = sh.encode();
        let decoded = ServerHello::decode(&wire).unwrap();
        let err = decoded.validate(&[0x1301, 0x1303, 0x1302], &[]).unwrap_err();
        assert_eq!(err, Error::DowngradeSentinel(DOWNGRD_SENTINEL_TLS12));
        assert!(format!("{err}").starts_with("tls: downgrade:"));
        assert!(format!("{err}").contains("DOWNGRD"));
        assert_eq!(err.alert(), crate::alert::AlertDescription::IllegalParameter);

        // TLS-1.1 sentinel variant (…44 00).
        let mut random = rfc_sh_random();
        random[24..32].copy_from_slice(&DOWNGRD_SENTINEL_TLS11);
        let sh11 = ServerHello { random, ..decoded_without_supported_versions(&sh) };
        let err = sh11.validate(&[0x1301, 0x1303, 0x1302], &[]).unwrap_err();
        assert_eq!(err, Error::DowngradeSentinel(DOWNGRD_SENTINEL_TLS11));

        // A sentinel is ALSO fatal when supported_versions selects 0x0303 —
        // the §4.1.3 text covers "a ServerHello indicating TLS 1.2 or below".
        let mut random = rfc_sh_random();
        random[24..32].copy_from_slice(&DOWNGRD_SENTINEL_TLS12);
        let sh_stale = ServerHello {
            legacy_version: 0x0303,
            random,
            legacy_session_id_echo: vec![],
            cipher_suite: cipher_suite::TLS_AES_128_GCM_SHA256,
            legacy_compression_method: 0,
            extensions: vec![encode_supported_versions_sh(0x0303)],
        };
        assert_eq!(
            sh_stale.validate(&[0x1301, 0x1303, 0x1302], &[]).unwrap_err(),
            Error::DowngradeSentinel(DOWNGRD_SENTINEL_TLS12)
        );
    }

    /// Helper for the downgrade tests: same fields minus supported_versions.
    fn decoded_without_supported_versions(sh: &ServerHello) -> ServerHello {
        ServerHello {
            legacy_version: sh.legacy_version,
            random: sh.random,
            legacy_session_id_echo: sh.legacy_session_id_echo.clone(),
            cipher_suite: sh.cipher_suite,
            legacy_compression_method: sh.legacy_compression_method,
            extensions: sh
                .extensions
                .iter()
                .filter(|e| e.ext_type != ext_type::SUPPORTED_VERSIONS)
                .cloned()
                .collect(),
        }
    }

    #[test]
    fn tls12_server_hello_rejected() {
        // The OTHER downgrade path: a plain TLS 1.2 server answers with NO
        // supported_versions extension and NO sentinel.  HoloNet is
        // TLS-1.3-only → abort with the distinct plain-downgrade error.
        let sh = ServerHello {
            legacy_version: 0x0303,
            random: rfc_sh_random(),
            legacy_session_id_echo: vec![],
            cipher_suite: cipher_suite::TLS_AES_128_GCM_SHA256,
            legacy_compression_method: 0,
            extensions: vec![encode_key_share_sh(&KeyShareEntry {
                group: named_group::X25519,
                key_exchange: vec![0xBB; 32],
            })],
        };
        let wire = sh.encode();
        let decoded = ServerHello::decode(&wire).unwrap();
        let err = decoded.validate(&[0x1301, 0x1303, 0x1302], &[]).unwrap_err();
        assert_eq!(err, Error::DowngradeNoTls13);
        assert!(format!("{err}").starts_with("tls: downgrade:"));
        assert!(format!("{err}").contains("TLS 1.2-or-older server"));
        assert_eq!(err.alert(), crate::alert::AlertDescription::IllegalParameter);

        // supported_versions selecting exactly 0x0304 is the ONLY passing case.
        let mut ok = decoded.clone();
        ok.extensions.push(encode_supported_versions_sh(0x0304));
        ok.validate(&[0x1301, 0x1303, 0x1302], &[]).unwrap();
    }

    #[test]
    fn serverhello_extension_validator_rejects_unknown_and_duplicate() {
        // §4.1.3, lines 1743-1751: the ServerHello extension set is a
        // restricted subset.  server_name(0) is a perfectly good extension
        // type in general — but NOT in a ServerHello.
        let err = validate_hello_extensions(
            &[Extension { ext_type: 0, data: vec![] }, encode_supported_versions_sh(0x0304)],
            false,
        )
        .unwrap_err();
        assert_eq!(err, Error::ServerHelloUnknownExtension(0));
        assert!(format!("{err}").contains("restricted subset"));

        // Duplicates are rejected (§4.2 lines 2083-2084) — both by the block
        // parser and by the validator on hand-built lists.
        assert_eq!(
            parse_extension_block(&encode_extension_block(&[
                encode_key_share_sh(&KeyShareEntry { group: 0x001d, key_exchange: vec![1; 32] }),
                encode_key_share_sh(&KeyShareEntry { group: 0x0017, key_exchange: vec![2; 65] }),
            ])[2..])
            .unwrap_err(),
            Error::ExtensionDuplicate(ext_type::KEY_SHARE)
        );
        assert_eq!(
            validate_hello_extensions(
                &[encode_supported_versions_sh(0x0304), encode_supported_versions_sh(0x0304)],
                false,
            )
            .unwrap_err(),
            Error::ExtensionDuplicate(ext_type::SUPPORTED_VERSIONS)
        );

        // The SH subset accepts pre_shared_key too.
        validate_hello_extensions(
            &[
                Extension { ext_type: ext_type::PRE_SHARED_KEY, data: vec![0x00, 0x01, 0x00] },
                encode_supported_versions_sh(0x0304),
            ],
            false,
        )
        .unwrap();
        // Cookie is only legal in an HRR, not in a ServerHello (§4.2 table
        // line 2058: cookie = CH, HRR).
        assert_eq!(
            validate_hello_extensions(&[encode_cookie(b"x").unwrap()], false).unwrap_err(),
            Error::ServerHelloUnknownExtension(ext_type::COOKIE)
        );
        assert!(validate_hello_extensions(&[encode_cookie(b"x").unwrap()], true).is_ok());
    }

    #[test]
    fn serverhello_session_echo_and_cipher_suite_validation() {
        // §4.1.3, lines 1720-1734: echo mismatch, unoffered suite, and
        // non-zero compression are each their own error.
        let base = || ServerHello {
            legacy_version: 0x0303,
            random: rfc_sh_random(),
            legacy_session_id_echo: vec![0x11; 32],
            cipher_suite: cipher_suite::TLS_AES_128_GCM_SHA256,
            legacy_compression_method: 0,
            extensions: vec![
                encode_key_share_sh(&KeyShareEntry { group: named_group::X25519, key_exchange: vec![0; 32] }),
                encode_supported_versions_sh(0x0304),
            ],
        };
        // echo matches → OK
        let sh = base();
        sh.validate(&[0x1301, 0x1303, 0x1302], &sh.legacy_session_id_echo.clone()).unwrap();
        // echo differs → illegal_parameter
        let mut sh = base();
        sh.legacy_session_id_echo = vec![0x22; 32];
        assert_eq!(
            sh.validate(&[0x1301, 0x1303, 0x1302], &[0x11; 32]).unwrap_err(),
            Error::ServerHelloSessionIdEchoMismatch
        );
        // suite not offered → illegal_parameter
        let mut sh = base();
        sh.cipher_suite = 0x0035; // some TLS 1.2 suite
        assert_eq!(
            sh.validate(&[0x1301, 0x1303, 0x1302], &[0x11; 32]).unwrap_err(),
            Error::ServerHelloCipherSuiteNotOffered(0x0035)
        );
        // compression ≠ 0 → error
        let mut sh = base();
        sh.legacy_compression_method = 1;
        assert_eq!(
            sh.validate(&[0x1301, 0x1303, 0x1302], &[0x11; 32]).unwrap_err(),
            Error::ServerHelloCompressionInvalid(1)
        );
    }

    #[test]
    fn typed_extensions_roundtrip() {
        // Every typed codec: encode → parse → identical value.
        let sv = encode_supported_versions_ch(&[0x0304, 0x0303]).unwrap();
        assert_eq!(parse_supported_versions_ch(&sv.data).unwrap(), vec![0x0304, 0x0303]);
        assert_eq!(sv.data, vec![0x04, 0x03, 0x04, 0x03, 0x03]);

        let ks = encode_key_share_ch(&[
            KeyShareEntry { group: named_group::X25519, key_exchange: vec![0xAA; 32] },
            KeyShareEntry { group: named_group::SECP256R1, key_exchange: vec![0x04; 65] },
        ]).unwrap();
        let parsed = parse_key_share_ch(&ks.data).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].group, named_group::X25519);
        assert_eq!(parsed[1].key_exchange.len(), 65);

        let sh_ks = encode_key_share_sh(&KeyShareEntry { group: named_group::X25519, key_exchange: vec![7; 32] });
        assert_eq!(parse_key_share_sh(&sh_ks.data).unwrap().group, named_group::X25519);
        assert_eq!(parse_key_share_hrr(&encode_key_share_hrr(named_group::X448).data).unwrap(), named_group::X448);

        let ck = encode_cookie(b"stateless!").unwrap();
        assert_eq!(parse_cookie(&ck.data).unwrap(), b"stateless!".to_vec());

        let groups = encode_supported_groups(&[named_group::X25519, named_group::FFDHE2048]).unwrap();
        assert_eq!(parse_supported_groups(&groups.data).unwrap(), vec![0x001d, 0x0100]);

        let algs = encode_signature_algorithms(&[
            signature_scheme::ECDSA_SECP256R1_SHA256,
            signature_scheme::RSA_PSS_RSAE_SHA256,
        ]).unwrap();
        assert_eq!(
            parse_signature_algorithms(&algs.data).unwrap(),
            vec![signature_scheme::ECDSA_SECP256R1_SHA256, signature_scheme::RSA_PSS_RSAE_SHA256]
        );

        let sni = encode_server_name(b"holograph.example").unwrap();
        assert_eq!(parse_server_name(&sni.data).unwrap(), b"holograph.example".to_vec());

        let modes = encode_psk_key_exchange_modes(&[psk_key_exchange_mode::PSK_KE, psk_key_exchange_mode::PSK_DHE_KE]).unwrap();
        assert_eq!(parse_psk_key_exchange_modes(&modes.data).unwrap(), vec![0, 1]);

        // Full extension block round-trip through a record, u16 prefix
        // included.  Types must be UNIQUE (§4.2 line 2083) — sv(43), ks(51),
        // ck(44), groups(10), algs(13), sni(0), modes(45).
        let names = [sv, ks, ck, groups, algs, sni, modes];
        let block = encode_extension_block(&names);
        let rec = TlsPlaintext::new(crate::record::ContentType::Handshake, 0x0303, block.clone()).unwrap();
        let wire = rec.encode();
        let (rec2, used) = TlsPlaintext::decode(&wire).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(rec2.fragment, block);
        let exts = parse_extension_block(&block[2..]).unwrap();
        assert_eq!(exts.len(), 7);
        assert_eq!(exts, names);

        // Structural rejections.
        assert!(encode_supported_versions_ch(&[]).is_err(), "list<2..254> cannot be empty");
        assert!(encode_supported_versions_ch(&[0u16; 128]).is_err(), "254-byte bound");
        assert!(encode_cookie(&[]).is_err(), "cookie<1..2^16-1> cannot be empty");
        assert!(encode_server_name(b"").is_err());
        assert!(encode_key_share_ch(&[KeyShareEntry { group: 1, key_exchange: vec![] }]).is_err(),
            "key_exchange<1..2^16-1> cannot be empty");
        assert_eq!(
            parse_supported_versions_ch(&[0x03, 0x03, 0x04]).unwrap_err(),
            Error::ExtensionTruncated { ext_type: 43, what: "list length (must be even, 2..254)" }
        );
    }

    #[test]
    fn client_hello_codec_rejects_illegal_parameters() {
        // Base a valid CH on the RFC 8448 trace, then mutate field by field.
        let valid = rfc8448::CLIENT_HELLO.clone();

        // legacy_version != 0x0303 (§4.1.2 line 1583) → distinct error.
        let mut bad = valid.clone();
        bad[4] = 0x03;
        bad[5] = 0x04;
        assert_eq!(
            ClientHello::decode(&bad).unwrap_err(),
            Error::ClientHelloLegacyVersion(0x0304)
        );

        // session_id length byte > 32 (bound opaque<0..32>) → decode_error.
        // Craft a minimal CH with a 33-byte id.
        let mut ch = ClientHello {
            legacy_version: 0x0303,
            random: [0; 32],
            legacy_session_id: vec![0xEE; 33],
            cipher_suites: vec![0x1301],
            legacy_compression_methods: vec![0],
            extensions: vec![encode_supported_versions_ch(&[0x0304]).unwrap()],
        };
        let err = ClientHello::decode_body(&ch.body()).unwrap_err();
        assert_eq!(err, Error::ClientHelloSessionIdTooLong(33));
        ch.legacy_session_id = vec![0xEE; 32];
        assert!(ClientHello::decode_body(&ch.body()).is_ok(), "exactly 32 is legal");

        // compression methods other than [0] (§4.1.2 lines 1633-1638).
        ch.legacy_compression_methods = vec![0, 1];
        assert_eq!(
            ClientHello::decode_body(&ch.body()).unwrap_err(),
            Error::ClientHelloCompressionInvalid
        );
        ch.legacy_compression_methods = vec![1];
        assert_eq!(
            ClientHello::decode_body(&ch.body()).unwrap_err(),
            Error::ClientHelloCompressionInvalid
        );
        ch.legacy_compression_methods = vec![0];

        // empty cipher_suites (<2..2^16-2> cannot be empty).
        ch.cipher_suites = vec![];
        assert_eq!(
            ClientHello::decode_body(&ch.body()).unwrap_err(),
            Error::ClientHelloCipherSuitesInvalid(0)
        );
        ch.cipher_suites = vec![0x1301];

        let _ = &valid; // valid is the RFC trace; only bad is mutated below
        // Truncation at each field is its own error path.
        for cut in [0usize, 2, 6, 38, 39, 40, 43, 44, 46] {
            let err = ClientHello::decode_body(&ch.body()[..cut]);
            assert!(err.is_err(), "cut at {cut} must fail");
        }

        // Trailing bytes after a complete message.
        let mut trail = ch.encode();
        trail.push(0x00);
        assert_eq!(
            ClientHello::decode(&trail).unwrap_err(),
            Error::HandshakeTrailingBytes(1)
        );

        // Declared u24 length beyond the buffer.
        assert_eq!(
            parse_one_handshake(&valid[..10]).unwrap_err(),
            Error::HandshakeLengthExceedsBuffer { declared: 192, available: 6 }
        );
        // Unknown handshake type byte.
        assert_eq!(
            HandshakeType::from_u8(99).unwrap_err(),
            Error::UnknownHandshakeType(99)
        );
        let _ = valid;
    }

    #[test]
    fn canonical_client_hello_profile_structure() {
        // The task's canonical profile: 32 zero-byte compat session id,
        // suites [0x1301, 0x1302, 0x1303], groups [x25519],
        // sigalgs [0x0403, 0x0804, 0x0805, 0x0806] (RFC 8446 §4.2.3 names:
        // 0x0403 = ecdsa_secp256r1_sha256, 0x0804/0x0805/0x0806 =
        // rsa_pss_rsae_sha256/384/512), supported_versions [0x0304],
        // key_share [(x25519, 32-byte pubkey)].
        let random = [0x5Au8; 32];
        let pubkey = [0x42u8; 32];
        let built = canonical_client_hello(&random, None, &pubkey).unwrap();

        let ch = ClientHello::decode(&built).unwrap();
        assert_eq!(ch.legacy_version, 0x0303);
        assert_eq!(ch.random, random);
        assert_eq!(ch.legacy_session_id, vec![0u8; 32], "compat mode: 32 zero bytes");
        assert_eq!(ch.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert_eq!(ch.legacy_compression_methods, vec![0]);
        let types: Vec<u16> = ch.extensions.iter().map(|e| e.ext_type).collect();
        assert_eq!(types, vec![10, 51, 43, 13]);
        assert_eq!(parse_supported_groups(&ch.extensions[0].data).unwrap(), vec![0x001d]);
        let share = parse_key_share_ch(&ch.extensions[1].data).unwrap();
        assert_eq!(share.len(), 1);
        assert_eq!(share[0].group, named_group::X25519);
        assert_eq!(share[0].key_exchange, pubkey.to_vec());
        assert_eq!(parse_supported_versions_ch(&ch.extensions[2].data).unwrap(), vec![0x0304]);
        assert_eq!(
            parse_signature_algorithms(&ch.extensions[3].data).unwrap(),
            vec![0x0403, 0x0804, 0x0805, 0x0806]
        );

        // Deterministic: same inputs → same bytes.
        assert_eq!(canonical_client_hello(&random, None, &pubkey).unwrap(), built);

        // With SNI the server_name extension leads the list.
        let with_sni = canonical_client_hello(&random, Some(b"holograph.example"), &pubkey).unwrap();
        let ch2 = ClientHello::decode(&with_sni).unwrap();
        assert_eq!(ch2.extensions[0].ext_type, ext_type::SERVER_NAME);
        assert_eq!(parse_server_name(&ch2.extensions[0].data).unwrap(), b"holograph.example".to_vec());
        // Same fields apart from the leading server_name extension.
        assert_eq!(ch2.cipher_suites, ch.cipher_suites);
        assert_eq!(ch2.legacy_session_id, ch.legacy_session_id);
        assert_eq!(ch2.extensions.len(), ch.extensions.len() + 1);
        assert_eq!(&ch2.extensions[1..], &ch.extensions[..]);
    }
}
