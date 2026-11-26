//! Minimal TLS 1.3 LOOPBACK TEST SERVER (RFC 8446) — holo-tls-internal test
//! infrastructure, shipped in the crate so the e2e tests of
//! [`crate::client`] can run against a real `std::net::TcpStream` peer.
//!
//! NOT a production server: it implements exactly the flight the HoloNet
//! client needs for acceptance testing — one `ClientHello` (optionally one
//! HelloRetryRequest round trip), `EncryptedExtensions` (empty),
//! `Certificate` (the embedded RSA-2048 loopback fixture), `CertificateVerify`
//! (signed LIVE with the fixture's private exponent via
//! `holo_crypto::rsa_sign`), the server `Finished`, verification of the
//! client's `Finished`, and then an application-data ECHO loop.
//!
//! The CLIENT side treats this fixture exactly like any pinned server —
//! there is no special-casing anywhere in `client.rs`: the caller supplies
//! the SPKI pin and the expected hostname as usual.
//!
//! Deterministic-failure seams (constructor flags, documented per the task):
//!
//! - `force_hrr`       — send a HelloRetryRequest carrying a fresh `cookie`
//!                       and force the client to re-send a SECOND ClientHello
//!                       with a NEW x25519 key share (§4.1.4 path).
//! - `corrupt_finished`— flip one bit of the server Finished verify_data so
//!                       the client's transcript/keys mismatch is exercised.
//! - `wrong_sig_blob`  — sign the CertificateVerify over the WRONG context
//!                       string ("TLS 1.3, client CertificateVerify") so the
//!                       client's §4.4.3 verification fails.
//! - `use_pkcs1`       — sign CertificateVerify with rsa_pkcs1_sha256
//!                       (0x0401, RFC 8446 §B.2) instead of the default
//!                       rsa_pss_rsae_sha256 (0x0804).
//!
//! Charter context (quoted from `spki.rs` module docs, batch 1): "By design
//! there is NO chain building and NO certificate-signature verification in
//! this module: pinning REPLACES chain validation (the pin is the trust
//! anchor; the peer must present the pinned key)."  The loopback server
//! therefore sends ONE certificate and no chain.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::OnceLock;

use holo_crypto::rsa_sign;
use holo_crypto::sha256;

use crate::client::{
    certificate_verify_signed_blob, open_record, seal_record, AeadAlg, ClientError, OsEntropy,
    ReadKeys, WriteKeys, CLIENT_CERTIFICATE_VERIFY_CONTEXT,
};
use crate::handshake::{
    self, cipher_suite, ext_type, named_group, signature_scheme, CertificateEntry, CertificateMsg,
    ClientHello, EncryptedExtensions, Finished, ServerHello,
};
use crate::record::{self, ContentType, HandshakeAssembler, HandshakeFrame, LEGACY_VERSION_OTHER};
use crate::schedule;
use crate::transcript::{message_hash_synthetic, transcript_hash};
use crate::Error as CodecError;

// ---------------------------------------------------------------------------
// Embedded RSA-2048 loopback fixture — verbatim copies of the python-generated
// batch-1 constants (see `spki.rs` tests: `fixgen.py`, python3-cryptography
// 44.0.3; self-signed PKCS#1-v1.5-SHA256 RSA-2048, validity 2025..2035, SANs:
// dNSName "localhost" + iPAddress 127.0.0.1).  Batch-1 pins the key/cert
// consistency (test `spki::tests::loopback_key_crt_components_are_consistent`)
// and the pin value (test `spki::tests::spki_pin_matches_python_computed_hash`).
// The SPKI pin of this certificate is
//   7249efe8b51d96f4ed9b04e848e927ce7b9834ee927fe55887d551b1fcb51666
// and is computed AT RUNTIME by the tests via `spki::spki_pin_sha256` (never
// hard-coded at the call site, so the fixture and pin can never drift apart).
// ---------------------------------------------------------------------------

/// The loopback end-entity certificate, DER (hex).
pub const LOOPBACK_CERT_DER_HEX: &str = "308202ec308201d4a00302010202145caeb5d5b7a80777cd1f1a7323d9eea9c92e7ba4300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100bdb003b9e5520156d25e9b5de74d13273961b39e252a4186a80ac5314ca808d46ede147508b1612e0d85bd9364de5df09f207639c42cf9a9a8dab2e1fe4e9aa28131e70d4abce857b751742121d1b824b92f91113bb1bba76dc45d7cc9f7299fe6789a7e9e8349a378849688b14201e4824378af233b5f6ba1f1df345ef43ebfc126d290047d95276aabc2734466591bb86c768308e4554cc9feedb001ed51066e7d709e668f96d71ac68847d662c9067341c77ad90633a695fdaeeadc0674d93e78840cbe01a633dea50e79635afe27850fc1c90f5f701914790f1144caaf6e75de3291ca764e6c53f4f2c881cdfb61f876254242655c29c2d308b93a30caa90203010001a31e301c301a0603551d110413301182096c6f63616c686f737487047f000001300d06092a864886f70d01010b05000382010100210e3d7c95b95a29935547963dc88676feebd60994b52a8e9f60f4291a8c24c20306730578f184b709e1b8671d5eb70547ff34dcb17244a5877bd06ab410beec9eafebcc8edbba1e966f47a14df09838cc7f56209a4403ceeb85e0016f2972840693bfb78514bae208640814a7ac40857410e5565d06374529e71864cbf444969e98fb51cff0c359a8af7698a3210a752137709c35a8827afafdc896257a13a06b3aafab65507f245595c15ea057032083b77b5338c0114b5adf57ede1e1c15e721ae1f6b6c6f1bbb12fbe81a745afd22a16ca03c6634014525a8aee968d0c0ad4b1e70adf71c24ad1ef8fb035a4dbe5370b79723b97ffd59f5c13fa91461ef4";

/// Loopback RSA modulus `n` (big-endian, 256 octets) — matches the
/// certificate's SubjectPublicKeyInfo (pinned by batch-1 tests).
pub const LOOPBACK_RSA_N_HEX: &str = "bdb003b9e5520156d25e9b5de74d13273961b39e252a4186a80ac5314ca808d46ede147508b1612e0d85bd9364de5df09f207639c42cf9a9a8dab2e1fe4e9aa28131e70d4abce857b751742121d1b824b92f91113bb1bba76dc45d7cc9f7299fe6789a7e9e8349a378849688b14201e4824378af233b5f6ba1f1df345ef43ebfc126d290047d95276aabc2734466591bb86c768308e4554cc9feedb001ed51066e7d709e668f96d71ac68847d662c9067341c77ad90633a695fdaeeadc0674d93e78840cbe01a633dea50e79635afe27850fc1c90f5f701914790f1144caaf6e75de3291ca764e6c53f4f2c881cdfb61f876254242655c29c2d308b93a30caa9";

/// Loopback RSA public exponent `e` = 65537 (010001).
pub const LOOPBACK_RSA_E_HEX: &str = "010001";

/// Loopback RSA private exponent `d` (big-endian, 256 octets) — the TEST-ONLY
/// signing key material.  This is a fixture, not a production credential:
/// it lives in the crate so the loopback server can sign CertificateVerify
/// messages with `holo_crypto::rsa_sign` exactly like a real server would.
pub const LOOPBACK_RSA_D_HEX: &str = "01d85bf8eb73a442b1722d25b931c53d6ceff7dcd274ba45728e04440a005a71a29073777df9a7bdd870d41ac270ed4e016641f026e9df15d8e823b4521276ab9d011cc3c2d5da96bbd8457e6b034cbcc2b6653d5b2ccbec0183d6faf745f9b82df83f5c7af340fc9f97fe94ded08b0f2b7b3789d0986bc1b2c6150b3fdf355b08d32144f0b06fa193760e2e6f12e822881df36458f29e130cbb663b961e14045741e883320db2e728f8684a9108e2072b2ad0947238d9f2e8a4e07c30b6ed4e0a4b8fa20ea8fc502066e7cc77496a273fb7c1085f0691885d425e6b07176444836d8b3ae7e94762322128b3a2a3f39ba1eaf99ced983a4491ce2ccc9942c597";

fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0, "fixture hex must be even-length");
    (0..b.len())
        .step_by(2)
        .map(|i| {
            let hi = (b[i] as char).to_digit(16).expect("fixture hex digit");
            let lo = (b[i + 1] as char).to_digit(16).expect("fixture hex digit");
            ((hi << 4) | lo) as u8
        })
        .collect()
}

// OnceLock, not LazyLock: LazyLock stabilized in Rust 1.80 and the workspace
// MSRV floor is 1.77.2 (the Win7/Catalina CI canary enforces it — found by
// that canary on the first batch-2 push).
/// Decoded fixture certificate DER.
static LOOPBACK_CERT_DER: OnceLock<Vec<u8>> = OnceLock::new();
/// Decoded fixture RSA modulus.
static LOOPBACK_RSA_N: OnceLock<Vec<u8>> = OnceLock::new();
/// Decoded fixture RSA private exponent (TEST-ONLY material).
static LOOPBACK_RSA_D: OnceLock<Vec<u8>> = OnceLock::new();

pub(crate) fn loopback_cert_der() -> &'static [u8] {
    LOOPBACK_CERT_DER.get_or_init(|| unhex(LOOPBACK_CERT_DER_HEX))
}
pub(crate) fn loopback_rsa_n() -> &'static [u8] {
    LOOPBACK_RSA_N.get_or_init(|| unhex(LOOPBACK_RSA_N_HEX))
}
pub(crate) fn loopback_rsa_d() -> &'static [u8] {
    LOOPBACK_RSA_D.get_or_init(|| unhex(LOOPBACK_RSA_D_HEX))
}

// ---------------------------------------------------------------------------
// Errors — every failure stage a distinct "tls: server(loopback): ..." string
// ---------------------------------------------------------------------------

/// Loopback-server failure.  Tests drive the CLIENT and assert on the
/// client's errors; the server's own error is surfaced through the thread
/// join handle when a test wants to inspect it.
#[derive(Debug)]
pub enum ServerError {
    Io(std::io::Error),
    /// Codec/record-layer failure (the inner string is the codec's own
    /// distinct `tls: ...` message).
    Codec(CodecError),
    /// Entropy source failure — fail-closed, never a weak fallback.
    Entropy(std::io::Error),
    /// §7.1 key-schedule rejection (e.g. the §7.4.1 all-zero DH guard).
    KeySchedule(String),
    /// The computed x25519 shared secret is the all-zero value.
    SharedSecretNotContributory,
    /// The ClientHello could not be decoded.
    ClientHelloDecode(CodecError),
    /// The negotiated suite is not one of the three implemented ones.
    UnsupportedCipherSuite(u16),
    /// The configured suite was not in the client's offer.
    SuiteNotOffered(u16),
    /// No x25519 key share in the ClientHello.
    MissingClientKeyShare,
    /// The client's key share is not 32 bytes.
    BadClientKeyShare(usize),
    /// The client did not echo the HRR cookie verbatim (§4.1.4).
    HrrCookieMismatch,
    /// The client re-sent the SAME key share after the HelloRetryRequest —
    /// §4.1.4 requires a fresh share for the re-negotiated group.
    HrrKeyShareNotRefreshed,
    /// AEAD open of a client record failed (bad_record_mac, §5.2).
    AeadOpen(&'static str),
    /// A client record carried something other than Handshake/Alert/app data.
    UnexpectedRecord(u8),
    /// The client Finished verify_data did not match (§4.4.4 decrypt_error).
    ClientFinishedMismatch,
    /// The live CertificateVerify signing failed (fixture/signature path).
    CertSignFailed(String),
    /// The client sent a (fatal) alert mid-handshake.
    ClientAlert(String),
    /// A crate-internal plumbing error surfaced while mapping a client-side
    /// record error — reported verbatim.
    Plumbing(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Io(e) => write!(f, "tls: server(loopback): io: {e}"),
            ServerError::Codec(e) => write!(f, "tls: server(loopback): codec: {e}"),
            ServerError::Entropy(e) => write!(
                f,
                "tls: server(loopback): entropy: {e} — fail-closed (no weak fallback)"
            ),
            ServerError::KeySchedule(s) => {
                write!(f, "tls: server(loopback): key schedule: {s}")
            }
            ServerError::SharedSecretNotContributory => write!(
                f,
                "tls: server(loopback): x25519: shared secret is the all-zero value (RFC 8446 §7.4.1: MUST abort)"
            ),
            ServerError::ClientHelloDecode(e) => {
                write!(f, "tls: server(loopback): clienthello decode: {e}")
            }
            ServerError::UnsupportedCipherSuite(s) => write!(
                f,
                "tls: server(loopback): cipher suite 0x{s:04x} is not one of the three implemented suites"
            ),
            ServerError::SuiteNotOffered(s) => write!(
                f,
                "tls: server(loopback): configured suite 0x{s:04x} was not offered by the client"
            ),
            ServerError::MissingClientKeyShare => {
                write!(f, "tls: server(loopback): client sent no x25519 key share")
            }
            ServerError::BadClientKeyShare(n) => write!(
                f,
                "tls: server(loopback): client key share is {n} bytes (x25519 requires 32)"
            ),
            ServerError::HrrCookieMismatch => write!(
                f,
                "tls: server(loopback): the second ClientHello did not echo the HelloRetryRequest cookie verbatim (RFC 8446 §4.1.4)"
            ),
            ServerError::HrrKeyShareNotRefreshed => write!(
                f,
                "tls: server(loopback): the second ClientHello reused the pre-HRR key share (RFC 8446 §4.1.4 requires a fresh share)"
            ),
            ServerError::AeadOpen(e) => write!(
                f,
                "tls: server(loopback): record: AEAD open failed: {e} — bad_record_mac (RFC 8446 §5.2)"
            ),
            ServerError::UnexpectedRecord(t) => write!(
                f,
                "tls: server(loopback): unexpected record content type 0x{t:02x}"
            ),
            ServerError::ClientFinishedMismatch => write!(
                f,
                "tls: server(loopback): client Finished verify_data mismatch (RFC 8446 §4.4.4: decrypt_error)"
            ),
            ServerError::CertSignFailed(e) => {
                write!(f, "tls: server(loopback): certificateverify signing failed: {e}")
            }
            ServerError::ClientAlert(s) => {
                write!(f, "tls: server(loopback): client sent alert {s}")
            }
            ServerError::Plumbing(s) => {
                write!(f, "tls: server(loopback): plumbing: {s}")
            }
        }
    }
}

impl std::error::Error for ServerError {}

impl From<CodecError> for ServerError {
    fn from(e: CodecError) -> Self {
        ServerError::Codec(e)
    }
}

// ---------------------------------------------------------------------------
// LoopbackServer
// ---------------------------------------------------------------------------

/// The loopback TLS 1.3 test server.  Binds 127.0.0.1:0 (OS-assigned port).
/// See the module docs for the seam flags.
pub struct LoopbackServer {
    listener: TcpListener,
    /// Force the HelloRetryRequest path (§4.1.4): the server answers the
    /// first ClientHello with an HRR carrying a cookie, then expects a
    /// second ClientHello with a FRESH key share.
    pub force_hrr: bool,
    /// Flip one bit of the server Finished verify_data (deterministic
    /// transcript-mismatch injection).
    pub corrupt_finished: bool,
    /// Sign CertificateVerify over the WRONG context string ("TLS 1.3,
    /// client CertificateVerify").
    pub wrong_sig_blob: bool,
    /// Sign CertificateVerify with rsa_pkcs1_sha256 (0x0401) instead of
    /// rsa_pss_rsae_sha256 (0x0804).
    pub use_pkcs1: bool,
    /// Cipher suite the server selects (must be one of the three the client
    /// offers).  Default TLS_AES_128_GCM_SHA256 (0x1301).
    pub suite: u16,
}

impl LoopbackServer {
    /// Bind to 127.0.0.1:0 (OS-assigned port) with default flags.
    pub fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        Ok(LoopbackServer {
            listener,
            force_hrr: false,
            corrupt_finished: false,
            wrong_sig_blob: false,
            use_pkcs1: false,
            suite: cipher_suite::TLS_AES_128_GCM_SHA256,
        })
    }

    /// The OS-assigned bind address (for `TcpStream::connect` in tests).
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept ONE connection and run the full TLS 1.3 handshake using OS
    /// entropy, then hand back the echo session.
    pub fn serve_one(&self) -> Result<ServerEchoSession, ServerError> {
        self.serve_one_with_entropy(&mut OsEntropy)
    }

    /// Accept ONE connection with an INJECTED entropy source (tests pin
    /// consumption order: cookie (HRR path) → server random → server x25519
    /// private → PSS salt (PSS path)).
    pub fn serve_one_with_entropy(
        &self,
        entropy: &mut dyn crate::client::Entropy,
    ) -> Result<ServerEchoSession, ServerError> {
        let (stream, _peer) = self.listener.accept().map_err(ServerError::Io)?;
        // Tests must never hang: a stuck peer surfaces as a 10 s IO timeout.
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        let mut stream = stream;

        // ---- 1. read the (first) ClientHello ----------------------------
        let (mut ch_raw, ch) = read_client_hello(&mut stream)?;

        let mut transcript: Vec<Vec<u8>>;
        let client_share: [u8; 32];

        // ---- 2. optional HelloRetryRequest round trip (§4.1.4) ----------
        if self.force_hrr {
            // The client's initial share (for the freshness check below).
            let initial_share = client_x25519_share(&ch)?;

            // The HRR carries a fresh cookie the client MUST echo (§4.1.4).
            let mut cookie_buf = [0u8; 32];
            entropy
                .fill32(&mut cookie_buf)
                .map_err(ServerError::Entropy)?;
            let cookie = cookie_buf.to_vec();

            let hrr = ServerHello {
                legacy_version: 0x0303,
                random: handshake::HELLO_RETRY_REQUEST_RANDOM,
                legacy_session_id_echo: ch.legacy_session_id.clone(),
                cipher_suite: self.suite,
                legacy_compression_method: 0,
                extensions: vec![
                    handshake::encode_key_share_hrr(named_group::X25519),
                    handshake::encode_cookie(&cookie).map_err(CodecError::from)?,
                    handshake::encode_supported_versions_sh(handshake::VERSION_TLS13),
                ],
            };
            let hrr_raw = hrr.encode();
            // §5.1, lines 4413-4417: "a record containing ... a ServerHello
            // MUST have version 0x0303".
            write_plaintext_record(
                &mut stream,
                ContentType::Handshake,
                LEGACY_VERSION_OTHER,
                &hrr_raw,
            )?;

            // §4.4.1 (transcript module): ClientHello1 is replaced by the
            // synthetic message_hash message.
            let th1 = sha256::digest(&ch_raw);
            let synthetic = message_hash_synthetic(&th1);
            transcript = vec![synthetic, hrr_raw];

            // ---- read the second ClientHello ----------------------------
            let (ch2_raw, ch2) = read_client_hello(&mut stream)?;
            if ch2.legacy_session_id != ch.legacy_session_id {
                return Err(ServerError::HrrCookieMismatch);
            }
            // Cookie MUST be echoed verbatim (§4.1.4).
            let echoed = ch2
                .extensions
                .iter()
                .find(|e| e.ext_type == ext_type::COOKIE)
                .map(|e| handshake::parse_cookie(&e.data))
                .transpose()
                .map_err(CodecError::from)?;
            if echoed.as_deref() != Some(cookie.as_slice()) {
                return Err(ServerError::HrrCookieMismatch);
            }
            let fresh_share = client_x25519_share(&ch2)?;
            if fresh_share == initial_share {
                return Err(ServerError::HrrKeyShareNotRefreshed);
            }
            client_share = fresh_share;
            ch_raw = ch2_raw;
            transcript.push(ch_raw.clone());
        } else {
            client_share = client_x25519_share(&ch)?;
            transcript = vec![ch_raw.clone()];
        }

        // ---- 3. ServerHello ---------------------------------------------
        if !ch.cipher_suites.contains(&self.suite) {
            return Err(ServerError::SuiteNotOffered(self.suite));
        }
        let mut srv_priv = [0u8; 32];
        entropy
            .fill32(&mut srv_priv)
            .map_err(ServerError::Entropy)?;
        let srv_pub = holo_crypto::x25519::public_from_private(&srv_priv);
        let shared =
            holo_crypto::x25519::x25519(&srv_priv, &client_share).ok_or(
                ServerError::SharedSecretNotContributory,
            )?;

        let mut srv_random = [0u8; 32];
        entropy
            .fill32(&mut srv_random)
            .map_err(ServerError::Entropy)?;
        let sh = ServerHello {
            legacy_version: 0x0303,
            random: srv_random,
            legacy_session_id_echo: ch.legacy_session_id.clone(),
            cipher_suite: self.suite,
            legacy_compression_method: 0,
            extensions: vec![
                handshake::encode_key_share_sh(&handshake::KeyShareEntry {
                    group: named_group::X25519,
                    key_exchange: srv_pub.to_vec(),
                }),
                handshake::encode_supported_versions_sh(handshake::VERSION_TLS13),
            ],
        };
        let sh_raw = sh.encode();
        write_plaintext_record(&mut stream, ContentType::Handshake, LEGACY_VERSION_OTHER, &sh_raw)?;
        transcript.push(sh_raw);

        // ---- 4. §7.1 schedule: handshake secrets -------------------------
        let th_ch_sh = transcript_hash(&transcript.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        let (c_hs, s_hs) =
            schedule::handshake_secrets(&shared, &th_ch_sh).map_err(ServerError::KeySchedule)?;
        let hs_secret = crate::client::handshake_secret_from_dh(&shared);
        let aead = AeadAlg::from_suite(self.suite)
            .map_err(|_| ServerError::UnsupportedCipherSuite(self.suite))?;
        let mut s_write = WriteKeys::derive(aead, &s_hs);
        let mut c_read = ReadKeys::derive(aead, &c_hs);

        // ---- 5. the encrypted flight (one coalesced record, RFC 8448 §3
        //         shape: EE + Certificate + CertificateVerify + Finished) --
        let ee = EncryptedExtensions { extensions: vec![] }.encode();
        transcript.push(ee.clone());
        let cert = CertificateMsg {
            certificate_request_context: vec![],
            entries: vec![CertificateEntry {
                cert_data: loopback_cert_der().to_vec(),
                extensions: vec![],
            }],
        }
        .encode();
        transcript.push(cert.clone());

        // §4.4.3: the signed content is
        //   64 × 0x20 || context string || 0x00 || Transcript-Hash(CH..Certificate)
        let th_to_cert = transcript_hash(&transcript.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        let context = if self.wrong_sig_blob {
            // Deterministic failure injection: the WRONG context string.
            CLIENT_CERTIFICATE_VERIFY_CONTEXT
        } else {
            crate::client::SERVER_CERTIFICATE_VERIFY_CONTEXT
        };
        let blob = certificate_verify_signed_blob(context, &th_to_cert);
        let md = sha256::digest(&blob);
        let (alg, sig) = if self.use_pkcs1 {
            (
                signature_scheme::RSA_PKCS1_SHA256,
                rsa_sign::sign_pkcs1_v1_5_sha256(loopback_rsa_n(), loopback_rsa_d(), &md)
                    .map_err(ServerError::CertSignFailed)?,
            )
        } else {
            let mut salt = [0u8; 32];
            entropy
                .fill32(&mut salt)
                .map_err(ServerError::Entropy)?;
            (
                signature_scheme::RSA_PSS_RSAE_SHA256,
                rsa_sign::sign_pss_sha256(loopback_rsa_n(), loopback_rsa_d(), &md, &salt)
                    .map_err(ServerError::CertSignFailed)?,
            )
        };
        let cv = handshake::CertificateVerify {
            algorithm: alg,
            signature: sig,
        }
        .encode();
        transcript.push(cv.clone());

        // §4.4.4: verify_data = HMAC(finished_key(s_hs),
        //                            Transcript-Hash(CH..CertificateVerify))
        let th_pre_finished =
            transcript_hash(&transcript.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        let mut verify_data =
            schedule::finished_verify_data(&schedule::finished_key(&s_hs), &th_pre_finished)
                .to_vec();
        if self.corrupt_finished {
            verify_data[0] ^= 0x01; // deterministic one-bit tamper
        }
        let fin = Finished { verify_data }.encode();

        // Send EE || Certificate || CertificateVerify || Finished in ONE
        // protected record (RFC 8448 §3 coalescing shape).
        let mut payload = Vec::with_capacity(ee.len() + cert.len() + cv.len() + fin.len());
        payload.extend_from_slice(&ee);
        payload.extend_from_slice(&cert);
        payload.extend_from_slice(&cv);
        payload.extend_from_slice(&fin);
        write_sealed_record(&mut stream, aead, &mut s_write, ContentType::Handshake, &payload)?;
        // The server's own Finished message IS part of the transcript
        // (§4.4.4: the client's Finished is computed over
        // Transcript-Hash(CH..server Finished)).
        transcript.push(fin.clone());

        // ---- 6. verify the client Finished (§4.4.4) ----------------------
        let th_post_server_finished =
            transcript_hash(&transcript.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        let expect_client_finished =
            schedule::finished_verify_data(&schedule::finished_key(&c_hs), &th_post_server_finished);
        let mut asm = HandshakeAssembler::new();
        let mut saw_finished = false;
        while !saw_finished {
            let (ct, content) = read_open_record(&mut stream, aead, &mut c_read)?;
            match ct {
                ContentType::Handshake => {
                    for frame in asm.push_fragment(&content)? {
                        if frame.msg_type() == 20 {
                            let finished = Finished::decode(&frame.bytes)?;
                            if !holo_crypto::ct_eq(&finished.verify_data, &expect_client_finished) {
                                return Err(ServerError::ClientFinishedMismatch);
                            }
                            saw_finished = true;
                        } else {
                            return Err(ServerError::UnexpectedRecord(frame.msg_type()));
                        }
                    }
                }
                ContentType::Alert => {
                    return Err(ServerError::ClientAlert(alert_text(&content)));
                }
                ContentType::ApplicationData => {
                    return Err(ServerError::UnexpectedRecord(23));
                }
                ContentType::ChangeCipherSpec => { /* §5.1 compat record — skip */ }
            }
        }

        // ---- 7. application traffic secrets (§7.1) -----------------------
        // master_secret takes the Handshake Secret; its transcript_hash
        // argument is TRANSCRIPT_HASH_EMPTY (see schedule::master_secret docs).
        let ms = schedule::master_secret(&hs_secret, &schedule::TRANSCRIPT_HASH_EMPTY);
        // §7.1: c/s ap traffic are derived over ClientHello...server Finished
        // (the transcript WITHOUT the client's Finished).
        let (c_ap, s_ap) = schedule::application_secrets(&ms, &th_post_server_finished);
        Ok(ServerEchoSession {
            stream,
            aead,
            s_write: WriteKeys::derive(aead, &s_ap),
            c_read: ReadKeys::derive(aead, &c_ap),
        })
    }
}

// ---------------------------------------------------------------------------
// ServerEchoSession — the post-handshake echo peer
// ---------------------------------------------------------------------------

/// One application-layer item delivered by [`ServerEchoSession::read_app`].
pub enum AppItem {
    Data(Vec<u8>),
    CloseNotify,
}

/// The established loopback session: echoes application-data records back to
/// the client under the negotiated application keys.
pub struct ServerEchoSession {
    stream: TcpStream,
    aead: AeadAlg,
    s_write: WriteKeys,
    c_read: ReadKeys,
}

impl ServerEchoSession {
    /// Echo loop: every application-data record is decrypted and re-encrypted
    /// back to the client; a close_notify (or EOF) ends the loop cleanly.
    pub fn echo_until_closed(&mut self) -> Result<(), ServerError> {
        loop {
            match self.read_app()? {
                AppItem::Data(data) => self.write_app(&data)?,
                AppItem::CloseNotify => {
                    // §6.1: "Each party MUST send a 'close_notify' alert
                    // before closing its write side of the connection."
                    let _ = self.write_alert_close_notify();
                    let _ = self.stream.shutdown(Shutdown::Write);
                    return Ok(());
                }
            }
        }
    }

    /// Read ONE application item (data, or close_notify).
    pub fn read_app(&mut self) -> Result<AppItem, ServerError> {
        loop {
            let mut hdr = [0u8; 5];
            match self.stream.read_exact(&mut hdr) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(AppItem::CloseNotify); // peer vanished — treat as close
                }
                Err(e) => return Err(ServerError::Io(e)),
            }
            match hdr[0] {
                20 => {
                    // Middlebox compatibility CCS (§5.1 / Appendix D.4): skip.
                    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut skip = vec![0u8; len];
                    self.stream.read_exact(&mut skip).map_err(ServerError::Io)?;
                }
                21 => {
                    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut payload = vec![0u8; len];
                    self.stream.read_exact(&mut payload).map_err(ServerError::Io)?;
                    if payload.len() == 2 && payload[0] == 1 && payload[1] == 0 {
                        return Ok(AppItem::CloseNotify);
                    }
                    return Err(ServerError::ClientAlert(alert_text(&payload)));
                }
                22 => return Err(ServerError::UnexpectedRecord(22)),
                23 => {
                    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut payload = vec![0u8; len];
                    self.stream.read_exact(&mut payload).map_err(ServerError::Io)?;
                    let (ct, content) = open_record(self.aead, &mut self.c_read, &hdr, &payload)
                        .map_err(map_client_err)?;
                    match ct {
                        ContentType::ApplicationData => return Ok(AppItem::Data(content)),
                        ContentType::Alert => {
                            if content.len() == 2 && content[0] == 1 && content[1] == 0 {
                                return Ok(AppItem::CloseNotify);
                            }
                            return Err(ServerError::ClientAlert(alert_text(&content)));
                        }
                        ContentType::Handshake => {
                            // NewSessionTicket / KeyUpdate etc. are out of
                            // scope by charter — distinct error, abort.
                            return Err(ServerError::UnexpectedRecord(content[0]));
                        }
                        ContentType::ChangeCipherSpec => {}
                    }
                }
                other => return Err(ServerError::UnexpectedRecord(other)),
            }
        }
    }

    /// Encrypt and send one application-data record.
    pub fn write_app(&mut self, data: &[u8]) -> Result<(), ServerError> {
        write_sealed_record(
            &mut self.stream,
            self.aead,
            &mut self.s_write,
            ContentType::ApplicationData,
            data,
        )
    }

    fn write_alert_close_notify(&mut self) -> Result<(), ServerError> {
        write_sealed_record(
            &mut self.stream,
            self.aead,
            &mut self.s_write,
            ContentType::Alert,
            &[1, 0], // warning(1) close_notify(0) — RFC 8446 §6.1
        )
    }
}

// ---------------------------------------------------------------------------
// Shared record-layer helpers (stream I/O)
// ---------------------------------------------------------------------------

fn map_client_err(e: ClientError) -> ServerError {
    match e {
        ClientError::AeadOpen(m) => ServerError::AeadOpen(m),
        other => ServerError::Plumbing(format!("{other}")),
    }
}

/// Read one plaintext handshake record and decode the ClientHello inside.
/// Returns the raw handshake message (transcript unit) and the decoded
/// structure.
fn read_client_hello(stream: &mut TcpStream) -> Result<(Vec<u8>, ClientHello), ServerError> {
    loop {
        let (ct, payload) = read_plaintext_record(stream)?;
        match ct {
            ContentType::Handshake => {
                let mut asm = HandshakeAssembler::new();
                let frames: Vec<HandshakeFrame> = asm.push_fragment(&payload)?;
                if frames.is_empty() {
                    return Err(CodecError::HandshakeZeroLengthFragment.into());
                }
                let ch =
                    ClientHello::decode(&frames[0].bytes).map_err(ServerError::ClientHelloDecode)?;
                return Ok((frames[0].bytes.clone(), ch));
            }
            ContentType::ChangeCipherSpec => { /* compat record — skip */ }
            ContentType::Alert => {
                return Err(ServerError::ClientAlert(alert_text(&payload)));
            }
            ContentType::ApplicationData => return Err(ServerError::UnexpectedRecord(23)),
        }
    }
}

/// Read one UNPROTECTED record (handshake/alert/CCS) with the §5.1 length
/// bound enforced.  Returns the content type and fragment.
pub(crate) fn read_plaintext_record(
    stream: &mut TcpStream,
) -> Result<(ContentType, Vec<u8>), ServerError> {
    let mut hdr = [0u8; 5];
    match stream.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed mid-handshake",
            )));
        }
        Err(e) => return Err(ServerError::Io(e)),
    }
    let ct = ContentType::from_u8(hdr[0])?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > record::MAX_PLAINTEXT_FRAGMENT {
        return Err(
            CodecError::RecordFragmentTooLong {
                got: len,
                max: record::MAX_PLAINTEXT_FRAGMENT,
            }
            .into(),
        );
    }
    let mut frag = vec![0u8; len];
    stream.read_exact(&mut frag).map_err(ServerError::Io)?;
    Ok((ct, frag))
}

/// Write one UNPROTECTED record.
pub(crate) fn write_plaintext_record(
    stream: &mut TcpStream,
    ct: ContentType,
    version: u16,
    fragment: &[u8],
) -> Result<(), ServerError> {
    let rec = record::TlsPlaintext::new(ct, version, fragment.to_vec())?;
    stream.write_all(&rec.encode()).map_err(ServerError::Io)?;
    stream.flush().map_err(ServerError::Io)
}

/// Seal + send one protected record (§5.2).  `keys` is mutated: the §5.2
/// record sequence number increments per sealed record.
pub(crate) fn write_sealed_record(
    stream: &mut TcpStream,
    alg: AeadAlg,
    keys: &mut WriteKeys,
    ct: ContentType,
    content: &[u8],
) -> Result<(), ServerError> {
    let wire = seal_record(alg, keys, ct, content).map_err(map_client_err)?;
    stream.write_all(&wire).map_err(ServerError::Io)?;
    stream.flush().map_err(ServerError::Io)
}

/// Open + return one protected record (§5.2).
pub(crate) fn read_open_record(
    stream: &mut TcpStream,
    alg: AeadAlg,
    keys: &mut ReadKeys,
) -> Result<(ContentType, Vec<u8>), ServerError> {
    let mut hdr = [0u8; 5];
    match stream.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed mid-flight",
            )));
        }
        Err(e) => return Err(ServerError::Io(e)),
    }
    // §5.2: TLSCiphertext opaque_type is ALWAYS 23.
    let _ = record::decode_ciphertext_header(&hdr)?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).map_err(ServerError::Io)?;
    open_record(alg, keys, &hdr, &payload).map_err(map_client_err)
}

fn alert_text(payload: &[u8]) -> String {
    if payload.len() == 2 {
        format!(
            "level {} description {} ({})",
            payload[0],
            payload[1],
            crate::alert::AlertDescription::from_u8(payload[1]).name()
        )
    } else {
        format!("malformed alert of {} bytes", payload.len())
    }
}

/// Extract the x25519 key share from a ClientHello (32 bytes exactly).
fn client_x25519_share(ch: &ClientHello) -> Result<[u8; 32], ServerError> {
    let ext = ch
        .extensions
        .iter()
        .find(|e| e.ext_type == ext_type::KEY_SHARE)
        .ok_or(ServerError::MissingClientKeyShare)?;
    let entries = handshake::parse_key_share_ch(&ext.data)?;
    let entry = entries
        .iter()
        .find(|e| e.group == named_group::X25519)
        .ok_or(ServerError::MissingClientKeyShare)?;
    if entry.key_exchange.len() != 32 {
        return Err(ServerError::BadClientKeyShare(entry.key_exchange.len()));
    }
    let mut share = [0u8; 32];
    share.copy_from_slice(&entry.key_exchange);
    Ok(share)
}
