//! TLS 1.3 key schedule — RFC 8446 §7.1, SHA-256 suites only (Hash.length = 32).
//!
//! Every function below implements one line of the RFC 8446 §7.1 schedule
//! diagram. The RFC defines, verbatim (§7.1):
//!
//! ```text
//!    The key derivation process makes use of the HKDF-Extract and
//!    HKDF-Expand functions as defined for HKDF [RFC5869], as well as the
//!    functions defined below:
//!
//!    HKDF-Expand-Label(Secret, Label, Context, Length) =
//!         HKDF-Expand(Secret, HkdfLabel, Length)
//!
//!    Where HkdfLabel is specified as:
//!
//!    struct {
//!        uint16 length = Length;
//!        opaque label<7..255> = "tls13 " + Label;
//!        opaque context<0..255> = Context;
//!    } HkdfLabel;
//!
//!    Derive-Secret(Secret, Label, Messages) =
//!         HKDF-Expand-Label(Secret, Label,
//!                           Transcript-Hash(Messages), Hash.length)
//! ```
//!
//! and:
//!
//! ```text
//!    Keys are derived from two input secrets using the HKDF-Extract and
//!    Derive-Secret functions.  The general pattern for adding a new secret
//!    is to use HKDF-Extract with the Salt being the current secret state
//!    and the Input Keying Material (IKM) being the new secret to be added.
//! ```
//!
//! with the diagram conventions:
//!
//! ```text
//!    -  HKDF-Extract is drawn as taking the Salt argument from the top and
//!       the IKM argument from the left, with its output to the bottom and
//!       the name of the output on the right.
//!
//!    -  "0" indicates a string of Hash.length bytes set to zero.
//! ```
//!
//! PSK-less operation: RFC 8446 §7.1 states "If a given secret is not
//! available, then the 0-value consisting of a string of Hash.length bytes
//! set to zeros is used.  Note that this does not mean skipping rounds, so
//! if PSK is not in use, Early Secret will still be HKDF-Extract(0, 0)."
//! This module implements exactly that PSK-less schedule; PSK binders
//! ("ext binder"/"res binder" branches), client_early_traffic_secret and
//! 0-RTT are OUT OF SCOPE (see the task scope), as is the "tls13
//! resumption" ticket secret derivation.
//!
//! IMPORTANT — the two "derived" Derive-Secret calls. The §7.1 diagram
//! reads `Derive-Secret(., "derived", "")` for BOTH the Early→Handshake and
//! the Handshake→Master transitions. The third argument is the EMPTY
//! message list, so the context passed to HKDF-Expand-Label is
//! `Transcript-Hash("")` = SHA-256 of the zero-length string
//! (= e3 b0 c4 42 ... b8 55), NOT a hash of 32 zero bytes. RFC 8448 §3
//! publishes this "hash (32 octets)" for both "tls13 derived" steps; see
//! [`TRANSCRIPT_HASH_EMPTY`]. The task brief for this module described it
//! as "sha256 of 32 zero bytes"; that reading contradicts both RFC 8446 and
//! RFC 8448 (sha256(0^32) = 66687aadf8... does NOT reproduce the published
//! `expanded` values), so it was corrected to the RFC semantics and the
//! deviation is recorded in the module report.
//!
//! Likewise the Master Secret's salt derivation is `Derive-Secret(.,
//! "derived", "")` from the Handshake Secret (RFC 8448 §3: "derive secret
//! for master "tls13 derived"" with the same empty-transcript hash), while
//! `Transcript-Hash(ClientHello...server Finished)` is used later, when
//! deriving the application traffic secrets FROM the Master Secret. Both
//! [`derived_secret`] and [`master_secret`] therefore take the
//! already-hashed transcript as an argument, and RFC-correct callers pass
//! [`TRANSCRIPT_HASH_EMPTY`].
//!
//! Every value this module can produce is pinned byte-exact against the
//! official RFC 8448 §3 "Simple 1-RTT Handshake" trace (all constants
//! transcribed mechanically from the RFC text; see the tests).

use holo_crypto::tls13::derive_secret;
use holo_crypto::tls13::hkdf_expand_label;
use holo_crypto::hmac_sha256;

/// `Transcript-Hash("")` — SHA-256 of the zero-length transcript.
///
/// This is the context value for the two `Derive-Secret(., "derived", "")`
/// stages of the §7.1 schedule (both the Early→Handshake and the
/// Handshake→Master transition; the diagram's `""` argument is the empty
/// message list, whose transcript hash is the hash of nothing at all).
/// RFC 8448 §3 publishes it verbatim as the `hash (32 octets)` input of both
/// "tls13 derived" steps:
///
/// ```text
///    hash (32 octets):  e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
///       27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55
/// ```
///
/// (RFC 8448 §3, page 5 and page 6 — the same value both times.)
///
/// NOTE: this is NOT sha256 of 32 zero bytes (that would be
/// `66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925`); see
/// the module-level docs. The `empty_transcript_hash_is_sha256_of_nothing`
/// test pins both facts.
pub const TRANSCRIPT_HASH_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// `"0"` of the §7.1 diagram — a string of Hash.length (32) zero bytes, used
/// as the IKM of the Early and Master Secret extracts and (as the zero PSK)
/// the salt of the Early Secret extract.
const ZERO32: [u8; 32] = [0u8; 32];

/// Early Secret — `HKDF-Extract(salt = 0^32, IKM = 0^32)`, the PSK-less top
/// of the §7.1 schedule.
///
/// RFC 8446 §7.1: "if PSK is not in use, Early Secret will still be
/// HKDF-Extract(0, 0)". PSK binders are out of scope here (module docs);
/// a PSK-aware schedule would be `Extract(salt = 0^32, IKM = PSK)` instead.
///
/// HKDF-Extract (RFC 5869 §2.2) is `HMAC-Hash(salt, IKM)`, which is exactly
/// [`holo_crypto::hmac_sha256`].
///
/// RFC 8448 §3 pins this to `33 ad 0a 1c 60 7e c0 3b ... f1 70 f9 2a`
/// ("extract secret "early"": salt 0, IKM 0^32, secret 33 ad 0a 1c ...).
pub fn early_secret() -> [u8; 32] {
    hmac_sha256(&ZERO32, &ZERO32)
}

/// One `Derive-Secret(., "derived", ...)` stage: the salt-derivation line
/// that links two extracts of the schedule.
///
/// RFC 8446 §7.1 diagram: `Derive-Secret(., "derived", "")` — the empty
/// transcript in the diagram means the context is
/// [`TRANSCRIPT_HASH_EMPTY`]. For RFC-correct callers:
///
/// ```text
/// derived = Derive-Secret(prev_secret, "derived", Transcript-Hash(""))
/// ```
///
/// The `transcript_hash` argument is the ALREADY-HASHED transcript (the
/// `hash` argument RFC 8448 shows for the step), matching the crate's
/// [`holo_crypto::tls13::derive_secret`] which also takes the precomputed
/// hash. Passing anything other than `&TRANSCRIPT_HASH_EMPTY` deviates from
/// RFC 8446 §7.1 and will not reproduce RFC 8448 (the `handshake` and
/// `master` extracts would get the wrong salt).
pub fn derived_secret(prev_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    derive_secret(prev_secret, b"derived", transcript_hash)
        .try_into()
        .expect("derive_secret with out_len 32 always yields 32 bytes")
}

/// Handshake Secret and the two handshake traffic secrets, in one call.
///
/// RFC 8446 §7.1 diagram:
///
/// ```text
///       Derive-Secret(., "derived", "")
///             |
///             v
///   (EC)DHE -> HKDF-Extract = Handshake Secret
///             |
///             +-----> Derive-Secret(., "c hs traffic",
///             |                     ClientHello...ServerHello)
///             |                     = client_handshake_traffic_secret
///             |
///             +-----> Derive-Secret(., "s hs traffic",
///             |                     ClientHello...ServerHello)
///             |                     = server_handshake_traffic_secret
/// ```
///
/// `dh_secret` is the raw (EC)DHE shared secret (the IKM of the extract).
/// RFC 8446 §7.4.1 requires, verbatim: "Implementations MUST check whether
/// the computed Diffie-Hellman shared secret is the all-zero value and abort
/// if so, as described in Section 6 of [RFC7748]." — hence the `Result`: an
/// all-zero (or empty) `dh_secret` returns `Err` instead of deriving
/// usable-looking keys from a non-contributory exchange.
///
/// Returns `(client_handshake_traffic_secret, server_handshake_traffic_secret)`
/// derived with the transcript hash of `ClientHello...ServerHello` (already
/// hashed by the caller — RFC 8448 §3 publishes it as the
/// `86 0c 06 ed ...` "hash" of both traffic-secret steps).
pub fn handshake_secrets(
    dh_secret: &[u8],
    ch_sh_transcript_hash: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), String> {
    if dh_secret.is_empty() {
        return Err("handshake_secrets: empty (EC)DHE shared secret".to_string());
    }
    if dh_secret.iter().all(|&b| b == 0) {
        // RFC 8446 §7.4.1 / RFC 7748 §6: the all-zero shared secret is not
        // contributory; implementations MUST abort.
        return Err(
            "handshake_secrets: (EC)DHE shared secret is all-zero (RFC 8446 §7.4.1: MUST abort)"
                .to_string(),
        );
    }
    let salt = derived_secret(&early_secret(), &TRANSCRIPT_HASH_EMPTY);
    let handshake_secret = hmac_sha256(&salt, dh_secret);
    let c = derive_secret(&handshake_secret, b"c hs traffic", ch_sh_transcript_hash)
        .try_into()
        .expect("derive_secret with out_len 32 always yields 32 bytes");
    let s = derive_secret(&handshake_secret, b"s hs traffic", ch_sh_transcript_hash)
        .try_into()
        .expect("derive_secret with out_len 32 always yields 32 bytes");
    Ok((c, s))
}

/// Master Secret — the third extract of the schedule.
///
/// RFC 8446 §7.1 diagram:
///
/// ```text
///       Derive-Secret(., "derived", "")
///             |
///             v
///   0 -> HKDF-Extract = Master Secret
/// ```
///
/// i.e. `Extract(salt = Derive-Secret(handshake_secret, "derived", ""),
/// IKM = 0^32)`. The transcript for that "derived" call is the EMPTY one
/// (RFC 8448 §3 "derive secret for master "tls13 derived"" publishes the
/// empty-transcript hash as its input), so RFC-correct callers pass
/// [`TRANSCRIPT_HASH_EMPTY`] as `transcript_hash`.
///
/// NOTE on naming: the task brief called the second parameter
/// "transcript_hash_after_server_finished"; that transcript
/// (`ClientHello...server Finished`) belongs to the Derive-Secret calls made
/// FROM the Master Secret ([`application_secrets`], the exporter and — with
/// the client Finished appended — [`resumption_master_secret`]), NOT to the
/// salt derivation feeding the Master Secret extract. The parameter is
/// therefore named `transcript_hash` and documented as the empty-transcript
/// hash; deviation recorded in the module report.
pub fn master_secret(handshake_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let salt = derived_secret(handshake_secret, transcript_hash);
    hmac_sha256(&salt, &ZERO32)
}

/// The first application traffic secrets, derived from the Master Secret.
///
/// RFC 8446 §7.1 diagram:
///
/// ```text
///   +-----> Derive-Secret(., "c ap traffic",
///   |                     ClientHello...server Finished)
///   |                     = client_application_traffic_secret_0
///   |
///   +-----> Derive-Secret(., "s ap traffic",
///   |                     ClientHello...server Finished)
///   |                     = server_application_traffic_secret_0
/// ```
///
/// `th` is the transcript hash of `ClientHello...server Finished` INCLUDING
/// the server's Finished message (already hashed by the caller; RFC 8448 §3
/// publishes it as `96 08 10 2a ...`). Returns
/// `(client_application_traffic_secret_0, server_application_traffic_secret_0)`.
///
/// (Key updates — the `_N` suffix chain of RFC 8446 §7.2 — are out of scope
/// here; this module produces generation 0.)
pub fn application_secrets(master: &[u8; 32], th: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let c = derive_secret(master, b"c ap traffic", th)
        .try_into()
        .expect("derive_secret with out_len 32 always yields 32 bytes");
    let s = derive_secret(master, b"s ap traffic", th)
        .try_into()
        .expect("derive_secret with out_len 32 always yields 32 bytes");
    (c, s)
}

/// `finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)`
/// — RFC 8446 §4.4.4, verbatim. The BaseKey is the sender's traffic secret
/// for the current epoch (client/server handshake or application traffic
/// secret). The empty context is the zero-length `context<0..255>` of the
/// HkdfLabel struct (§7.1: "Note that in some cases a zero-length Context
/// (indicated by "") is passed to HKDF-Expand-Label.").
pub fn finished_key(base_secret: &[u8; 32]) -> [u8; 32] {
    hkdf_expand_label(base_secret, b"finished", &[], 32)
        .try_into()
        .expect("hkdf_expand_label with out_len 32 always yields 32 bytes")
}

/// Resumption Master Secret —
/// `Derive-Secret(., "res master", ClientHello...client Finished)`.
///
/// RFC 8446 §7.1 diagram (last branch):
///
/// ```text
///   +-----> Derive-Secret(., "res master",
///                         ClientHello...client Finished)
///                         = resumption_master_secret
/// ```
///
/// `th_full` is the transcript hash INCLUDING the client's Finished message
/// (RFC 8448 §3 publishes it as `20 91 45 a9 ...`). Implemented and tested
/// for schedule completeness even though session tickets / PSK resumption
/// are out of scope (the "tls13 resumption" ticket secret itself is not
/// derived here).
pub fn resumption_master_secret(master: &[u8; 32], th_full: &[u8; 32]) -> [u8; 32] {
    derive_secret(master, b"res master", th_full)
        .try_into()
        .expect("derive_secret with out_len 32 always yields 32 bytes")
}

/// Finished MAC — RFC 8446 §4.4.4, verbatim:
///
/// ```text
///    verify_data =
///        HMAC(finished_key,
///             Transcript-Hash(Handshake Context,
///                             Certificate*, CertificateVerify*))
/// ```
///
/// ("* Only included if present.") The Finished message's OWN transcript
/// entry is excluded from its own verify_data — so the server MACs the hash
/// of `ClientHello...CertificateVerify`, and the client MACs the hash of
/// `ClientHello...server Finished`. RFC 8446 §4.4.4 also mandates:
/// "Recipients of Finished messages MUST verify that the contents are
/// correct and if incorrect MUST terminate the connection with a
/// "decrypt_error" alert."
pub fn finished_verify_data(finished_key: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(finished_key, transcript_hash)
}

// ---------------------------------------------------------------------------
// Tests — the whole schedule is pinned byte-exact to RFC 8448 §3
// ("Simple 1-RTT Handshake"). Every constant below was transcribed
// MECHANICALLY from the RFC text (a parser over rfc8448.txt §3; page-break
// furniture skipped, each block's stated octet count verified) — see the
// task report. RFC 8448 line references in the comments are the §3 trace
// pages of https://www.rfc-editor.org/rfc/rfc8448.txt.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use holo_crypto::sha256;
    use holo_crypto::x25519;
    use holo_crypto::hmac_sha256;
    use holo_crypto::tls13::derive_secret;

    /// ClientHello handshake message, RFC 8448 §3 pp.3-4 (196 octets).
    const CH: [u8; 196] = [
        0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38,
        0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef,
        0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01,
        0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76,
        0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00,
        0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00,
        0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d,
        0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e,
        0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00,
        0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
        0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
        0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c,
        0x00, 0x02, 0x40, 0x01,
    ];

    /// ServerHello handshake message, RFC 8448 §3 p.5 (90 octets).
    const SH: [u8; 90] = [
        0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e,
        0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55,
        0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24,
        0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb,
        0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0,
        0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
    ];

    /// EncryptedExtensions, RFC 8448 §3 p.7 (40 octets).
    const EE: [u8; 40] = [
        0x08, 0x00, 0x00, 0x24, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17,
        0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x1c,
        0x00, 0x02, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Certificate, RFC 8448 §3 pp.7-8 (445 octets).
    const CERT: [u8; 445] = [
        0x0b, 0x00, 0x01, 0xb9, 0x00, 0x00, 0x01, 0xb5, 0x00, 0x01, 0xb0, 0x30, 0x82, 0x01, 0xac, 0x30,
        0x82, 0x01, 0x15, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36,
        0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30,
        0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00,
        0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xbb, 0x49, 0x8f, 0x82, 0x79, 0x30, 0x3d, 0x98,
        0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98, 0x8c, 0x0c, 0x68, 0xde, 0x55, 0xe1, 0xbd, 0xb8, 0x26,
        0xd3, 0x90, 0x1a, 0x24, 0x61, 0xea, 0xfd, 0x2d, 0xe4, 0x9a, 0x91, 0xd0, 0x15, 0xab, 0xbc, 0x9a,
        0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1, 0x9e, 0xaa, 0x6a, 0xf9, 0x8c, 0x7c, 0xed, 0x43, 0x12,
        0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e, 0xe0, 0xcc, 0xb0, 0x52, 0x4b, 0x1b, 0x01, 0x8c, 0x3e, 0x0b,
        0x63, 0x26, 0x4d, 0x44, 0x9a, 0x6d, 0x38, 0xe2, 0x2a, 0x5f, 0xda, 0x43, 0x08, 0x46, 0x74, 0x80,
        0x30, 0x53, 0x0e, 0xf0, 0x46, 0x1c, 0x8c, 0xa9, 0xd9, 0xef, 0xbf, 0xae, 0x8e, 0xa6, 0xd1, 0xd0,
        0x3e, 0x2b, 0xd1, 0x93, 0xef, 0xf0, 0xab, 0x9a, 0x80, 0x02, 0xc4, 0x74, 0x28, 0xa6, 0xd3, 0x5a,
        0x8d, 0x88, 0xd7, 0x9f, 0x7f, 0x1e, 0x3f, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x1a, 0x30, 0x18,
        0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55,
        0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x85, 0xaa, 0xd2, 0xa0, 0xe5,
        0xb9, 0x27, 0x6b, 0x90, 0x8c, 0x65, 0xf7, 0x3a, 0x72, 0x67, 0x17, 0x06, 0x18, 0xa5, 0x4c, 0x5f,
        0x8a, 0x7b, 0x33, 0x7d, 0x2d, 0xf7, 0xa5, 0x94, 0x36, 0x54, 0x17, 0xf2, 0xea, 0xe8, 0xf8, 0xa5,
        0x8c, 0x8f, 0x81, 0x72, 0xf9, 0x31, 0x9c, 0xf3, 0x6b, 0x7f, 0xd6, 0xc5, 0x5b, 0x80, 0xf2, 0x1a,
        0x03, 0x01, 0x51, 0x56, 0x72, 0x60, 0x96, 0xfd, 0x33, 0x5e, 0x5e, 0x67, 0xf2, 0xdb, 0xf1, 0x02,
        0x70, 0x2e, 0x60, 0x8c, 0xca, 0xe6, 0xbe, 0xc1, 0xfc, 0x63, 0xa4, 0x2a, 0x99, 0xbe, 0x5c, 0x3e,
        0xb7, 0x10, 0x7c, 0x3c, 0x54, 0xe9, 0xb9, 0xeb, 0x2b, 0xd5, 0x20, 0x3b, 0x1c, 0x3b, 0x84, 0xe0,
        0xa8, 0xb2, 0xf7, 0x59, 0x40, 0x9b, 0xa3, 0xea, 0xc9, 0xd9, 0x1d, 0x40, 0x2d, 0xcc, 0x0c, 0xc8,
        0xf8, 0x96, 0x12, 0x29, 0xac, 0x91, 0x87, 0xb4, 0x2b, 0x4d, 0xe1, 0x00, 0x00,
    ];

    /// CertificateVerify, RFC 8448 §3 p.8 (136 octets).
    const CV: [u8; 136] = [
        0x0f, 0x00, 0x00, 0x84, 0x08, 0x04, 0x00, 0x80, 0x5a, 0x74, 0x7c, 0x5d, 0x88, 0xfa, 0x9b, 0xd2,
        0xe5, 0x5a, 0xb0, 0x85, 0xa6, 0x10, 0x15, 0xb7, 0x21, 0x1f, 0x82, 0x4c, 0xd4, 0x84, 0x14, 0x5a,
        0xb3, 0xff, 0x52, 0xf1, 0xfd, 0xa8, 0x47, 0x7b, 0x0b, 0x7a, 0xbc, 0x90, 0xdb, 0x78, 0xe2, 0xd3,
        0x3a, 0x5c, 0x14, 0x1a, 0x07, 0x86, 0x53, 0xfa, 0x6b, 0xef, 0x78, 0x0c, 0x5e, 0xa2, 0x48, 0xee,
        0xaa, 0xa7, 0x85, 0xc4, 0xf3, 0x94, 0xca, 0xb6, 0xd3, 0x0b, 0xbe, 0x8d, 0x48, 0x59, 0xee, 0x51,
        0x1f, 0x60, 0x29, 0x57, 0xb1, 0x54, 0x11, 0xac, 0x02, 0x76, 0x71, 0x45, 0x9e, 0x46, 0x44, 0x5c,
        0x9e, 0xa5, 0x8c, 0x18, 0x1e, 0x81, 0x8e, 0x95, 0xb8, 0xc3, 0xfb, 0x0b, 0xf3, 0x27, 0x84, 0x09,
        0xd3, 0xbe, 0x15, 0x2a, 0x3d, 0xa5, 0x04, 0x3e, 0x06, 0x3d, 0xda, 0x65, 0xcd, 0xf5, 0xae, 0xa2,
        0x0d, 0x53, 0xdf, 0xac, 0xd4, 0x2f, 0x74, 0xf3,
    ];

    /// server Finished message, RFC 8448 §3 p.8 (36 octets):
    /// 0x14 0x00 0x00 0x20 || verify_data 9b 9b 14 1d ... 8f 07 18.
    const SERVER_FINISHED: [u8; 36] = [
        0x14, 0x00, 0x00, 0x20, 0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc, 0xe7,
        0x1d, 0xf4, 0xde, 0xda, 0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72, 0xcb, 0x7f, 0xff, 0xee, 0x54, 0x54,
        0xb7, 0x8f, 0x07, 0x18,
    ];

    /// client Finished message, RFC 8448 §3 p.13 (36 octets):
    /// 0x14 0x00 0x00 0x20 || verify_data a8 ec 43 6d ... d5 ce 61.
    const CLIENT_FINISHED: [u8; 36] = [
        0x14, 0x00, 0x00, 0x20, 0xa8, 0xec, 0x43, 0x6d, 0x67, 0x76, 0x34, 0xae, 0x52, 0x5a, 0xc1, 0xfc,
        0xeb, 0xe1, 0x1a, 0x03, 0x9e, 0xc1, 0x76, 0x94, 0xfa, 0xc6, 0xe9, 0x85, 0x27, 0xb6, 0x42, 0xf2,
        0xed, 0xd5, 0xce, 0x61,
    ];

    /// client ephemeral X25519 private key, RFC 8448 §3 p.3.
    const CLIENT_X25519_PRIV: [u8; 32] = [
        0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca,
        0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05,
    ];

    /// client ephemeral X25519 public key, RFC 8448 §3 p.3.
    const CLIENT_X25519_PUB: [u8; 32] = [
        0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe,
        0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c,
    ];

    /// server ephemeral X25519 private key, RFC 8448 §3 p.5.
    const SERVER_X25519_PRIV: [u8; 32] = [
        0xb1, 0x58, 0x0e, 0xea, 0xdf, 0x6d, 0xd5, 0x89, 0xb8, 0xef, 0x4f, 0x2d, 0x56, 0x52, 0x57, 0x8c,
        0xc8, 0x10, 0xe9, 0x98, 0x01, 0x91, 0xec, 0x8d, 0x05, 0x83, 0x08, 0xce, 0xa2, 0x16, 0xa2, 0x1e,
    ];

    /// server ephemeral X25519 public key, RFC 8448 §3 p.5.
    const SERVER_X25519_PUB: [u8; 32] = [
        0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1,
        0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f,
    ];

    /// (EC)DHE shared secret as published as the extract IKM,
    /// RFC 8448 §3 p.5 ("extract secret "handshake": IKM (32 octets):
    /// 8b d4 05 4f ... 89 49 2d"). Cross-checked in tests against the
    /// X25519 computation from the published private keys.
    const DH_SECRET_PUBLISHED: [u8; 32] = [
        0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d,
        0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d,
    ];

    /// Early Secret, RFC 8448 §3 p.4: 33 ad 0a 1c ... f1 70 f9 2a.
    const EARLY_SECRET: [u8; 32] = [
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
        0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
    ];

    /// Derive-Secret(Early, "derived", "") — salt of the Handshake Secret
    /// extract, RFC 8448 §3 p.5: 6f 26 15 a1 ... 36 11 ba.
    const DERIVED_FROM_EARLY: [u8; 32] = [
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
        0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba,
    ];

    /// Handshake Secret, RFC 8448 §3 p.5: 1d c8 26 e9 ... 3f be ac.
    const HANDSHAKE_SECRET: [u8; 32] = [
        0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01,
        0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2, 0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac,
    ];

    /// client_handshake_traffic_secret, RFC 8448 §3 pp.5-6 (PRK p.5, expanded p.6):
    /// b3 ed db 12 ... a5 5a 21.
    const C_HS_TRAFFIC: [u8; 32] = [
        0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35, 0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
        0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96, 0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21,
    ];

    /// server_handshake_traffic_secret, RFC 8448 §3 pp.5-6 (PRK p.5, expanded p.6):
    /// b6 7b 7d 69 ... 91 ad 38.
    const S_HS_TRAFFIC: [u8; 32] = [
        0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
        0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
    ];

    /// Derive-Secret(Handshake, "derived", "") — salt of the Master Secret
    /// extract, RFC 8448 §3 p.6: 43 de 77 e0 ... 54 b4.
    const DERIVED_FROM_HS: [u8; 32] = [
        0x43, 0xde, 0x77, 0xe0, 0xc7, 0x77, 0x13, 0x85, 0x9a, 0x94, 0x4d, 0xb9, 0xdb, 0x25, 0x90, 0xb5,
        0x31, 0x90, 0xa6, 0x5b, 0x3e, 0xe2, 0xe4, 0xf1, 0x2d, 0xd7, 0xa0, 0xbb, 0x7c, 0xe2, 0x54, 0xb4,
    ];

    /// Master Secret, RFC 8448 §3 pp.6-7 (extract step p.6, secret p.7):
    /// 18 df 06 84 ... 29 19.
    const MASTER_SECRET: [u8; 32] = [
        0x18, 0xdf, 0x06, 0x84, 0x3d, 0x13, 0xa0, 0x8b, 0xf2, 0xa4, 0x49, 0x84, 0x4c, 0x5f, 0x8a, 0x47,
        0x80, 0x01, 0xbc, 0x4d, 0x4c, 0x62, 0x79, 0x84, 0xd5, 0xa4, 0x1d, 0xa8, 0xd0, 0x40, 0x29, 0x19,
    ];

    /// Transcript-Hash(ClientHello...ServerHello) as published as the
    /// "hash" input of both handshake traffic-secret steps,
    /// RFC 8448 §3 pp.5-6: 86 0c 06 ed ... e1 ca d8 (hash printed p.6).
    /// Cross-checked in tests
    /// against SHA-256 of the raw CH || SH bytes.
    const TH_CH_SH: [u8; 32] = [
        0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c, 0x58, 0xed,
        0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f, 0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8,
    ];

    /// Transcript-Hash(ClientHello...server Finished) as published as the
    /// "hash" input of the c/s ap traffic and exp master steps,
    /// RFC 8448 §3 p.10: 96 08 10 2a ... 83 df 13. Cross-checked in tests
    /// against SHA-256 of the raw CH..server Finished bytes.
    const TH_CH_SF: [u8; 32] = [
        0x96, 0x08, 0x10, 0x2a, 0x0f, 0x1c, 0xcc, 0x6d, 0xb6, 0x25, 0x0b, 0x7b, 0x7e, 0x41, 0x7b, 0x1a,
        0x00, 0x0e, 0xaa, 0xda, 0x3d, 0xaa, 0xe4, 0x77, 0x7a, 0x76, 0x86, 0xc9, 0xff, 0x83, 0xdf, 0x13,
    ];

    /// Transcript-Hash(ClientHello...client Finished) as published as the
    /// "hash" input of the res master step, RFC 8448 §3 p.13:
    /// 20 91 45 a9 ... 14 3d. Cross-checked in tests against SHA-256 of the
    /// raw CH..client Finished bytes.
    const TH_CH_CF: [u8; 32] = [
        0x20, 0x91, 0x45, 0xa9, 0x6e, 0xe8, 0xe2, 0xa1, 0x22, 0xff, 0x81, 0x00, 0x47, 0xcc, 0x95, 0x26,
        0x84, 0x65, 0x8d, 0x60, 0x49, 0xe8, 0x64, 0x29, 0x42, 0x6d, 0xb8, 0x7c, 0x54, 0xad, 0x14, 0x3d,
    ];

    /// client_application_traffic_secret_0, RFC 8448 §3 p.10:
    /// 9e 40 64 6c ... 04 a5.
    const C_AP_TRAFFIC: [u8; 32] = [
        0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce, 0x65, 0x52,
        0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87, 0xf7, 0x92, 0xeb, 0xb7, 0xc1, 0x75, 0x04, 0xa5,
    ];

    /// server_application_traffic_secret_0, RFC 8448 §3 p.11:
    /// a1 1a f9 f0 ... 16 43.
    const S_AP_TRAFFIC: [u8; 32] = [
        0xa1, 0x1a, 0xf9, 0xf0, 0x55, 0x31, 0xf8, 0x56, 0xad, 0x47, 0x11, 0x6b, 0x45, 0xa9, 0x50, 0x32,
        0x82, 0x04, 0xb4, 0xf4, 0x4b, 0xfb, 0x6b, 0x3a, 0x4b, 0x4f, 0x1f, 0x3f, 0xcb, 0x63, 0x16, 0x43,
    ];

    /// exporter_master_secret, RFC 8448 §3 p.11: fe 22 f8 81 ... cf 50.
    const EXPORTER_MASTER: [u8; 32] = [
        0xfe, 0x22, 0xf8, 0x81, 0x17, 0x6e, 0xda, 0x18, 0xeb, 0x8f, 0x44, 0x52, 0x9e, 0x67, 0x92, 0xc5,
        0x0c, 0x9a, 0x3f, 0x89, 0x45, 0x2f, 0x68, 0xd8, 0xae, 0x31, 0x1b, 0x43, 0x09, 0xd3, 0xcf, 0x50,
    ];

    /// resumption_master_secret, RFC 8448 §3 pp.13-14:
    /// 7d f2 35 f2 ... 19 6c.
    const RESUMPTION_MASTER: [u8; 32] = [
        0x7d, 0xf2, 0x35, 0xf2, 0x03, 0x1d, 0x2a, 0x05, 0x12, 0x87, 0xd0, 0x2b, 0x02, 0x41, 0xb0, 0xbf,
        0xda, 0xf8, 0x6c, 0xc8, 0x56, 0x23, 0x1f, 0x2d, 0x5a, 0xba, 0x46, 0xc4, 0x34, 0xec, 0x19, 0x6c,
    ];

    /// server finished_key (ExpandLabel(s hs traffic, "finished", "", 32)),
    /// RFC 8448 §3 p.8: 00 8d 3b 66 ... c1 9f c8.
    const SERVER_FINISHED_KEY: [u8; 32] = [
        0x00, 0x8d, 0x3b, 0x66, 0xf8, 0x16, 0xea, 0x55, 0x9f, 0x96, 0xb5, 0x37, 0xe8, 0x85, 0xc3, 0x1f,
        0xc0, 0x68, 0xbf, 0x49, 0x2c, 0x65, 0x2f, 0x01, 0xf2, 0x88, 0xa1, 0xd8, 0xcd, 0xc1, 0x9f, 0xc8,
    ];

    /// client finished_key (ExpandLabel(c hs traffic, "finished", "", 32)),
    /// RFC 8448 §3 pp.12-13 (PRK p.12, expanded p.13): b8 0a d0 10 ... 42 d9 c4.
    const CLIENT_FINISHED_KEY: [u8; 32] = [
        0xb8, 0x0a, 0xd0, 0x10, 0x15, 0xfb, 0x2f, 0x0b, 0xd6, 0x5f, 0xf7, 0xd4, 0xda, 0x5d, 0x6b, 0xf8,
        0x3f, 0x84, 0x82, 0x1d, 0x1f, 0x87, 0xfd, 0xc7, 0xd3, 0xc7, 0x5b, 0x5a, 0x7b, 0x42, 0xd9, 0xc4,
    ];

    /// server Finished verify_data = HMAC(server finished_key,
    /// th(CH..CertificateVerify)), RFC 8448 §3 p.8:
    /// 9b 9b 14 1d ... 8f 07 18.
    const SERVER_FINISHED_VERIFY_DATA: [u8; 32] = [
        0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc, 0xe7, 0x1d, 0xf4, 0xde, 0xda,
        0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72, 0xcb, 0x7f, 0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18,
    ];

    /// client Finished verify_data = HMAC(client finished_key,
    /// th(CH..server Finished)), RFC 8448 §3 p.13:
    /// a8 ec 43 6d ... d5 ce 61.
    const CLIENT_FINISHED_VERIFY_DATA: [u8; 32] = [
        0xa8, 0xec, 0x43, 0x6d, 0x67, 0x76, 0x34, 0xae, 0x52, 0x5a, 0xc1, 0xfc, 0xeb, 0xe1, 0x1a, 0x03,
        0x9e, 0xc1, 0x76, 0x94, 0xfa, 0xc6, 0xe9, 0x85, 0x27, 0xb6, 0x42, 0xf2, 0xed, 0xd5, 0xce, 0x61,
    ];

    fn concat(parts: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in parts {
            v.extend_from_slice(p);
        }
        v
    }

    /// §7.1 first line: Early Secret = HKDF-Extract(0, 0) for the PSK-less
    /// schedule. RFC 8448 §3 p.4: "{server} extract secret "early":"
    /// salt "0 (all zero octets)", IKM 0^32,
    /// secret `33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00
    /// aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a`.
    #[test]
    fn early_secret_rfc8448_matches_33ad0a1c() {
        let e = early_secret();
        assert_eq!(e, EARLY_SECRET);
        // Cross-check the primitive composition itself: Extract(salt, IKM) =
        // HMAC-Hash(salt, IKM) (RFC 5869 §2.2) = hmac_sha256(0^32, 0^32).
        assert_eq!(hmac_sha256(&[0u8; 32], &[0u8; 32]), EARLY_SECRET);
    }

    /// `Derive-Secret(Early Secret, "derived", "")` — the salt of the
    /// Handshake Secret extract. RFC 8448 §3 pp.5-6: "derive secret for
    /// handshake "tls13 derived"" — hash (the EMPTY-transcript hash,
    /// `e3 b0 c4 42 ... b8 55`) → expanded
    /// `6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48
    /// 25 0c eb ea c3 57 6c 36 11 ba`.
    #[test]
    fn derived_early_rfc8448_matches() {
        // The const IS sha256 of the empty string (RFC 8448's published
        // "hash" input), not sha256 of 32 zero bytes — see module docs.
        assert_eq!(sha256::digest(&[]), TRANSCRIPT_HASH_EMPTY);
        assert_ne!(
            sha256::digest(&[0u8; 32]),
            TRANSCRIPT_HASH_EMPTY,
            "sha256(0^32) must NOT be used as the 'derived' transcript context"
        );
        let d = derived_secret(&early_secret(), &TRANSCRIPT_HASH_EMPTY);
        assert_eq!(d, DERIVED_FROM_EARLY);
        // The handshake extract salted with it reproduces the RFC's
        // Handshake Secret from the published DH IKM (RFC 8448 §3 p.5):
        let hs = hmac_sha256(&d, &DH_SECRET_PUBLISHED);
        assert_eq!(hs, HANDSHAKE_SECRET);
    }

    /// Handshake Secret → both handshake traffic secrets, with BOTH input
    /// paths cross-checked against the RFC:
    ///   * transcript hash: published `86 0c 06 ed ...` AND recomputed as
    ///     SHA-256 over the published ClientHello || ServerHello raw bytes;
    ///   * DH secret: published IKM `8b d4 05 4f ...` AND recomputed with
    ///     the crate's X25519 from the published private keys (client priv ×
    ///     server pub, and the symmetric direction).
    /// RFC 8448 §3 pp.4-5: c hs traffic `b3 ed db 12 ...`, s hs traffic
    /// `b6 7b 7d 69 ...`, Handshake Secret `1d c8 26 e9 ...`.
    #[test]
    fn handshake_traffic_secrets_rfc8448_chain() {
        // Path B (transcript): SHA-256 of the raw CH..SH handshake messages
        // must equal the published "hash" input of the traffic-secret steps.
        let th_computed = sha256::digest(&concat(&[&CH, &SH]));
        assert_eq!(th_computed, TH_CH_SH, "recomputed th(CH..SH)");
        // Path B (DH): X25519(client_priv, server_pub) and the mirror
        // direction both reproduce the published shared secret.
        let dh_computed = x25519::x25519(&CLIENT_X25519_PRIV, &SERVER_X25519_PUB)
            .expect("RFC 8448 §3 x25519 is contributory");
        let dh_mirror = x25519::x25519(&SERVER_X25519_PRIV, &CLIENT_X25519_PUB)
            .expect("RFC 8448 §3 x25519 is contributory");
        assert_eq!(dh_computed, DH_SECRET_PUBLISHED);
        assert_eq!(dh_mirror, DH_SECRET_PUBLISHED);
        // Path A uses the published values directly.
        let (c, s) = handshake_secrets(&DH_SECRET_PUBLISHED, &TH_CH_SH).expect("contributory DH");
        assert_eq!(c, C_HS_TRAFFIC);
        assert_eq!(s, S_HS_TRAFFIC);
        // The computed-DH path must land on the same secrets.
        let (c2, s2) = handshake_secrets(&dh_computed, &th_computed).expect("contributory DH");
        assert_eq!(c2, C_HS_TRAFFIC);
        assert_eq!(s2, S_HS_TRAFFIC);
        // Internal stage check: Handshake Secret itself is published
        // (`1d c8 26 e9 ...`), reachable as Extract(derived(early), DH).
        let hs = hmac_sha256(&DERIVED_FROM_EARLY, &DH_SECRET_PUBLISHED);
        assert_eq!(hs, HANDSHAKE_SECRET);
    }

    /// The §7.4.1 MUST-abort: an all-zero (EC)DHE shared secret is refused.
    #[test]
    fn handshake_secrets_rejects_all_zero_dh_rfc8446_7_4_1() {
        let err = handshake_secrets(&[0u8; 32], &TH_CH_SH).unwrap_err();
        assert!(err.contains("all-zero"));
        assert!(handshake_secrets(&[], &TH_CH_SH).is_err());
        // A normal derivation still succeeds.
        assert!(handshake_secrets(&DH_SECRET_PUBLISHED, &TH_CH_SH).is_ok());
    }

    /// Master Secret. RFC 8448 §3 pp.6-7: "derive secret for master "tls13
    /// derived"" (PRK = Handshake Secret `1d c8 26 e9 ...`, hash = the
    /// EMPTY-transcript hash) → expanded `43 de 77 e0 ...`; then "extract
    /// secret "master"" (salt = that, IKM 0^32) → secret
    /// `18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62
    /// 79 84 d5 a4 1d a8 d0 40 29 19`.
    ///
    /// Note the RFC-correct transcript argument is the EMPTY-transcript
    /// hash, NOT th(ClientHello...server Finished) — see module docs.
    #[test]
    fn master_secret_rfc8448_matches_18df0684() {
        let d = derived_secret(&HANDSHAKE_SECRET, &TRANSCRIPT_HASH_EMPTY);
        assert_eq!(d, DERIVED_FROM_HS);
        let m = master_secret(&HANDSHAKE_SECRET, &TRANSCRIPT_HASH_EMPTY);
        assert_eq!(m, MASTER_SECRET);
    }

    /// `c ap traffic` / `s ap traffic` from the Master Secret, with BOTH
    /// transcript paths: published th(CH..server Finished) `96 08 10 2a ...`
    /// AND recomputed SHA-256 over the raw published handshake messages
    /// (ClientHello, ServerHello, EncryptedExtensions, Certificate,
    /// CertificateVerify, server Finished — RFC 8448 §3 pp.3-8).
    /// RFC 8448 §3 p.10: c ap `9e 40 64 6c ...`, s ap `a1 1a f9 f0 ...`.
    #[test]
    fn application_traffic_secrets_rfc8448_chain() {
        let th_computed = sha256::digest(&concat(&[&CH, &SH, &EE, &CERT, &CV, &SERVER_FINISHED]));
        assert_eq!(th_computed, TH_CH_SF, "recomputed th(CH..server Finished)");
        let (c, s) = application_secrets(&MASTER_SECRET, &TH_CH_SF);
        assert_eq!(c, C_AP_TRAFFIC);
        assert_eq!(s, S_AP_TRAFFIC);
        // Same answer through the recomputed-transcript path.
        let (c2, s2) = application_secrets(&MASTER_SECRET, &th_computed);
        assert_eq!(c2, C_AP_TRAFFIC);
        assert_eq!(s2, S_AP_TRAFFIC);
    }

    /// Exporter Master Secret — `Derive-Secret(., "exp master",
    /// ClientHello...server Finished)`. RFC 8448 §3 p.10: expanded
    /// `fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 92 c5 0c 9a 3f 89 45 2f
    /// 68 d8 ae 31 1b 43 09 d3 cf 50`. (No dedicated wrapper in this module;
    /// the generic Derive-Secret IS the RFC operation.)
    #[test]
    fn exporter_master_secret_rfc8448_matches() {
        let e = derive_secret(&MASTER_SECRET, b"exp master", &TH_CH_SF);
        assert_eq!(e.as_slice(), &EXPORTER_MASTER[..]);
    }

    /// Resumption Master Secret — `Derive-Secret(., "res master",
    /// ClientHello...client Finished)`. The recomputed transcript path adds
    /// the client's Finished message to the server-epoch transcript.
    /// RFC 8448 §3 pp.13-14: hash `20 91 45 a9 ...` (p.13), expanded
    /// `7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf da f8 6c c8 56 23
    /// 1f 2d 5a ba 46 c4 34 ec 19 6c` (p.14).
    #[test]
    fn resumption_master_secret_rfc8448_matches() {
        let th_computed = sha256::digest(&concat(&[
            &CH, &SH, &EE, &CERT, &CV, &SERVER_FINISHED, &CLIENT_FINISHED,
        ]));
        assert_eq!(th_computed, TH_CH_CF, "recomputed th(CH..client Finished)");
        let r = resumption_master_secret(&MASTER_SECRET, &TH_CH_CF);
        assert_eq!(r, RESUMPTION_MASTER);
        let r2 = resumption_master_secret(&MASTER_SECRET, &th_computed);
        assert_eq!(r2, RESUMPTION_MASTER);
    }

    /// Finished keys for both senders —
    /// `HKDF-Expand-Label(BaseKey, "finished", "", 32)` (RFC 8446 §4.4.4).
    /// RFC 8448 §3 p.8 (server, PRK = `b6 7b 7d 69 ...` = s hs traffic):
    /// expanded `00 8d 3b 66 f8 16 ea 55 ... c1 9f c8`; p.12 (client, PRK =
    /// `b3 ed db 12 ...` = c hs traffic): expanded `b8 0a d0 10 15 fb 2f 0b
    /// ... 42 d9 c4`.
    #[test]
    fn finished_keys_rfc8448_matches() {
        assert_eq!(finished_key(&S_HS_TRAFFIC), SERVER_FINISHED_KEY);
        assert_eq!(finished_key(&C_HS_TRAFFIC), CLIENT_FINISHED_KEY);
    }

    /// Server Finished verify_data — closes the server side of the loop.
    /// The server MACs `Transcript-Hash(ClientHello...CertificateVerify)`
    /// (its own Finished message is NOT part of its own Handshake Context,
    /// RFC 8446 §4.4.4). RFC 8448 does NOT publish th(CH..CV), so it is
    /// recomputed here from the published raw handshake messages; the same
    /// transcription is validated by `application_traffic_secrets_rfc8448_chain`
    /// (whose th includes the server Finished and matches the published
    /// `96 08 10 2a ...`). RFC 8448 §3 p.8: finished
    /// `9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72
    /// cb 7f ff ee 54 54 b7 8f 07 18`.
    #[test]
    fn server_finished_verify_data_rfc8448_matches() {
        let th_cv = sha256::digest(&concat(&[&CH, &SH, &EE, &CERT, &CV]));
        // Sanity: excluding the server Finished changes the hash (it is
        // included for the application secrets, cf. TH_CH_SF).
        assert_ne!(th_cv, TH_CH_SF);
        let vd = finished_verify_data(&SERVER_FINISHED_KEY, &th_cv);
        assert_eq!(vd, SERVER_FINISHED_VERIFY_DATA);
    }

    /// Client Finished verify_data — the client's Handshake Context INCLUDES
    /// the server's Finished message, so its MAC input is exactly
    /// th(ClientHello...server Finished) = `96 08 10 2a ...` (the value RFC
    /// 8448 publishes for the application secrets, p.10). RFC 8448 §3 p.13:
    /// finished `a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76
    /// 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61`.
    #[test]
    fn client_finished_verify_data_rfc8448_matches() {
        let vd = finished_verify_data(&CLIENT_FINISHED_KEY, &TH_CH_SF);
        assert_eq!(vd, CLIENT_FINISHED_VERIFY_DATA);
        // The client Finished message bytes the RFC publishes embed exactly
        // this verify_data (p.13: "14 00 00 20 a8 ec 43 6d ...").
        assert_eq!(&CLIENT_FINISHED[4..], &CLIENT_FINISHED_VERIFY_DATA[..]);
    }

    /// Whole §7.1 chain end-to-end from the two published external inputs
    /// (the DH shared secret and the transcript hashes), asserting every
    /// intermediate against RFC 8448 §3 in order.
    #[test]
    fn full_schedule_chain_rfc8448_end_to_end() {
        // Early Secret.
        let early = early_secret();
        assert_eq!(early, EARLY_SECRET);
        // Early -> Handshake.
        let salt1 = derived_secret(&early, &TRANSCRIPT_HASH_EMPTY);
        assert_eq!(salt1, DERIVED_FROM_EARLY);
        let (c_hs, s_hs) = handshake_secrets(&DH_SECRET_PUBLISHED, &TH_CH_SH).unwrap();
        assert_eq!(c_hs, C_HS_TRAFFIC);
        assert_eq!(s_hs, S_HS_TRAFFIC);
        // Handshake -> Master.
        let hs = hmac_sha256(&salt1, &DH_SECRET_PUBLISHED);
        assert_eq!(hs, HANDSHAKE_SECRET);
        let master = master_secret(&hs, &TRANSCRIPT_HASH_EMPTY);
        assert_eq!(master, MASTER_SECRET);
        // Master -> application generation 0 + exporter + resumption.
        let (c_ap, s_ap) = application_secrets(&master, &TH_CH_SF);
        assert_eq!(c_ap, C_AP_TRAFFIC);
        assert_eq!(s_ap, S_AP_TRAFFIC);
        assert_eq!(
            derive_secret(&master, b"exp master", &TH_CH_SF).as_slice(),
            &EXPORTER_MASTER[..]
        );
        assert_eq!(
            resumption_master_secret(&master, &TH_CH_CF),
            RESUMPTION_MASTER
        );
        // Finished loop on both sides.
        assert_eq!(finished_key(&s_hs), SERVER_FINISHED_KEY);
        assert_eq!(finished_key(&c_hs), CLIENT_FINISHED_KEY);
        let th_cv = sha256::digest(&concat(&[&CH, &SH, &EE, &CERT, &CV]));
        assert_eq!(
            finished_verify_data(&finished_key(&s_hs), &th_cv),
            SERVER_FINISHED_VERIFY_DATA
        );
        assert_eq!(
            finished_verify_data(&finished_key(&c_hs), &TH_CH_SF),
            CLIENT_FINISHED_VERIFY_DATA
        );
    }
}
