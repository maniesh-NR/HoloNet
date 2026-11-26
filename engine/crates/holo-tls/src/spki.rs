//! SPKI pinning + hostname matching over raw DER — TLS 1.3 client-side
//! identity checking.
//!
//! Charter: NO X.509 parser. Everything here operates on raw DER with a
//! hand-written, cursor-based TLV walker (tag u8, definite lengths incl.
//! multi-byte) and extracts ONLY what pinning needs:
//!
//! - [`spki_pin_sha256`] / [`verify_spki_pin`] — SHA-256 SPKI pin
//! - [`dns_names`] / [`ip_addresses`] — SAN extraction ([2] dNSName, [7] iPAddress)
//! - [`matches_hostname`] — RFC 6125 §6.4 identity comparison
//!
//! By design there is NO chain building and NO certificate-signature
//! verification in this module: pinning REPLACES chain validation (the pin is
//! the trust anchor; the peer must present the pinned key). No dates are
//! handled. Any hidden ASN.1 dependency would be a charter violation.
//!
//! Pin convention (project-internal, cross-checked against independent
//! python-cryptography fixtures — see `spki_report.md` / `fixgen.py`):
//! `pin = SHA-256(full SubjectPublicKeyInfo DER)` — over the complete
//! SEQUENCE (tag + length + AlgorithmIdentifier + subjectPublicKey), i.e. the
//! RFC 7469 "server certificate pin" shape. RFC 8446 §4.2.2.1 governs
//! signature_algorithms negotiation, not pinning; this pin format is
//! documented here as the HoloNet convention.
//!
//! Hostname semantics (RFC 6125 §6.4):
//! - comparison is case-insensitive (§6.4.1) — both sides are lowercased;
//! - wildcard: ONLY a leftmost label that is exactly `*`, matching exactly
//!   ONE label. Partial wildcards (`*x.example.com`), interior wildcards
//!   (`a.*.com`), multiple `*` labels and empty labels are NOT wildcards and
//!   never match. Documented choice: such names are treated as literal names
//!   that simply fail to match → `Ok(false)`, NOT an error, so one weird SAN
//!   cannot abort the whole check;
//! - a `*` in the HOSTNAME argument is never honored (reference identifiers
//!   are literal) → `Ok(false)`, not an error;
//! - an IP-literal hostname (bare `std::net::IpAddr` form — no brackets, no
//!   zone IDs, no name resolution) matches ONLY `[7] iPAddress` entries by
//!   raw 4-byte (IPv4) / 16-byte (IPv6) compare — never dNSName entries;
//! - any SAN dNSName containing a NUL byte → distinct spoofing-guard error
//!   `spki: san: embedded NUL` (the classic name-termination attack);
//! - an absent (or empty) SAN with a hostname expectation → distinct error
//!   `spki: san: absent`. Returning `Ok(false)` there would silently accept
//!   an attacker-substituted certificate in our threat model, so it is an
//!   error; document this at every call site.
//!
//! Errors are distinct strings with prefixes `spki: der:` (parse failures),
//! `spki: san:` (identity-extraction issues) and `spki: pin:` (pin mismatch).

use holo_crypto::{ct_eq, sha256};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Minimal DER TLV walker (charter: own implementation, ~100 lines, raw DER)
// ---------------------------------------------------------------------------

const TAG_BOOL: u8 = 0x01;
const TAG_INT: u8 = 0x02;
const TAG_BITSTRING: u8 = 0x03;
const TAG_OCTETSTRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQ: u8 = 0x30;

/// Cursor-based DER reader. All spans returned by [`tlv`] point INTO the
/// buffer handed to [`Cursor::new`] (never into copies), so outer spans stay
/// sliceable while walking nested structures.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| "spki: der: truncated".to_string())?;
        self.pos += 1;
        Ok(b)
    }

    /// Take `n` bytes as a span into the original buffer.
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.remaining() {
            return Err("spki: der: truncated".to_string());
        }
        let span = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(span)
    }
}

/// Read one TLV: return `(tag, content_span)` where `content_span` points
/// into the buffer the cursor was created with. Definite lengths only,
/// including multi-byte (0x81..0x84) forms; distinct errors per defect.
fn tlv<'a>(cur: &mut Cursor<'a>) -> Result<(u8, &'a [u8]), String> {
    let tag = cur.read_u8()?;
    if tag & 0x1f == 0x1f {
        // High tag numbers (multi-byte tag): we never need them for pinning.
        return Err(format!("spki: der: tag {tag:02x}: high tag numbers unsupported"));
    }
    let l0 = cur.read_u8()?;
    let len = match l0 {
        0x00..=0x7f => l0 as usize,
        0x80 => return Err("spki: der: indefinite length".to_string()),
        _ => {
            let n = (l0 & 0x7f) as usize;
            if n > 4 {
                return Err(format!("spki: der: length overflow ({n} length bytes)"));
            }
            let bytes = cur.take(n)?;
            let mut v = 0usize;
            for b in bytes {
                v = (v << 8) | usize::from(*b);
            }
            if v < 128 {
                return Err("spki: der: non-minimal length".to_string());
            }
            v
        }
    };
    let content = cur.take(len)?;
    Ok((tag, content))
}

/// [`tlv`] + tag check; distinct "spki: der: tag ..." error on mismatch.
fn expect_tlv<'a>(cur: &mut Cursor<'a>, want: u8) -> Result<&'a [u8], String> {
    let (tag, content) = tlv(cur)?;
    if tag != want {
        return Err(format!("spki: der: tag {tag:02x} (expected {want:02x})"));
    }
    Ok(content)
}

// ---------------------------------------------------------------------------
// Certificate walk (RFC 5280) — the minimum pinning needs
// ---------------------------------------------------------------------------

/// Walk `Certificate ::= SEQ { tbsCertificate, signatureAlgorithm,
/// signatureValue }` and return the `tbsCertificate` content span (a slice of
/// `cert_der`). The two trailing fields are only shape-checked (SEQuence /
/// BIT STRING with zero unused bits) — signatures are NOT verified here by
/// design (pinning replaces chain validation).
fn cert_tbs(cert_der: &[u8]) -> Result<&[u8], String> {
    let mut outer = Cursor::new(cert_der);
    let cert = expect_tlv(&mut outer, TAG_SEQ)?; // Certificate ::= SEQ { ... }
    if outer.remaining() != 0 {
        return Err("spki: der: trailing bytes".to_string());
    }
    // The three Certificate fields live INSIDE the outer SEQUENCE span —
    // continue walking with a fresh cursor over that span (all spans still
    // point into cert_der).
    let mut cur = Cursor::new(cert);
    let tbs = expect_tlv(&mut cur, TAG_SEQ)?; // tbsCertificate
    expect_tlv(&mut cur, TAG_SEQ)?; // signatureAlgorithm (AlgorithmIdentifier)
    let sig = expect_tlv(&mut cur, TAG_BITSTRING)?; // signatureValue
    if cur.remaining() != 0 {
        return Err("spki: der: trailing bytes".to_string());
    }
    if sig.is_empty() || sig[0] != 0 {
        return Err("spki: der: bitstring: unused bits not zero".to_string());
    }
    Ok(tbs)
}

/// One pass over `TBSCertificate` fields in order:
/// `[0] EXPLICIT version` (optional) → `serialNumber INTEGER` →
/// `signature SEQ` → `issuer SEQ` → `validity SEQ` → `subject SEQ` →
/// `subjectPublicKeyInfo SEQ` (7th field counting the optional version) →
/// optional `[1]`/`[2]` (unique IDs) / `[3] EXPLICIT extensions`.
/// Returns the full-SEQUENCE SPKI span and, when present, the Extensions
/// SEQUENCE content. All spans point into `tbs`.
fn walk_tbs<'a>(tbs: &'a [u8]) -> Result<(&'a [u8], Option<&'a [u8]>), String> {
    let mut cur = Cursor::new(tbs);
    if cur.peek() == Some(0xa0) {
        tlv(&mut cur)?; // [0] EXPLICIT version — skipped (no dates/semantics needed)
    }
    expect_tlv(&mut cur, TAG_INT)?; // serialNumber
    expect_tlv(&mut cur, TAG_SEQ)?; // signature (AlgorithmIdentifier)
    expect_tlv(&mut cur, TAG_SEQ)?; // issuer Name
    expect_tlv(&mut cur, TAG_SEQ)?; // validity
    expect_tlv(&mut cur, TAG_SEQ)?; // subject Name
    let start = cur.pos();
    expect_tlv(&mut cur, TAG_SEQ)?; // subjectPublicKeyInfo
    // Full DER span of the SPKI SEQUENCE (header + content), still a slice of
    // the original cert buffer via tbs.
    let spki = &tbs[start..cur.pos()];
    let mut ext = None;
    while cur.remaining() > 0 {
        let (tag, body) = tlv(&mut cur)?;
        match tag {
            0x81 | 0x82 => {} // [1]/[2] issuerUniqueID / subjectUniqueID — skip
            0xa3 => {
                // [3] EXPLICIT → exactly one Extensions SEQUENCE inside
                let mut e = Cursor::new(body);
                ext = Some(expect_tlv(&mut e, TAG_SEQ)?);
                if e.remaining() != 0 {
                    return Err("spki: der: trailing bytes in [3]".to_string());
                }
            }
            _ => return Err(format!("spki: der: tag {tag:02x} after subjectPublicKeyInfo")),
        }
    }
    Ok((spki, ext))
}

/// Return the FULL DER span of the `subjectPublicKeyInfo` SEQUENCE inside
/// `tbs` (the `tbsCertificate` content): tag + length + AlgorithmIdentifier +
/// subjectPublicKey. This is exactly the span the pin hashes.
fn tbs_spki_span(tbs: &[u8]) -> Result<&[u8], String> {
    Ok(walk_tbs(tbs)?.0)
}

// ---------------------------------------------------------------------------
// SPKI pin (project-internal convention — see module docs)
// ---------------------------------------------------------------------------

/// SHA-256 over the full SPKI DER of the end-entity certificate.
/// Parse failures are distinct `spki: der: ...` errors.
pub fn spki_pin_sha256(cert_der: &[u8]) -> Result<[u8; 32], String> {
    let tbs = cert_tbs(cert_der)?;
    let spki = tbs_spki_span(tbs)?;
    Ok(sha256::digest(spki))
}

/// Constant-time pin check via `holo_crypto::ct_eq`: hash the SPKI span, then
/// compare against `expected`. Pin mismatch → `spki: pin: sha256 mismatch`;
/// parse failures → distinct `spki: der: ...` errors.
pub fn verify_spki_pin(cert_der: &[u8], expected: &[u8; 32]) -> Result<(), String> {
    let pin = spki_pin_sha256(cert_der)?;
    if ct_eq(&pin, expected) {
        Ok(())
    } else {
        Err("spki: pin: sha256 mismatch".to_string())
    }
}

// ---------------------------------------------------------------------------
// SAN extraction
// ---------------------------------------------------------------------------

/// subjectAltName extnID: OID 2.5.29.17 → DER `06 03 55 1d 11`; the walker
/// compares the OID TLV content against these arcs.
const SAN_OID: [u8; 3] = [0x55, 0x1d, 0x11];

/// Find the subjectAltName GeneralNames SEQUENCE content (a slice of
/// `cert_der`): TBS field `[3] EXPLICIT` → Extensions SEQ →
/// `Extension { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET
/// STRING }` → the one with OID 2.5.29.17 → its extnValue OCTET STRING
/// content (the GeneralNames DER). `Ok(None)` when no SAN extension exists.
/// Other extensions are skipped without deep validation (minimal walker).
fn san_general_names(cert_der: &[u8]) -> Result<Option<&[u8]>, String> {
    let tbs = cert_tbs(cert_der)?;
    let (_, ext) = walk_tbs(tbs)?;
    let ext_seq = match ext {
        None => return Ok(None),
        Some(e) => e,
    };
    let mut cur = Cursor::new(ext_seq);
    while cur.remaining() > 0 {
        let (tag, body) = tlv(&mut cur)?;
        if tag != TAG_SEQ {
            return Err(format!("spki: der: tag {tag:02x} in extensions"));
        }
        let mut e = Cursor::new(body);
        let oid = expect_tlv(&mut e, TAG_OID)?;
        if oid != SAN_OID.as_slice() {
            continue; // some other extension — irrelevant to pinning
        }
        if e.peek() == Some(TAG_BOOL) {
            expect_tlv(&mut e, TAG_BOOL)?; // critical BOOLEAN (optional) — skipped
        }
        let val = expect_tlv(&mut e, TAG_OCTETSTRING)?; // extnValue
        if e.remaining() != 0 {
            return Err("spki: der: trailing bytes in extension".to_string());
        }
        // extnValue content = GeneralNames SEQUENCE DER
        let mut g = Cursor::new(val);
        let gn = expect_tlv(&mut g, TAG_SEQ)?;
        if g.remaining() != 0 {
            return Err("spki: der: trailing bytes in extnValue".to_string());
        }
        return Ok(Some(gn));
    }
    Ok(None)
}

/// Extract `(dNSName entries, iPAddress entries)` from the SAN. Distinct
/// errors: `spki: san: absent` (no SAN extension / empty GeneralNames),
/// `spki: san: dns name not ia5` (non-ASCII dNSName payload),
/// `spki: san: ip: N-byte address` (iPAddress payload not 4/16 bytes).
/// Other GeneralName choices (rfc822, URI, ...) are skipped.
fn san_entries(cert_der: &[u8]) -> Result<(Vec<String>, Vec<Vec<u8>>), String> {
    let gn = match san_general_names(cert_der)? {
        None => return Err("spki: san: absent".to_string()),
        Some(gn) => gn,
    };
    let mut cur = Cursor::new(gn);
    if cur.remaining() == 0 {
        return Err("spki: san: absent".to_string()); // empty GeneralNames SEQ
    }
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    while cur.remaining() > 0 {
        let (tag, body) = tlv(&mut cur)?;
        match tag {
            0x82 => {
                // [2] dNSName — IA5String payload (ASCII)
                let s = std::str::from_utf8(body)
                    .map_err(|_| "spki: san: dns name not ia5".to_string())?
                    .to_owned();
                dns.push(s);
            }
            0x87 => {
                // [7] iPAddress — 4-byte IPv4 or 16-byte IPv6 octets
                if body.len() != 4 && body.len() != 16 {
                    return Err(format!("spki: san: ip: {}-byte address", body.len()));
                }
                ips.push(body.to_vec());
            }
            _ => {} // other GeneralName choices — irrelevant to pinning
        }
    }
    Ok((dns, ips))
}

/// All `[2] dNSName` SAN entries, in certificate order.
/// Errors: `spki: san: absent`, `spki: san: dns name not ia5`, DER errors.
pub fn dns_names(cert_der: &[u8]) -> Result<Vec<String>, String> {
    Ok(san_entries(cert_der)?.0)
}

/// All `[7] iPAddress` SAN entries as raw 4-byte (IPv4) / 16-byte (IPv6)
/// octets, in certificate order. Errors: `spki: san: absent`, `spki: san:
/// ip: ...`, DER errors.
pub fn ip_addresses(cert_der: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    Ok(san_entries(cert_der)?.1)
}

// ---------------------------------------------------------------------------
// Hostname matching (RFC 6125 §6.4 — see module docs for the exact policy)
// ---------------------------------------------------------------------------

/// Compare `hostname` against the certificate's SAN per RFC 6125 §6.4:
/// exact case-insensitive dNSName match, single-label leftmost-`*` wildcard
/// only, IP-literal vs `[7] iPAddress` only. Error cases (all distinct):
/// parse failures `spki: der: ...`, absent SAN `spki: san: absent`, and the
/// spoofing guard `spki: san: embedded NUL`. `Ok(false)` means the name
/// simply does not match (including rejected wildcard forms).
pub fn matches_hostname(cert_der: &[u8], hostname: &str) -> Result<bool, String> {
    let (dns, ips) = san_entries(cert_der)?;

    // Spoofing guard: an embedded NUL in ANY SAN dNSName is the classic
    // name-termination attack — reject the whole certificate outright.
    if dns.iter().any(|n| n.as_bytes().contains(&0)) {
        return Err("spki: san: embedded NUL".to_string());
    }

    // IP-literal reference identifiers: bare IpAddr only. Matched
    // exclusively against raw [7] iPAddress bytes (4/16), constant-time per
    // entry; never against dNSName entries.
    let host = hostname.to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        let want: Vec<u8> = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        return Ok(ips
            .iter()
            .any(|got| got.len() == want.len() && ct_eq(got, &want)));
    }

    // DNS reference identifiers. RFC 6125 §6.4.1: ASCII case-insensitive.
    let host_labels: Vec<&str> = host.split('.').collect();
    for name in &dns {
        let name = name.to_ascii_lowercase();
        let labels: Vec<&str> = name.split('.').collect();
        if labels[0] == "*" {
            // Wildcard candidate. Valid form ONLY: leftmost label exactly
            // `*`, no `*` anywhere else, no empty labels, and the reference
            // has the SAME number of labels with a non-empty first label —
            // i.e. `*` substitutes exactly one label. `*.example.com`
            // matches `a.example.com` but NOT `b.a.example.com`.
            let valid = labels.len() >= 2
                && labels[1..].iter().all(|l| !l.contains('*') && !l.is_empty())
                && !host.contains('*') // host-side `*` is never honored
                && host_labels.len() == labels.len()
                && !host_labels[0].is_empty()
                && host_labels[1..] == labels[1..];
            if valid {
                return Ok(true);
            }
            // Invalid wildcard forms (partial `*x`, interior `a.*`, multiple
            // `*`) or label-count mismatch: fall through — no match.
        } else if !name.contains('*') && name == host {
            // Plain name: exact match only (host-side `*` can never match a
            // `*`-free SAN name, and SAN-side partial wildcards are never
            // honored as literals — see module docs).
            return Ok(true);
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// Tests — python-cryptography cross-checked fixtures
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use holo_crypto::{bignum, rsa};

    // ---- python-generated fixtures (fixgen.py, python3-cryptography 44.0.3) ----
    // Pin consts are sha256(full SPKI DER) computed INDEPENDENTLY in python:
    //   sha256(cert.public_key().public_bytes(Encoding.DER,
    //                                         PublicFormat.SubjectPublicKeyInfo))
    // DER certs are RSA-2048, self-signed PKCS#1-v1.5-SHA256, validity 2025..2035.

    const CERT1_LOCALHOST_DNS: &str = "308202e6308201cea003020102021464bed66b15c162c22412fcb5c06fafbe453fba6e300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100b91a214b69a876a98e609dc64adb371c9404cddbb3789171f7c59fe4d3730a0347f8ad1d47c2e76fca5f201e49cf993eb02b74e0d3e01e4e65c4032614b9cad30ec6fc6577d2575d0bbb413763e240c9ff634637dd4234795d686cf05d8f5bdfbebde90181e6eccd0a22a496a93d93acb8a36fe7574e3f479f8197f8e94afcc2e38503497f3bc5a22d7011d0e6034fe1a878505f2b86cc13892b2ed3b39baee81fc89a772a04a5b3aa1291708c6d31fba5b81ff02635848bffa72d68875e38bee213d6ab3051a50c198105246dc98a202814b6902a57b8fdfef9aa4666b5f19b7161c4364498bb7c80ef60116d0de48dbe8a1a02c492fee287f3d619d5c5d1870203010001a318301630140603551d11040d300b82096c6f63616c686f7374300d06092a864886f70d01010b0500038201010016ddae0d06c3dd5e253ff46ae7da83b4079597e1df420d599d3ab00eb899939dd3c896138804f3cafb64bf0ab2f43c492af273542be2f6fc2d18a22c96e8d6adac22cc88b188168cb4d47cfeac87deb2bd1ba8f9c4e3c36fb73884d0b7e3c51c7835e40c7db23ac6c70b9d4043516bd2f780520aff50bc8a1eac9d7d4da3447fdcc0a9dc461a370743da05301ee006fe1198f9587e262989baf7cd8128a68e87452cb8d58fc38ddc3886c50ec5381d4f4ab9ca641df6e9f21b00f619689a806fb1d303a5808217743e479921993b23500dd070dab73bab88dbd4bb6918c166be1489bda02ac84350e8aebb2fe5c369d16c5a0136186920e40fa39a2c5a79baf2";
    const CERT2_IPV4_ONLY: &str = "308202e1308201c9a003020102021470f84a52ba6067bfe2a7f1688fbcf736032e98f0300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100abe476f566b27c636816735b78e24659d01b92f4f746f226523adcd674de605537d2047a15317b99bbe81c7e60ac2abd2f2dbd2a20c72f26a95662b25ddf5db8c088caca00fb8343de0b4c5b3633ca617520d621c6c808cc96a68a7b902d83ef36a4229f2bad6de1b76a8ebe9bb10f2c96205f0dc0ad8f0b53c62aca46b2c74adffeff35568afff8bffe24f34c1164684a94bb85b313f2a0626e21d08d6fc18ec49f1e93b47e0bd15431db1e9469e1f881090a60efa233c7aa089f9eb4708e38671e5aa8abf582f8cd32cdb31b57b90ff3b02e3fda8b91f3f1905fc38b42560d4c7da622a5b3e7be484bcf1b20bab2b1bbaa189477887a7b820afb371ee50cfb0203010001a3133011300f0603551d110408300687047f000001300d06092a864886f70d01010b050003820101009f3e5b8021829fb16dc069fe86457a25ba9283cc21e0ce03a127bea5d3b2409afaf0e5c5c845879c2d3224b863646611c696c2911d320db7546dc2c36723fdbff4d7be7b3023a0e9c3d7f82a3c7df23425291a20a560130b7fe1ec01c534ddcc9d49972c64f649f7a1740e51623db20c38a09a9c71a624651e5d7a7b46505c74fa0f957c2036973cea8b00e2054bbe10ab78c32f8337f31349418da96e06e83f7c698df2cd2aa3addc89dc98bd63ec1a6afbaeb5d9fa9bb53c643d3b4fedab07064fcf6ffb8e581189bbaf4ab8923a8d7577bdae8713375df0c4905b22ffdc3e73e681433f05a200ed37ae24f7dfa69738a88b88e4ed06fa3d9761f229a0fe7b";
    const CERT3_WILDCARD: &str = "308202ea308201d2a00302010202144da39f0970599a48c872d537e96fca16cfc29b87300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a02820101008e4697d5caed87e48d73a2248a7396207d965966d991480bab996c62f86e3ac01cd01641b296b020048fa35551caa963e4d15e01fcc6c11141fec1c78679b588c0ced4ffd22949e85784730f97a7de744cbee6a2b8802e90eaa45e49aa00555e4991221d0d4953325cbb251dff0912be849adb62f35c616e48eb9e144b89a18e07d0b7ba9aef27a4937a79c17449b5acd5e4b6448b801ff5b7fdc47f80982a990612194cc54dd6cd2f07378b041ac8448cd3e2f8a0a45cbb7bd147c398a1af75a91455d25595272b5541624c85f1284bfa70b41dd95f3f0b86bf0d0ccd832ec4ca1cb48fe5f34c576d80080fbfd09c2864a466827b0a0c7ffa7780e00c6123790203010001a31c301a30180603551d110411300f820d2a2e6578616d706c652e636f6d300d06092a864886f70d01010b050003820101001ef9b3131ea06b175f94075e1bd1e7edc1417e48d9ff28fff1860111ef0037fba42e04271d422e56895fa090cb01742b31a0996be5e0859a2250f741d6fd7272cd5a20d0fb83fdb6b22bafe8d089425918dacae2cba76cab352134c8363c768505097fb2bf9e0392e37895eed07d990189434b13c11cf838122bd4cd4d20727ae85212ba19a2c859b1068760f36c7faa8e6330caf6ef79323c2b2d1c75fd00de42dd70579c26fcab6c9f670d32f9a02d618b778ab44cb12badd9d3aa01041a531f9dd1a34e1fbe42a2d3c20f52d75a3d1b29cbb5793e0ec6bc3289b12a976e08c9422cb7f343cf776b53d6da9b534a524acd5a7f003e91489c09df6a4331b485";
    const CERT4_MULTI_SAN: &str = "308202ec308201d4a0030201020214155ef48d4d9ee59ae0b3db0c5596b60d0e828740300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100a328590d8992b5bc479491076a0b498ec56ae8277de8d34fa677c0ef2fd9a36636c9df1f357bb61373967b32cf8726f609aae223f0acdf81f7fd96da076fd7acf2a234e0ac1e4f0f85b33ab2a26d3e8bfb5d1dd867d8b9cbdab7dbbd2d370a95c6bc0abd16f31af7514e5463ea647746a2e03656a061ccd47a36840e9f590314df22b6764189c6c456a1fdcdce84a2a54342567a9a738e0623db643859fa6a085a4ee1bca90f191883e528627b3b3d02150bcad983c6b948711eb10e9f4837a541985ec7ec2e49ef50a8a39b05ce193e79050f1903bc860da2888666816a8a6bb451670887ff8d7468c7facc50e0248f8545b53823ea34513a3350e72f9a227d0203010001a31e301c301a0603551d110413301182096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201010095ea95aea0a7e02508631a1e95198678eb1846cd98d59f1ef25cdc14e028348b8c837c64824d5146603ad8364340fe5315355b10d09a4c01bc16de0cba591c0ed4e90c3abf0eed44fb343d7986a35d5d0334519cf6ace191e680fd66fd31f0a37cc76b2a0791e87c9d8d275d331b93cf7469bcd282b3f03ff11955929c1cb12e4ba69aaa02e7f7a8a74e5e652cf85bf30f13030f63d37ad5dec602e07e65289a9f8753751552c153f44f875e9bf47a1c8986bb30811f0082fc910c9f6ecaa28d9673661cfa5d974f919bf2d76fd26af3661253d1f7b92e06bce9bc9fe3e9312e03f07d21d2fe31d6e8fc7f3fdce774fb1d5fc53c1033b1b0d4c828c9b6ea3b4c";
    const CERT5_UNRELATED: &str = "308202e4308201cca0030201020214076532a2fe7ece277be2fcee500f3e0731b1ec4f300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100a3563824b22c92a5490a7e5567a3269663a8d25003c71074e3d8f28b8d85f776478a753bf4cb093d3c96f779d28da7c9c52d3929e82db151ff417210f3524ef750dd0f2c81a3146b8c89c1f4ad98f79af5d1d67c6802f154267503ce56309e1a7ca7c116cdbb8a1ebdd0eb789510d07f6838f2aa55e95f8b893f8364c2d5207a64681f58c48b8ac646362cbea9a4e27999af15a10cdc7016de5d6b00d182eb2dc566208de7417792814dc689a5af24209436fcff1f82006dab5d5e2e630dc77ff8bc860c1a2d2f33546bf95687d5babb20149feaf5b705ecfb166cfee6988d867b05ce59cd9ece7549314ef239ab460f06b01ed9bef99a58311c11691d3717f30203010001a316301430120603551d11040b30098207666f6f2e626172300d06092a864886f70d01010b050003820101003e093035a45c94b0a11210392d30c50f77c1e4df388aa450af3dd30f9dd45b12fd180e34af914494753ddf0035e10a79ed934d570624589f8f6e8c51a3939d97b73d064508d383d9241eb0be818d958b4f3bffa0f27cd7abd08442afb2c01cd87435fbbb3b38c20df9b635e983d95c0f06cee92e40381f687d1896ed9c35fe62376ecb20e9f38251906ed0db226cc7daf7e29cbdfc778936ce22c193c135f723d61b2fc514acf0535d38f93e6faf463505ed4c019f8fb1ea3aa13318e8ad9ae00a4480b0e1c9c579342aad17bab159c35366b29751eaa6158c3c52ac3f653b24eac7f3a9336c509f990037a35adbeb2eb111534d1b19da602852bca2a4a7c2ad";
    const CERT6_LOOPBACK: &str = "308202ec308201d4a00302010202145caeb5d5b7a80777cd1f1a7323d9eea9c92e7ba4300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100bdb003b9e5520156d25e9b5de74d13273961b39e252a4186a80ac5314ca808d46ede147508b1612e0d85bd9364de5df09f207639c42cf9a9a8dab2e1fe4e9aa28131e70d4abce857b751742121d1b824b92f91113bb1bba76dc45d7cc9f7299fe6789a7e9e8349a378849688b14201e4824378af233b5f6ba1f1df345ef43ebfc126d290047d95276aabc2734466591bb86c768308e4554cc9feedb001ed51066e7d709e668f96d71ac68847d662c9067341c77ad90633a695fdaeeadc0674d93e78840cbe01a633dea50e79635afe27850fc1c90f5f701914790f1144caaf6e75de3291ca764e6c53f4f2c881cdfb61f876254242655c29c2d308b93a30caa90203010001a31e301c301a0603551d110413301182096c6f63616c686f737487047f000001300d06092a864886f70d01010b05000382010100210e3d7c95b95a29935547963dc88676feebd60994b52a8e9f60f4291a8c24c20306730578f184b709e1b8671d5eb70547ff34dcb17244a5877bd06ab410beec9eafebcc8edbba1e966f47a14df09838cc7f56209a4403ceeb85e0016f2972840693bfb78514bae208640814a7ac40857410e5565d06374529e71864cbf444969e98fb51cff0c359a8af7698a3210a752137709c35a8827afafdc896257a13a06b3aafab65507f245595c15ea057032083b77b5338c0114b5adf57ede1e1c15e721ae1f6b6c6f1bbb12fbe81a745afd22a16ca03c6634014525a8aee968d0c0ad4b1e70adf71c24ad1ef8fb035a4dbe5370b79723b97ffd59f5c13fa91461ef4";
    const CERT7_WILDCARD_PARTIAL: &str = "308202eb308201d3a00302010202141c4f334810b1a88001c51651d5c03aac6e9a6c70300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100d5a174b7781662110a68bae8ed9a577ac0cd27416ec0f706b26bacd24ad0ea3f12d718c93ba4f9b9692fdbdde5705ddce07ac62665073b3850b235e3d519adeaa2e9c9920f8c8d1af99bee001de0792cc4063760d0f39d9c4ab1f07858b5d552bb9e6c451c36708b3dfb1cacbda617988df0889ad56f44cfa5cbb57274d0eac321543bc4ac6255e1bed093b7952f2bf563382e3d38ba90ccee57e67fd9a7fd8e8a76f4affdd8675035eb4a1001d7cea5281f97224b6ea8a114be7585df9b9e9433377813d2f385b24b4d05967bde3d04d2ca2bb3eb40d0b240c476f9936954ec276d87633cc841cddd020b5a5f017c0453bc0968e7529da355ee9f48f2d44ebf0203010001a31d301b30190603551d1104123010820e2a782e6578616d706c652e636f6d300d06092a864886f70d01010b05000382010100550bee7cf163ccd5c5b29cc3718a74ff18faec5f6106ad2bb16df65643da8f5cf74713d24a27461137a39926f9b9a89a918cb440f131ad0a982f9756d3e404d03777b9bcaa8d45b7f1fe4c5e97d8734bda79e9cbc38fa0046e2b7a6d9c9d4cbca3ff7604a5d0d26e2fdced26374cb77a6b8a61faab8814f7419fb962c1656d81826cfce9fc51571b079d769b24ea549b0348733cdd49ae9ff5f77b92992bd701fa5c5c8cef27623c20eef9ccd296341e4c529b815301bd015718f46a78d3512fac0c9fc1d82c1422421f4a5563845e3998a7a1bf5db7dd615b8fcf7f973187ec0238da68a38dd2822d5d585833616e3c2a9ede060b385d6616097f357056bd27";
    const CERT8_WILDCARD_DOUBLE: &str = "308202ec308201d4a0030201020214776e2394bdce47930cb4a7ceaa2f3453dd4cd050300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100ab313d2a8f386c057b126795829bbaa81dbbd63b34f03cb3cf5d60c8c2e6b704b8d791f886ac42405454c7592c70bcec8936b855ec1112f4ae4df577e1252d8e71dc2de33ae678f635602f00b32c70f15d6186499018530dd07d99437036d118e3c64833e2492d1f48b3d104b67cc0ff403f99765b40e6c8e7b684dc7e984fb583d3941967ad176c67f089d08112a031528737baf5727ce1691e1ad8e9e088762573f59b9bde243c866b2b3f79b9039dcb66bc8201b33bc8d4fe21103c763d98cc29e2823c676c2ed2c2844ce2e7b4c9df34b9ab7a411b2eee610800dec2111c694f3f199e3c93b7cd832839c59c78213306bc31c49dc7a55ee60777c9667b070203010001a31e301c301a0603551d1104133011820f2a2e2a2e6578616d706c652e636f6d300d06092a864886f70d01010b050003820101004d4b2a378dff096273462aa88d6bee9d6fc138a8ec793877a8845556c05cf5a4744d662e5b71559267579686761dd91c51e739029d77f02b9ba819fce12150ac5e86b2ebaf143219c4266ccdd3eaa7597ac075fbd3a20252b1acd7e6e1c3560ee9593360c0685c2ab94f628e5167a8b9eebae07a6192a1e29e9459a2b46d31249e140bbb99381158c3e4f12aedf370dc58662f1590a97476a29d2f7672a3834e8431b270f66667050b7e9c6717134a5b26e6ff4c9a8162867f0032da8909a00d1e2c4bf88ac04a3fce2310a8892c6ac715b550f41634d9896676239c55c615be67b10255897b190a054bc3db8966d6d0946b375cc2159bdf237713f14c91eae2";
    const CERT9_IPV6: &str = "308202ed308201d5a00302010202146f7edc2fbe5e6bb57927eb088a274b5d6ab1344a300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100c24e5f44e10e2efa9e8fe90a50f2701744b43a93b9ec666ed2a9756025995b2e78a890cba0158108552f94cb0a31c10509d3cb5c05fc7407c88df77d76241068b93452731e2754075f452e990e61be6cb0a642e58d9917b593fd3a4c981062eb2b020b6599b527791f9edab4a5da5a02267dbe3ad585b1efc16b3a62cf9b3b5bc1c4cf56cd2c66990a6cf3cbe6ae607d66e5eda0e0f901ce0e0fd7c2563256afa95a796194a2f427906b477dd4859807331f5d2a5156d8e0716e0000ca1ea45d3aa922221385acc6d3308455dac53008155ab1c696086e6c4f84265f295a2c9d5475028e1b39e48fc149b3a6acdb3a90fc556c61fed86594a98bc1740bccfa670203010001a31f301d301b0603551d1104143012871000000000000000000000000000000001300d06092a864886f70d01010b0500038201010010f4561d9aa51103b9f2f8d6224dcfc834ffaa34faf80400926c9480edb9d48ad19cc11f0c510b0f56122ea62330aa5b4f5937322a1e1e6bff4ae53187297bf81529cd4a704670ead992df55736d36ef4d378bd4453d34f19885ef60b600d16a453c6decaa3961f2ff21eaae6b51eff62a9ee3b98fb11be50a07cecaa7dfc400bc29ee11c74b9e31dd38ca89392fabf14496fecffcc9eaf7405b6786e00900a4387d1a47cc780edd6fad2a3e6cdb83b08c241572d28f344489409176dc37f314504e45d4d459b87da93e6efabf6e3f9ee67d81dc01a033ea43229648f4e503037eaa39c382c0bdb1bac9e1bd236904b43cbe773b4b4268bde2fd31a49cb8c22b";
    const CERT10_NUL_SAN: &str = "308202f7308201dfa003020102021462133ed48df923e1285df5c2bc813366b2b09616300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100ba268cfde3cf0c2b953a473b7c415122b52c2e89c1f956291322709f59e3180f8b2b513e54b9db52fbaa9abc78555b53e664cfffd877d62c6601380914f74cc97c1e97c918ae45964612b67e53df38db3b1958f522044ebeb2e6a16e0461f9eef300878595a1cfbf55f5ddc01b2b8b1ff85383a7d81bd9bfee5ea309e06a6f652ff365a6b5cbdbcf518967b83e065895db6aed46286ac9cd6d7c3a67a9ba4c6574bb46df729b76bb20d203f8d04dcf02cf78ed3b3207447c07b2e64f06ba7664c35585c90e722be5db2481c2e1c16f632d7e176373eb8f788d8b9e261eb72e344bc62ae384b03c0eb9cbcf30dd4a63d16739ac0ccadb9af4c983cecc972f0a930203010001a329302730250603551d11041e301c821a6c6f63616c686f7374006576696c2e6578616d706c652e636f6d300d06092a864886f70d01010b05000382010100720a503d2cc0ca2d1e13a7060787e7a73ea42910672da1a67f1c5c851a0b9480dc556de9c19923ebddc26ebbe94695c950f74a09b845a1d0715d8d768320d32a72ba12ce24305e6b05fda14b395f763b1a51d7f6d253a713147c66a5e375582804d96d5eabb6eb062190ab1d41bfad0a9abca4d21bb5789594d0f37b0dd89ef2323f8de61448cf7f5bcb217c1bedf7d5e256d958421941ce731bb84ae78a27c3054315336515faf94c3445dc03e9c3adae3ddffd308ff9ccd48d749e96823c4cfbbd46c175df17854a69ff562842a58615f725533afbc957de4944cbab740df4099203a67f9df97c8e3d7b33e6d3e263fe77a8d45ece47149165c9ba17bc032c";
    const CERT11_NO_SAN: &str = "308202cc308201b4a00302010202147df7618c6eb3554757047ce4216d468566fa1f06300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100d76eb60772bfbf7f89663adf3ce335bb850d9d2d20bcbb973922b9db431c8b5669eaacf7abf5101a05458a2c136ad795bf4f82f90d02fd1e7e709bf8dd67f7bb0665ee37b2b1d2ab78a8f08d9f2a8af23a915df951a643510390d0ae2305e9b3a5081a72d722749346abb0690705396499ccbf32485f85337d364c82d19730b3ff9e69048e72f8397703e1274a943aec5ae849fb67e8bdbf1bc1bb2bcd221b01156cd7260cd03d78ba289e547db30fba106c3b143844926b3f1d192a7a44e7b02391458c75634d5646d05720f04cd9e4d5a03a06e70c308f2e0a4878398d378926749c2404b8c198f71fc27da0bd24f8fae31714ae485ec2777bb24fa93257310203010001300d06092a864886f70d01010b050003820101006784ff3e0428267c35aee96feda3f82711f0c1763257be850e6265bd57aa1e2d22abeff6ff90f3d0e375d2bb40d66e5a057a74f29e84cad76ee92c14c7840e188a814ff9bf77d5a9db736f292a19019ec31abaf48fe607d03552eb32d963e3cb1c7ce41282a5010726dcd9db696be3187387c7245e2c5543b5fc9c66a0e9f3a842e96e049fe061fe3e8d116f9bd55dde8c85a624be2b49151ab84a58d551df2cb2c70c871fa63413010e5f3cd368d693d5231efa0bb84781b03b7ee525a9eff7c0a5abbf7213dddbb7208bc073c7334231330fc892efa87affd8f5e4e25b75537149d711c6f4a0fcfa3465894097c32de55ca37ad62c95f239b1fd69125eeff2";

    const PIN1: &str = "465625e5c717de6b494211ca4bd7301cf5aba771ed9e629d25ebb0284c0e436d";
    const PIN2: &str = "9d36b667ab1ca9e27cda203e463ca8cb3042dfe5f018fbb0f6d68b8f37d3801f";
    const PIN3: &str = "de04af4866a74de4e892ab40b85f7fe317aff2a12f0030100dddc6a63cb885f9";
    const PIN4: &str = "862ff705777a53f0a18e897088ff0474618ad6808b4050a5bc2641a46ed9bb27";
    const PIN5: &str = "449cdfe62a537b2631dbe1d45e7feff643c555c8d188220d5901e07e5eebdf9a";
    const PIN6: &str = "7249efe8b51d96f4ed9b04e848e927ce7b9834ee927fe55887d551b1fcb51666";
    const PIN7: &str = "43c2bf1de07bb4bbe903791016aed03de47061c2b8da7c7b912849219027f20b";
    const PIN8: &str = "0ccb6ccecaab8aeec7a038fd684381abc95b6583bf9969fe84acef03096682bd";
    const PIN9: &str = "c785ca2f1aeee2034c980cc66aa55bba6981960a90dc965ac16588f6005d9bc1";
    const PIN10: &str = "7a317635429b06b8bde3baecc79ac2107c704b2381c0b25f03ab116040f32429";
    const PIN11: &str = "09fa71e5a5d04560d30ad2680da7b20c2b2e9500b0e8d3982a41766f66d60c55";

    // Canonical loopback server fixture (fixture 6):
    // self-made test fixture — not a real identity; the embedded private key
    // (d, p, q, dP, dQ, qInv) exists ONLY in this #[cfg(test)] module.
    // RSA-2048, big-endian hex. n/e are re-extracted from the cert's own
    // SPKI span in the tests below and must equal these python exports.
    const LOOP_N_HEX: &str = "bdb003b9e5520156d25e9b5de74d13273961b39e252a4186a80ac5314ca808d46ede147508b1612e0d85bd9364de5df09f207639c42cf9a9a8dab2e1fe4e9aa28131e70d4abce857b751742121d1b824b92f91113bb1bba76dc45d7cc9f7299fe6789a7e9e8349a378849688b14201e4824378af233b5f6ba1f1df345ef43ebfc126d290047d95276aabc2734466591bb86c768308e4554cc9feedb001ed51066e7d709e668f96d71ac68847d662c9067341c77ad90633a695fdaeeadc0674d93e78840cbe01a633dea50e79635afe27850fc1c90f5f701914790f1144caaf6e75de3291ca764e6c53f4f2c881cdfb61f876254242655c29c2d308b93a30caa9";
    const LOOP_E_HEX: &str = "010001";
    const LOOP_D_HEX: &str = "01d85bf8eb73a442b1722d25b931c53d6ceff7dcd274ba45728e04440a005a71a29073777df9a7bdd870d41ac270ed4e016641f026e9df15d8e823b4521276ab9d011cc3c2d5da96bbd8457e6b034cbcc2b6653d5b2ccbec0183d6faf745f9b82df83f5c7af340fc9f97fe94ded08b0f2b7b3789d0986bc1b2c6150b3fdf355b08d32144f0b06fa193760e2e6f12e822881df36458f29e130cbb663b961e14045741e883320db2e728f8684a9108e2072b2ad0947238d9f2e8a4e07c30b6ed4e0a4b8fa20ea8fc502066e7cc77496a273fb7c1085f0691885d425e6b07176444836d8b3ae7e94762322128b3a2a3f39ba1eaf99ced983a4491ce2ccc9942c597";
    const LOOP_P_HEX: &str = "ff2870e5b35ae767c348e82d68215ce698c1a310f27f6a91afcf07c02f1dcf4e4439dd46eda47e1bf6377fcda8338795e0fd2e5c6bc4e4d402c17fb3984f2d460077bae1b76c7f1a661beec11ad66db071a4eb0e5d3e70e6a953f9518db799785abcb1f03bbb8ff2309c27a64d1bcc09187e0f951e8496015856e5050220c883";
    const LOOP_Q_HEX: &str = "be504384fcdb1222cde24b1e34138227c55246c6e200eadd5037f19688db1924ade0e1ce82cc984925efe829558f012b05865b2c28de7410612005d3cbccf4dd7e03395be63d385268425e03be6d18bb64ef417f0a18bdc4ac4e6014a4a2809daeaf3157694f34bfce1262cef19963846f49306b6679d3b11ee44df5a68bc063";
    const LOOP_DP_HEX: &str = "e08b6c5f18a9a4ff71a21580f0247c270ac34d87ba805afe7ea34904ddf1f3dfc2b6d17e7bdfc8833ef8b465fde1eb2e00e38e0b136420a45b10821b40ac5d013fa41e38493d17d5d98a37608507b35c1586b6bcdb5df9e963965cd06250f2a431e5e109b2e76ad40de73e1561c2569aa28d3d95535806d284356432361f3795";
    const LOOP_DQ_HEX: &str = "06a4e6b68ddd5814befb5784066d67eddb85b3d2ddb10a820f7ae4844ce2d94dde842b5dfa530a3e03850ca5e4c6c953a72db9a1210c23212f42def135fc41d039c6030aa24f20d83fab917caff93f13cbc24e9710d32c4ce1771b039d7bcee1b2678b6171dbc20bb036141d057245772a2b73f54bee94e56a1eae5a15266be1";
    const LOOP_QINV_HEX: &str = "c721f9f4e2dcb167ffc6c60f983bf63d033db03601bcc7acbf859bfb2465236684116f615b0c6d5eee3d35eb580d581e64fbbb9e092f8ddee13eabdbacaa98d47826bd71b0699c821e953e267e482d06fd0be05ffbf657c1e1d84318282b8b44aaad6832de293921a40840fd075c6f228f6cf9a91de30b9d95982cc0a9034da2";
    // Two python-generated signatures over the fixed transcript blob below:
    // rsa_pss_rsae_sha256 with 32-byte salt, and rsa_pkcs1_sha256.
    const LOOP_SIG_PSS_32SALT_HEX: &str = "136b8127d44631e028cd19b78fd7010c818b6f97a33dbd03ef43bb65f6675c3859ac90514817208b2a3da2f6c9e5f7ab52b3adb0c7d2d45233ab34a4f762203c5b014af15ee307bcec800c9fceafd119b7b91f606f1f203b5b7fac3794eb7742d6e2d3e627078ce10ca173dfbe75f034deb3c4b86b4600d588185275ec22ee0ebfa852a582ccb54acb5df39af6ab8b65d7f67c4c2297fc0e33dd78803b8ea781b33a84373ba8656e1c1c352202f088adaac337fba4a5d3e89193bc316526dd958fa88e667651ac4c42b2669e052664031c4515252208d1ca1fd77b895f8b0ada021bd8ecec8db83e38b315121b9c5ea4101b3f6a075657d0a7b88d6d1864803d";
    const LOOP_SIG_PKCS1_HEX: &str = "5800b40ef425985ebd788eb3ef6bf86fe7d0bef6f0ad3d22b53a042540fb4793104138b7fd1f827a87e64b17508902e5cb9423c451d0612d26e5588238609c316eb040c63e2335e13ddb696d824112f4ea92d38d0a5f5202c6a2113aab7fa6932e05095120ba36473dd27f5d9b237e2815f4ecffe06358b97dd5be240cea7f85bf2235e4068dc3b77919fbef75a678cf22937ef4db7bbb3477481efbc656cffa31aed9caf84ad65c89f0ff6eaadb700994fb99ab6c340c1663d14601b719e9bff0f96d700a61d3770fd57321b91262867938687a29cb021985062f03f52f4383f51d15bcca39177a2f4956c8e1bb611f626c7cf9f8be9a27a073957c0e309ebc";

    /// Fixed 64-byte transcript blob: bytes(range(64)) = 00 01 02 .. 3f.
    /// Both python signatures above are computed over exactly these bytes.
    const TRANSCRIPT_BLOB: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    /// python's sha256(TRANSCRIPT_BLOB) — independent cross-check of the blob.
    const TRANSCRIPT_SHA256_HEX: &str = "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108";

    // Malformed DER samples derived from fixture 1 (python-side mutations):
    // outer SEQUENCE cut short / first tag byte 30→31 / 5-byte DER length.
    const MAL_TRUNCATED: &str = "308202e6308201cea003020102021464bed66b15c162c22412fcb5c06fafbe453fba6e300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100b91a214b69a876a98e609dc64adb371c9404cddbb3789171f7c59fe4d3730a0347f8ad1d47c2e76fca5f201e49cf993eb02b74e0d3e01e4e65c4032614b9cad30ec6fc6577d2575d0bbb413763e240c9ff634637dd4234795d686cf05d8f5bdfbebde90181e6eccd0a22a496a93d93acb8a36fe7574e3f479f8197f8e94afcc2e38503497f3bc5a22d7011d0e6034fe1a878505f2b86cc13892b2ed3b39baee81fc89a772a04a5b3aa1291708c6d31fba5b81ff02635848bffa72d68875e38bee213d6ab3051a50c198105246dc98a202814b6902a57b8fdfef9aa4666b5f19b7161c4364498bb7c80ef60116d0de48dbe8a1a02c492fee287f3d619d5c5d1870203010001a318301630140603551d11040d300b82096c6f63616c686f7374300d06092a864886f70d01010b050003820101";
    const MAL_WRONG_TAG: &str = "318202e6308201cea003020102021464bed66b15c162c22412fcb5c06fafbe453fba6e300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100b91a214b69a876a98e609dc64adb371c9404cddbb3789171f7c59fe4d3730a0347f8ad1d47c2e76fca5f201e49cf993eb02b74e0d3e01e4e65c4032614b9cad30ec6fc6577d2575d0bbb413763e240c9ff634637dd4234795d686cf05d8f5bdfbebde90181e6eccd0a22a496a93d93acb8a36fe7574e3f479f8197f8e94afcc2e38503497f3bc5a22d7011d0e6034fe1a878505f2b86cc13892b2ed3b39baee81fc89a772a04a5b3aa1291708c6d31fba5b81ff02635848bffa72d68875e38bee213d6ab3051a50c198105246dc98a202814b6902a57b8fdfef9aa4666b5f19b7161c4364498bb7c80ef60116d0de48dbe8a1a02c492fee287f3d619d5c5d1870203010001a318301630140603551d11040d300b82096c6f63616c686f7374300d06092a864886f70d01010b0500038201010016ddae0d06c3dd5e253ff46ae7da83b4079597e1df420d599d3ab00eb899939dd3c896138804f3cafb64bf0ab2f43c492af273542be2f6fc2d18a22c96e8d6adac22cc88b188168cb4d47cfeac87deb2bd1ba8f9c4e3c36fb73884d0b7e3c51c7835e40c7db23ac6c70b9d4043516bd2f780520aff50bc8a1eac9d7d4da3447fdcc0a9dc461a370743da05301ee006fe1198f9587e262989baf7cd8128a68e87452cb8d58fc38ddc3886c50ec5381d4f4ab9ca641df6e9f21b00f619689a806fb1d303a5808217743e479921993b23500dd070dab73bab88dbd4bb6918c166be1489bda02ac84350e8aebb2fe5c369d16c5a0136186920e40fa39a2c5a79baf2";
    const MAL_LEN_OVERFLOW: &str = "30850100000000308201cea003020102021464bed66b15c162c22412fcb5c06fafbe453fba6e300d06092a864886f70d01010b05003020311e301c06035504030c15686f6c6f2d746c7320746573742066697874757265301e170d3235303130313030303030305a170d3335303130313030303030305a3020311e301c06035504030c15686f6c6f2d746c732074657374206669787475726530820122300d06092a864886f70d01010105000382010f003082010a0282010100b91a214b69a876a98e609dc64adb371c9404cddbb3789171f7c59fe4d3730a0347f8ad1d47c2e76fca5f201e49cf993eb02b74e0d3e01e4e65c4032614b9cad30ec6fc6577d2575d0bbb413763e240c9ff634637dd4234795d686cf05d8f5bdfbebde90181e6eccd0a22a496a93d93acb8a36fe7574e3f479f8197f8e94afcc2e38503497f3bc5a22d7011d0e6034fe1a878505f2b86cc13892b2ed3b39baee81fc89a772a04a5b3aa1291708c6d31fba5b81ff02635848bffa72d68875e38bee213d6ab3051a50c198105246dc98a202814b6902a57b8fdfef9aa4666b5f19b7161c4364498bb7c80ef60116d0de48dbe8a1a02c492fee287f3d619d5c5d1870203010001a318301630140603551d11040d300b82096c6f63616c686f7374300d06092a864886f70d01010b0500038201010016ddae0d06c3dd5e253ff46ae7da83b4079597e1df420d599d3ab00eb899939dd3c896138804f3cafb64bf0ab2f43c492af273542be2f6fc2d18a22c96e8d6adac22cc88b188168cb4d47cfeac87deb2bd1ba8f9c4e3c36fb73884d0b7e3c51c7835e40c7db23ac6c70b9d4043516bd2f780520aff50bc8a1eac9d7d4da3447fdcc0a9dc461a370743da05301ee006fe1198f9587e262989baf7cd8128a68e87452cb8d58fc38ddc3886c50ec5381d4f4ab9ca641df6e9f21b00f619689a806fb1d303a5808217743e479921993b23500dd070dab73bab88dbd4bb6918c166be1489bda02ac84350e8aebb2fe5c369d16c5a0136186920e40fa39a2c5a79baf2";

    fn hex_bytes(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd-length hex const");
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn pin32(s: &str) -> [u8; 32] {
        hex_bytes(s).try_into().unwrap()
    }

    /// Peel SubjectPublicKeyInfo → subjectPublicKey BIT STRING →
    /// RSAPublicKey SEQ { n INTEGER, e INTEGER } with the same minimal walker
    /// (test-only helper: the shipping module extracts nothing beyond what
    /// pinning needs). Returns minimal big-endian (n, e).
    fn rsa_pubkey_from_spki(spki_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut cur = Cursor::new(spki_der);
        let spki = expect_tlv(&mut cur, TAG_SEQ)?;
        let mut s = Cursor::new(spki);
        expect_tlv(&mut s, TAG_SEQ)?; // AlgorithmIdentifier (rsaEncryption)
        let bits = expect_tlv(&mut s, TAG_BITSTRING)?; // subjectPublicKey
        if s.remaining() != 0 {
            return Err("spki: der: trailing bytes".to_string());
        }
        if bits.is_empty() || bits[0] != 0 {
            return Err("spki: der: bitstring: unused bits not zero".to_string());
        }
        let mut k = Cursor::new(&bits[1..]);
        let rsa_seq = expect_tlv(&mut k, TAG_SEQ)?; // RSAPublicKey
        let mut r = Cursor::new(rsa_seq);
        let n = expect_tlv(&mut r, TAG_INT)?;
        let e = expect_tlv(&mut r, TAG_INT)?;
        if r.remaining() != 0 {
            return Err("spki: der: trailing bytes in RSAPublicKey".to_string());
        }
        // INTEGERs are positive here: drop the DER leading zero octet.
        let n = if n.len() > 1 && n[0] == 0 { &n[1..] } else { n };
        let e = if e.len() > 1 && e[0] == 0 { &e[1..] } else { e };
        Ok((n.to_vec(), e.to_vec()))
    }

    #[test]
    fn spki_pin_matches_python_computed_hash() {
        // Independent python cross-check: rust-side SHA-256 over the raw SPKI
        // span must equal python's sha256 over the serialized SPKI DER.
        let cases: &[(&str, &str)] = &[
            (CERT1_LOCALHOST_DNS, PIN1),
            (CERT2_IPV4_ONLY, PIN2),
            (CERT3_WILDCARD, PIN3),
            (CERT4_MULTI_SAN, PIN4),
            (CERT5_UNRELATED, PIN5),
            (CERT6_LOOPBACK, PIN6),
            (CERT7_WILDCARD_PARTIAL, PIN7),
            (CERT8_WILDCARD_DOUBLE, PIN8),
            (CERT9_IPV6, PIN9),
            (CERT10_NUL_SAN, PIN10),
            (CERT11_NO_SAN, PIN11),
        ];
        for (cert, want) in cases {
            assert_eq!(
                spki_pin_sha256(&hex_bytes(cert)).unwrap(),
                pin32(want),
                "SPKI pin mismatch vs python for fixture {cert}"
            );
        }
    }

    #[test]
    fn spki_pin_verify_positive_and_negative() {
        let c1 = hex_bytes(CERT1_LOCALHOST_DNS);
        let pin = spki_pin_sha256(&c1).unwrap();
        // positive: computed pin and python pin both verify (ct_eq path)
        assert!(verify_spki_pin(&c1, &pin).is_ok());
        assert!(verify_spki_pin(&c1, &pin32(PIN1)).is_ok());
        // negative: one flipped bit → distinct pin-mismatch error
        let mut bad = pin;
        bad[0] ^= 0x01;
        assert_eq!(
            verify_spki_pin(&c1, &bad).unwrap_err(),
            "spki: pin: sha256 mismatch"
        );
        // parse failure is a DIFFERENT error path than pin mismatch
        assert!(
            verify_spki_pin(&hex_bytes(MAL_TRUNCATED), &pin32(PIN1))
                .unwrap_err()
                .starts_with("spki: der:")
        );
    }

    #[test]
    fn san_dns_names_extracts_all_variants() {
        assert_eq!(
            dns_names(&hex_bytes(CERT1_LOCALHOST_DNS)).unwrap(),
            vec!["localhost"]
        );
        assert_eq!(
            dns_names(&hex_bytes(CERT3_WILDCARD)).unwrap(),
            vec!["*.example.com"]
        );
        assert_eq!(
            dns_names(&hex_bytes(CERT5_UNRELATED)).unwrap(),
            vec!["foo.bar"]
        );
        assert_eq!(
            dns_names(&hex_bytes(CERT7_WILDCARD_PARTIAL)).unwrap(),
            vec!["*x.example.com"]
        );
        assert_eq!(
            dns_names(&hex_bytes(CERT8_WILDCARD_DOUBLE)).unwrap(),
            vec!["*.*.example.com"]
        );
        assert_eq!(
            dns_names(&hex_bytes(CERT4_MULTI_SAN)).unwrap(),
            vec!["localhost"]
        );
        // IP-only cert: no DNS names, but the IPv4 octets are there
        assert!(dns_names(&hex_bytes(CERT2_IPV4_ONLY)).unwrap().is_empty());
        assert_eq!(
            ip_addresses(&hex_bytes(CERT2_IPV4_ONLY)).unwrap(),
            vec![vec![127, 0, 0, 1]]
        );
        assert_eq!(
            ip_addresses(&hex_bytes(CERT4_MULTI_SAN)).unwrap(),
            vec![vec![127, 0, 0, 1]]
        );
        let mut v6 = vec![0u8; 15];
        v6.push(1); // ::1
        assert_eq!(ip_addresses(&hex_bytes(CERT9_IPV6)).unwrap(), vec![v6]);
    }

    #[test]
    fn wildcard_leftmost_label_matches() {
        let c = hex_bytes(CERT3_WILDCARD); // SAN: *.example.com
        assert_eq!(matches_hostname(&c, "a.example.com").unwrap(), true);
        assert_eq!(matches_hostname(&c, "www.example.com").unwrap(), true);
        // `*` substitutes exactly ONE label:
        assert_eq!(matches_hostname(&c, "b.a.example.com").unwrap(), false);
        assert_eq!(matches_hostname(&c, "example.com").unwrap(), false);
        assert_eq!(matches_hostname(&c, "notexample.com").unwrap(), false);
    }

    #[test]
    fn wildcard_partial_rejected() {
        let c = hex_bytes(CERT7_WILDCARD_PARTIAL); // SAN: *x.example.com
        assert_eq!(matches_hostname(&c, "ax.example.com").unwrap(), false);
        assert_eq!(matches_hostname(&c, "x.example.com").unwrap(), false);
        assert_eq!(matches_hostname(&c, "abc.example.com").unwrap(), false);
    }

    #[test]
    fn wildcard_double_rejected() {
        let c = hex_bytes(CERT8_WILDCARD_DOUBLE); // SAN: *.*.example.com
        assert_eq!(matches_hostname(&c, "a.b.example.com").unwrap(), false);
        assert_eq!(matches_hostname(&c, "a.example.com").unwrap(), false);
        assert_eq!(matches_hostname(&c, "b.c.example.com").unwrap(), false);
    }

    #[test]
    fn wildcard_rejects_second_label_only_substitution() {
        // Documented choice: a `*` in the HOSTNAME argument is never honored
        // (reference identifiers are literal) → Ok(false), not an error.
        let c = hex_bytes(CERT3_WILDCARD); // SAN: *.example.com
        assert_eq!(matches_hostname(&c, "a.*.example.com").unwrap(), false);
        assert_eq!(matches_hostname(&c, "*.example.com").unwrap(), false);
    }

    #[test]
    fn ip_san_matches_ipv4_literal_only() {
        let c2 = hex_bytes(CERT2_IPV4_ONLY);
        assert_eq!(matches_hostname(&c2, "127.0.0.1").unwrap(), true);
        assert_eq!(matches_hostname(&c2, "127.0.0.2").unwrap(), false);
        assert_eq!(
            matches_hostname(&hex_bytes(CERT4_MULTI_SAN), "127.0.0.1").unwrap(),
            true
        );
        // IPv6 SAN: bare literal forms only
        let c9 = hex_bytes(CERT9_IPV6);
        assert_eq!(matches_hostname(&c9, "::1").unwrap(), true);
        assert_eq!(matches_hostname(&c9, "0:0:0:0:0:0:0:1").unwrap(), true);
        assert_eq!(matches_hostname(&c9, "::2").unwrap(), false);
    }

    #[test]
    fn ip_san_does_not_match_dns_hostname() {
        assert_eq!(
            matches_hostname(&hex_bytes(CERT2_IPV4_ONLY), "localhost").unwrap(),
            false
        );
        assert_eq!(
            matches_hostname(&hex_bytes(CERT9_IPV6), "ip6-localhost").unwrap(),
            false
        );
    }

    #[test]
    fn nul_in_san_rejected() {
        let c = hex_bytes(CERT10_NUL_SAN); // SAN dNSName: "localhost\0evil.example.com"
        assert_eq!(
            matches_hostname(&c, "localhost").unwrap_err(),
            "spki: san: embedded NUL"
        );
        assert_eq!(
            matches_hostname(&c, "evil.example.com").unwrap_err(),
            "spki: san: embedded NUL"
        );
        // documented: the guard lives in matches_hostname; the raw extractor
        // returns the (NUL-carrying) IA5 payload unchanged
        assert!(dns_names(&c).unwrap().iter().any(|n| n.contains('\0')));
    }

    #[test]
    fn absent_san_errors_on_hostname_check() {
        let c = hex_bytes(CERT11_NO_SAN);
        assert_eq!(
            matches_hostname(&c, "localhost").unwrap_err(),
            "spki: san: absent"
        );
        assert_eq!(dns_names(&c).unwrap_err(), "spki: san: absent");
        assert_eq!(ip_addresses(&c).unwrap_err(), "spki: san: absent");
    }

    #[test]
    fn malformed_truncated_rejected() {
        let c = hex_bytes(MAL_TRUNCATED); // fixture 1 cut short by 257 bytes
        assert_eq!(spki_pin_sha256(&c).unwrap_err(), "spki: der: truncated");
        assert!(dns_names(&c).is_err());
    }

    #[test]
    fn malformed_wrong_tag_rejected() {
        let c = hex_bytes(MAL_WRONG_TAG); // outer SEQ tag 30 -> 31 (SET)
        assert_eq!(
            spki_pin_sha256(&c).unwrap_err(),
            "spki: der: tag 31 (expected 30)"
        );
    }

    #[test]
    fn malformed_length_overflow_rejected() {
        let c = hex_bytes(MAL_LEN_OVERFLOW); // outer length encoded with 5 length bytes
        assert_eq!(
            spki_pin_sha256(&c).unwrap_err(),
            "spki: der: length overflow (5 length bytes)"
        );
    }

    #[test]
    fn loopback_fixture_both_signatures_verify_against_spki() {
        let cert = hex_bytes(CERT6_LOOPBACK);
        // 1) the pin cross-checks against python
        verify_spki_pin(&cert, &pin32(PIN6)).unwrap();
        // 2) pull n/e OUT of the cert's own SPKI span — proves the span is
        //    sliceable and the walker extracts the real key material
        let tbs = cert_tbs(&cert).unwrap();
        let spki = tbs_spki_span(tbs).unwrap();
        let (n, e) = rsa_pubkey_from_spki(spki).unwrap();
        assert_eq!(n, hex_bytes(LOOP_N_HEX)); // provenance: python-exported modulus
        assert_eq!(e, hex_bytes(LOOP_E_HEX)); // e = 010001
        // 3) both python signatures over the fixed transcript blob verify via
        //    holo-crypto RSA (signatures were made by the pinned key)
        let h = sha256::digest(&TRANSCRIPT_BLOB);
        assert_eq!(hex_bytes(TRANSCRIPT_SHA256_HEX), h.to_vec()); // blob cross-check
        rsa::verify_pkcs1_v1_5_sha256(&n, &e, &h, &hex_bytes(LOOP_SIG_PKCS1_HEX)).unwrap();
        rsa::verify_pss_sha256(&n, &e, 32, &h, &hex_bytes(LOOP_SIG_PSS_32SALT_HEX)).unwrap();
        // 4) negatives: tampered signature / tampered transcript / wrong salt len
        let mut bad_sig = hex_bytes(LOOP_SIG_PKCS1_HEX);
        bad_sig[10] ^= 0x80;
        assert!(rsa::verify_pkcs1_v1_5_sha256(&n, &e, &h, &bad_sig).is_err());
        let mut blob = TRANSCRIPT_BLOB;
        blob[0] ^= 0x01;
        let h2 = sha256::digest(&blob);
        assert!(rsa::verify_pss_sha256(&n, &e, 32, &h2, &hex_bytes(LOOP_SIG_PSS_32SALT_HEX)).is_err());
        assert!(rsa::verify_pss_sha256(&n, &e, 0, &h, &hex_bytes(LOOP_SIG_PSS_32SALT_HEX)).is_err());
    }

    #[test]
    fn loopback_key_crt_components_are_consistent() {
        // Full provenance of the embedded private-key constants against the
        // exported modulus, via holo_crypto::bignum (RFC 8017 §3.2):
        //   n == p*q;  dP == d mod (p-1);  dQ == d mod (q-1);  qInv*q ≡ 1 (mod p)
        let n = hex_bytes(LOOP_N_HEX);
        let d = bignum::os2ip(&hex_bytes(LOOP_D_HEX));
        let p = bignum::os2ip(&hex_bytes(LOOP_P_HEX));
        let q = bignum::os2ip(&hex_bytes(LOOP_Q_HEX));
        // n == p*q
        let n2 = bignum::i2osp(&bignum::mul(&p, &q), 256).unwrap();
        assert_eq!(n2, n);
        // dP == d mod (p-1), dQ == d mod (q-1)
        let pm1 = bignum::sub(&p, &[1]).unwrap();
        let qm1 = bignum::sub(&q, &[1]).unwrap();
        let dp = bignum::i2osp(&bignum::rem(&d, &pm1), 128).unwrap();
        assert_eq!(dp, hex_bytes(LOOP_DP_HEX));
        let dq = bignum::i2osp(&bignum::rem(&d, &qm1), 128).unwrap();
        assert_eq!(dq, hex_bytes(LOOP_DQ_HEX));
        // qInv * q ≡ 1 (mod p)
        let qinv = bignum::os2ip(&hex_bytes(LOOP_QINV_HEX));
        let one = bignum::i2osp(&bignum::rem(&bignum::mul(&qinv, &q), &p), 128).unwrap();
        let mut expect_one = vec![0u8; 127];
        expect_one.push(1);
        assert_eq!(one, expect_one);
    }

    #[test]
    fn hostname_case_insensitive_exact_match() {
        let c1 = hex_bytes(CERT1_LOCALHOST_DNS);
        // RFC 6125 §6.4.1: ASCII case-insensitive comparison
        assert_eq!(matches_hostname(&c1, "LOCALHOST").unwrap(), true);
        assert_eq!(matches_hostname(&c1, "LocalHost").unwrap(), true);
        // trailing dot is a DIFFERENT name (no implicit suffix strip)
        assert_eq!(matches_hostname(&c1, "localhost.").unwrap(), false);
        let c5 = hex_bytes(CERT5_UNRELATED);
        assert_eq!(matches_hostname(&c5, "FOO.BAR").unwrap(), true);
        assert_eq!(matches_hostname(&c5, "localhost").unwrap(), false);
        // multi-SAN cert: both name kinds match
        let c4 = hex_bytes(CERT4_MULTI_SAN);
        assert_eq!(matches_hostname(&c4, "LOCALHOST").unwrap(), true);
        assert_eq!(matches_hostname(&c4, "127.0.0.1").unwrap(), true);
    }
}
