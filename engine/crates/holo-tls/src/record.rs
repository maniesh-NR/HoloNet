//! TLS 1.3 record layer — RFC 8446 §5.1 (Record Layer), §5.2 (Record Payload
//! Protection framing), §5.4 (Record Padding).
//!
//! Normative behaviour implemented here, with the exact RFC 8446 sentences:
//!
//! §5.1 (lines 4384-4389):
//! > struct {
//! >     ContentType type;
//! >     ProtocolVersion legacy_record_version;
//! >     uint16 length;
//! >     opaque fragment[TLSPlaintext.length];
//! > } TLSPlaintext;
//!
//! §5.1 (lines 4402-4405):
//! > length:  The length (in bytes) of the following TLSPlaintext.fragment.
//! > The length MUST NOT exceed 2^14 bytes.  An endpoint that receives a
//! > record that exceeds this length MUST terminate the connection with a
//! > "record_overflow" alert.
//!
//! §5.1 (lines 4394-4398):
//! > legacy_record_version: MUST be set to 0x0303 for all records generated
//! > by a TLS 1.3 implementation other than an initial ClientHello (i.e.,
//! > one not generated after a HelloRetryRequest), where it MAY also be
//! > 0x0301 for compatibility purposes.  This field is deprecated and MUST
//! > be ignored for all purposes.
//!
//! §5.1 (lines 4413-4417):
//! > In order to maximize backward compatibility, a record containing an
//! > initial ClientHello SHOULD have version 0x0301 (reflecting TLS 1.0) and
//! > a record containing a second ClientHello or a ServerHello MUST have
//! > version 0x0303 (reflecting TLS 1.2).
//!
//! §5.1 (lines 4335-4356):
//! > Handshake messages MAY be coalesced into a single TLSPlaintext record
//! > or fragmented across several records, provided that:
//! > - Handshake messages MUST NOT be interleaved with other record types.
//! >   That is, if a handshake message is split over two or more records,
//! >   there MUST NOT be any other records between them.
//! > ...
//! > Implementations MUST NOT send zero-length fragments of Handshake
//! > types, even if those fragments contain padding.
//!
//! §5.2 (lines 4450-4454) — the plaintext that goes *into* the AEAD:
//! > struct {
//! >     opaque content[TLSPlaintext.length];
//! >     ContentType type;
//! >     uint8 zeros[length_of_padding];
//! > } TLSInnerPlaintext;
//!
//! §5.2 (lines 4501-4507):
//! > length: ... MUST NOT exceed 2^14 + 256 bytes.  An endpoint that
//! > receives a record that exceeds this length MUST terminate the
//! > connection with a "record_overflow" alert.
//!
//! §5.4 (lines 4655-4669):
//! > upon successful decryption of a TLSCiphertext.encrypted_record, the
//! > receiving implementation scans the field from the end toward the
//! > beginning until it finds a non-zero octet.  This non-zero octet is the
//! > content type of the message.
//! > ...
//! > If a receiving implementation does not find a non-zero octet in the
//! > cleartext, it MUST terminate the connection with an
//! > "unexpected_message" alert.
//!
//! §5.4 (lines 4631-4638):
//! > Implementations MUST NOT send Handshake and Alert records that have a
//! > zero-length TLSInnerPlaintext.content; if such a message is received,
//! > the receiving implementation MUST terminate the connection with an
//! > "unexpected_message" alert.
//!
//! This module is the *framing* layer only: AEAD sealing/opening stays in
//! `holo-crypto` (ChaCha20-Poly1305 / AES-GCM); the key schedule lives in the
//! lead's `schedule` module.  [`encode_inner_plaintext`] /
//! [`decode_inner_plaintext`] handle exactly the TLSInnerPlaintext byte
//! layout that sits inside (or outside, pre-negotiation) the AEAD envelope.

use crate::{Error, Result};

/// RFC 8446 §5.1, line 4403: TLSPlaintext.fragment "MUST NOT exceed 2^14
/// bytes" — the hard bound for UNPROTECTED records.
pub const MAX_PLAINTEXT_FRAGMENT: usize = 1 << 14;

/// RFC 8446 §5.4, line 4672: "the full encoded TLSInnerPlaintext MUST NOT
/// exceed 2^14 + 1 octets" (content + 1 content-type octet + padding).
pub const MAX_INNER_PLAINTEXT: usize = (1 << 14) + 1;

/// RFC 8446 §5.2, line 4505: TLSCiphertext.length "MUST NOT exceed
/// 2^14 + 256 bytes".
pub const MAX_CIPHERTEXT: usize = (1 << 14) + 256;

/// RFC 8446 §5.1: every record header is 5 bytes.
pub const RECORD_HEADER_LEN: usize = 5;

/// RFC 8446 §5.1, line 4414: version on a record containing an INITIAL
/// ClientHello ("SHOULD have version 0x0301").
pub const LEGACY_VERSION_INITIAL_CLIENT_HELLO: u16 = 0x0301;

/// RFC 8446 §5.1, line 4416: version on every other record ("MUST have
/// version 0x0303").
pub const LEGACY_VERSION_OTHER: u16 = 0x0303;

/// RFC 8446 §5.1, lines 4375-4382:
///
/// ```text
/// enum {
///     invalid(0),
///     change_cipher_spec(20),
///     alert(21),
///     handshake(22),
///     application_data(23),
///     (255)
/// } ContentType;
/// ```
///
/// NOTE: handshake is 22 (the task briefing's "20 handshake" is a typo — 20
/// is change_cipher_spec, quoted from the fetched RFC text above).  We
/// implement codec support for alert / handshake / application_data; CCS
/// exists as a named constant because §5.1 defines it (middlebox
/// compatibility records) but it carries no TLS 1.3 handshake semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

impl ContentType {
    pub fn as_u8(self) -> u8 {
        match self {
            ContentType::ChangeCipherSpec => 20,
            ContentType::Alert => 21,
            ContentType::Handshake => 22,
            ContentType::ApplicationData => 23,
        }
    }

    /// Decode a ContentType byte. `invalid(0)` and the (255) catch-all of
    /// RFC 8446 §5.1 line 4381 are rejected with a distinct error — a record
    /// with an unknown type cannot be routed to any handler.
    pub fn from_u8(b: u8) -> Result<Self> {
        match b {
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            _ => Err(Error::RecordUnknownContentType(b)),
        }
    }
}

/// RFC 8446 §5.1 TLSPlaintext: one unencrypted record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPlaintext {
    pub content_type: ContentType,
    /// Parsed but never validated — RFC 8446 §5.1, lines 4397-4398: "This
    /// field is deprecated and MUST be ignored for all purposes."
    pub legacy_record_version: u16,
    pub fragment: Vec<u8>,
}

impl TlsPlaintext {
    /// Build a record, checking the §5.1 fragment bound.
    pub fn new(content_type: ContentType, legacy_record_version: u16, fragment: Vec<u8>) -> Result<Self> {
        if fragment.len() > MAX_PLAINTEXT_FRAGMENT {
            return Err(Error::RecordFragmentTooLong {
                got: fragment.len(),
                max: MAX_PLAINTEXT_FRAGMENT,
            });
        }
        Ok(TlsPlaintext { content_type, legacy_record_version, fragment })
    }

    /// Encode the full record: 5-byte header + fragment.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.fragment.len() <= MAX_PLAINTEXT_FRAGMENT);
        let mut out = Vec::with_capacity(RECORD_HEADER_LEN + self.fragment.len());
        out.push(self.content_type.as_u8());
        out.extend_from_slice(&self.legacy_record_version.to_be_bytes());
        out.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.fragment);
        out
    }

    /// Decode one record from the front of `buf`.  Returns the record and
    /// the number of bytes consumed.  Trailing bytes in `buf` belong to
    /// subsequent records.
    pub fn decode(buf: &[u8]) -> Result<(TlsPlaintext, usize)> {
        if buf.len() < RECORD_HEADER_LEN {
            return Err(Error::RecordHeaderTruncated { got: buf.len() });
        }
        let content_type = ContentType::from_u8(buf[0])?;
        let legacy_record_version = u16::from_be_bytes([buf[1], buf[2]]);
        let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        // RFC 8446 §5.1, line 4403-4405: length > 2^14 → record_overflow.
        if length > MAX_PLAINTEXT_FRAGMENT {
            return Err(Error::RecordFragmentTooLong {
                got: length,
                max: MAX_PLAINTEXT_FRAGMENT,
            });
        }
        let total = RECORD_HEADER_LEN + length;
        if buf.len() < total {
            return Err(Error::RecordFragmentMismatch {
                declared: length,
                available: buf.len() - RECORD_HEADER_LEN,
            });
        }
        Ok((
            TlsPlaintext {
                content_type,
                legacy_record_version,
                fragment: buf[RECORD_HEADER_LEN..total].to_vec(),
            },
            total,
        ))
    }
}

/// RFC 8446 §5.2 TLSCiphertext header framing
/// (`opaque_type=23 | legacy_record_version=0x0303 | uint16 length`).
/// The encrypted_record itself is AEAD output handled by holo-crypto; this
/// codec exists so record-length overflow (2^14+256, §5.2 line 4505) is
/// caught BEFORE spending a decryption.
pub fn decode_ciphertext_header(buf: &[u8]) -> Result<usize> {
    if buf.len() < RECORD_HEADER_LEN {
        return Err(Error::RecordHeaderTruncated { got: buf.len() });
    }
    let opaque_type = ContentType::from_u8(buf[0])?;
    if opaque_type != ContentType::ApplicationData {
        // §5.2, line 4487-4491: opaque_type of TLSCiphertext is ALWAYS 23.
        return Err(Error::RecordUnknownContentType(buf[0]));
    }
    let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if length > MAX_CIPHERTEXT {
        return Err(Error::RecordFragmentTooLong {
            got: length,
            max: MAX_CIPHERTEXT,
        });
    }
    Ok(length)
}

/// Build the 5-byte TLSCiphertext header (§5.2 lines 4456-4461).
pub fn encode_ciphertext_header(encrypted_len: usize) -> Result<[u8; RECORD_HEADER_LEN]> {
    if encrypted_len > MAX_CIPHERTEXT {
        return Err(Error::RecordFragmentTooLong {
            got: encrypted_len,
            max: MAX_CIPHERTEXT,
        });
    }
    let mut hdr = [0u8; RECORD_HEADER_LEN];
    hdr[0] = ContentType::ApplicationData.as_u8();
    hdr[1..3].copy_from_slice(&LEGACY_VERSION_OTHER.to_be_bytes());
    hdr[3..5].copy_from_slice(&(encrypted_len as u16).to_be_bytes());
    Ok(hdr)
}

/// Build the RFC 8446 §5.4 TLSInnerPlaintext:
/// `content || content_type || zeros[length_of_padding]`.
///
/// §5.4, lines 4628-4638: padding octets MUST be zero; handshake and alert
/// records MUST NOT have zero-length content.  This is the plaintext input
/// to the AEAD (§5.2 line 4525: "The plaintext input to the AEAD algorithm
/// is the encoded TLSInnerPlaintext structure.").
pub fn encode_inner_plaintext(
    content: &[u8],
    content_type: ContentType,
    padding_len: usize,
) -> Result<Vec<u8>> {
    match content_type {
        ContentType::Handshake | ContentType::Alert => {
            if content.is_empty() {
                return Err(Error::InnerPlaintextEmptyHandshakeOrAlert);
            }
        }
        ContentType::ChangeCipherSpec => {
            // CCS is never carried inside a protected record in TLS 1.3
            // (§5.1 line 4331 reserves it for compatibility records).
            return Err(Error::InnerPlaintextInvalidType(content_type.as_u8()));
        }
        ContentType::ApplicationData => {}
    }
    let total = content.len() + 1 + padding_len;
    if total > MAX_INNER_PLAINTEXT {
        return Err(Error::InnerPlaintextTooLong {
            got: total,
            max: MAX_INNER_PLAINTEXT,
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(content);
    out.push(content_type.as_u8());
    out.resize(total, 0); // the §5.4 zero padding
    Ok(out)
}

/// Reverse of [`encode_inner_plaintext`] — §5.4, lines 4655-4659: scan from
/// the end toward the beginning until a non-zero octet is found; that octet
/// is the content type, everything before it is the content.  Returns the
/// content type and the (borrowed) content slice.
pub fn decode_inner_plaintext(inner: &[u8]) -> Result<(ContentType, &[u8])> {
    let Some(pos) = inner.iter().rposition(|&b| b != 0) else {
        // §5.4, lines 4666-4669: no non-zero octet → unexpected_message.
        return Err(Error::InnerPlaintextMissingType);
    };
    let ct_byte = inner[pos];
    // Only the types that travel inside protected records.
    let content_type = match ct_byte {
        21 => ContentType::Alert,
        22 => ContentType::Handshake,
        23 => ContentType::ApplicationData,
        _ => return Err(Error::InnerPlaintextInvalidType(ct_byte)),
    };
    let content = &inner[..pos];
    if content.is_empty() {
        // §5.4, lines 4631-4638: handshake/alert MUST NOT be empty;
        // zero-length ApplicationData is legal cover traffic (§5.1 line
        // 4360: "Zero-length fragments of Application Data MAY be sent").
        if content_type != ContentType::ApplicationData {
            return Err(Error::InnerPlaintextEmptyHandshakeOrAlert);
        }
    }
    Ok((content_type, content))
}

/// One reassembled handshake message: the full wire bytes (4-byte header +
/// body), exactly the unit the transcript hash needs (RFC 8446 §4.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeFrame {
    pub bytes: Vec<u8>,
}

impl HandshakeFrame {
    pub fn msg_type(&self) -> u8 {
        self.bytes[0]
    }

    pub fn declared_len(&self) -> usize {
        ((self.bytes[1] as usize) << 16) | ((self.bytes[2] as usize) << 8) | self.bytes[3] as usize
    }

    pub fn body(&self) -> &[u8] {
        &self.bytes[4..]
    }
}

/// Inbound handshake-message reassembly (RFC 8446 §5.1).
///
/// Accepts the fragments of handshake-type records in wire order and emits
/// complete messages.  Handles BOTH §5.1 shapes:
/// - several complete handshake messages coalesced into one record, and
/// - one handshake message fragmented across several records,
/// and enforces the §5.1 interleaving prohibition: while a message is split
/// across records, a different-typed record between the fragments is an
/// error ("Handshake messages MUST NOT be interleaved with other record
/// types").
#[derive(Debug, Default)]
pub struct HandshakeAssembler {
    /// Buffered bytes of the currently-split message (empty when no message
    /// is pending).
    pending: Vec<u8>,
}

impl HandshakeAssembler {
    pub fn new() -> Self {
        HandshakeAssembler { pending: Vec::new() }
    }

    /// True while a handshake message is still waiting for more fragments.
    pub fn is_split_open(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Feed the fragment of ONE handshake record.  Returns every message
    /// completed by this fragment, in order.  Zero-length fragments are
    /// rejected (§5.1, line 4350).
    pub fn push_fragment(&mut self, fragment: &[u8]) -> Result<Vec<HandshakeFrame>> {
        if fragment.is_empty() {
            return Err(Error::HandshakeZeroLengthFragment);
        }
        self.pending.extend_from_slice(fragment);
        let mut done = Vec::new();
        loop {
            if self.pending.len() < 4 {
                break;
            }
            let declared = ((self.pending[1] as usize) << 16)
                | ((self.pending[2] as usize) << 8)
                | self.pending[3] as usize;
            let total = 4 + declared;
            if self.pending.len() < total {
                break; // still fragmented; wait for more records
            }
            let mut bytes = self.pending.drain(..total).collect::<Vec<u8>>();
            // A corrupt stream cannot derail the assembler: u24 lengths that
            // point into the middle of another message are caught by the
            // caller when the frame is decoded by the handshake codec.
            done.push(HandshakeFrame { bytes: std::mem::take(&mut bytes) });
        }
        Ok(done)
    }

    /// Feed a batch of records (already TLSPlaintext-decoded).  Enforces the
    /// §5.1 interleaving rule: a non-handshake record between the fragments
    /// of a split message is rejected with [`Error::HandshakeInterleaved`];
    /// non-handshake records encountered while NO message is pending are
    /// simply skipped (alerts and app data legitimately occur between
    /// complete handshake messages).
    pub fn push_records(&mut self, records: &[TlsPlaintext]) -> Result<Vec<HandshakeFrame>> {
        let mut done = Vec::new();
        for rec in records {
            if rec.content_type != ContentType::Handshake {
                if self.is_split_open() {
                    return Err(Error::HandshakeInterleaved);
                }
                continue;
            }
            done.extend(self.push_fragment(&rec.fragment)?);
        }
        Ok(done)
    }
}

/// Outbound fragmentation of ONE handshake message across several record
/// payloads, each at most `max_fragment` bytes (§5.1: "Handshake messages
/// MAY be coalesced into a single TLSPlaintext record or fragmented across
/// several records").  A message that fits is returned as a single fragment.
/// Zero-length messages cannot be fragmented (§5.1, line 4350).
pub fn fragment_message(raw: &[u8], max_fragment: usize) -> Result<Vec<Vec<u8>>> {
    if raw.is_empty() {
        return Err(Error::HandshakeZeroLengthFragment);
    }
    if max_fragment == 0 {
        // A zero max would imply zero-length fragments — forbidden above.
        return Err(Error::HandshakeZeroLengthFragment);
    }
    if max_fragment > MAX_PLAINTEXT_FRAGMENT {
        return Err(Error::RecordFragmentTooLong {
            got: max_fragment,
            max: MAX_PLAINTEXT_FRAGMENT,
        });
    }
    if raw.len() <= max_fragment {
        return Ok(vec![raw.to_vec()]);
    }
    let mut out = Vec::new();
    for chunk in raw.chunks(max_fragment) {
        out.push(chunk.to_vec());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc8448;

    #[test]
    fn record_fragmentation_reassembly() {
        // Take the RFC 8448 §3 ClientHello (196 octets, RFC lines 177-186)
        // and split its raw handshake message across THREE handshake records
        // (60 + 60 + 76 bytes) — the §5.1 "fragmented across several
        // records" shape.  legacy_record_version: 0x0301 would be used for
        // the first flight; here we use 0x0303 for all (both legal for
        // decode — the field MUST be ignored, §5.1 line 4397).
        let raw = &*rfc8448::client_hello();
        let pieces = fragment_message(raw, 60).unwrap();
        assert_eq!(pieces.len(), 4, "196 bytes split at 60: 60+60+60+16");
        assert!(pieces.iter().all(|p| p.len() <= 60));

        let records: Vec<TlsPlaintext> = pieces
            .into_iter()
            .map(|p| TlsPlaintext::new(ContentType::Handshake, LEGACY_VERSION_OTHER, p).unwrap())
            .collect();
        // Wire bytes round-trip: decode each record back out of its encoding.
        let mut decoded = Vec::new();
        for rec in &records {
            let wire = rec.encode();
            let (r, used) = TlsPlaintext::decode(&wire).unwrap();
            assert_eq!(used, wire.len());
            assert_eq!(&r, rec);
            decoded.push(r);
        }

        let mut asm = HandshakeAssembler::new();
        let frames = asm.push_records(&decoded).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(!asm.is_split_open());
        assert_eq!(frames[0].bytes, *raw);
        assert_eq!(frames[0].msg_type(), 0x01); // client_hello
        assert_eq!(frames[0].declared_len(), raw.len() - 4);
        assert_eq!(frames[0].body(), &raw[4..]);
    }

    #[test]
    fn record_multiple_handshakes_one_record() {
        // RFC 8448 §3, lines 457-488: the server flight payload (657 octets)
        // coalesces EncryptedExtensions + Certificate + CertificateVerify +
        // Finished into ONE record.  We rebuild that coalescing from the
        // individual published messages and re-parse it through one record
        // (the §5.1 "coalesced into a single TLSPlaintext record" shape).
        let flight = rfc8448::server_flight_payload().to_vec();
        let rec = TlsPlaintext::new(ContentType::Handshake, LEGACY_VERSION_OTHER, flight.clone()).unwrap();
        let wire = rec.encode();
        assert_eq!(wire.len(), 5 + 657);
        let (r, used) = TlsPlaintext::decode(&wire).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(r.fragment, flight);

        let mut asm = HandshakeAssembler::new();
        let frames = asm.push_records(&[r]).unwrap();
        assert_eq!(frames.len(), 4);
        let types: Vec<u8> = frames.iter().map(|f| f.msg_type()).collect();
        assert_eq!(types, vec![0x08, 0x0b, 0x0f, 0x14]); // EE, Certificate, CertVerify, Finished
        assert!(!asm.is_split_open());
        assert_eq!(
            frames.iter().map(|f| f.bytes.len()).sum::<usize>(),
            657,
            "reassembly must preserve every byte"
        );
    }

    #[test]
    fn record_rejects_mixed_content_types() {
        // §5.1, lines 4338-4340: "if a handshake message is split over two or
        // more records, there MUST NOT be any other records between them."
        // Synthetic case: the RFC 8448 ClientHello is split in half and an
        // ALERT record is inserted between the two fragments.
        let raw = &*rfc8448::client_hello();
        let (first, second) = raw.split_at(100);
        let rec1 = TlsPlaintext::new(ContentType::Handshake, LEGACY_VERSION_OTHER, first.to_vec()).unwrap();
        let rec2 = TlsPlaintext::new(ContentType::Handshake, LEGACY_VERSION_OTHER, second.to_vec()).unwrap();
        let alert_rec = TlsPlaintext::new(
            ContentType::Alert,
            LEGACY_VERSION_OTHER,
            vec![0x02, 0x28], // fatal handshake_failure, §6 line 4774
        )
        .unwrap();

        let mut asm = HandshakeAssembler::new();
        let err = asm
            .push_records(&[rec1, alert_rec.clone(), rec2])
            .unwrap_err();
        assert_eq!(err, Error::HandshakeInterleaved);
        assert!(format!("{err}").contains("MUST NOT be interleaved"));

        // Negative control: a complete handshake record followed by an alert
        // record and another complete handshake record is NOT interleaving —
        // no split is open between them.
        let ee = rfc8448::encrypted_extensions().to_vec();
        let cv = rfc8448::certificate_verify().to_vec();
        let rec_ee = TlsPlaintext::new(ContentType::Handshake, LEGACY_VERSION_OTHER, ee).unwrap();
        let rec_cv = TlsPlaintext::new(ContentType::Handshake, LEGACY_VERSION_OTHER, cv).unwrap();
        let mut asm2 = HandshakeAssembler::new();
        let frames = asm2
            .push_records(&[rec_ee, alert_rec, rec_cv])
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].msg_type(), 0x08);
        assert_eq!(frames[1].msg_type(), 0x0f);

        // A record cannot carry two content types by construction (one type
        // byte, §5.1 TLSPlaintext struct); attempting to smuggle a second
        // content stream inside a handshake record fails as a decode error
        // when the trailing bytes are not a valid handshake header.
        let mut smuggle = rfc8448::encrypted_extensions().to_vec();
        // Complete bogus message whose type byte 0x15 (21 = alert content
        // type!) is not a HandshakeType — a stream that "smuggles" a second
        // content type inside a handshake record cannot be routed anywhere;
        // the codec surfaces it faithfully for the caller to abort.
        smuggle.extend_from_slice(&[0x15, 0x00, 0x00, 0x02, 0xde, 0xad]);
        let rec3 = TlsPlaintext::new(ContentType::Handshake, LEGACY_VERSION_OTHER, smuggle).unwrap();
        let mut asm3 = HandshakeAssembler::new();
        let frames = asm3.push_records(&[rec3]).unwrap();
        assert_eq!(frames.len(), 2, "EE parses; the trailing 4 bytes declare an alert-type 'message'");
        assert_eq!(frames[1].msg_type(), 0x15, "codec faithfully reports the alien type byte for the caller to reject");
        assert_eq!(
            crate::handshake::HandshakeType::from_u8(0x15),
            Err(Error::UnknownHandshakeType(0x15))
        );
    }

    #[test]
    fn record_rejects_oversized() {
        // §5.1, lines 4402-4405: "The length MUST NOT exceed 2^14 bytes...
        // MUST terminate the connection with a 'record_overflow' alert."
        // Synthetic header: handshake record claiming 16385 bytes of
        // fragment (2^14 + 1).
        let mut wire = vec![22, 0x03, 0x03, 0x40, 0x01]; // length = 0x4001 = 16385
        wire.extend_from_slice(&vec![0u8; 16]);
        let err = TlsPlaintext::decode(&wire).unwrap_err();
        assert_eq!(
            err,
            Error::RecordFragmentTooLong { got: 16385, max: 16384 }
        );
        assert_eq!(err.alert(), crate::alert::AlertDescription::RecordOverflow);
        assert!(format!("{err}").contains("record_overflow"));

        // The encode path enforces the same bound.
        let big = TlsPlaintext::new(
            ContentType::ApplicationData,
            LEGACY_VERSION_OTHER,
            vec![0u8; 16385],
        );
        assert_eq!(
            big.unwrap_err(),
            Error::RecordFragmentTooLong { got: 16385, max: 16384 }
        );

        // Exactly 2^14 is legal.
        let ok = TlsPlaintext::new(
            ContentType::ApplicationData,
            LEGACY_VERSION_OTHER,
            vec![0u8; 16384],
        )
        .unwrap();
        assert_eq!(ok.encode().len(), 5 + 16384);

        // §5.2 ciphertext bound: 2^14 + 256.
        let mut ct = vec![23, 0x03, 0x03, 0x42, 0x01]; // 0x4201 = 16897 = 2^14+513
        ct.extend_from_slice(&[0u8; 8]);
        assert!(decode_ciphertext_header(&ct).is_err());
        let ok_ct = [23u8, 0x03, 0x03, 0x41, 0x00]; // 0x4100 = 16640 = 2^14+256, legal
        assert_eq!(decode_ciphertext_header(&ok_ct).unwrap(), 16640);
        let hdr = encode_ciphertext_header(16640).unwrap();
        assert_eq!(hdr[0], 23);
        assert_eq!(&hdr[1..3], &[0x03, 0x03]);
    }

    #[test]
    fn record_rejects_unknown_content_type_and_truncation() {
        // invalid(0) — RFC 8446 §5.1 line 4376 — and any other type byte are
        // rejected with a distinct error.
        let wire = [0x00u8, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(
            TlsPlaintext::decode(&wire).unwrap_err(),
            Error::RecordUnknownContentType(0)
        );
        let wire = [0x2au8, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(
            TlsPlaintext::decode(&wire).unwrap_err(),
            Error::RecordUnknownContentType(42)
        );
        // < 5 header bytes.
        assert_eq!(
            TlsPlaintext::decode(&[22, 3, 3]).unwrap_err(),
            Error::RecordHeaderTruncated { got: 3 }
        );
        // Declared fragment missing.
        let wire = [22u8, 0x03, 0x03, 0x00, 0x10, 1, 2, 3];
        assert_eq!(
            TlsPlaintext::decode(&wire).unwrap_err(),
            Error::RecordFragmentMismatch { declared: 16, available: 3 }
        );

        // legacy_record_version MUST be ignored on decode (§5.1 line 4397):
        // a nonsense version still decodes.
        let (rec, used) = TlsPlaintext::decode(&[21, 0xAB, 0xCD, 0x00, 0x02, 1, 2]).unwrap();
        assert_eq!(used, 7);
        assert_eq!(rec.legacy_record_version, 0xABCD);
        assert_eq!(rec.content_type, ContentType::Alert);

        // Zero-length handshake fragments are forbidden (§5.1 line 4350).
        let mut asm = HandshakeAssembler::new();
        assert_eq!(
            asm.push_fragment(&[]).unwrap_err(),
            Error::HandshakeZeroLengthFragment
        );
    }

    #[test]
    fn inner_plaintext_type_trailer_and_padding() {
        // §5.4: content || content_type || zeros(padding).  Synthetic case:
        // 3 bytes of app content, 5 bytes of padding, appdata trailer.
        let inner = encode_inner_plaintext(b"abc", ContentType::ApplicationData, 5).unwrap();
        assert_eq!(inner, vec![b'a', b'b', b'c', 23, 0, 0, 0, 0, 0]);
        let (ct, content) = decode_inner_plaintext(&inner).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(content, b"abc");

        // Handshake content with padding round-trips.
        let inner = encode_inner_plaintext(&[1, 2, 3, 4], ContentType::Handshake, 2).unwrap();
        assert_eq!(&inner[4..5], &[22]);
        let (ct, content) = decode_inner_plaintext(&inner).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(content, &[1, 2, 3, 4]);

        // Zero-length handshake/alert content is forbidden (§5.4 lines
        // 4631-4638) — but zero-length APP content is legal ("Zero-length
        // fragments of Application Data MAY be sent", §5.1 line 4360).
        assert_eq!(
            encode_inner_plaintext(&[], ContentType::Handshake, 0).unwrap_err(),
            Error::InnerPlaintextEmptyHandshakeOrAlert
        );
        assert_eq!(
            encode_inner_plaintext(&[], ContentType::Alert, 0).unwrap_err(),
            Error::InnerPlaintextEmptyHandshakeOrAlert
        );
        let empty_app = encode_inner_plaintext(&[], ContentType::ApplicationData, 0).unwrap();
        assert_eq!(empty_app, vec![23]);
        let (ct, content) = decode_inner_plaintext(&empty_app).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert!(content.is_empty());
        // ...but a zero-length handshake inner content on DECODE is also
        // forbidden (§5.4 line 4636: "if such a message is received, the
        // receiving implementation MUST terminate ... unexpected_message").
        assert_eq!(
            decode_inner_plaintext(&[22]).unwrap_err(),
            Error::InnerPlaintextEmptyHandshakeOrAlert
        );

        // Content itself may contain zero bytes; only the TRAILER scan skips
        // zeros (§5.4 line 4657-4659).
        let inner = encode_inner_plaintext(&[0, 0, 7], ContentType::ApplicationData, 0).unwrap();
        assert_eq!(inner, vec![0, 0, 7, 23]);
        let (ct, content) = decode_inner_plaintext(&inner).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(content, &[0, 0, 7]);

        // All-zero inner plaintext → no content type → unexpected_message
        // (§5.4 lines 4666-4669).
        assert_eq!(
            decode_inner_plaintext(&[0, 0, 0]).unwrap_err(),
            Error::InnerPlaintextMissingType
        );
        // Invalid inner type byte.
        assert_eq!(
            decode_inner_plaintext(&[1, 20]).unwrap_err(),
            Error::InnerPlaintextInvalidType(20),
            "change_cipher_spec never travels inside protected records"
        );

        // TLSInnerPlaintext bound: 2^14 + 1 (§5.4 line 4672).  16384
        // content + 1 type = 16385 = 2^14+1 is EXACTLY legal; one padding
        // byte more overflows.
        assert!(encode_inner_plaintext(&vec![0u8; 16384], ContentType::ApplicationData, 0).is_ok());
        assert_eq!(
            encode_inner_plaintext(&vec![0u8; 16384], ContentType::ApplicationData, 1).unwrap_err(),
            Error::InnerPlaintextTooLong { got: 16386, max: 16385 }
        );
        // 16383 content + 1 type + 1 padding = 16385 = 2^14+1, exactly legal.
        assert!(encode_inner_plaintext(&vec![0u8; 16383], ContentType::ApplicationData, 1).is_ok());
    }
}
