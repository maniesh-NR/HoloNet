//! Transcript-Hash — RFC 8446 §4.4.1.
//!
//! RFC 8446 §4.4.1 (lines 3481-3488):
//!
//! > Many of the cryptographic computations in TLS make use of a transcript
//! > hash.  This value is computed by hashing the concatenation of each
//! > included handshake message, including the handshake message header
//! > carrying the handshake message type and length fields, but not including
//! > record layer headers.  I.e.,
//! >
//! > Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
//!
//! The hash is SHA-256 for every cipher suite HoloNet offers
//! (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 uses SHA-384 — the
//! SHA-256 variant implemented here covers the mandatory-to-implement suite
//! and the RFC 8448 traces).
//!
//! RFC 8446 §4.4.1 (lines 3489-3498) also defines the HelloRetryRequest
//! synthetic `message_hash` replacement message:
//!
//! > Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
//! >     Hash(message_hash ||        /* Handshake type */
//! >          00 00 Hash.length  ||  /* Handshake message length (bytes) */
//! >          Hash(ClientHello1) ||  /* Hash of ClientHello1 */
//! >          HelloRetryRequest  || ... || Mn)
//!
//! [`message_hash_synthetic`] builds exactly that synthetic message so the
//! key-schedule module can feed it into a transcript.

use holo_crypto::sha256;

/// Transcript-Hash over the concatenation of the given handshake messages.
///
/// Each slice must be a COMPLETE handshake message — 4-byte header (type +
/// u24 length) included, record layer headers excluded.  Passing record
/// fragments here would corrupt the transcript; use
/// `crate::record::HandshakeAssembler` to obtain message boundaries first.
pub fn transcript_hash(messages: &[&[u8]]) -> [u8; 32] {
    let mut joined = Vec::with_capacity(messages.iter().map(|m| m.len()).sum());
    for m in messages {
        joined.extend_from_slice(m);
    }
    sha256::digest(&joined)
}

/// Build the RFC 8446 §4.4.1 synthetic `message_hash` handshake message used
/// to replace ClientHello1 in the transcript after a HelloRetryRequest:
/// `message_hash(254) || 00 00 20 || Hash(ClientHello1)`.
pub fn message_hash_synthetic(client_hello1_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.push(254); // message_hash — RFC 8446 §4 HandshakeType, line 1362
    out.extend_from_slice(&[0x00, 0x00, 0x20]); // u24 length = 32 = Hash.length
    out.extend_from_slice(client_hello1_hash);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc8448;

    #[test]
    fn transcript_hash_matches_rfc8448() {
        // RFC 8448 §3, lines 287-288: the "hash" input published for the
        // server's derive of "tls13 c hs traffic" is the Transcript-Hash over
        // ClientHello || ServerHello:
        //   86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
        //   d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8
        let expect: [u8; 32] = [
            0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c,
            0x58, 0xed, 0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f, 0x02, 0xed, 0x06, 0x3c,
            0xf0, 0xe1, 0xca, 0xd8,
        ];
        // The two raw handshake messages (4-byte headers included, record
        // headers excluded) exactly as published in RFC 8448 §3.
        let th = transcript_hash(&[&rfc8448::CLIENT_HELLO, &rfc8448::SERVER_HELLO]);
        assert_eq!(th, expect);

        // Splitting the same bytes into differently-ordered slices would be
        // wrong; feeding the concatenation as one slice must give the same
        // answer as two slices (associativity of ||).
        let mut joined = rfc8448::CLIENT_HELLO.clone();
        joined.extend_from_slice(&rfc8448::SERVER_HELLO);
        assert_eq!(transcript_hash(&[&joined]), expect);

        // Transcript-Hash of the empty transcript = SHA-256 of nothing =
        // RFC 8448 §3 lines 252-253 ("hash" for "tls13 derived" before any
        // message): e3 b0 c4 42 ... b8 55.
        let empty = transcript_hash(&[]);
        assert_eq!(
            empty,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
                0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
                0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn message_hash_synthetic_layout() {
        let h = [0xAB_u8; 32];
        let m = message_hash_synthetic(&h);
        assert_eq!(m.len(), 36);
        assert_eq!(m[0], 254); // message_hash — RFC 8446 §4 line 1362
        assert_eq!(&m[1..4], &[0x00, 0x00, 0x20]); // u24 length, Hash.length
        assert_eq!(&m[4..], &h);
        // Transcript-Hash(message_hash_synthetic) hashes the synthetic message
        // itself (§4.4.1 lines 3494-3498).
        let th = transcript_hash(&[&m]);
        assert_eq!(th, holo_crypto::sha256::digest(&m));
    }
}
