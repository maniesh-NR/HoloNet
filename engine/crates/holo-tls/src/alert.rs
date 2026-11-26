//! Alert codec — RFC 8446 §6.
//!
//! RFC 8446 §6 (line 4717): "Alert messages convey a description of the
//! alert and a legacy field that conveyed the severity level of the message
//! in previous versions of TLS."  In TLS 1.3 the level "can safely be
//! ignored"; it is still encoded/decoded faithfully because it is on the
//! wire.  An `Alert` is exactly two bytes on the wire:
//!
//! ```text
//! struct {
//!     AlertLevel level;
//!     AlertDescription description;
//! } Alert;
//! ```
//! (RFC 8446 §6, struct at lines 4800-4803.)

use crate::{Error, Result};

/// RFC 8446 §6, line 4767: `enum { warning(1), fatal(2), (255) } AlertLevel;`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    Warning,
    Fatal,
}

impl AlertLevel {
    pub fn as_u8(self) -> u8 {
        match self {
            AlertLevel::Warning => 1,
            AlertLevel::Fatal => 2,
        }
    }

    pub fn from_u8(b: u8) -> Result<Self> {
        match b {
            1 => Ok(AlertLevel::Warning),
            2 => Ok(AlertLevel::Fatal),
            _ => Err(Error::AlertUnknownLevel(b)),
        }
    }

    /// RFC 8446 §6, line 4734: "All the alerts listed in Section 6.2 MUST be
    /// sent with AlertLevel=fatal". Closure alerts (§6.1) are warning-level.
    pub fn is_closure_level(self) -> bool {
        matches!(self, AlertLevel::Warning)
    }
}

/// RFC 8446 §6, lines 4769-4798 — the complete `AlertDescription` enum:
///
/// ```text
/// enum {
///     close_notify(0), unexpected_message(10), bad_record_mac(20),
///     record_overflow(22), handshake_failure(40), bad_certificate(42),
///     unsupported_certificate(43), certificate_revoked(44),
///     certificate_expired(45), certificate_unknown(46),
///     illegal_parameter(47), unknown_ca(48), access_denied(49),
///     decode_error(50), decrypt_error(51), protocol_version(70),
///     insufficient_security(71), internal_error(80),
///     inappropriate_fallback(86), user_canceled(90), missing_extension(109),
///     unsupported_extension(110), unrecognized_name(112),
///     bad_certificate_status_response(113), unknown_psk_identity(115),
///     certificate_required(116), no_application_protocol(120), (255)
/// } AlertDescription;
/// ```
///
/// Unknown received values decode to [`AlertDescription::Other`] and "MUST be
/// treated as error alerts" (RFC 8446 §6, line 4736-4737).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertDescription {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    InappropriateFallback,
    UserCanceled,
    MissingExtension,
    UnsupportedExtension,
    UnrecognizedName,
    BadCertificateStatusResponse,
    UnknownPskIdentity,
    CertificateRequired,
    NoApplicationProtocol,
    /// Any value the RFC 8446 enum does not name; carried verbatim.
    Other(u8),
}

impl AlertDescription {
    pub fn as_u8(self) -> u8 {
        match self {
            AlertDescription::CloseNotify => 0,
            AlertDescription::UnexpectedMessage => 10,
            AlertDescription::BadRecordMac => 20,
            AlertDescription::RecordOverflow => 22,
            AlertDescription::HandshakeFailure => 40,
            AlertDescription::BadCertificate => 42,
            AlertDescription::UnsupportedCertificate => 43,
            AlertDescription::CertificateRevoked => 44,
            AlertDescription::CertificateExpired => 45,
            AlertDescription::CertificateUnknown => 46,
            AlertDescription::IllegalParameter => 47,
            AlertDescription::UnknownCa => 48,
            AlertDescription::AccessDenied => 49,
            AlertDescription::DecodeError => 50,
            AlertDescription::DecryptError => 51,
            AlertDescription::ProtocolVersion => 70,
            AlertDescription::InsufficientSecurity => 71,
            AlertDescription::InternalError => 80,
            AlertDescription::InappropriateFallback => 86,
            AlertDescription::UserCanceled => 90,
            AlertDescription::MissingExtension => 109,
            AlertDescription::UnsupportedExtension => 110,
            AlertDescription::UnrecognizedName => 112,
            AlertDescription::BadCertificateStatusResponse => 113,
            AlertDescription::UnknownPskIdentity => 115,
            AlertDescription::CertificateRequired => 116,
            AlertDescription::NoApplicationProtocol => 120,
            AlertDescription::Other(b) => b,
        }
    }

    pub fn from_u8(b: u8) -> Self {
        match b {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            22 => AlertDescription::RecordOverflow,
            40 => AlertDescription::HandshakeFailure,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCa,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            86 => AlertDescription::InappropriateFallback,
            90 => AlertDescription::UserCanceled,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            112 => AlertDescription::UnrecognizedName,
            113 => AlertDescription::BadCertificateStatusResponse,
            115 => AlertDescription::UnknownPskIdentity,
            116 => AlertDescription::CertificateRequired,
            120 => AlertDescription::NoApplicationProtocol,
            other => AlertDescription::Other(other),
        }
    }

    /// RFC 8446 §6.1: "close_notify" and "user_canceled" are closure alerts.
    pub fn is_closure_alert(self) -> bool {
        matches!(
            self,
            AlertDescription::CloseNotify | AlertDescription::UserCanceled
        )
    }

    /// RFC 8446 §6 name, for diagnostics ("decrypt_error", "close_notify", ...).
    pub fn name(self) -> &'static str {
        match self {
            AlertDescription::CloseNotify => "close_notify",
            AlertDescription::UnexpectedMessage => "unexpected_message",
            AlertDescription::BadRecordMac => "bad_record_mac",
            AlertDescription::RecordOverflow => "record_overflow",
            AlertDescription::HandshakeFailure => "handshake_failure",
            AlertDescription::BadCertificate => "bad_certificate",
            AlertDescription::UnsupportedCertificate => "unsupported_certificate",
            AlertDescription::CertificateRevoked => "certificate_revoked",
            AlertDescription::CertificateExpired => "certificate_expired",
            AlertDescription::CertificateUnknown => "certificate_unknown",
            AlertDescription::IllegalParameter => "illegal_parameter",
            AlertDescription::UnknownCa => "unknown_ca",
            AlertDescription::AccessDenied => "access_denied",
            AlertDescription::DecodeError => "decode_error",
            AlertDescription::DecryptError => "decrypt_error",
            AlertDescription::ProtocolVersion => "protocol_version",
            AlertDescription::InsufficientSecurity => "insufficient_security",
            AlertDescription::InternalError => "internal_error",
            AlertDescription::InappropriateFallback => "inappropriate_fallback",
            AlertDescription::UserCanceled => "user_canceled",
            AlertDescription::MissingExtension => "missing_extension",
            AlertDescription::UnsupportedExtension => "unsupported_extension",
            AlertDescription::UnrecognizedName => "unrecognized_name",
            AlertDescription::BadCertificateStatusResponse => "bad_certificate_status_response",
            AlertDescription::UnknownPskIdentity => "unknown_psk_identity",
            AlertDescription::CertificateRequired => "certificate_required",
            AlertDescription::NoApplicationProtocol => "no_application_protocol",
            AlertDescription::Other(_) => "unknown_alert",
        }
    }
}

/// An RFC 8446 §6 alert: `struct { AlertLevel level; AlertDescription
/// description; } Alert;` — two bytes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    pub fn new(level: AlertLevel, description: AlertDescription) -> Self {
        Alert { level, description }
    }

    /// Fatal error alert (RFC 8446 §6, line 4734: "All the alerts listed in
    /// Section 6.2 MUST be sent with AlertLevel=fatal").
    pub fn fatal(description: AlertDescription) -> Self {
        Alert { level: AlertLevel::Fatal, description }
    }

    /// Encode the 2-byte wire form: level || description.
    pub fn encode(&self) -> [u8; 2] {
        [self.level.as_u8(), self.description.as_u8()]
    }

    /// Decode from the front of `buf`; returns the alert and the number of
    /// bytes consumed (always 2 on success).
    pub fn decode(buf: &[u8]) -> Result<(Alert, usize)> {
        if buf.len() < 2 {
            return Err(Error::AlertTruncated { got: buf.len() });
        }
        let level = AlertLevel::from_u8(buf[0])?;
        let description = AlertDescription::from_u8(buf[1]);
        Ok((Alert { level, description }, 2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_roundtrip() {
        // The descriptions the task requires at minimum, plus closure alerts,
        // plus the unknown passthrough. Synthetic bytes — each alert is two
        // bytes: level(1) || description(1), RFC 8446 §6 struct at lines
        // 4800-4803.
        let cases: &[(u8, AlertDescription)] = &[
            (2, AlertDescription::DecryptError),      // 02 33
            (1, AlertDescription::CloseNotify),       // 01 00 — §6.1 closure
            (1, AlertDescription::UserCanceled),      // 01 5a — §6.1, warning
            (2, AlertDescription::HandshakeFailure),  // 02 28
            (2, AlertDescription::IllegalParameter),  // 02 2f
            (2, AlertDescription::DecodeError),       // 02 32
            (2, AlertDescription::RecordOverflow),    // 02 16
            (2, AlertDescription::BadRecordMac),      // 02 14
            (2, AlertDescription::NoApplicationProtocol), // 02 78
        ];
        for &(level, desc) in cases {
            let a = Alert::new(
                AlertLevel::from_u8(level).unwrap(),
                desc,
            );
            let bytes = a.encode();
            assert_eq!(bytes.len(), 2);
            assert_eq!(bytes[0], level);
            assert_eq!(bytes[1], desc.as_u8());
            let (back, consumed) = Alert::decode(&bytes).unwrap();
            assert_eq!(consumed, 2);
            assert_eq!(back, a);
            assert_eq!(back.description.name(), desc.name());
        }

        // Exact synthetic wire bytes: fatal decrypt_error = 02 33
        // (decrypt_error(51) per RFC 8446 §6 line 4784).
        let (a, n) = Alert::decode(&[0x02, 0x33]).unwrap();
        assert_eq!(n, 2);
        assert_eq!(a, Alert::fatal(AlertDescription::DecryptError));

        // Unknown description passthrough: level 1, description 200 — RFC 8446
        // §6 line 4736: "Unknown Alert types MUST be treated as error alerts".
        let (a, _) = Alert::decode(&[0x01, 200]).unwrap();
        assert_eq!(a.description, AlertDescription::Other(200));
        assert!(!a.description.is_closure_alert());
        // roundtrip of the unknown value keeps the byte
        assert_eq!(a.encode(), [0x01, 200]);

        // Truncated alert → distinct error.
        assert_eq!(
            Alert::decode(&[0x01]),
            Err(Error::AlertTruncated { got: 1 })
        );

        // Unknown level byte (not 1/2) → distinct error, RFC 8446 §6 line 4767.
        assert_eq!(
            Alert::decode(&[0x03, 0x00]),
            Err(Error::AlertUnknownLevel(3))
        );
        assert!(format!("{}", Error::AlertUnknownLevel(3)).starts_with("tls: alert: unknown alert level 3"));
    }
}
