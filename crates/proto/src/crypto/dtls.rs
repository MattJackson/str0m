//! Provider-owned DTLS values, independent of any concrete DTLS engine.

use std::error::Error;
use std::fmt;
use std::ops::Deref;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::time::Instant;
use zeroize::Zeroizing;

pub use super::provider::{DtlsInstance, DtlsProvider};

#[cfg(feature = "dtls-dimpl")]
pub use dimpl::{CryptoError as DtlsCryptoError, CryptoOperation as DtlsCryptoOperation};

/// Certificate and private key in DER format.
#[derive(Clone)]
pub struct DtlsCert {
    /// Certificate DER bytes.
    pub certificate: Vec<u8>,
    /// Private key DER bytes.
    pub private_key: Vec<u8>,
}
impl fmt::Debug for DtlsCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DtlsCert")
            .field("certificate", &self.certificate.len())
            .field("private_key", &self.private_key.len())
            .finish()
    }
}

/// Owned SRTP keying material, erased when dropped.
pub struct KeyingMaterial(Zeroizing<Vec<u8>>);
impl KeyingMaterial {
    /// Copy exported keying material into wiping custody.
    pub fn new(material: &[u8]) -> Self {
        Self(Zeroizing::new(material.to_vec()))
    }
}
impl Deref for KeyingMaterial {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
impl fmt::Debug for KeyingMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyingMaterial")
    }
}

/// DTLS wire version, including unrecognized registry values.
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ProtocolVersion(u16);
impl ProtocolVersion {
    /// DTLS 1.0.
    pub const DTLS1_0: Self = Self(0xfeff);
    /// DTLS 1.2.
    pub const DTLS1_2: Self = Self(0xfefd);
    /// DTLS 1.3.
    pub const DTLS1_3: Self = Self(0xfefc);
    /// Preserve a wire value without interpreting unknown versions.
    pub const fn from_u16(value: u16) -> Self {
        Self(value)
    }
    /// The original wire value.
    pub const fn as_u16(&self) -> u16 {
        self.0
    }
    /// Whether this is outside the known DTLS versions.
    pub const fn is_unknown(&self) -> bool {
        !matches!(self.0, 0xfeff | 0xfefd | 0xfefc)
    }
}
impl fmt::Debug for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DTLS1_0 => f.write_str("DTLS1_0"),
            Self::DTLS1_2 => f.write_str("DTLS1_2"),
            Self::DTLS1_3 => f.write_str("DTLS1_3"),
            _ => f.debug_tuple("Unknown").field(&self.0).finish(),
        }
    }
}

/// Supported DTLS-SRTP protection profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum SrtpProfile {
    /// SRTP_AES128_CM_SHA1_80.
    AES128_CM_SHA1_80,
    /// SRTP_AEAD_AES_128_GCM.
    AEAD_AES_128_GCM,
    /// SRTP_AEAD_AES_256_GCM.
    AEAD_AES_256_GCM,
}
impl SrtpProfile {
    /// Profiles in descending preference order.
    pub const ALL: &'static [Self] = &[
        Self::AEAD_AES_256_GCM,
        Self::AEAD_AES_128_GCM,
        Self::AES128_CM_SHA1_80,
    ];
    /// Exported master keys and salts for both directions.
    pub fn keying_material_len(&self) -> usize {
        match self {
            Self::AES128_CM_SHA1_80 => 60,
            Self::AEAD_AES_128_GCM => 56,
            Self::AEAD_AES_256_GCM => 88,
        }
    }
}
impl fmt::Display for SrtpProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AES128_CM_SHA1_80 => "SRTP_AES128_CM_SHA1_80",
            Self::AEAD_AES_128_GCM => "SRTP_AEAD_AES_128_GCM",
            Self::AEAD_AES_256_GCM => "SRTP_AEAD_AES_256_GCM",
        })
    }
}

/// A provider failure, preserving concrete errors through `source()`.
#[derive(Debug)]
#[non_exhaustive]
pub enum DtlsImplError {
    /// Application data was attempted before handshake completion.
    HandshakePending,
    /// The connection is closed.
    ConnectionClosed,
    /// The engine returned an output unknown to this adapter.
    UnsupportedProviderOutput,
    /// The engine selected a profile unknown to this adapter.
    UnsupportedSrtpProfile,
    /// Concrete provider failure. No stringification or reclassification.
    Other(Box<dyn Error + Send + Sync + RefUnwindSafe + UnwindSafe>),
}
impl fmt::Display for DtlsImplError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandshakePending => f.write_str("DTLS handshake pending"),
            Self::ConnectionClosed => f.write_str("DTLS connection closed"),
            Self::UnsupportedProviderOutput => f.write_str("unsupported DTLS provider output"),
            Self::UnsupportedSrtpProfile => f.write_str("unsupported DTLS-SRTP profile"),
            Self::Other(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl Error for DtlsImplError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Other(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// Output from a DTLS provider. Payload slices borrow the supplied poll buffer.
#[non_exhaustive]
pub enum DtlsOutput<'a> {
    /// Encrypted record to transmit.
    Packet(&'a [u8]),
    /// Retry with at least this many bytes; the provider retains the pending output.
    BufferTooSmall {
        /// Minimum buffer size.
        needed: usize,
    },
    /// Next timeout; terminates a poll cycle.
    Timeout(Instant),
    /// Handshake completed.
    Connected,
    /// Peer leaf certificate for independent validation.
    PeerCert(&'a [u8]),
    /// Exported SRTP material and profile.
    KeyingMaterial(KeyingMaterial, SrtpProfile),
    /// Received plaintext.
    ApplicationData(&'a [u8]),
    /// Peer closed gracefully.
    CloseNotify,
}
impl fmt::Debug for DtlsOutput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(v) => f.debug_tuple("Packet").field(&v.len()).finish(),
            Self::BufferTooSmall { needed } => f
                .debug_struct("BufferTooSmall")
                .field("needed", needed)
                .finish(),
            Self::Timeout(t) => f.debug_tuple("Timeout").field(t).finish(),
            Self::Connected => f.write_str("Connected"),
            Self::PeerCert(v) => f.debug_tuple("PeerCert").field(&v.len()).finish(),
            Self::KeyingMaterial(v, p) => f
                .debug_tuple("KeyingMaterial")
                .field(&v.len())
                .field(p)
                .finish(),
            Self::ApplicationData(v) => f.debug_tuple("ApplicationData").field(&v.len()).finish(),
            Self::CloseNotify => f.write_str("CloseNotify"),
        }
    }
}
