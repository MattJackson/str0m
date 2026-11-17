mod provider;
pub use provider::{AeadAes128Gcm, AeadAes128GcmCipher, AeadAes256Gcm, AeadAes256GcmCipher};
pub use provider::{Aes128CmSha1_80, Aes128CmSha1_80Cipher, CryptoProvider, CryptoSafe};
pub use provider::{DtlsVersion, Sha1HmacProvider, Sha256Provider};
pub use provider::{SrtpProvider, SupportedAeadAes128Gcm};
pub use provider::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

mod error;
pub use error::{CryptoError, DtlsError};

/// DTLS related types and traits.
pub mod dtls;

#[cfg(feature = "dtls-dimpl")]
mod dimpl_adapter;
