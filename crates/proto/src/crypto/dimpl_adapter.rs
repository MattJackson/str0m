//! The optional concrete dimpl boundary; neutral provider types never depend on the engine.

use super::dtls::{DtlsImplError, DtlsOutput, KeyingMaterial, ProtocolVersion, SrtpProfile};

impl From<dimpl::Error> for DtlsImplError {
    fn from(error: dimpl::Error) -> Self {
        match error {
            dimpl::Error::HandshakePending => Self::HandshakePending,
            dimpl::Error::ConnectionClosed => Self::ConnectionClosed,
            other => Self::Other(Box::new(other)),
        }
    }
}
impl From<dimpl::ProtocolVersion> for ProtocolVersion {
    fn from(value: dimpl::ProtocolVersion) -> Self {
        Self::from_u16(value.as_u16())
    }
}
impl TryFrom<dimpl::SrtpProfile> for SrtpProfile {
    type Error = DtlsImplError;
    fn try_from(profile: dimpl::SrtpProfile) -> Result<Self, Self::Error> {
        match profile {
            dimpl::SrtpProfile::AES128_CM_SHA1_80 => Ok(Self::AES128_CM_SHA1_80),
            dimpl::SrtpProfile::AEAD_AES_128_GCM => Ok(Self::AEAD_AES_128_GCM),
            dimpl::SrtpProfile::AEAD_AES_256_GCM => Ok(Self::AEAD_AES_256_GCM),
            _ => Err(DtlsImplError::UnsupportedSrtpProfile),
        }
    }
}
impl<'a> TryFrom<dimpl::Output<'a>> for DtlsOutput<'a> {
    type Error = DtlsImplError;
    fn try_from(output: dimpl::Output<'a>) -> Result<Self, Self::Error> {
        Ok(match output {
            dimpl::Output::Packet(v) => Self::Packet(v),
            dimpl::Output::BufferTooSmall { needed } => Self::BufferTooSmall { needed },
            dimpl::Output::Timeout(t) => Self::Timeout(t),
            dimpl::Output::Connected => Self::Connected,
            dimpl::Output::PeerCert(v) => Self::PeerCert(v),
            dimpl::Output::KeyingMaterial(material, profile) => {
                let profile = profile.try_into()?;
                Self::KeyingMaterial(KeyingMaterial::new(&material), profile)
            }
            dimpl::Output::ApplicationData(v) => Self::ApplicationData(v),
            dimpl::Output::CloseNotify => Self::CloseNotify,
            _ => return Err(DtlsImplError::UnsupportedProviderOutput),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::time::Instant;

    #[test]
    fn every_current_output_preserves_its_payload_or_control_value() {
        let bytes = [1, 2, 3];
        let now = Instant::now();
        assert!(
            matches!(DtlsOutput::try_from(dimpl::Output::Packet(&bytes)).unwrap(), DtlsOutput::Packet(v) if std::ptr::eq(v, &bytes[..]))
        );
        assert!(
            matches!(DtlsOutput::try_from(dimpl::Output::PeerCert(&bytes)).unwrap(), DtlsOutput::PeerCert(v) if std::ptr::eq(v, &bytes[..]))
        );
        assert!(
            matches!(DtlsOutput::try_from(dimpl::Output::ApplicationData(&bytes)).unwrap(), DtlsOutput::ApplicationData(v) if std::ptr::eq(v, &bytes[..]))
        );
        assert!(matches!(
            DtlsOutput::try_from(dimpl::Output::BufferTooSmall { needed: 4096 }).unwrap(),
            DtlsOutput::BufferTooSmall { needed: 4096 }
        ));
        assert!(
            matches!(DtlsOutput::try_from(dimpl::Output::Timeout(now)).unwrap(), DtlsOutput::Timeout(t) if t == now)
        );
        assert!(matches!(
            DtlsOutput::try_from(dimpl::Output::Connected).unwrap(),
            DtlsOutput::Connected
        ));
        assert!(matches!(
            DtlsOutput::try_from(dimpl::Output::CloseNotify).unwrap(),
            DtlsOutput::CloseNotify
        ));
        for (profile, expected) in [
            (
                dimpl::SrtpProfile::AEAD_AES_256_GCM,
                SrtpProfile::AEAD_AES_256_GCM,
            ),
            (
                dimpl::SrtpProfile::AEAD_AES_128_GCM,
                SrtpProfile::AEAD_AES_128_GCM,
            ),
            (
                dimpl::SrtpProfile::AES128_CM_SHA1_80,
                SrtpProfile::AES128_CM_SHA1_80,
            ),
        ] {
            let bytes = vec![9; expected.keying_material_len()];
            match DtlsOutput::try_from(dimpl::Output::KeyingMaterial(
                dimpl::KeyingMaterial::new(&bytes),
                profile,
            ))
            .unwrap()
            {
                DtlsOutput::KeyingMaterial(material, selected) => {
                    assert_eq!(&*material, &bytes);
                    assert_eq!(selected, expected);
                }
                other => panic!("wrong conversion: {other:?}"),
            }
        }
    }

    #[test]
    fn errors_keep_control_categories_and_other_source_identity() {
        assert!(matches!(
            DtlsImplError::from(dimpl::Error::HandshakePending),
            DtlsImplError::HandshakePending
        ));
        assert!(matches!(
            DtlsImplError::from(dimpl::Error::ConnectionClosed),
            DtlsImplError::ConnectionClosed
        ));
        let original = dimpl::Error::ReceiveQueueFull;
        let error = DtlsImplError::from(original.clone());
        assert_eq!(
            error.source().unwrap().downcast_ref::<dimpl::Error>(),
            Some(&original)
        );
    }
}
