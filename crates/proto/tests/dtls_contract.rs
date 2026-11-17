#![cfg(feature = "dtls")]

use str0m_proto::crypto::dtls::{KeyingMaterial, ProtocolVersion, SrtpProfile};

#[test]
fn protocol_versions_preserve_known_and_unknown_wire_values() {
    for value in 0..=u16::MAX {
        let version = ProtocolVersion::from_u16(value);
        assert_eq!(version.as_u16(), value);
        assert_eq!(
            version.is_unknown(),
            !matches!(value, 0xfeff | 0xfefd | 0xfefc)
        );
    }
    assert_eq!(ProtocolVersion::default().as_u16(), 0);
    assert_eq!(ProtocolVersion::DTLS1_0.as_u16(), 0xfeff);
    assert_eq!(ProtocolVersion::DTLS1_2.as_u16(), 0xfefd);
    assert_eq!(ProtocolVersion::DTLS1_3.as_u16(), 0xfefc);
}

#[test]
fn profiles_keep_their_preference_and_key_lengths() {
    assert_eq!(
        SrtpProfile::ALL,
        &[
            SrtpProfile::AEAD_AES_256_GCM,
            SrtpProfile::AEAD_AES_128_GCM,
            SrtpProfile::AES128_CM_SHA1_80,
        ]
    );
    let lengths: Vec<_> = SrtpProfile::ALL
        .iter()
        .map(SrtpProfile::keying_material_len)
        .collect();
    assert_eq!(lengths, [88, 56, 60]);
}

#[test]
fn owned_keying_material_has_drop_custody_and_redacted_debug() {
    let secret = b"private key material";
    let material = KeyingMaterial::new(secret);
    assert_eq!(&*material, secret);
    assert!(std::mem::needs_drop::<KeyingMaterial>());
    assert_eq!(format!("{material:?}"), "KeyingMaterial");
}
