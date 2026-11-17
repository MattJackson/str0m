use std::collections::VecDeque;
use std::io;
use std::ops::RangeInclusive;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::time::Instant;

use crate::crypto::Fingerprint;
use crate::crypto::Sha256Provider;
use crate::crypto::dtls::{DtlsCert, DtlsImplError, DtlsOutput, ProtocolVersion};
use crate::crypto::dtls::{DtlsInstance, DtlsProvider, DtlsVersion};
use crate::crypto::{CryptoError, DtlsError};
use crate::io::DatagramSend;
use crate::util::{already_happened, not_happening};

/// Encapsulation of DTLS.
///
/// This is a thin wrapper around `DtlsInstance` that adds fingerprint tracking
/// and active/passive state management. The API follows dimpl's sans-IO pattern.
pub struct Dtls {
    /// The underlying DTLS instance.
    instance: Box<dyn DtlsInstance>,

    /// The fingerprint of the local certificate.
    fingerprint: Fingerprint,

    /// Remote fingerprint (set when received via poll_output).
    remote_fingerprint: Option<Fingerprint>,

    /// Whether set_active has been called.
    active_state: Option<bool>,

    /// Packets to be sent.
    pending_packets: VecDeque<DatagramSend>,

    /// Target MTU (start) and warn threshold (end). The target is forwarded to
    /// the backend's fragmenter; outgoing records larger than the warn
    /// threshold log a warning.
    mtu: RangeInclusive<usize>,
}

pub(crate) fn is_would_block(error: &DtlsError) -> bool {
    match error {
        DtlsError::Io(e) => e.kind() == io::ErrorKind::WouldBlock,
        DtlsError::CryptoError(crypto_err) => match crypto_err {
            CryptoError::Io(e) => e.kind() == io::ErrorKind::WouldBlock,
            #[allow(unreachable_patterns)]
            _ => false,
        },
    }
}

impl UnwindSafe for Dtls {}
impl RefUnwindSafe for Dtls {}

impl Dtls {
    /// Creates a new DTLS instance.
    pub fn new(
        cert: &DtlsCert,
        dtls_provider: &dyn DtlsProvider,
        sha256_provider: &dyn Sha256Provider,
        now: Instant,
        dtls_version: DtlsVersion,
        mtu: RangeInclusive<usize>,
    ) -> Result<Self, DtlsError> {
        let instance = dtls_provider
            .new_dtls(cert, now, dtls_version, Some(*mtu.start()))
            .map_err(DtlsError::CryptoError)?;

        // Compute fingerprint from the certificate DER bytes
        let fingerprint = Fingerprint {
            hash_func: "sha-256".to_string(),
            bytes: sha256_provider.sha256(&cert.certificate).to_vec(),
        };

        Ok(Self {
            instance,
            fingerprint,
            remote_fingerprint: None,
            active_state: None,
            pending_packets: VecDeque::new(),
            mtu,
        })
    }

    /// Threshold above which an outgoing DTLS record triggers an MTU warning.
    pub fn mtu_warn(&self) -> usize {
        *self.mtu.end()
    }

    /// Tells if this instance has been inited (set_active called).
    pub fn is_inited(&self) -> bool {
        self.active_state.is_some()
    }

    /// Set whether this instance is active (client) or passive (server).
    pub fn set_active(&mut self, active: bool) {
        self.active_state = Some(active);
        self.instance.set_active(active)
    }

    /// If set_active was called, returns what was set.
    pub fn is_active(&self) -> Option<bool> {
        self.active_state
    }

    /// The local certificate fingerprint.
    pub fn local_fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Remote fingerprint, if received.
    pub fn remote_fingerprint(&self) -> Option<&Fingerprint> {
        self.remote_fingerprint.as_ref()
    }

    /// The negotiated DTLS protocol version, or `None` before handshake completion.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.instance.protocol_version()
    }

    pub fn is_closed(&self) -> bool {
        self.pending_packets.is_empty() && self.instance.is_closed()
    }

    /// Set the remote fingerprint (extracted from peer certificate).
    pub fn set_remote_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.remote_fingerprint = Some(fingerprint);
    }

    /// Poll for output from the DTLS instance.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Result<DtlsOutput<'a>, DtlsError> {
        if !self.is_inited() {
            return Ok(DtlsOutput::Timeout(not_happening()));
        }

        let next = self.instance.poll_output(buf).map_err(provider_error)?;

        if let DtlsOutput::Packet(packet) = next {
            if packet.len() > self.mtu_warn() {
                warn!("DTLS above MTU {}: {}", self.mtu_warn(), packet.len());
            }
            self.pending_packets.push_back(packet.to_vec().into());

            // Return timeout indicating we want another poll straight away
            return Ok(DtlsOutput::Timeout(already_happened()));
        }

        Ok(next)
    }

    pub fn poll_packet(&mut self) -> Option<DatagramSend> {
        self.pending_packets.pop_front()
    }

    /// Handle an incoming DTLS packet.
    pub fn handle_receive(&mut self, packet: &[u8]) -> Result<(), DtlsError> {
        if !self.is_inited() {
            debug!("Ignoring DTLS datagram prior to DTLS start");
            return Ok(());
        }

        self.instance.handle_packet(packet).map_err(provider_error)
    }

    /// Send application data over DTLS.
    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), DtlsError> {
        fn make_handshake_pending_err() -> DtlsError {
            DtlsError::Io(io::Error::new(
                io::ErrorKind::WouldBlock,
                DtlsImplError::HandshakePending,
            ))
        }

        // Don't rely on the inner instance for proper pre-init behavior.
        if !self.is_inited() {
            return Err(make_handshake_pending_err());
        }

        self.instance
            .send_application_data(data)
            .map_err(|e| match e {
                DtlsImplError::HandshakePending => make_handshake_pending_err(),
                e => provider_error(e),
            })
    }

    /// Handle a timeout event.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsError> {
        if !self.is_inited() {
            return Ok(());
        }

        self.instance.handle_timeout(now).map_err(provider_error)
    }

    /// Initiate graceful shutdown by sending a close_notify alert.
    pub fn close(&mut self) -> Result<(), DtlsError> {
        self.instance.close().map_err(provider_error)
    }
}

fn provider_error(error: DtlsImplError) -> DtlsError {
    DtlsError::CryptoError(CryptoError::DtlsImpl(error))
}

#[cfg(test)]
mod provider_contract_tests {
    use super::*;
    use crate::crypto::dtls::DtlsImplError;
    use std::error::Error;

    #[derive(Debug)]
    struct Refusal;
    impl std::fmt::Display for Refusal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fixture provider refusal")
        }
    }
    impl Error for Refusal {}
    #[derive(Debug)]
    struct Provider;
    impl Sha256Provider for Provider {
        fn sha256(&self, _: &[u8]) -> [u8; 32] {
            [7; 32]
        }
    }
    impl DtlsProvider for Provider {
        fn generate_certificate(&self) -> Option<DtlsCert> {
            None
        }
        fn new_dtls(
            &self,
            _: &DtlsCert,
            _: Instant,
            _: DtlsVersion,
            _: Option<usize>,
        ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
            Ok(Box::new(Provider))
        }
    }
    fn refusal() -> DtlsImplError {
        DtlsImplError::Other(Box::new(Refusal))
    }
    impl DtlsInstance for Provider {
        fn set_active(&mut self, _: bool) {}
        fn handle_packet(&mut self, _: &[u8]) -> Result<(), DtlsImplError> {
            Err(refusal())
        }
        fn poll_output<'a>(&mut self, _: &'a mut [u8]) -> Result<DtlsOutput<'a>, DtlsImplError> {
            Err(DtlsImplError::UnsupportedProviderOutput)
        }
        fn handle_timeout(&mut self, _: Instant) -> Result<(), DtlsImplError> {
            Err(refusal())
        }
        fn send_application_data(&mut self, _: &[u8]) -> Result<(), DtlsImplError> {
            Err(DtlsImplError::HandshakePending)
        }
        fn is_active(&self) -> bool {
            false
        }
        fn protocol_version(&self) -> Option<ProtocolVersion> {
            None
        }
        fn close(&mut self) -> Result<(), DtlsImplError> {
            Err(refusal())
        }
    }
    fn wrapper() -> Dtls {
        let cert = DtlsCert {
            certificate: vec![],
            private_key: vec![],
        };
        let mut dtls = Dtls::new(
            &cert,
            &Provider,
            &Provider,
            Instant::now(),
            DtlsVersion::Dtls12,
            1200..=1400,
        )
        .unwrap();
        dtls.set_active(true);
        dtls
    }
    fn has_source(error: &(dyn Error + 'static)) -> bool {
        let mut next = Some(error);
        while let Some(e) = next {
            if e.downcast_ref::<Refusal>().is_some() {
                return true;
            }
            next = e.source();
        }
        false
    }
    #[test]
    fn provider_errors_retain_identity_at_rtc_boundary() {
        let mut dtls = wrapper();
        for error in [
            dtls.handle_receive(&[1]).unwrap_err(),
            dtls.handle_timeout(Instant::now()).unwrap_err(),
            dtls.close().unwrap_err(),
        ] {
            let error = crate::RtcError::from(error);
            assert!(has_source(&error));
        }
        assert!(is_would_block(&dtls.handle_input(&[1]).unwrap_err()));
    }
    #[test]
    fn refused_poll_never_queues_a_packet() {
        let mut dtls = wrapper();
        let error = dtls.poll_output(&mut [0; 128]).unwrap_err();
        assert!(matches!(
            error,
            DtlsError::CryptoError(CryptoError::DtlsImpl(
                DtlsImplError::UnsupportedProviderOutput
            ))
        ));
        assert!(dtls.poll_packet().is_none());
    }
}
