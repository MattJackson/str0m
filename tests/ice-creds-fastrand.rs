//! Where str0m's ICE credentials come from.
//!
//! `IceCreds::new()` draws every ufrag and password character from fastrand's
//! thread-local generator, so a set of credentials is a pure function of that
//! generator's 64-bit state. The answer to a remote-initiated ICE restart takes
//! its new local credentials from `IceCreds::new()` too, with no way for the
//! embedder to supply them.

use std::net::Ipv4Addr;
use std::time::Instant;

use str0m::{IceCreds, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

const SEED: u64 = 0x5eed_1ce5;

#[test]
pub fn ice_credentials_are_a_function_of_the_fastrand_seed() {
    fastrand::seed(SEED);
    let first = IceCreds::new();

    fastrand::seed(SEED);
    let second = IceCreds::new();

    assert_eq!(first.ufrag, second.ufrag);
    assert_eq!(first.pass, second.pass);
}

#[test]
pub fn a_restart_answer_takes_its_credentials_from_the_fastrand_seed() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let first = restart_answer_credentials(SEED)?;
    let second = restart_answer_credentials(SEED)?;

    assert_eq!(first, second);
    Ok(())
}

/// Connect two peers, let R offer an ICE restart, and seed fastrand just before L
/// answers it. Returns the local credentials L answers with.
fn restart_answer_credentials(seed: u64) -> Result<IceCreds, RtcError> {
    let mut l = TestRtc::new(Peer::Left);
    let rtc = RtcConfig::new().set_ice_lite(true).build(Instant::now());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let (offer, pending) = l.span.in_scope(|| {
        let mut change = l.rtc.sdp_api();
        let _ = change.add_channel("channel".into());
        change.apply().unwrap()
    });
    let answer = r.span.in_scope(|| r.rtc.sdp_api().accept_offer(offer))?;
    l.span
        .in_scope(|| l.rtc.sdp_api().accept_answer(pending, answer))?;

    while !(l.is_connected() && r.is_connected()) {
        progress(&mut l, &mut r)?;
    }

    let (offer, _pending) = r.span.in_scope(|| {
        let mut change = r.rtc.sdp_api();
        change.ice_restart(true);
        change.apply().expect("Should be able to apply changes")
    });

    fastrand::seed(seed);
    l.span.in_scope(|| l.rtc.sdp_api().accept_offer(offer))?;

    Ok(l._local_ice_creds())
}
