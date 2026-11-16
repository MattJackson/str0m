use std::sync::OnceLock;

/// The process-wide random fill, installed once with [`set_fill`].
static FILL: OnceLock<fn(&mut [u8])> = OnceLock::new();

/// Install the random source every value str0m draws comes from: ICE credentials (including the
/// ones an ICE restart makes), STUN transaction ids, SSRCs and pacer/loss-controller jitter.
///
/// `fill` must fill the whole slice with random bytes, or panic; it is called from inside str0m's
/// own calls, on whatever thread drives the `Rtc`. The first call installs it for the life of the
/// process and returns `true`; a later call changes nothing and returns `false`.
///
/// With no fill installed, a draw falls back to `fastrand` when the `fastrand` feature is on (the
/// default), and panics when it is off, so a build without `fastrand` never produces a value from
/// a source it did not choose.
pub fn set_fill(fill: fn(&mut [u8])) -> bool {
    FILL.set(fill).is_ok()
}

#[inline(always)]
fn fill(buf: &mut [u8]) {
    match FILL.get() {
        Some(f) => f(buf),
        None => fallback(buf),
    }
}

#[cfg(feature = "fastrand")]
fn fallback(buf: &mut [u8]) {
    fastrand::fill(buf);
}

#[cfg(not(feature = "fastrand"))]
#[cold]
fn fallback(_buf: &mut [u8]) {
    panic!("str0m-proto: no random fill installed (call str0m_proto::set_fill first)");
}

pub struct NonCryptographicRng;

impl NonCryptographicRng {
    #[inline(always)]
    pub fn u8() -> u8 {
        let mut b = [0; 1];
        fill(&mut b);
        b[0]
    }

    #[inline(always)]
    pub fn u16() -> u16 {
        let mut b = [0; 2];
        fill(&mut b);
        u16::from_le_bytes(b)
    }

    #[inline(always)]
    pub fn u32() -> u32 {
        let mut b = [0; 4];
        fill(&mut b);
        u32::from_le_bytes(b)
    }

    #[inline(always)]
    pub fn u64() -> u64 {
        let mut b = [0; 8];
        fill(&mut b);
        u64::from_le_bytes(b)
    }

    /// A value in `[0, 1)`: the top 24 bits of [`Self::u32`] over 2^24, so every value is exact.
    #[inline(always)]
    pub fn f32() -> f32 {
        (Self::u32() >> 8) as f32 / 16_777_216.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn f32_stays_below_one() {
        for _ in 0..1000 {
            let v = NonCryptographicRng::f32();
            assert!((0.0..1.0).contains(&v), "{v}");
        }
    }
}
