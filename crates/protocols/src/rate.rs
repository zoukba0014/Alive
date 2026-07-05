//! Outbound request rate limiting (M8).
//!
//! A global token-bucket limiter (`governor`) that the HTTP runner awaits before
//! each request, so large scans stay within a configurable requests/sec cap and
//! don't overwhelm targets or trip WAF/rate defenses. `rate == 0` means no limit.

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

/// A keyless, in-memory, wall-clock rate limiter shared across requests.
pub type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Build a shared limiter admitting up to `rate_per_sec` requests/second.
/// Returns `None` when `rate_per_sec == 0` (unlimited).
pub fn build_limiter(rate_per_sec: u32) -> Option<Arc<DirectLimiter>> {
    let rate = NonZeroU32::new(rate_per_sec)?;
    Some(Arc::new(RateLimiter::direct(Quota::per_second(rate))))
}

#[cfg(test)]
mod tests {
    use governor::clock::FakeRelativeClock;
    use governor::{Quota, RateLimiter};
    use std::num::NonZeroU32;
    use std::time::Duration;

    #[test]
    fn limiter_admits_at_configured_rate() {
        // Deterministic test using governor's fake clock: a 5/sec bucket admits
        // 5 immediately, then blocks until the clock advances.
        let clock = FakeRelativeClock::default();
        let quota = Quota::per_second(NonZeroU32::new(5).unwrap());
        let limiter = RateLimiter::direct_with_clock(quota, &clock);

        for _ in 0..5 {
            assert!(limiter.check().is_ok(), "first 5 should be admitted");
        }
        assert!(limiter.check().is_err(), "6th should be throttled");

        // Advance ~1s: the bucket refills and admits again.
        clock.advance(Duration::from_secs(1));
        assert!(limiter.check().is_ok(), "should admit after refill");
    }

    #[test]
    fn zero_rate_is_unlimited() {
        assert!(super::build_limiter(0).is_none());
        assert!(super::build_limiter(100).is_some());
    }
}
