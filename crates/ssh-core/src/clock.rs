//! Time, as a dependency rather than an ambient fact.
//!
//! Session expiry is a security property, so its tests must be able to move
//! time deliberately. A test that sleeps to observe a timeout is slow, flaky,
//! and can only check timeouts short enough to wait for — which are never the
//! ones actually configured.

use std::sync::atomic::{AtomicU64, Ordering};

use nix::time::{ClockId, clock_gettime};

/// Milliseconds since an arbitrary but fixed origin.
///
/// Only differences are meaningful, so the origin does not matter as long as it
/// does not move while the process runs.
pub type Millis = u64;

pub trait Clock: Send + Sync {
    fn now(&self) -> Millis;
}

/// The service's clock: the system's boot-time clock, and nothing else.
///
/// A session's lifetime is a security boundary, so the failure that matters is
/// elapsed time coming out *too small* — a bounded window silently becoming a
/// longer one. `CLOCK_BOOTTIME` has exactly the two properties that requires,
/// and providing them is the operating system's job rather than this module's:
///
/// - It **never moves backwards**, so no clock adjustment can shorten a
///   session's age.
/// - It **counts time spent suspended**, unlike `CLOCK_MONOTONIC`, so a host
///   paused and resumed does not treat every live session as younger than it is.
///
/// Earlier versions of this type tried to build those properties out of
/// `Instant` and `SystemTime`: take the larger reading, then keep a high-water
/// mark so it could not fall. Each attempt closed the previous one's hole and
/// opened another — the last froze the clock at a spuriously large reading
/// after a forward jump was corrected, so a session opened during the freeze
/// never aged at all. Combining two clocks that are each wrong in a different
/// way does not produce a right one; asking for the clock that already has the
/// semantics does.
#[derive(Debug)]
pub struct SystemClock {
    origin: Millis,
    /// The last reading taken successfully.
    ///
    /// A read cannot fail once construction has proved the clock id valid, but
    /// "cannot happen" is not a reason to encode an answer that would be
    /// catastrophic if it did. Every candidate constant is wrong in one
    /// direction: zero and the origin make live sessions immortal, and a large
    /// value makes a session opened at that moment immortal, because every
    /// later reading is smaller and its age saturates to zero. The last real
    /// reading is wrong in no direction — it is neither in the future nor
    /// earlier than something already observed.
    last_good: AtomicU64,
}

impl SystemClock {
    /// Reads the clock once, to fix an origin.
    ///
    /// Fallible rather than panicking, and the service is expected to refuse to
    /// start: without this clock there is no working expiry, and a session that
    /// never ages is worse than a service that does not come up.
    pub fn new() -> Result<Self, ClockUnavailable> {
        let origin = boot_millis().ok_or(ClockUnavailable)?;
        Ok(Self {
            origin,
            last_good: AtomicU64::new(0),
        })
    }
}

/// The clock a session's lifetime depends on could not be read.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("CLOCK_BOOTTIME could not be read, so session expiry cannot be enforced")]
pub struct ClockUnavailable;

impl Clock for SystemClock {
    fn now(&self) -> Millis {
        match boot_millis() {
            Some(reading) => {
                // Saturating: the source does not move backwards, so this
                // cannot underflow — but underflow is the failure this type
                // exists to prevent, so it does not rest on an argument.
                let elapsed = reading.saturating_sub(self.origin);
                self.last_good.store(elapsed, Ordering::SeqCst);
                elapsed
            }
            None => self.last_good.load(Ordering::SeqCst),
        }
    }
}

/// Milliseconds since boot, including time spent suspended.
fn boot_millis() -> Option<Millis> {
    let time = clock_gettime(ClockId::CLOCK_BOOTTIME).ok()?;
    let seconds = u64::try_from(time.tv_sec()).ok()?;
    let nanos = u64::try_from(time.tv_nsec()).ok()?;
    Some(
        seconds
            .saturating_mul(1_000)
            .saturating_add(nanos / 1_000_000),
    )
}

/// A shared clock is still a clock.
///
/// The session store and the record each hold one and must agree about the
/// time, so they share a single instance rather than each constructing its own
/// origin.
impl<C: Clock> Clock for std::sync::Arc<C> {
    fn now(&self) -> Millis {
        (**self).now()
    }
}

/// A clock a test drives by hand.
#[derive(Debug, Default)]
pub struct TestClock(AtomicU64);

impl TestClock {
    #[must_use]
    pub fn at(millis: Millis) -> Self {
        Self(AtomicU64::new(millis))
    }

    /// Moves time forward. Saturating, so a test cannot accidentally wrap and
    /// observe a session that is expired appearing fresh again.
    pub fn advance(&self, millis: Millis) {
        let current = self.0.load(Ordering::SeqCst);
        self.0
            .store(current.saturating_add(millis), Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Millis {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_moves_only_when_told() {
        let clock = TestClock::at(1_000);
        assert_eq!(clock.now(), 1_000);
        assert_eq!(clock.now(), 1_000, "time does not pass on its own");
        clock.advance(500);
        assert_eq!(clock.now(), 1_500);
    }

    #[test]
    fn test_clock_saturates_rather_than_wrapping() {
        let clock = TestClock::at(u64::MAX - 1);
        clock.advance(100);
        assert_eq!(clock.now(), u64::MAX, "wrapping would rewind time");
    }

    /// The clock measures from its own construction, not from an external
    /// origin.
    ///
    /// This discriminates: a wall-clock reading is milliseconds since 1970 and
    /// a raw `CLOCK_BOOTTIME` reading is milliseconds since the host booted,
    /// both enormous, while a clock built moments ago reads small.
    ///
    /// What it does *not* establish is the property that matters — that
    /// elapsed time never comes out too small. That now rests on
    /// `CLOCK_BOOTTIME`'s documented semantics rather than on arithmetic here,
    /// and no unit test can suspend a machine or step a clock to demonstrate
    /// it. Depending on the operating system for it is the point: the previous
    /// attempts to establish it in code were testable and wrong.
    #[test]
    fn the_production_clock_measures_from_its_own_start_not_the_epoch() {
        let clock = SystemClock::new().unwrap();
        let reading = clock.now();
        assert!(
            reading < 60_000,
            "a freshly built clock read {reading}ms, which is wall time, not elapsed time"
        );
    }

    /// A second clock built later starts over, which is what "measures from its
    /// own construction" means and what a shared epoch would not do.
    #[test]
    fn each_production_clock_has_its_own_origin() {
        let earlier = SystemClock::new().unwrap();
        while earlier.now() == 0 {
            std::hint::spin_loop();
        }
        let later = SystemClock::new().unwrap();
        assert!(
            later.now() < earlier.now(),
            "the later clock did not start from its own construction"
        );
    }
}
