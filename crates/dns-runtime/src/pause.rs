//! Pausing blocking for a set time.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// When blocking resumes, read on every query.
///
/// A pause only lives in memory and uses the monotonic clock, so a restart or a clock change can
/// end it early but never extend it: the failure direction is that blocking comes back.
#[derive(Debug)]
pub struct BlockingPause {
    started: Instant,
    /// Milliseconds after `started` when the pause ends. Zero means there's no pause.
    until_ms: AtomicU64,
}

impl Default for BlockingPause {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            until_ms: AtomicU64::new(0),
        }
    }
}

impl BlockingPause {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Pauses blocking for this long from now, replacing any pause already running.
    pub fn pause(&self, duration: Duration) {
        let length = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let until = self.now_ms().saturating_add(length).max(1);
        self.until_ms.store(until, Ordering::Relaxed);
    }

    /// Ends any pause now.
    pub fn resume(&self) {
        self.until_ms.store(0, Ordering::Relaxed);
    }

    /// Whether blocking is paused.
    pub fn is_active(&self) -> bool {
        self.until_ms.load(Ordering::Relaxed) > self.now_ms()
    }

    /// How long until blocking resumes, if it's paused.
    pub fn remaining(&self) -> Option<Duration> {
        let until = self.until_ms.load(Ordering::Relaxed);
        let now = self.now_ms();
        (until > now).then(|| Duration::from_millis(until - now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pause_ends_on_its_own_or_when_resumed() {
        let pause = BlockingPause::default();
        assert!(!pause.is_active());
        assert_eq!(pause.remaining(), None);

        pause.pause(Duration::from_secs(60));
        assert!(pause.is_active());
        assert!(
            pause
                .remaining()
                .is_some_and(|left| left <= Duration::from_secs(60))
        );
        pause.resume();
        assert!(!pause.is_active());

        pause.pause(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!pause.is_active());
        assert_eq!(pause.remaining(), None);
    }

    #[test]
    fn a_new_pause_replaces_the_old_one() {
        let pause = BlockingPause::default();
        pause.pause(Duration::from_secs(600));
        pause.pause(Duration::from_secs(5));
        assert!(
            pause
                .remaining()
                .is_some_and(|left| left <= Duration::from_secs(5))
        );
    }
}
