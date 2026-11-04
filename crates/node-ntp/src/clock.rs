//! This machine's clock, and whether something is keeping it accurate.

use std::time::{Duration, Instant, SystemTime};

/// Seconds between the NTP epoch (1900) and the Unix epoch (1970).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
/// How long to reuse the kernel's answer. It changes slowly, and packets arrive quickly.
const STATE_LIFETIME: Duration = Duration::from_secs(1);

/// What the kernel says about the clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockState {
    /// A time service is keeping the clock accurate, to within this much.
    Synchronized { max_error: Duration },
    /// Nothing is keeping the clock accurate.
    Unsynchronized,
    /// The kernel's answer isn't available, such as under a strict system call filter.
    Unknown,
}

/// An NTP timestamp: seconds since 1900, then a binary fraction of a second.
pub fn ntp_timestamp(time: SystemTime) -> u64 {
    let since_unix = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let seconds = since_unix.as_secs().wrapping_add(NTP_UNIX_OFFSET);
    let fraction = (u64::from(since_unix.subsec_nanos()) << 32) / 1_000_000_000;
    (seconds << 32) | fraction
}

/// Asks the kernel about the clock. With no changes requested, this only reads and needs no
/// privileges.
#[allow(unsafe_code)]
fn read_state() -> ClockState {
    // SAFETY: `timex` is plain data, so all zeros is valid, and zero `modes` asks only to read.
    // The pointer is valid and exclusive for the whole call, which doesn't retain it.
    let (result, max_error_us) = unsafe {
        let mut timex: libc::timex = std::mem::zeroed();
        let result = libc::adjtimex(&raw mut timex);
        (result, timex.maxerror)
    };
    match result {
        -1 => ClockState::Unknown,
        libc::TIME_ERROR => ClockState::Unsynchronized,
        _ => ClockState::Synchronized {
            max_error: Duration::from_micros(u64::try_from(max_error_us).unwrap_or(0)),
        },
    }
}

/// Reads the clock's state, at most once a second.
#[derive(Debug, Default)]
pub struct ClockMonitor {
    last: Option<(Instant, ClockState)>,
}

impl ClockMonitor {
    pub fn state(&mut self) -> ClockState {
        match self.last {
            Some((read, state)) if read.elapsed() < STATE_LIFETIME => state,
            _ => {
                let state = read_state();
                self.last = Some((Instant::now(), state));
                state
            }
        }
    }
}

/// The clock's state right now, for status pages.
pub fn current_state() -> ClockState {
    read_state()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_count_from_1900_with_a_binary_fraction() {
        let time = SystemTime::UNIX_EPOCH + Duration::new(1, 500_000_000);
        let stamp = ntp_timestamp(time);
        assert_eq!(stamp >> 32, NTP_UNIX_OFFSET + 1);
        assert_eq!(stamp & 0xffff_ffff, 0x8000_0000);
    }

    #[test]
    fn the_kernel_can_be_asked_without_privileges() {
        // The answer depends on the machine, but the call itself must not misbehave.
        let _ = read_state();
        let mut monitor = ClockMonitor::default();
        assert_eq!(monitor.state(), monitor.state());
    }
}
