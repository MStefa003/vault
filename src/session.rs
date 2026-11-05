//! Inactivity tracking for automatic locking. Time is passed in explicitly so
//! the logic is deterministic and testable.

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AutoLock {
    timeout: Duration,
    last_activity: Instant,
}

impl AutoLock {
    pub fn new(timeout: Duration, now: Instant) -> Self {
        AutoLock {
            timeout,
            last_activity: now,
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Record user activity.
    pub fn touch(&mut self, now: Instant) {
        if now > self.last_activity {
            self.last_activity = now;
        }
    }

    pub fn should_lock(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= self.timeout
    }

    pub fn remaining(&self, now: Instant) -> Duration {
        self.timeout
            .saturating_sub(now.saturating_duration_since(self.last_activity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_timeout_and_activity_resets() {
        let t0 = Instant::now();
        let mut a = AutoLock::new(Duration::from_secs(60), t0);
        assert!(!a.should_lock(t0 + Duration::from_secs(59)));
        assert!(a.should_lock(t0 + Duration::from_secs(60)));

        a.touch(t0 + Duration::from_secs(50));
        assert!(!a.should_lock(t0 + Duration::from_secs(100)));
        assert!(a.should_lock(t0 + Duration::from_secs(110)));
        assert_eq!(
            a.remaining(t0 + Duration::from_secs(80)),
            Duration::from_secs(30)
        );

        // Stale timestamps never move the deadline backwards.
        a.touch(t0);
        assert!(a.should_lock(t0 + Duration::from_secs(110)));
    }

    #[test]
    fn timeout_change_applies_immediately() {
        let t0 = Instant::now();
        let mut a = AutoLock::new(Duration::from_secs(600), t0);
        a.set_timeout(Duration::from_secs(10));
        assert!(a.should_lock(t0 + Duration::from_secs(10)));
    }
}
