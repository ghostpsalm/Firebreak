//! Turning kernel packet counters into a usage total that survives resets.
//!
//! Windows hands Firebreak *events*: each one is a fact that happened once,
//! and a monotonic EventRecordID makes resume exact. Linux hands it a
//! *gauge*: `iptables -L -v` reports packets since the rule was installed.
//! Gauges reset — on reboot, on `ufw reload`, on `iptables -Z` — and a naive
//! reader silently loses everything counted before the reset, or (worse)
//! double-counts by adding a raw reading to a running total every run.
//!
//! So each rule carries `accumulated` (everything banked from previous
//! counter lifetimes) plus `last_raw` (the reading at the previous run).
//! Total is the sum. A reset banks `last_raw` and starts the new lifetime.
//!
//! Two independent reset signals, because neither alone is sufficient:
//!
//!  1. `raw < last_raw` — the counter went backwards, which only a reset
//!     can do. Misses a reset that climbed back past the old value between
//!     two runs.
//!  2. A changed *generation* token (boot id + a hash of the rule set).
//!     Catches reboots and rule reloads regardless of counter values.
//!
//! What neither catches: `iptables -Z` (zero counters) with no rule-set
//! change and no reboot, where traffic then pushes the counter past its old
//! value before the next run. That undercounts, and it is unfixable by
//! polling — recorded here so nobody later reads a total as exact.

/// Per-rule counter bookkeeping, persisted between runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CounterState {
    /// Packets banked from counter lifetimes that have already ended.
    pub accumulated: i64,
    /// The raw counter as of the previous observation.
    pub last_raw: i64,
}

impl CounterState {
    /// Everything this rule has matched, across resets.
    pub fn total(&self) -> i64 {
        self.accumulated + self.last_raw
    }

    /// Fold a fresh reading in. `generation_changed` is the caller's verdict
    /// on whether the counter's lifetime restarted (reboot / rule reload).
    pub fn observe(self, raw: i64, generation_changed: bool) -> CounterState {
        // A negative reading is not physically meaningful; treat it as zero
        // rather than letting it subtract from a real total.
        let raw = raw.max(0);
        if generation_changed || raw < self.last_raw {
            CounterState {
                accumulated: self.accumulated + self.last_raw,
                last_raw: raw,
            }
        } else {
            CounterState {
                accumulated: self.accumulated,
                last_raw: raw,
            }
        }
    }
}

/// A token identifying the current counter lifetime. Changes whenever the
/// counters could have been reset out from under us: a reboot changes the
/// boot id, and any rule-set edit or reload changes the digest.
pub fn generation(rule_identities: &[String]) -> String {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "no-boot-id".into());
    format!("{boot}:{:016x}", digest(rule_identities))
}

/// FNV-1a over the rule identities. Not a security hash — it only needs to
/// change when the rule set does, and to be stable across runs and builds.
fn digest(items: &[String]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for item in items {
        for b in item.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        // separator, so ["ab","c"] and ["a","bc"] differ
        h ^= 0xff;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rising_counter_is_not_double_counted() {
        // The bug this whole module exists to prevent: adding each raw
        // reading to a running total. Three runs seeing 10, 25, 40 packets
        // is a rule that has matched 40 — not 75.
        let s = CounterState::default();
        let s = s.observe(10, false);
        let s = s.observe(25, false);
        let s = s.observe(40, false);
        assert_eq!(s.total(), 40);
    }

    #[test]
    fn a_counter_going_backwards_banks_the_old_lifetime() {
        let s = CounterState::default().observe(500, false);
        // reboot: counter restarts, and the 500 must not be lost
        let s = s.observe(7, false);
        assert_eq!(s.accumulated, 500);
        assert_eq!(s.last_raw, 7);
        assert_eq!(s.total(), 507);
    }

    #[test]
    fn a_generation_change_banks_even_when_the_counter_rose() {
        // ufw reload between runs: the new counter (600) is larger than the
        // old (500), so the backwards check alone would read it as continued
        // growth and lose 500 packets of real evidence.
        let s = CounterState::default().observe(500, false);
        let s = s.observe(600, true);
        assert_eq!(s.accumulated, 500);
        assert_eq!(s.total(), 1100);
    }

    #[test]
    fn repeated_resets_keep_banking() {
        let mut s = CounterState::default();
        for _ in 0..4 {
            s = s.observe(100, false);
            s = s.observe(0, true);
        }
        assert_eq!(s.total(), 400);
    }

    #[test]
    fn an_unchanged_counter_adds_nothing() {
        let s = CounterState::default().observe(42, false);
        let s = s.observe(42, false);
        assert_eq!(s.total(), 42);
    }

    #[test]
    fn a_negative_reading_cannot_subtract_from_a_real_total() {
        let s = CounterState::default().observe(100, false);
        // a parse failure or garbage reading must not eat banked evidence
        let s = s.observe(-5, false);
        assert_eq!(s.accumulated, 100);
        assert_eq!(s.total(), 100);
    }

    #[test]
    fn generation_digest_tracks_the_rule_set() {
        let a = vec!["allow tcp 22".to_string(), "deny tcp 23".to_string()];
        let b = vec!["allow tcp 22".to_string()];
        assert_ne!(digest(&a), digest(&b));
        assert_eq!(digest(&a), digest(&a.clone()));
        // order matters: reordering rules changes which counter is which
        let c = vec!["deny tcp 23".to_string(), "allow tcp 22".to_string()];
        assert_ne!(digest(&a), digest(&c));
    }

    #[test]
    fn digest_is_not_fooled_by_boundary_shifts() {
        let a = vec!["ab".to_string(), "c".to_string()];
        let b = vec!["a".to_string(), "bc".to_string()];
        assert_ne!(digest(&a), digest(&b));
    }
}
