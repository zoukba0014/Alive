//! Target de-duplication (M8) for large-range scans.
//!
//! Two modes:
//! - [`DedupMode::Exact`] (default): a `HashSet` — never drops a distinct target.
//! - [`DedupMode::Bloom`]: a growable Bloom filter — O(1) memory-frugal for huge
//!   ranges, but false positives can cause a distinct target to be **skipped**.
//!   Opt-in only; callers should log the skip count (a bounded-coverage signal
//!   per WORKSPACE_SPEC's "no silent caps" rule).
//!
//! Bloom never yields false negatives, so it only ever *skips* — it can't invent
//! a duplicate that changes results beyond coverage.

use std::collections::HashSet;
use std::hash::Hash;

use growable_bloom_filter::GrowableBloom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupMode {
    /// Exact set membership — correct, memory scales with distinct items.
    Exact,
    /// Bloom pre-filter — memory-frugal, may skip distinct items (false positives).
    Bloom,
}

/// De-duplicate `items` preserving first-seen order.
///
/// Returns the unique items and the number skipped as duplicates. In
/// [`DedupMode::Bloom`] the skip count may include a small number of false
/// positives (distinct items dropped) — see the module docs.
pub fn dedup<T>(items: impl IntoIterator<Item = T>, mode: DedupMode) -> (Vec<T>, u64)
where
    T: Hash + Eq + Clone,
{
    let items: Vec<T> = items.into_iter().collect();
    let mut out = Vec::with_capacity(items.len());
    let mut skipped = 0u64;

    match mode {
        DedupMode::Exact => {
            let mut seen: HashSet<T> = HashSet::with_capacity(items.len());
            for it in items {
                if seen.insert(it.clone()) {
                    out.push(it);
                } else {
                    skipped += 1;
                }
            }
        }
        DedupMode::Bloom => {
            // Size for the input with a low target error rate.
            let mut bloom = GrowableBloom::new(0.001, items.len().max(1));
            for it in items {
                if bloom.contains(&it) {
                    skipped += 1;
                } else {
                    bloom.insert(&it);
                    out.push(it);
                }
            }
        }
    }
    (out, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_dedup_is_lossless_and_counts_dupes() {
        let input = vec![1u32, 2, 2, 3, 1, 4, 4, 4];
        let (unique, skipped) = dedup(input, DedupMode::Exact);
        assert_eq!(unique, vec![1, 2, 3, 4]);
        assert_eq!(skipped, 4); // one extra 1, one extra 2, two extra 4
    }

    #[test]
    fn bloom_dedup_removes_duplicates() {
        // For a small distinct set the bloom has no false positives, so all
        // distinct items survive and only true duplicates are skipped.
        let input = vec![10u32, 20, 10, 30, 20, 40];
        let (unique, skipped) = dedup(input, DedupMode::Bloom);
        let mut u = unique.clone();
        u.sort_unstable();
        assert_eq!(u, vec![10, 20, 30, 40]);
        assert_eq!(skipped, 2);
    }

    #[test]
    fn dedup_pairs_of_ip_port() {
        use std::net::{IpAddr, Ipv4Addr};
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let input = vec![(ip, 80u16), (ip, 443), (ip, 80)];
        let (unique, skipped) = dedup(input, DedupMode::Exact);
        assert_eq!(unique.len(), 2);
        assert_eq!(skipped, 1);
    }
}
