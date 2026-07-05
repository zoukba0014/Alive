use std::collections::BTreeMap;

/// A node identity. In the gossip layer this is the node's mesh socket address
/// string (e.g. `10.0.0.5:7946`), which gives a stable, comparable ordering.
pub type NodeId = String;

/// Pure membership + failure-detection state machine.
///
/// Time is injected as a monotonic `now` tick (any unit — the gossip layer uses
/// milliseconds). A member is *live* if it was heard from within `dead_after`
/// ticks of `now`; otherwise it is considered failed. `self` is always live.
/// This struct performs no I/O and holds no clock, so tests drive it directly.
#[derive(Debug, Clone)]
pub struct MembershipState {
    self_id: NodeId,
    /// member id -> tick we last heard a heartbeat from them
    last_seen: BTreeMap<NodeId, u64>,
    dead_after: u64,
}

impl MembershipState {
    /// `dead_after` — ticks of silence before a member is declared failed.
    pub fn new(self_id: impl Into<NodeId>, dead_after: u64) -> Self {
        let self_id = self_id.into();
        let mut last_seen = BTreeMap::new();
        last_seen.insert(self_id.clone(), 0);
        Self {
            self_id,
            last_seen,
            dead_after: dead_after.max(1),
        }
    }

    pub fn self_id(&self) -> &str {
        &self.self_id
    }

    /// Record a heartbeat directly observed from `id` at `now`.
    pub fn heartbeat(&mut self, id: impl Into<NodeId>, now: u64) {
        self.last_seen.insert(id.into(), now);
    }

    /// Refresh our own liveness timestamp (called each gossip tick).
    pub fn touch_self(&mut self, now: u64) {
        let id = self.self_id.clone();
        self.last_seen.insert(id, now);
    }

    /// Merge a peer-gossiped member list. Members we don't already track are
    /// recorded at `now` (indirect discovery — SWIM's dissemination component).
    pub fn merge_members(&mut self, members: &[NodeId], now: u64) {
        for m in members {
            self.last_seen.entry(m.clone()).or_insert(now);
        }
    }

    /// Members considered live at `now` (sorted, `self` always included).
    pub fn live_members(&self, now: u64) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self
            .last_seen
            .iter()
            .filter(|(id, &seen)| {
                id.as_str() == self.self_id || now.saturating_sub(seen) <= self.dead_after
            })
            .map(|(id, _)| id.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Drop members that have been silent longer than `gc_after` (bounded memory).
    pub fn reap(&mut self, now: u64, gc_after: u64) {
        let self_id = self.self_id.clone();
        self.last_seen
            .retain(|id, seen| *id == self_id || now.saturating_sub(*seen) <= gc_after);
    }

    /// The elected leader = lowest live `NodeId`. Deterministic across nodes.
    pub fn leader(&self, now: u64) -> NodeId {
        self.live_members(now)
            .into_iter()
            .min()
            .unwrap_or_else(|| self.self_id.clone())
    }

    /// Whether this node is the current leader.
    pub fn is_leader(&self, now: u64) -> bool {
        self.leader(now) == self.self_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_is_always_live_and_leads_alone() {
        let s = MembershipState::new("b", 5);
        assert_eq!(s.live_members(1000), vec!["b".to_string()]);
        assert!(s.is_leader(1000));
        assert_eq!(s.leader(1000), "b");
    }

    #[test]
    fn converges_on_shared_members() {
        let mut a = MembershipState::new("a", 5);
        a.heartbeat("b", 0);
        a.merge_members(&["c".into()], 0);
        assert_eq!(a.live_members(3), vec!["a", "b", "c"]);
    }

    #[test]
    fn silent_member_is_detected_dead() {
        let mut a = MembershipState::new("a", 5);
        a.heartbeat("b", 0);
        // within window
        assert!(a.live_members(5).contains(&"b".to_string()));
        // past dead_after → b is failed and drops out
        assert!(!a.live_members(6).contains(&"b".to_string()));
    }

    #[test]
    fn leader_is_lowest_live_id_and_re_elects() {
        let mut n = MembershipState::new("b", 5);
        n.heartbeat("a", 0);
        n.heartbeat("c", 0);
        // a, b, c live → lowest is "a"
        assert_eq!(n.leader(3), "a");
        assert!(!n.is_leader(3));
        // a goes silent past the window; b and c refreshed → leader re-elects to "b"
        n.heartbeat("b", 6);
        n.heartbeat("c", 6);
        assert_eq!(n.leader(7), "b");
        assert!(n.is_leader(7));
    }

    #[test]
    fn reap_removes_long_dead_but_keeps_self() {
        let mut a = MembershipState::new("a", 5);
        a.heartbeat("b", 0);
        a.reap(100, 10);
        assert_eq!(a.live_members(100), vec!["a".to_string()]);
    }
}
