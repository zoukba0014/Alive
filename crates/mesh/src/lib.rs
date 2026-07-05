//! Decentralized peer mesh for the agent fleet.
//!
//! Two layers:
//! - [`MembershipState`] — a pure, time-injected state machine (SWIM-style
//!   failure detection + deterministic leader election). Fully unit-tested
//!   without any sockets or wall clock.
//! - [`GossipMembership`] — a thin async wrapper that runs the state machine
//!   over UDP heartbeats so real agents discover each other and converge.
//!
//! **Leader election is deterministic: the lowest live `NodeId` wins.** No
//! consensus protocol is needed — every node computes the same leader from the
//! same live set, and leadership re-resolves automatically as members join or
//! leave. The elected leader is the designated relay when the control-plane
//! server is unreachable (see the agent's offline path).
//!
//! Swapping in the `memberlist` crate later is a matter of providing an
//! alternative [`GossipMembership`] behind the same accessor surface; the
//! deterministic election rule in [`MembershipState`] stays.

mod gossip;
mod state;

pub use gossip::GossipMembership;
pub use state::{MembershipState, NodeId};
