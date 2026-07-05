use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::state::{MembershipState, NodeId};

/// A gossip heartbeat: who sent it and the live members they know about.
#[derive(Debug, Serialize, Deserialize)]
struct Beat {
    from: NodeId,
    members: Vec<NodeId>,
}

/// Runs [`MembershipState`] over UDP so agents discover each other and converge.
///
/// Bind to a concrete, routable `ip:port` — the local address becomes this
/// node's `NodeId`, so peers must be able to reach it. Accessors are cheap and
/// synchronous; the send/recv loops run on background tasks aborted on drop.
pub struct GossipMembership {
    state: Arc<Mutex<MembershipState>>,
    start: Instant,
    self_id: NodeId,
    tasks: Vec<JoinHandle<()>>,
}

impl GossipMembership {
    /// Bind, seed with known peer addresses, and start gossiping.
    ///
    /// `interval_ms` — heartbeat period; `dead_after_ms` — silence before a
    /// peer is declared failed (use a few multiples of the interval).
    pub async fn start(
        bind_addr: &str,
        seeds: Vec<String>,
        interval_ms: u64,
        dead_after_ms: u64,
    ) -> std::io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let self_id = socket.local_addr()?.to_string();
        let start = Instant::now();

        let mut initial = MembershipState::new(self_id.clone(), dead_after_ms);
        // Seed peers so our first heartbeat reaches them; they answer and we converge.
        initial.merge_members(&seeds, 0);
        let state = Arc::new(Mutex::new(initial));

        let mut tasks = Vec::new();

        // Receive loop: fold incoming heartbeats into the state.
        {
            let socket = socket.clone();
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let Ok((n, _peer)) = socket.recv_from(&mut buf).await else {
                        continue;
                    };
                    if let Ok(beat) = serde_json::from_slice::<Beat>(&buf[..n]) {
                        let now = start.elapsed().as_millis() as u64;
                        if let Ok(mut s) = state.lock() {
                            s.heartbeat(beat.from, now);
                            s.merge_members(&beat.members, now);
                            s.reap(now, dead_after_ms.saturating_mul(10));
                        }
                    }
                }
            }));
        }

        // Send loop: heartbeat every interval to all currently-live peers.
        {
            let socket = socket.clone();
            let state = state.clone();
            let self_id2 = self_id.clone();
            tasks.push(tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_millis(interval_ms.max(1)));
                loop {
                    ticker.tick().await;
                    let now = start.elapsed().as_millis() as u64;
                    // Snapshot peers under the lock, then release before awaiting I/O.
                    let (payload, peers) = {
                        let Ok(mut s) = state.lock() else { continue };
                        s.touch_self(now);
                        let members = s.live_members(now);
                        let peers: Vec<NodeId> = members
                            .iter()
                            .filter(|m| **m != self_id2)
                            .cloned()
                            .collect();
                        let beat = Beat {
                            from: self_id2.clone(),
                            members,
                        };
                        (serde_json::to_vec(&beat).unwrap_or_default(), peers)
                    };
                    for peer in peers {
                        let _ = socket.send_to(&payload, &peer).await;
                    }
                }
            }));
        }

        Ok(Self {
            state,
            start,
            self_id,
            tasks,
        })
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub fn self_id(&self) -> &str {
        &self.self_id
    }

    /// Currently-live members (including self).
    pub fn live_members(&self) -> Vec<NodeId> {
        let now = self.now();
        self.state
            .lock()
            .map(|s| s.live_members(now))
            .unwrap_or_default()
    }

    /// The current elected leader (lowest live id).
    pub fn leader(&self) -> NodeId {
        let now = self.now();
        self.state
            .lock()
            .map(|s| s.leader(now))
            .unwrap_or_else(|_| self.self_id.clone())
    }

    /// Whether this node is currently the leader / designated relay.
    pub fn is_leader(&self) -> bool {
        self.leader() == self.self_id
    }
}

impl Drop for GossipMembership {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two loopback nodes seeded one-way should converge to the same membership
    /// and agree on the (lowest-id) leader. Real UDP, but 127.0.0.1 only.
    #[tokio::test]
    async fn two_nodes_converge_over_loopback() {
        let a = GossipMembership::start("127.0.0.1:0", vec![], 25, 500)
            .await
            .unwrap();
        let a_addr = a.self_id().to_string();
        let b = GossipMembership::start("127.0.0.1:0", vec![a_addr.clone()], 25, 500)
            .await
            .unwrap();

        // Poll for convergence (avoid fixed sleeps / flakiness).
        let mut converged = false;
        for _ in 0..80 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            if a.live_members().len() == 2 && b.live_members().len() == 2 {
                converged = true;
                break;
            }
        }
        assert!(
            converged,
            "a={:?} b={:?}",
            a.live_members(),
            b.live_members()
        );

        // Deterministic election: both pick the lowest id, and exactly one leads.
        assert_eq!(a.leader(), b.leader());
        assert_ne!(a.is_leader(), b.is_leader());
    }
}
