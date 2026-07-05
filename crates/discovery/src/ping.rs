use std::net::IpAddr;
use std::time::Duration;

use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PingError {
    /// The ICMP socket could not be created — almost always missing privileges
    /// (raw/ICMP sockets typically need root or `CAP_NET_RAW`). Callers should
    /// fall back to connect-scan liveness rather than treating this as fatal.
    #[error("cannot open ICMP socket (insufficient privileges?): {0}")]
    Socket(std::io::Error),
}

/// ICMP-echo liveness for a set of hosts, best-effort.
///
/// Returns the subset of `hosts` that answered an echo request. If the ICMP
/// socket cannot be created (the common unprivileged case), returns
/// [`PingError::Socket`] so the caller can degrade to connect-scan liveness —
/// which needs no special privileges and is the default path in the CLI.
pub async fn ping_hosts(hosts: &[IpAddr], timeout: Duration) -> Result<Vec<IpAddr>, PingError> {
    let client = Client::new(&Config::default()).map_err(PingError::Socket)?;

    let mut alive = Vec::new();
    for (i, &host) in hosts.iter().enumerate() {
        let mut pinger = client.pinger(host, PingIdentifier(i as u16)).await;
        pinger.timeout(timeout);
        // A single echo is enough for a liveness signal.
        if pinger.ping(PingSequence(0), &[0u8; 32]).await.is_ok() {
            alive.push(host);
        }
    }
    Ok(alive)
}
