use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// Async TCP connect scan over the cartesian product of `hosts` × `ports`.
///
/// A successful connect is treated as "open"; connection refused / timeout is
/// "closed". Concurrency is bounded by a semaphore, mirroring the pattern used
/// by the scan engine in `bin/alive`. Results are returned sorted for stable
/// output.
pub async fn scan_ports(
    hosts: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
) -> Vec<(IpAddr, u16)> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();

    for &host in hosts {
        for &port in ports {
            let sem = sem.clone();
            set.spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let addr = SocketAddr::new(host, port);
                match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(_stream)) => Some((host, port)),
                    _ => None,
                }
            });
        }
    }

    let mut open = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(hit)) = joined {
            open.push(hit);
        }
    }
    open.sort_unstable();
    open
}
