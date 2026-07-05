use alive_core::Result;
use async_trait::async_trait;

/// A raw TCP reply the engine matches against (`part: data`).
#[derive(Debug, Clone)]
pub struct TcpResponse {
    pub data: String,
}

/// Transport for TCP/network templates. Implemented by `alive-protocols` and
/// by fakes in tests.
#[async_trait]
pub trait TcpClient: Send + Sync {
    /// Connect to `addr` (`host:port`), write each input in order, then read up
    /// to `read_size` bytes of reply.
    async fn send(&self, addr: &str, inputs: &[String], read_size: usize) -> Result<TcpResponse>;
}
