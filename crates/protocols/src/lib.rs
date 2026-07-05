//! Concrete protocol runners implementing the engine's transport traits:
//! HTTP (reqwest), TCP (tokio), and TLS (tokio-rustls + x509-parser). DNS
//! arrives in a later milestone.

mod http;
mod tcp;
mod tls;

pub use http::HttpRunner;
pub use tcp::TcpRunner;
pub use tls::TlsRunner;
