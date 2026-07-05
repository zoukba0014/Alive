//! Host discovery layer.
//!
//! This crate turns a user's target spec into concrete assets:
//! `expand` (spec → IPs) → `portscan` (open TCP ports) → `service` (what is
//! listening). `ping` offers ICMP liveness where the OS permits it, but the
//! privilege-free liveness signal is simply "has an open port" from the
//! connect scan — the CLI relies on that fallback so it never needs root.
//!
//! Nothing here is transport-agnostic like `engine`; these are the concrete
//! network probes that feed the fingerprint → tag-routing step.

mod dedup;
mod expand;
mod ping;
mod ports;
mod portscan;
mod service;

pub use dedup::{dedup, DedupMode};
pub use expand::{expand, ExpandError};
pub use ping::{ping_hosts, PingError};
pub use ports::{parse_ports, PortParseError};
pub use portscan::scan_ports;
pub use service::{detect, service_for_port, Service};
