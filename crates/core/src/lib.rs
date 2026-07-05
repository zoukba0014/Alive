//! Shared core types for the Alive scanner.
//!
//! This crate is dependency-light on purpose: every other crate in the
//! workspace depends on it, so it must stay cheap to compile and free of
//! heavy runtime dependencies (no tokio, no reqwest here).
//!
//! Layers that build on these types:
//! - `engine` / `protocols` produce [`Finding`]s against [`Target`]s.
//! - `ai` consumes [`Finding`]s for triage.
//! - `server` / `agent` ship [`Finding`]s and tasks across the fleet.

mod error;
mod finding;
mod protocol;
mod severity;
mod target;

pub use error::{Error, Result};
pub use finding::{Evidence, Finding};
pub use protocol::Protocol;
pub use severity::Severity;
pub use target::Target;
