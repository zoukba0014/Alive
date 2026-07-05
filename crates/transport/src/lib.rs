//! Transport-security primitives for the fleet.
//!
//! Three concerns, all safety-critical (see `WORKSPACE_SPEC.md`):
//! - [`sign`] — ed25519 signing/verification over a deterministic canonical
//!   encoding of a [`alive_proto::Task`]. Agents verify before executing.
//! - [`scope`] — the authorized-target check: a task's targets must fall
//!   inside its `authorized_scope`, or the agent refuses.
//! - [`ca`] / [`tls`] — enrollment CA issuance and tonic mTLS config builders.

mod ca;
mod scope;
mod sign;
mod tls;

pub use ca::{generate_ca, issue_leaf, Ca, CaError};
pub use scope::{target_in_scope, targets_in_scope};
pub use sign::{
    canonical_task_bytes, load_signing_key, sign_task, verify_key_bytes, verify_task, SignError,
    SigningIdentity,
};
pub use tls::{client_tls, server_tls, TlsError};
