//! Fleet agent library. The safety-critical path is [`exec::verify_and_execute`]:
//! an agent NEVER runs a task until its ed25519 signature checks out AND every
//! target falls inside the task's authorized scope. Task execution reuses the
//! standalone scanner engine crates.

pub mod exec;
pub mod run;

pub use exec::{verify_and_execute, ExecContext, ExecError};
pub use run::{run_agent, AgentConfig};
