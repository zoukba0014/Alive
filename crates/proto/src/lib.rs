//! Generated gRPC types for the fleet control plane.
//!
//! The `.proto` is compiled at build time (see `build.rs`) into the
//! `alive.fleet.v1` module, re-exported flat here. The key safety property
//! lives in the schema: [`task::Body`] is a closed set of task types with no
//! free-form command field.

pub mod fleet {
    #![allow(clippy::doc_lazy_continuation)]
    tonic::include_proto!("alive.fleet.v1");
}

pub use fleet::{
    agent_message, fleet_client, fleet_server, server_message, task, AgentMessage, AgentStatus,
    CollectInventoryTask, DiscoverTask, EnrollRequest, EnrollResponse, Hello, Ping, Pong, ScanTask,
    ServerMessage, Task, TaskResult,
};
