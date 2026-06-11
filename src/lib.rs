//! The Agent Hypervisor: an MCP enforcement layer between an AI agent and the
//! filesystem/shell/git. Exposed as a library so the policy core (verdicts,
//! taint tracking, the ABSENT tool filter) can be exercised by integration
//! tests without standing up a full MCP transport.

pub mod policy;
pub mod registry;
pub mod server;
pub mod session;
pub mod taint;
pub mod tools;
