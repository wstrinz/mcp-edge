//! `mcp-edge`: one authenticated front door for personal MCP servers.
//!
//! Phase 2 composes the OAuth authorization server (`edge-auth`), signed edge
//! assertions (`edge-assert`) and an in-binary `echo` backend. No request can
//! reach any other host: the route table only knows built-in backends.
#![forbid(unsafe_code)]

pub mod app;
pub mod config;
pub mod deny_all;
pub mod echo;
pub mod forward;
pub mod keyfile;
pub mod server;

use std::io;

/// Process mode chosen by `EDGE_MODE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The original inert process (default when `EDGE_MODE` is unset).
    DenyAll,
    /// OAuth authorization server + built-in backends.
    Edge,
}

impl Mode {
    pub fn parse(value: Option<&str>) -> io::Result<Self> {
        match value {
            None | Some("deny-all") => Ok(Mode::DenyAll),
            Some("edge") => Ok(Mode::Edge),
            _ => Err(io::Error::other("unsupported EDGE_MODE")),
        }
    }
}
