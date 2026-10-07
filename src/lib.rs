//! `mcp-edge`: one authenticated front door for personal MCP servers.
//!
//! Composes the OAuth authorization server (`edge-auth`), signed edge
//! assertions (`edge-assert`), an in-binary `echo` backend and (phase 3) an
//! HTTP forwarder for `kind = "http"` backends. Requests only ever reach the
//! upstream URLs fixed in the route table; nothing in a request selects one.
#![forbid(unsafe_code)]

pub mod app;
pub mod config;
pub mod deny_all;
pub mod echo;
pub mod forward;
pub mod keyfile;
pub mod server;
pub mod tunnel;

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
