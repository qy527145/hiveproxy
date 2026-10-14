//! hiveproxy-core — 去中心化覆盖网络引擎。
//!
//! 本 crate 不依赖任何 UI 框架，可独立测试与复用（设计文档 §6.7）。
//! 分层见 DESIGN.md §4：L1 链路 / L2 帧 / L3 路由 / L4 会话 / L5 应用出口。

pub mod admin;
pub mod api;
pub mod config;
pub mod dialer;
pub mod discovery;
pub mod error;
pub mod events;
pub mod identity;
pub mod gossip;
pub mod handshake;
pub mod heartbeat;
pub mod http_proxy;
pub mod link;
pub mod listener;
pub mod msg;
pub mod net;
pub mod node;
pub mod persist;
pub mod proto;
pub mod proxy;
pub mod relay;
pub mod resolver;
pub mod router;
pub mod rules;
pub mod session;
pub mod service;
pub mod socks5;
pub mod state;
pub mod stream;
pub mod stats;
pub mod topology;
pub mod view;
pub mod web;
pub mod zone;

#[cfg(test)]
pub(crate) mod testutil;

pub use error::{ConfigError, ProtoError, RelayError};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
