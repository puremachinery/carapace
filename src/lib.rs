//! carapace gateway library
//!
//! This library provides the core functionality for the carapace gateway,
//! including HTTP/WebSocket servers, plugin system, and channel management.
//!
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod agent;
pub mod auth;
pub mod channels;
pub mod cli;
pub mod config;
pub mod credentials;
pub mod cron;
pub mod devices;
pub mod discovery;
pub mod exec;
#[cfg(feature = "gateway")]
pub mod gateway;
pub mod hooks;
pub mod links;
pub mod logging;
pub mod media;
pub mod messages;
pub mod nodes;
pub mod plugins;
pub mod server;
pub mod sessions;
pub mod tailscale;
pub mod tls;
pub mod usage;
