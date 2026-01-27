//! rusty-clawd gateway library
//!
//! This library provides the core functionality for the rusty-clawd gateway,
//! including HTTP/WebSocket servers, plugin system, and channel management.

#![allow(dead_code)]
#![allow(unused_imports)]

pub mod auth;
pub mod channels;
pub mod config;
pub mod credentials;
pub mod cron;
pub mod devices;
pub mod exec;
pub mod hooks;
pub mod logging;
pub mod media;
pub mod messages;
pub mod nodes;
pub mod plugins;
pub mod server;
pub mod sessions;
