//! Shared test-only helpers.
//!
//! Tests that mutate process environment variables should use
//! [`env::ScopedEnv`] instead of ad hoc module-local guards.
//! Tests that mutate process-global config cache state should use
//! [`config::ScopedConfigCache`] when they need that state to remain stable
//! across async boundaries or long assertions.

pub(crate) mod agent;
pub(crate) mod config;
pub(crate) mod env;
pub(crate) mod plugins;
