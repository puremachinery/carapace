//! Shared test-only helpers.
//!
//! Tests that mutate process environment variables should use
//! [`env::ScopedEnv`] instead of ad hoc module-local guards.

pub(crate) mod env;
pub(crate) mod plugins;
