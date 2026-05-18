//! Sophos Firewall Manager — library crate.
//!
//! A Rust port of the Python `sophos-firewall-manager` tool, organized in the
//! same clean-architecture layers: `domain`, `infra`, `services`,
//! `presentation`, plus `config` and `cli`.

pub mod cli;
pub mod config;
pub mod domain;
pub mod infra;
pub mod presentation;
pub mod services;
pub mod workflow;
