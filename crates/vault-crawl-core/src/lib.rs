//! Host-local retrieval, extraction, evidence, and policy primitives for
//! `vault-crawl`.

pub mod contract;
pub mod db;
pub mod error;
pub mod extract;
pub mod fetch;
pub mod hash;
pub mod paths;
pub mod policy;
pub mod schema;
pub mod store;
pub mod threat;

pub const PRODUCER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const IMPLEMENTATION_PHASE: u8 = 1;
