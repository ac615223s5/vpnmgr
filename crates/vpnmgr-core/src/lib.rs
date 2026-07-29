//! Core logic for the vpnmgr WireGuard manager: provider data, configuration,
//! server filtering and ranking.
//!
//! This crate is deliberately free of privileged and platform-specific code —
//! it neither creates interfaces nor sends packets, so all of it is testable
//! without root. Tunnel control lives in `vpnmgr-tunnel`, probing in
//! `vpnmgr-probe`.
//!
//! # The AirVPN shortcut
//!
//! Every AirVPN server shares one WireGuard peer public key, and all of them
//! listen on `ip_v4_in1:1637`. A single client keypair — imported once from the
//! Config Generator — is therefore valid fleet-wide. Selecting a server is a
//! local decision made against the public [`airvpn`] status API, and applying
//! it means rewriting one `Endpoint` line ([`render`]). There is no login, no
//! per-server credential fetch and nothing to rate limit.
//!
//! # Pipeline
//!
//! ```text
//! airvpn::Client::fetch  ->  filter::apply  ->  (probe)  ->  score::rank
//!        257 servers          Tier 0, free      Tier 1      best-first
//! ```

pub mod airvpn;
pub mod config;
pub mod error;
pub mod filter;
pub mod key;
pub mod render;
pub mod score;
pub mod wgconf;

pub use config::Config;
pub use error::{Error, Result};
pub use key::{PublicKey, SecretKey};
pub use score::{Measured, Scored};
pub use wgconf::{Cidr, ClientConfig};
