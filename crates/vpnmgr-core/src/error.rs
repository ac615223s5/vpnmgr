use std::path::PathBuf;

/// Errors produced by `vpnmgr-core`.
///
/// Secrets are never included in error messages: key-parsing failures name the
/// file and the field, never the value.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("fetching the AirVPN server list failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("the AirVPN API returned result={0:?} instead of \"ok\"")]
    ApiResult(String),

    #[error("decoding the AirVPN server list failed: {0}")]
    Decode(#[source] serde_json::Error),

    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("parsing config {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("{path} is not a usable WireGuard config: {reason}")]
    WgConf { path: PathBuf, reason: String },

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error(
        "no servers match the current filters ({considered} known, {healthy} healthy); \
         loosen filters.max_load or the country lists"
    )]
    NoCandidates { considered: usize, healthy: usize },
}

pub type Result<T> = std::result::Result<T, Error>;
