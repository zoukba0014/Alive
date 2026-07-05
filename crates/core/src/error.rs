use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type shared across the workspace.
///
/// Downstream crates add their own variants by wrapping this or by defining
/// their own error enums that convert into it. Kept intentionally small.
#[derive(Debug, Error)]
pub enum Error {
    /// A target string could not be parsed into a [`crate::Target`].
    #[error("invalid target `{0}`")]
    InvalidTarget(String),

    /// I/O failure surfaced from the standard library.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for errors that do not yet warrant a dedicated variant.
    #[error("{0}")]
    Other(String),
}
