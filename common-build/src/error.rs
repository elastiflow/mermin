use std::path::PathBuf;

use thiserror::Error;

/// Errors that can occur during build operations
#[derive(Debug, Error)]
pub enum BuildError {
    /// Failed to read toolchain file
    #[error("failed to read toolchain file at {path}: {source}")]
    ToolchainFileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse toolchain file
    #[error("failed to parse toolchain file: {0}")]
    ToolchainFileParse(String),

    /// Missing required field in toolchain file
    #[error("missing required field '{field}' in toolchain file")]
    MissingToolchainField { field: String },

    /// Invalid toolchain channel value
    #[error("invalid toolchain channel value: {0}")]
    InvalidToolchainChannel(String),

    /// TOML parsing error
    #[error("TOML parsing error: {0}")]
    TomlParse(#[from] toml::de::Error),
}

impl BuildError {
    pub fn toolchain_file_read(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::ToolchainFileRead {
            path: path.into(),
            source,
        }
    }

    pub fn missing_field(field: impl Into<String>) -> Self {
        Self::MissingToolchainField {
            field: field.into(),
        }
    }
}
