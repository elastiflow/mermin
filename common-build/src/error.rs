use std::{error::Error, fmt, path::PathBuf};

/// Errors that can occur during build operations
#[derive(Debug)]
pub enum BuildError {
    /// Failed to read toolchain file.
    ToolchainFileRead {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Failed to parse toolchain file.
    ToolchainFileParse(String),
    /// Missing required field in toolchain file.
    MissingToolchainField { field: String },
    /// Invalid toolchain channel value.
    InvalidToolchainChannel(String),
    /// TOML deserialization error.
    TomlParse(toml::de::Error),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToolchainFileRead { path, .. } => {
                write!(f, "failed to read toolchain file at {}", path.display())
            }
            Self::ToolchainFileParse(msg) => write!(f, "failed to parse toolchain file: {msg}"),
            Self::MissingToolchainField { field } => {
                write!(f, "missing required field '{field}' in toolchain file")
            }
            Self::InvalidToolchainChannel(val) => {
                write!(f, "invalid toolchain channel value: {val}")
            }
            Self::TomlParse(err) => write!(f, "TOML parsing error: {err}"),
        }
    }
}

impl Error for BuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ToolchainFileRead { source, .. } => Some(source),
            Self::TomlParse(err) => Some(err),
            _ => None,
        }
    }
}

impl From<toml::de::Error> for BuildError {
    fn from(err: toml::de::Error) -> Self {
        Self::TomlParse(err)
    }
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
