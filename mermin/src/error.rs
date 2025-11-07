// Error types for Mermin

use std::fmt;

/// Main error type for Mermin operations
#[derive(Debug)]
pub struct MerminError {
    message: String,
}

impl MerminError {
    /// Create a new internal error
    pub fn internal(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for MerminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for MerminError {}
