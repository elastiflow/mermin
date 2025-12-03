use thiserror::Error;

use crate::runtime::{
    cli::Cli,
    conf::{Conf, ConfError},
};

pub struct Context {
    #[allow(dead_code)]
    pub cli: Cli,
    pub conf: Conf,
}

impl Context {
    pub fn new(cli: Cli) -> Result<Self, ContextError> {
        let (conf, cli) = Conf::new(cli)?;

        Ok(Context { cli, conf })
    }
}

/// Errors that can occur during runtime context initialization
#[derive(Debug, Error)]
pub enum ContextError {
    /// Configuration error
    #[error("configuration error: {0}")]
    Conf(#[from] ConfError),
}
