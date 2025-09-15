use std::{error::Error, fmt};

use clap::Parser;

use crate::runtime::{
    cli::Cli,
    conf::{Conf, ConfigError},
};

pub mod cli;
pub mod conf;

pub struct Runtime {
    #[allow(dead_code)]
    pub cli: Cli,
    pub config: Conf,
}

impl Runtime {
    pub fn new() -> Result<Self, RuntimeError> {
        let cli = Cli::parse();
        let (config, cli) = Conf::new(cli)?;

        Ok(Runtime { cli, config })
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Conf(ConfigError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeError::Conf(e) => e.fmt(f),
        }
    }
}

impl Error for RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RuntimeError::Conf(e) => Some(e),
        }
    }
}

impl From<ConfigError> for RuntimeError {
    fn from(e: ConfigError) -> Self {
        RuntimeError::Conf(e)
    }
}
