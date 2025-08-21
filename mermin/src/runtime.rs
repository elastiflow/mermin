use std::{error::Error, fmt};

use clap::Parser;

use crate::runtime::{
    cli::Cli,
    conf::{Config, ConfigError},
};

pub mod cli;
pub mod conf;

pub struct Runtime {
    #[allow(dead_code)]
    pub cli: Cli,
    pub config: Config,
}

impl Runtime {
    pub fn new() -> Result<Self, RuntimeError> {
        let cli = Cli::parse();
        let (config, cli) = Config::new(cli)?;

        Ok(Runtime { cli, config })
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Config(ConfigError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeError::Config(e) => e.fmt(f),
        }
    }
}

impl Error for RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RuntimeError::Config(e) => Some(e),
        }
    }
}

impl From<ConfigError> for RuntimeError {
    fn from(e: ConfigError) -> Self {
        RuntimeError::Config(e)
    }
}
