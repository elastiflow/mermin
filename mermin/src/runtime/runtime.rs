use std::{error::Error, fmt};

use clap::Parser;

use crate::runtime::{cli::Cli, conf::ConfError, props::Properties};

pub struct Runtime {
    #[allow(dead_code)]
    pub cli: Cli,
    pub properties: Properties,
}

impl Runtime {
    pub fn new() -> Result<Self, RuntimeError> {
        let cli = Cli::parse();
        let (properties, cli) = Properties::new(cli)?;

        Ok(Runtime { cli, properties })
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Conf(ConfError),
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

impl From<ConfError> for RuntimeError {
    fn from(e: ConfError) -> Self {
        RuntimeError::Conf(e)
    }
}
