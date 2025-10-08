use std::{error::Error, fmt};

use clap::Parser;

use crate::runtime::{cli::Cli, conf::ConfError, props::Properties};

pub struct Context {
    #[allow(dead_code)]
    pub cli: Cli,
    pub properties: Properties,
}

impl Context {
    pub fn new() -> Result<Self, ContextError> {
        let cli = Cli::parse();
        let (properties, cli) = Properties::new(cli)?;

        Ok(Context { cli, properties })
    }
}

#[derive(Debug)]
pub enum ContextError {
    Conf(ConfError),
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextError::Conf(e) => e.fmt(f),
        }
    }
}

impl Error for ContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ContextError::Conf(e) => Some(e),
        }
    }
}

impl From<ConfError> for ContextError {
    fn from(e: ConfError) -> Self {
        ContextError::Conf(e)
    }
}
