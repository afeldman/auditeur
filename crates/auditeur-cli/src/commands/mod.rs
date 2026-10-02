//! Command implementations.

pub mod audit;
pub mod doctor;
pub mod setup;
pub mod update;

use crate::cli::{Cli, Command};
use crate::error::CliError;

/// Run the command the user asked for, returning the process exit code.
pub fn dispatch(cli: &Cli) -> Result<u8, CliError> {
    match &cli.command {
        None => {
            let target = crate::cli::target_path(cli, None);
            audit::run(cli, &target)
        }
        Some(Command::Audit { path }) => {
            let target = crate::cli::target_path(cli, path.as_ref());
            audit::run(cli, &target)
        }
        Some(Command::Setup {
            non_interactive,
            source,
            force,
        }) => setup::run(cli, *non_interactive, source.as_deref(), *force),
        Some(Command::Doctor { json }) => doctor::run(cli, *json),
        Some(Command::Update { check_models }) => update::run(cli, *check_models),
    }
}
