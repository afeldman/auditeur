//! `auditeur` — local evidence-driven software auditor.
//!
//! The binary is deliberately thin: parse arguments, hand over to
//! [`auditeur_cli::run`], turn the result into an exit code. Anything that needs
//! testing lives in the library beside it.

use std::process::ExitCode;

use auditeur_cli::cli::Cli;
use clap::Parser;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match auditeur_cli::run(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            // Errors go to standard error, so a pipeline reading standard output
            // never has to filter them out.
            eprintln!("auditeur: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}
