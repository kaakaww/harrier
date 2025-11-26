use anyhow::Result;
use clap::Command;
use clap_complete::{Shell, generate};
use std::io;

/// Execute the completion command - generates completion script to stdout
pub fn execute(shell: Shell, cmd: &mut Command) -> Result<()> {
    let bin_name = cmd.get_name().to_string();
    generate(shell, cmd, bin_name, &mut io::stdout());
    Ok(())
}
