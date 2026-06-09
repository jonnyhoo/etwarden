//! # `stdout`
//!
//! **Purpose**: Binary stdout NDJSON writer.
//! **Public API**: binary-internal `write_output_line`
//! **Dependencies**: `output::schema`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 25 / 80

use std::io::Write;

use etwarden::output::schema::OutputLine;

pub fn write_output_line(output: &OutputLine) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    write_output_line_to(&mut stdout, output)
}

fn write_output_line_to(writer: &mut dyn Write, output: &OutputLine) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *writer, output)?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests;
