use clap::ValueEnum;

pub mod commands;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
    Table,
}

impl OutputFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputFormat::Pretty => "pretty",
            OutputFormat::Json => "json",
            OutputFormat::Table => "table",
        }
    }
}
