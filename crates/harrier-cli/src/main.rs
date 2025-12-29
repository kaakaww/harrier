use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::Shell;
use harrier_cli::{OutputFormat, commands};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "harrier")]
#[command(author, version, about)]
#[command(
    about = "Analyze, filter, and capture HTTP Archive (HAR) files",
    after_help = "EXAMPLES:\n  \
        harrier app.har                              Quick summary\n  \
        harrier capture --url https://example.com    Capture with Chrome\n  \
        harrier analyze app.har --all                Full analysis\n  \
        harrier export app.har --hawkscan            Generate HawkScan config\n\n\
        Docs: https://github.com/kaakaww/harrier"
)]
pub struct Cli {
    /// HAR file to analyze (shows quick summary)
    #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
    file: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format: pretty, json, table [default: pretty]
    #[arg(short, long, global = true, default_value_t = OutputFormat::Pretty, value_enum, hide_possible_values = true, hide_default_value = true)]
    format: OutputFormat,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze HAR for security, auth, APIs, and architecture
    Analyze {
        /// HAR file to analyze
        #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
        file: PathBuf,

        /// Focus area: map, auth (repeatable)
        #[arg(long, value_enum, hide_possible_values = true)]
        focus: Vec<commands::analyze::Focus>,

        /// Run all analysis types
        #[arg(long)]
        all: bool,

        /// Filter to specific hosts (comma-separated or repeatable)
        #[arg(long, value_delimiter = ',', value_hint = ValueHint::Hostname)]
        host: Vec<String>,
    },

    /// Capture HTTP traffic via browser (default) or proxy
    Capture {
        /// Use MITM proxy instead of browser
        #[arg(long)]
        proxy: bool,

        /// Output HAR file [default: captured.har]
        #[arg(short, long, default_value = "captured.har", value_hint = ValueHint::FilePath, hide_default_value = true)]
        output: PathBuf,

        /// Filter to specific hosts (comma-separated or repeatable)
        #[arg(long, value_delimiter = ',', value_hint = ValueHint::Hostname)]
        host: Vec<String>,

        /// Show HawkScan guidance after capture
        #[arg(long)]
        hawkscan: bool,

        /// Starting URL to navigate to (browser mode)
        #[arg(long, value_hint = ValueHint::Url)]
        url: Option<String>,

        /// Use named persistent profile (browser mode)
        #[arg(long, value_hint = ValueHint::Other)]
        profile: Option<String>,

        /// Use temporary profile (browser mode)
        #[arg(long)]
        temp: bool,

        /// Override Chrome binary location (browser mode)
        #[arg(long, value_hint = ValueHint::FilePath)]
        chrome_path: Option<PathBuf>,

        /// Port to listen on (proxy mode) [default: 8080]
        #[arg(short = 'p', long, default_value = "8080", hide_default_value = true)]
        port: u16,

        /// Custom CA certificate path (proxy mode)
        #[arg(long, value_hint = ValueHint::FilePath)]
        cert: Option<PathBuf>,

        /// Custom CA private key path (proxy mode)
        #[arg(long, value_hint = ValueHint::FilePath)]
        key: Option<PathBuf>,
    },

    /// Generate configs from HAR (currently: --hawkscan)
    Export {
        /// HAR file to export from
        #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
        file: PathBuf,

        /// Generate HawkScan YAML configuration
        #[arg(long)]
        hawkscan: bool,

        /// Filter to specific hosts (comma-separated or repeatable)
        #[arg(long, value_delimiter = ',', value_hint = ValueHint::Hostname)]
        host: Vec<String>,

        /// Include all hosts (even non-scannable ones)
        #[arg(long)]
        all_hosts: bool,

        /// Write output to file
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },

    /// Filter HAR entries by host, status, method, or content-type
    Filter {
        /// HAR file to filter (use '-' for stdin)
        #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
        file: PathBuf,

        /// Filter to specific hosts (comma-separated or repeatable)
        #[arg(long, value_delimiter = ',', value_hint = ValueHint::Hostname)]
        host: Vec<String>,

        /// Status codes (2xx, 404, 500-599, etc.)
        #[arg(long, value_hint = ValueHint::Other)]
        status: Option<String>,

        /// HTTP method (GET, POST, etc.)
        #[arg(long, value_hint = ValueHint::Other)]
        method: Option<String>,

        /// Content type pattern
        #[arg(long, value_hint = ValueHint::Other)]
        content_type: Option<String>,

        /// Output file (defaults to stdout)
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },

    /// Manage Chrome profiles for capture
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },

    /// Generate shell completions (bash, zsh, fish, powershell)
    Completion {
        /// Shell: bash, zsh, fish, powershell
        #[arg(long, value_enum, required = true, hide_possible_values = true)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// List all available profiles
    List,

    /// Show detailed information about a profile
    Info {
        /// Profile name
        #[arg(value_hint = ValueHint::Other)]
        name: String,
    },

    /// Delete a profile
    Delete {
        /// Profile name
        #[arg(value_hint = ValueHint::Other)]
        name: String,

        /// Force deletion without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Clear cache from profiles
    Clean {
        /// Specific profile to clean (cleans all if omitted)
        #[arg(long, value_hint = ValueHint::Other)]
        profile: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose);

    // Handle default command (positional HAR file)
    if let Some(ref file) = cli.file
        && cli.command.is_none()
    {
        return commands::summary::execute(file, cli.format);
    }

    // Execute subcommand
    match cli.command {
        Some(Commands::Analyze {
            file,
            focus,
            all,
            host,
        }) => commands::analyze::execute(&file, focus, all, host, cli.format),

        Some(Commands::Capture {
            proxy,
            output,
            host,
            hawkscan,
            url,
            profile,
            temp,
            chrome_path,
            port,
            cert,
            key,
        }) => {
            let mode = if proxy {
                commands::capture::CaptureMode::Proxy
            } else {
                commands::capture::CaptureMode::Browser
            };
            commands::capture::execute(
                mode,
                &output,
                host,
                hawkscan,
                url,
                profile,
                temp,
                chrome_path,
                port,
                cert,
                key,
            )
        }

        Some(Commands::Export {
            file,
            hawkscan,
            host,
            all_hosts,
            output,
        }) => {
            if !hawkscan {
                // Default to hawkscan if no export type specified
                // In the future, we'll require one of the export type flags
                eprintln!("Note: No export type specified, defaulting to --hawkscan");
            }
            commands::export::execute(
                &file,
                commands::export::ExportType::HawkScan,
                host,
                all_hosts,
                output,
                cli.format,
            )
        }

        Some(Commands::Filter {
            file,
            host,
            status,
            method,
            content_type,
            output,
        }) => commands::filter::execute(
            &file,
            host,
            status,
            method,
            content_type,
            output,
            cli.format,
        ),

        Some(Commands::Profile { command }) => match command {
            ProfileCommands::List => commands::profile::list(),
            ProfileCommands::Info { name } => commands::profile::info(&name),
            ProfileCommands::Delete { name, force } => commands::profile::delete(&name, force),
            ProfileCommands::Clean { profile } => commands::profile::clean(profile.as_deref()),
        },

        Some(Commands::Completion { shell }) => {
            let mut cmd = Cli::command();
            commands::completion::execute(shell, &mut cmd)
        }

        None => {
            // No file and no command - show help
            Cli::command().print_help()?;
            Ok(())
        }
    }
}

fn init_logging(verbose: bool) {
    use tracing_subscriber::EnvFilter;

    let filter = if verbose {
        EnvFilter::new("harrier=debug,harrier_core=debug,harrier_detectors=debug")
    } else {
        EnvFilter::new("harrier=info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .init();
}
