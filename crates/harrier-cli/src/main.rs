use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::Shell;
use harrier_cli::{OutputFormat, commands};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "harrier")]
#[command(author, version, about, long_about = None)]
#[command(
    about = "CLI tool for working with HTTP Archive (HAR) files",
    long_about = "Harrier analyzes, filters, and captures HAR files for security testing and API discovery.\n\n\
                  Quick start: harrier <file.har> for a summary of any HAR file.",
    after_help = "EXAMPLES:\n  \
        harrier app.har                              Quick summary\n  \
        harrier capture --url https://example.com    Capture with Chrome\n  \
        harrier analyze app.har --all                Full analysis\n  \
        harrier export app.har --hawkscan            Generate HawkScan config\n\n\
        Documentation: https://github.com/kaakaww/harrier"
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

    /// Output format
    #[arg(short, long, global = true, default_value_t = OutputFormat::Pretty, value_enum)]
    format: OutputFormat,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze HAR for security, auth, APIs, and architecture
    #[command(
        long_about = "Analyze a HAR file for security issues, authentication patterns, API types, and host architecture.\n\n\
                      By default, shows a summary. Use --focus to analyze specific areas, or --all for everything."
    )]
    Analyze {
        /// HAR file to analyze
        #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
        file: PathBuf,

        /// Focus on specific analysis areas (can be repeated)
        #[arg(long, value_enum)]
        focus: Vec<commands::analyze::Focus>,

        /// Run all analysis types
        #[arg(long)]
        all: bool,

        /// Scope analysis to specific host
        #[arg(long, value_hint = ValueHint::Hostname)]
        host: Option<String>,
    },

    /// Capture HTTP traffic via browser or proxy
    #[command(long_about = "Capture HTTP traffic to generate HAR files.\n\n\
                      By default, uses Chrome with DevTools Protocol (recommended for SPAs and sites requiring login).\n\
                      Use --proxy to start a MITM proxy instead (better for mobile apps and any HTTP client).")]
    Capture {
        /// Use MITM proxy instead of browser
        #[arg(long)]
        proxy: bool,

        /// Output HAR file
        #[arg(short, long, default_value = "captured.har", value_hint = ValueHint::FilePath)]
        output: PathBuf,

        /// Filter captured traffic to specific hosts (supports globs, repeatable)
        #[arg(long, value_hint = ValueHint::Hostname)]
        hosts: Vec<String>,

        /// Show HawkScan guidance after capture
        #[arg(long)]
        hawkscan: bool,

        // Browser-specific options
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

        // Proxy-specific options
        /// Port to listen on (proxy mode)
        #[arg(short = 'p', long, default_value = "8080")]
        port: u16,

        /// Custom CA certificate path (proxy mode)
        #[arg(long, value_hint = ValueHint::FilePath)]
        cert: Option<PathBuf>,

        /// Custom CA private key path (proxy mode)
        #[arg(long, value_hint = ValueHint::FilePath)]
        key: Option<PathBuf>,
    },

    /// Generate configs and reports from HAR data
    #[command(long_about = "Export HAR analysis to various formats.\n\n\
                      Currently supports HawkScan configuration generation.")]
    Export {
        /// HAR file to export from
        #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
        file: PathBuf,

        /// Generate HawkScan YAML configuration
        #[arg(long)]
        hawkscan: bool,

        /// Scope export to specific host
        #[arg(long, value_hint = ValueHint::Hostname)]
        host: Option<String>,

        /// Include all hosts (even non-scannable ones)
        #[arg(long)]
        all_hosts: bool,

        /// Write output to file
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },

    /// Filter HAR entries by criteria
    #[command(
        long_about = "Filter HAR file entries by host, status code, method, or content type.\n\n\
                      Outputs filtered HAR to stdout (or file with -o)."
    )]
    Filter {
        /// HAR file to filter
        #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
        file: PathBuf,

        /// Host patterns (exact or glob like *.example.com)
        #[arg(long, value_hint = ValueHint::Hostname)]
        hosts: Vec<String>,

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

    /// Generate shell completion scripts
    #[command(long_about = "Generate shell completion scripts for your shell.\n\n\
                     USAGE:\n  \
                     harrier completion --shell <SHELL>\n\n\
                     SUPPORTED SHELLS:\n  \
                     bash, zsh, fish, powershell\n\n\
                     INSTALLATION:\n\n\
                     Bash:\n  \
                     Add to ~/.bashrc:\n    \
                     echo 'source <(harrier completion --shell bash)' >> ~/.bashrc\n    \
                     source ~/.bashrc\n\n\
                     Zsh:\n  \
                     Add to ~/.zshrc:\n    \
                     echo 'source <(harrier completion --shell zsh)' >> ~/.zshrc\n    \
                     source ~/.zshrc\n\n\
                     Fish:\n  \
                     Save to completion directory:\n    \
                     harrier completion --shell fish > ~/.config/fish/completions/harrier.fish\n\n\
                     PowerShell:\n  \
                     Add to your PowerShell profile:\n    \
                     harrier completion --shell powershell >> $PROFILE\n    \
                     Then restart PowerShell or run: . $PROFILE")]
    Completion {
        /// Shell to generate completions for
        #[arg(long, value_enum, required = true)]
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
        /// Specific profile to clean (cleans all if not specified)
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
        }) => commands::analyze::execute(&file, focus, all, host.as_deref(), cli.format),

        Some(Commands::Capture {
            proxy,
            output,
            hosts,
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
                hosts,
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
                host.as_deref(),
                all_hosts,
                output,
                cli.format,
            )
        }

        Some(Commands::Filter {
            file,
            hosts,
            status,
            method,
            content_type,
            output,
        }) => commands::filter::execute(
            &file,
            hosts,
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
