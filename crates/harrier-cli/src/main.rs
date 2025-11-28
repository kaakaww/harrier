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
    long_about = "Harrier analyzes, filters, and modifies HAR files for security testing and API discovery."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format
    #[arg(short, long, global = true, default_value_t = OutputFormat::Pretty, value_enum)]
    format: OutputFormat,
}

#[derive(Subcommand)]
enum Commands {
    /// Display HAR file statistics
    Stats {
        /// HAR file to analyze
        #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
        file: PathBuf,

        /// Show detailed timing info
        #[arg(long)]
        timings: bool,

        /// Show all hosts with request counts
        #[arg(long)]
        hosts: bool,

        /// Show authentication analysis
        #[arg(long)]
        auth: bool,

        /// Show all details
        #[arg(short, long)]
        verbose: bool,
    },

    /// Filter HAR entries by criteria
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

    /// Perform security analysis
    Security {
        /// HAR file to analyze
        #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
        file: PathBuf,

        /// Check authentication patterns
        #[arg(long)]
        check_auth: bool,

        /// Scan for sensitive data
        #[arg(long)]
        find_sensitive: bool,

        /// Show only insecure requests
        #[arg(long)]
        insecure_only: bool,
    },

    /// Discover APIs and app types
    Discover {
        /// HAR file to analyze
        #[arg(value_name = "FILE", value_hint = ValueHint::FilePath)]
        file: PathBuf,

        /// Show only API endpoints
        #[arg(long)]
        endpoints_only: bool,

        /// Generate OpenAPI spec
        #[arg(long)]
        openapi: bool,

        /// Output file for spec
        #[arg(short, long, requires = "openapi", value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },

    /// Start MITM proxy to capture HAR traffic
    Proxy {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Output HAR file
        #[arg(short, long, default_value = "captured.har", value_hint = ValueHint::FilePath)]
        output: PathBuf,

        /// Certificate path (uses ~/.harrier/ca.crt if not specified)
        #[arg(long, value_hint = ValueHint::FilePath)]
        cert: Option<PathBuf>,

        /// Private key path (uses ~/.harrier/ca.key if not specified)
        #[arg(long, value_hint = ValueHint::FilePath)]
        key: Option<PathBuf>,
    },

    /// Launch Chrome and capture HAR traffic
    Chrome {
        /// Output HAR file
        #[arg(short, long, default_value = "chrome-capture.har", value_hint = ValueHint::FilePath)]
        output: PathBuf,

        /// Filter to specific hosts (supports globs, repeatable)
        #[arg(long, value_hint = ValueHint::Hostname)]
        hosts: Vec<String>,

        /// Print HawkScan configuration guidance after capture
        #[arg(long)]
        hawkscan: bool,

        /// Override Chrome binary location
        #[arg(long, value_hint = ValueHint::FilePath)]
        chrome_path: Option<PathBuf>,

        /// Starting URL to navigate to
        #[arg(long, value_hint = ValueHint::Url)]
        url: Option<String>,

        /// Use named persistent profile at ~/.harrier/profiles/<NAME>
        #[arg(long, value_hint = ValueHint::Other)]
        profile: Option<String>,

        /// Use temporary profile (auto-deleted after use)
        #[arg(long)]
        temp: bool,
    },

    /// Manage Chrome profiles
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

    // Execute the command
    match cli.command {
        Commands::Stats {
            file,
            timings,
            hosts,
            auth,
            verbose,
        } => commands::stats::execute(&file, timings, hosts, auth, verbose, cli.format),
        Commands::Filter {
            file,
            hosts,
            status,
            method,
            content_type,
            output,
        } => commands::filter::execute(&file, hosts, status, method, content_type, output),
        Commands::Security {
            file,
            check_auth,
            find_sensitive,
            insecure_only,
        } => commands::security::execute(
            &file,
            check_auth,
            find_sensitive,
            insecure_only,
            cli.format,
        ),
        Commands::Discover {
            file,
            endpoints_only,
            openapi,
            output,
        } => commands::discover::execute(&file, endpoints_only, openapi, output, cli.format),
        Commands::Proxy {
            port,
            output,
            cert,
            key,
        } => commands::proxy::execute(port, &output, cert.as_deref(), key.as_deref()),
        Commands::Chrome {
            output,
            hosts,
            hawkscan,
            chrome_path,
            url,
            profile,
            temp,
        } => commands::chrome::execute(&output, hosts, hawkscan, chrome_path, url, profile, temp),
        Commands::Profile { command } => match command {
            ProfileCommands::List => commands::profile::list(),
            ProfileCommands::Info { name } => commands::profile::info(&name),
            ProfileCommands::Delete { name, force } => commands::profile::delete(&name, force),
            ProfileCommands::Clean { profile } => commands::profile::clean(profile.as_deref()),
        },
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            commands::completion::execute(shell, &mut cmd)
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
