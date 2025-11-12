use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;

#[derive(Parser)]
#[command(name = "harrier")]
#[command(author, version, about, long_about = None)]
#[command(
    about = "CLI tool for working with HTTP Archive (HAR) files",
    long_about = "Harrier analyzes, filters, and modifies HAR files for security testing and API discovery."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format
    #[arg(short, long, global = true, default_value = "pretty")]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Display HAR file statistics
    Stats {
        /// HAR file to analyze
        #[arg(value_name = "FILE")]
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
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Host patterns (exact or glob like *.example.com)
        #[arg(long)]
        hosts: Vec<String>,

        /// Status codes (2xx, 404, 500-599, etc.)
        #[arg(long)]
        status: Option<String>,

        /// HTTP method (GET, POST, etc.)
        #[arg(long)]
        method: Option<String>,

        /// Content type pattern
        #[arg(long)]
        content_type: Option<String>,

        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Perform security analysis
    Security {
        /// HAR file to analyze
        #[arg(value_name = "FILE")]
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
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Show only API endpoints
        #[arg(long)]
        endpoints_only: bool,

        /// Generate OpenAPI spec
        #[arg(long)]
        openapi: bool,

        /// Output file for spec
        #[arg(short, long, requires = "openapi")]
        output: Option<PathBuf>,
    },

    /// Start MITM proxy to capture HAR traffic
    Proxy {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Output HAR file
        #[arg(short, long, default_value = "captured.har")]
        output: PathBuf,

        /// Certificate path (uses ~/.harrier/ca.crt if not specified)
        #[arg(long)]
        cert: Option<PathBuf>,

        /// Private key path (uses ~/.harrier/ca.key if not specified)
        #[arg(long)]
        key: Option<PathBuf>,
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
        } => commands::stats::execute(&file, timings, hosts, auth, verbose, &cli.format),
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
            &cli.format,
        ),
        Commands::Discover {
            file,
            endpoints_only,
            openapi,
            output,
        } => commands::discover::execute(&file, endpoints_only, openapi, output, &cli.format),
        Commands::Proxy {
            port,
            output,
            cert,
            key,
        } => commands::proxy::execute(port, &output, cert.as_deref(), key.as_deref()),
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
