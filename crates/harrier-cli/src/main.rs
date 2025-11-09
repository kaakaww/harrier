use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;

#[derive(Parser)]
#[command(name = "harrier")]
#[command(author, version, about, long_about = None)]
#[command(
    about = "A CLI tool for collecting, analyzing, and modifying HTTP Archive (HAR) files",
    long_about = "Harrier helps you work with HAR files by providing tools to analyze traffic, \
                  detect security patterns, discover APIs, and capture new HAR files via proxy or browser."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format (json, table, pretty)
    #[arg(short, long, global = true, default_value = "pretty")]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Display HAR file statistics
    Stats {
        /// Path to the HAR file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Include detailed timing information
        #[arg(long)]
        timings: bool,

        /// Show all hosts with request counts
        #[arg(long)]
        hosts: bool,
    },

    /// Filter HAR entries by various criteria
    Filter {
        /// Path to the HAR file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Filter by domain pattern
        #[arg(long)]
        domain: Option<String>,

        /// Filter by HTTP status code (supports ranges like 2xx, 404, etc.)
        #[arg(long)]
        status: Option<String>,

        /// Filter by HTTP method (GET, POST, etc.)
        #[arg(long)]
        method: Option<String>,

        /// Filter by content type pattern
        #[arg(long)]
        content_type: Option<String>,

        /// Output filtered HAR to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Perform security analysis
    Security {
        /// Path to the HAR file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Check for authentication patterns
        #[arg(long)]
        check_auth: bool,

        /// Scan for sensitive data
        #[arg(long)]
        find_sensitive: bool,

        /// Only show insecure requests
        #[arg(long)]
        insecure_only: bool,
    },

    /// Discover APIs and detect application types
    Discover {
        /// Path to the HAR file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Only show API endpoints
        #[arg(long)]
        endpoints_only: bool,

        /// Generate OpenAPI spec (if possible)
        #[arg(long)]
        openapi: bool,

        /// Output file for OpenAPI spec
        #[arg(short, long, requires = "openapi")]
        output: Option<PathBuf>,
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
        } => commands::stats::execute(&file, timings, hosts, &cli.format),
        Commands::Filter {
            file,
            domain,
            status,
            method,
            content_type,
            output,
        } => commands::filter::execute(&file, domain, status, method, content_type, output),
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
        .init();
}
