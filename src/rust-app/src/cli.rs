//! Command-line interface. Ports `src/cli/commands.py`.
//!
//! The CLI is a thin front-end over [`crate::workflow`]: it loads settings and
//! the input file, then translates workflow events to colored terminal output.

use clap::Parser;

use crate::config::load_settings;
use crate::domain::errors::AppError;
use crate::infra::file_reader::TextFileReader;
use crate::presentation::formatters as fmt;
use crate::workflow::{run_workflow, LogLevel, WorkflowConfig, WorkflowEvent};

/// Create Sophos Firewall host groups from network records.
#[derive(Parser)]
#[command(
    name = "sophos-firewall-manager",
    version = "2.0.0",
    about = "Create Sophos Firewall host groups from network records"
)]
struct Cli {
    /// Path to file with IP addresses, CIDR networks, and FQDNs (one per line)
    #[arg(short, long, value_name = "PATH")]
    file: String,

    /// Base name for host groups (suffixes are added automatically)
    #[arg(short, long, value_name = "NAME")]
    name: String,

    /// Add existing records to target groups (default: skip existing)
    #[arg(short, long)]
    update: bool,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// Print a markup string with ANSI rendering.
fn pline(markup: &str) {
    println!("{}", fmt::render_markup(markup));
}

/// Render a workflow event to the terminal.
fn print_event(event: WorkflowEvent) {
    match event {
        WorkflowEvent::Log { level, message } => {
            let markup = match level {
                LogLevel::Info => fmt::info(&message),
                LogLevel::Success => fmt::success(&message),
                LogLevel::Warning => fmt::warning(&message),
            };
            pline(&markup);
        }
        WorkflowEvent::Record(result) => pline(&fmt::format_result(&result)),
        WorkflowEvent::Summary(summary) => pline(&fmt::format_summary(&summary)),
    }
}

/// CLI entry point. Returns the process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();
    match execute(&cli) {
        Ok(code) => code,
        Err(err) => {
            let code = report_error(&err);
            if cli.verbose {
                pline(&fmt::info(&format!("Exited with status code {code}")));
            }
            code
        }
    }
}

/// Print the error the way `Application.run()` does and return its exit code.
fn report_error(err: &AppError) -> i32 {
    match err {
        AppError::File(_) => pline(&fmt::error(&format!("File error: {err}"))),
        AppError::FirewallIpRestriction(_) => {
            pline(&fmt::error(&format!("Access denied: {err}")));
            pline(&fmt::warning(
                "Your IP address is not allowed to access the firewall API.",
            ));
        }
        AppError::FirewallConnection(_)
        | AppError::FirewallAuthentication(_)
        | AppError::FirewallOperation { .. }
        | AppError::ResourceAlreadyExists(_) => {
            pline(&fmt::error(&format!("Firewall error: {err}")))
        }
        AppError::Configuration(_) => pline(&fmt::error(&format!("Configuration error: {err}"))),
        AppError::Validation(_) => pline(&fmt::error(&format!("Unexpected error: {err}"))),
    }
    err.exit_code()
}

/// Load settings + the input file, then run the workflow.
fn execute(cli: &Cli) -> Result<i32, AppError> {
    let (app_settings, firewall_settings) = load_settings()?;

    pline(&fmt::info(&format!("Loading records from: {}", cli.file)));
    let lines = TextFileReader::new(app_settings.file_encoding).read_lines(&cli.file)?;
    pline(&fmt::success(&format!("Loaded {} records\n", lines.len())));

    let config = WorkflowConfig {
        hostname: firewall_settings.hostname,
        username: firewall_settings.username,
        password: firewall_settings.password,
        port: firewall_settings.port,
        verify_ssl: firewall_settings.verify_ssl,
        base_name: cli.name.clone(),
        update_mode: cli.update,
    };

    run_workflow(&config, lines, &mut print_event)?;
    Ok(0)
}
