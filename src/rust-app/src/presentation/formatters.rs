//! Output formatting for terminal display. Ports `src/presentation/formatters.py`.
//!
//! Formatter functions return Rich-style markup strings (e.g. `[green]ok[/green]`)
//! exactly as the Python code does. `render_markup` converts that markup to ANSI
//! escape codes at the point of printing.

use crate::domain::entities::{OperationResult, OperationStatus, ProcessingSummary};

// Color marker templates (ASCII-safe), matching `ColorFormatter`.
pub const SUCCESS: &str = "[green]+[/green]";
pub const ERROR: &str = "[red]x[/red]";
pub const WARNING: &str = "[yellow]![/yellow]";
pub const INFO: &str = "[blue]i[/blue]";

/// Wrap a message in green markup.
pub fn success(message: &str) -> String {
    format!("[green]{message}[/green]")
}

/// Wrap a message in red markup.
pub fn error(message: &str) -> String {
    format!("[red]{message}[/red]")
}

/// Wrap a message in yellow markup.
pub fn warning(message: &str) -> String {
    format!("[yellow]{message}[/yellow]")
}

/// Wrap a message in blue markup.
pub fn info(message: &str) -> String {
    format!("[blue]{message}[/blue]")
}

/// Format a single operation result, matching `OperationResultFormatter`.
pub fn format_result(result: &OperationResult) -> String {
    let value = &result.record.value;
    let message = &result.message;
    match result.status {
        OperationStatus::Success | OperationStatus::Updated => {
            format!("{SUCCESS} {value}: {message}")
        }
        OperationStatus::AlreadyExists => format!("{WARNING} {value}: {message}"),
        OperationStatus::Skipped => format!("{WARNING} {value}: Skipped (invalid format)"),
        OperationStatus::Failed => format!("{ERROR} {value}: {message}"),
    }
}

/// Format a processing summary, matching `SummaryFormatter`.
pub fn format_summary(summary: &ProcessingSummary) -> String {
    let bar = "=".repeat(60);
    let lines = [
        format!("\n{bar}"),
        info("Processing Summary"),
        bar.clone(),
        format!("Total records: {}", summary.total),
        format!("{SUCCESS} Created: {}", summary.successful),
        format!("{SUCCESS} Updated: {}", summary.updated),
        format!("{WARNING} Already existed: {}", summary.already_exists),
        format!("{ERROR} Failed: {}", summary.failed),
        format!("{WARNING} Skipped: {}", summary.skipped),
        format!("\nSuccess rate: {:.1}%", summary.success_rate()),
        bar,
    ];
    lines.join("\n")
}

/// Format a group creation result, matching `GroupCreationFormatter`.
pub fn format_group(group_name: &str, created: bool) -> String {
    if created {
        format!("{SUCCESS} Created group: {group_name}")
    } else {
        format!("{WARNING} Group already exists: {group_name}")
    }
}

/// Convert Rich-style color markup into ANSI escape codes for terminal output.
pub fn render_markup(text: &str) -> String {
    text.replace("[green]", "\x1b[32m")
        .replace("[red]", "\x1b[31m")
        .replace("[yellow]", "\x1b[33m")
        .replace("[blue]", "\x1b[34m")
        .replace("[/green]", "\x1b[0m")
        .replace("[/red]", "\x1b[0m")
        .replace("[/yellow]", "\x1b[0m")
        .replace("[/blue]", "\x1b[0m")
}
