//! Tauri desktop shell for the Sophos Firewall Manager.
//!
//! The UI supplies connection details and a dropped records file; this layer
//! reuses the `sfm` core crate unchanged and streams workflow events to the
//! front-end.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use sfm::infra::file_reader::TextFileReader;
use sfm::workflow::{run_workflow, WorkflowConfig, WorkflowEvent};

/// Run parameters sent from the UI.
#[derive(Deserialize)]
struct RunArgs {
    hostname: String,
    username: String,
    password: String,
    port: u16,
    verify_ssl: bool,
    base_name: String,
    update_mode: bool,
    /// Absolute path of the records file dropped onto the window.
    file_path: String,
}

/// A workflow event in a shape the front-end can render directly.
#[derive(Serialize, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum UiEvent {
    Log {
        level: String,
        message: String,
    },
    Record {
        value: String,
        record_type: String,
        status: String,
        status_code: String,
        message: String,
    },
    Summary {
        total: u64,
        successful: u64,
        updated: u64,
        already_exists: u64,
        failed: u64,
        skipped: u64,
        success_rate: f64,
    },
}

fn to_ui_event(event: WorkflowEvent) -> UiEvent {
    match event {
        WorkflowEvent::Log { level, message } => UiEvent::Log {
            level: level.as_str().to_string(),
            message,
        },
        WorkflowEvent::Record(result) => UiEvent::Record {
            value: result.record.value,
            record_type: result.record.record_type.as_str().to_string(),
            status: result.status.as_str().to_string(),
            status_code: result.status_code,
            message: result.message,
        },
        WorkflowEvent::Summary(summary) => UiEvent::Summary {
            total: summary.total,
            successful: summary.successful,
            updated: summary.updated,
            already_exists: summary.already_exists,
            failed: summary.failed,
            skipped: summary.skipped,
            success_rate: summary.success_rate(),
        },
    }
}

/// Read the dropped file and run the host-group workflow, streaming each event
/// to the front-end as a `workflow-event`.
///
/// The workflow performs blocking network I/O, so it runs on a blocking task
/// to keep the window responsive and let events stream live.
#[tauri::command]
async fn run_manager(app: AppHandle, args: RunArgs) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let lines = TextFileReader::new("utf-8")
            .read_lines(&args.file_path)
            .map_err(|e| e.to_string())?;

        let config = WorkflowConfig {
            hostname: args.hostname,
            username: args.username,
            password: args.password,
            port: args.port,
            verify_ssl: args.verify_ssl,
            base_name: args.base_name,
            update_mode: args.update_mode,
        };

        let mut on_event = |event: WorkflowEvent| {
            let _ = app.emit("workflow-event", to_ui_event(event));
        };

        run_workflow(&config, lines, &mut on_event).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![run_manager])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
