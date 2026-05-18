# Sophos Firewall Manager — Desktop UI

A [Tauri 2](https://tauri.app) + [SolidJS](https://www.solidjs.com) desktop app
that wraps the Rust core in [`../rust-app`](../rust-app). It does everything the CLI
does, but without command-line flags or a `.env` file:

- Enter the **firewall connection details** (host, port, user, password,
  verify-SSL) directly in the window.
- **Drop a records file** (`.txt`, one IP / CIDR / FQDN per line) onto the app.
- Enter the **base group name**, optionally enable **update mode**, and click
  **Run**.
- Watch each step and per-record result stream into the activity log, then read
  the final summary card.

The UI reuses the exact same `sfm::workflow::run_workflow` as the CLI, so the
behavior is identical — only the input and output surfaces differ.

## Prerequisites

- [Rust](https://rustup.rs) (stable) and [Node.js](https://nodejs.org) 18+.
- The Tauri 2 system dependencies for your platform (WebView2 is preinstalled
  on Windows 11). See <https://tauri.app/start/prerequisites/>.

## Develop

```bash
cd src/desktop-app
npm install
npm run tauri dev
```

`tauri dev` starts the Vite dev server and opens the desktop window with hot
reload.

## Build a release bundle

```bash
npm run tauri build
```

The installer / executable is written under `src-tauri/target/release/`.

## How it is wired

| Layer | Location |
|---|---|
| UI (form, drop zone, streaming log) | `src/App.tsx` |
| Tauri command `run_manager` | `src-tauri/src/lib.rs` |
| Workflow + firewall logic | `../rust-app` (`sfm` crate, unchanged) |

The backend command reads the dropped file with the core `TextFileReader`,
calls `run_workflow`, and emits each `WorkflowEvent` to the front-end as a
`workflow-event`. All validation stays in Rust — the UI never re-implements it.
