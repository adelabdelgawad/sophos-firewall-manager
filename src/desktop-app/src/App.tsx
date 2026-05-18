import { createSignal, For, Show, onMount, onCleanup } from "solid-js";
import { createStore } from "solid-js/store";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";

// --- Event types emitted by the Rust backend --------------------------------

type LogEvent = { kind: "log"; level: string; message: string };
type RecordEvent = {
  kind: "record";
  value: string;
  record_type: string;
  status: string;
  status_code: string;
  message: string;
};
type SummaryEvent = {
  kind: "summary";
  total: number;
  successful: number;
  updated: number;
  already_exists: number;
  failed: number;
  skipped: number;
  success_rate: number;
};
type WorkflowEvent = LogEvent | RecordEvent | SummaryEvent;
type Entry = LogEvent | RecordEvent;

function baseName(path: string): string {
  const parts = path.split(/[/\\]/);
  return parts[parts.length - 1] || path;
}

export default function App() {
  // Connection details — entered in the UI, no .env file.
  const [hostname, setHostname] = createSignal("");
  const [port, setPort] = createSignal("4444");
  const [username, setUsername] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [verifySsl, setVerifySsl] = createSignal(false);

  // Run parameters.
  const [baseGroupName, setBaseGroupName] = createSignal("");
  const [updateMode, setUpdateMode] = createSignal(false);
  const [filePath, setFilePath] = createSignal("");

  // Run state.
  const [running, setRunning] = createSignal(false);
  const [dragging, setDragging] = createSignal(false);
  const [error, setError] = createSignal("");
  const [entries, setEntries] = createStore<Entry[]>([]);
  const [summary, setSummary] = createSignal<SummaryEvent | null>(null);

  let unlistenEvent: UnlistenFn | undefined;
  let unlistenDrop: UnlistenFn | undefined;

  onMount(async () => {
    unlistenEvent = await listen<WorkflowEvent>("workflow-event", (event) => {
      const payload = event.payload;
      if (payload.kind === "summary") {
        setSummary(payload);
      } else {
        setEntries(entries.length, payload);
      }
    });

    unlistenDrop = await getCurrentWebview().onDragDropEvent((event) => {
      const payload = event.payload as { type: string; paths?: string[] };
      if (payload.type === "over" || payload.type === "enter") {
        setDragging(true);
      } else if (payload.type === "drop") {
        setDragging(false);
        if (payload.paths && payload.paths.length > 0) {
          setFilePath(payload.paths[0]);
          setError("");
        }
      } else {
        setDragging(false);
      }
    });
  });

  onCleanup(() => {
    unlistenEvent?.();
    unlistenDrop?.();
  });

  function canRun(): boolean {
    return (
      !running() &&
      hostname().trim() !== "" &&
      username().trim() !== "" &&
      password() !== "" &&
      baseGroupName().trim() !== "" &&
      filePath() !== ""
    );
  }

  async function run() {
    if (!canRun()) {
      setError("Fill in the connection details, a group name, and drop a records file.");
      return;
    }
    setError("");
    setEntries([]);
    setSummary(null);
    setRunning(true);
    try {
      await invoke("run_manager", {
        args: {
          hostname: hostname().trim(),
          username: username().trim(),
          password: password(),
          port: Number(port()) || 4444,
          verify_ssl: verifySsl(),
          base_name: baseGroupName().trim(),
          update_mode: updateMode(),
          file_path: filePath(),
        },
      });
    } catch (err) {
      setError(String(err));
    } finally {
      setRunning(false);
    }
  }

  return (
    <main class="app">
      <header class="header">
        <h1>Sophos Firewall Manager</h1>
        <p>Bulk-create host groups from a records file — no CLI, no .env.</p>
      </header>

      <div class="grid">
        <section class="panel">
          <h2>Firewall Connection</h2>
          <label>
            Hostname / IP
            <input
              type="text"
              placeholder="firewall.example.com"
              value={hostname()}
              onInput={(e) => setHostname(e.currentTarget.value)}
            />
          </label>
          <div class="row">
            <label class="grow">
              Username
              <input
                type="text"
                placeholder="admin"
                value={username()}
                onInput={(e) => setUsername(e.currentTarget.value)}
              />
            </label>
            <label class="port">
              Port
              <input
                type="number"
                value={port()}
                onInput={(e) => setPort(e.currentTarget.value)}
              />
            </label>
          </div>
          <label>
            Password
            <input
              type="password"
              placeholder="********"
              value={password()}
              onInput={(e) => setPassword(e.currentTarget.value)}
            />
          </label>
          <label class="check">
            <input
              type="checkbox"
              checked={verifySsl()}
              onChange={(e) => setVerifySsl(e.currentTarget.checked)}
            />
            Verify SSL certificate
          </label>
        </section>

        <section class="panel">
          <h2>Host Groups</h2>
          <label>
            Base group name
            <input
              type="text"
              placeholder="Production"
              value={baseGroupName()}
              onInput={(e) => setBaseGroupName(e.currentTarget.value)}
            />
          </label>
          <p class="hint">
            Creates <code>{(baseGroupName() || "Name")}_FQDNHostGroup</code> and{" "}
            <code>{(baseGroupName() || "Name")}_IPHostGroup</code>.
          </p>
          <label class="check">
            <input
              type="checkbox"
              checked={updateMode()}
              onChange={(e) => setUpdateMode(e.currentTarget.checked)}
            />
            Update mode (add existing records to groups)
          </label>

          <div
            class={`dropzone ${dragging() ? "dragging" : ""} ${
              filePath() ? "has-file" : ""
            }`}
          >
            <Show
              when={filePath()}
              fallback={<span>Drop a records file (.txt) here</span>}
            >
              <span class="file-name">{baseName(filePath())}</span>
              <button class="link" onClick={() => setFilePath("")}>
                clear
              </button>
            </Show>
          </div>
        </section>
      </div>

      <div class="actions">
        <button class="run" disabled={!canRun()} onClick={run}>
          {running() ? "Running..." : "Run"}
        </button>
        <Show when={error()}>
          <span class="error-msg">{error()}</span>
        </Show>
      </div>

      <section class="panel output">
        <h2>Activity</h2>
        <Show
          when={entries.length > 0}
          fallback={<p class="hint">Results will stream here once you run.</p>}
        >
          <div class="log">
            <For each={entries}>
              {(entry) =>
                entry.kind === "log" ? (
                  <div class={`log-line level-${entry.level}`}>{entry.message}</div>
                ) : (
                  <div class="record-line">
                    <span class={`badge status-${entry.status}`}>{entry.status}</span>
                    <span class="record-value">{entry.value}</span>
                    <span class="record-msg">{entry.message}</span>
                  </div>
                )
              }
            </For>
          </div>
        </Show>

        <Show when={summary()}>
          {(s) => (
            <div class="summary">
              <h3>Summary</h3>
              <div class="stats">
                <Stat label="Total" value={s().total} />
                <Stat label="Created" value={s().successful} tone="ok" />
                <Stat label="Updated" value={s().updated} tone="ok" />
                <Stat label="Existed" value={s().already_exists} tone="warn" />
                <Stat label="Failed" value={s().failed} tone="bad" />
                <Stat label="Skipped" value={s().skipped} tone="warn" />
              </div>
              <p class="rate">Success rate: {s().success_rate.toFixed(1)}%</p>
            </div>
          )}
        </Show>
      </section>
    </main>
  );
}

function Stat(props: { label: string; value: number; tone?: string }) {
  return (
    <div class={`stat ${props.tone ?? ""}`}>
      <span class="stat-value">{props.value}</span>
      <span class="stat-label">{props.label}</span>
    </div>
  );
}
