# Sophos Firewall Manager — Rust core

A Rust port of the Python application in [`../python-app`](../python-app). It
keeps the same clean-architecture layering and is verified to produce identical
results to the Python code (see [`../../EQUIVALENCE.md`](../../EQUIVALENCE.md)).

## Layout

| Module | Responsibility |
|---|---|
| `domain/` | Entities, validators, error types — no external dependencies |
| `infra/` | File reading, XML parsing, the Sophos Firewall HTTP client |
| `services/` | Host-group and record-processing orchestration |
| `presentation/` | Output formatting |
| `workflow.rs` | The end-to-end workflow, shared by the CLI and the desktop UI |
| `cli.rs` | Command-line front-end |

`workflow::run_workflow` is the single orchestration entry point; both the CLI
(`src/main.rs`) and the Tauri UI (`../desktop-app`) call into it.

## Build and run

```bash
cargo build --release

# Same arguments as the Python CLI; settings come from a .env file.
cargo run --release --bin sophos-firewall-manager -- -f hosts.txt -n Production
```

Configuration (`.env`, `FIREWALL_` prefix):

```bash
FIREWALL_HOSTNAME=firewall.example.com
FIREWALL_USERNAME=admin
FIREWALL_PASSWORD=secret
FIREWALL_PORT=4444
FIREWALL_VERIFY_SSL=false
```

The desktop UI ([`../desktop-app`](../desktop-app)) needs no
`.env` — connection details are entered in the window.

## Test

```bash
cargo test                        # unit + service-layer tests
python ../../equivalence/compare.py   # differential check against the Python app
```

The `oracle` binary (`src/bin/oracle.rs`) exists only for the equivalence
harness.
