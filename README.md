# Sophos Firewall Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Equivalence: 233/233](https://img.shields.io/badge/equivalence-233%2F233-brightgreen.svg)](EQUIVALENCE.md)

Bulk-manage Sophos Firewall host groups from a file of network records — FQDNs,
IP addresses, and CIDR networks. The project ships **three interchangeable
front-ends over one behavior**, plus a differential harness that proves the
Python and Rust cores agree byte-for-byte.

## Repository layout

```
sophos-firewall-manager/
├── src/
│   ├── python-app/    # Python 3.12 CLI — the original implementation
│   ├── rust-app/      # Rust port of the CLI — verified byte-identical
│   └── desktop-app/   # Tauri + SolidJS desktop UI over the Rust core
├── equivalence/       # Differential harness: proves Python == Rust
├── vault/             # Sample record files (Microsoft 365, Teams, Zoom, …)
├── EQUIVALENCE.md     # What the harness verifies
├── LICENSE
└── README.md
```

## The three apps

| App | Path | Stack | Use it when |
|---|---|---|---|
| **Python CLI** | [`src/python-app`](src/python-app) | Python 3.12, Pydantic, Rich | Scripting, automation, cron jobs |
| **Rust CLI** | [`src/rust-app`](src/rust-app) | Rust 2021 | You want a single static binary, no runtime |
| **Desktop UI** | [`src/desktop-app`](src/desktop-app) | Tauri 2, SolidJS | No CLI flags, no `.env` — fill in a form |

Each app has its own README with detailed build and run instructions.

## Quick start

Pick one app and follow its README:

**Python CLI** — [`src/python-app/README.md`](src/python-app/README.md)

```bash
cd src/python-app
uv sync
uv run main.py -f hosts.txt -n Production
```

**Rust CLI** — [`src/rust-app/README.md`](src/rust-app/README.md)

```bash
cd src/rust-app
cargo run --release --bin sophos-firewall-manager -- -f hosts.txt -n Production
```

**Desktop UI** — [`src/desktop-app/README.md`](src/desktop-app/README.md)

```bash
cd src/desktop-app
npm install
npm run tauri dev
```

The two CLIs read firewall credentials from a `.env` file (`FIREWALL_` prefix);
the desktop app takes them in the window.

## How it works

All three apps perform the same workflow:

1. Read a file of network records, one per line.
2. Classify each record — CIDR → IP address → FQDN.
3. Create two host groups: `{NAME}_FQDNHostGroup` and `{NAME}_IPHostGroup`.
4. Fetch existing records once, then create only the genuinely new ones.
5. Report a per-record result and a final summary.

## Equivalence

The Python and Rust cores are not just "similar" — every pure-logic surface is
checked input-for-input by the harness in [`equivalence/`](equivalence):

```bash
src/python-app/.venv/Scripts/python.exe equivalence/compare.py
```

**Current status: 233 / 233 cases identical across 19 categories.** See
[`EQUIVALENCE.md`](EQUIVALENCE.md) for exactly what is — and isn't — covered.

## Contributing

1. Fork the repository and create a feature branch.
2. Make changes with tests; keep the relevant app's checks green
   (`pytest` / `cargo test`).
3. If you touch shared logic, run `equivalence/compare.py` and keep it at
   233/233.
4. Use [Conventional Commits](https://www.conventionalcommits.org)
   (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
5. Open a pull request.

## License

MIT — see [LICENSE](LICENSE).
