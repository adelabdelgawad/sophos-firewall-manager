# Sophos Firewall Manager — Python CLI

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

The original Python implementation of Sophos Firewall Manager — a CLI tool that
bulk-creates Sophos Firewall host groups from a file of network records (FQDNs,
IP addresses, and CIDR networks). Built with clean-architecture layering, strict
typing, and Pydantic validation.

> Part of the [Sophos Firewall Manager](../../README.md) monorepo. A
> behavior-identical [Rust port](../rust-app) and [desktop UI](../desktop-app)
> live alongside it — see [`EQUIVALENCE.md`](../../EQUIVALENCE.md).

## Requirements

- Python 3.12 or higher
- Access to a Sophos Firewall with the API enabled
- API credentials with permission to manage host groups

## Installation

All commands below are run from this directory (`src/python-app/`).

### Using uv (recommended)

```bash
cd src/python-app
uv sync
```

### Using pip

```bash
cd src/python-app
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

Copy the example environment file and fill in your firewall details:

```bash
cp .env.example .env
```

```bash
FIREWALL_HOSTNAME=firewall.example.com
FIREWALL_USERNAME=admin
FIREWALL_PASSWORD=your_secure_password
FIREWALL_PORT=4444
FIREWALL_VERIFY_SSL=false
```

Settings are loaded by Pydantic `BaseSettings` (the `FIREWALL_` prefix) and
cached via `get_settings()` in `config/settings.py`.

## Usage

```bash
# Create host groups from a records file
uv run main.py -f hosts.txt -n Production

# Verbose output
uv run main.py -f hosts.txt -n Production -v

# Update mode: add already-existing records to the target groups
uv run main.py -f hosts.txt -n Production -u
```

| Option | Description |
|---|---|
| `-f, --file PATH` | File of network records, one per line (required) |
| `-n, --name NAME` | Base name for the host groups (required) |
| `-u, --update` | Add existing records to groups instead of skipping them |
| `-v, --verbose` | Enable verbose output |

Each run creates two groups: `{NAME}_FQDNHostGroup` and `{NAME}_IPHostGroup`.

### Input file format

One record per line; blank lines are ignored.

```text
example.com
*.example.com
192.168.1.10
2001:db8::1
10.0.0.0/8
```

## Supported record types

| Type | Format | Example |
|---|---|---|
| FQDN | Domain name | `example.com`, `*.example.com` |
| IPv4 / IPv6 address | Single IP | `192.168.1.1`, `2001:db8::1` |
| IPv4 / IPv6 network | CIDR notation | `10.0.0.0/8`, `2001:db8::/32` |

## Architecture

Clean Architecture with four layers, under `src/`:

| Layer | Responsibility |
|---|---|
| `domain/` | Entities, validators, exceptions — no external dependencies |
| `infrastructure/` | `firewall_client.py` (Sophos API), `file_reader.py` |
| `services/` | `group_service.py`, `record_service.py`, `cache_service.py` |
| `presentation/` | `formatters.py` (Rich output), `progress.py` |
| `cli/` | `commands.py` — the CLI entry point |

Records are classified in priority order: CIDR → IP address → FQDN. Existing
records are fetched once and cached, so a run only creates what is genuinely
new.

## Development

```bash
black src tests        # format
ruff check src tests   # lint
mypy src               # type-check (strict)
pytest                 # run the test suite
pytest --cov=src --cov-report=term-missing   # with coverage
```

## License

MIT — see [LICENSE](../../LICENSE).
