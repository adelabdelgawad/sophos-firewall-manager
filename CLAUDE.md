# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sophos Firewall Manager is a Python 3.12+ CLI tool for bulk managing Sophos Firewall host groups from network records. It follows Clean Architecture principles with strict type safety and uses Pydantic for validation.

## Essential Commands

```bash
# Run the application
uv run main.py -f hosts.txt -n Production
uv run main.py -f hosts.txt -n Production -v  # verbose

# Development
black src tests                    # format
ruff check src tests               # lint
mypy src                           # type check
pytest                             # test
pytest tests/unit/test_validators.py  # single test file
pytest --cov=src --cov-report=html    # coverage

# Dependencies
uv sync                            # install (recommended)
uv pip install -r requirements.txt # alternative
```

## Architecture

Clean Architecture with four layers:

- **domain/**: Core business logic, no external dependencies. Contains `entities.py` (immutable value objects), `validators.py` (LRU-cached validation), `exceptions.py`
- **infrastructure/**: External integrations - `firewall_client.py` (Sophos API), `file_reader.py`
- **services/**: Orchestration - `group_service.py`, `record_service.py`
- **presentation/**: UI - `formatters.py` (Rich output), `progress.py`
- **cli/**: Entry point - `commands.py`

### Key Patterns

- **Value Objects**: `NetworkRecord` is immutable (`@dataclass(frozen=True)`)
- **Strategy Pattern**: `RecordClassifier` uses ordered validators (CIDR → IP → FQDN)
- **LRU Caching**: All validators use `@lru_cache(maxsize=1024)`
- **Dependency Injection**: Services receive dependencies via constructor

## Configuration

Required `.env` file:

```bash
FIREWALL_HOSTNAME=firewall.example.com
FIREWALL_USERNAME=admin
FIREWALL_PASSWORD=secure_password
FIREWALL_PORT=4444
FIREWALL_VERIFY_SSL=false
```

Settings use Pydantic `BaseSettings` with `FIREWALL_` prefix, cached via `get_settings()` in `config/settings.py`.

## Code Style

- **Strict typing**: All functions require type hints, must pass mypy strict
- **Naming**: `snake_case` for Python (classes: `PascalCase`, constants: `UPPER_SNAKE_CASE`)
- Use `Protocol` for interfaces, `@dataclass` for entities, `Enum` for status types

## Validation Order

Records classified in this priority (see `RecordClassifier._validators`):
1. `NetworkCIDRValidator` - checks for `/` first
2. `IPAddressValidator` - Pydantic IPvAnyAddress
3. `FQDNValidator` - RFC 1035/3696 compliant

## Extension Points

- **New validator**: Add class in `domain/validators.py` with `@lru_cache`, add to `RecordClassifier._validators` tuple
- **New record type**: Extend `RecordType` enum, add corresponding validator
- **New exception**: Define in `domain/exceptions.py`, add handler in `Application.run()` in `cli/commands.py`
