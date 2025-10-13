# Sophos Firewall Manager

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A modern, production-ready CLI tool for bulk managing Sophos Firewall host groups from network records. Built with clean architecture principles, full type safety, and comprehensive error handling.

## ✨ Features

- 🏗️ **Clean Architecture** - Organized in layers with clear separation of concerns
- 🔒 **Type Safe** - Full type hints with mypy strict mode compliance
- ✅ **Validated** - Pydantic models for settings and data validation
- 📊 **Rich UI** - Beautiful terminal output with progress bars
- 🎨 **Colored Output** - Clear, colorful feedback for all operations
- ⚡ **Performance** - LRU caching for validators
- 🔧 **Configurable** - Environment-based configuration
- 🛡️ **Resilient** - Continues processing even when records already exist

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Supported Record Types](#supported-record-types)
- [Architecture](#architecture)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## 🚀 Installation

### Prerequisites

- Python 3.11 or higher
- Access to a Sophos Firewall with API enabled
- API credentials with appropriate permissions

### Option 1: Using UV (Recommended - Fast!)

[UV](https://github.com/astral-sh/uv) is an extremely fast Python package installer.

```bash
# Install UV if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/adelabdelgawad/sophos-firewall-manager.git
cd sophos-firewall-manager

# Install dependencies
uv pip install -r requirements.txt

# Run directly with UV
uv run main.py -f hosts.txt -n Production
```

### Option 2: Using pip

```bash
# Clone the repository
git clone https://github.com/adelabdelgawad/sophos-firewall-manager.git
cd sophos-firewall-manager

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py -f hosts.txt -n Production
```

### Option 3: Using Poetry

```bash
# Clone the repository
git clone https://github.com/adelabdelgawad/sophos-firewall-manager.git
cd sophos-firewall-manager

# Install dependencies
poetry install

# Run the application
poetry run python main.py -f hosts.txt -n Production
```

## ⚡ Quick Start

1. **Create a `.env` file** with your firewall credentials:

```bash
cp .env.example .env
# Edit .env with your credentials
```

2. **Prepare your input file** (`hosts.txt`):

```text
example.com
api.example.com
192.168.1.10
10.0.0.0/8
172.16.0.0/12
2001:db8::1
```

3. **Run the tool**:

```bash
# Using UV (recommended)
uv run main.py -f hosts.txt -n Production

# Using Python directly
python main.py -f hosts.txt -n Production

# Using Poetry
poetry run python main.py -f hosts.txt -n Production
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Sophos Firewall Configuration (Required)
FIREWALL_HOSTNAME=firewall.example.com
FIREWALL_USERNAME=admin
FIREWALL_PASSWORD=your_secure_password
FIREWALL_PORT=4444
FIREWALL_VERIFY_SSL=false

# Application Settings (Optional)
FILE_ENCODING=utf-8
PROGRESS_ENABLED=true
VERBOSE=false
```

### Configuration Priority

1. Environment variables
2. `.env` file
3. Default values

## 📖 Usage

### Basic Usage

```bash
# Create host groups from a file
python main.py -f hosts.txt -n Production

# With verbose output
python main.py -f networks.txt -n Development -v

# Using UV for faster execution
uv run main.py -f hosts.txt -n Production
```

### Command Line Options

```
usage: python main.py [-f PATH] [-n NAME] [-v]

Create Sophos Firewall host groups from network records

Required Arguments:
  -f, --file PATH    Path to file with network records (one per line)
  -n, --name NAME    Base name for host groups

Optional Arguments:
  -v, --verbose      Enable verbose output
  -h, --help         Show help message and exit
```

### Input File Format

One record per line, blank lines and comments ignored:

```text
# FQDNs
example.com
subdomain.example.com
*.wildcard.example.com

# IPv4 Addresses
192.168.1.1
10.0.0.50

# IPv6 Addresses
2001:db8::1
fe80::1

# CIDR Networks
10.0.0.0/8
172.16.0.0/16
192.168.0.0/24
2001:db8::/32
```

### Output Example

```
i Loading records from: hosts.txt
+ Loaded 10 records

i Classifying records...
+ Valid: 9, Invalid: 1

i Creating host groups...
+ Created group: Production_FQDNHostGroup
+ Created group: Production_IPHostGroup

Processing 10 records...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

+ example.com: Created successfully
+ 192.168.1.1: Created successfully
! api.example.com: Already exists
! 10.0.0.0/8: Already exists
x invalid-record: Skipped (invalid format)

============================================================
i Processing Summary
============================================================
Total records: 10
+ Created: 7
! Already existed: 2
x Failed: 0
! Skipped: 1

Success rate: 70.0%
============================================================
```

## 🎯 Supported Record Types

| Type | Format | Examples |
|------|--------|----------|
| **FQDN** | Domain names | `example.com`, `sub.example.com` |
| **Wildcard FQDN** | Wildcards | `*.example.com` |
| **IPv4 Address** | Single IP | `192.168.1.1`, `10.0.0.50` |
| **IPv6 Address** | Single IP | `2001:db8::1`, `fe80::1` |
| **IPv4 Network** | CIDR notation | `10.0.0.0/8`, `192.168.0.0/24` |
| **IPv6 Network** | CIDR notation | `2001:db8::/32` |

## 🏗️ Architecture

The project follows **Clean Architecture** principles with clear separation of concerns:

```
sophos-firewall-manager/
├── main.py                    # Entry point
├── src/
│   ├── domain/                # Business logic (framework-independent)
│   │   ├── entities.py        # Core business entities
│   │   ├── validators.py      # Domain validation rules
│   │   └── exceptions.py      # Domain-specific exceptions
│   │
│   ├── infrastructure/        # External integrations
│   │   ├── firewall_client.py # Sophos API adapter
│   │   └── file_reader.py     # File I/O operations
│   │
│   ├── services/             # Application services
│   │   ├── group_service.py  # Host group management
│   │   └── record_service.py # Record processing logic
│   │
│   ├── presentation/         # UI layer
│   │   ├── formatters.py     # Output formatting
│   │   └── progress.py       # Progress tracking
│   │
│   └── cli/                  # CLI interface
│       └── commands.py       # Command-line handlers
│
├── config/
│   └── settings.py           # Configuration management
│
├── tests/
│   ├── unit/                 # Unit tests
│   └── integration/          # Integration tests
│
├── requirements.txt          # Python dependencies
├── pyproject.toml           # Project metadata
├── .env.example             # Example environment file
└── README.md                # This file
```

### Key Design Patterns

- **Repository Pattern** - Abstract API interactions
- **Strategy Pattern** - Multiple validation strategies
- **Dependency Injection** - Loose coupling
- **Value Objects** - Immutable domain entities
- **Clean Architecture** - Separation of concerns across layers

## 🛠️ Development

### Setup Development Environment

```bash
# Clone and install
git clone https://github.com/adelabdelgawad/sophos-firewall-manager.git
cd sophos-firewall-manager

# Using UV (fastest)
uv pip install -r requirements.txt

# OR using pip
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Code Quality Tools

```bash
# Format code
black src tests

# Lint code
ruff check src tests

# Type check
mypy src

# Run tests
pytest

# Run tests with coverage
pytest --cov=src --cov-report=html
```

### Project Structure Benefits

✅ **Maintainability** - Clear responsibility boundaries  
✅ **Testability** - Easy to mock and test components  
✅ **Extensibility** - Add features without breaking existing code  
✅ **Readability** - Self-documenting structure  
✅ **Scalability** - Organized for growth

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_validators.py

# Run with verbose output
pytest -v
```

## 🔧 Troubleshooting

### Common Issues

**Issue: `ModuleNotFoundError: No module named 'pydantic'`**

```bash
# Make sure dependencies are installed
pip install -r requirements.txt
# OR
uv pip install -r requirements.txt
```

**Issue: `Configuration error: field required`**

```bash
# Ensure .env file exists with all required variables
cp .env.example .env
# Edit .env and add your credentials
```

**Issue: Records already exist**

This is normal! The tool will show a warning (!) for records that already exist and continue processing the rest. This is the expected behavior.

**Issue: `Firewall error: Operation failed`**

Check that:
- Your firewall credentials are correct
- Your IP is allowed to access the firewall API
- The firewall API is enabled
- You have the necessary permissions

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with proper tests
4. Run quality checks (`black`, `ruff`, `mypy`, `pytest`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Commit Message Format

```
feat: Add support for IPv6 networks
fix: Handle connection timeout errors
docs: Update configuration examples
test: Add tests for RecordClassifier
refactor: Simplify error handling logic
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [sophosfirewall-python](https://github.com/sophos/sophosfirewall-python) - Sophos Firewall API wrapper
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting
- [Pydantic](https://github.com/pydantic/pydantic) - Data validation using type hints
- [UV](https://github.com/astral-sh/uv) - Extremely fast Python package installer

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/adelabdelgawad/sophos-firewall-manager/issues)
- **Discussions**: [GitHub Discussions](https://github.com/adelabdelgawad/sophos-firewall-manager/discussions)

## 🗺️ Roadmap

- [ ] Support for service groups
- [ ] Dry-run mode for validation without changes
- [ ] Export existing groups to file
- [ ] Batch delete operations
- [ ] Web UI interface
- [ ] Docker container support
- [ ] Additional firewall vendor support

## 📊 Status

![Build Status](https://img.shields.io/github/actions/workflow/status/adelabdelgawad/sophos-firewall-manager/ci.yml?branch=main)
![Last Commit](https://img.shields.io/github/last-commit/adelabdelgawad/sophos-firewall-manager)
![Issues](https://img.shields.io/github/issues/adelabdelgawad/sophos-firewall-manager)
![Stars](https://img.shields.io/github/stars/adelabdelgawad/sophos-firewall-manager)

---

**Made with ❤️ for Sophos Firewall Administrators**

⭐ Star this repository if you find it helpful!

## 💡 Tips

- Use UV for the fastest package installation and execution
- Run with `-v` flag to see detailed operation logs
- Process records in batches for large files
- Keep your `.env` file secure and never commit it
- The tool handles "already exists" gracefully - no need to clean up before re-running
- Group names are automatically created: `{BaseName}_FQDNHostGroup` and `{BaseName}_IPHostGroup`

## 📝 Example Use Cases

### Bulk Import New Office Network

```bash
python main.py -f office_networks.txt -n Office2024
```

### Update Partner Access Lists

```bash
python main.py -f partner_domains.txt -n Partners
```

### Migrate from Old System

```bash
# Export from old system to CSV/TXT
# Run the tool
python main.py -f migration_list.txt -n Migration
```

### Regular Updates

```bash
# Add to cron/scheduled task
0 2 * * * cd /path/to/sophos-firewall-manager && uv run main.py -f daily_updates.txt -n DailyUpdate
```