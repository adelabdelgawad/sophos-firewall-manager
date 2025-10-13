#!/usr/bin/env python3
"""
Sophos Firewall Manager - Main Entry Point

Direct execution entry point.
Usage: python main.py -f hosts.txt -n Production
"""

import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import and run the CLI
if __name__ == "__main__":
    from src.cli.commands import main
    main()