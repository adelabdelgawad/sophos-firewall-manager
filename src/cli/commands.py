"""CLI command implementation."""

import sys
from pathlib import Path

from rich import print

from config.settings import get_settings
from src.domain.entities import OperationResult  # Add this import
from src.domain.exceptions import (
    ConfigurationException,
    FileOperationException,
    FirewallException,
    FirewallIPRestrictionException,
)
from src.domain.validators import RecordClassifier
from src.infrastructure.file_reader import TextFileReader
from src.infrastructure.firewall_client import SophosFirewallClient
from src.presentation.formatters import (
    ColorFormatter,
    GroupCreationFormatter,
    OperationResultFormatter,
    SummaryFormatter,
)
from src.presentation.progress import ProgressTracker, create_progress_callback
from src.services.group_service import GroupConfiguration, HostGroupService
from src.services.record_service import RecordProcessingService


class Application:
    """Main application orchestrator."""
    
    def __init__(self, file_path: str, base_name: str):
        """
        Initialize application.
        
        Args:
            file_path: Path to input file
            base_name: Base name for host groups
        """
        self.file_path = file_path
        self.base_name = base_name
        
        # Load settings
        try:
            self.app_settings, self.firewall_settings = get_settings()
        except Exception as e:
            raise ConfigurationException(f"Failed to load settings: {e}")
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self) -> None:
        """Initialize all application components."""
        # File reader
        self.file_reader = TextFileReader(
            encoding=self.app_settings.file_encoding
        )
        
        # Firewall client
        self.firewall_client = SophosFirewallClient(
            hostname=self.firewall_settings.hostname,
            username=self.firewall_settings.username,
            password=self.firewall_settings.password,
            port=self.firewall_settings.port,
            verify_ssl=self.firewall_settings.verify_ssl,
        )
        
        # Services
        group_config = GroupConfiguration(base_name=self.base_name)
        self.group_service = HostGroupService(
            firewall_client=self.firewall_client,
            config=group_config,
        )
        self.record_service = RecordProcessingService(
            firewall_client=self.firewall_client,
            group_service=self.group_service,
        )
        
        # Validators and formatters
        self.classifier = RecordClassifier()
        self.result_formatter = OperationResultFormatter()
        self.summary_formatter = SummaryFormatter()
        self.group_formatter = GroupCreationFormatter()
    
    def run(self) -> int:
        """
        Run the application.
        
        Returns:
            Exit code (0 for success)
        """
        try:
            # Step 1: Load records from file
            print(ColorFormatter.info(f"Loading records from: {self.file_path}"))
            raw_records = self.file_reader.read_lines(self.file_path)
            print(ColorFormatter.success(f"Loaded {len(raw_records)} records\n"))
            
            # Step 2: Classify records
            print(ColorFormatter.info("Classifying records..."))
            records = self.classifier.classify_batch(raw_records)
            
            valid_count = sum(1 for r in records if r.is_valid)
            invalid_count = len(records) - valid_count
            print(ColorFormatter.success(f"Valid: {valid_count}, Invalid: {invalid_count}\n"))
            
            # Step 3: Create host groups
            print(ColorFormatter.info("Creating host groups..."))
            group_results = self.group_service.create_groups()
            
            for group_name, created in group_results.items():
                print(self.group_formatter.format(group_name, created))
            print()
            
            # Step 4: Process records
            print(ColorFormatter.info(f"Processing {len(records)} records..."))
            
            with ProgressTracker() as tracker:
                tracker.start_task(
                    total=len(records),
                    description="Creating firewall entries"
                )
                
                # Process with progress callback
                def process_callback(result: OperationResult) -> None:
                    """Callback to print result and advance progress."""
                    print(self.result_formatter.format(result))
                    tracker.advance()
                
                summary = self.record_service.process_batch(
                    records=records,
                    callback=process_callback
                )
            
            # Step 5: Display summary
            print(self.summary_formatter.format(summary))
            
            return 0
            
        except FileOperationException as e:
            print(ColorFormatter.error(f"File error: {e}"))
            return 1
        
        except FirewallIPRestrictionException as e:
            print(ColorFormatter.error(f"Access denied: {e}"))
            print(ColorFormatter.warning(
                "Your IP address is not allowed to access the firewall API."
            ))
            return 2
        
        except FirewallException as e:
            print(ColorFormatter.error(f"Firewall error: {e}"))
            return 3
        
        except ConfigurationException as e:
            print(ColorFormatter.error(f"Configuration error: {e}"))
            return 4
        
        except KeyboardInterrupt:
            print(ColorFormatter.warning("\n\nOperation cancelled by user"))
            return 130
        
        except Exception as e:
            print(ColorFormatter.error(f"Unexpected error: {e}"))
            if self.app_settings.verbose:
                import traceback
                traceback.print_exc()
            return 1


def main() -> None:
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        prog="sophos-firewall-manager",
        description="Create Sophos Firewall host groups from network records",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f hosts.txt -n Production
  %(prog)s --file networks.txt --name Dev_Network
  
Environment Variables:
  FIREWALL_HOSTNAME    Firewall hostname or IP
  FIREWALL_USERNAME    API username
  FIREWALL_PASSWORD    API password
  FIREWALL_PORT        API port (default: 4444)
        """
    )
    
    parser.add_argument(
        "-f", "--file",
        required=True,
        metavar="PATH",
        help="Path to file with IP addresses, CIDR networks, and FQDNs (one per line)"
    )
    
    parser.add_argument(
        "-n", "--name",
        required=True,
        metavar="NAME",
        help="Base name for host groups (suffixes will be added automatically)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0"
    )
    
    args = parser.parse_args()
    
    # Set verbose mode if requested
    if args.verbose:
        import os
        os.environ["VERBOSE"] = "true"
    
    # Run application
    app = Application(
        file_path=args.file,
        base_name=args.name
    )
    
    exit_code = app.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()