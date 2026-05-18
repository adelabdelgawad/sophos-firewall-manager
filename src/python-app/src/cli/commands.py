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
from src.services.cache_service import ExistingRecordsCache, GroupMembershipCache
from src.services.group_service import GroupConfiguration, HostGroupService
from src.services.record_service import RecordProcessingService


class Application:
    """Main application orchestrator."""

    def __init__(self, file_path: str, base_name: str, update_mode: bool = False):
        """
        Initialize application.

        Args:
            file_path: Path to input file
            base_name: Base name for host groups
            update_mode: If True, add existing records to groups instead of skipping
        """
        self.file_path = file_path
        self.base_name = base_name
        self.update_mode = update_mode

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

        # Caches
        self.existing_cache = ExistingRecordsCache()
        self.group_membership_cache = GroupMembershipCache()
    
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

            # Step 4: Fetch existing records for de-duplication
            print(ColorFormatter.info("Checking existing records..."))
            cache_loaded = self.existing_cache.load(self.firewall_client)

            existing_records: list = []
            new_records: list = []
            skipped_existing = 0

            if cache_loaded:
                stats = self.existing_cache.stats
                print(ColorFormatter.success(
                    f"Found {stats['total']} existing records "
                    f"(FQDNs: {stats['fqdns']}, IPs: {stats['ip_hosts']}, Networks: {stats['networks']})"
                ))

                # Separate existing and new records
                for r in records:
                    if r.is_valid and self.existing_cache.exists(r):
                        existing_records.append(r)
                    else:
                        new_records.append(r)

                if self.update_mode and existing_records:
                    # In update mode, load group membership to check what needs updating
                    print(ColorFormatter.info("Loading group membership..."))
                    self.group_membership_cache.load(
                        self.firewall_client,
                        self.group_service.fqdn_group,
                        self.group_service.ip_group,
                    )
                    gstats = self.group_membership_cache.stats
                    print(ColorFormatter.success(
                        f"Group has {gstats['fqdn_members']} FQDNs, {gstats['ip_members']} IPs"
                    ))

                    # Filter existing records: only update those not in the group
                    records_to_update = [
                        r for r in existing_records
                        if not self.group_membership_cache.is_member(r)
                    ]
                    already_in_group = len(existing_records) - len(records_to_update)

                    if already_in_group > 0:
                        print(ColorFormatter.warning(
                            f"Skipping {already_in_group} records already in group"
                        ))
                    if records_to_update:
                        print(ColorFormatter.info(
                            f"Will update {len(records_to_update)} existing records to add to group"
                        ))
                else:
                    # Default mode: skip existing records
                    records_to_update = []
                    skipped_existing = len(existing_records)
                    if skipped_existing > 0:
                        print(ColorFormatter.warning(
                            f"Skipping {skipped_existing} records that already exist"
                        ))
            else:
                print(ColorFormatter.warning(
                    "Could not fetch existing records - will attempt all creations"
                ))
                new_records = records
                records_to_update = []

            print()

            # Step 5: Process new records
            total_to_process = len(new_records) + len(records_to_update)
            if total_to_process == 0:
                msg = "All records already exist"
                if self.update_mode:
                    msg += " and are in the target groups"
                print(ColorFormatter.success(f"{msg} - nothing to do!"))
                return 0

            from src.domain.entities import ProcessingSummary
            summary = ProcessingSummary()

            # Process new records (create)
            if new_records:
                valid_new = [r for r in new_records if r.is_valid]
                invalid_new = [r for r in new_records if not r.is_valid]
                print(ColorFormatter.info(f"Creating {len(valid_new)} new records..."))

                with ProgressTracker() as tracker:
                    tracker.start_task(
                        total=len(new_records),
                        description="Creating firewall entries"
                    )

                    def create_callback(result: OperationResult) -> None:
                        print(self.result_formatter.format(result))
                        tracker.advance()

                    batch_summary = self.record_service.process_batch(
                        records=new_records,
                        callback=create_callback
                    )
                    summary.total += batch_summary.total
                    summary.successful += batch_summary.successful
                    summary.already_exists += batch_summary.already_exists
                    summary.failed += batch_summary.failed
                    summary.skipped += batch_summary.skipped

            # Process existing records (update group membership)
            if records_to_update:
                print(ColorFormatter.info(
                    f"Updating {len(records_to_update)} existing records..."
                ))

                with ProgressTracker() as tracker:
                    tracker.start_task(
                        total=len(records_to_update),
                        description="Updating group membership"
                    )

                    for record in records_to_update:
                        result = self.record_service.update_existing_record(record)
                        summary.record_result(result)
                        print(self.result_formatter.format(result))
                        tracker.advance()

            # Add skipped existing records to summary
            summary.already_exists += skipped_existing
            summary.total += skipped_existing

            # Step 6: Display summary
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
        "-u", "--update",
        action="store_true",
        help="Add existing records to target groups (default: skip existing)"
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
        base_name=args.name,
        update_mode=args.update
    )
    
    exit_code = app.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()