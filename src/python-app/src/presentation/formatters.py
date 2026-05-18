"""Output formatting for terminal display."""

from typing import Final

from src.domain.entities import OperationResult, OperationStatus, ProcessingSummary


class ColorFormatter:
    """Formats messages with Rich terminal colors."""
    
    # Color templates - using ASCII-safe characters
    SUCCESS: Final[str] = "[green]+[/green]"
    ERROR: Final[str] = "[red]x[/red]"
    WARNING: Final[str] = "[yellow]![/yellow]"
    INFO: Final[str] = "[blue]i[/blue]"
    
    @classmethod
    def success(cls, message: str) -> str:
        """Format success message."""
        return f"[green]{message}[/green]"
    
    @classmethod
    def error(cls, message: str) -> str:
        """Format error message."""
        return f"[red]{message}[/red]"
    
    @classmethod
    def warning(cls, message: str) -> str:
        """Format warning message."""
        return f"[yellow]{message}[/yellow]"
    
    @classmethod
    def info(cls, message: str) -> str:
        """Format info message."""
        return f"[blue]{message}[/blue]"


class OperationResultFormatter:
    """Formats operation results for display."""
    
    @staticmethod
    def format(result: OperationResult) -> str:
        """
        Format an operation result.
        
        Args:
            result: Operation result to format
            
        Returns:
            Formatted string with color markup
        """
        record_value = result.record.value
        message = result.message
        
        if result.status == OperationStatus.SUCCESS:
            return f"{ColorFormatter.SUCCESS} {record_value}: {message}"

        if result.status == OperationStatus.UPDATED:
            return f"{ColorFormatter.SUCCESS} {record_value}: {message}"

        if result.status == OperationStatus.ALREADY_EXISTS:
            return f"{ColorFormatter.WARNING} {record_value}: {message}"

        if result.status == OperationStatus.SKIPPED:
            return f"{ColorFormatter.WARNING} {record_value}: Skipped (invalid format)"

        if result.status == OperationStatus.FAILED:
            return f"{ColorFormatter.ERROR} {record_value}: {message}"

        return f"{ColorFormatter.INFO} {record_value}: Unknown status"


class SummaryFormatter:
    """Formats processing summaries."""
    
    @staticmethod
    def format(summary: ProcessingSummary) -> str:
        """
        Format a processing summary.
        
        Args:
            summary: Processing summary to format
            
        Returns:
            Multi-line formatted summary
        """
        lines = [
            "\n" + "=" * 60,
            ColorFormatter.info("Processing Summary"),
            "=" * 60,
            f"Total records: {summary.total}",
            f"{ColorFormatter.SUCCESS} Created: {summary.successful}",
            f"{ColorFormatter.SUCCESS} Updated: {summary.updated}",
            f"{ColorFormatter.WARNING} Already existed: {summary.already_exists}",
            f"{ColorFormatter.ERROR} Failed: {summary.failed}",
            f"{ColorFormatter.WARNING} Skipped: {summary.skipped}",
            f"\nSuccess rate: {summary.success_rate:.1f}%",
            "=" * 60,
        ]
        
        return "\n".join(lines)


class GroupCreationFormatter:
    """Formats group creation results."""
    
    @staticmethod
    def format(group_name: str, created: bool) -> str:
        """
        Format group creation result.
        
        Args:
            group_name: Name of the group
            created: Whether the group was created or already existed
            
        Returns:
            Formatted string
        """
        if created:
            return f"{ColorFormatter.SUCCESS} Created group: {group_name}"
        
        return f"{ColorFormatter.WARNING} Group already exists: {group_name}"