"""Progress tracking for batch operations."""

from typing import Callable

from rich.progress import Progress, TaskID

from src.domain.entities import NetworkRecord, OperationResult


class ProgressTracker:
    """
    Tracks progress of record processing operations.
    
    Wraps Rich Progress for consistent progress display.
    """
    
    def __init__(self):
        """Initialize progress tracker."""
        self._progress = Progress()
        self._task: TaskID | None = None
    
    def __enter__(self):
        """Enter context manager."""
        self._progress.__enter__()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        return self._progress.__exit__(exc_type, exc_val, exc_tb)
    
    def start_task(self, total: int, description: str = "Processing") -> None:
        """
        Start a new progress task.
        
        Args:
            total: Total number of items to process
            description: Task description
        """
        self._task = self._progress.add_task(
            f"[blue]{description}...[/blue]",
            total=total,
        )
    
    def advance(self, amount: int = 1) -> None:
        """
        Advance progress.
        
        Args:
            amount: Amount to advance (default: 1)
        """
        if self._task is not None:
            self._progress.update(self._task, advance=amount)
    
    def update_description(self, description: str) -> None:
        """
        Update task description.
        
        Args:
            description: New description
        """
        if self._task is not None:
            self._progress.update(
                self._task,
                description=f"[blue]{description}...[/blue]"
            )


def create_progress_callback(tracker: ProgressTracker) -> Callable[[OperationResult], None]:
    """
    Create a callback that updates progress tracker.
    
    Args:
        tracker: Progress tracker to update
        
    Returns:
        Callback function
    """
    def callback(result: OperationResult) -> None:
        """Update progress on each result."""
        tracker.advance()
    
    return callback