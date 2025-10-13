"""File reading infrastructure."""

from pathlib import Path
from typing import Protocol

from src.domain.exceptions import FileOperationException


class FileReader(Protocol):
    """Protocol for file reading operations."""
    
    def read_lines(self, path: str) -> list[str]:
        """Read lines from file."""
        ...


class TextFileReader:
    """
    Reads text files containing network records.
    
    Handles file validation and encoding issues.
    """
    
    def __init__(self, encoding: str = "utf-8"):
        """
        Initialize file reader.
        
        Args:
            encoding: Text encoding (default: utf-8)
        """
        self.encoding = encoding
    
    def read_lines(self, path: str) -> list[str]:
        """
        Read and clean lines from a text file.
        
        Args:
            path: Path to input file
            
        Returns:
            List of non-empty, stripped lines
            
        Raises:
            FileOperationException: If file cannot be read
        """
        file_path = Path(path)
        
        # Validate file exists
        if not file_path.exists():
            raise FileOperationException(f"File not found: {path}")
        
        # Validate it's a file
        if not file_path.is_file():
            raise FileOperationException(f"Not a file: {path}")
        
        # Read and clean lines
        try:
            with file_path.open("r", encoding=self.encoding) as f:
                lines = [line.strip() for line in f if line.strip()]
            
            if not lines:
                raise FileOperationException(f"File is empty: {path}")
            
            return lines
            
        except UnicodeDecodeError as e:
            raise FileOperationException(
                f"Encoding error in {path}: {e}. Expected {self.encoding}."
            )
        except Exception as e:
            raise FileOperationException(f"Error reading {path}: {e}")
    
    def validate_file(self, path: str) -> bool:
        """
        Validate that a file can be read.
        
        Args:
            path: Path to validate
            
        Returns:
            True if file is valid and readable
        """
        try:
            self.read_lines(path)
            return True
        except FileOperationException:
            return False