//! File reading infrastructure. Ports `src/infrastructure/file_reader.py`.

use std::fs;
use std::path::Path;

use crate::domain::errors::{AppError, Result};

/// Reads text files containing network records, one per line.
pub struct TextFileReader {
    /// Declared text encoding. Only UTF-8 is supported (the application default).
    pub encoding: String,
}

impl TextFileReader {
    pub fn new(encoding: impl Into<String>) -> Self {
        Self {
            encoding: encoding.into(),
        }
    }

    /// Read and clean lines from a text file.
    ///
    /// Returns the non-empty, trimmed lines. Each line is trimmed of
    /// surrounding whitespace and blank lines are dropped, matching the
    /// Python `[line.strip() for line in f if line.strip()]`.
    pub fn read_lines(&self, path: &str) -> Result<Vec<String>> {
        let file_path = Path::new(path);

        if !file_path.exists() {
            return Err(AppError::File(format!("File not found: {path}")));
        }
        if !file_path.is_file() {
            return Err(AppError::File(format!("Not a file: {path}")));
        }

        let bytes = fs::read(file_path)
            .map_err(|e| AppError::File(format!("Error reading {path}: {e}")))?;

        let content = String::from_utf8(bytes).map_err(|_| {
            AppError::File(format!(
                "Encoding error in {path}: invalid byte sequence. Expected {}.",
                self.encoding
            ))
        })?;

        let lines: Vec<String> = content
            .split('\n')
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        if lines.is_empty() {
            return Err(AppError::File(format!("File is empty: {path}")));
        }

        Ok(lines)
    }

    /// Validate that a file can be read.
    pub fn validate_file(&self, path: &str) -> bool {
        self.read_lines(path).is_ok()
    }
}
