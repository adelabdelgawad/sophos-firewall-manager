//! Sophos Firewall Manager — CLI entry point.

use std::process::exit;

fn main() {
    exit(sfm::cli::run());
}
