#!/usr/bin/env python3
"""Update CVE delta script for HTTPMR.

A simple wrapper script to re-run the CVE scanner and update the custom delta.
This can be called periodically or when new CVE files are added.
"""

import sys
from pathlib import Path

# Add the current directory to the path to import our modules
sys.path.insert(0, str(Path(__file__).parent))

from cve_scanner import main as scan_main

if __name__ == "__main__":
    print("Updating CVE delta database...")
    scan_main()
    print("CVE delta update complete!")
