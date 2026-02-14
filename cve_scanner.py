#!/usr/bin/env python3
"""CVE directory scanner for HTTPMR.

Scans the cves directory structure to build a complete database of all CVE files,
creating a custom delta.json in the .secure directory for comprehensive CVE search.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

REPO_ROOT = Path(__file__).parent
CVE_ROOT = REPO_ROOT / "cves"
SECURE_DIR = REPO_ROOT / ".secure"
CUSTOM_DELTA_PATH = SECURE_DIR / "cve_delta.json"


def scan_cve_directory() -> Dict[str, List[str]]:
    """Scan the CVE directory and return a mapping of years to CVE files."""
    print(f"Scanning CVE directory: {CVE_ROOT}")
    
    if not CVE_ROOT.exists():
        print(f"CVE directory not found: {CVE_ROOT}")
        return {}
    
    year_to_cves: Dict[str, List[str]] = {}
    
    # Get all year directories (they should be numeric)
    year_dirs = [d for d in CVE_ROOT.iterdir() if d.is_dir() and d.name.isdigit()]
    year_dirs.sort(key=lambda d: int(d.name), reverse=True)  # Sort years descending
    
    print(f"Found {len(year_dirs)} year directories: {', '.join(d.name for d in year_dirs)}")
    
    total_cves = 0
    for year_dir in year_dirs:
        year = year_dir.name
        cve_files = []
        
        # Recursively find all .json files in the year directory
        for json_file in year_dir.rglob("*.json"):
            if json_file.is_file():
                # Extract CVE ID from filename
                cve_id = json_file.stem
                if cve_id.startswith("CVE-"):
                    cve_files.append(cve_id)
        
        cve_files.sort()  # Sort CVE IDs
        year_to_cves[year] = cve_files
        total_cves += len(cve_files)
        print(f"Year {year}: {len(cve_files)} CVE files")
    
    print(f"Total CVE files found: {total_cves}")
    return year_to_cves


def create_custom_delta(year_to_cves: Dict[str, List[str]]) -> Dict:
    """Create a custom delta structure from scanned CVE data."""
    now = datetime.utcnow().isoformat() + "Z"
    
    # Create entries similar to deltaLog.json structure but with all CVEs
    all_entries = []
    
    for year, cve_ids in year_to_cves.items():
        for cve_id in cve_ids:
            # Create a basic entry for each CVE
            entry = {
                "cveId": cve_id,
                "cveOrgLink": f"https://www.cve.org/CVERecord?id={cve_id}",
                "githubLink": f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{_get_group_from_cve(cve_id)}/{cve_id}.json",
                "dateUpdated": None,  # We'll populate this when we read the actual file
                "scanned": True,
                "scanTime": now
            }
            all_entries.append(entry)
    
    # Create the delta structure
    delta = {
        "scanTime": now,
        "scanType": "directory_scan",
        "totalCVEs": len(all_entries),
        "years": list(year_to_cves.keys()),
        "yearCounts": {year: len(cves) for year, cves in year_to_cves.items()},
        "entries": all_entries
    }
    
    return delta


def _get_group_from_cve(cve_id: str) -> str:
    """Extract the group directory name from a CVE ID (e.g., '14xxx' from CVE-2025-14553)."""
    try:
        parts = cve_id.split("-")
        if len(parts) < 3:
            return "0xxx"
        
        suffix = parts[2]
        suffix_num = int(suffix)
        group = f"{suffix_num // 1000}xxx"
        return group
    except (ValueError, IndexError):
        return "0xxx"


def update_cve_timestamps(delta: Dict) -> Dict:
    """Update CVE entries with actual timestamps from their JSON files."""
    print("Updating CVE timestamps from JSON files...")
    
    updated_count = 0
    for entry in delta["entries"]:
        cve_id = entry["cveId"]
        
        # Try to read the actual CVE file to get the date
        cve_file_path = _resolve_cve_path(cve_id)
        if cve_file_path and cve_file_path.exists():
            try:
                with open(cve_file_path, 'r') as f:
                    cve_data = json.load(f)
                
                # Try to extract dateUpdated from the CVE data
                containers = cve_data.get("containers", {})
                cna = containers.get("cna", {})
                date_updated = cna.get("dateUpdated")
                
                if date_updated:
                    entry["dateUpdated"] = date_updated
                    updated_count += 1
            except (json.JSONDecodeError, Exception) as e:
                print(f"Warning: Could not read {cve_file_path}: {e}")
    
    print(f"Updated timestamps for {updated_count} CVE entries")
    return delta


def _resolve_cve_path(cve_id: str) -> Path | None:
    """Resolve the file path for a given CVE ID."""
    if not cve_id:
        return None
    
    parts = cve_id.split("-")
    if len(parts) < 3:
        return None
    
    year_part = parts[1]
    suffix = parts[2]
    
    try:
        suffix_num = int(suffix)
    except ValueError:
        return None
    
    group = f"{suffix_num // 1000}xxx"
    year_dir = CVE_ROOT / year_part
    direct_path = year_dir / group / f"{cve_id}.json"
    
    if direct_path.exists():
        return direct_path
    
    # Fallback to glob search
    if year_dir.exists():
        matches = list(year_dir.rglob(f"{cve_id}.json"))
        if matches:
            return matches[0]
    
    return None


def save_custom_delta(delta: Dict) -> None:
    """Save the custom delta to the .secure directory."""
    SECURE_DIR.mkdir(exist_ok=True)
    
    print(f"Saving custom delta to: {CUSTOM_DELTA_PATH}")
    
    with open(CUSTOM_DELTA_PATH, 'w') as f:
        json.dump(delta, f, indent=2)
    
    print(f"Custom delta saved with {delta['totalCVEs']} CVE entries")


def main():
    """Main scanning function."""
    print("=== CVE Directory Scanner ===")
    print(f"Repository root: {REPO_ROOT}")
    print(f"CVE directory: {CVE_ROOT}")
    print(f"Output file: {CUSTOM_DELTA_PATH}")
    print()
    
    # Scan the directory
    year_to_cves = scan_cve_directory()
    
    if not year_to_cves:
        print("No CVE files found. Exiting.")
        return
    
    # Create custom delta
    delta = create_custom_delta(year_to_cves)
    
    # Update with actual timestamps (optional but recommended)
    delta = update_cve_timestamps(delta)
    
    # Save the custom delta
    save_custom_delta(delta)
    
    print()
    print("=== Scan Summary ===")
    print(f"Years scanned: {', '.join(delta['years'])}")
    print(f"Total CVEs: {delta['totalCVEs']}")
    print(f"Custom delta saved to: {CUSTOM_DELTA_PATH}")
    print("You can now update cve_search.py to use this custom delta.")


if __name__ == "__main__":
    main()
