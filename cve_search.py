#!/usr/bin/env python3
"""CVE search helper for HTTPMR.

Loads metadata from cves/deltaLog.json, provides fuzzy search helpers,
listing by year, and loading full CVE JSON records.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).parent
CVE_ROOT = REPO_ROOT / "cves"
DELTA_LOG_PATH = CVE_ROOT / "deltaLog.json"
CUSTOM_DELTA_PATH = REPO_ROOT / ".secure" / "cve_delta.json"

# Import platform year hints for optimization
try:
    from platform_year_hints import get_optimized_search_years, get_platform_info
    OPTIMIZATION_AVAILABLE = True
except ImportError:
    OPTIMIZATION_AVAILABLE = False


@dataclass
class CVEEntry:
    cve_id: str
    year: int
    kind: str
    github_link: Optional[str]
    org_link: Optional[str]
    date_updated: Optional[str]
    fetch_time: Optional[str]
    search_blob: Optional[str] = field(default=None, repr=False, compare=False)

    def iso_date(self) -> datetime:
        stamp = self.date_updated or self.fetch_time
        if not stamp:
            return datetime.min
        try:
            return datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            return datetime.min


class CVELibrary:
    """Loads CVE metadata from custom delta or deltaLog and provides lookup helpers."""

    def __init__(self, delta_log: Path | None = None, cve_root: Path | None = None, use_custom_delta: bool = True):
        self.cve_root = cve_root or CVE_ROOT
        self.use_custom_delta = use_custom_delta
        
        if use_custom_delta:
            self.delta_path = delta_log or CUSTOM_DELTA_PATH
        else:
            self.delta_path = delta_log or DELTA_LOG_PATH
            
        self._entries: List[CVEEntry] = []
        self._by_year: Dict[int, List[CVEEntry]] = {}
        self._loaded = False
        self._search_blob_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def list_years(self) -> List[int]:
        self._ensure_loaded()
        return sorted(self._by_year.keys(), reverse=True)

    def list_entries_by_year(self, year: int, limit: Optional[int] = None) -> List[CVEEntry]:
        self._ensure_loaded()
        entries = self._by_year.get(year, [])
        return entries if limit is None else entries[:limit]

    def search(self, term: str, limit: int = None) -> List[CVEEntry]:
        self._ensure_loaded()
        term = (term or "").strip()
        if not term:
            return []

        term_lower = term.lower()
        
        # Early exit for exact CVE ID matches
        if term_lower.startswith('cve-') and '-' in term_lower:
            for entry in self._entries:
                if entry.cve_id.lower() == term_lower:
                    return [entry]
        
        # Get optimization info if available
        years_to_search = None
        optimization_applied = False
        if OPTIMIZATION_AVAILABLE:
            platform_info = get_platform_info(term)
            if platform_info and platform_info["optimization_applied"]:
                available_years = list(self._by_year.keys())
                years_to_search = get_optimized_search_years(term, available_years)
                optimization_applied = True
        
        # Determine which entries to search through
        if years_to_search:
            # Filter entries by optimized years
            entries_to_search = []
            for year in years_to_search:
                entries_to_search.extend(self._by_year.get(year, []))
        else:
            entries_to_search = self._entries
        
        # Multi-pass search for better performance
        results = []
        
        # Pass 1: Exact CVE ID matches (highest priority)
        exact_matches = [entry for entry in entries_to_search if term_lower == entry.cve_id.lower()]
        results.extend(exact_matches)
        if limit is not None and len(results) >= limit:
            return results[:limit]
        
        # Pass 2: CVE ID contains term (high priority)
        cve_matches = [entry for entry in entries_to_search if term_lower in entry.cve_id.lower() and entry not in results]
        results.extend(cve_matches)
        if limit is not None and len(results) >= limit:
            return results[:limit]
        
        # Pass 3: Description blob contains term (medium priority) - LIMITED
        if limit is None or len(results) < limit:
            remaining_needed = limit - len(results) if limit is not None else None
            blob_matches = []
            
            # If no limit, search all entries, otherwise search through the timeline
            if limit is None:
                blob_search_limit = len(entries_to_search)
            else:
                # Search through the entire timeline to find old results
                blob_search_limit = len(entries_to_search)
            
            for entry in entries_to_search[:blob_search_limit]:
                if entry in results:
                    continue
                    
                blob = self._get_entry_search_blob(entry)
                if blob and term_lower in blob:
                    blob_matches.append(entry)
                    # Don't break early - collect all matches for diversity selection
            
            results.extend(blob_matches)
            # Don't return early - let diversity logic handle the final selection
        
        # Pass 4: Fuzzy matching (lowest priority) - VERY LIMITED
        if limit is None or len(results) < limit:
            remaining_needed = limit - len(results) if limit is not None else None
            fuzzy_matches = []
            
            # If no limit, search more entries, otherwise limit strictly
            fuzzy_search_limit = min(5000, len(entries_to_search)) if limit is None else min(2000, len(entries_to_search))
            
            for entry in entries_to_search[:fuzzy_search_limit]:
                if entry in results:
                    continue
                    
                blob = self._get_entry_search_blob(entry)
                if blob:
                    ratio = difflib.SequenceMatcher(None, term_lower, blob[:256]).ratio()
                    if ratio >= 0.5:  # Higher threshold for fuzzy matches
                        fuzzy_matches.append((ratio, entry))
            
            # Sort fuzzy matches by ratio and take the best ones
            fuzzy_matches.sort(key=lambda x: x[0], reverse=True)
            if limit is not None:
                results.extend([entry for _, entry in fuzzy_matches[:remaining_needed]])
            else:
                results.extend([entry for _, entry in fuzzy_matches])
        
        # Sort final results by score (implicit) and date
        # The order is: exact -> cve_contains -> blob_contains -> fuzzy
        results.sort(key=lambda entry: entry.iso_date(), reverse=True)
        
        # If we have a limit and more results than the limit, ensure chronological diversity
        if limit is not None and len(results) > limit:
            final_results = []
            total_results = len(results)
            
            # Take samples from different parts of the timeline
            samples_per_section = limit // 5  # 5 sections across the timeline
            
            for section in range(5):
                start_pos = int((section / 5) * total_results)
                end_pos = int(((section + 1) / 5) * total_results)
                
                # Take samples from this section
                section_results = results[start_pos:end_pos]
                if section_results:
                    # Take up to samples_per_section from this section
                    final_results.extend(section_results[:samples_per_section])
                
                # Stop if we've reached our limit
                if len(final_results) >= limit:
                    break
            
            return final_results[:limit]
        
        return results[:limit] if limit is not None else results

    def get_search_optimization_info(self, term: str) -> Dict:
        """Get optimization information for a search term."""
        if not OPTIMIZATION_AVAILABLE:
            return {"optimization_applied": False, "reason": "Platform hints not available"}
        
        platform_info = get_platform_info(term)
        if not platform_info["optimization_applied"]:
            return {"optimization_applied": False, "reason": "No platform hint found"}
        
        available_years = list(self._by_year.keys())
        optimized_years = get_optimized_search_years(term, available_years)
        
        return {
            "optimization_applied": True,
            "platform": platform_info["platform"],
            "min_year": platform_info["min_year"],
            "total_years_available": len(available_years),
            "years_searched": len(optimized_years),
            "year_reduction": f"{len(optimized_years)}/{len(available_years)} years",
            "performance_gain": f"{((len(available_years) - len(optimized_years)) / len(available_years) * 100):.1f}% fewer years"
        }

    def _get_entry_search_blob(self, entry: CVEEntry) -> str:
        cached = self._search_blob_cache.get(entry.cve_id)
        if cached is not None:
            return cached

        record = self.get_cve_record(entry.cve_id)
        blob = ""
        if record:
            containers = record.get("containers") or {}
            cna = containers.get("cna") or {}
            parts: List[str] = []
            for desc in cna.get("descriptions", []) or []:
                value = desc.get("value")
                if value:
                    parts.append(value)
            for problem in cna.get("problemTypes", []) or []:
                for desc in problem.get("descriptions", []) or []:
                    text = desc.get("description")
                    if text:
                        parts.append(text)
            for ref in cna.get("references", []) or []:
                if ref.get("name"):
                    parts.append(ref["name"])
                if ref.get("url"):
                    parts.append(ref["url"])
            for affected in cna.get("affected", []) or []:
                vendor = affected.get("vendor")
                for product in affected.get("products", []) or []:
                    product_name = product.get("product")
                    if vendor or product_name:
                        parts.append(f"{vendor or ''} {product_name or ''}")
            blob = " ".join(parts).lower()

        self._search_blob_cache[entry.cve_id] = blob
        return blob

    def get_cve_record(self, cve_id: str) -> Optional[dict]:
        path = self._resolve_cve_path(cve_id)
        if not path or not path.exists():
            return None
        try:
            with open(path, "r") as fh:
                return json.load(fh)
        except Exception:
            return None

    def get_entry(self, cve_id: str) -> Optional[CVEEntry]:
        self._ensure_loaded()
        target = cve_id.upper()
        for entry in self._entries:
            if entry.cve_id.upper() == target:
                return entry
        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if not self.delta_path.exists():
            self._entries = []
            self._by_year = {}
            self._loaded = True
            return

        with open(self.delta_path, "r") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError:
                data = {}

        entries: List[CVEEntry] = []
        
        if self.use_custom_delta and "entries" in data:
            # Load from our custom delta format
            for item in data["entries"]:
                cve_id = item.get("cveId")
                if not cve_id:
                    continue
                year = _extract_year_from_cve(cve_id)
                entries.append(
                    CVEEntry(
                        cve_id=cve_id,
                        year=year,
                        kind="scanned",  # All entries are from directory scan
                        github_link=item.get("githubLink"),
                        org_link=item.get("cveOrgLink"),
                        date_updated=item.get("dateUpdated"),
                        fetch_time=item.get("scanTime"),
                    )
                )
        else:
            # Load from original deltaLog.json format
            batches = data if isinstance(data, list) else []
            for batch in batches:
                fetch_time = batch.get("fetchTime")
                for kind in ("new", "updated"):
                    for item in batch.get(kind, []) or []:
                        cve_id = item.get("cveId")
                        if not cve_id:
                            continue
                        year = _extract_year_from_cve(cve_id)
                        entries.append(
                            CVEEntry(
                                cve_id=cve_id,
                                year=year,
                                kind=kind,
                                github_link=item.get("githubLink"),
                                org_link=item.get("cveOrgLink"),
                                date_updated=item.get("dateUpdated"),
                                fetch_time=fetch_time,
                            )
                        )

        entries.sort(key=lambda entry: entry.iso_date(), reverse=True)
        by_year: Dict[int, List[CVEEntry]] = {}
        for entry in entries:
            by_year.setdefault(entry.year, []).append(entry)

        self._entries = entries
        self._by_year = by_year
        self._search_blob_cache = {}
        self._loaded = True

    def _resolve_cve_path(self, cve_id: str) -> Optional[Path]:
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
        year_dir = self.cve_root / year_part
        direct_path = year_dir / group / f"{cve_id}.json"
        if direct_path.exists():
            return direct_path

        # Fallback to glob search within the year directory (slower, but reliable)
        if year_dir.exists():
            matches = list(year_dir.rglob(f"{cve_id}.json"))
            if matches:
                return matches[0]
        return None


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _extract_year_from_cve(cve_id: str) -> int:
    try:
        return int(cve_id.split("-")[1])
    except (ValueError, IndexError):
        return 0


def _format_entry(entry: CVEEntry) -> str:
    stamp = entry.iso_date().isoformat() if entry.iso_date() != datetime.min else "unknown"
    return f"{entry.cve_id} ({entry.kind}) - updated {stamp}"


# ----------------------------------------------------------------------
# CLI entrypoints
# ----------------------------------------------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Search CVEs using HTTPMR custom delta database")
    parser.add_argument("--search", help="Fuzzy search term (CVE id, partial)")
    parser.add_argument("--year", type=int, help="List CVEs for a specific year")
    parser.add_argument("--details", metavar="CVE-ID", help="Show JSON details for a CVE")
    parser.add_argument("--limit", type=int, default=25, help="Limit results")
    parser.add_argument("--use-deltalog", action="store_true", help="Use original deltaLog.json instead of custom delta")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    use_custom_delta = not args.use_deltalog
    library = CVELibrary(use_custom_delta=use_custom_delta)

    if args.details:
        record = library.get_cve_record(args.details.upper())
        if not record:
            print(f"No record found for {args.details}")
            return 1
        print(json.dumps(record, indent=2))
        return 0

    if args.search:
        matches = library.search(args.search, limit=args.limit)
        if not matches:
            print("No matches found.")
            return 0
        for entry in matches:
            print(_format_entry(entry))
        return 0

    if args.year:
        entries = library.list_entries_by_year(args.year, limit=args.limit)
        if not entries:
            source = "custom delta" if use_custom_delta else "delta log"
            print(f"No CVEs captured for {args.year} in {source}.")
            return 0
        for entry in entries:
            print(_format_entry(entry))
        return 0

    print("Available years (latest first):")
    for year in library.list_years():
        print(f"  - {year} ({len(library.list_entries_by_year(year))} entries)")
    source = "custom delta" if use_custom_delta else "delta log"
    print(f"Using {source} for queries. Use --use-deltalog to switch.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
