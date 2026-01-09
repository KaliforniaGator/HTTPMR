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
    """Loads deltaLog metadata and provides lookup helpers."""

    def __init__(self, delta_log: Path | None = None, cve_root: Path | None = None):
        self.delta_log = delta_log or DELTA_LOG_PATH
        self.cve_root = cve_root or CVE_ROOT
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

    def search(self, term: str, limit: int = 30) -> List[CVEEntry]:
        self._ensure_loaded()
        term = (term or "").strip()
        if not term:
            return []

        term_lower = term.lower()
        scored: List[tuple[float, CVEEntry]] = []
        for entry in self._entries:
            cid = entry.cve_id.lower()
            score = 0.0
            if term_lower == cid:
                score = 1.0
            elif term_lower in cid:
                score = 0.9
            else:
                blob = self._get_entry_search_blob(entry)
                if blob and term_lower in blob:
                    score = 0.78
                elif blob:
                    ratio = difflib.SequenceMatcher(None, term_lower, blob[:512]).ratio()
                    if ratio >= 0.4:
                        score = ratio * 0.85
                    else:
                        continue
                else:
                    ratio = difflib.SequenceMatcher(None, term_lower, cid).ratio()
                    if ratio < 0.35:
                        continue
                    score = ratio
            scored.append((score, entry))

        scored.sort(key=lambda tup: (tup[0], tup[1].iso_date()), reverse=True)
        return [entry for _, entry in scored[:limit]]

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
        if not self.delta_log.exists():
            self._entries = []
            self._by_year = {}
            self._loaded = True
            return

        with open(self.delta_log, "r") as fh:
            try:
                batches = json.load(fh)
            except json.JSONDecodeError:
                batches = []

        entries: List[CVEEntry] = []
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
    parser = argparse.ArgumentParser(description="Search CVEs using HTTPMR delta log")
    parser.add_argument("--search", help="Fuzzy search term (CVE id, partial)")
    parser.add_argument("--year", type=int, help="List CVEs for a specific year")
    parser.add_argument("--details", metavar="CVE-ID", help="Show JSON details for a CVE")
    parser.add_argument("--limit", type=int, default=25, help="Limit results")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    library = CVELibrary()

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
            print(f"No CVEs captured for {args.year} in delta log.")
            return 0
        for entry in entries:
            print(_format_entry(entry))
        return 0

    print("Available years (latest first):")
    for year in library.list_years():
        print(f"  - {year} ({len(library.list_entries_by_year(year))} entries)")
    print("Use --search, --year, or --details for specific queries.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
