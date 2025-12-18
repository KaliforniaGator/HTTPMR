# HTTPMR Toolset Overview

This document describes the HTTPMR toolset that exists in this workspace, what each component does, how it works, and how to use it. The content below only states facts observed in the repository and from recent work performed on the project.

## Project components (files)
- `HTTPMR.py` — The main scanner and report generator (v2.0). Implements:
  - Auto Mode: orchestrates multiple tests automatically against a target.
  - WordPress detection and version/theme extraction.
  - CVE testing for known WordPress vulnerabilities (tests include - but are not limited to - a 2024 CVE set and a placeholder 2025 CVE).
  - Server & port detection (header extraction and common port scanning).
  - Security headers analysis with a scoring system.
  - Payload builders (NoSQL, SSTI, SSRF) and shareable payload URLs.
  - JSON report export via `-o` or equivalent (Auto Mode writes JSON reports such as `test_report.json` and `auto_report.json`).

- `HTTPMR_Reader.py` (also present as `HTTPMR-Reader.py`) — A report interpreter that:
  - Loads JSON reports created by `HTTPMR.py`.
  - Presents a paged, human-friendly, explanatory CLI intended for non-technical stakeholders.
  - Includes a threat database with layman explanations, TTP mapping, business impact, and remediation guidance.
  - Uses ANSI colorized output via a `Color` helper and `colorize()` utility.
  - Has a fixed `display_page()` behavior that preserves previous printed content when a page is empty (prevents clearing content prior to "Press ENTER").

- `HTTPMR_Tester.py` — A report-driven tester used to verify findings in HTTPMR JSON reports. Key facts:
  - Runs safe, non-destructive verification checks by default.
  - Checks implemented include: user enumeration (REST API), XML-RPC endpoint reachability, oEmbed proxy traversal probe, stored XSS non-destructive checks, plugin-install reachability (CSRF proxy check), and security headers analysis.
  - Each verification result includes confidence, evidence and a mapped MITRE ATT&CK identifier (examples: `T1589`, `T1110`, `T1217`, `T1505`, `T1149`, `T1562` (approximation)).
  - Outputs a colorized terminal summary via `print_summary()`.
  - Requires explicit confirmation for aggressive lab tests: use `--mode aggressive` plus the `--confirm-lab` flag and an interactive `CONFIRM` prompt.
  - Supports an output flag `-o/--output` to save findings (report path and findings array) as JSON for downstream consumption.

- Example artifacts observed:
  - Example JSON reports created by Auto Mode: `test_report.json`, `auto_report.json`, and `denprohvac_scan.json`.

## Design & Safety facts
- Default behavior is safe: the tester and scanner prefer non-destructive probes and will not perform exploitative actions automatically.
- Aggressive/destructive checks are gated behind `--mode aggressive` and require `--confirm-lab` and an interactive typed `CONFIRM` to run.
- The toolset outputs JSON reports intended for downstream tooling, human review (via the Reader), and verification (via the Tester).

## How it works (high-level factual workflow)
1. `HTTPMR.py` runs scans against a target URL. Auto Mode runs the full pipeline which includes WordPress detection, CVE testing, server/port discovery, security header analysis, and more. The run produces a JSON report.
2. `HTTPMR_Reader.py` reads that JSON report and renders a paged, colorized, human-friendly summary and detailed explanations mapped to TTPs/techniques.
3. `HTTPMR_Tester.py` consumes the JSON report and performs safe verification checks to assess exploitability; results include confidence/evidence and MITRE ATT&CK mapping. Tester can optionally export its findings to JSON using `-o`.

## How to use (examples based on repository files)
- Run an Auto Mode scan (example - adjust target URL and flags in your environment):

```bash
# from repository root (e.g., `./`)
python HTTPMR.py --auto --target example.com -o auto_report.json
```

- Read a generated report with the reader (interactive paged CLI):

```bash
python HTTPMR_Reader.py auto_report.json
```

- Run the tester in safe mode (default) and see colorized output:

```bash
python HTTPMR_Tester.py -r test_report.json
```

- Run the tester in aggressive/lab mode (requires explicit flag and interactive confirmation):

```bash
python HTTPMR_Tester.py -r test_report.json --mode aggressive --confirm-lab
# Then type CONFIRM when prompted to proceed.
```

- Save tester findings to a JSON file for automation or ticketing systems:

```bash
python HTTPMR_Tester.py -r test_report.json -o tester_findings.json
```

## Known limitations & factual notes
- The MITRE ATT&CK mappings in `HTTPMR_Tester.py` are approximations added to each check (they are included in the output and JSON findings).
- The reader includes a pre-populated threat database containing CVE and threat explanations; additional mappings can be added to the `THREAT_DATABASE` in `HTTPMR_Reader.py`.
- The toolset uses `requests`, `json`, `socket`, `urllib.parse`, and standard Python libraries; ensure your Python environment has `requests` installed.

## Files of interest (relative paths)
- `./HTTPMR.py`
- `./HTTPMR_Reader.py` (and `HTTPMR-Reader.py` copy)
- `./HTTPMR_Tester.py`
- Example reports: `./test_report.json`, `./auto_report.json`


