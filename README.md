# HTTPMR Toolset

This repository contains HTTPMR — a lightweight HTTP reconnaissance, vulnerability discovery, and verification toolset with a browser-based Web UI and standardized report export (SARIF).

**Quick summary**
- **Scanner:** `HTTPMR.py` — auto/full scans, WordPress detection & CVE checks, server/port discovery, security headers analysis, payload builders (NoSQL / SSTI / SSRF), and JSON report output.
- **Reader:** `HTTPMR_Reader.py` — CLI report viewer that loads JSON reports and presents a paged, colorized, human-friendly summary with remediation guidance.
- **Tester:** `HTTPMR_Tester.py` — report-driven verifier that re-checks findings (safe-by-default). Outputs colorized summaries and can save findings to JSON.
- **Web UI:** `webui/` — FastAPI app with a dashboard, live-run view (WebSocket streaming), report viewer, SARIF conversion, and the ability to run the `Tester` from a report.
- **SARIF export:** `sarif_exporter.py` — converts HTTPMR JSON reports into SARIF 2.1.0 compatible output (minimal rules & results).

**Notable helpers**
- `run_webui.sh` — create a `.venv`, install dependencies from `requirements.txt`, and start the Web UI (uvicorn). Use this for a quick start.
- `clean_pycache.sh` — remove Python bytecode caches and test artifacts.

**Recent / Important Features**
- Web UI (FastAPI) with:
  - Dashboard to start scans and upload reports.
  - Live streaming run page using WebSockets (stdout/stderr streamed line-by-line).
  - Client-side ANSI → HTML rendering for colored logs (`ansi_up` used in `run.html`).
  - Report viewer with export-to-SARIF and delete actions.
  - "Run Tester" button on each report to spawn `HTTPMR_Tester.py` and stream verification output live.
- SARIF export on report save and via on-demand conversion endpoint (`/convert_sarif`).
- Reports saved to the repository root as `scan_<target>_<ts>.json` (SARIF companion: `<same>.sarif.json`).
- Web UI normalizes legacy single-request JSON reports into a consistent `tests` structure (original content preserved under `legacy`) so the UI can reliably render summaries.

Security note
- The Web UI currently has no authentication. Do not expose it to untrusted networks. Adding token-based auth or reverse-proxy + TLS is recommended before public exposure.

Getting started (local)
1. Create and activate a venv, install deps, and run the Web UI quickly:

```bash
./run_webui.sh
# or manually:
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
.venv/bin/uvicorn webui.app:app --reload --host 127.0.0.1 --port 8000
```

2. **For CVE data (optional but recommended):** Download actual CVE data from https://www.cve.org/downloads, download the `main.zip` file, and extract its contents into a `cves` folder in the HTTPMR directory.

3. Open the dashboard at `http://127.0.0.1:8000/`.

4. Start a scan from the dashboard (enter a host like `example.com`), view live colored logs on the run page, and view the generated report when finished.

CLI examples
- Run an Auto Mode scan and save JSON:

```bash
python HTTPMR.py --auto --target example.com -o scan_example.json
```

- Read a JSON report with the CLI reader:

```bash
python HTTPMR_Reader.py scan_example.json
```

- Run the Tester against an existing report (safe-by-default):

```bash
python HTTPMR_Tester.py --report scan_example.json -o tester_results.json
```

Developer notes & TODOs
- Job state and live logs are currently stored in-memory in `webui/app.py`. If you need persistence across restarts, add per-job log files or a small database.
- Add authentication (token-based or OAuth) to the Web UI before exposing externally.
- SARIF exporter is intentionally minimal. If you need richer rule metadata, extend `sarif_exporter.convert_report_to_sarif()`.
- The Web UI normalizes older report formats into a `tests` dict and preserves original content under `legacy` — change this behavior if you prefer merging instead of nesting.

Files of interest
- `HTTPMR.py` — scanner
- `HTTPMR_Reader.py` — CLI reader
- `HTTPMR_Tester.py` — verifier/tester
- `sarif_exporter.py` — SARIF conversion
- `webui/app.py` — FastAPI backend
- `webui/templates/` — UI templates (`dashboard.html`, `run.html`, `report.html`)
- `requirements.txt` — Python dependencies for Web UI
- `run_webui.sh`, `clean_pycache.sh` — helpers

License & safety
- This toolset is designed for authorized security testing only. Do not use it against systems you do not own or have explicit permission to test. The project contains safety gates for destructive actions, but operational risk remains — use responsibly.

If you want, I can also:
- Replace this README content into the old `HTTPMR_TOOLSET_OVERVIEW.md` (rename) and remove the original file.
- Add a short `README` section that documents the Web UI API endpoints for automation.

---
Generated: an updated project README reflecting the current Web UI and SARIF integrations.
