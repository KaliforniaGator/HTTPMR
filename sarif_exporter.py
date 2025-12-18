"""
SARIF Exporter for HTTPMR reports

Converts HTTPMR JSON reports into a minimal SARIF 2.1.0 structure and
adds MITRE ATT&CK metadata into the result properties for downstream
consumption by SOAR/SIEM tools.

Usage:
    python sarif_exporter.py input_report.json output.sarif.json

This is intentionally minimal and conservative — it will not add
exploit payloads or other sensitive data into SARIF results.
"""
import json
import sys
from typing import Dict, Any, List

SARIF_VERSION = "2.1.0"


def _level_from_severity(sev: str) -> str:
    sev = (sev or "").lower()
    if sev in ("critical", "high"):
        return "error"
    if sev in ("medium", "moderate"):
        return "warning"
    return "note"


def convert_report_to_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    runs = []

    tool_driver = {
        "name": "HTTPMR",
        "version": report.get('tool_version', '2.0'),
        "informationUri": "https://example.local/HTTPMR",
        "rules": []
    }

    results: List[Dict[str, Any]] = []

    # 1) CVE style findings under tests.cves
    for c in report.get('tests', {}).get('cves', []) or []:
        rule_id = c.get('cve') or c.get('id') or 'CVE-UNKNOWN'
        message = c.get('description') or c.get('summary') or c.get('title') or str(c)
        severity = c.get('severity', 'medium')
        level = _level_from_severity(severity)

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "properties": {
                "confidence": c.get('confidence'),
                "vulnerable": c.get('vulnerable'),
                "mitre": c.get('mitre', [])
            }
        })

    # 2) Security headers missing -> create one result per missing header
    sh = report.get('tests', {}).get('security_headers', {}) or {}
    for h in sh.get('missing', []) or []:
        results.append({
            "ruleId": f"SEC_HEADER_MISSING::{h}",
            "level": _level_from_severity('medium'),
            "message": {"text": f"Missing security header: {h}"},
            "properties": {"category": "security-headers", "header": h}
        })

    # 3) Generic analysis indicators (from analysis.indicators)
    for ind in (report.get('analysis', {}).get('indicators') or []):
        # indicator items in HTTPMR are often tuples-like [level, message]
        if isinstance(ind, dict):
            lvl = ind.get('level')
            msg = ind.get('message')
        elif isinstance(ind, (list, tuple)) and len(ind) >= 2:
            lvl, msg = ind[0], ind[1]
        else:
            lvl, msg = 'info', str(ind)

        results.append({
            "ruleId": f"INDICATOR::{lvl}",
            "level": _level_from_severity('low'),
            "message": {"text": msg},
            "properties": {"indicator_level": lvl}
        })

    # 4) Add server info as an informational run-level property
    run = {
        "tool": {"driver": tool_driver},
        "results": results,
        "properties": {
            "target": report.get('url'),
            "timestamp": report.get('timestamp')
        }
    }

    runs.append(run)

    sarif = {
        "version": SARIF_VERSION,
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": runs
    }

    return sarif


def main(argv: List[str]):
    if len(argv) < 2:
        print("Usage: python sarif_exporter.py input_report.json [output.sarif.json]")
        return 1

    in_path = argv[0]
    out_path = argv[1] if len(argv) > 1 else in_path.replace('.json', '.sarif.json')

    with open(in_path, 'r') as f:
        report = json.load(f)

    sarif = convert_report_to_sarif(report)

    with open(out_path, 'w') as f:
        json.dump(sarif, f, indent=2)

    print(f"SARIF written to: {out_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
