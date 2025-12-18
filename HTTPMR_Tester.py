#!/usr/bin/env python3
"""
HTTPMR Tester - Report-driven verification module

This tool consumes HTTPMR JSON reports and performs safe, non-destructive
verification checks to determine whether reported findings are likely
exploitable by an attacker. It maps checks to MITRE techniques and
provides confidence and recommended next steps for red-team validation.

Default mode: SAFE (no destructive exploits, only verification/footprinting).
Use `--mode aggressive` only in controlled lab environments with explicit
authorization (the tool will warn and requires confirmation).
"""

import json
import sys
import argparse
import requests
import re
from typing import Dict, Any, List

from HTTPMR_Reader import get_threat_info, colorize, Color


def load_report(path: str) -> Dict[str, Any]:
    with open(path, 'r') as f:
        return json.load(f)


def safe_request_get(url: str, timeout: int = 6) -> Dict[str, Any]:
    """Perform a safe GET with basic error handling."""
    try:
        resp = requests.get(url if url.startswith(("http://", "https://")) else f"https://{url}", timeout=timeout)
        return {"status": resp.status_code, "text": resp.text, "headers": dict(resp.headers)}
    except Exception as e:
        return {"status": None, "error": str(e)}


def verify_user_enumeration(report: Dict[str, Any]) -> Dict[str, Any]:
    # If report flagged CVE-2024-25157 or REST users endpoint accessible
    tests = report.get('tests', {})
    cves = tests.get('cves', [])
    # MITRE ATT&CK mapping: T1589 - Gather Victim Identity Information
    result = {"check": "User Enumeration (REST API)", "exposed": False, "confidence": 0, "evidence": None, "mitre": ["T1589"]}

    for c in cves:
        if c.get('cve') == 'CVE-2024-25157':
            # If previously reported vulnerable, raise confidence
            if c.get('vulnerable') is True:
                result.update({"exposed": True, "confidence": 80, "evidence": c.get('description')})
                return result

    # Safe verification: request /wp-json/wp/v2/users
    url = report.get('url')
    if not url:
        return result

    resp = safe_request_get(f"{url.rstrip('/')}/wp-json/wp/v2/users")
    if resp.get('status') == 200:
        # Try to parse as JSON to see if user list returned
        try:
            data = requests.get(f"{url.rstrip('/')}/wp-json/wp/v2/users", timeout=6).json()
            if isinstance(data, list) and len(data) > 0:
                result.update({"exposed": True, "confidence": 90, "evidence": f"Returned {len(data)} users"})
            else:
                result.update({"exposed": False, "confidence": 20, "evidence": "REST returned 200 but no user list"})
        except Exception as e:
            result.update({"exposed": False, "confidence": 10, "evidence": f"Parse error: {e}"})
    else:
        result.update({"exposed": False, "confidence": 5, "evidence": resp.get('error') or resp.get('status')})

    return result


def verify_xmlrpc(report: Dict[str, Any]) -> Dict[str, Any]:
    # Check if xmlrpc was reported enabled and verify endpoint reachable
    url = report.get('url')
    # MITRE ATT&CK mapping: T1110 - Brute Force
    result = {"check": "XML-RPC Endpoint", "exposed": False, "confidence": 0, "evidence": None, "mitre": ["T1110"]}
    if not url:
        return result

    resp = safe_request_get(f"{url.rstrip('/')}/xmlrpc.php")
    if resp.get('status') == 200 and resp.get('text') and ('xmlrpc' in (resp.get('text') or '').lower() or '<?xml' in (resp.get('text') or '')):
        result.update({"exposed": True, "confidence": 80, "evidence": "xmlrpc.php responded"})
    elif resp.get('status') in (403, 401, 404):
        result.update({"exposed": False, "confidence": 30, "evidence": f"HTTP {resp.get('status')}"})
    else:
        if resp.get('status') is None:
            result.update({"exposed": False, "confidence": 5, "evidence": resp.get('error')})
        else:
            result.update({"exposed": False, "confidence": 10, "evidence": f"HTTP {resp.get('status')}"})

    return result


def verify_oembed_traversal(report: Dict[str, Any]) -> Dict[str, Any]:
    # Non-destructive check: call oEmbed proxy with a harmless remote URL and observe response
    url = report.get('url')
    # MITRE ATT&CK mapping: T1217 - Local Discovery / Enumerate Local System Information
    result = {"check": "oEmbed Directory Traversal (non-destructive check)", "likely": False, "confidence": 0, "evidence": None, "mitre": ["T1217"]}
    if not url:
        return result

    # Use a safe remote URL known to return a small response (example: https://example.com)
    target = "https://example.com/"
    probe = f"{url.rstrip('/')}/wp-json/oembed/1.0/proxy?url={target}"
    resp = safe_request_get(probe)
    if resp.get('status') == 200 and 'example' in (resp.get('text') or '').lower():
        # oEmbed proxy returned remote contents (expected), reduce suspicion
        result.update({"likely": False, "confidence": 20, "evidence": "oEmbed proxy returned remote site content"})
    elif resp.get('status') == 200 and ('root:' in (resp.get('text') or '') or 'wp-config' in (resp.get('text') or '')):
        # Defensive: if server returns files content, we flag higher
        result.update({"likely": True, "confidence": 95, "evidence": "Sensitive file content detected in proxy response"})
    else:
        # ambiguous
        result.update({"likely": False, "confidence": 10, "evidence": resp.get('error') or resp.get('status')})

    return result


def verify_xss(report: Dict[str, Any]) -> Dict[str, Any]:
    # Non-destructive detection: query pages endpoint and look for unescaped script tags
    url = report.get('url')
    # MITRE ATT&CK mapping: T1505 - Stored XSS / Web Shell style persistence
    result = {"check": "Stored XSS (non-destructive)", "likely": False, "confidence": 0, "evidence": None, "mitre": ["T1505"]}
    if not url:
        return result

    resp = safe_request_get(f"{url.rstrip('/')}/wp-json/wp/v2/pages")
    if resp.get('status') == 200:
        body = (resp.get('text') or '').lower()
        if '<script' in body or 'onclick=' in body:
            result.update({"likely": True, "confidence": 85, "evidence": "Script tags or event handlers found in page JSON"})
        else:
            result.update({"likely": False, "confidence": 20, "evidence": "No obvious script markers in pages endpoint"})
    else:
        result.update({"likely": False, "confidence": 10, "evidence": resp.get('error') or resp.get('status')})

    return result


def verify_plugin_csrf(report: Dict[str, Any]) -> Dict[str, Any]:
    # Do NOT attempt to install plugins. Instead, verify if plugin-install.php is reachable
    url = report.get('url')
    # MITRE ATT&CK mapping: T1149 - Social Engineering (used as a proxy for CSRF flows)
    result = {"check": "Plugin Install CSRF (reachability)", "risky": False, "confidence": 0, "evidence": None, "mitre": ["T1149"]}
    if not url:
        return result

    resp = safe_request_get(f"{url.rstrip('/')}/wp-admin/plugin-install.php?tab=featured")
    if resp.get('status') == 200:
        # Page accessible; could be CSRFable if admin is logged-in and CSRF protections absent
        result.update({"risky": True, "confidence": 60, "evidence": "plugin-install.php returned 200 (accessible without auth?)"})
    elif resp.get('status') == 302:
        result.update({"risky": False, "confidence": 80, "evidence": "Redirect to login - likely protected"})
    else:
        result.update({"risky": False, "confidence": 20, "evidence": resp.get('error') or resp.get('status')})

    return result


def verify_headers(report: Dict[str, Any]) -> Dict[str, Any]:
    # Map missing security controls to ATT&CK defensive-evasion/adversary techniques where relevant
    headers = report.get('tests', {}).get('security_headers', {})
    missing = headers.get('missing', [])
    score = headers.get('score', 0)
    mitre_map = ["T1562"] if missing else []  # T1562: Impair Defenses (approximation)
    return {"check": "Security Headers", "missing": missing, "score": score, "recommendation": "Add missing headers: " + ", ".join(missing) if missing else "All present", "mitre": mitre_map}


def run_all_checks(report: Dict[str, Any], mode: str = 'safe') -> List[Dict[str, Any]]:
    findings = []
    # Map of checks to run
    findings.append(verify_user_enumeration(report))
    findings.append(verify_xmlrpc(report))
    findings.append(verify_oembed_traversal(report))
    findings.append(verify_xss(report))
    findings.append(verify_plugin_csrf(report))
    findings.append(verify_headers(report))

    # Add guidance for aggressive mode (not implemented exploiters)
    if mode == 'aggressive':
        findings.append({"note": "Aggressive checks require manual, controlled testing in a lab. This tool will not perform destructive exploits automatically."})

    return findings


def print_summary(report_path: str, findings: List[Dict[str, Any]]):
    # Pretty, colorized summary output
    print("\n" + colorize("=" * 60, Color.BLUE))
    print(colorize("HTTPMR TESTER - VERIFICATION SUMMARY", Color.BOLD + Color.CYAN))
    print(colorize("=" * 60 + "\n", Color.BLUE))
    print(f"Report: {colorize(report_path, Color.BOLD)}\n")

    def _fmt_val(k: str, v: Any) -> str:
        if isinstance(v, bool):
            return colorize(str(v), Color.RED if v else Color.GREEN)
        if isinstance(v, int):
            return colorize(str(v), Color.YELLOW if v < 50 else Color.GREEN)
        if v is None:
            return colorize('N/A', Color.DIM)
        return str(v)

    for f in findings:
        if 'check' in f:
            # Determine header color by severity flags
            header_color = Color.GREEN
            if f.get('exposed') or f.get('risky') or f.get('likely'):
                header_color = Color.RED
            elif f.get('confidence', 0) >= 70:
                header_color = Color.YELLOW

            print(colorize(f"- {f['check']}", header_color))
            keys = [k for k in f.keys() if k not in ('check',)]
            for k in keys:
                val = _fmt_val(k, f[k])
                # show mitre tags in magenta for quick scanning
                if k == 'mitre' and isinstance(f[k], list):
                    val = colorize(', '.join(f[k]), Color.MAGENTA)
                print(f"    {colorize(k + ':', Color.CYAN)} {val}")
            print()
        else:
            print(colorize(f"- Note: {f.get('note')}", Color.YELLOW) + "\n")


def main():
    parser = argparse.ArgumentParser(description='HTTPMR Report Tester - Safe verification checks')
    parser.add_argument('--report', '-r', required=True, help='Path to HTTPMR JSON report')
    parser.add_argument('--mode', choices=['safe', 'aggressive'], default='safe', help='Test mode (safe/aggressive)')
    parser.add_argument('--confirm-lab', action='store_true', dest='confirm_lab', help='Explicit confirmation to run lab-only aggressive checks')
    parser.add_argument('-o', '--output', dest='output', help='Write findings to JSON file')
    args = parser.parse_args()

    report_path = args.report
    try:
        report = load_report(report_path)
    except Exception as e:
        print(colorize(f"Failed to load report: {e}", "\033[91m"))
        sys.exit(1)

    if args.mode == 'aggressive':
        print(colorize("AGGRESSIVE MODE selected. Ensure you have authorization and are in a lab environment.", "\033[93m"))
        if not getattr(args, 'confirm_lab', False):
            print(colorize("ERROR: Aggressive mode requires explicit --confirm-lab flag. Aborting.", "\033[91m"))
            sys.exit(2)
        # Interactive confirmation to avoid accidental destructive runs
        try:
            resp = input(colorize("Type 'CONFIRM' to proceed with aggressive lab checks: ", "\033[93m"))
        except KeyboardInterrupt:
            print(colorize("Aborted by user.", "\033[91m"))
            sys.exit(2)
        if resp.strip() != 'CONFIRM':
            print(colorize("Confirmation failed. Aborting aggressive checks.", "\033[91m"))
            sys.exit(2)

    findings = run_all_checks(report, mode=args.mode)
    print_summary(report_path, findings)

    # Optionally dump findings to JSON for downstream use
    if getattr(args, 'output', None):
        out_path = args.output
        try:
            with open(out_path, 'w') as f:
                json.dump({"report": report_path, "findings": findings}, f, indent=2)
            print(colorize(f"Findings written to: {out_path}", Color.GREEN))
        except Exception as e:
            print(colorize(f"Failed to write output file: {e}", Color.RED))


if __name__ == '__main__':
    main()
