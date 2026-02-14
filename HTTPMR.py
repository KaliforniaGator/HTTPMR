import os
import sys
import json
import time
import re
import socket
from urllib.parse import urlencode

import requests

# optional SARIF exporter integration
try:
    import sarif_exporter
except Exception:
    sarif_exporter = None

# Settings and API integration
try:
    from settings_integration import enhance_cve_with_external_apis, is_real_time_scans_enabled
    SETTINGS_AVAILABLE = True
except ImportError:
    SETTINGS_AVAILABLE = False

    def enhance_cve_with_external_apis(cve_data):
        return cve_data

    def is_real_time_scans_enabled():
        return False

# Paths & configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECURE_DIR = os.path.join(BASE_DIR, ".secure")
BUILTIN_CVE_CONFIG_PATH = os.path.join(SECURE_DIR, "built-in-cves.config")
_CVE_CONFIG_CACHE = []
_CVE_CONFIG_MTIME = 0.0

# -----------------------------
# Terminal helpers
# -----------------------------

class Color:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


def colorize(text, color):
    return f"{color}{text}{Color.RESET}"


def load_builtin_cve_definitions():
    """Load CVE definitions from .secure/built-in-cves.config with caching."""
    global _CVE_CONFIG_CACHE, _CVE_CONFIG_MTIME

    try:
        mtime = os.path.getmtime(BUILTIN_CVE_CONFIG_PATH)
    except OSError:
        if not _CVE_CONFIG_CACHE:
            print(colorize("[!] built-in CVE config not found. No WordPress CVEs will be tested.", Color.YELLOW))
        return _CVE_CONFIG_CACHE

    if not _CVE_CONFIG_CACHE or mtime != _CVE_CONFIG_MTIME:
        try:
            with open(BUILTIN_CVE_CONFIG_PATH, "r") as f:
                data = json.load(f)
            if isinstance(data, list):
                _CVE_CONFIG_CACHE = data
                _CVE_CONFIG_MTIME = mtime
            else:
                print(colorize("[!] built-in CVE config is not a list. Skipping load.", Color.RED))
        except json.JSONDecodeError as exc:
            print(colorize(f"[!] Unable to parse built-in CVE config: {exc}", Color.RED))
        except Exception as exc:
            print(colorize(f"[!] Unexpected error loading CVE config: {exc}", Color.RED))
    return _CVE_CONFIG_CACHE


def _filter_cve_definitions(platform=None, selected_ids=None):
    """Filter loaded CVE definitions by platform or explicit IDs."""
    definitions = load_builtin_cve_definitions()
    selected_set = {sid.upper() for sid in selected_ids} if selected_ids else None
    filtered = []

    for definition in definitions:
        cve_id = (definition.get("id") or "").upper()

        if platform and definition.get("platform") != platform:
            continue
        if selected_set and cve_id not in selected_set:
            continue
        if not cve_id:
            continue
        filtered.append(definition)

    return filtered


def _ensure_url_scheme(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _build_cve_request_url(base_url, request_cfg):
    base = _ensure_url_scheme(base_url).rstrip("/")
    path = request_cfg.get("path", "").strip()
    if path and not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


def _parse_json_response(resp):
    try:
        return resp.json()
    except ValueError:
        return None


def _evaluate_checks(defn, resp, parsed_json):
    """Evaluate configured checks against the HTTP response."""
    checks = defn.get("checks", [])
    if not checks:
        return True, "No checks specified; defaulting to pass."

    logic = (defn.get("checks_logic") or "all").lower()
    results = []
    lower_body = (resp.text or "").lower()

    for check in checks:
        ctype = check.get("type")
        values = check.get("values") or []
        outcome = False
        evidence = None

        if ctype == "status_code_in":
            outcome = resp.status_code in values
            evidence = f"status_code={resp.status_code}"
        elif ctype == "status_code_not_in":
            outcome = resp.status_code not in values
            evidence = f"status_code={resp.status_code}"
        elif ctype == "body_contains_any":
            matches = [val for val in values if val.lower() in lower_body]
            outcome = bool(matches)
            if matches:
                evidence = f"matched={matches[0]}"
        elif ctype == "json_array_min_length":
            target_len = check.get("value", 1)
            if isinstance(parsed_json, list):
                outcome = len(parsed_json) >= target_len
                evidence = f"json_len={len(parsed_json)}"
            else:
                outcome = False
                evidence = "json_not_array"
        else:
            evidence = f"Unsupported check type {ctype}"

        results.append({"passed": outcome, "evidence": evidence})

    if logic == "any":
        passed = any(r["passed"] for r in results)
    else:  # default to 'all'
        passed = all(r["passed"] for r in results)

    return passed, results


def _run_version_handler(url, definition):
    """Special handler for version disclosure detection."""
    result = {
        "cve": definition.get("id"),
        "title": definition.get("title"),
        "description": definition.get("description"),
        "mitre": definition.get("mitre", []),
        "vulnerable": False
    }
    feed_url = _ensure_url_scheme(url).rstrip("/") + "/?feed=rss2"
    try:
        resp = requests.get(feed_url, timeout=10, allow_redirects=True)
        version_match = re.search(r'<generator>https://wordpress.org/\?v=([0-9.]+)</generator>', resp.text)
        if version_match:
            version = version_match.group(1)
            result.update({
                "vulnerable": "detected",
                "version": version,
                "confidence": definition.get("success", {}).get("confidence", 100),
                "description": definition.get("success", {}).get("message", "Version detected via RSS feed")
            })
        else:
            result.update({
                "vulnerable": False,
                "confidence": definition.get("failure", {}).get("confidence", 20),
                "description": definition.get("failure", {}).get("message", "Version not observed in RSS feed")
            })
    except Exception as exc:
        result.update({
            "vulnerable": False,
            "confidence": 0,
            "error": str(exc)
        })
    return result


def _execute_cve_definition(url, definition):
    """Execute a single CVE definition against the target."""
    result = {
        "cve": definition.get("id"),
        "title": definition.get("title"),
        "description": definition.get("description"),
        "mitre": definition.get("mitre", []),
        "vulnerable": False
    }

    if not definition.get("enabled", True):
        result.update({"vulnerable": False, "description": "CVE check disabled in config"})
        return result

    handler = definition.get("handler")
    if handler:
        if handler == "wordpress_version_feed":
            return _run_version_handler(url, definition)
        result.update({"error": f"Unknown handler '{handler}'"})
        return result

    request_cfg = definition.get("request") or {}
    target_url = _build_cve_request_url(url, request_cfg)
    method = request_cfg.get("method", "GET").upper()
    timeout = request_cfg.get("timeout", 10)
    query = request_cfg.get("query")
    headers = request_cfg.get("headers")

    try:
        resp = requests.request(
            method=method,
            url=target_url,
            params=query if method == "GET" else None,
            json=request_cfg.get("json") if method != "GET" else None,
            data=request_cfg.get("data") if method != "GET" else None,
            headers=headers,
            timeout=timeout,
            allow_redirects=True
        )
        parsed_json = _parse_json_response(resp)
        passed, check_evidence = _evaluate_checks(definition, resp, parsed_json)

        evidence_summary = check_evidence if isinstance(check_evidence, list) else [{"info": check_evidence}]
        success_cfg = definition.get("success", {})
        failure_cfg = definition.get("failure", {})

        if passed:
            result.update({
                "vulnerable": True,
                "confidence": success_cfg.get("confidence", 80),
                "description": success_cfg.get("message", "Checks passed"),
                "evidence": evidence_summary,
                "response_snippet": resp.text[:200]
            })
        else:
            result.update({
                "vulnerable": False,
                "confidence": failure_cfg.get("confidence", 20),
                "description": failure_cfg.get("message", "Checks failed"),
                "evidence": evidence_summary,
                "response_snippet": resp.text[:200]
            })
    except Exception as exc:
        failure_cfg = definition.get("failure") or {}
        result.update({
            "vulnerable": False,
            "confidence": 0,
            "description": failure_cfg.get("message", "Request failed"),
            "error": str(exc)
        })

    return result


# -----------------------------
# Preset payloads
# -----------------------------

PRESETS = {
    "nosql_basic": {
        "id[$ne]": "1"
    },
    "nosql_exists": {
        "user[$exists]": "true"
    },
    "nosql_always_true": {
        "id[$ne]": "__INVALID__"
    },
    "nosql_always_false": {
        "id[$eq]": "__INVALID__"
    },
    "ssti_basic": {
        "input": "{{7*7}}"
    },
    "ssrf_metadata": {
        "url": "http://169.254.169.254/"
    }
}

# -----------------------------
# Helpers
# -----------------------------

def prompt(msg, default=None):
    value = input(f"{msg}{f' [{default}]' if default else ''}: ").strip()
    return value if value else default

def log_step(step_num, description, verbose=False):
    """Log a progress step."""
    if verbose:
        print(f"{Color.CYAN}[Step {step_num}]{Color.RESET} {description}")

def choose_method():
    methods = ["GET", "POST", "PUT", "DELETE"]
    for i, m in enumerate(methods, 1):
        print(f"{i}. {m}")
    return methods[int(input("Select HTTP method: ")) - 1]

def choose_preset():
    print("\nPayload presets:")
    print("0. None (manual input)")
    for i, key in enumerate(PRESETS.keys(), 1):
        print(f"{i}. {key}")
    choice = int(input("Select preset: "))
    if choice == 0:
        return {}
    return PRESETS[list(PRESETS.keys())[choice - 1]]

def parse_params():
    print("\nEnter parameters (key=value). Empty line to finish.")
    params = {}
    while True:
        line = input("> ").strip()
        if not line:
            break
        if "=" not in line:
            print("Invalid format, use key=value")
            continue
        k, v = line.split("=", 1)
        params[k] = v
    return params

def build_payload_url(base_url, method, params):
    """Build a shareable payload URL for testing in browser."""
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    
    if method == "GET" and params:
        query_string = urlencode(params)
        return f"{base_url}?{query_string}"
    return base_url

def display_main_menu():
    """Display the main menu."""
    print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
    print("HTTPMR - HTTP Vulnerability Testing Tool v2.0")
    print(f"{'='*60}{Color.RESET}\n")
    print(f"{Color.CYAN}Main Menu:{Color.RESET}")
    print("1. General Vulnerability Test (NoSQL, SSTI, SSRF)")
    print("2. WordPress Site Testing & CVE Detection")
    print("3. Payload Builder (for manual browser testing)")
    print("4. Server & Port Detection")
    print("5. Security Headers Analysis")
    print("6. Auto Mode (Full Comprehensive Test)")
    print("7. Exit")
    return prompt("\nSelect option", "1")

def display_wordpress_menu():
    """Display WordPress testing options."""
    print(f"\n{Color.BOLD}{Color.MAGENTA}WordPress Security Testing{Color.RESET}\n")
    print("1. Automatic WordPress & CVE Scan")
    print("2. Select Specific CVEs to Test")
    print("3. WordPress Version Detection Only")
    print("4. Back to Main Menu")
    return prompt("\nSelect option", "1")

def display_cve_menu():
    """Display dynamic CVE selection menu from config."""
    definitions = _filter_cve_definitions(platform="wordpress")
    if not definitions:
        print(colorize("\n[!] No built-in CVE definitions available.", Color.RED))
        prompt("Press Enter to continue")
        return "7"

    print(f"\n{Color.BOLD}{Color.MAGENTA}Select WordPress CVEs to Test:{Color.RESET}\n")

    index_map = {}
    for idx, definition in enumerate(definitions, 1):
        print(f"{idx}. {definition.get('id', 'UNKNOWN')} - {definition.get('title', 'No description')}")
        index_map[str(idx)] = definition.get('id')

    all_option = str(len(definitions) + 1)
    back_option = str(len(definitions) + 2)
    print(f"{all_option}. Run ALL configured CVEs")
    print(f"{back_option}. Back to menu")

    choice = prompt("\nSelect option", all_option)
    if choice == back_option:
        return "BACK"
    if choice == all_option:
        return "ALL"
    return index_map.get(choice)

def display_payload_builder_menu():
    """Display payload builder options."""
    print(f"\n{Color.BOLD}{Color.MAGENTA}Payload Builder{Color.RESET}\n")
    print("1. Build NoSQL Injection Payload")
    print("2. Build SSTI Payload")
    print("3. Build SSRF Payload")
    print("4. Build Custom Payload")
    print("5. Back to Main Menu")
    return prompt("\nSelect option", "1")

def build_nosql_payload(base_url):
    """Build NoSQL injection payloads."""
    print(f"\n{Color.CYAN}NoSQL Injection Payload Builder{Color.RESET}")
    print("\nPayload Types:")
    print("1. Bypass Authentication (id[$ne]: 1)")
    print("2. Check Field Existence (user[$exists]: true)")
    print("3. Always True (id[$ne]: __INVALID__)")
    print("4. Custom Operator")
    
    choice = prompt("Select type", "1")
    
    payloads = {
        "1": {"id[$ne]": "1"},
        "2": {"user[$exists]": "true"},
        "3": {"id[$ne]": "__INVALID__"},
    }
    
    if choice in payloads:
        payload = payloads[choice]
    else:
        operator = prompt("Enter operator (e.g., $ne, $exists, $gt)")
        field = prompt("Enter field name")
        value = prompt("Enter value")
        payload = {f"{field}[${operator}]": value}
    
    url = build_payload_url(base_url, "GET", payload)
    print(f"\n{Color.GREEN}Generated Payload URL:{Color.RESET}")
    print(f"{Color.DIM}{url}{Color.RESET}")
    return payload

def build_ssti_payload(base_url):
    """Build SSTI payloads."""
    print(f"\n{Color.CYAN}SSTI Payload Builder{Color.RESET}")
    print("\nPayload Types:")
    print("1. Basic Math ({{7*7}})")
    print("2. Jinja2 Config (__import__('os').popen('id').read())")
    print("3. Freemarker Payload")
    print("4. Custom SSTI")
    
    choice = prompt("Select type", "1")
    
    payloads = {
        "1": {"input": "{{7*7}}"},
        "2": {"input": "{{7*7}} - Check for 49 in response"},
        "3": {"input": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('id')}"},
    }
    
    if choice in payloads:
        payload = payloads[choice]
    else:
        custom = prompt("Enter custom SSTI payload")
        payload = {"input": custom}
    
    url = build_payload_url(base_url, "GET", payload)
    print(f"\n{Color.GREEN}Generated Payload URL:{Color.RESET}")
    print(f"{Color.DIM}{url}{Color.RESET}")
    return payload

def build_ssrf_payload(base_url):
    """Build SSRF payloads."""
    print(f"\n{Color.CYAN}SSRF Payload Builder{Color.RESET}")
    print("\nTarget Services:")
    print("1. AWS Metadata (169.254.169.254)")
    print("2. Internal Service (localhost:8080)")
    print("3. Custom Target")
    
    choice = prompt("Select target", "1")
    
    targets = {
        "1": "http://169.254.169.254/latest/meta-data/",
        "2": "http://localhost:8080/",
    }
    
    if choice in targets:
        target = targets[choice]
    else:
        target = prompt("Enter target URL")
    
    payload = {"url": target}
    url = build_payload_url(base_url, "GET", payload)
    print(f"\n{Color.GREEN}Generated Payload URL:{Color.RESET}")
    print(f"{Color.DIM}{url}{Color.RESET}")
    return payload

def build_custom_payload(base_url):
    """Build completely custom payload."""
    print(f"\n{Color.CYAN}Custom Payload Builder{Color.RESET}")
    print("Build your own payload manually.")
    
    params = parse_params()
    
    if not params:
        print(colorize("No parameters provided", Color.YELLOW))
        return None
    
    url = build_payload_url(base_url, "GET", params)
    print(f"\n{Color.GREEN}Generated Payload URL:{Color.RESET}")
    print(f"{Color.DIM}{url}{Color.RESET}")
    
    # Also show as POST JSON
    print(f"\n{Color.GREEN}POST JSON Body:{Color.RESET}")
    print(f"{Color.DIM}{json.dumps(params, indent=2)}{Color.RESET}")
    
    return params

def send_request(url, method, params, json_body, verbose=False):
    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    if verbose:
        log_step(1, f"Preparing request to {colorize(url, Color.BOLD)}")
        log_step(2, f"HTTP Method: {colorize(method, Color.BOLD)}")
        if params:
            log_step(3, f"Query Parameters: {colorize(json.dumps(params, indent=2), Color.DIM)}")
        if json_body:
            log_step(3, f"Request Body: {colorize(json.dumps(json_body, indent=2), Color.DIM)}")
        log_step(4, "Sending request...")
    
    start = time.time()
    resp = requests.request(
        method=method,
        url=url,
        params=params if method == "GET" else None,
        json=json_body if method != "GET" else None,
        timeout=10
    )
    elapsed = time.time() - start
    
    if verbose:
        log_step(5, f"Response received in {colorize(f'{elapsed:.2f}s', Color.CYAN)}")
    
    return resp, elapsed

def detect_vulnerability_indicators(resp, payload_params):
    """Analyze response for potential vulnerability indicators."""
    indicators = []
    response_text_lower = resp.text.lower()
    
    # NoSQL injection indicators
    if any(k in payload_params for k in ["id[$ne]", "user[$exists]"]):
        if "error" not in response_text_lower and "exception" not in response_text_lower:
            if resp.status_code == 200 and len(resp.text) > 100:
                indicators.append(("SUSPICIOUS", "NoSQL payload returned 200 with normal response (may bypass auth)"))
        elif "error" in response_text_lower or "exception" in response_text_lower:
            indicators.append(("LIKELY_VULNERABLE", "NoSQL payload triggered database error"))
    
    # SSTI indicators
    if "input" in payload_params and "{{7*7}}" in str(payload_params.get("input", "")):
        if "49" in resp.text or "7*7" not in resp.text:
            indicators.append(("LIKELY_VULNERABLE", "SSTI payload evaluated (49 found or payload escaped)"))
    
    # SSRF indicators
    if "169.254.169.254" in str(payload_params):
        if resp.status_code == 200 and len(resp.text) > 50:
            indicators.append(("SUSPICIOUS", "SSRF payload got a response (may have internal access)"))
        elif "404" not in str(resp.status_code) and "timeout" not in response_text_lower:
            indicators.append(("LIKELY_VULNERABLE", "SSRF payload did not timeout or error"))
    
    return indicators

def save_json_report(output_file, url, method, payload_params, resp, elapsed, wordpress_results=None):
    """Save test results to a JSON file."""
    indicators = detect_vulnerability_indicators(resp, payload_params)
    
    # Ensure output file is in reports directory
    if not os.path.dirname(output_file):
        reports_dir = os.path.join(os.path.dirname(__file__), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        output_file = os.path.join(reports_dir, output_file)
    
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "test_config": {
            "url": url,
            "method": method,
            "payload": payload_params
        },
        "response": {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
            "elapsed_time": elapsed,
            "content_length": len(resp.text)
        },
        "analysis": {
            "indicators": [{"level": level, "message": msg} for level, msg in indicators],
            "summary": "vulnerable" if any(level == "LIKELY_VULNERABLE" for level, _ in indicators) else "suspicious" if indicators else "clean"
        }
    }
    
    # Add WordPress analysis if available
    if wordpress_results:
        report["wordpress_analysis"] = wordpress_results
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    # Also write SARIF export (if exporter available)
    try:
        if sarif_exporter:
            sarif = sarif_exporter.convert_report_to_sarif(report)
            sarif_path = output_file.replace('.json', '.sarif.json')
            with open(sarif_path, 'w') as sf:
                json.dump(sarif, sf, indent=2)
            print(f"[+] SARIF export written: {sarif_path}")
    except Exception as e:
        print(f"[!] Failed to write SARIF export: {e}")
    
    return output_file

def detect_server_and_ports(url, verbose=False):
    """Detect server information and scan common ports."""
    if verbose:
        print(f"\n{Color.CYAN}[SERVER] Analyzing server information...{Color.RESET}")
    
    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    server_info = {
        "server": "Unknown",
        "powered_by": "Unknown",
        "open_ports": [],
        "web_server": "Unknown",
        "ssl_version": "Unknown"
    }
    
    try:
        # Extract host from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        scheme = parsed.scheme
        
        # Get server headers
        resp = requests.head(url, timeout=5, allow_redirects=True)
        
        server_header = resp.headers.get('Server', 'Not specified')
        server_info['server'] = server_header
        
        # Common web server detection
        if 'nginx' in server_header.lower():
            server_info['web_server'] = 'nginx'
        elif 'apache' in server_header.lower():
            server_info['web_server'] = 'Apache'
        elif 'iis' in server_header.lower():
            server_info['web_server'] = 'Microsoft IIS'
        
        # Check for X-Powered-By header
        powered_by = resp.headers.get('X-Powered-By', '')
        if powered_by:
            server_info['powered_by'] = powered_by
        
        if verbose:
            print(f"{Color.GREEN}[+] Server: {server_header}{Color.RESET}")
            print(f"{Color.GREEN}[+] Powered By: {powered_by if powered_by else 'Not specified'}{Color.RESET}")
        
        # Port scanning for common ports
        common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            5000: 'Development',
            8000: 'Development',
            9200: 'Elasticsearch'
        }
        
        if verbose:
            print(f"{Color.CYAN}[*] Scanning common ports on {host}...{Color.RESET}")
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    server_info['open_ports'].append({"port": port, "service": service, "status": "open"})
                    if verbose:
                        print(f"{Color.GREEN}[+] Port {port}/{service} is OPEN{Color.RESET}")
                sock.close()
            except:
                pass
        
        if verbose and not server_info['open_ports']:
            print(f"{Color.YELLOW}[-] No additional open ports detected{Color.RESET}")
    
    except Exception as e:
        if verbose:
            print(f"{Color.RED}[!] Error during server detection: {str(e)}{Color.RESET}")
    
    return server_info

def analyze_security_headers(url, verbose=False):
    """Analyze security headers for best practices."""
    if verbose:
        print(f"\n{Color.CYAN}[HEADERS] Analyzing security headers...{Color.RESET}")
    
    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    headers_analysis = {
        "present": {},
        "missing": [],
        "missing_details": [],
        "score": 0,
        "max_score": 100
    }
    
    critical_headers = {
        "Strict-Transport-Security": {"weight": 20, "missing_msg": "HSTS not configured"},
        "X-Content-Type-Options": {"weight": 15, "missing_msg": "MIME type sniffing not prevented"},
        "X-Frame-Options": {"weight": 15, "missing_msg": "Clickjacking not prevented"},
        "Content-Security-Policy": {"weight": 20, "missing_msg": "CSP not configured"},
        "X-XSS-Protection": {"weight": 10, "missing_msg": "XSS protection not enabled"},
    }
    
    other_headers = {
        "Referrer-Policy": 5,
        "Permissions-Policy": 10,
        "X-UA-Compatible": 5,
        "Server": 3,  # Server header disclosure check
        "Reporting-Endpoints": 2,  # Modern CSP reporting
    }
    
    try:
        resp = requests.head(url, timeout=5, allow_redirects=True)
        headers = resp.headers
        
        # Check critical headers
        for header_name, details in critical_headers.items():
            if header_name in headers:
                value = headers[header_name]
                headers_analysis['present'][header_name] = value
                headers_analysis['score'] += details['weight']
                if verbose:
                    print(f"{Color.GREEN}[+] {header_name}: {value[:60]}...{Color.RESET}")
            else:
                headers_analysis['missing'].append(details['missing_msg'])
                headers_analysis['missing_details'].append({
                    "header": header_name,
                    "message": details['missing_msg']
                })
                if verbose:
                    print(f"{Color.RED}[-] {header_name}: Missing{Color.RESET}")
        
        # Check optional headers
        for header_name, weight in other_headers.items():
            if header_name in headers:
                value = headers[header_name]
                headers_analysis['present'][header_name] = value
                headers_analysis['score'] += weight
                if verbose:
                    print(f"{Color.GREEN}[+] {header_name}: {value[:60]}...{Color.RESET}")
            else:
                if verbose:
                    print(f"{Color.YELLOW}[~] {header_name}: Optional (not present){Color.RESET}")
        
        # Advanced header analysis for new vulnerabilities
        if verbose:
            print(f"\n{Color.CYAN}[ADVANCED] Checking for new vulnerabilities...{Color.RESET}")
        
        # Check Server header disclosure
        if "Server" in headers:
            server_value = headers["Server"]
            if any(version in server_value.lower() for version in ["apache/", "nginx/", "iis/", "cloudflare"]):
                if verbose:
                    print(f"{Color.YELLOW}[!] Server header disclosure detected: {server_value}{Color.RESET}")
                headers_analysis['missing_details'].append({
                    "header": "Server",
                    "message": "Server header reveals software version information"
                })
        
        # Check CSP for deprecated report-uri
        if "Content-Security-Policy" in headers:
            csp_value = headers["Content-Security-Policy"]
            if "report-uri" in csp_value:
                if verbose:
                    print(f"{Color.YELLOW}[!] CSP uses deprecated report-uri directive{Color.RESET}")
                headers_analysis['missing_details'].append({
                    "header": "CSP-Report-URI-Deprecated",
                    "message": "CSP uses deprecated report-uri instead of report-to"
                })
        
        # Check for cookie security issues (need to make a request to get Set-Cookie headers)
        try:
            resp_get = requests.get(url, timeout=5, allow_redirects=True)
            if 'Set-Cookie' in resp_get.headers:
                cookies = resp_get.headers['Set-Cookie']
                missing_attrs = []
                if 'secure' not in cookies.lower():
                    missing_attrs.append('Secure')
                if 'httponly' not in cookies.lower():
                    missing_attrs.append('HttpOnly')
                if 'samesite' not in cookies.lower():
                    missing_attrs.append('SameSite')
                
                if missing_attrs:
                    if verbose:
                        print(f"{Color.YELLOW}[!] Cookie missing attributes: {', '.join(missing_attrs)}{Color.RESET}")
                    headers_analysis['missing_details'].append({
                        "header": "Cookie-Security",
                        "message": f"Authentication cookies missing: {', '.join(missing_attrs)}"
                    })
        except Exception as e:
            if verbose:
                print(f"{Color.DIM}[~] Could not analyze cookies: {str(e)}{Color.RESET}")
        
        # Check for React Server Components (indicators in response headers or HTML)
        react_indicators = []
        if "x-react-ssr" in headers or "react-server" in str(headers).lower():
            react_indicators.append("React Server headers detected")
        
        try:
            resp_html = requests.get(url, timeout=5, allow_redirects=True)
            if "react-server" in resp_html.text.lower() or "_rsc" in resp_html.text:
                react_indicators.append("React Server Components content detected")
        except Exception as e:
            if verbose:
                print(f"{Color.DIM}[~] Could not analyze React content: {str(e)}{Color.RESET}")
        
        if react_indicators:
            if verbose:
                print(f"{Color.RED}[!] React Server Components detected - potential CVE-2025-55182 risk{Color.RESET}")
            headers_analysis['missing_details'].append({
                "header": "React-Server-Components-RCE",
                "message": "React Server Components detected - update to patched versions (CVE-2025-55182)"
            })
        
        if verbose:
            print(f"\n{Color.BOLD}Security Score: {headers_analysis['score']}/{headers_analysis['max_score']}{Color.RESET}")
    
    except Exception as e:
        if verbose:
            print(f"{Color.RED}[!] Error analyzing headers: {str(e)}{Color.RESET}")
    
    return headers_analysis

def detect_wordpress(url):
    """Detect if the site is running WordPress with multiple fallback methods."""
    wordpress_indicators = {
        "wp_content": False,
        "wp_includes": False,
        "wordpress_version": None,
        "wordpress_theme": None,
        "admin_panel": False,
        "wp_json": False,
        "wp_cookies": False,
        "wp_json_api_version": None,
        "is_wordpress": False,
        "detection_method": []
    }
    
    try:
        # Ensure URL has a scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        # PRIMARY METHOD 1: Check /wp-json/wp/v2/ endpoint (most reliable)
        try:
            json_resp = requests.get(f"{url}/wp-json/wp/v2/", timeout=5, allow_redirects=True)
            if json_resp.status_code == 200:
                wordpress_indicators["wp_json"] = True
                wordpress_indicators["detection_method"].append("wp-json-endpoint")
                try:
                    json_data = json_resp.json()
                    if 'wordpress' in json_resp.text.lower() or 'wp' in json_resp.text.lower():
                        wordpress_indicators["is_wordpress"] = True
                except:
                    pass
        except requests.Timeout:
            pass
        except requests.ConnectionError:
            pass
        except Exception:
            pass
        
        # SECONDARY METHOD 2: Check homepage for WordPress indicators
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True)
            html = resp.text.lower()
            headers = resp.headers
            
            # Check for WordPress content indicators
            if "wp-content" in html or "/wp-content/" in html:
                wordpress_indicators["wp_content"] = True
                wordpress_indicators["detection_method"].append("wp-content-path")
            if "wp-includes" in html or "/wp-includes/" in html:
                wordpress_indicators["wp_includes"] = True
                wordpress_indicators["detection_method"].append("wp-includes-path")
            
            # Check for WordPress version in meta or comments
            version_match = re.search(r'content=["\']?(.?\d+\.\d+(\.\d+)?)["\']?\s+name=["\']?generator["\']?|<meta name=[\'\"]?generator[\'\"]? content=[\'"]?WordPress ([\d.]+)', html, re.IGNORECASE)
            if version_match:
                wordpress_indicators["wordpress_version"] = version_match.group(1) or version_match.group(3)
                wordpress_indicators["detection_method"].append("meta-generator")
            
            # Check for WordPress theme
            theme_match = re.search(r'/wp-content/themes/([a-z0-9-]+)/', html)
            if theme_match:
                wordpress_indicators["wordpress_theme"] = theme_match.group(1)
            
            # Check for WordPress admin
            if "/wp-admin/" in html:
                wordpress_indicators["admin_panel"] = True
                wordpress_indicators["detection_method"].append("wp-admin-path")
            
        except requests.Timeout:
            pass
        except requests.ConnectionError:
            pass
        except Exception:
            pass
        
        # TERTIARY METHOD 3: Check for WordPress-specific cookies
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True)
            wp_cookies = [c for c in resp.cookies if 'wordpress' in c.lower() or 'wp_' in c.lower()]
            if wp_cookies:
                wordpress_indicators["wp_cookies"] = True
                wordpress_indicators["detection_method"].append("wp-cookies")
        except:
            pass
        
        # FALLBACK METHOD 4: Try direct version.php probe (fallback)
        try:
            version_resp = requests.get(f"{url}/wp-includes/version.php", timeout=5)
            if version_resp.status_code == 200 and "wp_version" in version_resp.text:
                version_match = re.search(r'\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]', version_resp.text)
                if version_match:
                    wordpress_indicators["wordpress_version"] = version_match.group(1)
                    wordpress_indicators["detection_method"].append("version-php-probe")
        except:
            pass
        
        # Determine if WordPress - prioritize by impact
        wordpress_indicators["is_wordpress"] = (
            wordpress_indicators["wp_json"] or 
            wordpress_indicators["wp_content"] or 
            wordpress_indicators["wp_includes"] or
            wordpress_indicators["wordpress_version"] is not None or
            wordpress_indicators["wp_cookies"] or
            wordpress_indicators["admin_panel"]
        )
        
        return wordpress_indicators
    except Exception as e:
        return None


def detect_joomla(url):
    """Detect if the site is running Joomla."""
    joomla_indicators = {
        "administrator": False,
        "joomla_version": None,
        "joomla_generator": False,
        "com_content": False,
        "media_joomla": False,
        "is_joomla": False,
        "detection_method": []
    }
    
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        # Check for Joomla administrator panel
        try:
            admin_resp = requests.get(f"{url}/administrator/", timeout=5, allow_redirects=True)
            if admin_resp.status_code == 200 and "joomla" in admin_resp.text.lower():
                joomla_indicators["administrator"] = True
                joomla_indicators["detection_method"].append("administrator-panel")
        except:
            pass
        
        # Check homepage for Joomla indicators
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True)
            html = resp.text.lower()
            
            # Check for Joomla meta generator
            if "joomla" in html and "generator" in html:
                joomla_indicators["joomla_generator"] = True
                joomla_indicators["detection_method"].append("meta-generator")
            
            # Check for Joomla paths
            if "/media/jui/" in html or "/media/system/" in html:
                joomla_indicators["media_joomla"] = True
                joomla_indicators["detection_method"].append("media-paths")
            
            # Check for com_content
            if "com_content" in html:
                joomla_indicators["com_content"] = True
                joomla_indicators["detection_method"].append("com-content")
            
            # Determine if Joomla
            if len(joomla_indicators["detection_method"]) >= 1:
                joomla_indicators["is_joomla"] = True
                
        except:
            pass
        
        return joomla_indicators
    except Exception as e:
        return None


def detect_woocommerce(url):
    """Detect if the site is running WooCommerce (WordPress plugin)."""
    woo_indicators = {
        "woocommerce_api": False,
        "woocommerce_assets": False,
        "woocommerce_cart": False,
        "woocommerce_checkout": False,
        "is_woocommerce": False,
        "detection_method": []
    }
    
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        # Check for WooCommerce API endpoints
        try:
            api_resp = requests.get(f"{url}/wp-json/wc/v3/", timeout=5, allow_redirects=True)
            if api_resp.status_code == 200 and "woocommerce" in api_resp.text.lower():
                woo_indicators["woocommerce_api"] = True
                woo_indicators["detection_method"].append("wc-api")
        except:
            pass
        
        # Check homepage for WooCommerce indicators
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True)
            html = resp.text.lower()
            
            # Check for WooCommerce assets
            if "woocommerce" in html and ("assets" in html or "css" in html):
                woo_indicators["woocommerce_assets"] = True
                woo_indicators["detection_method"].append("woocommerce-assets")
            
            # Check for cart/checkout pages
            if "/cart/" in html or "/checkout/" in html:
                woo_indicators["woocommerce_cart"] = True
                woo_indicators["detection_method"].append("cart-checkout")
            
            # Determine if WooCommerce
            if len(woo_indicators["detection_method"]) >= 1:
                woo_indicators["is_woocommerce"] = True
                
        except:
            pass
        
        return woo_indicators
    except Exception as e:
        return None


def detect_laravel(url):
    """Detect if the site is running Laravel."""
    laravel_indicators = {
        "laravel_cookie": False,
        "laravel_routes": False,
        "laravel_debug": False,
        "laravel_assets": False,
        "is_laravel": False,
        "detection_method": []
    }
    
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        # Check homepage for Laravel indicators
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True)
            html = resp.text.lower()
            headers = resp.headers
            
            # Check for Laravel session cookie
            set_cookie = headers.get("set-cookie", "")
            if "laravel_session" in set_cookie.lower():
                laravel_indicators["laravel_cookie"] = True
                laravel_indicators["detection_method"].append("laravel-session")
            
            # Check for Laravel debug errors
            if "whoops" in html or "laravel" in html:
                laravel_indicators["laravel_debug"] = True
                laravel_indicators["detection_method"].append("laravel-debug")
            
            # Check for Laravel asset patterns
            if "/storage/" in html or "mix-manifest.json" in html:
                laravel_indicators["laravel_assets"] = True
                laravel_indicators["detection_method"].append("laravel-assets")
            
            # Determine if Laravel
            if len(laravel_indicators["detection_method"]) >= 1:
                laravel_indicators["is_laravel"] = True
                
        except:
            pass
        
        return laravel_indicators
    except Exception as e:
        return None


def detect_php_application(url):
    """Detect if the site is running a PHP application."""
    php_indicators = {
        "php_headers": False,
        "php_extensions": False,
        "php_errors": False,
        "php_session": False,
        "is_php": False,
        "detection_method": []
    }
    
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        # Check homepage for PHP indicators
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True)
            headers = resp.headers
            html = resp.text.lower()
            
            # Check for PHP headers
            server = headers.get("server", "").lower()
            x_powered_by = headers.get("x-powered-by", "").lower()
            if "php" in server or "php" in x_powered_by:
                php_indicators["php_headers"] = True
                php_indicators["detection_method"].append("php-headers")
            
            # Check for PHP session cookies
            set_cookie = headers.get("set-cookie", "")
            if "phpsessid" in set_cookie.lower():
                php_indicators["php_session"] = True
                php_indicators["detection_method"].append("php-session")
            
            # Check for PHP file extensions in links
            if ".php" in html:
                php_indicators["php_extensions"] = True
                php_indicators["detection_method"].append("php-extensions")
            
            # Check for PHP error messages
            if "php warning" in html or "php fatal error" in html or "php notice" in html:
                php_indicators["php_errors"] = True
                php_indicators["detection_method"].append("php-errors")
            
            # Determine if PHP
            if len(php_indicators["detection_method"]) >= 1:
                php_indicators["is_php"] = True
                
        except:
            pass
        
        return php_indicators
    except Exception as e:
        return None

def test_wordpress_cves(url, verbose=False, selected_ids=None, use_apis=True):
    """Run configured WordPress CVE tests defined in built-in-cves.config."""
    definitions = _filter_cve_definitions(platform="wordpress", selected_ids=selected_ids)
    if not definitions:
        if verbose:
            print(colorize("[WP-CVE] No CVE definitions available to test.", Color.YELLOW))
        return []

    target_url = _ensure_url_scheme(url)
    results = []

    if verbose:
        print(f"\n{Color.CYAN}[WP-CVE] Running {len(definitions)} configured CVE checks...{Color.RESET}")

    for definition in definitions:
        cve_id = definition.get("id", "UNKNOWN")
        if verbose:
            print(f"{Color.DIM}  -> {cve_id}: {definition.get('title', 'Untitled check')}{Color.RESET}")

        result = _execute_cve_definition(target_url, definition)
        results.append(result)

        if verbose:
            if result.get("vulnerable") is True:
                status = colorize("VULNERABLE", Color.RED)
            elif result.get("vulnerable") == "detected":
                status = colorize("DETECTED", Color.MAGENTA)
            else:
                status = colorize("SAFE", Color.GREEN)
            print(f"       {status} - {result.get('description', 'No details available')}")

    # Only enhance with external APIs if use_apis is True
    if use_apis and SETTINGS_AVAILABLE:
        enhanced_results = []
        for cve_result in results:
            enhanced = enhance_cve_with_external_apis(cve_result)
            enhanced_results.append(enhanced)

            if verbose and enhanced.get('external_data', {}).get('has_external_data'):
                external = enhanced['external_data']
                print(f"  {Color.CYAN}[API DATA] Enhanced {cve_result.get('cve')} with external sources:{Color.RESET}")
                if external.get('nvd'):
                    print(f"    NVD: Score {external['nvd'].get('score', 'N/A')}, Severity {external['nvd'].get('severity', 'N/A')}")
                if external.get('exploitdb'):
                    print(f"    ExploitDB: {external['exploitdb']['count']} exploits found")
                if external.get('vulndb'):
                    print(f"    VulnDB: {external['vulndb'].get('severity', 'N/A')} severity")
        results = enhanced_results

    return results


def test_php_cves(url, verbose=False, selected_ids=None, use_apis=True):
    """Run configured PHP CVE tests defined in built-in-cves.config."""
    definitions = _filter_cve_definitions(platform="php", selected_ids=selected_ids)
    if not definitions:
        if verbose:
            print(colorize("[PHP-CVE] No CVE definitions available to test.", Color.YELLOW))
        return []

    target_url = _ensure_url_scheme(url)
    results = []

    if verbose:
        print(f"\n{Color.CYAN}[PHP-CVE] Running {len(definitions)} configured CVE checks...{Color.RESET}")

    for definition in definitions:
        cve_id = definition.get("id", "UNKNOWN")
        if verbose:
            print(f"{Color.DIM}  -> {cve_id}: {definition.get('title', 'Untitled check')}{Color.RESET}")

        result = _execute_cve_definition(target_url, definition)
        results.append(result)

        if verbose:
            if result.get("vulnerable") is True:
                status = colorize("VULNERABLE", Color.RED)
            elif result.get("vulnerable") == "detected":
                status = colorize("DETECTED", Color.MAGENTA)
            else:
                status = colorize("SAFE", Color.GREEN)
            print(f"       {status} - {result.get('description', 'No details available')}")

    # Only enhance with external APIs if use_apis is True
    if use_apis and SETTINGS_AVAILABLE:
        enhanced_results = []
        for cve_result in results:
            enhanced = enhance_cve_with_external_apis(cve_result)
            enhanced_results.append(enhanced)

            if verbose and enhanced.get('external_data', {}).get('has_external_data'):
                external = enhanced['external_data']
                print(f"  {Color.CYAN}[API DATA] Enhanced {cve_result.get('cve')} with external sources:{Color.RESET}")
                if external.get('nvd'):
                    print(f"    NVD: Score {external['nvd'].get('score', 'N/A')}, Severity {external['nvd'].get('severity', 'N/A')}")
                if external.get('exploitdb'):
                    print(f"    ExploitDB: {external['exploitdb']['count']} exploits found")
                if external.get('vulndb'):
                    print(f"    VulnDB: {external['vulndb'].get('severity', 'N/A')} severity")
        results = enhanced_results

    return results


def test_joomla_cves(url, verbose=False, selected_ids=None, use_apis=True):
    """Run configured Joomla CVE tests defined in built-in-cves.config."""
    definitions = _filter_cve_definitions(platform="joomla", selected_ids=selected_ids)
    if not definitions:
        if verbose:
            print(colorize("[JOOMLA-CVE] No CVE definitions available to test.", Color.YELLOW))
        return []

    target_url = _ensure_url_scheme(url)
    results = []

    if verbose:
        print(f"\n{Color.CYAN}[JOOMLA-CVE] Running {len(definitions)} configured CVE checks...{Color.RESET}")

    for definition in definitions:
        cve_id = definition.get("id", "UNKNOWN")
        if verbose:
            print(f"{Color.DIM}  -> {cve_id}: {definition.get('title', 'Untitled check')}{Color.RESET}")

        result = _execute_cve_definition(target_url, definition)
        results.append(result)

        if verbose:
            if result.get("vulnerable") is True:
                status = colorize("VULNERABLE", Color.RED)
            elif result.get("vulnerable") == "detected":
                status = colorize("DETECTED", Color.MAGENTA)
            else:
                status = colorize("SAFE", Color.GREEN)
            print(f"       {status} - {result.get('description', 'No details available')}")

    # Only enhance with external APIs if use_apis is True
    if use_apis and SETTINGS_AVAILABLE:
        enhanced_results = []
        for cve_result in results:
            enhanced = enhance_cve_with_external_apis(cve_result)
            enhanced_results.append(enhanced)

            if verbose and enhanced.get('external_data', {}).get('has_external_data'):
                external = enhanced['external_data']
                print(f"  {Color.CYAN}[API DATA] Enhanced {cve_result.get('cve')} with external sources:{Color.RESET}")
                if external.get('nvd'):
                    print(f"    NVD: Score {external['nvd'].get('score', 'N/A')}, Severity {external['nvd'].get('severity', 'N/A')}")
                if external.get('exploitdb'):
                    print(f"    ExploitDB: {external['exploitdb']['count']} exploits found")
                if external.get('vulndb'):
                    print(f"    VulnDB: {external['vulndb'].get('severity', 'N/A')} severity")
        results = enhanced_results

    return results


def test_woocommerce_cves(url, verbose=False, selected_ids=None, use_apis=True):
    """Run configured WooCommerce CVE tests defined in built-in-cves.config."""
    definitions = _filter_cve_definitions(platform="woocommerce", selected_ids=selected_ids)
    if not definitions:
        if verbose:
            print(colorize("[WOO-CVE] No CVE definitions available to test.", Color.YELLOW))
        return []

    target_url = _ensure_url_scheme(url)
    results = []

    if verbose:
        print(f"\n{Color.CYAN}[WOO-CVE] Running {len(definitions)} configured CVE checks...{Color.RESET}")

    for definition in definitions:
        cve_id = definition.get("id", "UNKNOWN")
        if verbose:
            print(f"{Color.DIM}  -> {cve_id}: {definition.get('title', 'Untitled check')}{Color.RESET}")

        result = _execute_cve_definition(target_url, definition)
        results.append(result)

        if verbose:
            if result.get("vulnerable") is True:
                status = colorize("VULNERABLE", Color.RED)
            elif result.get("vulnerable") == "detected":
                status = colorize("DETECTED", Color.MAGENTA)
            else:
                status = colorize("SAFE", Color.GREEN)
            print(f"       {status} - {result.get('description', 'No details available')}")

    # Only enhance with external APIs if use_apis is True
    if use_apis and SETTINGS_AVAILABLE:
        enhanced_results = []
        for cve_result in results:
            enhanced = enhance_cve_with_external_apis(cve_result)
            enhanced_results.append(enhanced)

            if verbose and enhanced.get('external_data', {}).get('has_external_data'):
                external = enhanced['external_data']
                print(f"  {Color.CYAN}[API DATA] Enhanced {cve_result.get('cve')} with external sources:{Color.RESET}")
                if external.get('nvd'):
                    print(f"    NVD: Score {external['nvd'].get('score', 'N/A')}, Severity {external['nvd'].get('severity', 'N/A')}")
                if external.get('exploitdb'):
                    print(f"    ExploitDB: {external['exploitdb']['count']} exploits found")
                if external.get('vulndb'):
                    print(f"    VulnDB: {external['vulndb'].get('severity', 'N/A')} severity")
        results = enhanced_results

    return results


def test_laravel_cves(url, verbose=False, selected_ids=None, use_apis=True):
    """Run configured Laravel CVE tests defined in built-in-cves.config."""
    definitions = _filter_cve_definitions(platform="laravel", selected_ids=selected_ids)
    if not definitions:
        if verbose:
            print(colorize("[LARAVEL-CVE] No CVE definitions available to test.", Color.YELLOW))
        return []

    target_url = _ensure_url_scheme(url)
    results = []

    if verbose:
        print(f"\n{Color.CYAN}[LARAVEL-CVE] Running {len(definitions)} configured CVE checks...{Color.RESET}")

    for definition in definitions:
        cve_id = definition.get("id", "UNKNOWN")
        if verbose:
            print(f"{Color.DIM}  -> {cve_id}: {definition.get('title', 'Untitled check')}{Color.RESET}")

        result = _execute_cve_definition(target_url, definition)
        results.append(result)

        if verbose:
            if result.get("vulnerable") is True:
                status = colorize("VULNERABLE", Color.RED)
            elif result.get("vulnerable") == "detected":
                status = colorize("DETECTED", Color.MAGENTA)
            else:
                status = colorize("SAFE", Color.GREEN)
            print(f"       {status} - {result.get('description', 'No details available')}")

    # Only enhance with external APIs if use_apis is True
    if use_apis and SETTINGS_AVAILABLE:
        enhanced_results = []
        for cve_result in results:
            enhanced = enhance_cve_with_external_apis(cve_result)
            enhanced_results.append(enhanced)

            if verbose and enhanced.get('external_data', {}).get('has_external_data'):
                external = enhanced['external_data']
                print(f"  {Color.CYAN}[API DATA] Enhanced {cve_result.get('cve')} with external sources:{Color.RESET}")
                if external.get('nvd'):
                    print(f"    NVD: Score {external['nvd'].get('score', 'N/A')}, Severity {external['nvd'].get('severity', 'N/A')}")
                if external.get('exploitdb'):
                    print(f"    ExploitDB: {external['exploitdb']['count']} exploits found")
                if external.get('vulndb'):
                    print(f"    VulnDB: {external['vulndb'].get('severity', 'N/A')} severity")
        results = enhanced_results

    return results

def summarize_response(resp, elapsed, payload_params, verbose=False, show_full=False, wordpress_data=None):
    if show_full:
        text = resp.text
    else:
        text = resp.text[:500].replace("\n", " ")
    
    # Determine status color
    if resp.status_code >= 500:
        status_color = Color.RED
    elif resp.status_code >= 400:
        status_color = Color.YELLOW
    elif resp.status_code >= 200:
        status_color = Color.GREEN
    else:
        status_color = Color.CYAN
    
    print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
    print(f"RESPONSE SUMMARY")
    print(f"{'='*60}{Color.RESET}\n")
    
    # Display WordPress information if detected
    if wordpress_data and wordpress_data.get("is_wordpress"):
        print(f"\n{Color.BOLD}{Color.MAGENTA}WORDPRESS DETECTED:{Color.RESET}")
        if wordpress_data.get("wordpress_version"):
            print(f"  Version: {colorize(wordpress_data['wordpress_version'], Color.YELLOW)}")
        if wordpress_data.get("wordpress_theme"):
            print(f"  Theme: {wordpress_data['wordpress_theme']}")
        print()
    
    if verbose:
        log_step(6, "Response Headers:")
        for header, value in resp.headers.items():
            print(f"  {colorize(header, Color.DIM)}: {value}")
    
    print(f"\nStatus Code  : {colorize(str(resp.status_code), status_color)}")
    print(f"Time         : {colorize(f'{elapsed:.2f}s', Color.CYAN)}")
    print(f"Content Size : {colorize(f'{len(resp.text)} bytes', Color.CYAN)}")
    print(f"Content-Type : {colorize(resp.headers.get('Content-Type', 'unknown'), Color.DIM)}")
    
    # Detect vulnerability indicators
    indicators = detect_vulnerability_indicators(resp, payload_params)
    
    if indicators:
        print(f"\n{Color.BOLD}{Color.MAGENTA}VULNERABILITY ANALYSIS:{Color.RESET}")
        for level, message in indicators:
            if level == "LIKELY_VULNERABLE":
                icon = colorize("⚠️  VULNERABLE:", Color.RED)
            else:
                icon = colorize("⚡ SUSPICIOUS:", Color.YELLOW)
            print(f"{icon} {message}")
    else:
        print(f"\n{colorize('✓ No obvious vulnerability indicators detected', Color.GREEN)}")
    
    # Display WordPress CVE results if available
    if wordpress_data and wordpress_data.get("cve_results"):
        print(f"\n{Color.BOLD}{Color.MAGENTA}WORDPRESS CVE ANALYSIS:{Color.RESET}")
        vulnerable_count = 0
        for cve in wordpress_data["cve_results"]:
            if cve.get("vulnerable") is True:
                icon = colorize("⚠️  VULNERABLE:", Color.RED)
                vulnerable_count += 1
            elif cve.get("vulnerable") is False:
                icon = colorize("✓ SAFE:", Color.GREEN)
            else:
                icon = colorize("ℹ️  INFO:", Color.BLUE)
            
            cve_name = cve.get('cve', 'UNKNOWN')
            cve_desc = cve.get('description', 'No description available')
            print(f"{icon} {cve_name} - {cve_desc}")
        
        if vulnerable_count > 0:
            print(f"\n{colorize(f'Found {vulnerable_count} potential WordPress vulnerabilities', Color.RED)}")
    
    if show_full:
        print(f"\n{Color.BOLD}{Color.MAGENTA}FULL RESPONSE BODY:{Color.RESET}")
        print(f"{Color.DIM}{'-'*60}{Color.RESET}")
        print(text)
        print(f"{Color.DIM}{'-'*60}{Color.RESET}")
    else:
        print(f"\n{Color.DIM}Response Preview:{Color.RESET}")
        print(f"{Color.DIM}{text[:200]}...{Color.RESET}")
    
    print(f"\n{Color.BLUE}{'='*60}{Color.RESET}\n")

# -----------------------------
# Main flow
# -----------------------------

def auto_mode_test(url, verbose=False, output_file=None, mode="auto", use_apis=True):
    """Run comprehensive automatic security test on target."""
    
    # Set scan title based on mode
    mode_titles = {
        "auto": "COMPREHENSIVE SECURITY TEST",
        "wordpress": "WORDPRESS SECURITY TEST",
        "joomla": "JOOMLA SECURITY TEST", 
        "woocommerce": "WOOCOMMERCE SECURITY TEST",
        "laravel": "LARAVEL SECURITY TEST",
        "php": "PHP APPLICATION SECURITY TEST",
        "headers": "SECURITY HEADERS ANALYSIS",
        "server": "SERVER DETECTION SCAN",
        "stealth": "STEALTH MODE (PASSIVE SCAN)"
    }
    
    title = mode_titles.get(mode, "SECURITY TEST")
    print(f"\n{Color.BOLD}{Color.CYAN}{'='*60}")
    print(f"AUTO MODE - {title}")
    print(f"{'='*60}{Color.RESET}\n")
    
    auto_results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "mode": mode,
        "use_apis": use_apis,
        "tests": {}
    }
    
    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Mode-specific scanning logic
    if mode == "headers":
        run_headers_only_scan(url, verbose, auto_results)
    elif mode == "server":
        run_server_only_scan(url, verbose, auto_results)
    elif mode == "stealth":
        run_stealth_scan(url, verbose, auto_results)
    elif mode == "wordpress":
        run_platform_specific_scan(url, verbose, auto_results, "wordpress", use_apis)
    elif mode == "joomla":
        run_platform_specific_scan(url, verbose, auto_results, "joomla", use_apis)
    elif mode == "woocommerce":
        run_platform_specific_scan(url, verbose, auto_results, "woocommerce", use_apis)
    elif mode == "laravel":
        run_platform_specific_scan(url, verbose, auto_results, "laravel", use_apis)
    elif mode == "php":
        run_platform_specific_scan(url, verbose, auto_results, "php", use_apis)
    else:  # auto mode - comprehensive scan
        run_comprehensive_scan(url, verbose, auto_results, use_apis)
    
    # Generate final summary
    generate_scan_summary(auto_results, mode)
    
    # Save report if requested
    if output_file:
        save_scan_report(auto_results, output_file)
    
    return auto_results


def run_headers_only_scan(url, verbose, auto_results):
    """Run security headers analysis only."""
    print(f"{Color.BOLD}[1/1] Security Headers Analysis...{Color.RESET}")
    headers_analysis = analyze_security_headers(url, verbose=verbose)
    auto_results["tests"]["security_headers"] = headers_analysis
    
    print(f"  Security Score: {headers_analysis['score']}/{headers_analysis['max_score']}")
    if headers_analysis['missing']:
        print(f"  Missing Headers: {len(headers_analysis['missing'])}")
        for missing in headers_analysis['missing'][:3]:
            print(f"    - {missing}")


def run_server_only_scan(url, verbose, auto_results):
    """Run server detection only."""
    print(f"{Color.BOLD}[1/1] Server & Port Detection...{Color.RESET}")
    server_info = detect_server_and_ports(url, verbose=verbose)
    auto_results["tests"]["server_info"] = server_info
    
    print(f"  Server: {server_info['server']}")
    if server_info['open_ports']:
        print(f"  Open Ports: {len(server_info['open_ports'])}")
        for port_info in server_info['open_ports']:
            print(f"    - {port_info['port']}/{port_info['service']}")


def run_stealth_scan(url, verbose, auto_results):
    """Run passive/stealth scan only."""
    print(f"{Color.BOLD}[1/1] Passive Information Gathering...{Color.RESET}")
    
    # Only do passive detection, no active scanning
    wordpress_data = detect_wordpress(url)
    joomla_data = detect_joomla(url)
    woo_data = detect_woocommerce(url)
    laravel_data = detect_laravel(url)
    php_data = detect_php_application(url)
    server_info = detect_server_and_ports(url, verbose=False)
    
    auto_results["tests"]["wordpress"] = wordpress_data
    auto_results["tests"]["platform_detection"] = {
        "joomla": joomla_data,
        "woocommerce": woo_data,
        "laravel": laravel_data,
        "php": php_data
    }
    auto_results["tests"]["server_info"] = server_info
    
    # Show detected platforms (passive detection only)
    detected_platforms = []
    if joomla_data and joomla_data.get("is_joomla"):
        detected_platforms.append("Joomla")
    if woo_data and woo_data.get("is_woocommerce"):
        detected_platforms.append("WooCommerce")
    if laravel_data and laravel_data.get("is_laravel"):
        detected_platforms.append("Laravel")
    if php_data and php_data.get("is_php"):
        detected_platforms.append("PHP")
    if wordpress_data and wordpress_data.get("is_wordpress"):
        detected_platforms.append("WordPress")
    
    if detected_platforms:
        print(f"  {Color.GREEN}✓ Detected platforms: {', '.join(detected_platforms)}{Color.RESET}")
    else:
        print(f"  {Color.YELLOW}- No specific platforms detected{Color.RESET}")
    
    print(f"  Server: {server_info['server']}")
    print(f"  {Color.DIM}Note: Stealth mode - no active vulnerability testing performed{Color.RESET}")


def run_platform_specific_scan(url, verbose, auto_results, platform, use_apis=True):
    """Run scan for specific platform only."""
    print(f"{Color.BOLD}[1/2] Platform Detection...{Color.RESET}")
    
    # Detect all platforms but focus on the target
    wordpress_data = detect_wordpress(url) if platform == "wordpress" else {"is_wordpress": False}
    joomla_data = detect_joomla(url) if platform == "joomla" else {"is_joomla": False}
    woo_data = detect_woocommerce(url) if platform == "woocommerce" else {"is_woocommerce": False}
    laravel_data = detect_laravel(url) if platform == "laravel" else {"is_laravel": False}
    php_data = detect_php_application(url) if platform == "php" else {"is_php": False}
    
    auto_results["tests"]["wordpress"] = wordpress_data
    auto_results["tests"]["platform_detection"] = {
        "joomla": joomla_data,
        "woocommerce": woo_data,
        "laravel": laravel_data,
        "php": php_data
    }
    
    # Show detection results
    platform_detected = False
    if platform == "wordpress" and wordpress_data.get("is_wordpress"):
        platform_detected = True
        print(f"  {Color.GREEN}✓ WordPress detected{Color.RESET}")
    elif platform == "joomla" and joomla_data.get("is_joomla"):
        platform_detected = True
        print(f"  {Color.GREEN}✓ Joomla detected{Color.RESET}")
    elif platform == "woocommerce" and woo_data.get("is_woocommerce"):
        platform_detected = True
        print(f"  {Color.GREEN}✓ WooCommerce detected{Color.RESET}")
    elif platform == "laravel" and laravel_data.get("is_laravel"):
        platform_detected = True
        print(f"  {Color.GREEN}✓ Laravel detected{Color.RESET}")
    elif platform == "php" and php_data.get("is_php"):
        platform_detected = True
        print(f"  {Color.GREEN}✓ PHP application detected{Color.RESET}")
    else:
        print(f"  {Color.YELLOW}- {platform.title()} not detected, but scanning anyway{Color.RESET}")
    
    # Run CVE tests for the specific platform
    print(f"\n{Color.BOLD}[2/2] {platform.title()} CVE Testing...{Color.RESET}")
    all_cve_results = []
    
    if platform == "wordpress" and (platform_detected or True):
        wp_results = test_wordpress_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(wp_results)
    elif platform == "joomla" and (platform_detected or True):
        joomla_results = test_joomla_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(joomla_results)
    elif platform == "woocommerce" and (platform_detected or True):
        woo_results = test_woocommerce_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(woo_results)
    elif platform == "laravel" and (platform_detected or True):
        laravel_results = test_laravel_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(laravel_results)
    elif platform == "php" and (platform_detected or True):
        php_results = test_php_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(php_results)
    
    auto_results["tests"]["cves"] = all_cve_results
    
    # Show CVE summary
    if all_cve_results:
        vulnerable_count = sum(1 for c in all_cve_results if c.get("vulnerable") is True)
        print(f"  Found {vulnerable_count} potential vulnerabilities")
    else:
        print(f"  No CVE tests were run")


def run_comprehensive_scan(url, verbose, auto_results, use_apis=True):
    """Run full comprehensive scan (original auto mode)."""
    # This will contain the original auto mode logic that we had before
    # WordPress Detection
    print(f"{Color.BOLD}[1/5] WordPress Detection...{Color.RESET}")
    wordpress_data = detect_wordpress(url)
    auto_results["tests"]["wordpress"] = wordpress_data
    
    if wordpress_data and wordpress_data.get("is_wordpress"):
        print(f"{Color.GREEN}  ✓ WordPress detected{Color.RESET}")
        if wordpress_data.get("wordpress_version"):
            print(f"    Version: {wordpress_data['wordpress_version']}")
    else:
        print(f"{Color.YELLOW}  - Not a WordPress site{Color.RESET}")
    
    # Platform Detection & CVE Testing (original comprehensive logic)
    print(f"\n{Color.BOLD}[2/5] Platform Detection & CVE Testing...{Color.RESET}")
    
    # Detect all platforms
    joomla_data = detect_joomla(url)
    woo_data = detect_woocommerce(url)
    laravel_data = detect_laravel(url)
    php_data = detect_php_application(url)
    
    # Store platform detection results
    auto_results["tests"]["platform_detection"] = {
        "joomla": joomla_data,
        "woocommerce": woo_data,
        "laravel": laravel_data,
        "php": php_data
    }
    
    # Show platform detection results
    detected_platforms = []
    if joomla_data and joomla_data.get("is_joomla"):
        detected_platforms.append("Joomla")
        print(f"  {Color.GREEN}✓ Joomla detected{Color.RESET}")
    if woo_data and woo_data.get("is_woocommerce"):
        detected_platforms.append("WooCommerce")
        print(f"  {Color.GREEN}✓ WooCommerce detected{Color.RESET}")
    if laravel_data and laravel_data.get("is_laravel"):
        detected_platforms.append("Laravel")
        print(f"  {Color.GREEN}✓ Laravel detected{Color.RESET}")
    if php_data and php_data.get("is_php"):
        detected_platforms.append("PHP")
        print(f"  {Color.GREEN}✓ PHP application detected{Color.RESET}")
    if wordpress_data and wordpress_data.get("is_wordpress"):
        detected_platforms.append("WordPress")
        print(f"  {Color.GREEN}✓ WordPress detected{Color.RESET}")
    
    if not detected_platforms:
        print(f"  {Color.YELLOW}- No specific platforms detected, running general vulnerability tests{Color.RESET}")
    
    # Run CVE tests for detected platforms
    all_cve_results = []
    
    if wordpress_data and wordpress_data.get("is_wordpress"):
        print(f"\n  {Color.CYAN}Testing WordPress CVEs...{Color.RESET}")
        wp_results = test_wordpress_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(wp_results)
    
    if joomla_data and joomla_data.get("is_joomla"):
        print(f"\n  {Color.CYAN}Testing Joomla CVEs...{Color.RESET}")
        joomla_results = test_joomla_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(joomla_results)
    
    if woo_data and woo_data.get("is_woocommerce"):
        print(f"\n  {Color.CYAN}Testing WooCommerce CVEs...{Color.RESET}")
        woo_results = test_woocommerce_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(woo_results)
    
    if laravel_data and laravel_data.get("is_laravel"):
        print(f"\n  {Color.CYAN}Testing Laravel CVEs...{Color.RESET}")
        laravel_results = test_laravel_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(laravel_results)
    
    if php_data and php_data.get("is_php"):
        print(f"\n  {Color.CYAN}Testing PHP CVEs...{Color.RESET}")
        php_results = test_php_cves(url, verbose=verbose, use_apis=use_apis)
        all_cve_results.extend(php_results)
    
    # If no platforms detected, run general vulnerability tests
    if not detected_platforms:
        print(f"\n  {Color.CYAN}Running general vulnerability tests...{Color.RESET}")
        test_params = {
            "id[$ne]": "1",
            "user[$exists]": "true"
        }
        try:
            resp, elapsed = send_request(url, "GET", test_params, None, verbose=False)
            indicators = detect_vulnerability_indicators(resp, test_params)
            auto_results["tests"]["general_vulns"] = [{"level": level, "message": msg} for level, msg in indicators]
            if indicators:
                print(f"    ⚠️  Found {len(indicators)} potential issue(s)")
            else:
                print(f"    ✓ No obvious vulnerabilities detected")
        except requests.Timeout:
            print(f"    {Color.YELLOW}⏱ Request timeout (target slow or unreachable){Color.RESET}")
            auto_results["tests"]["general_vulns"] = []
        except requests.ConnectionError:
            print(f"    {Color.RED}✗ Connection failed (unable to reach target){Color.RESET}")
            auto_results["tests"]["general_vulns"] = []
        except requests.exceptions.InvalidURL:
            print(f"    {Color.RED}✗ Invalid URL format{Color.RESET}")
            auto_results["tests"]["general_vulns"] = []
        except Exception as e:
            print(f"    {Color.YELLOW}⚠ Skipped: {str(e)}{Color.RESET}")
            auto_results["tests"]["general_vulns"] = []
    
    # Store CVE results
    auto_results["tests"]["cves"] = all_cve_results
    
    # Show CVE summary
    if all_cve_results:
        vulnerable_count = sum(1 for c in all_cve_results if c.get("vulnerable") is True)
        print(f"\n  CVE Testing Summary: {vulnerable_count} potential vulnerabilities found")
    else:
        print(f"\n  CVE Testing Summary: No CVE tests were run")
    
    # Server & Port Detection
    print(f"\n{Color.BOLD}[3/5] Server & Port Detection...{Color.RESET}")
    server_info = detect_server_and_ports(url, verbose=False)
    auto_results["tests"]["server_info"] = server_info
    
    print(f"  Server: {server_info['server']}")
    if server_info['open_ports']:
        print(f"  Open Ports: {len(server_info['open_ports'])}")
        for port_info in server_info['open_ports']:
            print(f"    - {port_info['port']}/{port_info['service']}")
    
    # Security Headers Analysis
    print(f"\n{Color.BOLD}[4/5] Security Headers Analysis...{Color.RESET}")
    headers_analysis = analyze_security_headers(url, verbose=False)
    auto_results["tests"]["security_headers"] = headers_analysis
    
    print(f"  Security Score: {headers_analysis['score']}/{headers_analysis['max_score']}")
    if headers_analysis['missing']:
        print(f"  Missing Headers: {len(headers_analysis['missing'])}")
        for missing in headers_analysis['missing'][:3]:
            print(f"    - {missing}")
    
    # Store for summary generation
    auto_results["_temp"] = {
        "all_cve_results": all_cve_results,
        "detected_platforms": detected_platforms,
        "headers_analysis": headers_analysis,
        "server_info": server_info
    }


def generate_scan_summary(auto_results, mode):
    """Generate final scan summary based on mode."""
    if mode == "headers":
        headers_analysis = auto_results["tests"]["security_headers"]
        print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
        print(f"SECURITY HEADERS SUMMARY")
        print(f"{'='*60}{Color.RESET}\n")
        
        print(f"Target                 : {auto_results['url']}")
        score_str = f"{headers_analysis['score']}/{headers_analysis['max_score']}"
        score_color = Color.GREEN if headers_analysis['score'] >= 80 else Color.YELLOW if headers_analysis['score'] >= 60 else Color.RED
        print(f"Security Score         : {colorize(score_str, score_color)}")
        
    elif mode == "server":
        server_info = auto_results["tests"]["server_info"]
        print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
        print(f"SERVER DETECTION SUMMARY")
        print(f"{'='*60}{Color.RESET}\n")
        
        print(f"Target                 : {auto_results['url']}")
        print(f"Server                 : {server_info['server']}")
        if server_info['open_ports']:
            print(f"Open Ports             : {len(server_info['open_ports'])}")
        
    elif mode == "stealth":
        server_info = auto_results["tests"]["server_info"]
        detected_platforms = []
        
        # Check detected platforms
        if auto_results["tests"]["wordpress"].get("is_wordpress"):
            detected_platforms.append("WordPress")
        if auto_results["tests"]["platform_detection"]["joomla"].get("is_joomla"):
            detected_platforms.append("Joomla")
        if auto_results["tests"]["platform_detection"]["woocommerce"].get("is_woocommerce"):
            detected_platforms.append("WooCommerce")
        if auto_results["tests"]["platform_detection"]["laravel"].get("is_laravel"):
            detected_platforms.append("Laravel")
        if auto_results["tests"]["platform_detection"]["php"].get("is_php"):
            detected_platforms.append("PHP")
        
        print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
        print(f"STEALTH SCAN SUMMARY")
        print(f"{'='*60}{Color.RESET}\n")
        
        print(f"Target                 : {auto_results['url']}")
        platforms_str = ", ".join(detected_platforms) if detected_platforms else "None detected"
        print(f"Detected Platforms     : {colorize(platforms_str, Color.GREEN if detected_platforms else Color.YELLOW)}")
        print(f"Server                 : {server_info['server']}")
        print(f"Scan Type              : {Color.GREEN}Passive (No active testing){Color.RESET}")
        
    elif mode in ["wordpress", "joomla", "woocommerce", "laravel", "php"]:
        all_cve_results = auto_results["tests"]["cves"]
        vuln_count = sum(1 for c in all_cve_results if c.get("vulnerable") is True) if all_cve_results else 0
        
        print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
        print(f"{mode.upper()} SECURITY SUMMARY")
        print(f"{'='*60}{Color.RESET}\n")
        
        print(f"Target                 : {auto_results['url']}")
        print(f"Scan Mode              : {mode.title()} Only")
        print(f"Vulnerabilities Found  : {colorize(str(vuln_count), Color.RED if vuln_count > 0 else Color.GREEN)}")
        
    else:  # auto mode - comprehensive
        temp = auto_results.get("_temp", {})
        all_cve_results = temp.get("all_cve_results", [])
        detected_platforms = temp.get("detected_platforms", [])
        headers_analysis = temp.get("headers_analysis", {})
        server_info = temp.get("server_info", {})
        
        # Count findings
        vuln_count = 0
        if all_cve_results:
            vuln_count += sum(1 for c in all_cve_results if c.get("vulnerable") is True)
        vuln_count += len(auto_results["tests"].get("general_vulns", []))
        vuln_count += len(headers_analysis.get('missing', []))
        
        print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
        print(f"AUTO TEST SUMMARY")
        print(f"{'='*60}{Color.RESET}\n")
        
        print(f"Target                 : {auto_results['url']}")
        
        # Show detected platforms
        platforms_str = ", ".join(detected_platforms) if detected_platforms else "None detected"
        print(f"Detected Platforms     : {colorize(platforms_str, Color.GREEN if detected_platforms else Color.YELLOW)}")
        
        print(f"Vulnerabilities Found  : {colorize(str(vuln_count), Color.RED if vuln_count > 0 else Color.GREEN)}")
        score_str = f"{headers_analysis.get('score', 0)}/{headers_analysis.get('max_score', 100)}"
        score_color = Color.GREEN if headers_analysis.get('score', 0) >= 80 else Color.YELLOW if headers_analysis.get('score', 0) >= 60 else Color.RED
        print(f"Security Score         : {colorize(score_str, score_color)}")
        print(f"Server                 : {server_info.get('server', 'Unknown')}")
    
    # Clean up temp data
    if "_temp" in auto_results:
        del auto_results["_temp"]


def save_scan_report(auto_results, output_file):
    """Save scan report to file."""
    try:
        # Ensure output file is in reports directory
        if not os.path.dirname(output_file):
            reports_dir = os.path.join(os.path.dirname(__file__), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            output_file = os.path.join(reports_dir, output_file)
        
        with open(output_file, 'w') as f:
            json.dump(auto_results, f, indent=2)
        print(f"\n{Color.GREEN}✓ Report saved to: {output_file}{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}✗ Error saving report: {e}{Color.RESET}")

def main():
    import sys
    
    # Check for command-line flags
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    show_full = "--full" in sys.argv or "-f" in sys.argv
    output_file = None
    auto = "--auto" in sys.argv
    target = None
    mode = "auto"
    use_apis = "--no-apis" not in sys.argv
    
    # Check for -o option
    if "-o" in sys.argv:
        o_index = sys.argv.index("-o")
        if o_index + 1 < len(sys.argv):
            output_file = sys.argv[o_index + 1]
    
    # Check for --target option
    if "--target" in sys.argv:
        t_index = sys.argv.index("--target")
        if t_index + 1 < len(sys.argv):
            target = sys.argv[t_index + 1]
    
    # Check for --mode option
    if "--mode" in sys.argv:
        m_index = sys.argv.index("--mode")
        if m_index + 1 < len(sys.argv):
            mode = sys.argv[m_index + 1].lower()
    
    if verbose:
        print(colorize("[INFO] Verbose mode enabled", Color.CYAN))
    if show_full:
        print(colorize("[INFO] Full response output enabled", Color.CYAN))
    if output_file:
        print(colorize(f"[INFO] JSON report will be saved to: {output_file}", Color.CYAN))
    if auto:
        api_status = "enabled" if use_apis else "disabled"
        print(colorize(f"[INFO] Auto mode enabled with {mode} scan (APIs: {api_status})", Color.CYAN))
        if not target:
            url = prompt("Target URL")
        else:
            url = target
            print(colorize(f"[INFO] Target: {url}", Color.CYAN))
        auto_mode_test(url, verbose=verbose, output_file=output_file, mode=mode, use_apis=use_apis)
        return
    
    while True:
        choice = display_main_menu()
        
        # General Vulnerability Test
        if choice == "1":
            url = prompt("Target URL (no params)")
            method = choose_method()
            
            preset_params = choose_preset()
            manual_params = parse_params()
            all_params = {**manual_params, **preset_params}
            
            print("\nFinal parameters:")
            print(json.dumps(all_params, indent=2))
            
            confirm = prompt("Send request? (y/n)", "y")
            if confirm.lower() != "y":
                continue
            
            # Check if target is WordPress
            print(f"\n{Color.CYAN}[*] Checking for WordPress...{Color.RESET}")
            wordpress_data = detect_wordpress(url)
            
            if wordpress_data and wordpress_data.get("is_wordpress"):
                print(colorize("✓ WordPress detected! Running CVE tests...", Color.GREEN))
                cve_results = test_wordpress_cves(url, verbose=verbose)
                wordpress_data["cve_results"] = cve_results
            
            if method == "GET":
                resp, elapsed = send_request(url, method, all_params, None, verbose=verbose)
            else:
                resp, elapsed = send_request(url, method, None, all_params, verbose=verbose)
            
            summarize_response(resp, elapsed, all_params, verbose=verbose, show_full=show_full, wordpress_data=wordpress_data)
            
            if output_file:
                try:
                    saved_path = save_json_report(output_file, url, method, all_params, resp, elapsed, wordpress_results=wordpress_data)
                    print(colorize(f"\n✓ Report saved to: {saved_path}", Color.GREEN))
                except Exception as e:
                    print(colorize(f"\n✗ Error saving report: {e}", Color.RED))
        
        # WordPress Testing
        elif choice == "2":
            url = prompt("Target URL (WordPress)")
            
            while True:
                wp_choice = display_wordpress_menu()
                
                if wp_choice == "1":
                    # Automatic scan
                    print(f"\n{Color.CYAN}[*] Scanning for WordPress...{Color.RESET}")
                    wordpress_data = detect_wordpress(url)
                    
                    if wordpress_data and wordpress_data.get("is_wordpress"):
                        print(colorize("✓ WordPress detected!", Color.GREEN))
                        if wordpress_data.get("wordpress_version"):
                            print(f"  Version: {wordpress_data['wordpress_version']}")
                        if wordpress_data.get("wordpress_theme"):
                            print(f"  Theme: {wordpress_data['wordpress_theme']}")
                        
                        print(f"\n{Color.CYAN}Running CVE tests...{Color.RESET}")
                        cve_results = test_wordpress_cves(url, verbose=verbose)
                        
                        print(f"\n{Color.BOLD}{Color.MAGENTA}CVE TEST RESULTS:{Color.RESET}")
                        for cve in cve_results:
                            if cve.get("vulnerable") is True:
                                icon = colorize("⚠️  VULNERABLE:", Color.RED)
                            elif cve.get("vulnerable") is False:
                                icon = colorize("✓ SAFE:", Color.GREEN)
                            else:
                                icon = colorize("ℹ️  INFO:", Color.BLUE)
                            cve_name = cve.get('cve', 'UNKNOWN')
                            cve_desc = cve.get('description', 'No description available')
                            print(f"{icon} {cve_name} - {cve_desc}")
                        
                        if output_file:
                            try:
                                # Ensure output file is in reports directory
                                if not os.path.dirname(output_file):
                                    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
                                    os.makedirs(reports_dir, exist_ok=True)
                                    output_file = os.path.join(reports_dir, output_file)
                                
                                report_data = {
                                    "wordpress_info": wordpress_data,
                                    "cve_results": cve_results,
                                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                                }
                                with open(output_file, 'w') as f:
                                    json.dump(report_data, f, indent=2)
                                print(colorize(f"\n✓ Report saved to: {output_file}", Color.GREEN))
                            except Exception as e:
                                print(colorize(f"\n✗ Error saving report: {e}", Color.RED))
                    else:
                        print(colorize("✗ WordPress not detected on this site", Color.YELLOW))
                
                elif wp_choice == "2":
                    # Select specific CVEs
                    while True:
                        selection = display_cve_menu()
                        
                        if selection in ("BACK", None):
                            break
                        
                        if selection == "ALL":
                            print(f"\n{Color.CYAN}Running all configured CVE tests...{Color.RESET}")
                            cve_results = test_wordpress_cves(url, verbose=verbose)
                        else:
                            print(f"\n{Color.CYAN}Running {selection} test...{Color.RESET}")
                            cve_results = test_wordpress_cves(url, verbose=verbose, selected_ids=[selection])
                        
                        if not cve_results:
                            print(colorize("No CVE results returned.", Color.YELLOW))
                            continue
                        
                        print(f"\n{Color.BOLD}{Color.MAGENTA}CVE TEST RESULTS:{Color.RESET}")
                        for cve in cve_results:
                            if cve.get("vulnerable") is True:
                                icon = colorize("⚠️  VULNERABLE:", Color.RED)
                            elif cve.get("vulnerable") is False:
                                icon = colorize("✓ SAFE:", Color.GREEN)
                            else:
                                icon = colorize("ℹ️  INFO:", Color.BLUE)
                            cve_name = cve.get('cve', 'UNKNOWN')
                            cve_desc = cve.get('description', 'No description available')
                            print(f"{icon} {cve_name} - {cve_desc}")
                
                elif wp_choice == "3":
                    # Version detection only via config handler
                    print(f"\n{Color.CYAN}[*] Detecting WordPress version...{Color.RESET}")
                    version_results = test_wordpress_cves(url, verbose=verbose, selected_ids=["VERSION-DETECTION"])
                    if version_results:
                        for item in version_results:
                            status = item.get("vulnerable")
                            if status == "detected":
                                print(colorize(f"✓ WordPress version detected: {item.get('version', 'unknown')}", Color.GREEN))
                            else:
                                print(colorize("✗ Could not detect WordPress version", Color.YELLOW))
                    else:
                        print(colorize("✗ Version detection definition not available", Color.YELLOW))
                
                elif wp_choice == "4":
                    break
        
        # Payload Builder
        elif choice == "3":
            url = prompt("Target URL (for payload testing)")
            
            while True:
                builder_choice = display_payload_builder_menu()
                
                if builder_choice == "1":
                    build_nosql_payload(url)
                elif builder_choice == "2":
                    build_ssti_payload(url)
                elif builder_choice == "3":
                    build_ssrf_payload(url)
                elif builder_choice == "4":
                    build_custom_payload(url)
                elif builder_choice == "5":
                    break
                
                prompt("\nPress Enter to continue...")
        
        # Server & Port Detection
        elif choice == "4":
            url = prompt("Target URL")
            print(f"\n{Color.CYAN}Scanning...{Color.RESET}")
            server_info = detect_server_and_ports(url, verbose=True)
            
            print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
            print(f"SERVER INFORMATION")
            print(f"{'='*60}{Color.RESET}\n")
            print(f"Server Header: {server_info['server']}")
            print(f"Web Server:    {server_info['web_server']}")
            print(f"Powered By:    {server_info['powered_by']}")
            
            if server_info['open_ports']:
                print(f"\nOpen Ports:")
                for port_info in server_info['open_ports']:
                    print(f"  {port_info['port']}/{port_info['service']}: OPEN")
            else:
                print(f"\nNo additional ports detected (may be filtered)")
        
        # Security Headers Analysis
        elif choice == "5":
            url = prompt("Target URL")
            print(f"\n{Color.CYAN}Analyzing headers...{Color.RESET}")
            headers_analysis = analyze_security_headers(url, verbose=True)
            
            print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
            print(f"SECURITY HEADERS ANALYSIS")
            print(f"{'='*60}{Color.RESET}\n")
            print(f"Security Score: {headers_analysis['score']}/{headers_analysis['max_score']}")
            
            if headers_analysis['missing']:
                print(f"\nMissing Headers ({len(headers_analysis['missing'])}):")
                for missing in headers_analysis['missing']:
                    print(f"  ✗ {missing}")
        
        # Auto Mode
        elif choice == "6":
            url = prompt("Target URL")
            auto_mode_test(url, verbose=verbose, output_file=output_file)
        
        # Exit
        elif choice == "7":
            print(colorize("\nGoodbye!", Color.GREEN))
            break
        
        else:
            print(colorize("Invalid option. Please try again.", Color.RED))

if __name__ == "__main__":
    main()
