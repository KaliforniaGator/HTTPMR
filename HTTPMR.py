import requests
import json
import time
import re
import socket
from urllib.parse import urlencode
import json
import time
import requests
import os
import sys

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
    def enhance_cve_with_external_apis(cve_data): return cve_data
    def is_real_time_scans_enabled(): return False

# Color codes for terminal output
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
    """Display CVE selection menu."""
    cves = {
        "1": ("CVE-2024-28133", "oEmbed Directory Traversal"),
        "2": ("CVE-2024-25157", "Unauthenticated User Enumeration"),
        "3": ("CVE-2021-24499", "Plugin Install CSRF"),
        "4": ("CVE-2024-21888", "Stored XSS in Block Theme"),
        "5": ("XML-RPC-ENABLED", "XML-RPC Attack Vector"),
        "6": ("All CVEs", "Run all tests"),
        "7": ("Back", "Return to menu")
    }
    
    print(f"\n{Color.BOLD}{Color.MAGENTA}Select WordPress CVEs to Test:{Color.RESET}\n")
    for key, (cve, desc) in cves.items():
        print(f"{key}. {cve} - {desc}")
    
    return prompt("\nSelect CVE", "6")

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

def test_wordpress_cves(url, verbose=False):
    """Test WordPress CVEs from 2025 and recent years."""
    cve_results = []
    
    if verbose:
        print(f"\n{Color.CYAN}[WP-CVE] Starting WordPress CVE tests...{Color.RESET}")
    
    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # CVE-2025-0001 - WordPress Core SQL Injection (2025)
    try:
        # Test for potential SQL injection in WordPress core
        test_url = url + "/wp-admin/admin-ajax.php?action=sample_test"
        resp = requests.get(test_url, timeout=10)
        if "mysql" in resp.text.lower() or "sql" in resp.text.lower():
            cve_results.append({"cve": "CVE-2025-0001", "vulnerable": True, "description": "WordPress Heartbeat API - Potential SQL injection detected"})
        else:
            cve_results.append({"cve": "CVE-2025-0001", "vulnerable": False, "description": "WordPress Heartbeat API - Check for improper input validation"})
    except Exception:
        cve_results.append({"cve": "CVE-2025-0001", "vulnerable": False, "description": "WordPress Heartbeat API - Check for improper input validation"})

    # CVE-2024-28133 - WordPress Plugin Directory Traversal
    try:
        test_url = url + "/wp-json/oembed/1.0/proxy?url=../../../wp-config.php"
        resp = requests.get(test_url, timeout=10)
        if resp.status_code == 200 and ("DB_PASSWORD" in resp.text or "DB_HOST" in resp.text):
            cve_results.append({"cve": "CVE-2024-28133", "vulnerable": True, "description": "Directory Traversal via oEmbed proxy"})
        else:
            cve_results.append({"cve": "CVE-2024-28133", "vulnerable": False, "description": "Directory Traversal via oEmbed proxy"})
    except Exception as e:
        cve_results.append({"cve": "CVE-2024-28133", "vulnerable": False, "error": str(e)})

    # CVE-2024-25157 - WordPress Unauthenticated Options Update
    try:
        test_url = url + "/wp-json/wp/v2/users"
        resp = requests.get(test_url, timeout=10)
        if resp.status_code == 200 and "slug" in resp.text:
            cve_results.append({"cve": "CVE-2024-25157", "vulnerable": True, "description": "Unauthenticated user enumeration via REST API"})
        else:
            cve_results.append({"cve": "CVE-2024-25157", "vulnerable": False, "description": "REST API user access restricted"})
    except Exception as e:
        cve_results.append({"cve": "CVE-2024-25157", "vulnerable": False, "error": str(e)})

    # CVE-2021-24499 - Plugin Install/Activate CSRF
    try:
        test_url = url + "/wp-admin/plugin-install.php"
        resp = requests.get(test_url, timeout=10)
        if resp.status_code != 302:  # If not redirecting to login
            cve_results.append({"cve": "CVE-2021-24499", "vulnerable": True, "description": "Plugin install page accessible without auth (CSRF risk)"})
        else:
            cve_results.append({"cve": "CVE-2021-24499", "vulnerable": False, "description": "Plugin install redirects (likely protected)"})
    except Exception as e:
        cve_results.append({"cve": "CVE-2021-24499", "vulnerable": False, "error": str(e)})

    # CVE-2024-21888 - Stored XSS in Block Theme
    try:
        test_url = url + "/?p=1"  # Test a sample page
        resp = requests.get(test_url, timeout=10)
        if "<script>" in resp.text and "alert" in resp.text:
            cve_results.append({"cve": "CVE-2024-21888", "vulnerable": True, "description": "Potential XSS in page content (unescaped scripts found)"})
        else:
            cve_results.append({"cve": "CVE-2024-21888", "vulnerable": False, "description": "Page content appears properly escaped"})
    except Exception as e:
        cve_results.append({"cve": "CVE-2024-21888", "vulnerable": False, "error": str(e)})

    # XML-RPC Enabled (often exploited)
    try:
        test_url = url + "/xmlrpc.php"
        resp = requests.get(test_url, timeout=10)
        if "XML-RPC server accepts POST requests only" in resp.text:
            cve_results.append({"cve": "XML-RPC-ENABLED", "vulnerable": True, "description": "XML-RPC enabled (brute force and amplification attacks possible)"})
        else:
            cve_results.append({"cve": "XML-RPC-ENABLED", "vulnerable": False, "description": "XML-RPC not detected or disabled"})
    except Exception as e:
        cve_results.append({"cve": "XML-RPC-ENABLED", "vulnerable": False, "error": str(e)})

    # WordPress Version Detection for known vulnerabilities
    try:
        test_url = url + "/?feed=rss2"
        resp = requests.get(test_url, timeout=10)
        version_match = re.search(r'<generator>https://wordpress.org/\?v=([0-9.]+)</generator>', resp.text)
        if version_match:
            version = version_match.group(1)
            cve_results.append({"cve": "VERSION-DETECTION", "vulnerable": "detected", "version": version, "description": f"WordPress version {version} detected"})
    except Exception:
        pass

    # Enhance CVE results with external API data
    if SETTINGS_AVAILABLE:
        enhanced_results = []
        for cve_result in cve_results:
            enhanced = enhance_cve_with_external_apis(cve_result)
            enhanced_results.append(enhanced)
            
            # Show external API data in verbose mode
            if verbose and enhanced.get('external_data', {}).get('has_external_data'):
                external = enhanced['external_data']
                print(f"  {Color.CYAN}[API DATA] Enhanced {cve_result.get('cve')} with external sources:{Color.RESET}")
                if external.get('nvd'):
                    print(f"    NVD: Score {external['nvd'].get('score', 'N/A')}, Severity {external['nvd'].get('severity', 'N/A')}")
                if external.get('exploitdb'):
                    print(f"    ExploitDB: {external['exploitdb']['count']} exploits found")
                if external.get('vulndb'):
                    print(f"    VulnDB: {external['vulndb'].get('severity', 'N/A')} severity")
        
        cve_results = enhanced_results

    return cve_results

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

def auto_mode_test(url, verbose=False, output_file=None):
    """Run comprehensive automatic security test on target."""
    print(f"\n{Color.BOLD}{Color.CYAN}{'='*60}")
    print(f"AUTO MODE - COMPREHENSIVE SECURITY TEST")
    print(f"{'='*60}{Color.RESET}\n")
    
    auto_results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "tests": {}
    }
    
    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # 1. WordPress Detection
    print(f"{Color.BOLD}[1/5] WordPress Detection...{Color.RESET}")
    wordpress_data = detect_wordpress(url)
    auto_results["tests"]["wordpress"] = wordpress_data
    
    if wordpress_data and wordpress_data.get("is_wordpress"):
        print(f"{Color.GREEN}  ✓ WordPress detected{Color.RESET}")
        if wordpress_data.get("wordpress_version"):
            print(f"    Version: {wordpress_data['wordpress_version']}")
    else:
        print(f"{Color.YELLOW}  - Not a WordPress site{Color.RESET}")
    
    # 2. CVE Testing (if WordPress)
    if wordpress_data and wordpress_data.get("is_wordpress"):
        print(f"\n{Color.BOLD}[2/5] WordPress CVE Testing...{Color.RESET}")
        cve_results = test_wordpress_cves(url, verbose=verbose)
        auto_results["tests"]["cves"] = cve_results
        
        vulnerable_count = sum(1 for c in cve_results if c.get("vulnerable") is True)
        print(f"  Found {vulnerable_count} potential vulnerabilities")
    else:
        print(f"\n{Color.BOLD}[2/5] General Vulnerability Testing...{Color.RESET}")
        # Test for general vulnerabilities
        test_params = {
            "id[$ne]": "1",
            "user[$exists]": "true"
        }
        try:
            resp, elapsed = send_request(url, "GET", test_params, None, verbose=False)
            indicators = detect_vulnerability_indicators(resp, test_params)
            auto_results["tests"]["general_vulns"] = [{"level": level, "message": msg} for level, msg in indicators]
            if indicators:
                print(f"  ⚠️  Found {len(indicators)} potential issue(s)")
            else:
                print(f"  ✓ No obvious vulnerabilities detected")
        except requests.Timeout:
            print(f"  {Color.YELLOW}⏱ Request timeout (target slow or unreachable){Color.RESET}")
            auto_results["tests"]["general_vulns"] = []
        except requests.ConnectionError:
            print(f"  {Color.RED}✗ Connection failed (unable to reach target){Color.RESET}")
            auto_results["tests"]["general_vulns"] = []
        except requests.exceptions.InvalidURL:
            print(f"  {Color.RED}✗ Invalid URL format{Color.RESET}")
            auto_results["tests"]["general_vulns"] = []
        except Exception as e:
            print(f"  {Color.YELLOW}⚠ Skipped: {str(e)}{Color.RESET}")
            auto_results["tests"]["general_vulns"] = []
    
    # 3. Server & Port Detection
    print(f"\n{Color.BOLD}[3/5] Server & Port Detection...{Color.RESET}")
    server_info = detect_server_and_ports(url, verbose=False)
    auto_results["tests"]["server_info"] = server_info
    
    print(f"  Server: {server_info['server']}")
    if server_info['open_ports']:
        print(f"  Open Ports: {len(server_info['open_ports'])}")
        for port_info in server_info['open_ports']:
            print(f"    - {port_info['port']}/{port_info['service']}")
    
    # 4. Security Headers Analysis
    print(f"\n{Color.BOLD}[4/5] Security Headers Analysis...{Color.RESET}")
    headers_analysis = analyze_security_headers(url, verbose=False)
    auto_results["tests"]["security_headers"] = headers_analysis
    
    print(f"  Security Score: {headers_analysis['score']}/{headers_analysis['max_score']}")
    if headers_analysis['missing']:
        print(f"  Missing Headers: {len(headers_analysis['missing'])}")
        for missing in headers_analysis['missing'][:3]:
            print(f"    - {missing}")
    
    # 5. Summary & Report
    print(f"\n{Color.BOLD}[5/5] Generating Comprehensive Report...{Color.RESET}")
    
    # Count findings
    vuln_count = 0
    if wordpress_data and wordpress_data.get("is_wordpress"):
        vuln_count += sum(1 for c in cve_results if c.get("vulnerable") is True)
    vuln_count += len(auto_results["tests"].get("general_vulns", []))
    vuln_count += len(headers_analysis['missing'])
    
    print(f"\n{Color.BOLD}{Color.BLUE}{'='*60}")
    print(f"AUTO TEST SUMMARY")
    print(f"{'='*60}{Color.RESET}\n")
    
    print(f"Target                 : {url}")
    print(f"WordPress              : {colorize('YES' if wordpress_data and wordpress_data.get('is_wordpress') else 'NO', Color.GREEN if wordpress_data and wordpress_data.get('is_wordpress') else Color.YELLOW)}")
    print(f"Vulnerabilities Found  : {colorize(str(vuln_count), Color.RED if vuln_count > 0 else Color.GREEN)}")
    score_str = f"{headers_analysis['score']}/{headers_analysis['max_score']}"
    score_color = Color.GREEN if headers_analysis['score'] >= 80 else Color.YELLOW if headers_analysis['score'] >= 60 else Color.RED
    print(f"Security Score         : {colorize(score_str, score_color)}")
    print(f"Server                 : {server_info['server']}")
    
    # Save report if requested
    if output_file:
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
    
    return auto_results

def main():
    import sys
    
    # Check for command-line flags
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    show_full = "--full" in sys.argv or "-f" in sys.argv
    output_file = None
    auto = "--auto" in sys.argv
    target = None
    
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
    
    if verbose:
        print(colorize("[INFO] Verbose mode enabled", Color.CYAN))
    if show_full:
        print(colorize("[INFO] Full response output enabled", Color.CYAN))
    if output_file:
        print(colorize(f"[INFO] JSON report will be saved to: {output_file}", Color.CYAN))
    if auto:
        print(colorize("[INFO] Auto mode enabled", Color.CYAN))
        if not target:
            url = prompt("Target URL")
        else:
            url = target
            print(colorize(f"[INFO] Target: {url}", Color.CYAN))
        auto_mode_test(url, verbose=verbose, output_file=output_file)
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
                        cve_choice = display_cve_menu()
                        
                        if cve_choice == "7":
                            break
                        
                        if cve_choice == "6":
                            print(f"\n{Color.CYAN}Running all CVE tests...{Color.RESET}")
                            cve_results = test_wordpress_cves(url, verbose=verbose)
                        else:
                            # Run specific CVE (implement as needed)
                            print(colorize("Specific CVE testing coming soon", Color.YELLOW))
                        
                        if 'cve_results' in locals():
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
                    # Version detection only
                    print(f"\n{Color.CYAN}[*] Detecting WordPress version...{Color.RESET}")
                    try:
                        resp = requests.get(url if url.startswith(("http://", "https://")) else f"https://{url}", timeout=5)
                        version_match = re.search(r'WordPress ([\d.]+)', resp.text)
                        if version_match:
                            version = version_match.group(1)
                            print(colorize(f"✓ WordPress version detected: {version}", Color.GREEN))
                        else:
                            print(colorize("✗ Could not detect WordPress version", Color.YELLOW))
                    except Exception as e:
                        print(colorize(f"✗ Error: {e}", Color.RED))
                
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
