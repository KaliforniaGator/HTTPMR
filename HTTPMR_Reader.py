#!/usr/bin/env python3
"""
HTTPMR Report Reader - Enterprise Security Report Interpreter
Converts technical JSON reports into human-readable explanations with TTPs
(Tactics, Techniques, and Procedures) for non-technical stakeholders.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

# ANSI Color codes for terminal output
class Color:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'

# ==================== THREAT DATABASE ====================
# Technical explanations and TTPs for vulnerabilities

THREAT_DATABASE = {
    "CVE-2025-0001": {
        "name": "WordPress Heartbeat API Vulnerability",
        "severity": "MEDIUM",
        "impact": "Unauthorized Access",
        "layman_explanation": "WordPress has a background 'heartbeat' feature that keeps the site responsive. Attackers can send specially crafted requests to this feature to inject malicious code or access information they shouldn't.",
        "tactic": "Execution & Lateral Movement",
        "technique": "Command & Scripting Interpreter (T1059)",
        "procedure": "1. Identify the heartbeat API endpoint\n2. Craft malicious AJAX request with code injection payload\n3. Execute arbitrary PHP code with WordPress privileges\n4. Gain unauthorized site access",
        "business_impact": "Your website could run attacker's code, stealing customer data or redirecting visitors to malicious sites.",
        "fix": "Keep WordPress updated to the latest version. Disable unnecessary AJAX endpoints if not used."
    },
    
    "CVE-2024-28133": {
        "name": "oEmbed Directory Traversal",
        "severity": "HIGH",
        "impact": "Information Disclosure",
        "layman_explanation": "The oEmbed feature (which embeds media from other sites) allows attackers to access files they shouldn't be able to read from your server, like configuration files containing passwords.",
        "tactic": "Reconnaissance & Discovery",
        "technique": "Enumerate Local System Information (T1217)",
        "procedure": "1. Target the /wp-json/oembed/1.0/proxy endpoint\n2. Use path traversal (../../../) to navigate file system\n3. Read sensitive files like /etc/passwd or wp-config.php\n4. Extract database credentials and API keys",
        "business_impact": "Attackers gain access to your database passwords, API keys, and customer information stored in configuration files.",
        "fix": "Update WordPress to patch. Restrict file system permissions. Use .htaccess to block access to sensitive files."
    },
    
    "CVE-2024-25157": {
        "name": "Unauthenticated User Enumeration",
        "severity": "MEDIUM",
        "impact": "Information Disclosure",
        "layman_explanation": "The WordPress REST API publicly lists all user names and IDs on your site without requiring a login. This gives attackers a target list for password-guessing attacks.",
        "tactic": "Reconnaissance",
        "technique": "Gather Victim Identity Information (T1589)",
        "procedure": "1. Attacker queries /wp-json/wp/v2/users endpoint\n2. API returns list of all usernames and user IDs\n3. Attacker uses this list for brute-force password attacks\n4. Once they crack a password, they gain site access",
        "business_impact": "Attackers can more easily guess passwords and access administrator accounts. Your site security is only as strong as the weakest password.",
        "fix": "Disable user enumeration via REST API. Use strong, unique passwords. Enable two-factor authentication."
    },
    
    "CVE-2021-24499": {
        "name": "Plugin Installation CSRF",
        "severity": "HIGH",
        "impact": "Unauthorized Plugin Installation",
        "layman_explanation": "An attacker can trick a logged-in administrator into installing malicious plugins without their knowledge. They do this by sending the admin a link that, when clicked, secretly installs the attacker's code.",
        "tactic": "Execution",
        "technique": "Cross-Site Request Forgery (T1149 - Social Engineering)",
        "procedure": "1. Attacker crafts malicious link disguised as innocent URL\n2. Admin clicks link while logged into WordPress\n3. Malicious plugin automatically installed on site\n4. Attacker gains full control of the website",
        "business_impact": "Your website can be completely compromised. Attackers can steal data, inject ads, or use your site to attack others.",
        "fix": "Keep WordPress updated. Be cautious with links from unknown sources. Restrict plugin installation permissions."
    },
    
    "CVE-2024-21888": {
        "name": "Stored XSS in Block Theme",
        "severity": "HIGH",
        "impact": "Code Injection & Data Theft",
        "layman_explanation": "Attackers can inject JavaScript code into your website pages that runs when visitors view the page. This code can steal visitor passwords, credit cards, or redirect them to phishing sites.",
        "tactic": "Execution & Exfiltration",
        "technique": "Stored XSS - Web Shell (T1505)",
        "procedure": "1. Attacker identifies unsanitized input field (comments, posts, etc.)\n2. Injects malicious JavaScript: <script>alert('hacked')</script>\n3. Code stored in database and runs every time page is viewed\n4. Visitor's browser executes attacker's code\n5. Steals cookies, passwords, or redirects to malicious site",
        "business_impact": "Visitor data is compromised. Your site reputation damaged. Potential legal liability for data breaches.",
        "fix": "Keep WordPress and themes updated. Validate all user input. Sanitize output. Use Content Security Policy headers."
    },
    
    "XML-RPC-ENABLED": {
        "name": "XML-RPC Protocol Enabled",
        "severity": "MEDIUM",
        "impact": "Amplification Attack & Brute Force",
        "layman_explanation": "XML-RPC is an old WordPress feature that allows remote blog management. It's often used for automation but creates a security risk because it can be abused for password-guessing attacks and spam amplification.",
        "tactic": "Impact & Defense Evasion",
        "technique": "Brute Force Attack (T1110)",
        "procedure": "1. Attacker discovers XML-RPC endpoint at /xmlrpc.php\n2. Uses it to send thousands of login attempts (harder to block than HTTP)\n3. Each attempt uses different password combinations\n4. Once password cracked, attacker gains access\n5. Server also affected by traffic amplification attacks",
        "business_impact": "Your site can be slowed down or knocked offline by brute force attacks. Attackers can break into administrator accounts.",
        "fix": "Disable XML-RPC if not needed: wp-config.php add define('XMLRPC_REQUEST_METHODS_ALLOWED', 'GET');"
    },
    
    "VERSION-DETECTION": {
        "name": "WordPress Version Detected",
        "severity": "INFO",
        "impact": "Reconnaissance",
        "layman_explanation": "Your website publicly broadcasts which version of WordPress it's running. This helps attackers know which vulnerabilities might affect you, like knowing which locks are on your doors.",
        "tactic": "Reconnaissance",
        "technique": "Gather Victim OS/Software Information (T1592)",
        "procedure": "1. Attacker checks WordPress meta tags or files\n2. Identifies exact WordPress version number\n3. Looks up known vulnerabilities for that version\n4. Crafts targeted attacks for those specific weaknesses",
        "business_impact": "Attackers can specifically target vulnerabilities in your version. Newer version usually means more secure.",
        "fix": "Hide WordPress version from headers. Remove version from source code comments and feeds."
    },
    
    "HSTS-MISSING": {
        "name": "HSTS Header Not Configured",
        "severity": "MEDIUM",
        "impact": "Man-in-the-Middle Attack",
        "layman_explanation": "HSTS tells browsers 'always use encrypted connections to this website.' Without it, attackers can force connections through unencrypted channels and spy on data.",
        "tactic": "Initial Access & Eavesdropping",
        "technique": "Downgrade Attack (T1409)",
        "procedure": "1. Attacker intercepts user's connection\n2. Without HSTS, forces browser to use HTTP (unencrypted)\n3. Attacker can read passwords and data in transit\n4. Attacker injects malicious code into pages",
        "business_impact": "Customer passwords and credit card numbers can be stolen during transmission.",
        "fix": "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    
    "CSP-MISSING": {
        "name": "Content Security Policy Not Configured",
        "severity": "MEDIUM",
        "impact": "XSS Attacks & Malware Injection",
        "layman_explanation": "CSP is like a whitelist that tells the browser 'only load JavaScript from MY server, not from random websites.' Without it, attackers can inject and run their own malicious code.",
        "tactic": "Execution",
        "technique": "Malware Injection (T1021)",
        "procedure": "1. Attacker finds way to inject code (XSS vulnerability)\n2. Browser loads malicious JavaScript since CSP doesn't restrict it\n3. Attacker's code steals cookies, redirects users, or harvests data\n4. No way for browser to know this isn't legitimate",
        "business_impact": "Attackers can inject malicious ads, steal customer data, or redirect visitors to phishing sites.",
        "fix": "Implement CSP header: Content-Security-Policy: default-src 'self'"
    },
    
    "XFRAME-MISSING": {
        "name": "X-Frame-Options Header Missing",
        "severity": "MEDIUM",
        "impact": "Clickjacking Attack",
        "layman_explanation": "Without this header, attackers can invisibly embed your website in their own page and trick visitors into clicking buttons they don't see, like 'Transfer Money' or 'Approve Purchase'.",
        "tactic": "Initial Access & Social Engineering",
        "technique": "Clickjacking (T1204)",
        "procedure": "1. Attacker creates web page with hidden iframe containing your site\n2. Overlays fake buttons on top of the hidden site\n3. Visitor clicks what they think is a normal button\n4. Hidden click actually performs action on your site\n5. Victim approves transfer, changes password, or triggers action",
        "business_impact": "Attackers can make your users perform actions without their knowledge. Financial fraud potential.",
        "fix": "Add X-Frame-Options: SAMEORIGIN or DENY to prevent embedding."
    },
    
    "MIMETYPE-MISSING": {
        "name": "X-Content-Type-Options Header Missing",
        "severity": "LOW",
        "impact": "MIME Type Sniffing",
        "layman_explanation": "Browsers can 'guess' what type of file is being sent even if you tell them it's a different type. This can be exploited to run malicious scripts.",
        "tactic": "Execution",
        "technique": "File Type Handling (T1036)",
        "procedure": "1. Attacker uploads file claiming it's a harmless document\n2. Browser ignores the file type you specified\n3. Browser 'sniffs' the file and realizes it contains code\n4. Browser executes the code instead of displaying document",
        "business_impact": "Uploaded files could be executed as code rather than treated as documents.",
        "fix": "Add X-Content-Type-Options: nosniff header to prevent sniffing."
    }
}

# ==================== UTILITY FUNCTIONS ====================

def colorize(text: str, color: str) -> str:
    """Add color to terminal text."""
    return f"{color}{text}{Color.RESET}"

def clear_screen():
    """Clear terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')

def print_header(title: str, width: int = 70):
    """Print a formatted header."""
    print(f"\n{Color.BOLD}{Color.BLUE}{'='*width}")
    print(f"{title.center(width)}")
    print(f"{'='*width}{Color.RESET}\n")

def print_section(title: str, width: int = 70):
    """Print a section header."""
    print(f"\n{Color.BOLD}{Color.CYAN}{title}{Color.RESET}")
    print(f"{Color.DIM}{'-'*len(title)}{Color.RESET}")

def prompt(msg: str, options: Optional[List[str]] = None) -> str:
    """Get user input with optional validation."""
    while True:
        response = input(f"\n{Color.BOLD}{msg}{Color.RESET} >> ").strip().lower()
        if options is None or response in options:
            return response
        print(colorize(f"Invalid option. Please choose: {', '.join(options)}", Color.RED))

def paginate(content: List[str], items_per_page: int = 5) -> List[List[str]]:
    """Split content into pages."""
    return [content[i:i+items_per_page] for i in range(0, len(content), items_per_page)]

def display_page(page: List[str], page_num: int, total_pages: int, show_nav: bool = True) -> bool:
    """Display a single page. Returns True if user wants to continue."""
    # If a page is provided, clear the screen and show the page content.
    # If `page` is empty, do NOT clear the screen — this preserves content
    # printed by the caller (e.g., show_executive_summary or other views)
    # and avoids erasing the report before the "Press ENTER to continue" prompt.
    if page:
        clear_screen()
        for item in page:
            print(item)
    else:
        # When page is empty, leave the screen as-is so previously printed
        # report content remains visible to the user.
        pass

    if show_nav and total_pages > 1:
        print(f"\n{Color.DIM}[Page {page_num + 1}/{total_pages}]{Color.RESET}")
        print(colorize("Press ENTER to continue, 'b' to go back, 'q' to quit", Color.YELLOW))
        response = input().strip().lower()

        if response == 'q':
            return False
        elif response == 'b' and page_num > 0:
            return True
    else:
        print(colorize("\nPress ENTER to continue...", Color.YELLOW))
        input()

    return True

# ==================== REPORT PARSING ====================

def load_report(filepath: str) -> Optional[Dict[str, Any]]:
    """Load and parse JSON report."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(colorize(f"Report not found: {filepath}", Color.RED))
        return None
    except json.JSONDecodeError:
        print(colorize(f"Invalid JSON format in: {filepath}", Color.RED))
        return None

def get_threat_info(threat_key: str) -> Dict[str, str]:
    """Get threat information from database."""
    if threat_key in THREAT_DATABASE:
        return THREAT_DATABASE[threat_key]
    
    # Generic template for unknown threats
    return {
        "name": threat_key,
        "severity": "UNKNOWN",
        "impact": "Unknown Impact",
        "layman_explanation": "This is a technical security issue that requires investigation.",
        "tactic": "Unknown",
        "technique": "Unknown",
        "procedure": "Requires technical analysis",
        "business_impact": "Potential security risk identified",
        "fix": "Consult with security team for remediation"
    }

# ==================== DISPLAY FUNCTIONS ====================

def show_executive_summary(report: Dict[str, Any]):
    """Show high-level executive summary."""
    clear_screen()
    print_header("EXECUTIVE SUMMARY")
    
    url = report.get('url', 'Unknown')
    timestamp = report.get('timestamp', 'Unknown')
    tests = report.get('tests', {})
    
    # Count vulnerabilities
    vuln_count = 0
    if 'cves' in tests:
        vuln_count = sum(1 for cve in tests['cves'] if cve.get('vulnerable') is True)
    
    security_headers = tests.get('security_headers', {})
    missing_headers = len(security_headers.get('missing', []))
    security_score = security_headers.get('score', 0)
    
    wordpress = tests.get('wordpress', {})
    is_wordpress = wordpress.get('is_wordpress', False)
    wp_version = wordpress.get('wordpress_version', 'Unknown')
    
    # Display summary
    print(f"Website URL: {colorize(url, Color.BOLD)}")
    print(f"Scan Date:   {timestamp}")
    print()
    
    print("KEY FINDINGS:")
    print(f"  • WordPress Detected:    {colorize('YES' if is_wordpress else 'NO', Color.GREEN if is_wordpress else Color.YELLOW)} {f'(v{wp_version})' if is_wordpress else ''}")
    print(f"  • Vulnerabilities Found: {colorize(str(vuln_count), Color.RED if vuln_count > 0 else Color.GREEN)}")
    print(f"  • Missing Security Headers: {colorize(str(missing_headers), Color.YELLOW if missing_headers > 0 else Color.GREEN)}")
    print(f"  • Security Score:        {colorize(f'{security_score}/100', Color.RED if security_score < 40 else Color.YELLOW if security_score < 70 else Color.GREEN)}")
    
    server = tests.get('server_info', {})
    open_ports = server.get('open_ports', [])
    if open_ports:
        port_list = ', '.join([f"{p['port']}/{p['service']}" for p in open_ports])
        print(f"  • Open Ports:            {port_list}")
    
    print("\n" + colorize("RECOMMENDATION:", Color.BOLD))
    if vuln_count == 0 and security_score >= 70:
        print(colorize("✓ This website appears well-secured. Continue regular monitoring.", Color.GREEN))
    elif vuln_count == 0 and security_score >= 50:
        print(colorize("⚠ Add missing security headers to improve protection.", Color.YELLOW))
    else:
        print(colorize(f"✗ {vuln_count} vulnerabilities found. Immediate action required!", Color.RED))
    
    display_page([], 0, 0, show_nav=False)

def show_vulnerability_details(report: Dict[str, Any]):
    """Show detailed vulnerability explanations."""
    tests = report.get('tests', {})
    cves = tests.get('cves', [])
    
    if not cves:
        print(colorize("No CVE data found in report.", Color.YELLOW))
        return
    
    # Find vulnerable items
    vulnerabilities = [cve for cve in cves if cve.get('vulnerable') is True]
    
    if not vulnerabilities:
        print(colorize("✓ No vulnerabilities detected!", Color.GREEN))
        display_page([], 0, 0, show_nav=False)
        return
    
    # Build vulnerability pages
    for idx, vuln in enumerate(vulnerabilities):
        clear_screen()
        cve_name = vuln.get('cve', 'UNKNOWN')
        threat_info = get_threat_info(cve_name)
        
        print_header(f"VULNERABILITY {idx + 1} of {len(vulnerabilities)}")
        
        print(f"{Color.BOLD}{threat_info.get('name', cve_name)}{Color.RESET}")
        print(f"CVE ID: {colorize(cve_name, Color.YELLOW)}")
        print(f"Severity: {colorize(threat_info.get('severity', 'UNKNOWN'), Color.RED)}")
        
        print_section("WHAT IS THIS IN SIMPLE TERMS?")
        print(threat_info.get('layman_explanation', 'N/A'))
        
        print_section("BUSINESS IMPACT")
        print(f"❌ {threat_info.get('business_impact', 'N/A')}")
        
        print_section("HOW ATTACKERS EXPLOIT THIS")
        print(f"\n{Color.BOLD}Attack Tactic:{Color.RESET} {threat_info.get('tactic', 'Unknown')}")
        print(f"{Color.BOLD}Technique:{Color.RESET} {threat_info.get('technique', 'Unknown')}")
        print(f"\n{Color.BOLD}Step-by-step Attack Procedure:{Color.RESET}")
        for line in threat_info.get('procedure', 'N/A').split('\n'):
            print(f"  {line}")
        
        print_section("HOW TO FIX IT")
        print(f"✓ {threat_info.get('fix', 'N/A')}")
        
        # Navigation
        if idx < len(vulnerabilities) - 1:
            print(colorize("\nPress ENTER for next vulnerability, 'q' to quit", Color.YELLOW))
            if input().strip().lower() == 'q':
                break
        else:
            display_page([], 0, 0, show_nav=False)

def show_wordpress_analysis(report: Dict[str, Any]):
    """Show WordPress-specific analysis."""
    tests = report.get('tests', {})
    wordpress = tests.get('wordpress', {})
    
    if not wordpress.get('is_wordpress'):
        print(colorize("This website is not running WordPress.", Color.YELLOW))
        display_page([], 0, 0, show_nav=False)
        return
    
    clear_screen()
    print_header("WORDPRESS SECURITY ANALYSIS")
    
    print(f"Website is running WordPress")
    print(f"  • Version:  {colorize(wordpress.get('wordpress_version', 'Unknown'), Color.YELLOW)}")
    print(f"  • Theme:    {wordpress.get('wordpress_theme', 'Unknown')}")
    print()
    
    print_section("WORDPRESS DETECTION INDICATORS")
    indicators = {
        'wp_content': 'WordPress content directory found',
        'wp_includes': 'WordPress includes directory found',
        'admin_panel': 'WordPress admin panel detected',
        'wp_json': 'WordPress REST API accessible'
    }
    
    for key, desc in indicators.items():
        if wordpress.get(key):
            print(f"  ✓ {desc}")
    
    print_section("WORDPRESS CVE TESTS")
    cves = tests.get('cves', [])
    if cves:
        for cve in cves:
            cve_name = cve.get('cve', 'UNKNOWN')
            vulnerable = cve.get('vulnerable')
            
            if vulnerable is True:
                status = colorize("⚠ VULNERABLE", Color.RED)
            elif vulnerable is False:
                status = colorize("✓ SAFE", Color.GREEN)
            else:
                status = colorize("ℹ DETECTED", Color.BLUE)
            
            print(f"  {status}: {cve_name}")
            if cve.get('description'):
                print(f"         {cve['description']}")
    
    display_page([], 0, 0, show_nav=False)

def show_security_headers_analysis(report: Dict[str, Any]):
    """Show security headers in detail."""
    tests = report.get('tests', {})
    headers = tests.get('security_headers', {})
    
    clear_screen()
    print_header("SECURITY HEADERS ANALYSIS")
    
    score = headers.get('score', 0)
    max_score = headers.get('max_score', 100)
    
    print(f"Security Score: {colorize(f'{score}/{max_score}', Color.GREEN if score >= 70 else Color.YELLOW if score >= 40 else Color.RED)}")
    print()
    
    print_section("HEADERS PRESENT (GOOD)")
    present = headers.get('present', {})
    if present:
        for header_name, value in present.items():
            print(f"  ✓ {Color.BOLD}{header_name}{Color.RESET}")
            print(f"    Value: {Color.DIM}{value[:70]}{'...' if len(value) > 70 else ''}{Color.RESET}")
    else:
        print("  None configured")
    
    print_section("HEADERS MISSING (NEEDS ATTENTION)")
    missing = headers.get('missing', [])
    if missing:
        for msg in missing:
            print(f"  ✗ {msg}")
    else:
        print("  All critical headers are present!")
    
    # Show new vulnerability types if detected
    missing_details = headers.get('missing_details', [])
    new_vulns = [d for d in missing_details if d.get('header') not in ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy', 'X-XSS-Protection', 'Referrer-Policy', 'Permissions-Policy']]
    
    if new_vulns:
        print_section("NEW VULNERABILITIES DETECTED (2024-2025)")
        for vuln in new_vulns:
            header_name = vuln.get('header', '')
            message = vuln.get('message', '')
            
            # Color code by severity
            if header_name == "React-Server-Components-RCE":
                vuln_color = Color.RED
                icon = "🚨"
            elif header_name in ["Server", "Cookie-Security"]:
                vuln_color = Color.YELLOW
                icon = "⚠️"
            else:
                vuln_color = Color.MAGENTA
                icon = "ℹ️"
            
            print(f"  {icon} {colorize(header_name.replace('-', ' ').title(), vuln_color)}")
            print(f"    {Color.DIM}{message}{Color.RESET}")
            print()
    
    print_section("WHAT ARE SECURITY HEADERS?")
    print("""Security headers are HTTP response headers that tell web browsers how to
protect your website and its visitors. They're like security instructions
that browsers follow when displaying your website. Examples:

• HSTS: "Always use encrypted connection to this site"
• CSP: "Only load scripts from my server, not others"
• X-Frame-Options: "Don't embed my site in other websites"
• X-Content-Type-Options: "Don't guess file types"

Missing headers leave visitors vulnerable to attacks.""")
    
    display_page([], 0, 0, show_nav=False)

def show_server_information(report: Dict[str, Any]):
    """Show server and infrastructure information."""
    tests = report.get('tests', {})
    server = tests.get('server_info', {})
    
    clear_screen()
    print_header("SERVER & INFRASTRUCTURE INFORMATION")
    
    print_section("SERVER DETAILS")
    print(f"  • Server Type:     {server.get('server', 'Unknown')}")
    print(f"  • Web Server:      {server.get('web_server', 'Unknown')}")
    print(f"  • Powered By:      {server.get('powered_by', 'Unknown')}")
    
    print_section("OPEN PORTS")
    ports = server.get('open_ports', [])
    if ports:
        for port_info in ports:
            print(f"  • Port {port_info['port']}: {port_info['service']} (OPEN)")
    else:
        print("  No additional ports detected (may be filtered)")
    
    print_section("WHAT DOES THIS MEAN?")
    print("""The server information tells us:
• What software powers your website
• What ports are accessible from the internet
• What services might be running

This information helps us understand what security measures are in place
and what potential vulnerabilities might exist.""")
    
    display_page([], 0, 0, show_nav=False)

def show_recommendations(report: Dict[str, Any]):
    """Show actionable recommendations."""
    tests = report.get('tests', {})
    recommendations = []
    
    # Analyze findings and generate recommendations
    cves = tests.get('cves', [])
    vulnerable_cves = [c for c in cves if c.get('vulnerable') is True]
    
    if vulnerable_cves:
        recommendations.append({
            'priority': 'CRITICAL',
            'title': 'Fix Active Vulnerabilities',
            'action': f'You have {len(vulnerable_cves)} active vulnerabilities. Update WordPress and plugins immediately.',
            'estimated_time': '1-4 hours'
        })
    
    headers = tests.get('security_headers', {})
    missing = headers.get('missing', [])
    if missing:
        recommendations.append({
            'priority': 'HIGH',
            'title': 'Add Security Headers',
            'action': f'Configure {len(missing)} missing security headers to protect visitors.',
            'estimated_time': '1-2 hours'
        })
    
    wordpress = tests.get('wordpress', {})
    if wordpress.get('is_wordpress'):
        if wordpress.get('wordpress_version'):
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'Hide WordPress Version',
                'action': 'Disable WordPress version disclosure to reduce attack surface.',
                'estimated_time': '30 minutes'
            })
    
    clear_screen()
    print_header("RECOMMENDED ACTIONS")
    
    if not recommendations:
        print(colorize("✓ No urgent recommendations. Keep monitoring for updates.", Color.GREEN))
        display_page([], 0, 0, show_nav=False)
        return
    
    for idx, rec in enumerate(recommendations, 1):
        priority_color = Color.RED if rec['priority'] == 'CRITICAL' else Color.YELLOW if rec['priority'] == 'HIGH' else Color.BLUE
        print(f"\n{idx}. {colorize(rec['priority'], priority_color)} - {rec['title']}")
        print(f"   Action: {rec['action']}")
        print(f"   Estimated Time: {rec['estimated_time']}")
    
    display_page([], 0, 0, show_nav=False)

# ==================== MAIN MENU ====================

def show_main_menu():
    """Display main menu."""
    clear_screen()
    print_header("HTTPMR REPORT READER")
    print(f"{Color.DIM}Enterprise Security Report Interpreter for Non-Technical Users{Color.RESET}\n")
    
    print("OPTIONS:")
    print("  1. Executive Summary (Quick Overview)")
    print("  2. Vulnerability Details (Full Explanations)")
    print("  3. WordPress Analysis (If Applicable)")
    print("  4. Security Headers Analysis")
    print("  5. Server Information")
    print("  6. Recommendations & Actions")
    print("  7. Full Report (Technical View)")
    print("  8. Exit")
    print()

def show_full_report(report: Dict[str, Any]):
    """Show technical JSON report."""
    clear_screen()
    print_header("FULL TECHNICAL REPORT")
    print(json.dumps(report, indent=2))
    display_page([], 0, 0, show_nav=False)

def main():
    """Main application loop."""
    if len(sys.argv) < 2:
        print(colorize("Usage: python HTTPMR-Reader.py <report.json>", Color.YELLOW))
        print(colorize("Example: python HTTPMR-Reader.py auto_report.json", Color.YELLOW))
        sys.exit(1)
    
    report_path = sys.argv[1]
    report = load_report(report_path)
    
    if not report:
        sys.exit(1)
    
    while True:
        show_main_menu()
        choice = prompt("Select option", ['1', '2', '3', '4', '5', '6', '7', '8'])
        
        if choice == '1':
            show_executive_summary(report)
        elif choice == '2':
            show_vulnerability_details(report)
        elif choice == '3':
            show_wordpress_analysis(report)
        elif choice == '4':
            show_security_headers_analysis(report)
        elif choice == '5':
            show_server_information(report)
        elif choice == '6':
            show_recommendations(report)
        elif choice == '7':
            show_full_report(report)
        elif choice == '8':
            print(colorize("\nThank you for using HTTPMR Report Reader!", Color.GREEN))
            break

if __name__ == "__main__":
    main()
