from fastapi import FastAPI, Request, UploadFile, File, Form, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os
import json
import uuid
import time
import asyncio
import shlex
import sys
import sqlite3
import bcrypt
import secrets
import logging
import requests
from datetime import datetime
from typing import Optional, Tuple, List

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    import nvdlib
    NVD_AVAILABLE = True
except ImportError:
    NVD_AVAILABLE = False

from cve_search import CVELibrary, CVEEntry

REPORT_DIR = os.path.join(BASE_DIR, "reports")
DB_PATH = os.path.join(BASE_DIR, ".secure", "httpmr.db")
CVE_FIXES_PATH = os.path.join(BASE_DIR, ".secure", "cves-fixes.json")
HEADER_FIXES_PATH = os.path.join(BASE_DIR, ".secure", "header-fixes.json")
SETTINGS_PATH = os.path.join(BASE_DIR, ".secure", "settings.config")
SESSION_TIMEOUT = 24 * 60 * 60  # 24 hours

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Check NVD availability after logger is set up
if not NVD_AVAILABLE:
    logger.warning("NVDLib not available - NVD API features disabled")

# In-memory job store: job_id -> {history: [lines], queue: asyncio.Queue(), status, outpath, target}
JOBS = {}
JOBS_LOCK = asyncio.Lock()
SESSIONS = {}  # session_token -> {user_id, username, created_at}
_CVE_FIXES_CACHE = {}
_CVE_FIXES_MTIME = 0.0
_HEADER_FIXES_CACHE = {}
_HEADER_FIXES_MTIME = 0.0
CVE_LIBRARY = CVELibrary(use_custom_delta=True)

HEADER_MESSAGE_TO_NAME = {
    "HSTS not configured": "Strict-Transport-Security",
    "MIME type sniffing not prevented": "X-Content-Type-Options",
    "Clickjacking not prevented": "X-Frame-Options",
    "CSP not configured": "Content-Security-Policy",
    "XSS protection not enabled": "X-XSS-Protection",
}


# ===== DATABASE INITIALIZATION =====
def _init_db():
    """Initialize SQLite database with users and jobs tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Jobs persistence table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            outpath TEXT NOT NULL,
            history TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")


def _hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, hash_: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode(), hash_.encode())


def _create_user(username: str, password: str) -> bool:
    """Create a new user. Returns True if successful, False if user exists."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        password_hash = _hash_password(password)
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        logger.info(f"User created: {username}")
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"User already exists: {username}")
        return False


def _verify_user(username: str, password: str) -> int | None:
    """Verify user credentials. Returns user_id if valid, None otherwise."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result and _verify_password(password, result[1]):
            logger.info(f"User authenticated: {username}")
            return result[0]
        logger.warning(f"Failed authentication attempt: {username}")
        return None
    except Exception as e:
        logger.error(f"Error verifying user: {str(e)}")
        return None


def _create_session(user_id: int) -> str:
    """Create a new session token."""
    token = secrets.token_urlsafe(32)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO sessions (token, user_id) VALUES (?, ?)', (token, user_id))
    conn.commit()
    conn.close()
    SESSIONS[token] = {"user_id": user_id, "created_at": time.time()}
    logger.info(f"Session created for user_id {user_id}")
    return token


def _get_user_from_session(token: str | None) -> dict | None:
    """Get user info from session token."""
    if not token:
        return None
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM sessions WHERE token = ?', (token,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            user_id = result[0]
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
            user_result = cursor.fetchone()
            conn.close()
            if user_result:
                return {"user_id": user_result[0], "username": user_result[1]}
        return None
    except Exception as e:
        logger.error(f"Error getting user from session: {str(e)}")
        return None


def _save_job_to_db(user_id: int, job_id: str, target: str, outpath: str, history: list, status: str):
    """Save job to database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO jobs (job_id, user_id, target, timestamp, status, outpath, history)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (job_id, user_id, target, time.strftime('%Y-%m-%d %H:%M:%S'), status, outpath, json.dumps(history)))
        conn.commit()
        conn.close()
        logger.info(f"Job saved to DB: {job_id}")
    except Exception as e:
        logger.error(f"Error saving job to DB: {str(e)}")


def _load_jobs_from_db(user_id: int) -> dict:
    """Load user's jobs from database."""
    jobs = {}
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT job_id, target, timestamp, status, outpath, history FROM jobs WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
        rows = cursor.fetchall()
        conn.close()
        
        for row in rows:
            job_id, target, timestamp, status, outpath, history = row
            jobs[job_id] = {
                "history": json.loads(history),
                "queue": asyncio.Queue(),
                "status": status,
                "outpath": outpath,
                "target": target,
                "timestamp": timestamp
            }
        logger.info(f"Loaded {len(jobs)} jobs for user_id {user_id}")
    except Exception as e:
        logger.error(f"Error loading jobs from DB: {str(e)}")
    
    return jobs


def _delete_job_from_db(job_id: str):
    """Delete job from database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM jobs WHERE job_id = ?', (job_id,))
        conn.commit()
        conn.close()
        logger.info(f"Job deleted from DB: {job_id}")
    except Exception as e:
        logger.error(f"Error deleting job from DB: {str(e)}")


# ===== HELPER FUNCTIONS =====
def _list_reports():
    return [f for f in os.listdir(REPORT_DIR) if f.endswith('.json') and not f.startswith('.')]


def _get_report_summary(path):
    """Extract summary info from a JSON report."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        tests = data.get('tests', {})
        vuln_count = 0
        if 'cves' in tests:
            vuln_count += len([c for c in tests.get('cves', []) if c.get('vulnerable')])
        headers = tests.get('security_headers', {})
        score = headers.get('score', 0)
        return {
            'url': data.get('url'),
            'timestamp': data.get('timestamp'),
            'vuln_count': vuln_count,
            'security_score': score,
            'size': os.path.getsize(path),
        }
    except Exception as e:
        return {'error': str(e)}


SORT_OPTIONS = [
    {"value": "newest", "label": "Newest first", "key": "timestamp", "reverse": True},
    {"value": "oldest", "label": "Oldest first", "key": "timestamp", "reverse": False},
    {"value": "score_desc", "label": "Score: high → low", "key": "score", "reverse": True},
    {"value": "score_asc", "label": "Score: low → high", "key": "score", "reverse": False},
    {"value": "name_asc", "label": "Name: A → Z", "key": "name", "reverse": False},
    {"value": "name_desc", "label": "Name: Z → A", "key": "name", "reverse": True},
]

_SORT_OPTION_MAP = {opt["value"]: opt for opt in SORT_OPTIONS}
DEFAULT_SORT_OPTION = _SORT_OPTION_MAP["newest"]


def _get_sort_key(option):
    key_name = option["key"]
    reverse = option["reverse"]

    if key_name == "timestamp":
        fallback = datetime.min if reverse else datetime.max

        def key(report):
            summary = report.get("summary") or {}
            ts = summary.get("timestamp")
            if not ts:
                return fallback
            try:
                return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return fallback

        return key

    if key_name == "score":
        fallback = -1 if reverse else 101

        def key(report):
            summary = report.get("summary") or {}
            score = summary.get("security_score")
            try:
                return float(score)
            except (TypeError, ValueError):
                return fallback

        return key

    # default to filename sort (case-insensitive)
    def key(report):
        return (report.get("filename") or "").lower()

    return key


def _fetch_reports(sort_value: str):
    sort_option = _SORT_OPTION_MAP.get(sort_value, DEFAULT_SORT_OPTION)
    sort_key = _get_sort_key(sort_option)

    files = _list_reports()
    reports = []
    for filename in files:
        path = os.path.join(REPORT_DIR, filename)
        summary = _get_report_summary(path)
        reports.append({'filename': filename, 'summary': summary})

    reports = sorted(reports, key=sort_key, reverse=sort_option["reverse"])
    return reports, sort_option


def _load_cve_fixes():
    """Load CVE fix metadata from secure storage with simple caching."""
    global _CVE_FIXES_CACHE, _CVE_FIXES_MTIME
    try:
        if not os.path.exists(CVE_FIXES_PATH):
            logger.warning("CVE fixes file not found at %s", CVE_FIXES_PATH)
            return {}
        mtime = os.path.getmtime(CVE_FIXES_PATH)
        if mtime != _CVE_FIXES_MTIME:
            with open(CVE_FIXES_PATH, 'r') as f:
                _CVE_FIXES_CACHE = json.load(f)
            _CVE_FIXES_MTIME = mtime
            logger.info("Loaded %d CVE fix definitions", len(_CVE_FIXES_CACHE))
        return _CVE_FIXES_CACHE
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in CVE fixes file: %s", e)
        return {}
    except Exception as e:
        logger.error("Failed to load CVE fixes: %s", e)
        return {}


def _get_cve_fix(cve_id: str):
    """Return fix metadata for a CVE ID."""
    if not cve_id:
        return None
    fixes = _load_cve_fixes()
    # prefer exact match, fall back to uppercase normalization
    return fixes.get(cve_id) or fixes.get(cve_id.upper())


def _load_header_fixes():
    """Load header fix metadata from secure storage with caching."""
    global _HEADER_FIXES_CACHE, _HEADER_FIXES_MTIME
    try:
        if not os.path.exists(HEADER_FIXES_PATH):
            logger.warning("Header fixes file not found at %s", HEADER_FIXES_PATH)
            return {}
        mtime = os.path.getmtime(HEADER_FIXES_PATH)
        if mtime != _HEADER_FIXES_MTIME:
            with open(HEADER_FIXES_PATH, 'r') as f:
                _HEADER_FIXES_CACHE = json.load(f)
            _HEADER_FIXES_MTIME = mtime
            logger.info("Loaded %d header fix definitions", len(_HEADER_FIXES_CACHE))
        return _HEADER_FIXES_CACHE
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in header fixes file: %s", e)
        return {}
    except Exception as e:
        logger.error("Failed to load header fixes: %s", e)
        return {}


def _get_header_fix(header_name: str):
    """Return fix metadata for a header name."""
    if not header_name:
        return None
    fixes = _load_header_fixes()
    return fixes.get(header_name)


def _serialize_cve_entry(entry: Optional[CVEEntry]) -> Optional[dict]:
    if not entry:
        return None
    iso_dt = entry.iso_date()
    return {
        "id": entry.cve_id,
        "year": entry.year,
        "kind": entry.kind,
        "github_link": entry.github_link,
        "org_link": entry.org_link,
        "date_updated": entry.date_updated,
        "timestamp": iso_dt.strftime("%Y-%m-%d %H:%M:%S") if iso_dt != datetime.min else "Unknown",
    }


def _list_year_summaries(limit_per_year: int | None = None):
    years = CVE_LIBRARY.list_years()
    summaries = []
    for year in years:
        entries_all = CVE_LIBRARY.list_entries_by_year(year)
        entries = entries_all if limit_per_year is None else entries_all[:limit_per_year]
        summaries.append({
            "year": year,
            "count": len(entries_all),
            "entries": [_serialize_cve_entry(e) for e in entries]
        })
    return summaries


def _load_cve_detail(cve_id: str) -> Tuple[Optional[CVEEntry], Optional[dict]]:
    if not cve_id:
        return None, None
    entry = CVE_LIBRARY.get_entry(cve_id.upper())
    record = CVE_LIBRARY.get_cve_record(cve_id.upper())
    return entry, record


# Cache for search results to avoid re-computation
_SEARCH_CACHE = {}
_CACHE_TTL = 300  # 5 minutes

def _build_cve_search_results(query: str, limit: int = 1000) -> dict:
    # Check cache first
    cache_key = f"all:{query}"  # Remove limit from cache key since we want all results
    current_time = time.time()
    
    if cache_key in _SEARCH_CACHE:
        cached_data, cached_time = _SEARCH_CACHE[cache_key]
        if current_time - cached_time < _CACHE_TTL:
            logger.debug(f"Cache hit for search: {query}")
            return cached_data
    
    # Perform search with higher limit to get more results
    start_time = time.time()
    matches = CVE_LIBRARY.search(query, limit=limit)  # Get more results but not unlimited
    search_time = time.time() - start_time
    
    optimization_info = CVE_LIBRARY.get_search_optimization_info(query)
    result = {
        "query": query,
        "count": len(matches),
        "results": [
            {
                "id": entry.cve_id,
                "year": entry.year,
                "timestamp": entry.iso_date().isoformat() if entry.iso_date() != datetime.min else "unknown",
                "kind": entry.kind,
            }
            for entry in matches
        ],
        "optimization": optimization_info,
        "search_time_ms": f"{search_time * 1000:.1f}",
        "limit_applied": limit if len(matches) >= limit else None
    }
    
    # Cache the result
    _SEARCH_CACHE[cache_key] = (result, current_time)
    
    # Clean old cache entries periodically
    if len(_SEARCH_CACHE) > 50:  # Reduce cache size since results are larger
        keys_to_remove = [k for k, (_, t) in _SEARCH_CACHE.items() if current_time - t > _CACHE_TTL]
        for k in keys_to_remove[:25]:  # Remove oldest 25
            del _SEARCH_CACHE[k]
    
    logger.info(f"Search completed: {query} ({len(matches)} results, {search_time*1000:.1f}ms)")
    return result


def _extract_cve_metadata(record: Optional[dict]) -> dict:
    metadata = {
        "description": None,
        "problem_types": [],
        "references": [],
        "cvss": [],
        "affected": [],
        "published": record.get("datePublished") if record else None,
        "last_modified": record.get("dateUpdated") if record else None,
    }
    if not record:
        return metadata

    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    desc_value = None
    for desc in cna.get("descriptions", []):
        if not desc_value:
            desc_value = desc.get("value")
        if desc.get("lang", "").lower().startswith("en") and desc.get("value"):
            desc_value = desc["value"]
            break
    metadata["description"] = desc_value

    problem_types: List[str] = []
    for problem in cna.get("problemTypes", []):
        for desc in problem.get("descriptions", []):
            text = desc.get("description")
            if text and text not in problem_types:
                problem_types.append(text)
    metadata["problem_types"] = problem_types

    references: List[dict] = []
    for ref in cna.get("references", []):
        references.append({
            "name": ref.get("name"),
            "url": ref.get("url"),
            "tags": ref.get("tags") or [],
        })
    metadata["references"] = references

    cvss_entries: List[dict] = []
    for metric in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2"):
            if key in metric:
                data = metric[key]
                cvss_entries.append({
                    "version": data.get("version") or key.replace("cvss", "CVSS "),
                    "base_score": data.get("baseScore"),
                    "severity": data.get("baseSeverity"),
                    "vector": data.get("vectorString"),
                })
    metadata["cvss"] = cvss_entries

    affected: List[str] = []
    for vendor in cna.get("affected", []):
        vendor_name = vendor.get("vendor")
        for product in vendor.get("products", []):
            product_name = product.get("product")
            version_data = product.get("versions", [])
            versions = ", ".join(v.get("version") for v in version_data if v.get("version"))
            label = " / ".join(filter(None, [vendor_name, product_name]))
            if versions:
                label = f"{label} ({versions})"
            if label:
                affected.append(label)
    metadata["affected"] = affected
    return metadata


def _load_settings():
    """Load settings from secure storage."""
    try:
        if not os.path.exists(SETTINGS_PATH):
            logger.warning("Settings file not found at %s", SETTINGS_PATH)
            return {
                "nvd_api_key": "",
                "exploitdb_api_key": "",
                "vulndb_api_key": "",
                "feed_update_interval": {"value": 1, "unit": "hours"},
                "enable_real_time_scans": False,
                "use_apis": True,
                "last_feed_update": None
            }
        with open(SETTINGS_PATH, 'r') as f:
            settings = json.load(f)
            logger.info("Loaded settings from %s", SETTINGS_PATH)
            return settings
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in settings file: %s", e)
        return {}
    except Exception as e:
        logger.error("Failed to load settings: %s", e)
        return {}


def _save_settings(settings: dict):
    """Save settings to secure storage."""
    try:
        with open(SETTINGS_PATH, 'w') as f:
            json.dump(settings, f, indent=2)
        logger.info("Settings saved to %s", SETTINGS_PATH)
        return True
    except Exception as e:
        logger.error("Failed to save settings: %s", e)
        return False


def _lookup_cve_with_nvd(cve_id: str):
    """Lookup CVE details using NVD API if key is available."""
    if not NVD_AVAILABLE:
        return None
        
    settings = _load_settings()
    api_key = settings.get('nvd_api_key', '')
    
    if not api_key:
        return None
    
    try:
        # Use NVDLib searchCVE (latest API)
        cve = None
        if hasattr(nvdlib, 'searchCVE'):
            results = nvdlib.searchCVE(cveId=cve_id, key=api_key)
            if results:
                cve = results[0]
        else:
            logger.error("Installed nvdlib version does not provide searchCVE")
            return None
        
        if cve:
            return {
                'id': cve.id,
                'description': cve.descriptions[0].value if cve.descriptions else '',
                'severity': cve.v31severity if hasattr(cve, 'v31severity') else cve.v2severity,
                'score': cve.v31score if hasattr(cve, 'v31score') else cve.v2score,
                'published': cve.publishedDate,
                'modified': cve.lastModifiedDate,
                'references': [ref.url for ref in cve.ref] if cve.ref else []
            }
    except Exception as e:
        logger.error(f"Failed to lookup CVE {cve_id} via NVD API: {str(e)}")
    
    return None


def _is_real_time_scans_enabled():
    """Check if real-time scans are enabled in settings."""
    settings = _load_settings()
    return settings.get('enable_real_time_scans', False)


def _lookup_exploitdb(cve_id: str):
    """Lookup exploit information from ExploitDB API if key is available."""
    settings = _load_settings()
    api_key = settings.get('exploitdb_api_key', '')
    
    if not api_key:
        return None
    
    try:
        # ExploitDB API integration
        url = f"https://www.exploit-db.com/api/v1/exploits?cve={cve_id}"
        headers = {'Authorization': f'Bearer {api_key}'}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('results') and len(data['results']) > 0:
                return {
                    'exploits': data['results'],
                    'count': len(data['results']),
                    'source': 'ExploitDB'
                }
    except Exception as e:
        logger.error(f"Failed to lookup ExploitDB for {cve_id}: {str(e)}")
    
    return None


def _lookup_vulndb(cve_id: str):
    """Lookup vulnerability details from VulnDB API if key is available."""
    settings = _load_settings()
    api_key = settings.get('vulndb_api_key', '')
    
    if not api_key:
        return None
    
    try:
        # VulnDB API integration (example implementation)
        url = f"https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/{cve_id}"
        headers = {'Authorization': f'Bearer {api_key}'}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'id': data.get('id'),
                'title': data.get('title'),
                'description': data.get('description'),
                'severity': data.get('severity'),
                'cvss_score': data.get('cvss_score'),
                'source': 'VulnDB'
            }
    except Exception as e:
        logger.error(f"Failed to lookup VulnDB for {cve_id}: {str(e)}")
    
    return None


def _normalize_report(path):
    """Ensure reports have a consistent top-level shape with a `tests` dict.
    Converts legacy single-request reports (which contain `test_config`/`response`)
    into a normalized report with `url`, `timestamp`, and `tests` entries so the
    WebUI templates can rely on a consistent schema.
    The original content is preserved under a `_raw` key for audit trails.
    """
    try:
        with open(path, 'r') as f:
            data = json.load(f)

        # If already normalized, validate and return
        if isinstance(data, dict) and data.get('tests'):
            logger.info(f"Report already normalized: {path}")
            # Validate required fields
            if not data.get('url'):
                logger.warning(f"Missing 'url' field in normalized report: {path}")
            if not data.get('timestamp'):
                logger.warning(f"Missing 'timestamp' field in normalized report: {path}")
            return True

        logger.info(f"Normalizing report: {path}")
        new = {}
        
        # Preserve original under _raw key for audit trails
        new['_raw'] = data
        logger.debug(f"Preserved original report data under '_raw' key")

        # Map known fields - validate extraction
        url = data.get('url') or (data.get('test_config') or {}).get('url') or (data.get('response') or {}).get('url')
        if not url:
            logger.warning(f"Could not extract URL from report: {path}")
        new['url'] = url
        
        timestamp = data.get('timestamp') or data.get('test_config', {}).get('timestamp') or time.strftime('%Y-%m-%d %H:%M:%S')
        new['timestamp'] = timestamp
        logger.info(f"Normalized report - URL: {url}, Timestamp: {timestamp}")

        tests = {}
        # If this was an auto_mode report (has tests already but at top-level), move it
        if 'tests' in data:
            tests = data['tests']
            logger.info(f"Found existing tests structure with {len(tests)} test groups")
        else:
            # Single-request report: include under a 'general' test
            general = {
                'test_config': data.get('test_config'),
                'response': data.get('response'),
                'analysis': data.get('analysis')
            }
            if data.get('wordpress_analysis'):
                tests['wordpress'] = data.get('wordpress_analysis')
            tests['general'] = general
            logger.info(f"Created general test structure from legacy report")

        new['tests'] = tests

        # Validate structure
        if not new.get('tests'):
            logger.error(f"Normalization failed - no tests in final structure: {path}")
            return False

        # Write back normalized report (overwrite)
        with open(path, 'w') as f:
            json.dump(new, f, indent=2)
        logger.info(f"Successfully wrote normalized report: {path}")

        # Try writing SARIF if exporter available
        try:
            import sarif_exporter
            sarif = sarif_exporter.convert_report_to_sarif(new)
            sarif_path = path.replace('.json', '.sarif.json')
            with open(sarif_path, 'w') as sf:
                json.dump(sarif, sf, indent=2)
            logger.info(f"Generated SARIF export: {sarif_path}")
        except Exception as e:
            logger.debug(f"SARIF export unavailable: {str(e)}")

        return True
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in report: {path} - {str(e)}")
        return False
    except FileNotFoundError:
        logger.error(f"Report file not found: {path}")
        return False
    except Exception as e:
        logger.error(f"Error normalizing report {path}: {str(e)}")
        return False


async def _get_user(request: Request):
    """Get current user from session cookie, return None if not authenticated."""
    token = request.cookies.get("session_token")
    user = _get_user_from_session(token)
    return user


# ===== LIFESPAN EVENT HANDLERS =====
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events."""
    # Startup
    _init_db()
    logger.info("HTTPMR WebUI started")
    yield
    # Shutdown
    logger.info("HTTPMR WebUI shutting down - persisting jobs")

app = FastAPI(title="HTTPMR WebUI", lifespan=lifespan)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Mount static files
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


# ===== AUTHENTICATION ROUTES =====
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Show login page. Redirect if already authenticated."""
    user = await _get_user(request)
    if user:
        return RedirectResponse(url='/', status_code=303)
    return templates.TemplateResponse('login.html', {"request": request})


@app.post("/login")
async def login(request: Request):
    """Handle login."""
    form = await request.form()
    username = form.get('username')
    password = form.get('password')
    
    if not username or not password:
        return templates.TemplateResponse('login.html', {"request": request, "error": "Username and password required"})
    
    user_id = _verify_user(username, password)
    if user_id:
        token = _create_session(user_id)
        response = RedirectResponse(url='/', status_code=303)
        response.set_cookie(key="session_token", value=token, max_age=SESSION_TIMEOUT)
        return response
    
    return templates.TemplateResponse('login.html', {"request": request, "error": "Invalid credentials"})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Show registration page. Redirect if already authenticated."""
    user = await _get_user(request)
    if user:
        return RedirectResponse(url='/', status_code=303)
    return templates.TemplateResponse('register.html', {"request": request})


@app.post("/register")
async def register(request: Request):
    """Handle registration."""
    form = await request.form()
    username = form.get('username')
    password = form.get('password')
    password_confirm = form.get('password_confirm')
    
    if not username or not password:
        return templates.TemplateResponse('register.html', {"request": request, "error": "Username and password required"})
    
    if len(username) < 3:
        return templates.TemplateResponse('register.html', {"request": request, "error": "Username must be at least 3 characters"})
    
    if len(password) < 8:
        return templates.TemplateResponse('register.html', {"request": request, "error": "Password must be at least 8 characters"})
    
    if password != password_confirm:
        return templates.TemplateResponse('register.html', {"request": request, "error": "Passwords do not match"})
    
    if _create_user(username, password):
        return templates.TemplateResponse('register.html', {"request": request, "success": "User created! Please log in."})
    
    return templates.TemplateResponse('register.html', {"request": request, "error": "Username already exists"})


@app.post("/logout")
async def logout(request: Request):
    """Handle logout."""
    response = RedirectResponse(url='/login', status_code=303)
    response.delete_cookie("session_token")
    return response


# ===== PROTECTED ROUTES =====
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)
    
    sort_value = request.query_params.get("sort", DEFAULT_SORT_OPTION["value"])
    reports, sort_option = _fetch_reports(sort_value)

    context = {
        "request": request,
        "reports": reports,
        "username": user["username"],
        "sort_options": SORT_OPTIONS,
        "current_sort": sort_option["value"],
    }
    return templates.TemplateResponse('dashboard.html', context)


@app.get("/api/cves/search")
async def api_cve_search(request: Request):
    """API endpoint for AJAX CVE search with pagination."""
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    
    query = request.query_params.get('query', '').strip()
    offset = int(request.query_params.get('offset', 0))
    limit = int(request.query_params.get('limit', 30))
    sort_order = request.query_params.get('sort', 'newest')  # Default to newest first
    
    if not query:
        return JSONResponse({"error": "Query parameter required"}, status_code=400)
    
    try:
        # Perform search with higher limit to get more results for pagination
        all_results = CVE_LIBRARY.search(query, limit=None)
        total_count = len(all_results)
        
        # Sort results based on request
        if sort_order == 'oldest':
            all_results.sort(key=lambda entry: entry.iso_date())  # Oldest first
        else:
            all_results.sort(key=lambda entry: entry.iso_date(), reverse=True)  # Newest first
        
        # Get the requested slice
        paginated_results = all_results[offset:offset + limit]
        
        # Convert to API format
        results_data = [
            {
                "id": entry.cve_id,
                "year": entry.year,
                "timestamp": entry.iso_date().isoformat() if entry.iso_date() != datetime.min else "unknown",
                "kind": entry.kind,
            }
            for entry in paginated_results
        ]
        
        return JSONResponse({
            "query": query,
            "results": results_data,
            "count": total_count,
            "offset": offset,
            "limit": limit,
            "sort": sort_order,
            "has_more": offset + limit < total_count
        })
        
    except Exception as e:
        logger.error(f"Error in API search: {e}")
        return JSONResponse({"error": f"Search failed: {str(e)}"}, status_code=500)


@app.get("/cves", response_class=HTMLResponse)
async def cve_search_view(request: Request, query: str = ""):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)

    # Only load year summaries if no query (initial page load)
    # For searches, we don't need the year buckets to avoid the performance bottleneck
    years = _list_year_summaries(limit_per_year=12) if not query else []
    search_results = _build_cve_search_results(query) if query else None
    context = {
        "request": request,
        "username": user["username"],
        "query": query,
        "search_results": search_results,
        "year_buckets": years,
    }
    return templates.TemplateResponse('cve_search.html', context)


@app.get("/cves/{cve_id}", response_class=HTMLResponse)
async def cve_detail_view(request: Request, cve_id: str, query: str = ""):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)

    entry, record = _load_cve_detail(cve_id)
    if not record:
        raise HTTPException(status_code=404, detail="CVE record not found")

    metadata = _extract_cve_metadata(record)
    context = {
        "request": request,
        "username": user["username"],
        "entry": _serialize_cve_entry(entry),
        "record": record,
        "metadata": metadata,
        "cve_id": cve_id.upper(),
        "search_query": query,
    }
    return templates.TemplateResponse('cve_detail.html', context)


@app.get("/reports_fragment", response_class=HTMLResponse)
async def reports_fragment(request: Request, sort: str = DEFAULT_SORT_OPTION["value"]):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)
    
    reports, sort_option = _fetch_reports(sort)
    context = {
        "request": request,
        "reports": reports,
        "username": user["username"],
        "sort_options": SORT_OPTIONS,
        "current_sort": sort_option["value"],
    }
    return templates.TemplateResponse('partials/all_reports.html', context)


@app.post("/upload")
async def upload_report(request: Request, file: UploadFile = File(...)):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)
    
    contents = await file.read()
    dest = os.path.join(REPORT_DIR, file.filename)
    with open(dest, 'wb') as f:
        f.write(contents)
    return RedirectResponse(url='/', status_code=303)


@app.post('/run')
async def run_scan(request: Request):
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    form = await request.form()
    target = form.get('target')
    mode = form.get('mode') or 'auto'
    use_apis = form.get('use-apis', 'true').lower() == 'true'

    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)

    # sanitize filename
    safe_target = ''.join(c for c in target if c.isalnum() or c in ('-', '_', '.'))
    timestamp = str(int(asyncio.get_event_loop().time()))
    outfilename = f"scan_{safe_target}_{timestamp}.json"
    outpath = os.path.join(REPORT_DIR, outfilename)

    job_id = str(uuid.uuid4())
    queue = asyncio.Queue()
    JOBS[job_id] = {"history": [], "queue": queue, "status": "queued", "outpath": outpath, "target": target, "user_id": user["user_id"]}

    # start background task
    asyncio.create_task(_run_httpmr_job(job_id, target, outpath, mode, user["user_id"], use_apis))

    return JSONResponse({"job_id": job_id, "outpath": outpath})


@app.get('/run/{job_id}', response_class=HTMLResponse)
async def run_page(request: Request, job_id: str):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)
    
    job = JOBS.get(job_id)
    if not job:
        return RedirectResponse(url='/', status_code=303)
    return templates.TemplateResponse('run.html', {"request": request, "job_id": job_id, "target": job.get('target'), "outpath": job.get('outpath'), "username": user["username"]})


@app.websocket('/ws/{job_id}')
async def ws_logs(websocket: WebSocket, job_id: str):
    await websocket.accept()
    job = JOBS.get(job_id)
    if not job:
        await websocket.send_text("ERROR: job not found")
        await websocket.close()
        return

    # send history first
    for line in job['history']:
        try:
            await websocket.send_text(line)
        except WebSocketDisconnect:
            return

    # then stream new lines
    q = job['queue']
    try:
        while True:
            line = await q.get()
            await websocket.send_text(line)
            if line.startswith("[JOB_FINISHED]"):
                break
    except WebSocketDisconnect:
        return


async def _run_httpmr_job(job_id: str, target: str, outpath: str, mode: str = 'auto', user_id: int = None, use_apis: bool = True):
    """Run HTTPMR.py in a subprocess and stream logs to JOBS[job_id]."""
    async with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job['status'] = 'running'

    cmd = [sys.executable, os.path.join(BASE_DIR, 'HTTPMR.py'), '--auto', '--target', target, '-o', outpath, '--verbose', '--mode', mode]
    
    # Add --no-apis flag if APIs are disabled
    if not use_apis:
        cmd.append('--no-apis')

    # start subprocess
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)

    # read lines and push to history and queue
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode('utf-8', errors='replace').rstrip('\n')
        job['history'].append(text)
        await job['queue'].put(text)

    rc = await proc.wait()
    # try to normalize the report file so the UI sees a consistent structure
    try:
        _normalize_report(outpath)
    except Exception:
        pass

    finished_msg = f"[JOB_FINISHED] rc={rc} out={outpath}"
    job['history'].append(finished_msg)
    await job['queue'].put(finished_msg)
    job['status'] = 'finished'
    job['returncode'] = rc
    
    # Persist job to database
    if user_id:
        _save_job_to_db(user_id, job_id, target, outpath, job['history'], 'finished')
        logger.info(f"Job {job_id} persisted for user {user_id}")


@app.get('/view', response_class=HTMLResponse)
async def view_report(request: Request, name: str):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)
    
    path = os.path.join(REPORT_DIR, name)
    if not os.path.exists(path):
        return templates.TemplateResponse('dashboard.html', {"request": request, "reports": [], "error": 'Report not found', "username": user["username"]})
    with open(path, 'r') as f:
        data = json.load(f)

    tests = data.get('tests', {})
    cve_fix_map = {}
    for cve in tests.get('cves', []) or []:
        cve_id = cve.get('cve') or cve.get('id')
        if cve_id:
            # Check for local fix only - API data should already be in the report
            has_local_fix = bool(_get_cve_fix(cve_id))
            
            # Use existing external_data from the scan, don't make new API calls
            external_data = cve.get('external_data', {})
            
            cve_fix_map[cve_id] = {
                'has_local_fix': has_local_fix,
                'nvd_data': external_data.get('nvd'),
                'exploitdb_data': external_data.get('exploitdb'),
                'vulndb_data': external_data.get('vulndb'),
                'has_external_data': external_data.get('has_external_data', False)
            }

    security_headers = tests.get('security_headers') or {}
    header_fix_details = []
    raw_missing_details = security_headers.get('missing_details') or []
    if isinstance(raw_missing_details, list) and raw_missing_details:
        for detail in raw_missing_details:
            header_name = detail.get('header')
            message = detail.get('message') or header_name
            if not header_name:
                continue
            header_fix_details.append({
                "header": header_name,
                "message": message,
                "has_fix": bool(_get_header_fix(header_name)),
            })
    else:
        # Backwards compatibility: infer from textual missing entries
        for missing_msg in security_headers.get('missing') or []:
            header_name = HEADER_MESSAGE_TO_NAME.get(missing_msg, missing_msg)
            header_fix_details.append({
                "header": header_name,
                "message": missing_msg,
                "has_fix": bool(_get_header_fix(header_name)),
            })

    summary = _get_report_summary(path)
    return templates.TemplateResponse(
        'report.html',
        {
            "request": request,
            "report": data,
            "summary": summary,
            "report_filename": name,
            "username": user["username"],
            "cve_fix_map": cve_fix_map,
            "header_fix_details": header_fix_details,
        },
    )


@app.post('/delete_report')
async def delete_report(request: Request):
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    form = await request.form()
    name = form.get('name')
    if not name:
        return JSONResponse({"error": "name required"}, status_code=400)
    
    path = os.path.join(REPORT_DIR, name)
    if not os.path.exists(path) or not path.startswith(REPORT_DIR):
        return JSONResponse({"error": "report not found or invalid path"}, status_code=400)
    
    try:
        os.remove(path)
        # also try to remove companion SARIF if it exists
        sarif_path = path.replace('.json', '.sarif.json')
        if os.path.exists(sarif_path):
            os.remove(sarif_path)
        return JSONResponse({"status": "deleted", "name": name})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post('/convert_sarif')
async def convert_sarif(request: Request):
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    form = await request.form()
    name = form.get('name')
    if not name:
        return JSONResponse({"error": "name required"}, status_code=400)
    
    path = os.path.join(REPORT_DIR, name)
    if not os.path.exists(path):
        return JSONResponse({"error": "report not found"}, status_code=400)
    
    try:
        import sarif_exporter
        with open(path, 'r') as f:
            report = json.load(f)
        sarif = sarif_exporter.convert_report_to_sarif(report)
        sarif_path = path.replace('.json', '.sarif.json')
        with open(sarif_path, 'w') as sf:
            json.dump(sarif, sf, indent=2)
        return JSONResponse({"status": "converted", "sarif_path": os.path.basename(sarif_path)})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get('/download_sarif')
async def download_sarif(request: Request, name: str):
    """Download a SARIF file (if it exists)."""
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)
    
    path = os.path.join(REPORT_DIR, name.replace('.json', '.sarif.json'))
    if not os.path.exists(path):
        return JSONResponse({"error": "sarif not found"}, status_code=404)
    return FileResponse(path, media_type='application/json', filename=os.path.basename(path))


@app.post('/run_tester')
async def run_tester(request: Request):
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    form = await request.form()
    report = form.get('report')
    if not report or not os.path.exists(os.path.join(REPORT_DIR, report)):
        return JSONResponse({"error": "report not found"}, status_code=400)

    safe_report = report
    job_id = str(uuid.uuid4())
    queue = asyncio.Queue()
    outpath = os.path.join(REPORT_DIR, f"tester_{safe_report}")
    JOBS[job_id] = {"history": [], "queue": queue, "status": "queued", "outpath": outpath, "target": report, "user_id": user["user_id"]}
    asyncio.create_task(_run_tester_job(job_id, report, outpath, user["user_id"]))
    return JSONResponse({"job_id": job_id, "outpath": outpath})


async def _run_tester_job(job_id: str, report: str, outpath: str, user_id: int = None):
    async with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job['status'] = 'running'

    cmd = [sys.executable, os.path.join(BASE_DIR, 'HTTPMR_Tester.py'), '--report', os.path.join(REPORT_DIR, report), '-o', outpath]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode('utf-8', errors='replace').rstrip('\n')
        job['history'].append(text)
        await job['queue'].put(text)
    rc = await proc.wait()
    finished_msg = f"[JOB_FINISHED] rc={rc} out={outpath}"
    job['history'].append(finished_msg)
    await job['queue'].put(finished_msg)
    job['status'] = 'finished'
    job['returncode'] = rc
    
    # Persist job to database
    if user_id:
        _save_job_to_db(user_id, job_id, report, outpath, job['history'], 'finished')
        logger.info(f"Tester job {job_id} persisted for user {user_id}")


@app.get('/cve_fix/{cve_id}', response_class=HTMLResponse)
async def cve_fix_page(request: Request, cve_id: str):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)

    fix_data = _get_cve_fix(cve_id)
    if not fix_data:
        return templates.TemplateResponse(
            'cve_fix.html',
            {
                "request": request,
                "cve_id": cve_id.upper(),
                "fix": None,
                "username": user["username"],
            },
            status_code=404,
        )

    return templates.TemplateResponse(
        'cve_fix.html',
        {
            "request": request,
            "cve_id": cve_id.upper(),
            "fix": fix_data,
            "username": user["username"],
        },
    )


@app.get('/settings', response_class=HTMLResponse)
async def settings_page(request: Request):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)
    
    settings = _load_settings()
    context = {
        "request": request,
        "username": user["username"],
        "settings": settings,
    }
    return templates.TemplateResponse('settings.html', context)


@app.post('/settings')
async def save_settings(request: Request):
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    form = await request.form()
    settings = _load_settings()
    
    # Update settings with form data
    settings["nvd_api_key"] = form.get('nvd_api_key', '')
    settings["exploitdb_api_key"] = form.get('exploitdb_api_key', '')
    settings["vulndb_api_key"] = form.get('vulndb_api_key', '')
    
    # Parse feed update interval
    interval_value = int(form.get('feed_update_value', 1))
    interval_unit = form.get('feed_update_unit', 'hours')
    settings["feed_update_interval"] = {
        "value": interval_value,
        "unit": interval_unit
    }
    
    # Parse real-time scans toggle
    settings["enable_real_time_scans"] = form.get('enable_real_time_scans') == 'on'
    
    if _save_settings(settings):
        # Check if this is an AJAX request by checking the X-Requested-With header
        is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest'
        if is_ajax:
            return JSONResponse({"success": True, "message": "Settings saved successfully"})
        else:
            # Traditional form submission - redirect as before
            return RedirectResponse(url='/settings?saved=true', status_code=303)
    else:
        return JSONResponse({"error": "Failed to save settings"}, status_code=500)


@app.post('/settings/account')
async def update_account_credentials(request: Request):
    """Allow authenticated users to update their username and/or password."""
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    form = await request.form()
    current_password = (form.get('current_password') or '').strip()
    new_username = (form.get('new_username') or '').strip()
    new_password = form.get('new_password') or ''
    confirm_password = form.get('confirm_password') or ''

    if not current_password:
        return JSONResponse({"error": "Current password is required"}, status_code=400)

    if not new_username and not new_password:
        return JSONResponse({"error": "Provide a new username or password to update"}, status_code=400)

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (user["user_id"],))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return JSONResponse({"error": "User not found"}, status_code=404)

        stored_hash = row[0]
        if not _verify_password(current_password, stored_hash):
            conn.close()
            return JSONResponse({"error": "Current password is incorrect"}, status_code=400)

        updates = []
        params: list[str] = []

        if new_username:
            if len(new_username) < 3:
                conn.close()
                return JSONResponse({"error": "Username must be at least 3 characters"}, status_code=400)
            updates.append("username = ?")
            params.append(new_username)

        if new_password:
            if len(new_password) < 8:
                conn.close()
                return JSONResponse({"error": "Password must be at least 8 characters"}, status_code=400)
            if new_password != confirm_password:
                conn.close()
                return JSONResponse({"error": "New passwords do not match"}, status_code=400)
            new_hash = _hash_password(new_password)
            updates.append("password_hash = ?")
            params.append(new_hash)

        if updates:
            params.append(user["user_id"])
            try:
                cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                return JSONResponse({"error": "Username already exists"}, status_code=400)

        conn.close()
    except Exception as exc:
        logger.error("Failed to update account credentials: %s", exc)
        return JSONResponse({"error": "Failed to update account"}, status_code=500)

    return JSONResponse({"success": True, "message": "Account updated successfully"})


@app.get('/api/settings/status')
async def get_settings_status(request: Request):
    """API endpoint to get current settings status."""
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    settings = _load_settings()
    
    # Get rate limit status
    try:
        from settings_integration import get_rate_limit_status
        rate_limit_status = get_rate_limit_status()
    except ImportError:
        rate_limit_status = {}
    
    return JSONResponse({
        "real_time_scans_enabled": settings.get('enable_real_time_scans', False),
        "has_nvd_key": bool(settings.get('nvd_api_key')),
        "has_exploitdb_key": bool(settings.get('exploitdb_api_key')),
        "has_vulndb_key": bool(settings.get('vulndb_api_key')),
        "feed_update_interval": settings.get('feed_update_interval', {'value': 1, 'unit': 'hours'}),
        "use_apis": settings.get('use_apis', True),
        "rate_limits": rate_limit_status
    })


@app.post('/api/settings/use-apis')
async def save_use_apis_setting(request: Request):
    """API endpoint to save the use_apis toggle state."""
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    try:
        data = await request.json()
        use_apis = data.get('use_apis')
        
        if isinstance(use_apis, bool):
            settings = _load_settings()
            settings['use_apis'] = use_apis
            
            if _save_settings(settings):
                return JSONResponse({"success": True, "use_apis": use_apis})
            else:
                return JSONResponse({"error": "Failed to save setting"}, status_code=500)
        else:
            return JSONResponse({"error": "Invalid value for use_apis"}, status_code=400)
    except Exception as e:
        logger.error(f"Error saving use_apis setting: {str(e)}")
        return JSONResponse({"error": "Server error"}, status_code=500)


@app.get('/header_fix/{header_name}', response_class=HTMLResponse)
async def header_fix_page(request: Request, header_name: str):
    user = await _get_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=303)

    fix_data = _get_header_fix(header_name)
    if not fix_data:
        return templates.TemplateResponse(
            'header_fix.html',
            {
                "request": request,
                "header_name": header_name,
                "fix": None,
                "username": user["username"],
            },
            status_code=404,
        )

    return templates.TemplateResponse(
        'header_fix.html',
        {
            "request": request,
            "header_name": header_name,
            "fix": fix_data,
            "username": user["username"],
        },
    )


@app.post('/api/cves/update_delta')
async def update_cve_delta(request: Request):
    """Update the CVE delta database by re-scanning the CVE directory."""
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    
    try:
        # Import and run the scanner
        import sys
        from pathlib import Path
        
        # Add the parent directory to the path to import our modules
        parent_dir = Path(__file__).parent.parent
        if str(parent_dir) not in sys.path:
            sys.path.insert(0, str(parent_dir))
        
        from cve_scanner import scan_cve_directory, create_custom_delta, update_cve_timestamps, save_custom_delta
        
        # Re-scan the CVE directory
        year_to_cves = scan_cve_directory()
        
        if not year_to_cves:
            return JSONResponse({"error": "No CVE files found during scan"}, status_code=500)
        
        # Create new delta
        delta = create_custom_delta(year_to_cves)
        delta = update_cve_timestamps(delta)
        save_custom_delta(delta)
        
        # Reload the CVE library to pick up new data
        global CVE_LIBRARY
        CVE_LIBRARY = CVELibrary(use_custom_delta=True)
        
        return JSONResponse({
            "success": True, 
            "message": f"CVE delta updated successfully with {delta['totalCVEs']} CVEs",
            "totalCVEs": delta['totalCVEs'],
            "years": len(delta['years'])
        })
        
    except Exception as e:
        logger.error(f"Error updating CVE delta: {e}")
        return JSONResponse({"error": f"Failed to update CVE delta: {str(e)}"}, status_code=500)


@app.get('/api/cves/year_buckets')
async def get_year_buckets(request: Request):
    """Get year buckets for CVE catalog via AJAX."""
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    
    try:
        years = _list_year_summaries(limit_per_year=12)
        return JSONResponse({
            "year_buckets": years
        })
    except Exception as e:
        logger.error(f"Error getting year buckets: {e}")
        return JSONResponse({"error": f"Failed to get year buckets: {str(e)}"}, status_code=500)


@app.get('/api/cves/search_progress')
async def get_search_progress(request: Request):
    """Get real-time search progress information."""
    user = await _get_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    
    query = request.query_params.get('query', '').strip()
    if not query:
        return JSONResponse({"error": "Query parameter required"}, status_code=400)
    
    try:
        # Get optimization info to calculate progress
        optimization_info = CVE_LIBRARY.get_search_optimization_info(query)
        
        if optimization_info.get("optimization_applied"):
            # Calculate total CVEs to search through efficiently
            years_searched = optimization_info["years_searched"]
            min_year = optimization_info.get("min_year", 1999)
            
            # Get counts efficiently without iterating through every year
            available_years = CVE_LIBRARY.list_years()
            total_cv_es = len(CVE_LIBRARY._entries) if CVE_LIBRARY._loaded else 0
            
            # Calculate searched CVEs by counting entries in optimized years
            searched_cv_es = 0
            for year in available_years:
                if year >= min_year:
                    searched_cv_es += len(CVE_LIBRARY._by_year.get(year, []))
            
            return JSONResponse({
                "query": query,
                "optimization_applied": True,
                "platform": optimization_info.get("platform"),
                "min_year": min_year,
                "total_cv_es_available": total_cv_es,
                "cv_es_to_search": searched_cv_es,
                "year_reduction": f"{years_searched}/{len(available_years)}",
                "performance_gain": optimization_info.get("performance_gain")
            })
        else:
            # No optimization - search through all CVEs
            total_cv_es = len(CVE_LIBRARY._entries) if CVE_LIBRARY._loaded else 0
            return JSONResponse({
                "query": query,
                "optimization_applied": False,
                "total_cv_es_available": total_cv_es,
                "cv_es_to_search": total_cv_es,
                "year_reduction": "all years",
                "performance_gain": "0%"
            })
            
    except Exception as e:
        logger.error(f"Error getting search progress: {e}")
        return JSONResponse({"error": f"Failed to get search progress: {str(e)}"}, status_code=500)