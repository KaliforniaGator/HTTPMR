"""
Shared settings and API integration module for HTTPMR
"""
import os
import json
import logging
import requests
import time
from datetime import datetime, timedelta
from collections import defaultdict

try:
    import nvdlib
    NVD_AVAILABLE = True
except ImportError:
    NVD_AVAILABLE = False

# Setup logging
logger = logging.getLogger(__name__)

# Settings file path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_PATH = os.path.join(BASE_DIR, ".secure", "settings.config")

# Rate limiting configuration
RATE_LIMITS = {
    'exploitdb': {
        'requests_per_minute': 20,  # Conservative limit for free tier
        'requests_per_hour': 100,
        'cooldown_minutes': 5  # Cooldown if rate limit hit
    },
    'vulndb': {
        'requests_per_minute': 30,
        'requests_per_hour': 200,
        'cooldown_minutes': 10
    },
    'nvd': {
        'requests_per_minute': 50,  # NVD has generous limits but still be respectful
        'requests_per_hour': 1000,
        'cooldown_minutes': 5
    }
}

# Rate limiting state
_request_times = defaultdict(list)
_last_rate_limit_hit = defaultdict(lambda: datetime.min)

def _check_rate_limit(api_name: str) -> bool:
    """Check if we're within rate limits for a given API."""
    now = datetime.now()
    
    # Check if we're in cooldown period
    if now - _last_rate_limit_hit[api_name] < timedelta(minutes=RATE_LIMITS[api_name]['cooldown_minutes']):
        logger.warning(f"Rate limit cooldown active for {api_name}")
        return False
    
    # Clean old requests (older than 1 hour)
    _request_times[api_name] = [
        req_time for req_time in _request_times[api_name] 
        if now - req_time < timedelta(hours=1)
    ]
    
    # Check per-hour limit
    if len(_request_times[api_name]) >= RATE_LIMITS[api_name]['requests_per_hour']:
        logger.warning(f"Hourly rate limit exceeded for {api_name}")
        _last_rate_limit_hit[api_name] = now
        return False
    
    # Check per-minute limit
    recent_requests = [
        req_time for req_time in _request_times[api_name]
        if now - req_time < timedelta(minutes=1)
    ]
    
    if len(recent_requests) >= RATE_LIMITS[api_name]['requests_per_minute']:
        logger.warning(f"Per-minute rate limit exceeded for {api_name}")
        _last_rate_limit_hit[api_name] = now
        return False
    
    return True

def _record_request(api_name: str):
    """Record a request for rate limiting purposes."""
    _request_times[api_name].append(datetime.now())

def load_settings():
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

def lookup_cve_with_nvd(cve_id: str):
    """Lookup CVE details using NVD API if key is available."""
    if not NVD_AVAILABLE:
        return None

    # NVD API only accepts CVE IDs in CVE-YYYY-NNNN format
    if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        logger.debug(f"Skipping NVD lookup for non-CVE identifier: {cve_id}")
        return None
    
    # Check rate limit first
    if not _check_rate_limit('nvd'):
        logger.warning("NVD API rate limit reached, skipping request")
        return None
        
    settings = load_settings()
    api_key = settings.get('nvd_api_key', '')
    
    if not api_key:
        return None
    
    try:
        # Record the request for rate limiting
        _record_request('nvd')
        
        # Add small delay to be respectful
        time.sleep(0.1)  # 100ms delay between requests
        
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
            descriptions = getattr(cve, 'descriptions', None) or getattr(cve, 'description', None)
            description_text = ''
            if isinstance(descriptions, list) and descriptions:
                first_desc = descriptions[0]
                description_text = getattr(first_desc, 'value', first_desc)
            elif descriptions:
                description_text = descriptions

            references = getattr(cve, 'references', None) or getattr(cve, 'ref', None)
            reference_urls = []
            if isinstance(references, list):
                for ref in references:
                    url = getattr(ref, 'url', ref)
                    if url:
                        reference_urls.append(url)

            # Prefer highest available CVSS version (v3.1 > v3.0 > v2)
            score = None
            severity = None
            vector = None
            version = None
            for prefix, version_label in (('v31', 'V3.1'), ('v30', 'V3.0'), ('v2', 'V2')):
                score_candidate = getattr(cve, f'{prefix}score', None)
                if score_candidate is not None:
                    score = score_candidate
                    severity = getattr(cve, f'{prefix}severity', None)
                    vector = getattr(cve, f'{prefix}vector', None)
                    version = version_label
                    break

            weaknesses = []
            cve_weaknesses = getattr(cve, 'weaknesses', None)
            if isinstance(cve_weaknesses, list):
                for weakness in cve_weaknesses:
                    descs = getattr(weakness, 'description', None)
                    if isinstance(descs, list) and descs:
                        weaknesses.append(getattr(descs[0], 'value', descs[0]))

            configurations = []
            cpe_data = getattr(cve, 'configurations', None)
            if isinstance(cpe_data, list):
                for config in cpe_data:
                    nodes = getattr(config, 'nodes', None)
                    if nodes:
                        configurations.append(str(nodes))

            return {
                'id': getattr(cve, 'id', cve_id),
                'description': description_text,
                'severity': severity,
                'score': score,
                'score_version': version,
                'vector': vector,
                'published': getattr(cve, 'published', None) or getattr(cve, 'publishedDate', None),
                'modified': getattr(cve, 'lastModified', None) or getattr(cve, 'lastModifiedDate', None),
                'source_identifier': getattr(cve, 'sourceIdentifier', None),
                'vuln_status': getattr(cve, 'vulnStatus', None),
                'weaknesses': weaknesses,
                'configurations': configurations,
                'references': reference_urls,
                'url': getattr(cve, 'url', None)
            }
    except Exception as e:
        # Check if it's a rate limit error
        if "429" in str(e) or "rate limit" in str(e).lower():
            logger.warning(f"NVD API rate limit hit for {cve_id}: {str(e)}")
            _last_rate_limit_hit['nvd'] = datetime.now()
        else:
            logger.error(f"Failed to lookup CVE {cve_id} via NVD API: {str(e)}")
    
    return None

def lookup_exploitdb(cve_id: str):
    """Lookup exploit information from ExploitDB API if key is available."""
    # Check rate limit first
    if not _check_rate_limit('exploitdb'):
        logger.warning("ExploitDB API rate limit reached, skipping request")
        return None
    
    settings = load_settings()
    api_key = settings.get('exploitdb_api_key', '')
    
    if not api_key:
        return None
    
    try:
        # Record the request for rate limiting
        _record_request('exploitdb')
        
        # ExploitDB API integration
        url = f"https://www.exploit-db.com/api/v1/exploits?cve={cve_id}"
        headers = {'Authorization': f'Bearer {api_key}'}
        
        # Add delay to be extra conservative
        time.sleep(0.5)  # 500ms delay between requests
        
        response = requests.get(url, headers=headers, timeout=10)
        
        # Handle rate limit responses
        if response.status_code == 429:
            logger.warning("ExploitDB API rate limit hit (429 response)")
            _last_rate_limit_hit['exploitdb'] = datetime.now()
            return None
        elif response.status_code == 403:
            logger.warning("ExploitDB API access forbidden (403 response) -可能 API key suspended or invalid")
            return None
        
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

def lookup_vulndb(cve_id: str):
    """Lookup vulnerability details from VulnDB API if key is available."""
    # Check rate limit first
    if not _check_rate_limit('vulndb'):
        logger.warning("VulnDB API rate limit reached, skipping request")
        return None
    
    settings = load_settings()
    api_key = settings.get('vulndb_api_key', '')
    
    if not api_key:
        return None
    
    try:
        # Record the request for rate limiting
        _record_request('vulndb')
        
        # VulnDB API integration (example implementation)
        url = f"https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/{cve_id}"
        headers = {'Authorization': f'Bearer {api_key}'}
        
        # Add conservative delay
        time.sleep(0.3)  # 300ms delay between requests
        
        response = requests.get(url, headers=headers, timeout=10)
        
        # Handle rate limit responses
        if response.status_code == 429:
            logger.warning("VulnDB API rate limit hit (429 response)")
            _last_rate_limit_hit['vulndb'] = datetime.now()
            return None
        elif response.status_code == 403:
            logger.warning("VulnDB API access forbidden (403 response) - API key may be suspended")
            return None
        
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

def enhance_cve_with_external_apis(cve_data: dict):
    """Enhance CVE data with information from external APIs."""
    if not isinstance(cve_data, dict) or not cve_data.get('cve'):
        return cve_data
    
    cve_id = cve_data.get('cve')
    
    # Lookup data from all available APIs
    nvd_data = lookup_cve_with_nvd(cve_id)
    exploitdb_data = lookup_exploitdb(cve_id)
    vulndb_data = lookup_vulndb(cve_id)
    
    # Enhance the CVE data
    enhanced = cve_data.copy()
    enhanced['external_data'] = {
        'nvd': nvd_data,
        'exploitdb': exploitdb_data,
        'vulndb': vulndb_data,
        'has_external_data': bool(nvd_data or exploitdb_data or vulndb_data)
    }
    
    # Add severity and score from NVD if available
    if nvd_data:
        if nvd_data.get('severity') and not enhanced.get('severity'):
            enhanced['severity'] = nvd_data['severity']
        if nvd_data.get('score') and not enhanced.get('score'):
            enhanced['score'] = nvd_data['score']
        if nvd_data.get('description') and not enhanced.get('description'):
            enhanced['description'] = nvd_data['description']
    
    return enhanced

def is_real_time_scans_enabled():
    """Check if real-time scans are enabled in settings."""
    settings = load_settings()
    return settings.get('enable_real_time_scans', False)


def get_rate_limit_status():
    """Get current rate limit status for all APIs."""
    now = datetime.now()
    status = {}
    
    for api_name in ['nvd', 'exploitdb', 'vulndb']:
        # Clean old requests
        _request_times[api_name] = [
            req_time for req_time in _request_times[api_name] 
            if now - req_time < timedelta(hours=1)
        ]
        
        # Count recent requests
        recent_minute = [
            req_time for req_time in _request_times[api_name]
            if now - req_time < timedelta(minutes=1)
        ]
        
        recent_hour = len(_request_times[api_name])
        
        # Check if in cooldown
        in_cooldown = now - _last_rate_limit_hit[api_name] < timedelta(minutes=RATE_LIMITS[api_name]['cooldown_minutes'])
        
        status[api_name] = {
            'requests_last_minute': len(recent_minute),
            'requests_last_hour': recent_hour,
            'limit_per_minute': RATE_LIMITS[api_name]['requests_per_minute'],
            'limit_per_hour': RATE_LIMITS[api_name]['requests_per_hour'],
            'in_cooldown': in_cooldown,
            'cooldown_remaining': (RATE_LIMITS[api_name]['cooldown_minutes'] - 
                                 (now - _last_rate_limit_hit[api_name]).total_seconds() / 60) 
                                 if in_cooldown else 0,
            'available': len(recent_minute) < RATE_LIMITS[api_name]['requests_per_minute'] and 
                        recent_hour < RATE_LIMITS[api_name]['requests_per_hour'] and 
                        not in_cooldown
        }
    
    return status
