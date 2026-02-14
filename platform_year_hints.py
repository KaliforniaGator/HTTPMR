#!/usr/bin/env python3
"""Platform-to-year mapping for optimized CVE search.

Provides hints about which years to search for specific platforms/technologies
based on their creation/release dates. This significantly speeds up CVE searches
by avoiding unnecessary searches in years where the platform didn't exist.
"""

from typing import Dict, Optional, List
import re

# Platform/technology to minimum search year mapping
PLATFORM_YEAR_HINTS: Dict[str, int] = {
    # Web Frameworks & Libraries
    "react": 2013,
    "reactjs": 2013,
    "vue": 2014,
    "vuejs": 2014,
    "angular": 2010,
    "angularjs": 2010,
    "svelte": 2016,
    "nextjs": 2016,
    "nuxt": 2016,
    "gatsby": 2015,
    
    # JavaScript Runtimes
    "node": 2009,
    "nodejs": 2009,
    "deno": 2018,
    "bun": 2023,
    
    # Frontend Libraries
    "jquery": 2006,
    "bootstrap": 2011,
    "tailwind": 2017,
    "tailwindcss": 2017,
    
    # Backend Frameworks
    "django": 2005,
    "flask": 2010,
    "rails": 2004,
    "rubyonrails": 2004,
    "express": 2010,
    "expressjs": 2010,
    "fastapi": 2018,
    "spring": 2002,
    "springboot": 2014,
    "laravel": 2011,
    "symfony": 2005,
    
    # CMS Platforms
    "wordpress": 2003,
    "drupal": 2001,
    "joomla": 2005,
    "magento": 2008,
    "shopify": 2006,
    "ghost": 2013,
    "strapi": 2013,
    "headless": 2013,
    
    # Programming Languages
    "python": 1991,
    "javascript": 1995,
    "typescript": 2012,
    "golang": 2012,
    "go": 2012,
    "rust": 2010,
    "java": 1995,
    "php": 1995,
    "ruby": 1995,
    "c#": 2000,
    "csharp": 2000,
    "kotlin": 2011,
    "swift": 2014,
    
    # Databases
    "mysql": 1995,
    "postgresql": 1996,
    "postgres": 1996,
    "mongodb": 2007,
    "redis": 2009,
    "sqlite": 2000,
    "elasticsearch": 2010,
    "cassandra": 2008,
    "cockroachdb": 2016,
    
    # Cloud Platforms
    "aws": 2006,
    "amazon": 2006,
    "azure": 2010,
    "gcp": 2008,
    "googlecloud": 2008,
    "heroku": 2007,
    "vercel": 2015,
    "netlify": 2015,
    "cloudflare": 2009,
    
    # Container & DevOps
    "docker": 2013,
    "kubernetes": 2014,
    "k8s": 2014,
    "jenkins": 2011,
    "gitlab": 2011,
    "github": 2008,
    "terraform": 2014,
    "ansible": 2012,
    "puppet": 2005,
    "chef": 2009,
    
    # Mobile
    "ios": 2007,
    "iphone": 2007,
    "android": 2008,
    "reactnative": 2015,
    "flutter": 2017,
    "xamarin": 2011,
    "cordova": 2009,
    "phonegap": 2009,
    
    # Security Tools & Libraries
    "openssl": 1998,
    "openssh": 1999,
    "apache": 1995,
    "nginx": 2004,
    "iis": 1996,
    
    # Package Managers
    "npm": 2010,
    "yarn": 2016,
    "pip": 2008,
    "composer": 2012,
    "maven": 2004,
    "gradle": 2012,
    
    # Modern Frontend Build Tools
    "webpack": 2012,
    "vite": 2019,
    "parcel": 2017,
    "rollup": 2015,
    "babel": 2014,
    "eslint": 2013,
    "prettier": 2017,
    
    # API & GraphQL
    "graphql": 2015,
    "rest": 2000,
    "oauth": 2007,
    "jwt": 2010,
    "openid": 2007,
    
    # Testing Frameworks
    "jest": 2014,
    "mocha": 2011,
    "jasmine": 2010,
    "cypress": 2017,
    "playwright": 2017,
    "selenium": 2004,
    
    # Monitoring & Analytics
    "grafana": 2014,
    "prometheus": 2012,
    "kibana": 2013,
    "datadog": 2010,
    "newrelic": 2008,
    
    # Blockchain & Crypto
    "bitcoin": 2009,
    "ethereum": 2015,
    "blockchain": 2009,
    "solidity": 2014,
    "web3": 2014,
    
    # AI/ML
    "tensorflow": 2015,
    "pytorch": 2016,
    "keras": 2015,
    "scikit": 2007,
    "pandas": 2008,
    "numpy": 2006,
    
    # Enterprise Software
    "sap": 1992,
    "salesforce": 1999,
    "oracle": 1977,
    "sharepoint": 2001,
    "exchange": 1996,
    "outlook": 1997,
    
    # Browsers
    "chrome": 2008,
    "firefox": 2004,
    "safari": 2003,
    "edge": 2015,
    "ie": 1995,
    "explorer": 1995,
    
    # Operating Systems
    "linux": 1991,
    "ubuntu": 2004,
    "centos": 2004,
    "rhel": 2000,
    "windows": 1985,
    "macos": 2001,
    "mac": 2001,
    
    # Server Software
    "tomcat": 1999,
    "jboss": 1999,
    "wildfly": 2013,
    "jetty": 1995,
    
    # IoT & Embedded
    "raspberry": 2012,
    "arduino": 2005,
    "esp32": 2016,
    "esp8266": 2014,
}


def get_search_year_hint(query: str) -> Optional[int]:
    """
    Get the minimum year to search for based on platform/technology keywords.
    
    Args:
        query: Search query string
        
    Returns:
        Minimum year to search, or None if no hint found
    """
    if not query:
        return None
    
    # Convert to lowercase for case-insensitive matching
    query_lower = query.lower()
    
    # Check for exact matches first
    for platform, year in PLATFORM_YEAR_HINTS.items():
        if platform in query_lower:
            return year
    
    # Check for partial matches and word boundaries
    for platform, year in PLATFORM_YEAR_HINTS.items():
        # Use word boundary matching to avoid false positives
        pattern = r'\b' + re.escape(platform) + r'\b'
        if re.search(pattern, query_lower, re.IGNORECASE):
            return year
    
    # Check for CVE patterns (CVE-YYYY-XXXXX)
    cve_match = re.search(r'CVE-(\d{4})', query_upper := query.upper())
    if cve_match:
        return int(cve_match.group(1))
    
    return None


def get_optimized_search_years(query: str, available_years: List[int]) -> List[int]:
    """
    Get optimized list of years to search based on query and available years.
    
    Args:
        query: Search query string
        available_years: List of available years in the database
        
    Returns:
        Optimized list of years to search (most recent first)
    """
    if not query or not available_years:
        return sorted(available_years, reverse=True)
    
    year_hint = get_search_year_hint(query)
    
    if year_hint is None:
        # No hint found, search all years (most recent first)
        return sorted(available_years, reverse=True)
    
    # Filter years to only include those >= hint year
    optimized_years = [year for year in available_years if year >= year_hint]
    
    # Sort by most recent first
    optimized_years.sort(reverse=True)
    
    return optimized_years


def get_platform_info(query: str) -> Dict[str, any]:
    """
    Get platform information for a search query.
    
    Args:
        query: Search query string
        
    Returns:
        Dictionary with platform info and optimization details
    """
    query_lower = query.lower()
    matched_platforms = []
    
    for platform, year in PLATFORM_YEAR_HINTS.items():
        if platform in query_lower:
            matched_platforms.append((platform, year))
    
    # Sort by year (newest first) to get the most relevant platform
    matched_platforms.sort(key=lambda x: x[1], reverse=True)
    
    if matched_platforms:
        platform, year = matched_platforms[0]
        return {
            "platform": platform,
            "min_year": year,
            "optimization_applied": True,
            "all_matches": matched_platforms
        }
    
    return {
        "platform": None,
        "min_year": None,
        "optimization_applied": False,
        "all_matches": []
    }


# Popular CVE search terms and their typical patterns
POPULAR_SEARCH_TERMS = [
    "wordpress", "apache", "nginx", "mysql", "php", "javascript", 
    "nodejs", "react", "angular", "docker", "kubernetes", "aws",
    "openssl", "java", "python", "linux", "windows", "chrome",
    "firefox", "safari", "ios", "android", "mysql", "postgresql",
    "mongodb", "redis", "elasticsearch", "spring", "django",
    "flask", "rails", "express", "jquery", "bootstrap", "vue",
    "typescript", "golang", "rust", "docker", "kubernetes"
]


if __name__ == "__main__":
    # Test the optimization
    test_queries = [
        "react vulnerability",
        "wordpress plugin",
        "CVE-2022-1234",
        "docker container",
        "python library",
        "random term"
    ]
    
    available_years = list(range(1999, 2027))
    
    print("=== Platform Year Hint Optimization Test ===")
    for query in test_queries:
        info = get_platform_info(query)
        optimized_years = get_optimized_search_years(query, available_years)
        
        print(f"\nQuery: '{query}'")
        if info["optimization_applied"]:
            print(f"  Platform: {info['platform']} (min year: {info['min_year']})")
            print(f"  Years to search: {len(optimized_years)} (from {min(optimized_years) if optimized_years else 'N/A'})")
        else:
            print(f"  No platform hint found")
            print(f"  Years to search: {len(optimized_years)} (all years)")
        
        print(f"  Year range: {min(optimized_years) if optimized_years else 'N/A'} - {max(optimized_years) if optimized_years else 'N/A'}")
