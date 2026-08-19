"""
Lightweight Web Crawler & Endpoint Discovery Module
"""

import re
import urllib3
import requests
from urllib.parse import urljoin, urlparse
from typing import Set, Dict, List, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LightweightCrawler:
    """Discovers internal routes, authentication endpoints, and API docs."""

    def __init__(self, max_pages: int = 15, timeout: int = 4):
        self.max_pages = max_pages
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisWeb/1.0"}

    def crawl(self, start_url: str) -> Dict[str, Any]:
        """Crawl internal links from starting URL."""
        parsed_base = urlparse(start_url)
        base_domain = parsed_base.netloc
        scheme = parsed_base.scheme or "https"

        visited: Set[str] = set()
        to_visit: List[str] = [start_url]
        discovered_routes: Set[str] = set()
        auth_portals: List[str] = []
        api_endpoints: List[str] = []

        while to_visit and len(visited) < self.max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue

            visited.add(current_url)
            try:
                resp = requests.get(current_url, headers=self.headers, timeout=self.timeout, verify=False)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                links = re.findall(r'href=[\'"]?([^\'" >]+)', resp.text)
                for link in links:
                    full_url = urljoin(current_url, link).split("#")[0]
                    parsed_link = urlparse(full_url)

                    if parsed_link.netloc == base_domain:
                        discovered_routes.add(parsed_link.path or "/")
                        if full_url not in visited and full_url not in to_visit:
                            to_visit.append(full_url)

                        path_lower = parsed_link.path.lower()
                        if any(kw in path_lower for kw in ["login", "admin", "signin", "portal", "dashboard"]):
                            if full_url not in auth_portals:
                                auth_portals.append(full_url)
                        if any(kw in path_lower for kw in ["api", "graphql", "swagger", "openapi", "v1", "v2"]):
                            if full_url not in api_endpoints:
                                api_endpoints.append(full_url)
            except Exception:
                continue

        return {
            "pages_crawled": len(visited),
            "discovered_routes_count": len(discovered_routes),
            "discovered_routes": sorted(list(discovered_routes))[:30],
            "auth_portals": auth_portals[:10],
            "api_endpoints": api_endpoints[:10]
        }