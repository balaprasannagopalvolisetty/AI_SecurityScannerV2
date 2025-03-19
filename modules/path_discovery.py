import asyncio
import aiohttp
import logging
import os
import json
from typing import List, Dict, Any
from bs4 import BeautifulSoup
import re

logger = logging.getLogger(__name__)

class PathDiscovery:
    def __init__(self, url: str):
        self.url = url
        if not self.url.startswith(('http://', 'https://')):
            self.url = f"https://{self.url}"
        
        # Common paths to check
        self.common_paths = [
            "/", "/admin", "/login", "/wp-admin", "/administrator", "/admin.php",
            "/wp-login.php", "/user", "/login.php", "/admin.html", "/admin/index.php",
            "/wp-content", "/wp-includes", "/api", "/api/v1", "/api/v2",
            "/includes", "/uploads", "/images", "/img", "/css", "/js",
            "/backup", "/bak", "/old", "/new", "/dev", "/test", "/temp",
            "/robots.txt", "/sitemap.xml", "/sitemap", "/.git", "/.env",
            "/config", "/settings", "/setup", "/install", "/phpinfo.php",
            "/server-status", "/server-info", "/.well-known", "/actuator",
            "/swagger", "/swagger-ui.html", "/docs", "/api-docs",  "/.well-known", "/actuator",
            "/swagger", "/swagger-ui.html", "/docs", "/api-docs", "/graphql",
            "/graphiql", "/console", "/metrics", "/health", "/status",
            "/debug", "/trace", "/info", "/dump", "/logs", "/log",
            "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
            "/database.sql", "/1.sql", "/dump.sql", "/data.sql", "/backup.tar",
            "/wp-config.php.bak", "/config.php.bak", ".DS_Store"
        ]
    
    async def discover_paths(self) -> List[Dict[str, Any]]:
        """Discover paths using multiple methods."""
        tasks = [
            self._crawl_website(),
            self._check_common_paths(),
            self._check_robots_txt(),
            self._check_sitemap_xml(),
            self._check_js_files()
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Combine and deduplicate results
        all_paths = []
        seen_paths = set()
        
        for result in results:
            for path_info in result:
                path = path_info["path"]
                if path not in seen_paths:
                    seen_paths.add(path)
                    all_paths.append(path_info)
        
        return all_paths
    
    async def _crawl_website(self) -> List[Dict[str, Any]]:
        """Crawl the website to discover paths."""
        discovered_paths = []
        visited_urls = set()
        urls_to_visit = [self.url]
        
        async def fetch_url(url):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, 
                        headers={"User-Agent": "Mozilla/5.0"},
                        timeout=10
                    ) as response:
                        if response.status == 200:
                            content_type = response.headers.get("Content-Type", "")
                            if "text/html" in content_type:
                                html = await response.text()
                                return html, response.status
                        return None, response.status
            except Exception as e:
                logger.warning(f"Error fetching {url}: {str(e)}")
                return None, 0
        
        max_urls = 50  # Limit to prevent excessive crawling
        
        while urls_to_visit and len(visited_urls) < max_urls:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue
            
            visited_urls.add(current_url)
            
            html, status = await fetch_url(current_url)
            if html:
                # Extract path from URL
                path = current_url.replace(self.url, "")
                if not path:
                    path = "/"
                
                discovered_paths.append({
                    "path": path,
                    "status_code": status,
                    "content_type": "text/html",
                    "method": "GET",
                    "source": "crawling"
                })
                
                # Extract links from HTML
                soup = BeautifulSoup(html, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    
                    # Handle relative URLs
                    if href.startswith('/'):
                        full_url = f"{self.url.rstrip('/')}{href}"
                    elif href.startswith(('http://', 'https://')):
                        # Only follow links to the same domain
                        if self.url.replace('https://', '').replace('http://', '') in href:
                            full_url = href
                        else:
                            continue
                    else:
                        full_url = f"{self.url.rstrip('/')}/{href}"
                    
                    if full_url not in visited_urls and full_url not in urls_to_visit:
                        urls_to_visit.append(full_url)
        
        return discovered_paths
    
    async def _check_common_paths(self) -> List[Dict[str, Any]]:
        """Check common paths on the website."""
        discovered_paths = []
        
        async def check_path(path):
            try:
                url = f"{self.url.rstrip('/')}{path}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, 
                        headers={"User-Agent": "Mozilla/5.0"},
                        timeout=5,
                        allow_redirects=False
                    ) as response:
                        status = response.status
                        if status != 404:  # Only include non-404 responses
                            content_type = response.headers.get("Content-Type", "")
                            discovered_paths.append({
                                "path": path,
                                "status_code": status,
                                "content_type": content_type,
                                "method": "GET",
                                "source": "common_paths"
                            })
                            logger.info(f"Found path: {path} (Status: {status})")
            except Exception as e:
                logger.warning(f"Error checking path {path}: {str(e)}")
        
        tasks = []
        for path in self.common_paths:
            tasks.append(asyncio.ensure_future(check_path(path)))
        
        await asyncio.gather(*tasks)
        return discovered_paths
    
    async def _check_robots_txt(self) -> List[Dict[str, Any]]:
        """Check robots.txt for paths."""
        discovered_paths = []
        
        try:
            robots_url = f"{self.url.rstrip('/')}/robots.txt"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    robots_url, 
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=5
                ) as response:
                    if response.status == 200:
                        robots_txt = await response.text()
                        
                        # Add robots.txt itself
                        discovered_paths.append({
                            "path": "/robots.txt",
                            "status_code": 200,
                            "content_type": "text/plain",
                            "method": "GET",
                            "source": "robots_txt"
                        })
                        
                        # Extract paths from robots.txt
                        for line in robots_txt.splitlines():
                            if line.startswith(('Disallow:', 'Allow:')):
                                parts = line.split(':', 1)
                                if len(parts) == 2:
                                    path = parts[1].strip()
                                    if path and path != '/':
                                        discovered_paths.append({
                                            "path": path,
                                            "status_code": None,  # We haven't checked it yet
                                            "content_type": None,
                                            "method": "GET",
                                            "source": "robots_txt"
                                        })
                                        logger.info(f"Found path in robots.txt: {path}")
        except Exception as e:
            logger.warning(f"Error checking robots.txt: {str(e)}")
        
        return discovered_paths
    
    async def _check_sitemap_xml(self) -> List[Dict[str, Any]]:
        """Check sitemap.xml for paths."""
        discovered_paths = []
        
        try:
            sitemap_url = f"{self.url.rstrip('/')}/sitemap.xml"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    sitemap_url, 
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=5
                ) as response:
                    if response.status == 200:
                        sitemap_xml = await response.text()
                        
                        # Add sitemap.xml itself
                        discovered_paths.append({
                            "path": "/sitemap.xml",
                            "status_code": 200,
                            "content_type": "application/xml",
                            "method": "GET",
                            "source": "sitemap_xml"
                        })
                        
                        # Extract URLs from sitemap
                        soup = BeautifulSoup(sitemap_xml, 'xml')
                        for loc in soup.find_all('loc'):
                            url = loc.text
                            if self.url in url:
                                path = url.replace(self.url.rstrip('/'), '')
                                if not path:
                                    path = '/'
                                
                                discovered_paths.append({
                                    "path": path,
                                    "status_code": None,  # We haven't checked it yet
                                    "content_type": None,
                                    "method": "GET",
                                    "source": "sitemap_xml"
                                })
                                logger.info(f"Found path in sitemap.xml: {path}")
        except Exception as e:
            logger.warning(f"Error checking sitemap.xml: {str(e)}")
        
        return discovered_paths
    
    async def _check_js_files(self) -> List[Dict[str, Any]]:
        """Extract paths from JavaScript files."""
        discovered_paths = []
        js_files = []
        
        # First, find JS files
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.url, 
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=10
                ) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Find script tags with src attribute
                        for script in soup.find_all('script', src=True):
                            src = script['src']
                            
                            # Handle relative URLs
                            if src.startswith('/'):
                                full_url = f"{self.url.rstrip('/')}{src}"
                            elif src.startswith(('http://', 'https://')):
                                # Only include scripts from the same domain
                                if self.url.replace('https://', '').replace('http://', '') in src:
                                    full_url = src
                                else:
                                    continue
                            else:
                                full_url = f"{self.url.rstrip('/')}/{src}"
                            
                            js_files.append((full_url, src))
        except Exception as e:
            logger.warning(f"Error finding JS files: {str(e)}")
        
        # Then, analyze each JS file
        for full_url, src in js_files:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        full_url, 
                        headers={"User-Agent": "Mozilla/5.0"},
                        timeout=5
                    ) as response:
                        if response.status == 200:
                            js_content = await response.text()
                            
                            # Add the JS file itself
                            path = src
                            if src.startswith(('http://', 'https://')):
                                path = src.replace(self.url.rstrip('/'), '')
                            
                            discovered_paths.append({
                                "path": path,
                                "status_code": 200,
                                "content_type": "application/javascript",
                                "method": "GET",
                                "source": "js_file"
                            })
                            
                            # Extract potential API endpoints and paths
                            # Look for URL patterns in the JS code
                            url_patterns = [
                                r'["\'](/[^"\']*)["\']',  # "/api/v1/users"
                                r'["\'](https?://[^"\']*)["\']',  # "https://example.com/api"
                                r'fetch\(["\']([^"\']*)["\']',  # fetch("/api/data")
                                r'url:\s*["\']([^"\']*)["\']',  # url: "/api/data"
                                r'path:\s*["\']([^"\']*)["\']',  # path: "/api/data"
                                r'endpoint:\s*["\']([^"\']*)["\']'  # endpoint: "/api/data"
                            ]
                            
                            for pattern in url_patterns:
                                for match in re.finditer(pattern, js_content):
                                    url_match = match.group(1)
                                    
                                    # Handle absolute URLs
                                    if url_match.startswith(('http://', 'https://')):
                                        if self.url.replace('https://', '').replace('http://', '') in url_match:
                                            path = url_match.replace(self.url.rstrip('/'), '')
                                        else:
                                            continue
                                    else:
                                        path = url_match
                                    
                                    if path and not path.startswith(('http://', 'https://')):
                                        discovered_paths.append({
                                            "path": path,
                                            "status_code": None,  # We haven't checked it yet
                                            "content_type": None,
                                            "method": "GET",
                                            "source": "js_analysis"
                                        })
                                        logger.info(f"Found path in JS: {path}")
            except Exception as e:
                logger.warning(f"Error analyzing JS file {full_url}: {str(e)}")
        
        return discovered_paths