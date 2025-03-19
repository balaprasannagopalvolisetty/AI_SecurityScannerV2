import asyncio
import aiohttp
import dns.resolver
import logging
import os
from typing import List, Dict, Any
import json

logger = logging.getLogger(__name__)

class SubdomainFinder:
    def __init__(self, url: str):
        self.url = url
        self.domain = self._extract_domain(url)
        self.shodan_api_key = os.getenv("SHODAN_API_KEY", "")
        self.vt_api_key = os.getenv("VT_API_KEY", "")
        
        # Common subdomain wordlist
        self.common_subdomains = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
            "portal", "dns", "ns", "ww1", "host", "support", "dev", "web",
            "bbs", "mx", "email", "cloud", "1", "2", "forum", "owa", "proxy",
            "admin", "api", "cdn", "staging", "app", "beta", "dashboard", "chat",
            "news", "cpanel", "whm", "autodiscover", "autoconfig", "mobile",
            "gateway", "intranet", "media", "help", "login", "client", "store",
            "status", "docs", "wiki", "git", "jenkins", "jira", "confluence"
        ]
    
    def _extract_domain(self, url: str) -> str:
        """Extract the domain from a URL."""
        url = url.replace("http://", "").replace("https://", "")
        return url.split("/")[0]
    
    async def find_subdomains(self) -> List[str]:
        """Find subdomains using multiple methods."""
        tasks = [
            self._find_subdomains_dns(),
            self._find_subdomains_shodan(),
            self._find_subdomains_virustotal(),
            self._find_subdomains_certificate_transparency()
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Combine and deduplicate results
        all_subdomains = set()
        for result in results:
            all_subdomains.update(result)
        
        # Remove the main domain from the results
        if self.domain in all_subdomains:
            all_subdomains.remove(self.domain)
        
        return sorted(list(all_subdomains))
    
    async def _find_subdomains_dns(self) -> List[str]:
        """Find subdomains using DNS brute force."""
        subdomains = set()
        
        async def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.domain}"
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    subdomains.add(full_domain)
                    logger.info(f"Found subdomain via DNS: {full_domain}")
            except Exception:
                pass
        
        tasks = []
        for subdomain in self.common_subdomains:
            tasks.append(asyncio.ensure_future(check_subdomain(subdomain)))
        
        await asyncio.gather(*tasks)
        return list(subdomains)
    
    async def _find_subdomains_shodan(self) -> List[str]:
        """Find subdomains using Shodan API."""
        if not self.shodan_api_key:
            logger.warning("Shodan API key not provided")
            return []
        
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://api.shodan.io/dns/domain/{self.domain}?key={self.shodan_api_key}"
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data.get("data", []):
                            if "subdomain" in entry and entry["subdomain"]:
                                full_domain = f"{entry['subdomain']}.{self.domain}"
                                subdomains.add(full_domain)
                                logger.info(f"Found subdomain via Shodan: {full_domain}")
        except Exception as e:
            logger.warning(f"Error finding subdomains with Shodan: {str(e)}")
        
        return list(subdomains)
    
    async def _find_subdomains_virustotal(self) -> List[str]:
        """Find subdomains using VirusTotal API."""
        if not self.vt_api_key:
            logger.warning("VirusTotal API key not provided")
            return []
        
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains",
                    headers={"x-apikey": self.vt_api_key}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data.get("data", []):
                            if "id" in item:
                                subdomains.add(item["id"])
                                logger.info(f"Found subdomain via VirusTotal: {item['id']}")
        except Exception as e:
            logger.warning(f"Error finding subdomains with VirusTotal: {str(e)}")
        
        return list(subdomains)
    
    async def _find_subdomains_certificate_transparency(self) -> List[str]:
        """Find subdomains using Certificate Transparency logs."""
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://crt.sh/?q=%.{self.domain}&output=json"
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get("name_value", "")
                            # Split by newlines and handle wildcards
                            for domain in name.split("\n"):
                                domain = domain.strip()
                                if domain.startswith("*"):
                                    domain = domain[2:]  # Remove *. prefix
                                if domain.endswith(self.domain) and domain != self.domain:
                                    subdomains.add(domain)
                                    logger.info(f"Found subdomain via CT logs: {domain}")
        except Exception as e:
            logger.warning(f"Error finding subdomains with CT logs: {str(e)}")
        
        return list(subdomains)