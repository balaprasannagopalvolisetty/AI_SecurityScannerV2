import asyncio
import socket
import dns.resolver
import whois
import requests
import json
import logging
from typing import Dict, List, Any
import aiohttp
import os

logger = logging.getLogger(__name__)

class DomainScanner:
    def __init__(self, url: str):
        self.url = url
        self.domain = self._extract_domain(url)
        self.shodan_api_key = os.getenv("SHODAN_API_KEY", "")
        self.vt_api_key = os.getenv("VT_API_KEY", "")
    
    def _extract_domain(self, url: str) -> str:
        """Extract the domain from a URL."""
        url = url.replace("http://", "").replace("https://", "")
        return url.split("/")[0]
    
    async def scan(self) -> Dict[str, Any]:
        """Scan domain and gather infrastructure information."""
        tasks = [
            self._get_ip_addresses(),
            self._get_dns_records(),
            self._get_whois_info(),
            self._detect_waf_cdn(),
            self._get_hosting_info(),
            self._get_ssl_info()
        ]
        
        results = await asyncio.gather(*tasks)
        
        return {
            "domain": self.domain,
            "ip_addresses": results[0],
            "dns_records": results[1],
            "whois_info": results[2],
            "waf_cdn": results[3],
            "hosting_info": results[4],
            "ssl_info": results[5]
        }
    
    async def _get_ip_addresses(self) -> Dict[str, List[str]]:
        """Get IPv4 and IPv6 addresses for the domain."""
        ipv4_addresses = []
        ipv6_addresses = []
        
        try:
            # Get IPv4 addresses
            answers = dns.resolver.resolve(self.domain, 'A')
            for rdata in answers:
                ipv4_addresses.append(str(rdata))
        except Exception as e:
            logger.warning(f"Error getting IPv4 addresses: {str(e)}")
        
        try:
            # Get IPv6 addresses
            answers = dns.resolver.resolve(self.domain, 'AAAA')
            for rdata in answers:
                ipv6_addresses.append(str(rdata))
        except Exception as e:
            logger.warning(f"Error getting IPv6 addresses: {str(e)}")
        
        return {
            "ipv4": ipv4_addresses,
            "ipv6": ipv6_addresses
        }
    
    async def _get_dns_records(self) -> Dict[str, List[str]]:
        """Get various DNS records for the domain."""
        dns_records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                logger.warning(f"Error getting {record_type} records: {str(e)}")
                dns_records[record_type] = []
        
        return dns_records
    
    async def _get_whois_info(self) -> Dict[str, Any]:
        """Get WHOIS information for the domain."""
        try:
            w = whois.whois(self.domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails
            }
        except Exception as e:
            logger.warning(f"Error getting WHOIS info: {str(e)}")
            return {}
    
    async def _detect_waf_cdn(self) -> Dict[str, Any]:
        """Detect if the domain is using a WAF or CDN."""
        waf_signatures = {
            "Cloudflare": ["Server: cloudflare", "__cfduid", "cf-ray"],
            "Akamai": ["X-Akamai-Transformed", "Akamai-Origin-Hop"],
            "Imperva": ["X-Iinfo", "_imp_apg_r_"],
            "Fastly": ["Fastly-SSL", "X-Fastly-Request-ID"],
            "Sucuri": ["X-Sucuri-ID", "X-Sucuri-Cache"],
            "AWS WAF": ["X-AMZ-CF-ID", "X-AMZ-CF-POP"]
        }
        
        result = {"detected": False, "providers": []}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{self.domain}", headers={"User-Agent": "Mozilla/5.0"}) as response:
                    headers = dict(response.headers)
                    
                    for provider, signatures in waf_signatures.items():
                        for signature in signatures:
                            for header, value in headers.items():
                                if signature.lower() in header.lower() or (isinstance(value, str) and signature.lower() in value.lower()):
                                    result["detected"] = True
                                    if provider not in result["providers"]:
                                        result["providers"].append(provider)
        except Exception as e:
            logger.warning(f"Error detecting WAF/CDN: {str(e)}")
        
        return result
    
    async def _get_hosting_info(self) -> Dict[str, Any]:
        """Get hosting provider information."""
        if not self.shodan_api_key:
            return {"error": "Shodan API key not provided"}
        
        try:
            ip_addresses = await self._get_ip_addresses()
            if not ip_addresses["ipv4"]:
                return {"error": "No IP addresses found"}
            
            ip = ip_addresses["ipv4"][0]
            
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_api_key}") as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "isp": data.get("isp", "Unknown"),
                            "org": data.get("org", "Unknown"),
                            "country": data.get("country_name", "Unknown"),
                            "os": data.get("os", "Unknown"),
                            "ports": data.get("ports", []),
                            "hostnames": data.get("hostnames", []),
                            "cloud_provider": self._detect_cloud_provider(data)
                        }
                    else:
                        return {"error": f"Shodan API error: {response.status}"}
        except Exception as e:
            logger.warning(f"Error getting hosting info: {str(e)}")
            return {"error": str(e)}
    
    def _detect_cloud_provider(self, shodan_data: Dict[str, Any]) -> str:
        """Detect cloud provider from Shodan data."""
        org = shodan_data.get("org", "").lower()
        
        if "amazon" in org or "aws" in org:
            return "AWS"
        elif "microsoft" in org or "azure" in org:
            return "Azure"
        elif "google" in org or "gcp" in org:
            return "Google Cloud"
        elif "digitalocean" in org:
            return "DigitalOcean"
        elif "linode" in org:
            return "Linode"
        elif "ovh" in org:
            return "OVH"
        elif "cloudflare" in org:
            return "Cloudflare"
        else:
            return "Unknown"
    
    async def _get_ssl_info(self) -> Dict[str, Any]:
        """Get SSL certificate information."""
        try:
            import ssl
            import socket
            import datetime
            
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    return {
                        "issuer": dict(cert['issuer']),
                        "subject": dict(cert['subject']),
                        "version": cert['version'],
                        "serial_number": cert['serialNumber'],
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "expired": datetime.datetime.now() > not_after
                    }
        except Exception as e:
            logger.warning(f"Error getting SSL info: {str(e)}")
            return {"error": str(e)}