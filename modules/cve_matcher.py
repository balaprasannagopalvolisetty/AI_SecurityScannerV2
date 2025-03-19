import asyncio
import aiohttp
import logging
import os
import json
import re
from typing import List, Dict, Any
import subprocess
import time

logger = logging.getLogger(__name__)

class CVEMatcher:
    def __init__(self):
        self.nvd_api_key = os.getenv("NVD_API_KEY", "")
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "ALIENTELLIGENCE/predictivethreatdetection")
        self.cve_repo_path = "cvelistV5"
    
    async def match_cves(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match vulnerabilities to CVEs."""
        if not vulnerabilities:
            return []
        
        cve_matches = []
        
        # Process vulnerabilities in batches to avoid overwhelming the APIs
        batch_size = 5
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i+batch_size]
            
            # Run different matching methods in parallel
            tasks = [
                self._match_with_nvd_api(batch),
                self._match_with_openai(batch),
                self._match_with_ollama(batch),
                self._match_with_cve_repo(batch)
            ]
            
            results = await asyncio.gather(*tasks)
            
            # Combine results from different methods
            for vuln_index, vuln in enumerate(batch):
                vuln_matches = []
                
                for method_results in results:
                    if method_results and vuln_index < len(method_results):
                        method_matches = method_results[vuln_index].get("matches", [])
                        for match in method_matches:
                            if match not in vuln_matches:
                                vuln_matches.append(match)
                
                cve_matches.append({
                    "vulnerability": vuln,
                    "matches": vuln_matches
                })
            
            # Add a small delay to avoid rate limiting
            await asyncio.sleep(1)
        
        return cve_matches
    
    async def _match_with_nvd_api(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match vulnerabilities with CVEs using the NVD API."""
        if not self.nvd_api_key:
            logger.warning("NVD API key not provided")
            return []
        
        results = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "")
            vuln_name = vuln.get("name", "")
            
            # Create search keywords based on vulnerability type
            keywords = []
            if vuln_type == "xss":
                keywords = ["XSS", "Cross-Site Scripting", "cross site scripting"]
            elif vuln_type == "sqli":
                keywords = ["SQL Injection", "SQLi", "sql injection"]
            elif vuln_type == "lfi":
                keywords = ["Local File Inclusion", "LFI", "path traversal", "directory traversal"]
            elif vuln_type == "open_redirect":
                keywords = ["Open Redirect", "URL Redirect"]
            elif vuln_type == "information_disclosure":
                keywords = ["Information Disclosure", "Information Leakage", "version disclosure"]
            elif vuln_type == "missing_security_headers":
                keywords = ["Security Headers", "HTTP Headers", "HSTS"]
            
            matches = []
            
            for keyword in keywords:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params={
                                "keywordSearch": keyword,
                                "resultsPerPage": 10
                            },
                            headers={
                                "apiKey": self.nvd_api_key
                            }
                        ) as response:
                            if response.status == 200:
                                data = await response.json()
                                
                                for cve_item in data.get("vulnerabilities", []):
                                    cve = cve_item.get("cve", {})
                                    cve_id = cve.get("id", "")
                                    description = ""
                                    
                                    for desc in cve.get("descriptions", []):
                                        if desc.get("lang") == "en":
                                            description = desc.get("value", "")
                                            break
                                    
                                    # Calculate a simple relevance score
                                    relevance_score = 0
                                    if vuln_type.lower() in description.lower():
                                        relevance_score += 2
                                    if any(kw.lower() in description.lower() for kw in keywords):
                                        relevance_score += 1
                                    
                                    # Only include matches with some relevance
                                    if relevance_score > 0:
                                        # Get CVSS score if available
                                        cvss_v3 = None
                                        metrics = cve.get("metrics", {})
                                        if "cvssMetricV31" in metrics:
                                            cvss_data = metrics["cvssMetricV31"][0]
                                            cvss_v3 = cvss_data.get("cvssData", {})
                                        elif "cvssMetricV30" in metrics:
                                            cvss_data = metrics["cvssMetricV30"][0]
                                            cvss_v3 = cvss_data.get("cvssData", {})
                                        
                                        severity = "unknown"
                                        base_score = 0
                                        if cvss_v3:
                                            base_score = cvss_v3.get("baseScore", 0)
                                            severity = cvss_v3.get("baseSeverity", "unknown")
                                        
                                        match = {
                                            "cve_id": cve_id,
                                            "description": description,
                                            "base_score": base_score,
                                            "severity": severity,
                                            "relevance_score": relevance_score,
                                            "source": "nvd_api"
                                        }
                                        
                                        # Check if this CVE is already in matches
                                        if not any(m["cve_id"] == cve_id for m in matches):
                                            matches.append(match)
                except Exception as e:
                    logger.warning(f"Error matching with NVD API for keyword {keyword}: {str(e)}")
            
            # Sort matches by relevance score
            matches.sort(key=lambda x: x["relevance_score"], reverse=True)
            
            # Limit to top 5 matches
            matches = matches[:5]
            
            results.append({
                "vulnerability": vuln,
                "matches": matches
            })
        
        return results
    
    async def _match_with_openai(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match vulnerabilities with CVEs using OpenAI."""
        if not self.openai_api_key:
            logger.warning("OpenAI API key not provided")
            return []
        
        results = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "")
            vuln_name = vuln.get("name", "")
            vuln_description = vuln.get("description", "")
            
            # Skip if there's not enough information
            if not vuln_type or not vuln_name:
                results.append({
                    "vulnerability": vuln,
                    "matches": []
                })
                continue
            
            try:
                # Prepare the prompt for OpenAI
                prompt = f"""
                I have a web vulnerability with the following details:
                - Type: {vuln_type}
                - Name: {vuln_name}
                - Description: {vuln_description}
                
                Please identify the most relevant CVE (Common Vulnerabilities and Exposures) entries that match this vulnerability.
                For each CVE, provide:
                1. CVE ID
                2. Brief description
                3. CVSS score and severity
                4. Relevance to the vulnerability (high, medium, or low)
                
                Format the response as a JSON array with the following structure:
                [
                  {{
                    "cve_id": "CVE-YYYY-NNNNN",
                    "description": "Brief description",
                    "base_score": 7.5,
                    "severity": "high",
                    "relevance_score": 2,
                    "source": "openai"
                  }}
                ]
                
                Limit to the 3 most relevant CVEs.
                """
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {self.openai_api_key}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "model": "gpt-4o",
                            "messages": [
                                {"role": "system", "content": "You are a cybersecurity expert specializing in CVE identification."},
                                {"role": "user", "content": prompt}
                            ],
                            "temperature": 0.3
                        }
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            content = data["choices"][0]["message"]["content"]
                            
                            # Extract JSON from the response
                            matches = []
                            try:
                                # Find JSON array in the response
                                json_match = re.search(r'\[\s*\{.*\}\s*\]', content, re.DOTALL)
                                if json_match:
                                    json_str = json_match.group(0)
                                    matches = json.loads(json_str)
                                else:
                                    # Try to parse the entire content as JSON
                                    matches = json.loads(content)
                            except json.JSONDecodeError:
                                logger.warning(f"Failed to parse OpenAI response as JSON: {content}")
                            
                            results.append({
                                "vulnerability": vuln,
                                "matches": matches
                            })
                        else:
                            error_data = await response.json()
                            logger.warning(f"OpenAI API error: {error_data}")
                            results.append({
                                "vulnerability": vuln,
                                "matches": []
                            })
            except Exception as e:
                logger.warning(f"Error matching with OpenAI: {str(e)}")
                results.append({
                    "vulnerability": vuln,
                    "matches": []
                })
        
        return results
    
    async def _match_with_ollama(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match vulnerabilities with CVEs using Ollama."""
        if not self.ollama_model:
            logger.warning("Ollama model not specified")
            return []
        
        results = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "")
            vuln_name = vuln.get("name", "")
            vuln_description = vuln.get("description", "")
            
            # Skip if there's not enough information
            if not vuln_type or not vuln_name:
                results.append({
                    "vulnerability": vuln,
                    "matches": []
                })
                continue
            
            try:
                # Prepare the prompt for Ollama
                prompt = f"""
                I have a web vulnerability with the following details:
                - Type: {vuln_type}
                - Name: {vuln_name}
                - Description: {vuln_description}
                
                Please identify the most relevant CVE (Common Vulnerabilities and Exposures) entries that match this vulnerability.
                For each CVE, provide:
                1. CVE ID
                2. Brief description
                3. CVSS score and severity
                4. Relevance to the vulnerability (high, medium, or low)
                
                Format the response as a JSON array with the following structure:
                [
                  {{
                    "cve_id": "CVE-YYYY-NNNNN",
                    "description": "Brief description",
                    "base_score": 7.5,
                    "severity": "high",
                    "relevance_score": 2,
                    "source": "ollama"
                  }}
                ]
                
                Limit to the 3 most relevant CVEs.
                """
                
                # Call Ollama API
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://localhost:11434/api/generate",
                        json={
                            "model": self.ollama_model,
                            "prompt": prompt,
                            "stream": False
                        }
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            content = data.get("response", "")
                            
                            # Extract JSON from the response
                            matches = []
                            try:
                                # Find JSON array in the response
                                json_match = re.search(r'\[\s*\{.*\}\s*\]', content, re.DOTALL)
                                if json_match:
                                    json_str = json_match.group(0)
                                    matches = json.loads(json_str)
                                else:
                                    # Try to parse the entire content as JSON
                                    matches = json.loads(content)
                            except json.JSONDecodeError:
                                logger.warning(f"Failed to parse Ollama response as JSON: {content}")
                            
                            results.append({
                                "vulnerability": vuln,
                                "matches": matches
                            })
                        else:
                            error_data = await response.text()
                            logger.warning(f"Ollama API error: {error_data}")
                            results.append({
                                "vulnerability": vuln,
                                "matches": []
                            })
            except Exception as e:
                logger.warning(f"Error matching with Ollama: {str(e)}")
                results.append({
                    "vulnerability": vuln,
                    "matches": []
                })
        
        return results
    
    async def _match_with_cve_repo(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match vulnerabilities with CVEs using the local CVE repository."""
        if not os.path.exists(self.cve_repo_path):
            logger.warning(f"CVE repository not found at {self.cve_repo_path}")
            return []
        
        results = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "")
            vuln_name = vuln.get("name", "")
            
            # Skip if there's not enough information
            if not vuln_type or not vuln_name:
                results.append({
                    "vulnerability": vuln,
                    "matches": []
                })
                continue
            
            # Create search keywords based on vulnerability type
            keywords = []
            if vuln_type == "xss":
                keywords = ["XSS", "Cross-Site Scripting", "cross site scripting"]
            elif vuln_type == "sqli":
                keywords = ["SQL Injection", "SQLi", "sql injection"]
            elif vuln_type == "lfi":
                keywords = ["Local File Inclusion", "LFI", "path traversal", "directory traversal"]
            elif vuln_type == "open_redirect":
                keywords = ["Open Redirect", "URL Redirect"]
            elif vuln_type == "information_disclosure":
                keywords = ["Information Disclosure", "Information Leakage", "version disclosure"]
            elif vuln_type == "missing_security_headers":
                keywords = ["Security Headers", "HTTP Headers", "HSTS"]
            
            matches = []
            
            try:
                # Use grep to search for keywords in the CVE repository
                for keyword in keywords:
                    # Escape the keyword for grep
                    escaped_keyword = keyword.replace('"', '\\"')
                    
                    # Run grep command
                    cmd = f'grep -r "{escaped_keyword}" {self.cve_repo_path} --include="*.json" -l | head -10'
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    
                    if stdout:
                        file_paths = stdout.decode().strip().split('\n')
                        
                        for file_path in file_paths:
                            if os.path.exists(file_path):
                                with open(file_path, 'r') as f:
                                    try:
                                        cve_data = json.load(f)
                                        
                                        # Extract CVE information
                                        cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")
                                        if not cve_id:
                                            continue
                                        
                                        # Get description
                                        description = ""
                                        for container in cve_data.get("containers", {}).get("cna", {}).get("descriptions", []):
                                            if container.get("lang") == "en":
                                                description = container.get("value", "")
                                                break
                                        
                                        # Calculate relevance score
                                        relevance_score = 0
                                        if vuln_type.lower() in description.lower():
                                            relevance_score += 2
                                        if any(kw.lower() in description.lower() for kw in keywords):
                                            relevance_score += 1
                                        
                                        # Only include matches with some relevance
                                        if relevance_score > 0:
                                            # Get CVSS score if available
                                            base_score = 0
                                            severity = "unknown"
                                            
                                            metrics = cve_data.get("containers", {}).get("cna", {}).get("metrics", [])
                                            for metric in metrics:
                                                if metric.get("format") == "CVSS":
                                                    cvss_data = metric.get("cvssV3_1", {}) or metric.get("cvssV3_0", {})
                                                    if cvss_data:
                                                        base_score = float(cvss_data.get("baseScore", 0))
                                                        severity = cvss_data.get("baseSeverity", "unknown")
                                                        break
                                            
                                            match = {
                                                "cve_id": cve_id,
                                                "description": description,
                                                "base_score": base_score,
                                                "severity": severity,
                                                "relevance_score": relevance_score,
                                                "source": "cve_repo"
                                            }
                                            
                                            # Check if this CVE is already in matches
                                            if not any(m["cve_id"] == cve_id for m in matches):
                                                matches.append(match)
                                    except json.JSONDecodeError:
                                        logger.warning(f"Failed to parse CVE file: {file_path}")
            except Exception as e:
                logger.warning(f"Error matching with CVE repository: {str(e)}")
            
            # Sort matches by relevance score
            matches.sort(key=lambda x: x["relevance_score"], reverse=True)
            
            # Limit to top 5 matches
            matches = matches[:5]
            
            results.append({
                "vulnerability": vuln,
                "matches": matches
            })
        
        return results