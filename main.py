from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
import uvicorn
import os
import json
from typing import Optional, List, Dict, Any
import asyncio
import logging

# Import our modules
from modules.domain_scanner import DomainScanner
from modules.subdomain_finder import SubdomainFinder
from modules.path_discovery import PathDiscovery
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.cve_matcher import CVEMatcher
from modules.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("security_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Advanced Web Security Scanner",
    description="A comprehensive web security scanning tool that discovers subdomains, paths, and vulnerabilities",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store scan results
scan_results = {}

class URLInput(BaseModel):
    url: str
    scan_depth: Optional[int] = 2
    timeout: Optional[int] = 30

@app.get("/")
async def root():
    return {"message": "Welcome to the Advanced Web Security Scanner API"}

@app.post("/scan")
async def scan_url(url_input: URLInput, background_tasks: BackgroundTasks):
    # Normalize URL
    url = url_input.url
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    scan_id = f"scan_{len(scan_results) + 1}"
    scan_results[scan_id] = {"status": "pending", "url": url}
    
    # Start scan in background
    background_tasks.add_task(run_scan, scan_id, url, url_input.scan_depth, url_input.timeout)
    
    return {"scan_id": scan_id, "status": "pending", "message": "Scan started"}

@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]

@app.get("/report/{scan_id}")
async def get_scan_report(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_results[scan_id]["status"] != "completed":
        return {"status": scan_results[scan_id]["status"], "message": "Report not ready yet"}
    
    return scan_results[scan_id]

async def run_scan(scan_id: str, url: str, scan_depth: int, timeout: int):
    try:
        logger.info(f"Starting scan for {url} with ID {scan_id}")
        scan_results[scan_id]["status"] = "scanning"
        
        # Initialize scanners
        domain_scanner = DomainScanner(url)
        subdomain_finder = SubdomainFinder(url)
        path_discovery = PathDiscovery(url)
        vulnerability_scanner = VulnerabilityScanner()
        cve_matcher = CVEMatcher()
        report_generator = ReportGenerator()
        
        # Step 1: Scan domain information
        logger.info(f"[{scan_id}] Scanning domain information")
        domain_info = await domain_scanner.scan()
        scan_results[scan_id]["domain_info"] = domain_info
        
        # Step 2: Find subdomains
        logger.info(f"[{scan_id}] Finding subdomains")
        subdomains = await subdomain_finder.find_subdomains()
        scan_results[scan_id]["subdomains"] = subdomains
        
        # Step 3: Discover paths
        logger.info(f"[{scan_id}] Discovering paths")
        paths = await path_discovery.discover_paths()
        scan_results[scan_id]["paths"] = paths
        
        # Step 4: Scan for vulnerabilities
        logger.info(f"[{scan_id}] Scanning for vulnerabilities")
        all_targets = [url] + subdomains
        all_paths = paths
        
        vulnerabilities = []
        for target in all_targets:
            target_vulns = await vulnerability_scanner.scan(target, all_paths, scan_depth, timeout)
            vulnerabilities.extend(target_vulns)
        
        scan_results[scan_id]["vulnerabilities"] = vulnerabilities
        
        # Step 5: Match CVEs
        logger.info(f"[{scan_id}] Matching CVEs")
        cve_matches = await cve_matcher.match_cves(vulnerabilities)
        scan_results[scan_id]["cve_matches"] = cve_matches
        
        # Step 6: Generate report
        logger.info(f"[{scan_id}] Generating report")
        report = report_generator.generate(
            domain_info, 
            subdomains, 
            paths, 
            vulnerabilities, 
            cve_matches
        )
        scan_results[scan_id]["report"] = report
        
        scan_results[scan_id]["status"] = "completed"
        logger.info(f"Scan completed for {url} with ID {scan_id}")
        
    except Exception as e:
        logger.error(f"Error during scan {scan_id}: {str(e)}")
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["error"] = str(e)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)