import logging
import json
from typing import List, Dict, Any
import datetime

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        pass
    
    def generate(
        self,
        domain_info: Dict[str, Any],
        subdomains: List[str],
        paths: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        cve_matches: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate a comprehensive security report."""
        
        # Count vulnerabilities by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            domain_info.get("domain", ""),
            len(subdomains),
            len(paths),
            len(vulnerabilities),
            severity_counts,
            risk_score
        )
        
        # Generate detailed findings
        detailed_findings = self._generate_detailed_findings(vulnerabilities, cve_matches)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities, cve_matches)
        
        # Create the final report
        report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "domain": domain_info.get("domain", ""),
            "risk_score": risk_score,
            "severity_counts": severity_counts,
            "executive_summary": executive_summary,
            "domain_info": domain_info,
            "subdomains": {
                "count": len(subdomains),
                "items": subdomains
            },
            "paths": {
                "count": len(paths),
                "items": paths
            },
            "vulnerabilities": {
                "count": len(vulnerabilities),
                "items": vulnerabilities
            },
            "cve_matches": cve_matches,
            "detailed_findings": detailed_findings,
            "recommendations": recommendations
        }
        
        return report
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """Calculate a risk score based on vulnerabilities."""
        if not vulnerabilities:
            return 0
        
        # Assign weights to different severity levels
        severity_weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0
        }
        
        # Calculate the weighted sum of vulnerabilities
        weighted_sum = 0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            weight = severity_weights.get(severity, 0)
            weighted_sum += weight
        
        # Normalize to a 0-100 scale
        # Assuming a maximum of 10 critical vulnerabilities would give a score of 100
        max_score = 10 * severity_weights["critical"]
        normalized_score = min(100, int((weighted_sum / max_score) * 100))
        
        return normalized_score
    
    def _generate_executive_summary(
        self,
        domain: str,
        subdomain_count: int,
        path_count: int,
        vuln_count: int,
        severity_counts: Dict[str, int],
        risk_score: int
    ) -> str:
        """Generate an executive summary of the security assessment."""
        
        # Determine the overall risk level
        risk_level = "Low"
        if risk_score >= 75:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 25:
            risk_level = "Medium"
        
        summary = f"""
        Security Assessment for {domain}
        
        Overall Risk Level: {risk_level} ({risk_score}/100)
        
        Summary of Findings:
        - {subdomain_count} subdomains discovered
        - {path_count} paths/endpoints identified
        - {vuln_count} vulnerabilities detected
          - {severity_counts["critical"]} Critical
          - {severity_counts["high"]} High
          - {severity_counts["medium"]} Medium
          - {severity_counts["low"]} Low
          - {severity_counts["info"]} Informational
        
        This security assessment identified various security issues that should be addressed to improve the overall security posture of the domain. The detailed findings and recommendations are provided in the subsequent sections of this report.
        """
        
        return summary
    
    def _generate_detailed_findings(
        self,
        vulnerabilities: List[Dict[str, Any]],
        cve_matches: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate detailed findings for each vulnerability."""
        detailed_findings = []
        
        # Create a mapping of vulnerabilities to their CVE matches
        vuln_to_cve = {}
        for cve_match in cve_matches:
            vuln = cve_match.get("vulnerability", {})
            matches = cve_match.get("matches", [])
            
            # Use a combination of type and URL as a key
            key = f"{vuln.get('type', '')}-{vuln.get('url', '')}"
            vuln_to_cve[key] = matches
        
        # Process each vulnerability
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "")
            vuln_url = vuln.get("url", "")
            
            # Get CVE matches for this vulnerability
            key = f"{vuln_type}-{vuln_url}"
            cve_matches_for_vuln = vuln_to_cve.get(key, [])
            
            # Create a detailed finding
            finding = {
                "title": vuln.get("name", "Unknown Vulnerability"),
                "type": vuln_type,
                "severity": vuln.get("severity", "info"),
                "description": vuln.get("description", ""),
                "url": vuln_url,
                "evidence": vuln.get("evidence", {}),
                "cve_matches": cve_matches_for_vuln,
                "remediation": vuln.get("remediation", "")
            }
            
            detailed_findings.append(finding)
        
        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        detailed_findings.sort(key=lambda x: severity_order.get(x["severity"].lower(), 5))
        
        return detailed_findings
    
    def _generate_recommendations(
        self,
        vulnerabilities: List[Dict[str, Any]],
        cve_matches: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate recommendations based on vulnerabilities and CVE matches."""
        recommendations = []
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "")
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Generate recommendations for each vulnerability type
        for vuln_type, vulns in vuln_types.items():
            # Count vulnerabilities by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for vuln in vulns:
                severity = vuln.get("severity", "info").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Get the highest severity
            highest_severity = "info"
            for severity in ["critical", "high", "medium", "low"]:
                if severity_counts[severity] > 0:
                    highest_severity = severity
                    break
            
            # Get a sample vulnerability for this type
            sample_vuln = vulns[0]
            
            # Create a recommendation
            recommendation = {
                "title": f"Fix {sample_vuln.get('name', 'Unknown Vulnerability')} Issues",
                "severity": highest_severity,
                "vulnerability_type": vuln_type,
                "count": len(vulns),
                "description": sample_vuln.get("description", ""),
                "remediation": sample_vuln.get("remediation", ""),
                "affected_urls": [vuln.get("url", "") for vuln in vulns if "url" in vuln][:5]  # Limit to 5 examples
            }
            
            recommendations.append(recommendation)
        
        # Sort recommendations by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        recommendations.sort(key=lambda x: severity_order.get(x["severity"].lower(), 5))
        
        return recommendations

