# AI_SecurityScannerV2

A comprehensive web security scanning tool that discovers subdomains, paths, and vulnerabilities, and matches them with CVEs.

## Features

- Domain and infrastructure information gathering
- Subdomain discovery
- Path and endpoint discovery
- Vulnerability scanning
- CVE matching using multiple sources (NVD API, OpenAI, Ollama, local CVE repository)
- Comprehensive security report generation

## Requirements

- Python 3.8+
- Ollama (for local LLM-based CVE matching)
- Git (for cloning repositories)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/advanced-web-security-scanner.git
cd advanced-web-security-scanner

