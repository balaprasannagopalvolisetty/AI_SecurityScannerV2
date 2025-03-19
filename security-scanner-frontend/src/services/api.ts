// src/services/api.ts

// Base URL for the API
const API_BASE_URL = "http://localhost:8000";

// Mock data for development
const MOCK_MODE = true;

// Helper function to handle API responses
const handleResponse = async (response: Response) => {
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || "An error occurred");
  }
  return response.json();
};

// Start a new scan
export const startScan = async (url: string, scanDepth = 2, timeout = 30) => {
  if (MOCK_MODE) {
    // Return mock data
    await new Promise((resolve) => setTimeout(resolve, 1500)); // Simulate API delay
    return {
      scan_id: `scan_${Math.floor(Math.random() * 1000)}`,
      status: "pending",
      message: "Scan started",
    };
  }

  const response = await fetch(`${API_BASE_URL}/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url, scan_depth: scanDepth, timeout }),
  });

  return handleResponse(response);
};

// Get scan status
export const getScanStatus = async (scanId: string) => {
  if (MOCK_MODE) {
    // Return mock data
    await new Promise((resolve) => setTimeout(resolve, 1000)); // Simulate API delay

    // Randomly choose a status for demo purposes
    const statuses = ["pending", "scanning", "completed"];
    const randomStatus = statuses[Math.floor(Math.random() * statuses.length)];

    return {
      scan_id: scanId,
      status: randomStatus,
      url: "example.com",
      timestamp: new Date().toISOString(),
    };
  }

  const response = await fetch(`${API_BASE_URL}/scan/${scanId}`);
  return handleResponse(response);
};

// Get scan report
export const getScanReport = async (scanId: string) => {
  if (MOCK_MODE) {
    // Return mock data
    await new Promise((resolve) => setTimeout(resolve, 1500)); // Simulate API delay

    return {
      scan_id: scanId,
      status: "completed",
      url: "example.com",
      timestamp: new Date().toISOString(),
      domain_info: {
        domain: "example.com",
        ip_addresses: {
          ipv4: ["93.184.216.34"],
          ipv6: [],
        },
        dns_records: {
          A: ["93.184.216.34"],
          AAAA: [],
          MX: ["0 example.com"],
          NS: ["a.iana-servers.net", "b.iana-servers.net"],
          TXT: [],
        },
        hosting_info: {
          isp: "IANA",
          org: "Internet Assigned Numbers Authority",
          country: "United States",
          cloud_provider: "Unknown",
        },
        waf_cdn: {
          detected: false,
          providers: [],
        },
      },
      subdomains: {
        count: 3,
        items: ["www.example.com", "api.example.com", "mail.example.com"],
      },
      paths: {
        count: 8,
        items: [
          { path: "/", status_code: 200, content_type: "text/html", method: "GET", source: "crawling" },
          { path: "/robots.txt", status_code: 404, content_type: "text/html", method: "GET", source: "common_paths" },
          { path: "/sitemap.xml", status_code: 404, content_type: "text/html", method: "GET", source: "common_paths" },
          { path: "/api", status_code: 404, content_type: "text/html", method: "GET", source: "common_paths" },
          { path: "/admin", status_code: 404, content_type: "text/html", method: "GET", source: "common_paths" },
          { path: "/login", status_code: 404, content_type: "text/html", method: "GET", source: "common_paths" },
          { path: "/wp-admin", status_code: 404, content_type: "text/html", method: "GET", source: "common_paths" },
          { path: "/.git", status_code: 404, content_type: "text/html", method: "GET", source: "common_paths" },
        ],
      },
      vulnerabilities: {
        count: 4,
        items: [
          {
            type: "information_disclosure",
            name: "Server Information Disclosure",
            description: "The server is disclosing version information through HTTP headers",
            severity: "medium",
            url: "https://example.com",
            evidence: {
              server: "ECS (dcb/7F84)",
            },
            remediation: "Configure the server to remove or obfuscate version information from HTTP headers",
          },
          {
            type: "missing_security_headers",
            name: "Missing Security Headers",
            description: "The server is missing 4 important security headers",
            severity: "medium",
            url: "https://example.com",
            evidence: [
              {
                header: "Content-Security-Policy",
                description: "Helps prevent XSS attacks by specifying which dynamic resources are allowed to load",
              },
              {
                header: "X-Frame-Options",
                description: "Protects against clickjacking attacks",
              },
            ],
            remediation: "Configure the server to include the missing security headers",
          },
          {
            type: "open_redirect",
            name: "Open Redirect",
            description: "Parameter redirect is vulnerable to open redirect",
            severity: "medium",
            url: "https://example.com/redirect?url=https://evil.com",
            evidence: {
              payload: "https://evil.com",
              param: "url",
              location: "https://evil.com",
            },
            remediation: "Implement a whitelist of allowed redirect URLs or use relative URLs",
          },
          {
            type: "xss",
            name: "Cross-Site Scripting (XSS)",
            description: "Parameter q is vulnerable to XSS",
            severity: "high",
            url: "https://example.com/search?q=<script>alert(1)</script>",
            evidence: {
              payload: "<script>alert(1)</script>",
              param: "q",
            },
            remediation: "Implement proper input validation and output encoding",
          },
        ],
      },
      severity_counts: {
        critical: 0,
        high: 1,
        medium: 2,
        low: 1,
        info: 0,
      },
      risk_score: 45,
      recommendations: [
        {
          title: "Fix Server Information Disclosure Issues",
          severity: "medium",
          vulnerability_type: "information_disclosure",
          count: 1,
          description: "The server is disclosing version information through HTTP headers",
          remediation: "Configure the server to remove or obfuscate version information from HTTP headers",
          affected_urls: ["https://example.com"],
        },
        {
          title: "Implement Missing Security Headers",
          severity: "medium",
          vulnerability_type: "missing_security_headers",
          count: 1,
          description: "The server is missing important security headers",
          remediation: "Configure the server to include the missing security headers",
          affected_urls: ["https://example.com"],
        },
        {
          title: "Fix Cross-Site Scripting (XSS) Issues",
          severity: "high",
          vulnerability_type: "xss",
          count: 1,
          description: "Parameter q is vulnerable to XSS",
          remediation: "Implement proper input validation and output encoding",
          affected_urls: ["https://example.com/search?q=<script>alert(1)</script>"],
        },
      ],
    };
  }

  const response = await fetch(`${API_BASE_URL}/report/${scanId}`);
  return handleResponse(response);
};

// Get all scans (for dashboard)
export const fetchScans = async () => {
  if (MOCK_MODE) {
    // Return mock data
    await new Promise((resolve) => setTimeout(resolve, 1000)); // Simulate API delay

    return [
      {
        id: "scan_123",
        url: "example.com",
        status: "completed",
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        vulnerabilities: {
          critical: 0,
          high: 1,
          medium: 2,
          low: 1,
          info: 0,
        },
      },
      {
        id: "scan_124",
        url: "test.com",
        status: "scanning",
        timestamp: new Date(Date.now() - 1800000).toISOString(),
      },
      {
        id: "scan_125",
        url: "demo.org",
        status: "completed",
        timestamp: new Date(Date.now() - 86400000).toISOString(),
        vulnerabilities: {
          critical: 1,
          high: 2,
          medium: 3,
          low: 2,
          info: 1,
        },
      },
      {
        id: "scan_126",
        url: "sample.net",
        status: "failed",
        timestamp: new Date(Date.now() - 43200000).toISOString(),
      },
    ];
  }

  // In a real implementation, you would fetch this from the API
  // This endpoint doesn't exist in our backend yet, so we'd need to add it
  const response = await fetch(`${API_BASE_URL}/scans`);
  return handleResponse(response);
};