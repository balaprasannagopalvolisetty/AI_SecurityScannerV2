"use client"

import type React from "react"
import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { Search, AlertTriangle } from "react-feather"
import MatrixEffect from "./MatrixEffect"
import { startScan } from "../services/api"

const ScanForm: React.FC = () => {
  const [url, setUrl] = useState("")
  const [scanDepth, setScanDepth] = useState(2)
  const [timeout, setTimeout] = useState(30)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // Validate URL
    if (!url) {
      setError("URL is required")
      return
    }

    try {
      setLoading(true)
      setError("")

      // Start scan
      const result = await startScan(url, scanDepth, timeout)

      // Navigate to results page
      navigate(`/results/${result.scan_id}`)
    } catch (error) {
      console.error("Error starting scan:", error)
      setError("Failed to start scan. Please try again.")
      setLoading(false)
    }
  }

  return (
    <div className="scan-form">
      <MatrixEffect />

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Start New Security Scan</h2>
          <Search size={20} />
        </div>

        {error && (
          <div
            style={{
              backgroundColor: "rgba(255, 0, 0, 0.1)",
              border: "1px solid rgba(255, 0, 0, 0.3)",
              borderRadius: "4px",
              padding: "10px",
              marginBottom: "20px",
              display: "flex",
              alignItems: "center",
              gap: "10px",
            }}
          >
            <AlertTriangle size={16} color="#ff0000" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="url" className="form-label">
              Target URL
            </label>
            <input
              type="text"
              id="url"
              className="form-input"
              placeholder="Enter URL (e.g., example.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
            <small style={{ display: "block", marginTop: "5px", fontSize: "12px", opacity: 0.7 }}>
              Enter a domain name or URL to scan (e.g., example.com, https://example.com)
            </small>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
            <div className="form-group">
              <label htmlFor="scanDepth" className="form-label">
                Scan Depth
              </label>
              <select
                id="scanDepth"
                className="form-input"
                value={scanDepth}
                onChange={(e) => setScanDepth(Number.parseInt(e.target.value))}
              >
                <option value={1}>Light (Faster)</option>
                <option value={2}>Medium (Recommended)</option>
                <option value={3}>Deep (Slower)</option>
              </select>
            </div>

            <div className="form-group">
              <label htmlFor="timeout" className="form-label">
                Timeout (seconds)
              </label>
              <input
                type="number"
                id="timeout"
                className="form-input"
                min={5}
                max={120}
                value={timeout}
                onChange={(e) => setTimeout(Number.parseInt(e.target.value))}
              />
            </div>
          </div>

          <div className="form-group" style={{ marginTop: "20px" }}>
            <button type="submit" className="btn btn-primary" style={{ width: "100%" }} disabled={loading}>
              {loading ? (
                <>
                  <span className="loader" style={{ marginRight: "10px" }}></span>
                  Starting Scan...
                </>
              ) : (
                <>
                  <Search size={16} style={{ marginRight: "10px" }} />
                  Start Security Scan
                </>
              )}
            </button>
          </div>
        </form>

        <div
          style={{ marginTop: "20px", padding: "15px", backgroundColor: "rgba(0, 255, 0, 0.05)", borderRadius: "4px" }}
        >
          <h3 style={{ marginBottom: "10px", fontSize: "16px" }}>What will be scanned?</h3>
          <ul style={{ paddingLeft: "20px", fontSize: "14px" }}>
            <li>Domain & Infrastructure Information</li>
            <li>Subdomains & Paths Discovery</li>
            <li>Web Application & Technology Stack</li>
            <li>OSINT & Publicly Available Data</li>
            <li>Network & Services Enumeration</li>
            <li>Files, Directories & Hidden Paths</li>
            <li>Security Vulnerabilities & Misconfigurations</li>
          </ul>
        </div>
      </div>
    </div>
  )
}

export default ScanForm

