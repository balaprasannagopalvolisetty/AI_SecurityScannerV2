// src/components/ScanResults.tsx

import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { 
  Shield, AlertTriangle, ChevronDown, ChevronRight, Download, RefreshCw 
} from 'react-feather';
import MatrixEffect from './MatrixEffect';
import { getScanStatus, getScanReport } from '../services/api';
import JsonViewer from './JsonViewer';

interface ScanResult {
  scan_id: string;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  url: string;
  timestamp: string;
  domain_info?: any;
  subdomains?: { count: number; items: string[] };
  paths?: { count: number; items: any[] };
  vulnerabilities?: {
    count: number;
    items: any[];
  };
  severity_counts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  risk_score?: number;
  detailed_findings?: any[];
  recommendations?: any[];
}

const ScanResults: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    'domain_info': true,
    'subdomains': false,
    'paths': false,
    'vulnerabilities': true,
    'detailed_findings': false,
    'recommendations': true,
    'raw_json': false
  });

  useEffect(() => {
    const fetchData = async () => {
      if (!scanId) return;
      
      try {
        setLoading(true);
        
        // Get scan status
        const status = await getScanStatus(scanId);
        
        if (status.status === 'completed') {
          // Get full report if scan is completed
          const report = await getScanReport(scanId);
          setResult(report);
        } else {
          // Just show status if scan is still running
          setResult(status);
          
          // Poll for updates if scan is still running
          if (status.status === 'pending' || status.status === 'scanning') {
            const timer = setTimeout(fetchData, 5000);
            return () => clearTimeout(timer);
          }
        }
        
        setLoading(false);
      } catch (error) {
        console.error('Error fetching scan results:', error);
        setError('Failed to load scan results. Please try again.');
        setLoading(false);
      }
    };
    
    fetchData();
  }, [scanId]);

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <span className="badge badge-success">Completed</span>;
      case 'pending':
        return <span className="badge badge-warning">Pending</span>;
      case 'scanning':
        return <span className="badge badge-info">Scanning</span>;
      case 'failed':
        return <span className="badge badge-danger">Failed</span>;
      default:
        return <span className="badge badge-warning">Unknown</span>;
    }
  };

  const getRiskLevelBadge = (score: number) => {
    if (score >= 75) {
      return <span className="badge badge-danger">Critical Risk</span>;
    } else if (score >= 50) {
      return <span className="badge badge-danger">High Risk</span>;
    } else if (score >= 25) {
      return <span className="badge badge-warning">Medium Risk</span>;
    } else {
      return <span className="badge badge-info">Low Risk</span>;
    }
  };

  const handleRefresh = () => {
    setLoading(true);
    setError('');
    window.location.reload();
  };

  const handleDownloadReport = () => {
    if (!result) return;
    
    const dataStr = JSON.stringify(result, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = `security-scan-${scanId}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '50vh' }}>
        <div className="loader"></div>
        <p style={{ marginTop: '20px' }}>Loading scan results...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '30px' }}>
        <AlertTriangle size={40} color="#ff0000" style={{ marginBottom: '20px' }} />
        <h2 style={{ marginBottom: '20px' }}>Error Loading Results</h2>
        <p>{error}</p>
        <button className="btn btn-primary" onClick={handleRefresh} style={{ marginTop: '20px' }}>
          Try Again
        </button>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '30px' }}>
        <AlertTriangle size={40} color="#ffcc00" style={{ marginBottom: '20px' }} />
        <h2 style={{ marginBottom: '20px' }}>Scan Not Found</h2>
        <p>The requested scan could not be found.</p>
        <Link to="/scan" className="btn btn-primary" style={{ marginTop: '20px' }}>
          Start New Scan
        </Link>
      </div>
    );
  }

  return (
    <div className="scan-results">
      <MatrixEffect />
      
      {/* Header */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2 style={{ marginBottom: '10px' }}>Scan Results: {result.url}</h2>
            <div style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
              <div>
                <strong>Scan ID:</strong> {scanId}
              </div>
              <div>
                <strong>Status:</strong> {getStatusBadge(result.status)}
              </div>
              {result.timestamp && (
                <div>
                  <strong>Date:</strong> {new Date(result.timestamp).toLocaleString()}
                </div>
              )}
              {result.risk_score !== undefined && (
                <div>
                  <strong>Risk Level:</strong> {getRiskLevelBadge(result.risk_score)}
                </div>
              )}
            </div>
          </div>
          
          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="btn btn-secondary" onClick={handleRefresh}>
              <RefreshCw size={16} style={{ marginRight: '5px' }} />
              Refresh
            </button>
            {result.status === 'completed' && (
              <button className="btn btn-primary" onClick={handleDownloadReport}>
                <Download size={16} style={{ marginRight: '5px' }} />
                Download Report
              </button>
            )}
          </div>
        </div>
      </div>
      
      {/* Scan in Progress */}
      {(result.status === 'pending' || result.status === 'scanning') && (
        <div className="card" style={{ textAlign: 'center', padding: '30px' }}>
          <div className="loader" style={{ width: '40px', height: '40px', margin: '0 auto 20px' }}></div>
          <h2 style={{ marginBottom: '20px' }}>Scan in Progress</h2>
          <p style={{ marginBottom: '20px' }}>
            {result.status === 'pending' ? 'Scan is queued and will start shortly.' : 'Actively scanning target...'}
          </p>
          <div className="progress" style={{ height: '10px', maxWidth: '400px', margin: '0 auto' }}>
            <div 
              className="progress-bar" 
              style={{ 
                width: result.status === 'pending' ? '10%' : '60%',
                backgroundColor: result.status === 'pending' ? '#ffcc00' : '#00ffff'
              }}
            ></div>
          </div>
          <p style={{ marginTop: '20px', fontSize: '14px', opacity: 0.7 }}>
            This page will automatically update when the scan completes.
          </p>
        </div>
      )}
      
      {/* Scan Failed */}
      {result.status === 'failed' && (
        <div className="card" style={{ textAlign: 'center', padding: '30px' }}>
          <AlertTriangle size={40} color="#ff0000" style={{ marginBottom: '20px' }} />
          <h2 style={{ marginBottom: '20px' }}>Scan Failed</h2>
          <p>The scan encountered an error and could not complete.</p>
          <Link to="/scan" className="btn btn-primary" style={{ marginTop: '20px' }}>
            Start New Scan
          </Link>
        </div>
      )}
      
      {/* Scan Results */}
      {result.status === 'completed' && (
        <>
          {/* Summary */}
          {result.severity_counts && (
            <div className="card" style={{ marginBottom: '20px' }}>
              <div className="card-header">
                <h2 className="card-title">Vulnerability Summary</h2>
                <Shield size={20} />
              </div>
              
              <div className="grid" style={{ marginTop: '10px' }}>
                <div style={{ textAlign: 'center', padding: '15px', backgroundColor: 'rgba(255, 0, 0, 0.1)', borderRadius: '4px' }}>
                  <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#ff0000' }}>
                    {result.severity_counts.critical}
                  </div>
                  <div>Critical</div>
                </div>
                
                <div style={{ textAlign: 'center', padding: '15px', backgroundColor: 'rgba(255, 51, 0, 0.1)', borderRadius: '4px' }}>
                  <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#ff3300' }}>
                    {result.severity_counts.high}
                  </div>
                  <div>High</div>
                </div>
                
                <div style={{ textAlign: 'center', padding: '15px', backgroundColor: 'rgba(255, 204, 0, 0.1)', borderRadius: '4px' }}>
                  <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#ffcc00' }}>
                    {result.severity_counts.medium}
                  </div>
                  <div>Medium</div>
                </div>
                
                <div style={{ textAlign: 'center', padding: '15px', backgroundColor: 'rgba(0, 255, 255, 0.1)', borderRadius: '4px' }}>
                  <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#00ffff' }}>
                    {result.severity_counts.low + result.severity_counts.info}
                  </div>
                  <div>Low/Info</div>
                </div>
              </div>
              
              {result.risk_score !== undefined && (
                <div style={{ marginTop: '20px' }}>
                  <div style={{ marginBottom: '5px', display: 'flex', justifyContent: 'space-between' }}>
                    <div>Risk Score</div>
                    <div>{result.risk_score}/100</div>
                  </div>
                  <div className="progress">
                    <div 
                      className="progress-bar" 
                      style={{ 
                        width: `${result.risk_score}%`,
                        backgroundColor: result.risk_score >= 75 ? '#ff0000' : 
                                        result.risk_score >= 50 ? '#ff3300' : 
                                        result.risk_score >= 25 ? '#ffcc00' : '#00ffff'
                      }}
                    ></div>
                  </div>
                </div>
              )}
            </div>
          )}
          
          {/* Domain Info */}
          {result.domain_info && (
            <div className="card" style={{ marginBottom: '20px' }}>
              <div 
                className="card-header" 
                style={{ cursor: 'pointer' }}
                onClick={() => toggleSection('domain_info')}
              >
                <h2 className="card-title">Domain Information</h2>
                {expandedSections.domain_info ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
              </div>
              
              {expandedSections.domain_info && (
                <div style={{ marginTop: '15px' }}>
                  <table className="table">
                    <tbody>
                      <tr>
                        <td><strong>Domain</strong></td>
                        <td>{result.domain_info.domain}</td>
                      </tr>
                      {result.domain_info.ip_addresses && (
                        <tr>
                          <td><strong>IP Addresses</strong></td>
                          <td>
                            {result.domain_info.ip_addresses.ipv4?.map((ip: string, i: number) => (
                              <div key={i}>{ip}</div>
                            ))}
                          </td>
                        </tr>
                      )}
                      {result.domain_info.hosting_info && (
                        <tr>
                          <td><strong>Hosting Provider</strong></td>
                          <td>
                            {result.domain_info.hosting_info.org || 'Unknown'}
                            {result.domain_info.hosting_info.cloud_provider && (
                              <span> ({result.domain_info.hosting_info.cloud_provider})</span>
                            )}
                          </td>
                        </tr>
                      )}
                      {result.domain_info.waf_cdn && (
                        <tr>
                          <td><strong>WAF/CDN</strong></td>
                          <td>
                            {result.domain_info.waf_cdn.detected ? (
                              <div>
                                Detected: {result.domain_info.waf_cdn.providers.join(', ')}
                              </div>
                            ) : (
                              <div>None detected</div>
                            )}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
          
          {/* Subdomains */}
          {result.subdomains && (
            <div className="card" style={{ marginBottom: '20px' }}>
              <div 
                className="card-header" 
                style={{ cursor: 'pointer' }}
                onClick={() => toggleSection('subdomains')}
              >
                <h2 className="card-title">Subdomains ({result.subdomains.count})</h2>
                {expandedSections.subdomains ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
              </div>
              
              {expandedSections.subdomains && result.subdomains.items.length > 0 && (
                <div style={{ marginTop: '15px', maxHeight: '300px', overflowY: 'auto' }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Subdomain</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.subdomains.items.map((subdomain: string, index: number) => (
                        <tr key={index}>
                          <td>{index + 1}</td>
                          <td>{subdomain}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              
              {expandedSections.subdomains && result.subdomains.items.length === 0 && (
                <div style={{ padding: '15px', textAlign: 'center' }}>
                  No subdomains discovered
                </div>
              )}
            </div>
          )}
          
          {/* Vulnerabilities */}
          {result.vulnerabilities && (
            <div className="card" style={{ marginBottom: '20px' }}>
              <div 
                className="card-header" 
                style={{ cursor: 'pointer' }}
                onClick={() => toggleSection('vulnerabilities')}
              >
                <h2 className="card-title">Vulnerabilities ({result.vulnerabilities.count})</h2>
                {expandedSections.vulnerabilities ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
              </div>
              
              {expandedSections.vulnerabilities && result.vulnerabilities.items.length > 0 && (
                <div style={{ marginTop: '15px' }}>
                  {result.vulnerabilities.items.map((vuln: any, index: number) => (
                    <div key={index} className={`vulnerability-item ${vuln.severity}`}>
                      <div className="vulnerability-header">
                        <div className="vulnerability-title">{vuln.name}</div>
                        <div>
                          <span className={`badge badge-${
                            vuln.severity === 'critical' || vuln.severity === 'high' ? 'danger' : 
                            vuln.severity === 'medium' ? 'warning' : 'info'
                          }`}>
                            {vuln.severity}
                          </span>
                        </div>
                      </div>
                      <div>{vuln.description}</div>
                      {vuln.url && (
                        <div className="vulnerability-details">
                          <strong>URL:</strong> {vuln.url}
                        </div>
                      )}
                      {vuln.remediation && (
                        <div className="vulnerability-details">
                          <strong>Remediation:</strong> {vuln.remediation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              
              {expandedSections.vulnerabilities && result.vulnerabilities.items.length === 0 && (
                <div style={{ padding: '15px', textAlign: 'center' }}>
                  No vulnerabilities detected
                </div>
              )}
            </div>
          )}
          
          {/* Recommendations */}
          {result.recommendations && (
            <div className="card" style={{ marginBottom: '20px' }}>
              <div 
                className="card-header" 
                style={{ cursor: 'pointer' }}
                onClick={() => toggleSection('recommendations')}
              >
                <h2 className="card-title">Recommendations</h2>
                {expandedSections.recommendations ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
              </div>
              
              {expandedSections.recommendations && result.recommendations.length > 0 && (
                <div style={{ marginTop: '15px' }}>
                  {result.recommendations.map((rec: any, index: number) => (
                    <div key={index} className={`vulnerability-item ${rec.severity}`} style={{ marginBottom: '15px' }}>
                      <div className="vulnerability-header">
                        <div className="vulnerability-title">{rec.title}</div>
                        <div>
                          <span className={`badge badge-${
                            rec.severity === 'critical' || rec.severity === 'high' ? 'danger' : 
                            rec.severity === 'medium' ? 'warning' : 'info'
                          }`}>
                            {rec.severity}
                          </span>
                        </div>
                      </div>
                      <div>{rec.description}</div>
                      {rec.remediation && (
                        <div className="vulnerability-details">
                          <strong>Remediation:</strong> {rec.remediation}
                        </div>
                      )}
                      {rec.affected_urls && rec.affected_urls.length > 0 && (
                        <div className="vulnerability-details">
                          <strong>Affected URLs:</strong>
                          <ul style={{ marginTop: '5px', paddingLeft: '20px' }}>
                            {rec.affected_urls.map((url: string, i: number) => (
                              <li key={i}>{url}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              
              {expandedSections.recommendations && result.recommendations.length === 0 && (
                <div style={{ padding: '15px', textAlign: 'center' }}>
                  No recommendations available
                </div>
              )}
            </div>
          )}
          
          {/* Raw JSON */}
          <div className="card">
            <div 
              className="card-header" 
              style={{ cursor: 'pointer' }}
              onClick={() => toggleSection('raw_json')}
            >
              <h2 className="card-title">Raw JSON Data</h2>
              {expandedSections.raw_json ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
            </div>
            
            {expandedSections.raw_json && (
              <div style={{ marginTop: '15px' }}>
                <JsonViewer data={result} />
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default ScanResults;