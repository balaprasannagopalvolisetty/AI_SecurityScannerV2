// src/components/Dashboard.tsx

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { BarChart2, Shield, AlertTriangle, Check, Clock, Search } from 'react-feather';
import MatrixEffect from './MatrixEffect';
import { fetchScans } from '../services/api';

interface Scan {
  id: string;
  url: string;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  timestamp: string;
  vulnerabilities?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

const Dashboard: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    totalScans: 0,
    completedScans: 0,
    pendingScans: 0,
    failedScans: 0,
    totalVulnerabilities: 0,
    criticalVulnerabilities: 0,
    highVulnerabilities: 0
  });

  useEffect(() => {
    const loadScans = async () => {
      try {
        setLoading(true);
        const data = await fetchScans();
        setScans(data);
        
        // Calculate stats
        const completed = data.filter((scan: Scan) => scan.status === 'completed').length;
        const pending = data.filter((scan: Scan) => scan.status === 'pending' || scan.status === 'scanning').length;
        const failed = data.filter((scan: Scan) => scan.status === 'failed').length;
        
        let totalVulns = 0;
        let criticalVulns = 0;
        let highVulns = 0;
        
        data.forEach((scan: Scan) => {
          if (scan.vulnerabilities) {
            totalVulns += scan.vulnerabilities.critical + 
                         scan.vulnerabilities.high + 
                         scan.vulnerabilities.medium + 
                         scan.vulnerabilities.low + 
                         scan.vulnerabilities.info;
            criticalVulns += scan.vulnerabilities.critical;
            highVulns += scan.vulnerabilities.high;
          }
        });
        
        setStats({
          totalScans: data.length,
          completedScans: completed,
          pendingScans: pending,
          failedScans: failed,
          totalVulnerabilities: totalVulns,
          criticalVulnerabilities: criticalVulns,
          highVulnerabilities: highVulns
        });
        
        setLoading(false);
      } catch (error) {
        console.error('Error loading scans:', error);
        setLoading(false);
      }
    };
    
    loadScans();
    
    // Simulate real-time updates
    const interval = setInterval(() => {
      loadScans();
    }, 10000);
    
    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <Check size={16} color="#00ff33" />;
      case 'pending':
        return <Clock size={16} color="#ffcc00" />;
      case 'scanning':
        return <Search size={16} color="#00ffff" />;
      case 'failed':
        return <AlertTriangle size={16} color="#ff0000" />;
      default:
        return <Clock size={16} color="#ffcc00" />;
    }
  };

  return (
    <div className="dashboard">
      <MatrixEffect />
      
      {/* Stats Cards */}
      <div className="grid">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Total Scans</h2>
            <BarChart2 size={20} />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>
            {loading ? <div className="loader"></div> : stats.totalScans}
          </div>
          <div style={{ marginTop: '10px', fontSize: '0.9rem' }}>
            <span style={{ color: '#00ff33', marginRight: '10px' }}>
              {stats.completedScans} completed
            </span>
            <span style={{ color: '#ffcc00', marginRight: '10px' }}>
              {stats.pendingScans} pending
            </span>
            <span style={{ color: '#ff0000' }}>
              {stats.failedScans} failed
            </span>
          </div>
        </div>
        
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Vulnerabilities</h2>
            <Shield size={20} />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>
            {loading ? <div className="loader"></div> : stats.totalVulnerabilities}
          </div>
          <div style={{ marginTop: '10px', fontSize: '0.9rem' }}>
            <span style={{ color: '#ff0000', marginRight: '10px' }}>
              {stats.criticalVulnerabilities} critical
            </span>
            <span style={{ color: '#ff3300' }}>
              {stats.highVulnerabilities} high
            </span>
          </div>
        </div>
        
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Quick Actions</h2>
          </div>
          <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
            <Link to="/scan" className="btn btn-primary">New Scan</Link>
            <Link to="/" className="btn btn-secondary">Terminal</Link>
          </div>
        </div>
      </div>
      
      {/* Recent Scans */}
      <div className="card" style={{ marginTop: '20px' }}>
        <div className="card-header">
          <h2 className="card-title">Recent Scans</h2>
        </div>
        
        {loading ? (
          <div style={{ textAlign: 'center', padding: '20px' }}>
            <div className="loader"></div>
            <p style={{ marginTop: '10px' }}>Loading scans...</p>
          </div>
        ) : scans.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '20px' }}>
            <p>No scans found. Start a new scan to see results here.</p>
            <Link to="/scan" className="btn btn-primary" style={{ marginTop: '10px' }}>
              Start New Scan
            </Link>
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>URL</th>
                <th>Status</th>
                <th>Timestamp</th>
                <th>Vulnerabilities</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan: Scan) => (
                <tr key={scan.id}>
                  <td>{scan.id}</td>
                  <td>{scan.url}</td>
                  <td>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                      {getStatusIcon(scan.status)}
                      {scan.status}
                    </span>
                  </td>
                  <td>{new Date(scan.timestamp).toLocaleString()}</td>
                  <td>
                    {scan.vulnerabilities ? (
                      <div style={{ display: 'flex', gap: '5px' }}>
                        {scan.vulnerabilities.critical > 0 && (
                          <span className="badge badge-danger">
                            {scan.vulnerabilities.critical} critical
                          </span>
                        )}
                        {scan.vulnerabilities.high > 0 && (
                          <span className="badge badge-danger">
                            {scan.vulnerabilities.high} high
                          </span>
                        )}
                        {scan.vulnerabilities.medium > 0 && (
                          <span className="badge badge-warning">
                            {scan.vulnerabilities.medium} medium
                          </span>
                        )}
                      </div>
                    ) : (
                      <span>-</span>
                    )}
                  </td>
                  <td>
                    <Link to={`/results/${scan.id}`} className="btn btn-secondary" style={{ padding: '5px 10px', fontSize: '12px' }}>
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default Dashboard;