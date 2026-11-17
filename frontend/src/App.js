import React, { useState, useEffect } from "react";

export default function App() {
  const [activeTab, setActiveTab] = useState("scan");
  const [ingestionMode, setIngestionMode] = useState("archive");
  const [projectId, setProjectId] = useState("frontend-demo-proj");
  const [targetInput, setTargetInput] = useState("");
  const [jobs, setJobs] = useState([
    {
      job_id: "job-demo-9921",
      project_id: "payment-service",
      status: "COMPLETED",
      grade: "A+",
      score: 0,
      timestamp: "Just now",
      findingsCount: 0
    },
    {
      job_id: "job-demo-8412",
      project_id: "auth-gateway",
      status: "COMPLETED",
      grade: "B",
      score: 25,
      timestamp: "10 mins ago",
      findingsCount: 1
    }
  ]);
  const [systemHealth, setSystemHealth] = useState({
    gateway: "ONLINE",
    backend: "CONNECTED",
    database: "MONGODB 7.0",
    vault: "ACTIVE (KV-v2)"
  });

  const [findings, setFindings] = useState([
    {
      rule_id: "SEC-AWS-001",
      severity: "critical",
      file_path: "config/secrets.py",
      line: 42,
      raw_secret: "AKIA****************",
      description: "AWS Access Key ID detected (Redacted)"
    },
    {
      rule_id: "CONT-ROOT-001",
      severity: "high",
      file_path: "Dockerfile",
      line: 1,
      raw_secret: "N/A",
      description: "Container runs as default root user without non-root USER instruction"
    }
  ]);

  const handleStartScan = (e) => {
    e.preventDefault();
    const newJobId = "job-" + Math.random().toString(36).substring(2, 9);
    const newJob = {
      job_id: newJobId,
      project_id: projectId,
      status: "SCANNING",
      grade: "...",
      score: 0,
      timestamp: "Running...",
      findingsCount: 0
    };
    setJobs([newJob, ...jobs]);

    // Simulate async lifecycle progression
    setTimeout(() => {
      setJobs(prev => prev.map(j => j.job_id === newJobId ? { ...j, status: "SCORING" } : j));
    }, 1500);

    setTimeout(() => {
      setJobs(prev => prev.map(j => j.job_id === newJobId ? { ...j, status: "COMPLETED", grade: "A", score: 8, timestamp: "Completed just now" } : j));
    }, 3000);
  };

  return (
    <div className="app-container">
      {/* Top Navigation */}
      <header className="navbar">
        <div className="nav-brand">
          <span className="logo-icon">🛡️</span>
          <div>
            <h1 className="brand-title">Secret Leak Guard <span className="version-pill">v2.0</span></h1>
            <p className="brand-subtitle">Automated Security Analysis & Secrets Guarding Gateway</p>
          </div>
        </div>

        <div className="system-status-pills">
          <div className="status-pill online">
            <span className="dot"></span> Nginx 1.27.5 (:80)
          </div>
          <div className="status-pill online">
            <span className="dot"></span> Backend API (:5000)
          </div>
          <div className="status-pill online">
            <span className="dot"></span> Mongo 7.0 (:27017)
          </div>
          <div className="status-pill online">
            <span className="dot"></span> Vault 1.15.6 (:8200)
          </div>
        </div>
      </header>

      {/* Main Grid Content */}
      <main className="dashboard-grid">
        {/* Left Column: Ingestion & Scan Form */}
        <section className="card card-scan">
          <h2 className="card-title">New Scan Ingestion</h2>
          <p className="card-desc">Execute multi-engine static analysis across 4 secure ingestion modes.</p>

          <form onSubmit={handleStartScan} className="scan-form">
            <div className="form-group">
              <label>Project Identifier</label>
              <input 
                type="text" 
                value={projectId} 
                onChange={(e) => setProjectId(e.target.value)} 
                required 
                className="input-text"
              />
            </div>

            <div className="form-group">
              <label>Ingestion Mode</label>
              <div className="mode-selector">
                {["archive", "local", "git", "dockerfile"].map(mode => (
                  <button 
                    key={mode} 
                    type="button" 
                    className={`mode-btn ${ingestionMode === mode ? "active" : ""}`}
                    onClick={() => setIngestionMode(mode)}
                  >
                    {mode.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {ingestionMode === "archive" && (
              <div className="form-group upload-box">
                <input type="file" id="archive-upload" className="file-input" />
                <label htmlFor="archive-upload" className="file-label">
                  📁 Click or Drag <code>.zip</code>, <code>.tar.gz</code>, or <code>.tgz</code> archive
                  <span className="subtext">Protected by Zip-Slip Canonical Path Traversal Defense (Up to 1000MB)</span>
                </label>
              </div>
            )}

            {ingestionMode === "git" && (
              <div className="form-group">
                <label>Git Repository URL (HTTPS)</label>
                <input 
                  type="url" 
                  placeholder="https://github.com/org/repo.git"
                  value={targetInput} 
                  onChange={(e) => setTargetInput(e.target.value)} 
                  className="input-text"
                />
                <span className="help-text">🔒 SSRF Protected: Private IPs, loopbacks & metadata IP ranges strictly blocked.</span>
              </div>
            )}

            {ingestionMode === "local" && (
              <div className="form-group">
                <label>Local Filesystem Directory</label>
                <input 
                  type="text" 
                  placeholder="/tmp/scanner_workspaces/project_src"
                  value={targetInput} 
                  onChange={(e) => setTargetInput(e.target.value)} 
                  className="input-text"
                />
                <span className="help-text">Validated against allowed scan directory whitelist.</span>
              </div>
            )}

            {ingestionMode === "dockerfile" && (
              <div className="form-group">
                <label>Dockerfile Content</label>
                <textarea 
                  rows={5} 
                  placeholder="FROM python:3.12-slim&#10;USER appuser&#10;CMD ['python', 'app.py']"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  className="input-textarea"
                />
              </div>
            )}

            <div className="engines-preview">
              <span className="badge engine">SecretEngine</span>
              <span className="badge engine">SASTEngine</span>
              <span className="badge engine">SCAEngine</span>
              <span className="badge engine">ContainerEngine</span>
            </div>

            <button type="submit" className="btn-primary">
              🚀 Launch Parallel Scan
            </button>
          </form>
        </section>

        {/* Right Column: Active Jobs & Security Findings */}
        <section className="dashboard-right">
          {/* Active Jobs Card */}
          <div className="card">
            <div className="card-header-flex">
              <h2 className="card-title">Recent Scan Jobs</h2>
              <span className="counter-pill">{jobs.length} Jobs</span>
            </div>

            <div className="jobs-table-container">
              <table className="custom-table">
                <thead>
                  <tr>
                    <th>Job ID</th>
                    <th>Project</th>
                    <th>Status</th>
                    <th>Grade</th>
                    <th>Score</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map(job => (
                    <tr key={job.job_id}>
                      <td><code className="code-pill">{job.job_id}</code></td>
                      <td><strong>{job.project_id}</strong></td>
                      <td>
                        <span className={`status-badge ${job.status.toLowerCase()}`}>
                          {job.status}
                        </span>
                      </td>
                      <td>
                        <span className={`grade-pill grade-${job.grade.replace("+", "plus")}`}>
                          {job.grade}
                        </span>
                      </td>
                      <td>{job.score}/100</td>
                      <td><span className="time-text">{job.timestamp}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Redacted Findings Card */}
          <div className="card">
            <div className="card-header-flex">
              <h2 className="card-title">Latest Security Findings (Strict Redaction)</h2>
              <span className="subtext">Raw credentials redacted across all boundaries</span>
            </div>

            <div className="findings-list">
              {findings.map((f, i) => (
                <div key={i} className="finding-item">
                  <div className="finding-header">
                    <span className={`severity-tag ${f.severity}`}>{f.severity.toUpperCase()}</span>
                    <span className="rule-tag">{f.rule_id}</span>
                    <span className="file-tag">{f.file_path}:{f.line}</span>
                  </div>
                  <p className="finding-desc">{f.description}</p>
                  <div className="redacted-box">
                    <span className="label">Preserved (First 4 Chars):</span>
                    <code className="secret-code">{f.raw_secret}</code>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="footer">
        <p>Secret Leak Guard v2.0 &bull; Unified Gateway Nginx 1.27.5 &bull; MongoDB 7.0 &bull; HashiCorp Vault 1.15.6</p>
      </footer>
    </div>
  );
}
