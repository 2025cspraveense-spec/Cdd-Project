import React, { useEffect, useMemo, useState } from "react";

const API_ROOT = "/api/v1";
const ACTIVE_STATUSES = new Set(["PENDING", "INGESTING", "SCANNING", "SCORING"]);
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const INGESTION_MODES = [
  { id: "archive", label: "Upload archive", icon: "↥" },
  { id: "local", label: "Local path", icon: "⌂" },
  { id: "git", label: "Git URL", icon: "⑂" },
  { id: "dockerfile", label: "Dockerfile", icon: "▤" },
];
const ENGINE_FILTERS = [
  { id: "all", label: "All findings" },
  { id: "SecretEngine", label: "Secrets" },
  { id: "SASTEngine", label: "SAST" },
  { id: "SCAEngine", label: "SCA" },
  { id: "ContainerEngine", label: "Container" },
];

function safeText(value) {
  if (typeof value !== "string") return value;
  return value
    .replace(/-----BEGIN [A-Z0-9 _-]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 _-]*PRIVATE KEY-----/g, "[REDACTED PRIVATE KEY]")
    .replace(/\b(AKIA[0-9A-Z]{16})\b/g, (secret) => `${secret.slice(0, 4)}${"*".repeat(secret.length - 4)}`)
    .replace(/\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|xox[baprs]-[0-9A-Za-z]{10,48})\b/g, (secret) => `${secret.slice(0, 4)}${"*".repeat(secret.length - 4)}`)
    .replace(/\bbearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*/gi, "Bearer [REDACTED]")
    .replace(/(["']?\b(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|aws[_-]?secret[_-]?access[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|credential)s?["']?\s*[:=]\s*)(["'])((?:\\.|[^\\'"\r\n])*)\2/gi, (match, prefix, quote, secret) => `${prefix}${quote}${secret.slice(0, 4)}${"*".repeat(Math.max(0, secret.length - 4))}${quote}`)
    .replace(/(["']?\b(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|aws[_-]?secret[_-]?access[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|credential)s?["']?\s*[:=]\s*)(?!["'])([^\s,;]+)/gi, (match, prefix, secret) => `${prefix}${secret.slice(0, 4)}${"*".repeat(Math.max(0, secret.length - 4))}`);
}

async function apiRequest(path, token, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData) && typeof options.body !== "string") {
    headers.set("Content-Type", "application/json");
    options.body = JSON.stringify(options.body);
  }
  const response = await fetch(`${API_ROOT}${path}`, { ...options, headers });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    const body = await response.text();
    if (body) {
      try {
        const parsed = JSON.parse(body);
        message = parsed.message || parsed.error || message;
      } catch {
        message = body;
      }
    }
    throw new Error(safeText(message));
  }
  return response;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function severityCounts(findings) {
  return findings.reduce((counts, finding) => {
    const severity = String(finding.severity || "info").toLowerCase();
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, {});
}

function Login({ onLogin, onRegister, onClearError, busy, error }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [formError, setFormError] = useState("");
  const [success, setSuccess] = useState("");

  function submit(event) {
    event.preventDefault();
    setFormError("");
    setSuccess("");
    if (mode === "register") {
      if (password !== confirmPassword) {
        setFormError("Passwords do not match.");
        return;
      }
      onRegister(username, password, () => {
        setMode("login");
        setPassword("");
        setConfirmPassword("");
        setSuccess("Account created. Sign in with your new credentials.");
      });
      return;
    }
    onLogin(username, password, () => setPassword(""));
  }

  function changeMode(nextMode) {
    setMode(nextMode);
    setPassword("");
    setConfirmPassword("");
    setFormError("");
    setSuccess("");
    onClearError();
  }

  return (
    <main className="login-shell grid min-h-screen place-items-center p-5">
      <section className="login-card glass-panel w-full max-w-[420px] rounded-2xl">
        <div className="brand-mark text-slg-cyan">◈</div>
        <p className="eyebrow">SECURITY OPERATIONS</p>
        <h1>Secret Leak Guard</h1>
        <p className="muted">{mode === "login" ? "Sign in to review scans, risk posture, and remediation reports." : "Create an analyst account to start reviewing security scans."}</p>
        {error && <div className="notice error-notice mb-4 flex items-center justify-between gap-4 rounded-lg border p-3 text-sm" role="alert">{error}</div>}
        {formError && <div className="notice error-notice mb-4 flex items-center justify-between gap-4 rounded-lg border p-3 text-sm" role="alert">{formError}</div>}
        {success && <div className="mb-4 rounded-lg border border-emerald-400/20 bg-emerald-400/5 p-3 text-sm text-emerald-200" role="status">{success}</div>}
        <form className="login-form grid gap-2" onSubmit={submit}>
          <label htmlFor="username">Username</label>
          <input className="w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-400" id="username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required />
          <label htmlFor="password">{mode === "login" ? "Password" : "Create password"}</label>
          <input className="w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-400" id="password" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} minLength={mode === "register" ? 8 : undefined} maxLength={72} value={password} onChange={(event) => setPassword(event.target.value)} required />
          {mode === "register" && <>
            <label htmlFor="confirm-password">Confirm password</label>
            <input className="w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-400" id="confirm-password" type="password" autoComplete="new-password" minLength={8} maxLength={72} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required />
            <p className="text-xs text-slate-400">New accounts receive the analyst role. Admin accounts must be provisioned separately.</p>
          </>}
          <button className="button primary-button mt-3 min-h-10 rounded-md focus-visible:ring-2 focus-visible:ring-cyan-300" type="submit" disabled={busy}>{busy ? (mode === "login" ? "Signing in…" : "Creating account…") : (mode === "login" ? "Sign in securely" : "Create account")}</button>
        </form>
        <p className="mt-4 text-center text-sm text-slate-400">
          {mode === "login" ? "Don't have an account?" : "Already have an account?"}{" "}
          <button className="font-semibold text-cyan-300 hover:text-cyan-200" type="button" onClick={() => changeMode(mode === "login" ? "register" : "login")}>
            {mode === "login" ? "Create account" : "Sign in"}
          </button>
        </p>
        <p className="login-footnote">Credentials are sent only to the configured Flask API.</p>
      </section>
    </main>
  );
}

export default function App() {
  const [token, setToken] = useState(() => window.sessionStorage.getItem("slg_access_token") || "");
  const [user, setUser] = useState(null);
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [apiError, setApiError] = useState("");
  const [health, setHealth] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [selectedJobId, setSelectedJobId] = useState("");
  const [scanResults, setScanResults] = useState(null);
  const [history, setHistory] = useState([]);
  const [projectId, setProjectId] = useState("demo-project");
  const [mode, setMode] = useState("archive");
  const [target, setTarget] = useState("");
  const [archive, setArchive] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [reportBusy, setReportBusy] = useState("");
  const [engineFilter, setEngineFilter] = useState("all");

  const selectedJob = jobs.find((job) => job.job_id === selectedJobId);
  const findings = scanResults?.findings || [];
  const counts = useMemo(() => {
    const summary = scanResults?.scores?.severity_counts;
    return summary || severityCounts(findings);
  }, [findings, scanResults]);
  const totalFindings = scanResults?.scores?.unique_findings ?? findings.length;
  const activeFindings = engineFilter === "all"
    ? findings
    : findings.filter((finding) => finding.engine_name === engineFilter);

  useEffect(() => {
    let cancelled = false;
    fetch(`${API_ROOT}/health`)
      .then(async (response) => {
        if (!response.ok) throw new Error("Health check unavailable");
        return response.json();
      })
      .then((data) => { if (!cancelled) setHealth(data); })
      .catch(() => { if (!cancelled) setHealth({ status: "unavailable" }); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (token) window.sessionStorage.setItem("slg_access_token", token);
    else window.sessionStorage.removeItem("slg_access_token");
  }, [token]);

  useEffect(() => {
    if (!token) {
      setUser(null);
      return undefined;
    }
    let cancelled = false;
    apiRequest("/auth/me", token)
      .then((response) => response.json())
      .then((data) => { if (!cancelled) setUser(data.user); })
      .catch((error) => { if (!cancelled) setApiError(error.message); });
    return () => { cancelled = true; };
  }, [token]);

  useEffect(() => {
    if (!token) {
      setJobs([]);
      setScanResults(null);
      setHistory([]);
      return undefined;
    }
    let cancelled = false;
    const refresh = async () => {
      try {
        const response = await apiRequest("/scans?limit=30", token);
        const data = await response.json();
        if (!cancelled) {
          setJobs(data.scans || []);
          setSelectedJobId((current) => current || data.scans?.[0]?.job_id || "");
          setApiError("");
        }
      } catch (error) {
        if (!cancelled) setApiError(error.message);
      }
    };
    refresh();
    const timer = window.setInterval(refresh, 10000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [token]);

  const activeJobIds = selectedJob && ACTIVE_STATUSES.has(selectedJob.status) ? selectedJob.job_id : "";
  useEffect(() => {
    if (!token || !activeJobIds) return undefined;
    let cancelled = false;
    const poll = async () => {
      const ids = activeJobIds.split(",");
      const updates = await Promise.all(ids.map(async (jobId) => {
        try {
          const response = await apiRequest(`/scans/${encodeURIComponent(jobId)}/status`, token);
          return await response.json();
        } catch (error) {
          if (!cancelled) setApiError(error.message);
          return null;
        }
      }));
      if (cancelled) return;
      setJobs((current) => current.map((job) => {
        const update = updates.find((item) => item?.job_id === job.job_id);
        return update ? { ...job, ...update } : job;
      }));
    };
    poll();
    const timer = window.setInterval(poll, 1800);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [activeJobIds, token]);

  useEffect(() => {
    if (!token || !selectedJobId || selectedJob?.status !== "COMPLETED") {
      if (selectedJob?.status !== "COMPLETED") setScanResults(null);
      return undefined;
    }
    let cancelled = false;
    apiRequest(`/scans/${encodeURIComponent(selectedJobId)}/results`, token)
      .then((response) => response.json())
      .then((data) => { if (!cancelled) setScanResults(data); })
      .catch((error) => { if (!cancelled) setApiError(error.message); });
    return () => { cancelled = true; };
  }, [selectedJobId, selectedJob?.status, token]);

  useEffect(() => {
    if (!token || !projectId.trim()) {
      setHistory([]);
      return undefined;
    }
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      try {
        const response = await apiRequest(`/projects/${encodeURIComponent(projectId.trim())}/metrics?limit=20`, token);
        const data = await response.json();
        if (!cancelled) setHistory(data.history || []);
      } catch (error) {
        if (!cancelled) setApiError(error.message);
      }
    }, 350);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [projectId, token]);

  async function handleLogin(username, password, clearPassword) {
    setLoginBusy(true);
    setLoginError("");
    try {
      const response = await apiRequest("/auth/login", "", { method: "POST", body: { username, password } });
      const data = await response.json();
      setToken(data.access_token);
      setUser(data.user);
      setApiError("");
      clearPassword();
    } catch (error) {
      setLoginError(error.message);
    } finally {
      setLoginBusy(false);
    }
  }

  async function handleRegister(username, password, onSuccess) {
    setLoginBusy(true);
    setLoginError("");
    try {
      await apiRequest("/auth/register", "", { method: "POST", body: { username, password } });
      onSuccess();
    } catch (error) {
      setLoginError(error.message);
    } finally {
      setLoginBusy(false);
    }
  }

  async function handleLogout() {
    setToken("");
    setUser(null);
    setJobs([]);
    setScanResults(null);
    setSelectedJobId("");
    setApiError("");
  }

  async function handleStartScan(event) {
    event.preventDefault();
    setSubmitting(true);
    setApiError("");
    try {
      if (!projectId.trim()) throw new Error("Enter a project identifier.");
      let body;
      let headers;
      if (mode === "archive") {
        if (!archive) throw new Error("Choose an archive file before starting the scan.");
        body = new FormData();
        body.append("ingestion_mode", mode);
        body.append("project_id", projectId.trim());
        body.append("file", archive);
      } else {
        if (!target.trim()) throw new Error("Enter a target before starting the scan.");
        body = { ingestion_mode: mode, project_id: projectId.trim() };
        if (mode === "dockerfile") body.dockerfile_content = target;
        else body.target = target.trim();
        headers = { "Content-Type": "application/json" };
      }
      const response = await apiRequest("/scans", token, { method: "POST", headers, body });
      const data = await response.json();
      const job = {
        job_id: data.job_id,
        project_id: data.project_id,
        status: data.scan_status || "PENDING",
        grade: null,
        scores: {},
        created_at: new Date().toISOString(),
        progress: { percentage: 0, message: "Scan queued." },
      };
      setJobs((current) => [job, ...current.filter((item) => item.job_id !== job.job_id)]);
      setSelectedJobId(job.job_id);
      setScanResults(null);
      if (mode === "archive") setArchive(null);
      setTarget("");
    } catch (error) {
      setApiError(error.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function downloadReport(format) {
    if (!selectedJobId) return;
    setReportBusy(format);
    setApiError("");
    try {
      const response = await apiRequest(`/scans/${encodeURIComponent(selectedJobId)}/reports/${format}`, token);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `security-report-${selectedJobId}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setApiError(error.message);
    } finally {
      setReportBusy("");
    }
  }

  if (!token) return <Login onLogin={handleLogin} onRegister={handleRegister} onClearError={() => setLoginError("")} busy={loginBusy} error={loginError} />;

  const score = Math.max(0, Math.min(100, Number(scanResults?.scores?.final_score || 0)));
  const historyPoints = [...history].reverse();
  const latestJobProgress = Number(selectedJob?.progress?.percentage || (selectedJob?.status === "COMPLETED" ? 100 : 0));

  return (
    <div className="app-shell min-h-screen">
      <header className="topbar sticky top-0 z-10 flex items-center justify-between">
        <a className="brand flex items-center gap-3 text-inherit no-underline" href="/" aria-label="Secret Leak Guard home">
          <span className="brand-mark">◈</span>
          <span><strong>Secret Leak Guard</strong><small>Application Security Center</small></span>
        </a>
        <div className="topbar-right">
          <div className={`connection-chip ${health?.status === "healthy" ? "connected" : "disconnected"}`}>
            <span className="status-dot" />
            API {health?.status === "healthy" ? "CONNECTED" : "UNAVAILABLE"}
          </div>
          <div className="user-chip"><span className="avatar">{(user?.username || "U").slice(0, 1).toUpperCase()}</span><span>{user?.username || "Signed in"}</span></div>
          <button className="button quiet-button rounded-md border px-3 py-2 transition-colors hover:border-cyan-300" type="button" onClick={handleLogout}>Sign out</button>
        </div>
      </header>

      <main className="workspace mx-auto w-full max-w-screen-2xl px-4 py-8 md:px-8">
        <div className="page-heading flex flex-wrap items-end justify-between gap-6">
          <div><p className="eyebrow">OVERVIEW / SECURITY POSTURE</p><h1>Unified security dashboard</h1><p className="muted">Scan, prioritize, and remediate risk across your codebase.</p></div>
          <div className="system-summary"><span><i className="status-dot" /> Flask API</span><span><i className="status-dot" /> {health?.database?.status || "Database"}</span><span><i className="status-dot" /> Vault {health?.vault?.status || "status"}</span></div>
        </div>

        {apiError && <div className="notice error-notice mb-4 flex items-center justify-between gap-4 rounded-lg border p-3 text-sm" role="alert"><span>{apiError}</span><button type="button" aria-label="Dismiss error" onClick={() => setApiError("")}>×</button></div>}

        <section className="stats-grid grid grid-cols-2 gap-3 xl:grid-cols-4" aria-label="Security summary">
          <article className="stat-card glass-panel flex min-h-28 items-center gap-4 rounded-xl p-4"><span className="stat-icon cyan">⌁</span><div><span className="stat-label">Total findings</span><strong>{totalFindings}</strong><small>{selectedJob ? "Selected scan" : "No completed scan selected"}</small></div></article>
          <article className="stat-card glass-panel flex min-h-28 items-center gap-4 rounded-xl p-4"><span className="stat-icon red">!</span><div><span className="stat-label">Critical</span><strong>{counts.critical || 0}</strong><small>Immediate attention</small></div></article>
          <article className="stat-card glass-panel flex min-h-28 items-center gap-4 rounded-xl p-4"><span className="stat-icon orange">↗</span><div><span className="stat-label">High severity</span><strong>{counts.high || 0}</strong><small>Prioritize remediation</small></div></article>
          <article className="stat-card glass-panel score-stat flex min-h-28 items-center gap-3 rounded-xl p-4"><div className="score-orb" style={{ "--score": `${score * 3.6}deg` }}><span>{score}</span></div><div><span className="stat-label">Risk score</span><strong className="grade-value">{scanResults?.grade || "—"}</strong><small>0–100 · lower is better</small></div></article>
        </section>

        <section className="main-grid grid grid-cols-1 gap-4 xl:grid-cols-[minmax(330px,0.92fr)_minmax(0,1.58fr)]">
          <article className="panel glass-panel scan-panel min-w-0 rounded-xl p-5">
            <div className="section-title"><div><p className="eyebrow">NEW ASSESSMENT</p><h2>Ingest a project</h2></div><span className="engine-count">4 engines enabled</span></div>
            <p className="muted panel-intro">Choose a source. Each scan runs secrets, SAST, dependency, and container checks.</p>
            <div className="mode-tabs" role="tablist" aria-label="Project ingestion method">
              {INGESTION_MODES.map((item) => <button key={item.id} type="button" role="tab" aria-selected={mode === item.id} className={mode === item.id ? "mode-tab active" : "mode-tab"} onClick={() => { setMode(item.id); setTarget(""); setArchive(null); }}><span>{item.icon}</span>{item.label}</button>)}
            </div>
            <form className="scan-form" onSubmit={handleStartScan}>
              <label htmlFor="project-id">Project identifier</label>
              <input className="w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-400" id="project-id" value={projectId} maxLength={120} required onChange={(event) => setProjectId(event.target.value)} placeholder="e.g. payments-api" />
              {mode === "archive" && <div className="upload-area">
                <input id="archive-file" className="visually-hidden" type="file" accept=".zip,.tar,.tar.gz,.tgz" onChange={(event) => setArchive(event.target.files?.[0] || null)} />
                <label htmlFor="archive-file" className="upload-label"><span className="upload-icon">↑</span><strong>{archive?.name || "Choose a project archive"}</strong><small>ZIP, TAR.GZ or TGZ · subject to server upload limit</small></label>
                <p>Archives are extracted in an isolated workspace with path traversal protection.</p>
              </div>}
              {mode === "local" && <div className="field-block"><label htmlFor="local-path">Local filesystem directory</label><input className="w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-400" id="local-path" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="/scan_targets/my-project" required /><small>Must be within a server-configured scan directory.</small></div>}
              {mode === "git" && <div className="field-block"><label htmlFor="git-url">Git repository HTTPS URL</label><input className="w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-400" id="git-url" type="url" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://github.com/org/repository.git" required /><small>Private, loopback, and metadata network addresses are blocked.</small></div>}
              {mode === "dockerfile" && <div className="field-block"><label htmlFor="dockerfile">Dockerfile contents</label><textarea className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 font-mono text-xs leading-6 text-slate-100 placeholder:text-slate-600 focus:border-cyan-400" id="dockerfile" rows={7} value={target} onChange={(event) => setTarget(event.target.value)} placeholder={"FROM python:3.12-slim\nUSER app\nCMD [\"python\", \"app.py\"]"} required /></div>}
              <div className="engine-list">{["Secrets", "SAST", "SCA", "Container"].map((engine) => <span key={engine}><i className="check-mark">✓</i>{engine}</span>)}</div>
              <button className="button primary-button launch-button" type="submit" disabled={submitting}>{submitting ? <><span className="spinner" /> Submitting scan…</> : "Start security scan"}<span aria-hidden="true">→</span></button>
            </form>
          </article>

          <div className="right-column">
            <article className="panel glass-panel jobs-panel">
              <div className="section-title"><div><p className="eyebrow">ACTIVITY</p><h2>Recent scans</h2></div><span className="count-chip">{jobs.length} jobs</span></div>
              {jobs.length === 0 ? <div className="empty-state"><span>⌁</span><strong>No scans yet</strong><p>Launch a scan to see progress and results here.</p></div> : <div className="jobs-list">
                {jobs.map((job) => {
                  const percentage = Math.max(0, Math.min(100, Number(job.progress?.percentage || (job.status === "COMPLETED" ? 100 : 0))));
                  return <button type="button" key={job.job_id} className={`job-row ${selectedJobId === job.job_id ? "selected" : ""}`} onClick={() => { setSelectedJobId(job.job_id); setProjectId(job.project_id || projectId); }}>
                    <span className={`job-state ${String(job.status).toLowerCase()}`}><i className="status-dot" />{job.status || "UNKNOWN"}</span>
                    <span className="job-info"><strong>{job.project_id || "Project"}</strong><small>{job.job_id} · {formatTime(job.created_at)}</small>
                      {ACTIVE_STATUSES.has(job.status) && <span className="progress-track"><span style={{ width: `${percentage}%` }} /></span>}
                    </span>
                    <span className="job-grade">{job.grade || (ACTIVE_STATUSES.has(job.status) ? `${percentage}%` : "—")}</span>
                  </button>;
                })}
              </div>}
            </article>

            <article className="panel glass-panel history-panel">
              <div className="section-title"><div><p className="eyebrow">TREND ANALYSIS</p><h2>Risk history</h2></div><span className="muted small-text">{projectId || "Current project"}</span></div>
              {historyPoints.length === 0 ? <div className="history-empty">Historical scores appear after the first completed scan.</div> : <div className="history-chart" role="img" aria-label="Historical risk scores">
                {historyPoints.map((point, index) => {
                  const value = Math.max(0, Math.min(100, Number(point.final_score || 0)));
                  return <div className="history-column" key={`${point.job_id || point.created_at}-${index}`} title={`${value}/100 · Grade ${point.grade || "—"}`}>
                    <div className="history-bar" style={{ height: `${Math.max(4, value)}%` }}><span>{value}</span></div>
                    <small>{point.grade || "—"}</small>
                  </div>;
                })}
              </div>}
              <div className="chart-caption"><span><i className="legend-dot" />Risk score · 0–100</span><span>{history.length} scans</span></div>
            </article>
          </div>
        </section>

        <section className="panel glass-panel results-panel min-w-0 overflow-hidden rounded-xl p-5">
          <div className="results-heading">
            <div><p className="eyebrow">ASSESSMENT DETAILS</p><h2>Findings & remediation</h2><p className="muted">{scanResults ? `${scanResults.project_id} · ${scanResults.scores?.unique_findings ?? findings.length} unique findings` : "Select a completed scan to review security findings."}</p></div>
            <div className="report-actions">
              {["pdf", "html", "json", "sarif"].map((format) => <button key={format} type="button" className="button export-button" disabled={!scanResults || !!reportBusy} onClick={() => downloadReport(format)}>{reportBusy === format ? <span className="spinner" /> : null}{format === "sarif" ? "SARIF" : format.toUpperCase()}</button>)}
            </div>
          </div>
          {selectedJob && ACTIVE_STATUSES.has(selectedJob.status) && <div className="scan-progress"><div className="progress-heading"><strong>Scan in progress</strong><span>{latestJobProgress}%</span></div><div className="progress-track large"><span style={{ width: `${latestJobProgress}%` }} /></div><p>{safeText(selectedJob.progress?.message || "Working through analysis engines…")}</p></div>}
          {selectedJob?.status === "FAILED" && <div className="notice error-notice">{safeText(selectedJob.error_message || "This scan failed. Check the target and try again.")}</div>}
          {scanResults && <>
            {Object.keys(scanResults.engine_errors || {}).length > 0 && <div className="notice error-notice" role="status">
              Partial scan: these engines did not complete: {Object.keys(scanResults.engine_errors).join(", ")}.
            </div>}
            <div className="severity-summary">
              {SEVERITIES.map((severity) => <div className="severity-metric" key={severity}><span className={`severity-dot ${severity}`} /><span>{severity}</span><strong>{counts[severity] || 0}</strong><div className="severity-track"><span className={severity} style={{ width: `${totalFindings ? ((counts[severity] || 0) / totalFindings) * 100 : 0}%` }} /></div></div>)}
            </div>
            <div className="finding-toolbar">
              <div className="filter-tabs" role="tablist" aria-label="Filter findings by engine">{ENGINE_FILTERS.map((filter) => <button type="button" role="tab" aria-selected={engineFilter === filter.id} key={filter.id} className={engineFilter === filter.id ? "filter-tab active" : "filter-tab"} onClick={() => setEngineFilter(filter.id)}>{filter.label}</button>)}</div>
              <span className="muted small-text">{activeFindings.length} shown</span>
            </div>
            <div className="findings-table-wrap">
              <table className="findings-table"><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Redacted evidence</th><th>Recommended remediation</th></tr></thead>
                <tbody>{activeFindings.map((finding, index) => <tr key={`${finding.fingerprint || finding.rule_id}-${index}`}>
                  <td><span className={`severity-pill ${String(finding.severity || "info").toLowerCase()}`}>{String(finding.severity || "info").toUpperCase()}</span></td>
                  <td><strong>{safeText(finding.description || finding.rule_id)}</strong><small>{finding.engine_name || finding.category || "Security"} · {finding.rule_id}</small></td>
                  <td><code>{safeText(finding.file_path || "—")}:{finding.line_number || 0}</code></td>
                  <td><code className="evidence">{safeText(finding.match_content || finding.raw_secret || "No code snippet")}</code></td>
                  <td>{safeText(finding.remediation || "Review and remediate this finding.")}</td>
                </tr>)}
                {!activeFindings.length && <tr><td className="no-findings" colSpan="5">{findings.length ? "No findings match this engine." : "No findings detected in this scan."}</td></tr>}
                </tbody></table>
            </div>
          </>}
        </section>
        <footer className="footer">Secret Leak Guard <span>·</span> Findings and exports are redacted before leaving the API.</footer>
      </main>
    </div>
  );
}
