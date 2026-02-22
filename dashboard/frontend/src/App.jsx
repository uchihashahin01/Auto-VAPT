import { useState, useEffect, useCallback } from 'react';
import { fetchStats, fetchScans, fetchScanDetail, startScan, deleteScan, connectWebSocket } from './api';
import './App.css';

/* ═══════════════════════════════════════════════════════════════
   Auto-VAPT Dashboard — Main App Component
   ═══════════════════════════════════════════════════════════════ */

function App() {
  const [view, setView] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [showNewScan, setShowNewScan] = useState(false);
  const [liveScan, setLiveScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [s, sc] = await Promise.all([fetchStats(), fetchScans()]);
      setStats(s);
      setScans(sc);
      setError(null);
    } catch (e) {
      setError('Cannot connect to Auto-VAPT API. Make sure the server is running.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => { const i = setInterval(refresh, 10000); return () => clearInterval(i); }, [refresh]);

  const handleStartScan = async (params) => {
    setShowNewScan(false);
    const result = await startScan(params);
    setLiveScan({ id: result.id, status: 'PENDING', target: params.target_url, events: [] });
    setView('scans');

    const ws = connectWebSocket(result.id, (msg) => {
      setLiveScan(prev => prev ? {
        ...prev,
        status: msg.status || prev.status,
        events: [...prev.events, msg],
        ...(msg.type === 'completed' ? { risk_score: msg.risk_score, total_vulns: msg.total_vulns } : {}),
      } : null);

      if (msg.type === 'completed' || msg.type === 'error') {
        setTimeout(() => { setLiveScan(null); refresh(); }, 2000);
      }
    });
  };

  const handleViewScan = async (scanId) => {
    const detail = await fetchScanDetail(scanId);
    setSelectedScan(detail);
    setView('detail');
  };

  const handleDeleteScan = async (scanId) => {
    await deleteScan(scanId);
    if (selectedScan?.id === scanId) { setSelectedScan(null); setView('scans'); }
    refresh();
  };

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh' }}>
      <div><div className="spinner" /><p style={{ color: 'var(--text-muted)' }}>Loading Auto-VAPT Dashboard...</p></div>
    </div>
  );

  return (
    <>
      <header className="app-header">
        <div className="logo"><span>🛡️</span><h1>Auto-VAPT</h1></div>
        <div className="nav-tabs">
          <button className={`nav-tab ${view === 'dashboard' ? 'active' : ''}`} onClick={() => setView('dashboard')}>Dashboard</button>
          <button className={`nav-tab ${view === 'scans' || view === 'detail' ? 'active' : ''}`} onClick={() => { setView('scans'); setSelectedScan(null); }}>Scans</button>
        </div>
        <div className="header-actions">
          <button className="btn btn-primary" onClick={() => setShowNewScan(true)}>⚡ New Scan</button>
        </div>
      </header>

      <div className="container">
        {error && <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid var(--danger)', borderRadius: 'var(--radius)', padding: '1rem', marginBottom: '1.5rem', color: 'var(--danger)', fontSize: '0.9rem' }}>⚠️ {error}</div>}

        {liveScan && <LiveScanProgress scan={liveScan} />}

        {view === 'dashboard' && <DashboardView stats={stats} scans={scans} onViewScan={handleViewScan} />}
        {view === 'scans' && <ScansView scans={scans} onViewScan={handleViewScan} onDeleteScan={handleDeleteScan} />}
        {view === 'detail' && selectedScan && <ScanDetailView scan={selectedScan} onBack={() => { setView('scans'); setSelectedScan(null); }} />}
      </div>

      {showNewScan && <NewScanModal onClose={() => setShowNewScan(false)} onSubmit={handleStartScan} />}
    </>
  );
}

/* ─── Dashboard View ─────────────────────────────────────────── */

function DashboardView({ stats, scans, onViewScan }) {
  if (!stats) return null;
  const sd = stats.severity_distribution || {};

  return (
    <>
      <div className="stats-grid">
        <div className="stat-card">
          <div className="label">Total Scans</div>
          <div className="value" style={{ color: 'var(--accent)' }}>{stats.total_scans}</div>
          <div className="sub">{stats.completed_scans} completed</div>
        </div>
        <div className="stat-card">
          <div className="label">Total Vulnerabilities</div>
          <div className="value" style={{ color: sd.CRITICAL > 0 ? 'var(--critical)' : 'var(--text-primary)' }}>{stats.total_vulnerabilities}</div>
          <div className="sub">{sd.CRITICAL || 0} critical, {sd.HIGH || 0} high</div>
        </div>
        <div className="stat-card">
          <div className="label">Avg Risk Score</div>
          <div className="value" style={{ color: stats.average_risk_score > 50 ? 'var(--critical)' : stats.average_risk_score > 20 ? 'var(--medium)' : 'var(--success)' }}>
            {stats.average_risk_score}/100
          </div>
          <div className="sub">across all scans</div>
        </div>
        <div className="stat-card">
          <div className="label">Security Posture</div>
          <div className="value" style={{ color: (sd.CRITICAL || 0) === 0 && (sd.HIGH || 0) === 0 ? 'var(--success)' : 'var(--danger)' }}>
            {(sd.CRITICAL || 0) === 0 && (sd.HIGH || 0) === 0 ? '✓ Good' : '⚠ At Risk'}
          </div>
          <div className="sub">{(sd.CRITICAL || 0) + (sd.HIGH || 0)} critical/high issues</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
        <div className="table-container">
          <div className="table-header"><h3>Severity Distribution</h3></div>
          <div style={{ padding: '1.5rem' }}>
            <SeverityBars distribution={sd} total={stats.total_vulnerabilities} />
          </div>
        </div>
        <div className="table-container">
          <div className="table-header"><h3>OWASP Categories</h3></div>
          <div style={{ padding: '1rem' }}>
            <div className="owasp-grid">
              {Object.entries(stats.owasp_distribution || {}).map(([cat, count]) => (
                <div key={cat} className="owasp-item">
                  <span style={{ fontSize: '0.78rem' }}>{cat.split(' - ')[1] || cat}</span>
                  <span className="count">{count}</span>
                </div>
              ))}
              {Object.keys(stats.owasp_distribution || {}).length === 0 && (
                <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', padding: '1rem' }}>No data yet</div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="section-header"><h2>Recent Scans</h2></div>
      <ScanTable scans={scans.slice(0, 10)} onViewScan={onViewScan} />
    </>
  );
}

/* ─── Severity Bar Chart ─────────────────────────────────────── */

function SeverityBars({ distribution, total }) {
  const sev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const colors = ['critical', 'high', 'medium', 'low', 'info'];
  const max = Math.max(...sev.map(s => distribution[s] || 0), 1);

  return (
    <div className="severity-bars">
      {sev.map((s, i) => {
        const count = distribution[s] || 0;
        const height = Math.max((count / max) * 100, 4);
        return (
          <div key={s} className="sev-bar-item">
            <div className={`sev-bar-count sev-${colors[i]}`}>{count}</div>
            <div className="sev-bar-wrapper">
              <div className={`sev-bar ${colors[i]}`} style={{ height: `${height}%` }} />
            </div>
            <div className="sev-bar-label">{s}</div>
          </div>
        );
      })}
    </div>
  );
}

/* ─── Scans View ─────────────────────────────────────────────── */

function ScansView({ scans, onViewScan, onDeleteScan }) {
  return (
    <>
      <div className="section-header">
        <h2>All Scans ({scans.length})</h2>
      </div>
      {scans.length > 0 ? (
        <ScanTable scans={scans} onViewScan={onViewScan} onDeleteScan={onDeleteScan} showActions />
      ) : (
        <div className="empty-state">
          <div className="icon">🔍</div>
          <h3>No scans yet</h3>
          <p>Start your first vulnerability scan to see results here.</p>
        </div>
      )}
    </>
  );
}

/* ─── Scan Table ─────────────────────────────────────────────── */

function ScanTable({ scans, onViewScan, onDeleteScan, showActions }) {
  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>Target</th>
            <th>Profile</th>
            <th>Status</th>
            <th>Risk</th>
            <th>C</th>
            <th>H</th>
            <th>M</th>
            <th>L</th>
            <th>Gate</th>
            <th>Duration</th>
            <th>Date</th>
            {showActions && <th>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {scans.map(s => (
            <tr key={s.id} onClick={() => onViewScan(s.id)} style={{ cursor: 'pointer' }}>
              <td style={{ maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {s.target_url}
              </td>
              <td><code>{s.profile}</code></td>
              <td><span className={`badge badge-status`}>{s.status}</span></td>
              <td style={{ fontWeight: 700, color: s.risk_score > 50 ? 'var(--critical)' : s.risk_score > 20 ? 'var(--medium)' : 'var(--success)' }}>
                {s.risk_score?.toFixed(0) || 0}
              </td>
              <td className="sev-critical" style={{ fontWeight: 700 }}>{s.critical_count || 0}</td>
              <td className="sev-high" style={{ fontWeight: 700 }}>{s.high_count || 0}</td>
              <td className="sev-medium" style={{ fontWeight: 700 }}>{s.medium_count || 0}</td>
              <td className="sev-low" style={{ fontWeight: 700 }}>{s.low_count || 0}</td>
              <td>
                {s.status === 'COMPLETED' && (
                  <span className={`badge ${s.pass_fail ? 'badge-pass' : 'badge-fail'}`}>
                    {s.pass_fail ? 'PASS' : 'FAIL'}
                  </span>
                )}
              </td>
              <td style={{ color: 'var(--text-muted)' }}>{s.duration_seconds ? `${s.duration_seconds.toFixed(1)}s` : '—'}</td>
              <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                {s.started_at ? new Date(s.started_at).toLocaleDateString() : '—'}
              </td>
              {showActions && (
                <td onClick={e => e.stopPropagation()}>
                  <button className="btn btn-danger btn-sm" onClick={() => onDeleteScan(s.id)}>✕</button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ─── Scan Detail View ───────────────────────────────────────── */

function ScanDetailView({ scan, onBack }) {
  const [expandedVuln, setExpandedVuln] = useState(null);
  const vulns = scan.vulnerabilities || [];

  return (
    <>
      <div className="section-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <button className="btn btn-sm" onClick={onBack}>← Back</button>
          <h2>Scan Results</h2>
        </div>
        <span className={`badge ${scan.pass_fail ? 'badge-pass' : 'badge-fail'}`} style={{ fontSize: '0.85rem', padding: '6px 14px' }}>
          {scan.pass_fail ? '✓ PASS' : '✗ FAIL'}
        </span>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="label">Target</div>
          <div className="value" style={{ fontSize: '0.95rem', wordBreak: 'break-all' }}>{scan.target_url}</div>
        </div>
        <div className="stat-card">
          <div className="label">Risk Score</div>
          <div className="value" style={{ color: scan.risk_score > 50 ? 'var(--critical)' : scan.risk_score > 20 ? 'var(--medium)' : 'var(--success)' }}>
            {scan.risk_score?.toFixed(0) || 0}/100
          </div>
        </div>
        <div className="stat-card">
          <div className="label">Vulnerabilities</div>
          <div className="value">{scan.total_vulns || vulns.length}</div>
        </div>
        <div className="stat-card">
          <div className="label">Duration</div>
          <div className="value">{scan.duration_seconds?.toFixed(1) || 0}s</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
        <div className="stat-card" style={{ display: 'flex', justifyContent: 'space-around', padding: '1.25rem' }}>
          <div style={{ textAlign: 'center' }}><div className="sev-critical" style={{ fontSize: '1.8rem', fontWeight: 800 }}>{scan.critical_count || 0}</div><div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Critical</div></div>
          <div style={{ textAlign: 'center' }}><div className="sev-high" style={{ fontSize: '1.8rem', fontWeight: 800 }}>{scan.high_count || 0}</div><div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>High</div></div>
          <div style={{ textAlign: 'center' }}><div className="sev-medium" style={{ fontSize: '1.8rem', fontWeight: 800 }}>{scan.medium_count || 0}</div><div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Medium</div></div>
          <div style={{ textAlign: 'center' }}><div className="sev-low" style={{ fontSize: '1.8rem', fontWeight: 800 }}>{scan.low_count || 0}</div><div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Low</div></div>
        </div>
        <div className="stat-card">
          <div className="label">Scan Info</div>
          <div style={{ marginTop: '0.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            <div>Profile: <code>{scan.profile}</code></div>
            <div>Status: <span className="badge badge-status">{scan.status}</span></div>
            <div>ID: <code style={{ fontSize: '0.75rem' }}>{scan.id?.slice(0, 8)}</code></div>
          </div>
        </div>
      </div>

      <div className="section-header"><h2>Findings ({vulns.length})</h2></div>
      {vulns.length === 0 ? (
        <div className="empty-state"><div className="icon">✅</div><h3>No vulnerabilities found</h3><p>This target passed the security assessment.</p></div>
      ) : (
        vulns.map(v => (
          <div key={v.id} className="vuln-card">
            <div className="vuln-card-header" onClick={() => setExpandedVuln(expandedVuln === v.id ? null : v.id)}>
              <span className={`badge badge-${v.severity?.toLowerCase()}`}>{v.severity}</span>
              <span style={{ fontSize: '0.8rem', color: 'var(--accent)', fontWeight: 600 }}>CVSS {v.cvss_score?.toFixed(1)}</span>
              <h4>{v.title}</h4>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{expandedVuln === v.id ? '▲' : '▼'}</span>
            </div>
            {expandedVuln === v.id && (
              <div className="vuln-card-body">
                <div className="vuln-field"><label>OWASP Category</label><p>{v.owasp_category}</p></div>
                {v.url && <div className="vuln-field"><label>URL</label><p><code>{v.url}</code></p></div>}
                {v.parameter && <div className="vuln-field"><label>Parameter</label><p><code>{v.parameter}</code></p></div>}
                {v.cwe_id && <div className="vuln-field"><label>CWE</label><p><code>{v.cwe_id}</code></p></div>}
                <div className="vuln-field"><label>Description</label><p>{v.description}</p></div>
                {v.evidence && <div className="vuln-field"><label>Evidence</label><pre>{v.evidence}</pre></div>}
                {v.remediation && <div className="vuln-field"><label>Remediation</label><div className="remediation-box">{v.remediation}</div></div>}
              </div>
            )}
          </div>
        ))
      )}
    </>
  );
}

/* ─── Live Scan Progress ─────────────────────────────────────── */

function LiveScanProgress({ scan }) {
  const statusMap = { PENDING: 10, PROFILING: 30, SCANNING: 60, REPORTING: 85, COMPLETED: 100, FAILED: 100 };
  const progress = statusMap[scan.status] || 10;

  return (
    <div className="scan-progress" style={{ marginBottom: '2rem' }}>
      <div className="spinner" />
      <h3 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>
        {scan.status === 'COMPLETED' ? '✓ Scan Complete!' : scan.status === 'FAILED' ? '✗ Scan Failed' : 'Scanning...'}
      </h3>
      <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{scan.target}</p>
      <div className="progress-bar-track">
        <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
      </div>
      <p style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>
        Status: {scan.status}
        {scan.events.filter(e => e.type === 'scanner_complete').map((e, i) => (
          <span key={i}> • {e.scanner}: {e.vulns_found} findings</span>
        ))}
      </p>
      {scan.total_vulns !== undefined && (
        <p style={{ marginTop: '0.5rem', fontWeight: 700, color: 'var(--accent)' }}>
          {scan.total_vulns} vulnerabilities found | Risk: {scan.risk_score?.toFixed(0)}/100
        </p>
      )}
    </div>
  );
}

/* ─── New Scan Modal ─────────────────────────────────────────── */

function NewScanModal({ onClose, onSubmit }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [profile, setProfile] = useState('default');
  const [rateLimit, setRateLimit] = useState(10);
  const [timeout, setTimeout_] = useState(1800);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!targetUrl) return;
    onSubmit({ target_url: targetUrl, profile, rate_limit: rateLimit, timeout: timeout });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>⚡ New Vulnerability Scan</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Target URL</label>
            <input className="form-input" type="url" placeholder="https://example.com" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} required autoFocus />
          </div>
          <div className="form-group">
            <label>Scan Profile</label>
            <select className="form-input" value={profile} onChange={e => setProfile(e.target.value)}>
              <option value="quick">Quick — Fast check (2 scanners)</option>
              <option value="default">Default — Standard scan (6 scanners)</option>
              <option value="full">Full — Deep analysis (6 scanners, max depth)</option>
              <option value="api">API — API-focused (3 scanners)</option>
              <option value="ci">CI — Pipeline optimized (6 scanners)</option>
            </select>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div className="form-group">
              <label>Rate Limit (req/s)</label>
              <input className="form-input" type="number" min="1" max="100" value={rateLimit} onChange={e => setRateLimit(parseInt(e.target.value))} />
            </div>
            <div className="form-group">
              <label>Timeout (seconds)</label>
              <input className="form-input" type="number" min="60" max="7200" value={timeout} onChange={e => setTimeout_(parseInt(e.target.value))} />
            </div>
          </div>
          <div className="modal-actions">
            <button type="button" className="btn" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary">🚀 Start Scan</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default App;
