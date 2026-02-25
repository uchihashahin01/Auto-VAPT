import { useState, useEffect, useCallback, useRef } from 'react';
import { fetchStats, fetchScans, fetchScanDetail, startScan, deleteScan, connectWebSocket, fetchScanDiff } from './api';

/* ═══════════════════════════════════════════════════════════════
   Auto-VAPT Dashboard — Complete Redesign
   Dynamic, interactive, feature-rich security dashboard
   ═══════════════════════════════════════════════════════════════ */

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/* ─── Animated Counter ───────────────────────────────────────── */

function AnimatedNumber({ value, duration = 800 }) {
  const [display, setDisplay] = useState(0);
  const ref = useRef(null);

  useEffect(() => {
    const target = typeof value === 'number' ? value : parseFloat(value) || 0;
    const start = display;
    const startTime = performance.now();

    function update(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(start + (target - start) * eased));
      if (progress < 1) ref.current = requestAnimationFrame(update);
    }

    ref.current = requestAnimationFrame(update);
    return () => cancelAnimationFrame(ref.current);
  }, [value]);

  return <span>{display}</span>;
}

/* ─── Donut Chart ────────────────────────────────────────────── */

function DonutChart({ data, size = 160 }) {
  const total = Object.values(data).reduce((a, b) => a + b, 0) || 1;
  const cx = size / 2, cy = size / 2, r = size / 2 - 12;
  const circumference = 2 * Math.PI * r;
  let offset = 0;

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="donut-chart">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="20" />
      {SEVERITY_ORDER.map(sev => {
        const count = data[sev] || 0;
        if (count === 0) return null;
        const pct = count / total;
        const dashLen = circumference * pct;
        const dashOffset = circumference * offset;
        offset += pct;
        return (
          <circle
            key={sev}
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={SEVERITY_COLORS[sev]}
            strokeWidth="20"
            strokeDasharray={`${dashLen} ${circumference - dashLen}`}
            strokeDashoffset={-dashOffset}
            strokeLinecap="round"
            className="donut-segment"
            style={{ transform: 'rotate(-90deg)', transformOrigin: 'center' }}
          />
        );
      })}
      <text x={cx} y={cy - 6} textAnchor="middle" fill="var(--text-primary)" fontSize="24" fontWeight="800">{total}</text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="var(--text-muted)" fontSize="11">TOTAL</text>
    </svg>
  );
}

/* ─── Risk Gauge ─────────────────────────────────────────────── */

function RiskGauge({ score, size = 140 }) {
  const cx = size / 2, cy = size / 2 + 10;
  const r = size / 2 - 16;
  const startAngle = -210, endAngle = 30;
  const range = endAngle - startAngle;
  const normalized = Math.min(Math.max(score, 0), 100);
  const angle = startAngle + (normalized / 100) * range;

  const arcPath = (start, end) => {
    const s = (start * Math.PI) / 180;
    const e = (end * Math.PI) / 180;
    const x1 = cx + r * Math.cos(s), y1 = cy + r * Math.sin(s);
    const x2 = cx + r * Math.cos(e), y2 = cy + r * Math.sin(e);
    const large = end - start > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
  };

  const color = score > 60 ? '#ef4444' : score > 30 ? '#eab308' : '#22c55e';

  return (
    <svg width={size} height={size - 10} viewBox={`0 0 ${size} ${size - 10}`}>
      <path d={arcPath(startAngle, endAngle)} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="14" strokeLinecap="round" />
      <path d={arcPath(startAngle, angle)} fill="none" stroke={color} strokeWidth="14" strokeLinecap="round" className="gauge-fill" />
      <text x={cx} y={cy - 4} textAnchor="middle" fill={color} fontSize="28" fontWeight="800">{Math.round(score)}</text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="var(--text-muted)" fontSize="10">/100</text>
    </svg>
  );
}

/* ─── Sparkline ──────────────────────────────────────────────── */

function Sparkline({ data, width = 120, height = 32, color = 'var(--accent)' }) {
  if (!data || data.length < 2) return null;
  const max = Math.max(...data, 1);
  const step = width / (data.length - 1);
  const points = data.map((v, i) => `${i * step},${height - (v / max) * (height - 4)}`).join(' ');

  return (
    <svg width={width} height={height} className="sparkline">
      <defs>
        <linearGradient id="sparkGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,${height} ${points} ${width},${height}`} fill="url(#sparkGrad)" />
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
    </svg>
  );
}

/* ═══════════════════════ MAIN APP ════════════════════════════ */

function App() {
  const [view, setView] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [showNewScan, setShowNewScan] = useState(false);
  const [liveScan, setLiveScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [theme, setTheme] = useState('dark');
  const [searchQuery, setSearchQuery] = useState('');
  const [showDiffModal, setShowDiffModal] = useState(false);
  const [diffResult, setDiffResult] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');

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
    connectWebSocket(result.id, (msg) => {
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

  const handleDiff = async (scanAId, scanBId) => {
    try {
      const result = await fetchScanDiff(scanAId, scanBId);
      setDiffResult(result);
      setShowDiffModal(false);
    } catch (e) {
      setError('Failed to compare scans.');
    }
  };

  if (loading) return <LoadingScreen />;

  return (
    <div className={`app-layout ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`} data-theme={theme}>
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="logo-icon">🛡️</div>
          {!sidebarCollapsed && <span className="logo-text">Auto-VAPT</span>}
          <button className="sidebar-toggle" onClick={() => setSidebarCollapsed(!sidebarCollapsed)}>
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>

        <nav className="sidebar-nav">
          <NavItem icon="📊" label="Dashboard" active={view === 'dashboard'} collapsed={sidebarCollapsed}
            onClick={() => { setView('dashboard'); setSelectedScan(null); setDiffResult(null); }} />
          <NavItem icon="🔍" label="Scans" active={view === 'scans' || view === 'detail'} collapsed={sidebarCollapsed}
            onClick={() => { setView('scans'); setSelectedScan(null); setDiffResult(null); }} />
          <NavItem icon="📈" label="Compare" active={view === 'compare'} collapsed={sidebarCollapsed}
            onClick={() => { setView('compare'); setDiffResult(null); }} />

          <div className="nav-divider" />

          <NavItem icon="⚡" label="New Scan" collapsed={sidebarCollapsed}
            onClick={() => setShowNewScan(true)} accent />
        </nav>

        {!sidebarCollapsed && (
          <div className="sidebar-footer">
            <div className="version-badge">v1.0.0</div>
          </div>
        )}
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <h2 className="page-title">
              {view === 'dashboard' && '📊 Dashboard'}
              {view === 'scans' && '🔍 Scan History'}
              {view === 'detail' && '📋 Scan Details'}
              {view === 'compare' && '📈 Compare Scans'}
            </h2>
          </div>
          <div className="topbar-right">
            <div className="search-box">
              <span className="search-icon">🔎</span>
              <input
                type="text"
                placeholder="Search targets..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
            </div>
            <button className="btn btn-primary btn-glow" onClick={() => setShowNewScan(true)}>
              <span>⚡</span> New Scan
            </button>
          </div>
        </header>

        <div className="content-area">
          {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
          {liveScan && <LiveScanProgress scan={liveScan} />}

          {view === 'dashboard' && <DashboardView stats={stats} scans={scans} onViewScan={handleViewScan} />}
          {view === 'scans' && (
            <ScansView
              scans={scans}
              onViewScan={handleViewScan}
              onDeleteScan={handleDeleteScan}
              searchQuery={searchQuery}
              filterSeverity={filterSeverity}
              setFilterSeverity={setFilterSeverity}
            />
          )}
          {view === 'detail' && selectedScan && (
            <ScanDetailView scan={selectedScan} onBack={() => { setView('scans'); setSelectedScan(null); }} />
          )}
          {view === 'compare' && (
            <CompareView scans={scans} onDiff={handleDiff} diffResult={diffResult} />
          )}
        </div>
      </main>

      {showNewScan && <NewScanModal onClose={() => setShowNewScan(false)} onSubmit={handleStartScan} />}
    </div>
  );
}

/* ─── Nav Item ───────────────────────────────────────────────── */

function NavItem({ icon, label, active, collapsed, onClick, accent }) {
  return (
    <button
      className={`nav-item ${active ? 'active' : ''} ${accent ? 'accent' : ''}`}
      onClick={onClick}
      title={collapsed ? label : ''}
    >
      <span className="nav-icon">{icon}</span>
      {!collapsed && <span className="nav-label">{label}</span>}
      {active && <span className="nav-indicator" />}
    </button>
  );
}

/* ─── Loading Screen ─────────────────────────────────────────── */

function LoadingScreen() {
  return (
    <div className="loading-screen">
      <div className="loading-content">
        <div className="pulse-ring" />
        <div className="loading-logo">🛡️</div>
        <h2>Auto-VAPT</h2>
        <p>Initializing security dashboard...</p>
        <div className="loading-bar"><div className="loading-bar-fill" /></div>
      </div>
    </div>
  );
}

/* ─── Error Banner ───────────────────────────────────────────── */

function ErrorBanner({ message, onDismiss }) {
  return (
    <div className="error-banner animate-slide-down">
      <span className="error-icon">⚠️</span>
      <p>{message}</p>
      <button onClick={onDismiss} className="error-dismiss">✕</button>
    </div>
  );
}

/* ═══════════════════ DASHBOARD VIEW ═════════════════════════ */

function DashboardView({ stats, scans, onViewScan }) {
  if (!stats) return null;
  const sd = stats.severity_distribution || {};
  const recentRisks = (stats.recent_scans || []).map(s => s.risk_score || 0).reverse();

  return (
    <div className="animate-fade-in">
      {/* Hero Stats */}
      <div className="hero-stats">
        <div className="hero-stat-card glass-card">
          <div className="hero-stat-icon">📡</div>
          <div className="hero-stat-info">
            <span className="hero-stat-label">Total Scans</span>
            <span className="hero-stat-value"><AnimatedNumber value={stats.total_scans} /></span>
            <span className="hero-stat-sub">{stats.completed_scans} completed</span>
          </div>
          <Sparkline data={recentRisks} color="var(--accent)" />
        </div>

        <div className="hero-stat-card glass-card">
          <div className="hero-stat-icon">🐛</div>
          <div className="hero-stat-info">
            <span className="hero-stat-label">Vulnerabilities</span>
            <span className="hero-stat-value" style={{ color: (sd.CRITICAL || 0) > 0 ? 'var(--critical)' : 'var(--text-primary)' }}>
              <AnimatedNumber value={stats.total_vulnerabilities} />
            </span>
            <span className="hero-stat-sub">{sd.CRITICAL || 0} critical, {sd.HIGH || 0} high</span>
          </div>
        </div>

        <div className="hero-stat-card glass-card">
          <div className="hero-stat-icon">🎯</div>
          <div className="hero-stat-info">
            <span className="hero-stat-label">Avg Risk Score</span>
            <span className="hero-stat-value" style={{ color: stats.average_risk_score > 50 ? 'var(--critical)' : stats.average_risk_score > 20 ? 'var(--medium)' : 'var(--success)' }}>
              <AnimatedNumber value={Math.round(stats.average_risk_score)} />
            </span>
            <span className="hero-stat-sub">across all scans</span>
          </div>
        </div>

        <div className="hero-stat-card glass-card">
          <div className="hero-stat-icon">{(sd.CRITICAL || 0) === 0 && (sd.HIGH || 0) === 0 ? '✅' : '🚨'}</div>
          <div className="hero-stat-info">
            <span className="hero-stat-label">Security Posture</span>
            <span className="hero-stat-value" style={{ color: (sd.CRITICAL || 0) === 0 && (sd.HIGH || 0) === 0 ? 'var(--success)' : 'var(--danger)', fontSize: '1.4rem' }}>
              {(sd.CRITICAL || 0) === 0 && (sd.HIGH || 0) === 0 ? 'Secure' : 'At Risk'}
            </span>
            <span className="hero-stat-sub">{(sd.CRITICAL || 0) + (sd.HIGH || 0)} critical/high issues</span>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="charts-row">
        <div className="chart-card glass-card">
          <div className="chart-card-header">
            <h3>Severity Distribution</h3>
          </div>
          <div className="chart-card-body" style={{ display: 'flex', alignItems: 'center', gap: '2rem', justifyContent: 'center' }}>
            <DonutChart data={sd} size={160} />
            <div className="chart-legend">
              {SEVERITY_ORDER.map(sev => (
                <div key={sev} className="legend-item">
                  <span className="legend-dot" style={{ background: SEVERITY_COLORS[sev] }} />
                  <span className="legend-label">{sev}</span>
                  <span className="legend-value">{sd[sev] || 0}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="chart-card glass-card">
          <div className="chart-card-header">
            <h3>Risk Score Trend</h3>
          </div>
          <div className="chart-card-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <RiskGauge score={stats.average_risk_score} size={160} />
          </div>
        </div>

        <div className="chart-card glass-card">
          <div className="chart-card-header">
            <h3>OWASP Coverage</h3>
          </div>
          <div className="chart-card-body owasp-coverage">
            {Object.entries(stats.owasp_distribution || {}).length > 0 ? (
              Object.entries(stats.owasp_distribution || {}).map(([cat, count]) => {
                const label = cat.split(' - ')[1] || cat;
                return (
                  <div key={cat} className="owasp-bar-item">
                    <div className="owasp-bar-label">{label}</div>
                    <div className="owasp-bar-track">
                      <div className="owasp-bar-fill" style={{
                        width: `${Math.min((count / Math.max(...Object.values(stats.owasp_distribution))) * 100, 100)}%`
                      }} />
                    </div>
                    <div className="owasp-bar-count">{count}</div>
                  </div>
                );
              })
            ) : (
              <p className="empty-text">No data yet — run your first scan!</p>
            )}
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="section-block">
        <div className="section-title">
          <h3>Recent Scans</h3>
          <button className="btn btn-sm btn-ghost" onClick={() => {}}>View All →</button>
        </div>
        <ScanTable scans={scans.slice(0, 8)} onViewScan={onViewScan} compact />
      </div>
    </div>
  );
}

/* ═══════════════════ SCANS VIEW ═════════════════════════════ */

function ScansView({ scans, onViewScan, onDeleteScan, searchQuery, filterSeverity, setFilterSeverity }) {
  const filtered = scans.filter(s => {
    const matchSearch = !searchQuery || s.target_url?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchSearch;
  });

  return (
    <div className="animate-fade-in">
      <div className="scans-toolbar">
        <div className="filter-chips">
          {['ALL', 'COMPLETED', 'PENDING', 'FAILED'].map(status => (
            <button key={status} className={`chip ${filterSeverity === status ? 'active' : ''}`}
              onClick={() => setFilterSeverity(status)}>
              {status === 'ALL' ? `All (${scans.length})` : status}
            </button>
          ))}
        </div>
      </div>

      {filtered.length > 0 ? (
        <ScanTable scans={filtered.filter(s => filterSeverity === 'ALL' || s.status === filterSeverity)} onViewScan={onViewScan} onDeleteScan={onDeleteScan} showActions />
      ) : (
        <EmptyState icon="🔍" title="No scans yet" subtitle="Start your first vulnerability scan to see results here." />
      )}
    </div>
  );
}

/* ═══════════════════ SCAN TABLE ══════════════════════════════ */

function ScanTable({ scans, onViewScan, onDeleteScan, showActions, compact }) {
  return (
    <div className="table-wrapper glass-card">
      <table className="data-table">
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
            {showActions && <th></th>}
          </tr>
        </thead>
        <tbody>
          {scans.map((s, idx) => (
            <tr key={s.id} onClick={() => onViewScan(s.id)} className="table-row-hover"
              style={{ animationDelay: `${idx * 0.03}s` }}>
              <td className="cell-target">
                <span className="target-indicator" />
                <span className="target-url">{s.target_url}</span>
              </td>
              <td><code className="profile-badge">{s.profile}</code></td>
              <td><StatusBadge status={s.status} /></td>
              <td>
                <span className="risk-value" style={{ color: s.risk_score > 50 ? 'var(--critical)' : s.risk_score > 20 ? 'var(--medium)' : 'var(--success)' }}>
                  {s.risk_score?.toFixed(0) || 0}
                </span>
              </td>
              <td><SevCount count={s.critical_count} sev="critical" /></td>
              <td><SevCount count={s.high_count} sev="high" /></td>
              <td><SevCount count={s.medium_count} sev="medium" /></td>
              <td><SevCount count={s.low_count} sev="low" /></td>
              <td>
                {s.status === 'COMPLETED' && (
                  <span className={`gate-badge ${s.pass_fail ? 'pass' : 'fail'}`}>
                    {s.pass_fail ? '✓ PASS' : '✗ FAIL'}
                  </span>
                )}
              </td>
              <td className="cell-muted">{s.duration_seconds ? `${s.duration_seconds.toFixed(1)}s` : '—'}</td>
              <td className="cell-muted cell-date">{s.started_at ? new Date(s.started_at).toLocaleDateString() : '—'}</td>
              {showActions && (
                <td onClick={e => e.stopPropagation()}>
                  <button className="btn-icon btn-danger-icon" onClick={() => onDeleteScan(s.id)} title="Delete">🗑️</button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StatusBadge({ status }) {
  const cls = {
    COMPLETED: 'status-completed',
    PENDING: 'status-pending',
    SCANNING: 'status-scanning',
    PROFILING: 'status-scanning',
    FAILED: 'status-failed',
  }[status] || 'status-pending';

  return <span className={`status-badge ${cls}`}>{status}</span>;
}

function SevCount({ count, sev }) {
  return <span className={`sev-count sev-${sev}`}>{count || 0}</span>;
}

/* ═══════════════════ SCAN DETAIL ════════════════════════════ */

function ScanDetailView({ scan, onBack }) {
  const [expandedVuln, setExpandedVuln] = useState(null);
  const [vulnFilter, setVulnFilter] = useState('ALL');
  const vulns = scan.vulnerabilities || [];
  const filteredVulns = vulnFilter === 'ALL' ? vulns : vulns.filter(v => v.severity === vulnFilter);

  return (
    <div className="animate-fade-in">
      <div className="detail-header">
        <button className="btn btn-ghost" onClick={onBack}>← Back to Scans</button>
        <span className={`gate-badge large ${scan.pass_fail ? 'pass' : 'fail'}`}>
          {scan.pass_fail ? '✓ PASSED' : '✗ FAILED'}
        </span>
      </div>

      {/* Detail Stats */}
      <div className="detail-stats">
        <div className="detail-stat glass-card">
          <span className="detail-stat-label">Target</span>
          <span className="detail-stat-value break-all" style={{ fontSize: '0.95rem' }}>{scan.target_url}</span>
        </div>
        <div className="detail-stat glass-card">
          <span className="detail-stat-label">Risk Score</span>
          <RiskGauge score={scan.risk_score || 0} size={110} />
        </div>
        <div className="detail-stat glass-card">
          <span className="detail-stat-label">Vulnerabilities</span>
          <span className="detail-stat-value"><AnimatedNumber value={scan.total_vulns || vulns.length} /></span>
        </div>
        <div className="detail-stat glass-card">
          <span className="detail-stat-label">Duration</span>
          <span className="detail-stat-value">{scan.duration_seconds?.toFixed(1) || 0}s</span>
        </div>
      </div>

      {/* Severity Chips */}
      <div className="severity-chips">
        <SeverityChip label="Critical" count={scan.critical_count} color="var(--critical)" />
        <SeverityChip label="High" count={scan.high_count} color="var(--high)" />
        <SeverityChip label="Medium" count={scan.medium_count} color="var(--medium)" />
        <SeverityChip label="Low" count={scan.low_count} color="var(--low)" />
      </div>

      {/* Scan Info */}
      <div className="detail-meta glass-card">
        <div className="meta-item"><span className="meta-key">Profile</span><code>{scan.profile}</code></div>
        <div className="meta-item"><span className="meta-key">Status</span><StatusBadge status={scan.status} /></div>
        <div className="meta-item"><span className="meta-key">Scan ID</span><code className="mono-sm">{scan.id?.slice(0, 8)}</code></div>
        <div className="meta-item"><span className="meta-key">Started</span><span>{scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}</span></div>
      </div>

      {/* Findings */}
      <div className="section-block">
        <div className="section-title">
          <h3>Findings ({filteredVulns.length})</h3>
          <div className="filter-chips compact">
            {['ALL', ...SEVERITY_ORDER].map(s => (
              <button key={s} className={`chip tiny ${vulnFilter === s ? 'active' : ''}`}
                onClick={() => setVulnFilter(s)}
                style={s !== 'ALL' ? { borderColor: SEVERITY_COLORS[s] + '44' } : {}}>
                {s}
              </button>
            ))}
          </div>
        </div>

        {filteredVulns.length === 0 ? (
          <EmptyState icon="✅" title="No vulnerabilities found" subtitle="This target passed the security assessment." />
        ) : (
          <div className="vuln-list">
            {filteredVulns.map((v, idx) => (
              <VulnCard key={v.id} vuln={v} expanded={expandedVuln === v.id}
                onClick={() => setExpandedVuln(expandedVuln === v.id ? null : v.id)}
                delay={idx * 0.02} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SeverityChip({ label, count, color }) {
  return (
    <div className="severity-chip" style={{ borderColor: color + '33' }}>
      <span className="severity-chip-count" style={{ color }}><AnimatedNumber value={count || 0} /></span>
      <span className="severity-chip-label">{label}</span>
    </div>
  );
}

/* ─── Vulnerability Card ─────────────────────────────────────── */

function VulnCard({ vuln, expanded, onClick, delay }) {
  const v = vuln;
  const sevColor = SEVERITY_COLORS[v.severity] || '#6b7280';

  return (
    <div className={`vuln-card ${expanded ? 'expanded' : ''}`}
      style={{ animationDelay: `${delay}s`, borderLeftColor: sevColor }}>
      <div className="vuln-card-header" onClick={onClick}>
        <span className={`badge badge-${v.severity?.toLowerCase()}`}>{v.severity}</span>
        <span className="cvss-badge">CVSS {v.cvss_score?.toFixed(1)}</span>
        <h4 className="vuln-title">{v.title}</h4>
        <span className="expand-icon">{expanded ? '▲' : '▼'}</span>
      </div>
      {expanded && (
        <div className="vuln-card-body animate-slide-down">
          <div className="vuln-fields">
            <VulnField label="OWASP Category" value={v.owasp_category} />
            {v.url && <VulnField label="URL" value={v.url} code />}
            {v.parameter && <VulnField label="Parameter" value={v.parameter} code />}
            {v.cwe_id && <VulnField label="CWE" value={v.cwe_id} code />}
            <VulnField label="Description" value={v.description} />
            {v.evidence && <VulnField label="Evidence" value={v.evidence} pre />}
            {v.remediation && (
              <div className="vuln-field">
                <label>Remediation</label>
                <div className="remediation-box">{v.remediation}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function VulnField({ label, value, code, pre }) {
  return (
    <div className="vuln-field">
      <label>{label}</label>
      {pre ? <pre>{value}</pre> : code ? <p><code>{value}</code></p> : <p>{value}</p>}
    </div>
  );
}

/* ═══════════════════ COMPARE VIEW ═══════════════════════════ */

function CompareView({ scans, onDiff, diffResult }) {
  const [scanAId, setScanAId] = useState('');
  const [scanBId, setScanBId] = useState('');
  const completedScans = scans.filter(s => s.status === 'COMPLETED');

  return (
    <div className="animate-fade-in">
      <div className="compare-selector glass-card">
        <h3>Select Two Scans to Compare</h3>
        <div className="compare-inputs">
          <div className="form-group">
            <label>Baseline Scan (A)</label>
            <select className="form-input" value={scanAId} onChange={e => setScanAId(e.target.value)}>
              <option value="">Select scan...</option>
              {completedScans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.target_url} — {new Date(s.started_at).toLocaleDateString()} ({s.total_vulns} vulns)
                </option>
              ))}
            </select>
          </div>
          <div className="compare-arrow">→</div>
          <div className="form-group">
            <label>Comparison Scan (B)</label>
            <select className="form-input" value={scanBId} onChange={e => setScanBId(e.target.value)}>
              <option value="">Select scan...</option>
              {completedScans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.target_url} — {new Date(s.started_at).toLocaleDateString()} ({s.total_vulns} vulns)
                </option>
              ))}
            </select>
          </div>
        </div>
        <button className="btn btn-primary"
          disabled={!scanAId || !scanBId || scanAId === scanBId}
          onClick={() => onDiff(scanAId, scanBId)}>
          Compare Scans
        </button>
      </div>

      {diffResult && <DiffResults diff={diffResult} />}
    </div>
  );
}

function DiffResults({ diff }) {
  const delta = diff.risk_delta || 0;
  const deltaColor = delta > 0 ? 'var(--critical)' : delta < 0 ? 'var(--success)' : 'var(--text-muted)';
  const deltaSign = delta > 0 ? '+' : '';

  return (
    <div className="diff-results animate-fade-in">
      <div className="diff-summary-cards">
        <div className="diff-card glass-card new">
          <span className="diff-card-icon">🆕</span>
          <span className="diff-card-count">{diff.summary?.new_count || 0}</span>
          <span className="diff-card-label">New</span>
        </div>
        <div className="diff-card glass-card resolved">
          <span className="diff-card-icon">✅</span>
          <span className="diff-card-count">{diff.summary?.resolved_count || 0}</span>
          <span className="diff-card-label">Resolved</span>
        </div>
        <div className="diff-card glass-card unchanged">
          <span className="diff-card-icon">➡️</span>
          <span className="diff-card-count">{diff.summary?.unchanged_count || 0}</span>
          <span className="diff-card-label">Unchanged</span>
        </div>
        <div className="diff-card glass-card delta">
          <span className="diff-card-icon">📊</span>
          <span className="diff-card-count" style={{ color: deltaColor }}>{deltaSign}{delta.toFixed(1)}</span>
          <span className="diff-card-label">Risk Delta</span>
        </div>
      </div>

      {diff.new_vulnerabilities?.length > 0 && (
        <div className="diff-section">
          <h4 className="diff-section-title" style={{ color: 'var(--critical)' }}>🆕 New Vulnerabilities</h4>
          {diff.new_vulnerabilities.map((v, i) => (
            <div key={i} className="diff-vuln-item new">
              <span className={`badge badge-${v.severity?.toLowerCase()}`}>{v.severity}</span>
              <span>{v.title}</span>
            </div>
          ))}
        </div>
      )}

      {diff.resolved_vulnerabilities?.length > 0 && (
        <div className="diff-section">
          <h4 className="diff-section-title" style={{ color: 'var(--success)' }}>✅ Resolved Vulnerabilities</h4>
          {diff.resolved_vulnerabilities.map((v, i) => (
            <div key={i} className="diff-vuln-item resolved">
              <span className={`badge badge-${v.severity?.toLowerCase()}`}>{v.severity}</span>
              <span style={{ textDecoration: 'line-through', opacity: 0.7 }}>{v.title}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ─── Live Scan Progress ─────────────────────────────────────── */

function LiveScanProgress({ scan }) {
  const statusMap = { PENDING: 10, PROFILING: 30, SCANNING: 60, REPORTING: 85, COMPLETED: 100, FAILED: 100 };
  const progress = statusMap[scan.status] || 10;
  const isDone = scan.status === 'COMPLETED';
  const isFailed = scan.status === 'FAILED';

  return (
    <div className={`live-scan-card glass-card ${isDone ? 'completed' : isFailed ? 'failed' : 'active'}`}>
      <div className="live-scan-header">
        {!isDone && !isFailed && <div className="scanning-pulse" />}
        <h3>{isDone ? '✓ Scan Complete!' : isFailed ? '✗ Scan Failed' : '⚡ Scanning...'}</h3>
        <span className="live-target">{scan.target}</span>
      </div>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${progress}%` }}>
          <div className="progress-glow" />
        </div>
      </div>
      <div className="live-scan-meta">
        <StatusBadge status={scan.status} />
        {scan.events.filter(e => e.type === 'scanner_complete').map((e, i) => (
          <span key={i} className="scanner-result">
            {e.scanner}: <span className="scanner-count">{e.vulns_found}</span> findings
          </span>
        ))}
      </div>
      {scan.total_vulns !== undefined && (
        <div className="live-scan-result">
          <span>{scan.total_vulns} vulnerabilities found</span>
          <span>Risk: {scan.risk_score?.toFixed(0)}/100</span>
        </div>
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
  const [step, setStep] = useState(1);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!targetUrl) return;
    onSubmit({ target_url: targetUrl, profile, rate_limit: rateLimit, timeout: timeout });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal glass-card animate-scale-in" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>⚡ New Vulnerability Scan</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            <div className="form-group">
              <label>Target URL</label>
              <input className="form-input form-input-lg" type="url" placeholder="https://example.com"
                value={targetUrl} onChange={e => setTargetUrl(e.target.value)} required autoFocus />
            </div>

            <div className="form-group">
              <label>Scan Profile</label>
              <div className="profile-cards">
                {[
                  { id: 'quick', icon: '⚡', name: 'Quick', desc: 'Fast check, 2 scanners', time: '~30s' },
                  { id: 'default', icon: '🔍', name: 'Default', desc: 'All 10 OWASP modules', time: '~2min' },
                  { id: 'full', icon: '🛡️', name: 'Full', desc: 'Deep analysis, max depth', time: '~5min' },
                  { id: 'api', icon: '🔗', name: 'API', desc: 'API-focused testing', time: '~2min' },
                  { id: 'ci', icon: '🚀', name: 'CI/CD', desc: 'Pipeline optimized', time: '~1min' },
                ].map(p => (
                  <button type="button" key={p.id}
                    className={`profile-card ${profile === p.id ? 'selected' : ''}`}
                    onClick={() => setProfile(p.id)}>
                    <span className="profile-icon">{p.icon}</span>
                    <span className="profile-name">{p.name}</span>
                    <span className="profile-desc">{p.desc}</span>
                    <span className="profile-time">{p.time}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Rate Limit (req/s)</label>
                <input className="form-input" type="number" min="1" max="100" value={rateLimit}
                  onChange={e => setRateLimit(parseInt(e.target.value))} />
              </div>
              <div className="form-group">
                <label>Timeout (seconds)</label>
                <input className="form-input" type="number" min="60" max="7200" value={timeout}
                  onChange={e => setTimeout_(parseInt(e.target.value))} />
              </div>
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary btn-glow" disabled={!targetUrl}>
              🚀 Launch Scan
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ─── Empty State ────────────────────────────────────────────── */

function EmptyState({ icon, title, subtitle }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{subtitle}</p>
    </div>
  );
}

export default App;
