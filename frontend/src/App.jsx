import { useState } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

function RiskBadge({ score }) {
  if (score === null || score === undefined) return <span className="badge badge-unknown">UNKNOWN</span>;
  if (score >= 70) return <span className="badge badge-high">HIGH RISK</span>;
  if (score >= 30) return <span className="badge badge-medium">MEDIUM</span>;
  return <span className="badge badge-low">CLEAN</span>;
}

function StatCard({ label, value, sub }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value ?? "—"}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

function VirusTotalPanel({ data }) {
  if (!data?.data?.attributes) return <div className="panel-empty">No VirusTotal data</div>;
  const attr = data.data.attributes;
  const stats = attr.last_analysis_stats || {};
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  const malicious = stats.malicious || 0;
  return (
    <div className="panel-section">
      <div className="panel-header">
        <span className="panel-icon">🛡</span> VirusTotal
        <RiskBadge score={total > 0 ? (malicious / total) * 100 : 0} />
      </div>
      <div className="stats-grid">
        <StatCard label="Malicious" value={stats.malicious} />
        <StatCard label="Suspicious" value={stats.suspicious} />
        <StatCard label="Harmless" value={stats.harmless} />
        <StatCard label="Undetected" value={stats.undetected} />
      </div>
      {attr.country && <div className="detail-row"><span>Country</span><span>{attr.country}</span></div>}
      {attr.as_owner && <div className="detail-row"><span>ASN Owner</span><span>{attr.as_owner}</span></div>}
    </div>
  );
}

function AbuseIPDBPanel({ data }) {
  if (!data?.data) return <div className="panel-empty">No AbuseIPDB data</div>;
  const d = data.data;
  return (
    <div className="panel-section">
      <div className="panel-header">
        <span className="panel-icon">⚠</span> AbuseIPDB
        <RiskBadge score={d.abuseConfidenceScore} />
      </div>
      <div className="stats-grid">
        <StatCard label="Abuse Score" value={`${d.abuseConfidenceScore}%`} />
        <StatCard label="Reports" value={d.totalReports} sub="last 90 days" />
        <StatCard label="Distinct Users" value={d.numDistinctUsers} />
        <StatCard label="Usage Type" value={d.usageType} />
      </div>
      {d.domain && <div className="detail-row"><span>Domain</span><span>{d.domain}</span></div>}
      {d.isp && <div className="detail-row"><span>ISP</span><span>{d.isp}</span></div>}
      {d.countryName && <div className="detail-row"><span>Country</span><span>{d.countryName}</span></div>}
      <div className="detail-row">
        <span>Tor Exit Node</span>
        <span className={d.isTor ? "text-danger" : "text-safe"}>{d.isTor ? "YES" : "NO"}</span>
      </div>
    </div>
  );
}

function ShodanPanel({ data }) {
  if (!data || data.error) return <div className="panel-empty">No Shodan data {data?.error ? `(${data.error})` : ""}</div>;
  return (
    <div className="panel-section">
      <div className="panel-header">
        <span className="panel-icon">🔍</span> Shodan
      </div>
      <div className="stats-grid">
        <StatCard label="Open Ports" value={data.ports?.length ?? 0} />
        <StatCard label="Hostnames" value={data.hostnames?.length ?? 0} />
        <StatCard label="Country" value={data.country_name} />
        <StatCard label="Org" value={data.org} />
      </div>
      {data.ports?.length > 0 && (
        <div className="ports-list">
          <div className="ports-label">OPEN PORTS</div>
          <div className="ports-tags">
            {data.ports.map(p => <span key={p} className="port-tag">{p}</span>)}
          </div>
        </div>
      )}
      {data.vulns && Object.keys(data.vulns).length > 0 && (
        <div className="ports-list">
          <div className="ports-label text-danger">KNOWN CVEs</div>
          <div className="ports-tags">
            {Object.keys(data.vulns).map(v => <span key={v} className="port-tag vuln-tag">{v}</span>)}
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);

  const analyze = async (target) => {
    const q = target || query.trim();
    if (!q) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const resp = await fetch(`${API_BASE}/api/analyze/${encodeURIComponent(q)}`);
      const data = await resp.json();
      setResult(data);
      setHistory(prev => [q, ...prev.filter(h => h !== q)].slice(0, 6));
    } catch (e) {
      setError("Failed to reach the API. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap');

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
          --bg: #060a0f;
          --bg2: #0c1219;
          --bg3: #111820;
          --border: #1e2d3d;
          --accent: #00e5ff;
          --accent2: #ff3b6b;
          --accent3: #39ff14;
          --text: #c8d8e8;
          --text-dim: #4a6070;
          --text-bright: #eaf4ff;
          --mono: 'Share Tech Mono', monospace;
          --sans: 'Syne', sans-serif;
        }

        body { background: var(--bg); color: var(--text); font-family: var(--mono); }

        .app {
          min-height: 100vh;
          background: var(--bg);
          background-image: radial-gradient(ellipse at 20% 0%, rgba(0,229,255,0.04) 0%, transparent 60%),
                            radial-gradient(ellipse at 80% 100%, rgba(255,59,107,0.04) 0%, transparent 60%);
        }

        header {
          border-bottom: 1px solid var(--border);
          padding: 24px 40px;
          display: flex;
          align-items: center;
          gap: 16px;
        }

        .logo-dot {
          width: 10px; height: 10px;
          background: var(--accent);
          border-radius: 50%;
          box-shadow: 0 0 12px var(--accent);
          animation: pulse 2s infinite;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.3; }
        }

        .logo-text {
          font-family: var(--sans);
          font-weight: 800;
          font-size: 18px;
          color: var(--text-bright);
          letter-spacing: 0.05em;
        }

        .logo-sub {
          font-size: 11px;
          color: var(--text-dim);
          margin-left: auto;
          letter-spacing: 0.15em;
          text-transform: uppercase;
        }

        main { max-width: 900px; margin: 0 auto; padding: 48px 24px; }

        .hero-label {
          font-size: 11px;
          letter-spacing: 0.2em;
          color: var(--accent);
          text-transform: uppercase;
          margin-bottom: 12px;
        }

        h1 {
          font-family: var(--sans);
          font-size: clamp(32px, 5vw, 52px);
          font-weight: 800;
          color: var(--text-bright);
          line-height: 1.1;
          margin-bottom: 8px;
        }

        h1 span { color: var(--accent); }

        .hero-desc {
          color: var(--text-dim);
          font-size: 13px;
          margin-bottom: 40px;
          line-height: 1.7;
        }

        .search-bar {
          display: flex;
          gap: 12px;
          margin-bottom: 16px;
        }

        .search-input {
          flex: 1;
          background: var(--bg2);
          border: 1px solid var(--border);
          color: var(--text-bright);
          font-family: var(--mono);
          font-size: 15px;
          padding: 14px 18px;
          outline: none;
          transition: border-color 0.2s;
        }

        .search-input::placeholder { color: var(--text-dim); }
        .search-input:focus { border-color: var(--accent); }

        .search-btn {
          background: var(--accent);
          color: var(--bg);
          border: none;
          font-family: var(--sans);
          font-weight: 700;
          font-size: 13px;
          letter-spacing: 0.1em;
          padding: 14px 28px;
          cursor: pointer;
          text-transform: uppercase;
          transition: opacity 0.2s;
        }

        .search-btn:hover { opacity: 0.85; }
        .search-btn:disabled { opacity: 0.4; cursor: not-allowed; }

        .history {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-bottom: 40px;
        }

        .history-tag {
          background: var(--bg3);
          border: 1px solid var(--border);
          color: var(--text-dim);
          font-size: 11px;
          padding: 4px 10px;
          cursor: pointer;
          transition: color 0.2s, border-color 0.2s;
        }

        .history-tag:hover { color: var(--accent); border-color: var(--accent); }

        .loading {
          text-align: center;
          padding: 60px;
          color: var(--text-dim);
          font-size: 13px;
          letter-spacing: 0.15em;
        }

        .loading-bar {
          width: 200px;
          height: 2px;
          background: var(--border);
          margin: 16px auto 0;
          overflow: hidden;
        }

        .loading-bar-inner {
          height: 100%;
          background: var(--accent);
          animation: scan 1.2s ease-in-out infinite;
        }

        @keyframes scan {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(200%); }
        }

        .error-box {
          border: 1px solid var(--accent2);
          background: rgba(255,59,107,0.05);
          color: var(--accent2);
          padding: 16px 20px;
          font-size: 13px;
        }

        .results { display: flex; flex-direction: column; gap: 2px; }

        .result-header {
          background: var(--bg3);
          border: 1px solid var(--border);
          padding: 20px 24px;
          display: flex;
          align-items: center;
          gap: 16px;
          margin-bottom: 2px;
        }

        .result-target {
          font-family: var(--sans);
          font-size: 20px;
          font-weight: 700;
          color: var(--text-bright);
        }

        .result-ts {
          font-size: 11px;
          color: var(--text-dim);
          margin-left: auto;
          letter-spacing: 0.1em;
        }

        .panel-section {
          background: var(--bg2);
          border: 1px solid var(--border);
          padding: 20px 24px;
        }

        .panel-header {
          display: flex;
          align-items: center;
          gap: 10px;
          font-family: var(--sans);
          font-size: 14px;
          font-weight: 700;
          color: var(--text-bright);
          margin-bottom: 16px;
          letter-spacing: 0.05em;
        }

        .panel-icon { font-size: 16px; }

        .panel-empty {
          color: var(--text-dim);
          font-size: 12px;
          padding: 20px 24px;
          background: var(--bg2);
          border: 1px solid var(--border);
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
          gap: 2px;
          margin-bottom: 16px;
        }

        .stat-card {
          background: var(--bg3);
          padding: 12px 14px;
        }

        .stat-label {
          font-size: 10px;
          letter-spacing: 0.15em;
          color: var(--text-dim);
          text-transform: uppercase;
          margin-bottom: 4px;
        }

        .stat-value {
          font-family: var(--sans);
          font-size: 22px;
          font-weight: 800;
          color: var(--text-bright);
        }

        .stat-sub { font-size: 10px; color: var(--text-dim); margin-top: 2px; }

        .detail-row {
          display: flex;
          justify-content: space-between;
          padding: 8px 0;
          border-top: 1px solid var(--border);
          font-size: 12px;
        }

        .detail-row span:first-child { color: var(--text-dim); }
        .detail-row span:last-child { color: var(--text-bright); }

        .badge {
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.12em;
          padding: 3px 8px;
          margin-left: 8px;
        }

        .badge-high { background: rgba(255,59,107,0.15); color: var(--accent2); border: 1px solid var(--accent2); }
        .badge-medium { background: rgba(255,165,0,0.1); color: #ffaa00; border: 1px solid #ffaa00; }
        .badge-low { background: rgba(57,255,20,0.1); color: var(--accent3); border: 1px solid var(--accent3); }
        .badge-unknown { background: var(--bg3); color: var(--text-dim); border: 1px solid var(--border); }

        .ports-list { margin-top: 12px; }
        .ports-label { font-size: 10px; letter-spacing: 0.15em; color: var(--text-dim); text-transform: uppercase; margin-bottom: 8px; }
        .ports-tags { display: flex; flex-wrap: wrap; gap: 6px; }
        .port-tag { background: var(--bg3); border: 1px solid var(--border); color: var(--text); font-size: 11px; padding: 3px 8px; }
        .vuln-tag { border-color: var(--accent2); color: var(--accent2); background: rgba(255,59,107,0.05); }

        .text-danger { color: var(--accent2) !important; }
        .text-safe { color: var(--accent3) !important; }

        .tips {
          margin-top: 60px;
          border-top: 1px solid var(--border);
          padding-top: 32px;
        }

        .tips-title { font-size: 11px; letter-spacing: 0.2em; color: var(--text-dim); text-transform: uppercase; margin-bottom: 16px; }
        .tips-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 2px; }
        .tip-card { background: var(--bg2); border: 1px solid var(--border); padding: 16px; }
        .tip-label { font-size: 10px; letter-spacing: 0.15em; color: var(--accent); text-transform: uppercase; margin-bottom: 6px; }
        .tip-text { font-size: 12px; color: var(--text-dim); line-height: 1.6; }
      `}</style>

      <header>
        <div className="logo-dot" />
        <div className="logo-text">THREATSCOPE</div>
        <div className="logo-sub">v1.0 — Threat Intelligence Dashboard</div>
      </header>

      <main>
        <div className="hero-label">// Security Intelligence Platform</div>
        <h1>Analyze any<br /><span>IP or URL</span></h1>
        <p className="hero-desc">
          Aggregate threat data from VirusTotal, AbuseIPDB, and Shodan.<br />
          Enter any IP address or URL to get a full threat report.
        </p>

        <div className="search-bar">
          <input
            className="search-input"
            type="text"
            placeholder="Enter IP (e.g. 8.8.8.8) or URL..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === "Enter" && analyze()}
          />
          <button className="search-btn" onClick={() => analyze()} disabled={loading}>
            {loading ? "Scanning..." : "Analyze →"}
          </button>
        </div>

        {history.length > 0 && (
          <div className="history">
            {history.map(h => (
              <span key={h} className="history-tag" onClick={() => { setQuery(h); analyze(h); }}>
                {h}
              </span>
            ))}
          </div>
        )}

        {loading && (
          <div className="loading">
            SCANNING TARGET...
            <div className="loading-bar"><div className="loading-bar-inner" /></div>
          </div>
        )}

        {error && <div className="error-box">⚠ {error}</div>}

        {result && (
          <div className="results">
            <div className="result-header">
              <div className="result-target">{result.target}</div>
              <div className="result-ts">{new Date().toISOString()}</div>
            </div>
            <VirusTotalPanel data={result.virustotal} />
            <AbuseIPDBPanel data={result.abuseipdb} />
            <ShodanPanel data={result.shodan} />
          </div>
        )}

        <div className="tips">
          <div className="tips-title">// Get Your Free API Keys</div>
          <div className="tips-grid">
            <div className="tip-card">
              <div className="tip-label">VirusTotal</div>
              <div className="tip-text">Free tier: 4 req/min. Sign up at virustotal.com → Profile → API Key</div>
            </div>
            <div className="tip-card">
              <div className="tip-label">AbuseIPDB</div>
              <div className="tip-text">Free tier: 1,000 req/day. Sign up at abuseipdb.com → Account → API</div>
            </div>
            <div className="tip-card">
              <div className="tip-label">Shodan</div>
              <div className="tip-text">Free tier available. Sign up at shodan.io → Account → API Key</div>
            </div>
            <div className="tip-card">
              <div className="tip-label">Deploy to Railway</div>
              <div className="tip-text">Push to GitHub, connect repo on railway.app, add env vars in dashboard</div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
