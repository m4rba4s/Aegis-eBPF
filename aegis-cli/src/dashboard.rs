//! Embedded Web Dashboard for Aegis eBPF Firewall
//!
//! Single-page HTML dashboard served inline — zero external dependencies.
//! Auto-refreshes stats via fetch('/api/stats') every 2 seconds.

/// The full dashboard HTML page, embedded as a compile-time constant.
pub const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis eBPF Firewall — Dashboard</title>
<style>
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #e6edf3;
  --text-dim: #8b949e;
  --accent: #58a6ff;
  --green: #3fb950;
  --red: #f85149;
  --orange: #d29922;
  --purple: #bc8cff;
  --radius: 12px;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  padding: 24px;
}
.header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 32px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--border);
}
.header .shield { font-size: 48px; }
.header h1 { font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }
.header .subtitle { color: var(--text-dim); font-size: 14px; margin-top: 4px; }
.status-badge {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: 20px;
  font-weight: 600;
  font-size: 14px;
}
.status-badge.up { background: rgba(63,185,80,0.15); color: var(--green); }
.status-badge.down { background: rgba(248,81,73,0.15); color: var(--red); }
.status-dot {
  width: 10px; height: 10px; border-radius: 50%;
  animation: pulse 2s infinite;
}
.status-badge.up .status-dot { background: var(--green); }
.status-badge.down .status-dot { background: var(--red); }
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  transition: border-color 0.2s;
}
.card:hover { border-color: var(--accent); }
.card .label {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-dim);
  margin-bottom: 8px;
}
.card .value {
  font-size: 32px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}
.card .detail {
  font-size: 13px;
  color: var(--text-dim);
  margin-top: 6px;
}
.value.green { color: var(--green); }
.value.red { color: var(--red); }
.value.accent { color: var(--accent); }
.value.orange { color: var(--orange); }
.value.purple { color: var(--purple); }
.section-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}
.bar-chart {
  display: flex;
  gap: 4px;
  height: 32px;
  border-radius: 6px;
  overflow: hidden;
  background: var(--bg);
  margin-top: 12px;
}
.bar-chart .segment {
  height: 100%;
  min-width: 2px;
  transition: width 0.5s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 600;
  color: rgba(255,255,255,0.9);
}
.bar-chart .pass { background: var(--green); }
.bar-chart .drop { background: var(--red); }
.blocklist-panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  margin-top: 16px;
}
.ip-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 12px;
  max-height: 200px;
  overflow-y: auto;
}
.ip-tag {
  background: rgba(248,81,73,0.12);
  color: var(--red);
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 13px;
  font-family: 'SF Mono', 'Consolas', monospace;
}
.actions {
  display: flex;
  gap: 8px;
  margin-top: 16px;
}
.actions input {
  flex: 1;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 8px 12px;
  color: var(--text);
  font-size: 14px;
  outline: none;
}
.actions input:focus { border-color: var(--accent); }
.actions button {
  padding: 8px 16px;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  font-size: 13px;
  cursor: pointer;
  transition: opacity 0.2s;
}
.actions button:hover { opacity: 0.85; }
.btn-block { background: var(--red); color: #fff; }
.btn-unblock { background: var(--green); color: #fff; }
.footer {
  margin-top: 32px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  color: var(--text-dim);
  font-size: 12px;
  text-align: center;
}
@media (max-width: 640px) {
  body { padding: 12px; }
  .header h1 { font-size: 20px; }
  .card .value { font-size: 24px; }
  .grid { grid-template-columns: 1fr 1fr; }
}
</style>
</head>
<body>

<div class="header">
  <div class="shield">🛡️</div>
  <div>
    <h1>Aegis eBPF Firewall</h1>
    <div class="subtitle">Real-time XDP/TC Network Defense Dashboard</div>
  </div>
  <div id="status-badge" class="status-badge down">
    <div class="status-dot"></div>
    <span id="status-text">Connecting...</span>
  </div>
</div>

<div class="grid">
  <div class="card">
    <div class="label">Packets Seen</div>
    <div class="value accent" id="pkts-seen">—</div>
  </div>
  <div class="card">
    <div class="label">Packets Passed</div>
    <div class="value green" id="pkts-pass">—</div>
  </div>
  <div class="card">
    <div class="label">Packets Dropped</div>
    <div class="value red" id="pkts-drop">—</div>
  </div>
  <div class="card">
    <div class="label">Drop Rate</div>
    <div class="value orange" id="drop-rate">—</div>
  </div>
  <div class="card">
    <div class="label">Port Scan Hits</div>
    <div class="value purple" id="portscan">—</div>
  </div>
  <div class="card">
    <div class="label">Conntrack Cache Hits</div>
    <div class="value accent" id="conntrack">—</div>
  </div>
  <div class="card">
    <div class="label">Manual Blocks</div>
    <div class="value red" id="blocks-manual">—</div>
  </div>
  <div class="card">
    <div class="label">CIDR Feed Blocks</div>
    <div class="value red" id="blocks-cidr">—</div>
  </div>
</div>

<div class="card" style="margin-bottom:16px">
  <div class="label">Traffic Distribution</div>
  <div class="bar-chart" id="traffic-bar">
    <div class="segment pass" id="bar-pass" style="width:50%">PASS</div>
    <div class="segment drop" id="bar-drop" style="width:50%">DROP</div>
  </div>
  <div class="detail" id="traffic-detail">—</div>
</div>

<div class="section-title">Active Blocklist (<span id="bl-count">0</span> entries)</div>
<div class="blocklist-panel">
  <div class="ip-grid" id="ip-grid">
    <span style="color:var(--text-dim)">Loading...</span>
  </div>
  <div class="actions">
    <input type="text" id="ip-input" placeholder="Enter IPv4 address (e.g. 203.0.113.5)">
    <button class="btn-block" onclick="doBlock()">Block</button>
    <button class="btn-unblock" onclick="doUnblock()">Unblock</button>
  </div>
</div>

<div class="footer">
  Aegis eBPF Firewall &mdash; localhost:9100 &mdash; Auto-refresh: 2s
</div>

<script>
function fmt(n) {
  if (n === undefined || n === null) return '—';
  if (n >= 1e9) return (n/1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return n.toString();
}

async function refresh() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    if (d.up) {
      document.getElementById('status-badge').className = 'status-badge up';
      document.getElementById('status-text').textContent = 'Protected';
      document.getElementById('pkts-seen').textContent = fmt(d.packets.seen);
      document.getElementById('pkts-pass').textContent = fmt(d.packets.pass);
      document.getElementById('pkts-drop').textContent = fmt(d.packets.drop);
      const rate = d.packets.seen > 0 ? ((d.packets.drop / d.packets.seen) * 100).toFixed(2) + '%' : '0%';
      document.getElementById('drop-rate').textContent = rate;
      document.getElementById('portscan').textContent = fmt(d.portscan_hits);
      document.getElementById('conntrack').textContent = fmt(d.conntrack_hits);
      document.getElementById('blocks-manual').textContent = fmt(d.blocks.manual);
      document.getElementById('blocks-cidr').textContent = fmt(d.blocks.cidr_feed);
      document.getElementById('bl-count').textContent = d.blocklist_entries;
      // Traffic bar
      const total = d.packets.pass + d.packets.drop;
      if (total > 0) {
        const passP = (d.packets.pass / total * 100).toFixed(1);
        const dropP = (d.packets.drop / total * 100).toFixed(1);
        document.getElementById('bar-pass').style.width = passP + '%';
        document.getElementById('bar-drop').style.width = dropP + '%';
        document.getElementById('bar-pass').textContent = passP + '% PASS';
        document.getElementById('bar-drop').textContent = dropP + '% DROP';
        document.getElementById('traffic-detail').textContent =
          `${fmt(d.packets.pass)} passed / ${fmt(d.packets.drop)} dropped of ${fmt(d.packets.seen)} total`;
      }
    } else {
      document.getElementById('status-badge').className = 'status-badge down';
      document.getElementById('status-text').textContent = 'Offline';
    }
  } catch(e) {
    document.getElementById('status-badge').className = 'status-badge down';
    document.getElementById('status-text').textContent = 'Error';
  }
}

async function refreshBlocklist() {
  try {
    const r = await fetch('/api/blocklist');
    const d = await r.json();
    const grid = document.getElementById('ip-grid');
    if (d.ips && d.ips.length > 0) {
      grid.innerHTML = d.ips.map(ip => `<span class="ip-tag">${ip}</span>`).join('');
    } else {
      grid.innerHTML = '<span style="color:var(--text-dim)">No blocked IPs</span>';
    }
  } catch(e) {}
}

async function doBlock() {
  const ip = document.getElementById('ip-input').value.trim();
  if (!ip) return;
  await fetch('/api/block', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ip})
  });
  document.getElementById('ip-input').value = '';
  refreshBlocklist();
}

async function doUnblock() {
  const ip = document.getElementById('ip-input').value.trim();
  if (!ip) return;
  await fetch('/api/unblock', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ip})
  });
  document.getElementById('ip-input').value = '';
  refreshBlocklist();
}

// Initial load
refresh();
refreshBlocklist();
// Auto-refresh
setInterval(refresh, 2000);
setInterval(refreshBlocklist, 5000);
</script>
</body>
</html>"##;
