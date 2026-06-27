DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Firewall Dashboard</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0f172a; color:#e2e8f0; }
  .header { background:#1e293b; padding:1rem 2rem; border-bottom:1px solid #334155; display:flex; align-items:center; gap:1rem; }
  .header h1 { font-size:1.25rem; font-weight:600; }
  .badge { background:#22c55e; color:#052e16; padding:0.25rem 0.75rem; border-radius:999px; font-size:0.75rem; font-weight:600; }
  .container { max-width:1200px; margin:0 auto; padding:2rem; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:1rem; margin-bottom:2rem; }
  .card { background:#1e293b; border-radius:0.75rem; padding:1.25rem; border:1px solid #334155; }
  .card h3 { font-size:0.875rem; color:#94a3b8; margin-bottom:0.5rem; text-transform:uppercase; letter-spacing:0.05em; }
  .card .value { font-size:1.75rem; font-weight:700; }
  .card .sub { font-size:0.75rem; color:#64748b; margin-top:0.25rem; }
  .section-title { font-size:1rem; font-weight:600; margin:1.5rem 0 1rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; }
  table { width:100%; border-collapse:collapse; }
  th { text-align:left; padding:0.5rem 0.75rem; font-size:0.75rem; color:#94a3b8; text-transform:uppercase; border-bottom:1px solid #334155; }
  td { padding:0.5rem 0.75rem; font-size:0.875rem; border-bottom:1px solid #1e293b; }
  .status-up { color:#22c55e; } .status-down { color:#ef4444; }
  .bar-bg { background:#334155; border-radius:999px; height:0.5rem; overflow:hidden; }
  .bar-fill { background:#3b82f6; height:100%; border-radius:999px; transition:width 0.5s; }
  .endpoints { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:0.5rem; }
  .endpoint { background:#0f172a; padding:0.5rem 0.75rem; border-radius:0.375rem; font-family:monospace; font-size:0.75rem; }
  .method { display:inline-block; padding:0.125rem 0.375rem; border-radius:0.25rem; font-weight:600; font-size:0.625rem; margin-right:0.375rem; }
  .get { background:#3b82f6; color:#fff; } .post { background:#22c55e; color:#fff; } .delete { background:#ef4444; color:#fff; }
</style>
</head>
<body>
<div class="header">
  <h1>LLM Firewall</h1>
  <span class="badge" id="statusBadge">Loading...</span>
  <span style="margin-left:auto;font-size:0.75rem;color:#64748b;" id="uptime"></span>
</div>
<div class="container">
  <div class="grid" id="statsGrid">
    <div class="card"><h3>Status</h3><div class="value" id="healthStatus">—</div></div>
    <div class="card"><h3>Version</h3><div class="value" id="version">—</div></div>
    <div class="card"><h3>Detection Layers</h3><div class="value" id="layers">—</div><div class="sub">active layers</div></div>
    <div class="card"><h3>Cache Size</h3><div class="value" id="cacheSize">—</div><div class="sub" id="cacheRate"></div></div>
    <div class="card"><h3>Audit Records</h3><div class="value" id="auditRecords">—</div><div class="sub" id="auditSize"></div></div>
    <div class="card"><h3>Malicious Seeds</h3><div class="value" id="seedCount">—</div></div>
  </div>

  <div class="section-title">Model Health</div>
  <div class="grid" id="modelsGrid"></div>

  <div class="section-title">API Endpoints</div>
  <div class="endpoints">
    <div class="endpoint"><span class="method get">GET</span> /health</div>
    <div class="endpoint"><span class="method get">GET</span> /metrics</div>
    <div class="endpoint"><span class="method get">GET</span> /v1/health</div>
    <div class="endpoint"><span class="method post">POST</span> /v1/moderate</div>
    <div class="endpoint"><span class="method post">POST</span> /v1/moderate/batch</div>
    <div class="endpoint"><span class="method get">GET</span> /admin/cache</div>
    <div class="endpoint"><span class="method post">POST</span> /admin/cache/clear</div>
    <div class="endpoint"><span class="method get">GET</span> /admin/audit/stats</div>
    <div class="endpoint"><span class="method get">GET</span> /admin/patterns/prompt-injection</div>
    <div class="endpoint"><span class="method get">GET</span> /admin/seeds</div>
    <div class="endpoint"><span class="method post">POST</span> /admin/seeds/reset</div>
    <div class="endpoint"><span class="method get">GET</span> /dashboard</div>
  </div>
</div>
<script>
async function fetchJSON(url) {
  try { const r=await fetch(url); return await r.json(); } catch { return null; }
}
async function refresh() {
  const health = await fetchJSON('/v1/health');
  if (health) {
    document.getElementById('healthStatus').textContent = health.status.toUpperCase();
    document.getElementById('statusBadge').textContent = health.status.toUpperCase();
    document.getElementById('statusBadge').className = 'badge ' + (health.status==='ok'?'status-up':'status-down');
    document.getElementById('version').textContent = health.version;
    document.getElementById('layers').textContent = health.layers.length;
    if (health.uptime_seconds) {
      document.getElementById('uptime').textContent = 'Uptime: ' + Math.floor(health.uptime_seconds) + 's';
    }
  }
  const cache = await fetchJSON('/admin/cache');
  if (cache) {
    document.getElementById('cacheSize').textContent = cache.size + ' / ' + cache.maxsize;
    document.getElementById('cacheRate').textContent = 'Hit rate: ' + (cache.hit_rate*100).toFixed(1) + '%';
  }
  const audit = await fetchJSON('/admin/audit/stats');
  if (audit) {
    document.getElementById('auditRecords').textContent = audit.total_records;
    const size = audit.file_size_bytes > 1024 ? (audit.file_size_bytes/1024).toFixed(1)+'KB' : audit.file_size_bytes+'B';
    document.getElementById('auditSize').textContent = 'File: ' + size;
  }
  const seeds = await fetchJSON('/admin/seeds');
  if (seeds) document.getElementById('seedCount').textContent = seeds.seeds.length;

  const detHealth = await fetchJSON('/v1/health-detailed');
  if (detHealth && detHealth.models) {
    const grid = document.getElementById('modelsGrid');
    grid.innerHTML = '';
    for (const [name,ok] of Object.entries(detHealth.models)) {
      const card = document.createElement('div'); card.className = 'card';
      card.innerHTML = '<h3>'+name+'</h3><div class="value '+(ok?'status-up':'status-down')+'">'+(ok?'HEALTHY':'DOWN')+'</div>';
      grid.appendChild(card);
    }
  }
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


def render_dashboard() -> str:
    return DASHBOARD_HTML
