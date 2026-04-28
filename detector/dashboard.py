"""
dashboard.py — Flask web dashboard. Refreshes every 3 seconds.
Shows: banned IPs, global req/s, top 10 source IPs, CPU/memory,
effective mean/stddev, and uptime.
"""

import time
import psutil
import logging
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger("dashboard")

# ------------------------------------------------------------------ #
#  HTML template (single-file, no external deps)                       #
# ------------------------------------------------------------------ #
HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>HNG Anomaly Detector</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }
    header { background: #161b22; padding: 16px 24px; border-bottom: 1px solid #30363d; }
    header h1 { font-size: 1.4rem; color: #58a6ff; }
    header span { font-size: 0.85rem; color: #8b949e; margin-left: 12px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; padding: 20px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
    .card h2 { font-size: 0.9rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px; }
    .metric { font-size: 2rem; font-weight: 700; color: #58a6ff; }
    .metric.danger { color: #f85149; }
    .metric.warn { color: #e3b341; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { text-align: left; color: #8b949e; padding: 4px 8px; border-bottom: 1px solid #30363d; }
    td { padding: 4px 8px; border-bottom: 1px solid #21262d; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; }
    .badge.banned { background: #3d1f1f; color: #f85149; }
    .badge.ok { background: #1f3d2a; color: #3fb950; }
    #uptime { font-size: 0.9rem; color: #3fb950; }
    footer { text-align: center; padding: 12px; font-size: 0.75rem; color: #484f58; }
  </style>
</head>
<body>
  <header>
    <h1>🛡 HNG Anomaly Detection Engine</h1>
    <span id="last-update">Loading...</span>
    <span id="uptime"></span>
  </header>

  <div class="grid">
    <div class="card">
      <h2>Global Req/s</h2>
      <div class="metric" id="global-rps">—</div>
    </div>
    <div class="card">
      <h2>Baseline Mean / Stddev</h2>
      <div class="metric" id="baseline">—</div>
    </div>
    <div class="card">
      <h2>CPU Usage</h2>
      <div class="metric" id="cpu">—</div>
    </div>
    <div class="card">
      <h2>Memory Usage</h2>
      <div class="metric" id="mem">—</div>
    </div>
    <div class="card">
      <h2>Banned IPs</h2>
      <div class="metric danger" id="ban-count">—</div>
      <table id="ban-table" style="margin-top:10px">
        <thead><tr><th>IP</th><th>Condition</th><th>Expires</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="card">
      <h2>Top 10 Source IPs</h2>
      <table id="top-table">
        <thead><tr><th>IP</th><th>Requests</th><th>Status</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <footer>Refreshes every 3 seconds &nbsp;|&nbsp; HNG DevSecOps Track Stage 3</footer>

  <script>
    async function refresh() {
      try {
        const r = await fetch('/api/metrics');
        const d = await r.json();

        document.getElementById('last-update').textContent = 'Updated: ' + new Date().toLocaleTimeString();
        document.getElementById('uptime').textContent = '  |  Uptime: ' + d.uptime;

        const rps = parseFloat(d.global_rps);
        const rpsEl = document.getElementById('global-rps');
        rpsEl.textContent = rps.toFixed(2) + ' req/s';
        rpsEl.className = 'metric' + (rps > d.baseline.mean * 3 ? ' danger' : rps > d.baseline.mean * 1.5 ? ' warn' : '');

        document.getElementById('baseline').textContent =
          d.baseline.mean.toFixed(3) + ' / ' + d.baseline.stddev.toFixed(3);

        document.getElementById('cpu').textContent = d.cpu_percent.toFixed(1) + '%';
        document.getElementById('mem').textContent = d.mem_percent.toFixed(1) + '%';
        document.getElementById('ban-count').textContent = d.banned_count;

        // Banned IPs table
        const banTbody = document.querySelector('#ban-table tbody');
        banTbody.innerHTML = '';
        for (const [ip, info] of Object.entries(d.banned_ips)) {
          const tr = document.createElement('tr');
          const expires = info.permanent ? 'permanent' : new Date(info.ban_until * 1000).toLocaleTimeString();
          tr.innerHTML = `<td>${ip}</td><td style="font-size:0.75rem">${info.condition}</td><td>${expires}</td>`;
          banTbody.appendChild(tr);
        }

        // Top IPs table
        const topTbody = document.querySelector('#top-table tbody');
        topTbody.innerHTML = '';
        for (const [ip, count] of d.top_ips) {
          const banned = d.banned_ips[ip] ? '<span class="badge banned">banned</span>' : '<span class="badge ok">ok</span>';
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${ip}</td><td>${count}</td><td>${banned}</td>`;
          topTbody.appendChild(tr);
        }
      } catch(e) {
        console.error('Metrics fetch failed', e);
      }
    }

    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
"""


def start_dashboard(config, shared_state, baseline):
    app = Flask(__name__)
    host = config["dashboard"]["host"]
    port = config["dashboard"]["port"]

    @app.route("/")
    def index():
        return render_template_string(HTML)

    @app.route("/api/metrics")
    def metrics():
        now = time.time()
        uptime_secs = int(now - shared_state.get("uptime_start", now))
        hours, rem = divmod(uptime_secs, 3600)
        mins, secs = divmod(rem, 60)
        uptime_str = f"{hours:02d}:{mins:02d}:{secs:02d}"

        stats = baseline.get_stats()

        # Top 10 IPs by request count
        top_ips = sorted(
            shared_state.get("top_ips", {}).items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        banned = shared_state.get("banned_ips", {})

        return jsonify({
            "global_rps": round(shared_state.get("global_rps", 0.0), 3),
            "baseline": {
                "mean": round(stats["mean"], 4),
                "stddev": round(stats["stddev"], 4),
                "hour": stats["hour"],
            },
            "cpu_percent": psutil.cpu_percent(interval=None),
            "mem_percent": psutil.virtual_memory().percent,
            "banned_count": len(banned),
            "banned_ips": {
                ip: {
                    "condition": info.get("condition", ""),
                    "ban_until": info.get("ban_until"),
                    "permanent": info.get("permanent", False),
                    "ban_count": info.get("ban_count", 1),
                }
                for ip, info in banned.items()
            },
            "top_ips": top_ips,
            "uptime": uptime_str,
            "log_lines_processed": shared_state.get("log_lines_processed", 0),
        })

    logger.info(f"Dashboard starting on http://{host}:{port}")
    # Use threaded=True so the API stays responsive
    app.run(host=host, port=port, threaded=True, use_reloader=False)
