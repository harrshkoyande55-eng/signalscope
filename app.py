"""SignalScope: local incident intelligence dashboard. Run with `python app.py`."""
import json, os, sqlite3
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from analyzer import parse, analyze

DB = Path(__file__).with_name("signalscope.db")
HTML = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SignalScope</title><style>
:root{--g:#9cff57;--b:#0b0d0c;--p:#141814;--l:#293029;--m:#929d93}*{box-sizing:border-box}body{margin:0;background:var(--b);color:#edf5ec;font:15px Arial}header{padding:22px 5vw;border-bottom:1px solid var(--l);display:flex;justify-content:space-between;font:12px monospace;letter-spacing:2px}.green{color:var(--g)}main{max-width:1100px;margin:auto;padding:65px 22px}h1{font-size:clamp(52px,8vw,92px);line-height:.9;letter-spacing:-5px;margin:18px 0 28px}.intro{max-width:650px;color:#aab4ab;font-size:18px;line-height:1.6}.tag,small{font:11px monospace;letter-spacing:1.5px;color:var(--m)}button{background:var(--g);border:0;padding:13px 20px;font-weight:bold;cursor:pointer;margin:16px 8px 0 0}textarea{width:100%;height:220px;background:#080a08;border:1px solid var(--l);color:#baf096;padding:18px;font:13px/1.6 monospace;margin-top:45px}.go{width:100%;margin:10px 0 55px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--l)}article{background:var(--p);padding:23px}.metrics b{display:block;font-size:40px;margin-top:8px}.grid{display:grid;grid-template-columns:1.3fr 1fr;gap:14px;margin:14px 0}.summary{font-size:20px;line-height:1.55}.service{margin-top:14px;font:12px monospace}.bar{height:5px;background:#303730;margin-top:6px}.bar i{display:block;height:100%;background:var(--g)}table{width:100%;border-collapse:collapse;margin-top:12px}td,th{text-align:left;padding:12px 6px;border-bottom:1px solid var(--l);font-size:12px}th{color:var(--m)}@media(max-width:650px){.metrics{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}}
</style></head><body><header><b><span class="green">◈</span> SIGNALSCOPE</b><span class="green">● LOCAL ANALYSIS</span></header><main><span class="tag">INCIDENT INTELLIGENCE</span><h1>Find the signal<br>inside the noise.</h1><p class="intro">Fingerprint failures, score anomalies, and build an incident brief. Your production logs never leave this machine.</p><button onclick="demo()">LOAD DEMO INCIDENT</button><textarea id="logs" placeholder="ISO_TIMESTAMP LEVEL SERVICE - MESSAGE"></textarea><button class="go" onclick="run()">ANALYZE INCIDENT →</button><section id="out" hidden><span class="tag">INCIDENT BRIEF</span><div class="metrics"><article><small>HEALTH</small><b id="health"></b></article><article><small>EVENTS</small><b id="total"></b></article><article><small>SEVERE</small><b id="critical"></b></article><article><small>REJECTED</small><b id="rejected"></b></article></div><div class="grid"><article><small>AUTOMATED ASSESSMENT</small><p class="summary" id="summary"></p></article><article><small>SERVICE RISK</small><div id="services"></div></article></div><article><small>ANOMALY CLUSTERS</small><table><thead><tr><th>SCORE</th><th>SERVICE</th><th>LEVEL</th><th>MESSAGE</th><th>COUNT</th></tr></thead><tbody id="groups"></tbody></table></article></section></main><script>
const q=x=>document.querySelector(x), esc=s=>s.replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));function demo(){q('#logs').value=`2026-08-10T14:01:02Z INFO api - request completed status 200
2026-08-10T14:02:11Z WARN payments - gateway latency 1800ms
2026-08-10T14:02:14Z ERROR payments - gateway timeout after 5000ms
2026-08-10T14:02:18Z ERROR payments - gateway timeout after 7000ms
2026-08-10T14:02:22Z CRITICAL payments - circuit breaker opened
2026-08-10T14:03:01Z ERROR checkout - payment failed order 82931
2026-08-10T14:03:03Z ERROR checkout - payment failed order 82942
2026-08-10T14:04:10Z INFO api - request completed status 200`};async function run(){let r=await fetch('/api/analyze',{method:'POST',body:JSON.stringify({logs:q('#logs').value})}).then(x=>x.json());q('#out').hidden=false;['health','total','critical','rejected'].forEach(k=>q('#'+k).textContent=r[k]);q('#summary').textContent=r.summary;q('#services').innerHTML=r.services.map(s=>`<div class=service>${s.name} · ${s.risk}%<div class=bar><i style="width:${s.risk}%"></i></div></div>`).join('');q('#groups').innerHTML=r.groups.map(g=>`<tr><td class=green>${g.score}</td><td>${g.service}</td><td>${g.level}</td><td>${esc(g.message)}</td><td>${g.count}</td></tr>`).join('');q('#out').scrollIntoView({behavior:'smooth'})}</script></body></html>'''

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = HTML.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", len(body)); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        if self.path != "/api/analyze": return self.send_error(404)
        size = int(self.headers.get("Content-Length", 0))
        if size > 2_000_000: return self.send_error(413)
        data = json.loads(self.rfile.read(size) or b"{}")
        events, rejected = parse(data.get("logs", "")); result = analyze(events); result["rejected"] = rejected
        with sqlite3.connect(DB) as db:
            db.execute("CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP, total INT, rejected INT, health INT)")
            result["run_id"] = db.execute("INSERT INTO runs(total,rejected,health) VALUES(?,?,?)", (result["total"], rejected, result["health"])).lastrowid
        body=json.dumps(result).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",len(body)); self.end_headers(); self.wfile.write(body)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"SignalScope listening on port {port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
