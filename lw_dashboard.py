# lw_dashboard.py
import os
import aiohttp
import aiohttp.web
import aiosqlite

# -------- CORS: global middleware (covers ALL responses, even errors) --------
@aiohttp.web.middleware
async def cors_middleware(request, handler):
    # Handle preflight early
    if request.method == "OPTIONS":
        resp = aiohttp.web.Response(status=204)
    else:
        resp = await handler(request)

    # Allow any origin; you can lock this to your Lovable origin if you prefer
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    resp.headers["Access-Control-Max-Age"] = "86400"
    return resp

def _cors_json(d: dict, status: int = 200) -> aiohttp.web.Response:
    """Per-response belt-and-suspenders CORS (in addition to middleware)."""
    resp = aiohttp.web.json_response(d, status=status)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return resp

def _cors_resp(text: str, content_type="text/html", status: int = 200) -> aiohttp.web.Response:
    resp = aiohttp.web.Response(text=text, content_type=content_type, status=status)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return resp

def make_app(node):
    app = aiohttp.web.Application(middlewares=[cors_middleware])

    async def health(_):
        return _cors_json({"ok": True, "node": node.ident.node_id, "port": node.tcp_port})

    async def peers(_):
        data = []
        for pid, p in node.store.peers.items():
            data.append({
                "node_id": pid,
                "host": p.host,
                "port": p.port,
                "capabilities": getattr(p, "capabilities", []),
            })
        return _cors_json(data)

    async def ask(req):
        try:
            body = await req.json()
        except Exception:
            body = {}
        q = (body.get("q") or "").strip()
        res = await node.query_mesh(q)
        return _cors_json(res)

    async def balance(_):
        async with aiosqlite.connect(node.db_path) as db:
            async with db.execute("SELECT COALESCE(SUM(amount),0) FROM credits") as cur:
                row = await cur.fetchone()
        return _cors_json({"credits": row[0] if row else 0})

    async def index(_):
        html = f"""<!doctype html><meta charset="utf-8">
        <link rel="icon" href='data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="%23111725"/><text x="50%" y="54%" font-size="34" text-anchor="middle" fill="%23EAEAF0" font-family="Arial,Helvetica,sans-serif">LW</text></svg>'>
        <style>
          body{{background:#0b0d14;color:#eaeaf0;font-family:ui-sans-serif,system-ui;margin:0}}
          .wrap{{max-width:900px;margin:40px auto;padding:16px}}
          .card{{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:16px;margin-bottom:16px}}
          input,button{{padding:10px;border-radius:10px;border:1px solid rgba(255,255,255,.15);background:#111725;color:#eaeaf0}}
          button{{cursor:pointer}}
          pre{{white-space:pre-wrap;word-break:break-word}}
          code{{background:#111725;padding:.2rem .4rem;border-radius:.4rem}}
        </style>
        <div class="wrap">
          <h2>Living Web Relay</h2>
          <div class="card"><div><b>Node:</b> <code>{node.ident.node_id}</code></div>
          <div><b>Mesh:</b> <code>{node.host}:{node.tcp_port}</code></div></div>
          <div class="card"><h3>Ask the Mesh</h3>
            <input id="q" style="width:70%" placeholder="Type a question…">
            <button onclick="ask()">Ask</button>
            <pre id="ans"></pre>
          </div>
          <div class="card"><h3>Peers</h3>
            <button onclick="peers()">Refresh</button>
            <pre id="peers"></pre>
          </div>
          <div class="card"><h3>Credits</h3>
            <button onclick="bal()">Check</button>
            <pre id="bal"></pre>
          </div>
        </div>
        <script>
          async function peers(){{ const r=await fetch('/peers'); document.getElementById('peers').textContent=await r.text(); }}
          async function ask(){{ const q=document.getElementById('q').value; const r=await fetch('/ask', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{q}})}}); document.getElementById('ans').textContent=await r.text(); }}
          async function bal(){{ const r=await fetch('/balance'); document.getElementById('bal').textContent=await r.text(); }}
          peers();
        </script>
        """
        return _cors_resp(html, "text/html")

    async def favicon(_):
        return aiohttp.web.Response(status=204)

    # OPTIONS catch-all so browsers can preflight any path
    app.router.add_route("OPTIONS", "/{tail:.*}", lambda _: aiohttp.web.Response(status=204))
    app.router.add_get("/", index)
    app.router.add_get("/health", health)
    app.router.add_get("/peers", peers)
    app.router.add_post("/ask", ask)
    app.router.add_get("/balance", balance)
    app.router.add_get("/favicon.ico", favicon)
    return app

async def start_dashboard(node, host=None, port=None):
    host = host or os.getenv("LW_BIND", "0.0.0.0")
    port = int(port or os.getenv("PORT", "8088"))
    app = make_app(node)
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, host, port)
    await site.start()
    print(f"[dash] http://{host}:{port}  (CORS on)")
