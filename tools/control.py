#!/usr/bin/env python3
"""
SANITY Control — a single-page web GUI to drive and observe the whole system.

What it does (no CLI needed):
  * Upload / pick an OpenXSAM++ DVD file and press Run.
  * Watch the threat-modeling process live (RAG queries, scenario derivation, tree assembly)
    streamed straight from the runner's output.
  * Browse the generated attack trees: click a scenario to expand its node tree
    (read from redis State st:tree:*).
  * Each node shows live attack (A) / defense (D) status dots (from the agent logs).
  * Click a node to open a detail panel: status timeline, LLM calls, cost/tokens,
    artifacts (PoV / patch) for that exact node.

Design: runs inside a container that uses the scenario-manager image (has threat_modeler,
the runner, sanity_* libs and the redis client) with `network_mode: host`, so gateway
(localhost:4000), redis (localhost:6379) and the Tailscale RAG are all reachable just like
on the host. The sanity-logs volume is mounted read-only at /logs.

Env:
  SANITY_LOG_DIR (default /logs)         — agent JSONL logs (comp*.jsonl)
  REDIS_URL_STATE (default redis://localhost:6379/1)
  REDIS_URL_BUS   (default redis://localhost:6379/0)
  LITELLM_API_BASE (default http://localhost:4000)
  SANITY_RAG_URL, SANITY_LITELLM_MASTER_KEY  — passed through to the runner
  SANITY_CONTROL_PORT (default 8092)
  SANITY_UPLOAD_DIR (default /work/uploads)
"""
from __future__ import annotations
import glob, json, os, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR   = os.getenv("SANITY_LOG_DIR", "/logs")
STATE_URL = os.getenv("REDIS_URL_STATE", "redis://localhost:6379/1")
BUS_URL   = os.getenv("REDIS_URL_BUS", "redis://localhost:6379/0")
GW_BASE   = os.getenv("LITELLM_API_BASE", "http://localhost:4000")
RAG_URL   = os.getenv("SANITY_RAG_URL", "")
MASTER    = os.getenv("SANITY_LITELLM_MASTER_KEY", "")
PORT      = int(os.getenv("SANITY_CONTROL_PORT", "8092"))
UPLOAD    = os.getenv("SANITY_UPLOAD_DIR", "/work/uploads")
try:
    os.makedirs(UPLOAD, exist_ok=True)
except Exception:
    UPLOAD = "/tmp/sanity_uploads"
    os.makedirs(UPLOAD, exist_ok=True)

try:
    import redis  # present in the scenario-manager image
except Exception:
    redis = None

# --- runner process state (single active run at a time) ---
_run_lock = threading.Lock()
_run = {"proc": None, "lines": [], "running": False, "dvd": None, "started": 0}


def _rconn(url):
    if not redis:
        return None
    try:
        return redis.Redis.from_url(url, decode_responses=True, socket_timeout=3)
    except Exception:
        return None


def read_trees() -> dict:
    """Return {tree_id: tree_json} from redis State (st:tree:*)."""
    r = _rconn(STATE_URL)
    out = {}
    if not r:
        return out
    try:
        for k in r.scan_iter("st:tree:*"):
            tid = k.split("st:tree:", 1)[1]
            v = r.get(k)
            if v:
                try:
                    out[tid] = json.loads(v)
                except Exception:
                    pass
    except Exception:
        pass
    return out


def inbox_len() -> int:
    r = _rconn(BUS_URL)
    if not r:
        return -1
    try:
        return int(r.xlen("sanity:tree:inbox"))
    except Exception:
        return -1


def parse_scope(sid: str):
    if not sid:
        return (None, None, None)
    p = sid.split(":", 2)
    if len(p) == 3 and p[0] in ("att", "def"):
        return (p[0], p[1], p[2])
    return ("other", sid, None)


def read_logs():
    """Aggregate agent JSONL: per-node att/def status, event feed, per-node detail, counters."""
    status = {}       # tree_id -> {tnode_id -> {att,def,att_ts,def_ts}}
    detail = {}       # scope_id -> [events...]
    feed = []
    llm = 0; cost = 0.0; ptok = 0; ctok = 0
    for path in sorted(glob.glob(os.path.join(LOG_DIR, "comp*.jsonl"))):
        try:
            fh = open(path, "r", encoding="utf-8")
        except FileNotFoundError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                et = e.get("event_type"); st = e.get("state"); ts = e.get("ts", 0)
                comp = str(e.get("component", "")); sid = e.get("scope_id", "")
                if et == "llm_call":
                    llm += 1
                    cost += float(e.get("cost_usd") or e.get("cost") or 0) or 0
                    ptok += int(e.get("prompt_tokens") or 0)
                    ctok += int(e.get("completion_tokens") or 0)
                kind, tid, tn = parse_scope(sid)
                if kind in ("att", "def") and tid:
                    node = status.setdefault(tid, {}).setdefault(
                        tn, {"att": None, "def": None, "att_ts": 0, "def_ts": 0})
                    if st:
                        if kind == "att" and ts >= node["att_ts"]:
                            node["att"] = st; node["att_ts"] = ts
                        if kind == "def" and ts >= node["def_ts"]:
                            node["def"] = st; node["def_ts"] = ts
                    detail.setdefault(sid, []).append({
                        "ts": ts, "comp": comp, "event": et, "state": st,
                        "ref": e.get("payload_ref", ""),
                        "extra": {k: v for k, v in e.items()
                                  if k not in ("ts", "component", "event_type", "state",
                                               "scope_id", "trace_id", "payload_ref")},
                    })
                if et in ("status", "artifact") and (st or et == "artifact"):
                    feed.append({"ts": ts, "comp": comp, "event": et, "state": st,
                                 "scope": sid, "ref": e.get("payload_ref", "")})
    feed.sort(key=lambda x: x["ts"], reverse=True)
    return {"status": status, "detail": detail, "feed": feed[:250],
            "llm": llm, "cost": round(cost, 4), "ptok": ptok, "ctok": ctok}


def state_payload():
    trees = read_trees()
    lg = read_logs()
    status = lg["status"]
    # counters
    nodes = 0; pov = 0; patch = 0
    for tid, tree in trees.items():
        def walk(n):
            nonlocal nodes
            nodes += 1
            for c in n.get("children") or []:
                walk(c)
        walk(tree)
    for tid, nd in status.items():
        for tn, s in nd.items():
            if s.get("att") == "SUCCESS":
                pov += 1
            if s.get("def") == "SUCCESS":
                patch += 1
    return {
        "trees": trees, "status": status, "feed": lg["feed"],
        "counters": {"trees": len(trees), "nodes": nodes, "pov": pov, "patch": patch,
                     "llm": lg["llm"], "cost": lg["cost"], "tok": lg["ptok"] + lg["ctok"],
                     "inbox": inbox_len()},
        "run": {"running": _run["running"], "dvd": _run["dvd"], "lines": _run["lines"][-400:]},
        "now": time.time(),
    }


def reset_session():
    """Fresh session: wipe previous agent logs + stored trees so all counters restart at 0."""
    n = 0
    for f in glob.glob(os.path.join(LOG_DIR, "comp*.jsonl")):
        try:
            os.remove(f); n += 1
        except Exception:
            pass
    rs = _rconn(STATE_URL)
    if rs:
        try:
            for k in rs.scan_iter("st:tree:*"):
                rs.delete(k)
        except Exception:
            pass
    return n


def start_run(dvd_path: str):
    with _run_lock:
        if _run["running"]:
            return False, "a run is already in progress"
        if not os.path.exists(dvd_path):
            return False, f"file not found: {dvd_path}"
        _run["lines"] = []; _run["running"] = True; _run["dvd"] = os.path.basename(dvd_path)
        _run["started"] = time.time()
    cleared = reset_session()          # counters restart at 0 each run
    _run["lines"].append(f"[session] cleared {cleared} previous log file(s); counters reset.")
    env = dict(os.environ)
    env["LITELLM_API_BASE"] = GW_BASE
    env["REDIS_URL_BUS"] = BUS_URL
    env["REDIS_URL_STATE"] = STATE_URL
    if RAG_URL:
        env["SANITY_RAG_URL"] = RAG_URL
    if MASTER:
        env["SANITY_LITELLM_MASTER_KEY"] = MASTER

    def worker():
        try:
            p = subprocess.Popen([sys.executable, "-u", "-m", "sanity_infra.dah.runner", dvd_path],
                                 cwd="/app", env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, bufsize=1)
            _run["proc"] = p
            for line in p.stdout:
                _run["lines"].append(line.rstrip("\n"))
                if len(_run["lines"]) > 5000:
                    _run["lines"] = _run["lines"][-4000:]
            p.wait()
            _run["lines"].append(f"[runner exited code={p.returncode}]")
        except Exception as exc:
            _run["lines"].append(f"[control error] {exc}")
        finally:
            _run["running"] = False
    threading.Thread(target=worker, daemon=True).start()
    return True, "started"


HTML = r"""<!doctype html><html><head><meta charset=utf-8><title>SANITY Control</title>
<style>
 :root{--bg:#0b0e14;--panel:#11151f;--line:#232a38;--fg:#cdd6e4;--mut:#8892a6;--acc:#7dd3fc}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 ui-monospace,Menlo,Consolas,monospace}
 header{padding:10px 14px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;gap:16px;flex-wrap:wrap;align-items:center}
 header b{color:var(--acc);font-size:15px}.k{color:var(--mut)}.v{color:#e8eef7;font-weight:700}
 .grid{display:grid;grid-template-columns:340px 1.4fr 1fr;gap:12px;padding:12px;align-items:start}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
 .card h3{margin:0 0 8px;font-size:12px;color:#9aa4b8;text-transform:uppercase;letter-spacing:.04em}
 button{background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:8px 12px;cursor:pointer;font:inherit}
 button:disabled{background:#374151;cursor:not-allowed}
 select,input[type=file]{width:100%;background:#0b0e14;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:7px;font:inherit;margin:4px 0}
 .console{background:#05070c;border:1px solid var(--line);border-radius:6px;padding:8px;height:300px;overflow:auto;white-space:pre-wrap;font-size:11.5px;color:#b9c4d6}
 .tree h4{margin:6px 0;cursor:pointer;color:#cbd5e1}.tree h4:hover{color:#fff}
 .scn{border:1px solid var(--line);border-radius:6px;margin-bottom:8px;padding:8px}
 .node{display:flex;align-items:center;gap:7px;padding:2px 0 2px calc(var(--d,0)*14px);cursor:pointer}
 .node:hover{background:#161c28;border-radius:4px}
 .dot{width:10px;height:10px;border-radius:50%;flex:none}.lab{width:12px;color:#5b6478;font-size:9px;text-align:center}
 .tn{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.tn small{color:var(--mut)}
 .none{background:#232a38}.PENDING{background:#6b7280}.RUNNING{background:#3b82f6;animation:p 1s infinite}
 .SUCCESS{background:#22c55e}.FAIL{background:#ef4444}
 @keyframes p{0%,100%{opacity:1}50%{opacity:.3}}
 .ev{display:flex;gap:8px;padding:2px 0;border-top:1px solid #1a2030;font-size:11.5px}
 .ev .c{color:var(--acc);width:26px}.ev .s{width:60px}.tSUCCESS{color:#22c55e}.tFAIL{color:#ef4444}.tRUNNING{color:#3b82f6}
 .sel{outline:1px solid var(--acc)}
 pre{white-space:pre-wrap;word-break:break-word;background:#05070c;border:1px solid var(--line);border-radius:6px;padding:8px;font-size:11px;max-height:220px;overflow:auto}
 .pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;margin-left:6px}
</style></head><body>
<header>
 <b>SANITY Control</b>
 <span class=k>trees <span class=v id=c_trees>0</span></span>
 <span class=k>nodes <span class=v id=c_nodes>0</span></span>
 <span class=k>PoV <span class=v id=c_pov style=color:#22c55e>0</span></span>
 <span class=k>Patch <span class=v id=c_patch style=color:#22c55e>0</span></span>
 <span class=k>inbox <span class=v id=c_inbox>0</span></span>
 <span class=k>LLM <span class=v id=c_llm>0</span></span>
 <span class=k>$ <span class=v id=c_cost>0</span></span>
 <span class=k>tok <span class=v id=c_tok>0</span></span>
 <span id=runbadge class=pill style="background:#374151">idle</span>
</header>
<div class=grid>
 <div class=card>
  <h3>1 · Target &amp; Run</h3>
  <div class=k>Upload an OpenXSAM++ (.xml) DVD file:</div>
  <input type=file id=file accept=".xml">
  <div class=k style="margin-top:6px">or pick an existing one:</div>
  <select id=dvd></select>
  <button id=run style="width:100%;margin-top:8px">▶ Run SANITY</button>
  <button id=reset style="width:100%;margin-top:6px;background:#374151">↺ Reset counters (clear logs)</button>
  <h3 style="margin-top:14px">2 · Threat-modeling console</h3>
  <div class=console id=console>— idle —</div>
 </div>

 <div class=card>
  <h3>3 · Attack trees (click a scenario, then a node)</h3>
  <div id=trees class=tree><div class=k>No trees yet. Upload a DVD and press Run.</div></div>
 </div>

 <div class=card>
  <h3>4 · Node detail</h3>
  <div id=detail class=k>Click a node to inspect what the attacker / defender is doing.</div>
  <h3 style="margin-top:14px">Event feed</h3>
  <div id=feed></div>
 </div>
</div>
<script>
const $=id=>document.getElementById(id);
let SEL=null, EXPANDED={}, LASTTREES={};
const cls=s=>s||'none';

async function api(u,opt){ const r=await fetch(u,opt); return r.json(); }

// upload
$('file').addEventListener('change', async e=>{
  const f=e.target.files[0]; if(!f) return;
  const text=await f.text();
  await api('/api/upload',{method:'POST',headers:{'Content-Type':'application/json'},
       body:JSON.stringify({name:f.name,content:text})});
  await refreshDvds(); $('dvd').value=f.name;
});
async function refreshDvds(){
  const d=await api('/api/dvds'); const sel=$('dvd'); const cur=sel.value;
  sel.innerHTML=d.files.map(f=>`<option>${f}</option>`).join('');
  if(cur) sel.value=cur;
}
$('run').addEventListener('click', async ()=>{
  const dvd=$('dvd').value; if(!dvd){alert('pick or upload a DVD file');return;}
  $('run').disabled=true;
  const r=await api('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({dvd})});
  if(!r.ok){ alert(r.msg); $('run').disabled=false; }
});
$('reset').addEventListener('click', async ()=>{
  const r=await api('/api/reset',{method:'POST'}); SEL=null; tick();
});

function nodeRow(tid,n,depth,status){
  const st=(status[tid]||{})[n.tnode_id]||{};
  const label=(n.summary||n.attack_context||n.tnode_id||'node');
  let h=`<div class="node ${SEL===('att:'+tid+':'+n.tnode_id)||SEL===('def:'+tid+':'+n.tnode_id)?'sel':''}"`
      +` style="--d:${depth}" data-tid="${tid}" data-tn="${n.tnode_id}">`
      +`<span class=lab>A</span><span class="dot ${cls(st.att)}" title="attack ${st.att||'-'}"></span>`
      +`<span class=lab>D</span><span class="dot ${cls(st.def)}" title="defense ${st.def||'-'}"></span>`
      +`<span class=tn title="${label}">${label} <small>${n.tnode_id}</small></span></div>`;
  for(const c of (n.children||[])) h+=nodeRow(tid,c,depth+1,status);
  return h;
}
function renderTrees(d){
  LASTTREES=d.trees;
  const ids=Object.keys(d.trees);
  if(!ids.length){ $('trees').innerHTML='<div class=k>No trees yet. Upload a DVD and press Run. (Trees appear once the runner publishes and the Scenario Manager stores them.)</div>'; return; }
  let h='';
  for(const tid of ids){ const t=d.trees[tid];
    const scn=(t.summary||t.objective||t.scenario||'scenario');
    const open=EXPANDED[tid]!==false; // default expanded
    h+=`<div class=scn><h4 data-tid="${tid}">${open?'▼':'▶'} 🌳 ${scn} <small style="color:#8892a6">${tid}</small></h4>`;
    if(open) h+=nodeRow(tid,t,0,d.status);
    h+='</div>';
  }
  $('trees').innerHTML=h;
  document.querySelectorAll('.scn h4').forEach(el=>el.onclick=()=>{
    const tid=el.dataset.tid; EXPANDED[tid]=(EXPANDED[tid]===false); renderTrees({trees:LASTTREES,status:d.status}); });
  document.querySelectorAll('.node').forEach(el=>el.onclick=()=>{
    const tid=el.dataset.tid, tn=el.dataset.tn; selectNode(tid,tn); });
}
function findNode(node,tn){
  if(!node) return null;
  if(node.tnode_id===tn) return node;
  for(const c of (node.children||[])){ const f=findNode(c,tn); if(f) return f; }
  return null;
}
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m])); }
async function selectNode(tid,tn){
  const r=await api('/api/node?tid='+encodeURIComponent(tid)+'&tn='+encodeURIComponent(tn));
  SEL='att:'+tid+':'+tn;
  const n=findNode(LASTTREES[tid],tn)||{};
  let h=`<div style="font-size:13px;color:#e8eef7;font-weight:700">${esc(n.summary||tn)}</div>`;
  h+=`<div style="margin:6px 0"><span class=pill style="background:#1e3a8a">attack ${r.att||'-'}</span>`
    +`<span class=pill style="background:#3f2937">defense ${r.def||'-'}</span>`
    +`<span class=pill style="background:#111">LLM ${r.llm} · $${r.cost}</span>`
    +(n.logic?`<span class=pill style="background:#2a2333">${n.logic}</span>`:'')+`</div>`;
  if(n.attack_context){ h+='<h3>attack context</h3><pre>'+esc(n.attack_context)+'</pre>'; }
  if(n.evidence&&n.evidence.length){ h+='<h3>evidence</h3><div>'+
    n.evidence.map(e=>`<span class=pill style="background:#0f2a1a" title="${esc(e.note||'')}">${esc(e.id||e)}</span>`).join('')+'</div>'; }
  h+='<h3>timeline (live agent activity)</h3>';
  if(!r.events.length) h+='<div class=k>No activity logged for this node yet.</div>';
  for(const e of r.events){ const t=new Date(e.ts*1000).toLocaleTimeString();
    h+=`<div class=ev><span class=c>${e.comp}</span><span class="s t${e.state||''}">${e.event=='artifact'?'📦':e.state||e.event}</span>`
      +`<span style="flex:1;color:#9aa4b8">${e.extra&&Object.keys(e.extra).length?JSON.stringify(e.extra).slice(0,120):''}</span>`
      +`<span style=color:#5b6478>${t}</span></div>`; }
  if(r.artifacts.length){ h+='<h3>artifacts</h3><pre>'+r.artifacts.map(a=>JSON.stringify(a)).join('\n')+'</pre>'; }
  $('detail').innerHTML=h;
}
function renderFeed(d){
  $('feed').innerHTML=d.feed.map(e=>{ const t=new Date(e.ts*1000).toLocaleTimeString();
    return `<div class=ev><span class=c>${e.comp}</span><span class="s t${e.state||''}">${e.event=='artifact'?'📦':e.state||''}</span>`
      +`<span style="flex:1;color:#8892a6;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${e.scope}">${e.scope}</span>`
      +`<span style=color:#5b6478>${t}</span></div>`; }).join('');
}
async function tick(){
  let d; try{ d=await api('/api/state'); }catch(e){ return; }
  const c=d.counters;
  c_trees.textContent=c.trees; c_nodes.textContent=c.nodes; c_pov.textContent=c.pov;
  c_patch.textContent=c.patch; c_inbox.textContent=c.inbox; c_llm.textContent=c.llm;
  c_cost.textContent=c.cost; c_tok.textContent=c.tok;
  const rb=$('runbadge');
  if(d.run.running){ rb.textContent='running: '+(d.run.dvd||''); rb.style.background='#1f6feb'; $('run').disabled=true; }
  else { rb.textContent='idle'; rb.style.background='#374151'; $('run').disabled=false; }
  const con=$('console');
  con.textContent=(d.run.lines&&d.run.lines.length)? d.run.lines.join('\n') : '— idle —';
  if(con.dataset.stick!=='0') con.scrollTop=con.scrollHeight;
  renderTrees(d); renderFeed(d);
  if(SEL){ const p=SEL.split(':'); selectNode(p[1],p[2]); }
}
$('console').addEventListener('scroll',function(){
  this.dataset.stick=(this.scrollTop+this.clientHeight>=this.scrollHeight-20)?'1':'0'; });
refreshDvds(); tick(); setInterval(tick,1500);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        if self.path.startswith("/api/state"):
            self._json(state_payload())
        elif self.path.startswith("/api/dvds"):
            fs = sorted(os.path.basename(p) for p in glob.glob(os.path.join(UPLOAD, "*.xml")))
            self._json({"files": fs})
        elif self.path.startswith("/api/node"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            tid = (q.get("tid") or [""])[0]; tn = (q.get("tn") or [""])[0]
            lg = read_logs()
            events = []; artifacts = []; llm = 0; cost = 0.0; att = None; deff = None
            for k in ("att:%s:%s" % (tid, tn), "def:%s:%s" % (tid, tn)):
                for e in lg["detail"].get(k, []):
                    events.append(e)
                    if e["event"] == "llm_call":
                        llm += 1
                    if e["event"] == "artifact":
                        artifacts.append({"ref": e.get("ref"), **(e.get("extra") or {})})
            stt = lg["status"].get(tid, {}).get(tn, {})
            att = stt.get("att"); deff = stt.get("def")
            events.sort(key=lambda x: x["ts"])
            self._json({"events": events, "artifacts": artifacts, "llm": llm,
                        "cost": round(cost, 4), "att": att, "def": deff})
        else:
            self._send(200, HTML.encode(), "text/html; charset=utf-8")

    def do_POST(self):
        if self.path.startswith("/api/upload"):
            try:
                d = json.loads(self._body() or b"{}")
                name = os.path.basename(d.get("name", "upload.xml")) or "upload.xml"
                if not name.endswith(".xml"):
                    name += ".xml"
                with open(os.path.join(UPLOAD, name), "w", encoding="utf-8") as fh:
                    fh.write(d.get("content", ""))
                self._json({"ok": True, "name": name})
            except Exception as exc:
                self._json({"ok": False, "msg": str(exc)}, 400)
        elif self.path.startswith("/api/run"):
            try:
                d = json.loads(self._body() or b"{}")
                dvd = os.path.join(UPLOAD, os.path.basename(d.get("dvd", "")))
                ok, msg = start_run(dvd)
                self._json({"ok": ok, "msg": msg})
            except Exception as exc:
                self._json({"ok": False, "msg": str(exc)}, 400)
        elif self.path.startswith("/api/reset"):
            try:
                self._body()
                n = reset_session()
                self._json({"ok": True, "cleared": n})
            except Exception as exc:
                self._json({"ok": False, "msg": str(exc)}, 400)
        else:
            self._json({"ok": False, "msg": "not found"}, 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"SANITY Control → http://localhost:{PORT}  (logs={LOG_DIR}, state={STATE_URL}, gw={GW_BASE})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
