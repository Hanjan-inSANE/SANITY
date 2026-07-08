#!/usr/bin/env python3
"""
C. SANITY 실시간 흐름 뷰어 — 구현/스펙 무변경, 로그만 읽어서 보여준다.

무엇을 보나: 트리별로 각 노드의 공격(3)·방어(4) 상태가 PENDING/RUNNING/SUCCESS/FAIL 로
실시간 색이 바뀌고, 하단에 공격·방어 이벤트 피드가 흐른다. + PoV/Patch/제출/토큰·비용 카운터.

의존성 없음(파이썬 표준 라이브러리). 사용:
    # 리포 루트에서(logs/, submissions/ 가 보이는 곳)
    python SANITY_IMPL_GUIDE/viewer.py
    # 브라우저에서 http://localhost:8090

읽는 곳: $SANITY_LOG_DIR(기본 ./logs)의 comp*.jsonl, 그리고 ./submissions/*.json
로그 스키마: DM-8/ sanity_log.Event {ts,trace_id,component,scope_id,event_type,state,payload_ref,...}
"""
from __future__ import annotations
import glob, json, os, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR = os.getenv("SANITY_LOG_DIR", "./logs")
SUB_DIR = os.getenv("SANITY_SUB_DIR", "./submissions")
PORT = int(os.getenv("SANITY_VIEWER_PORT", "8090"))


def _parse_scope(scope_id: str):
    """'att:t_ab:r/0/1' -> ('att','t_ab','r/0/1'). scenario/infra scope는 (kind, scope_id, None)."""
    if not scope_id:
        return (None, None, None)
    parts = scope_id.split(":", 2)
    if len(parts) == 3 and parts[0] in ("att", "def"):
        return (parts[0], parts[1], parts[2])
    return ("other", scope_id, None)


def collect():
    """전 컴포넌트 JSONL을 읽어 트리→노드 상태 + 이벤트 피드 + 카운터로 집계."""
    trees: dict = {}          # tree_id -> {nodes: {tnode_id: {...}}, order: []}
    feed: list = []
    llm_calls = 0; cost = 0.0; ptok = 0; ctok = 0
    for path in sorted(glob.glob(os.path.join(LOG_DIR, "comp*.jsonl"))):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    et = e.get("event_type"); comp = str(e.get("component", "")); st = e.get("state")
                    ts = e.get("ts", 0)
                    if et == "llm_call":
                        llm_calls += 1
                        cost += float(e.get("cost_usd") or e.get("cost") or 0) or 0
                        ptok += int(e.get("prompt_tokens") or 0)
                        ctok += int(e.get("completion_tokens") or 0)
                    kind, tree_id, tnode_id = _parse_scope(e.get("scope_id", ""))
                    if kind in ("att", "def") and tree_id:
                        t = trees.setdefault(tree_id, {"nodes": {}, "order": []})
                        if tnode_id not in t["nodes"]:
                            t["nodes"][tnode_id] = {"att": None, "def": None, "att_ts": 0, "def_ts": 0}
                            t["order"].append(tnode_id)
                        node = t["nodes"][tnode_id]
                        if st:                       # 상태 이벤트만 색에 반영(최신 우선)
                            if kind == "att" and ts >= node["att_ts"]:
                                node["att"] = st; node["att_ts"] = ts
                            if kind == "def" and ts >= node["def_ts"]:
                                node["def"] = st; node["def_ts"] = ts
                    # 이벤트 피드(상태·아티팩트만, 노이즈 감축)
                    if et in ("status", "artifact") and (st or et == "artifact"):
                        feed.append({
                            "ts": ts, "comp": comp, "event": et, "state": st,
                            "scope": e.get("scope_id", ""), "ref": e.get("payload_ref", ""),
                        })
        except FileNotFoundError:
            continue
    feed.sort(key=lambda x: x["ts"], reverse=True)
    feed = feed[:200]
    # 카운터
    pov = sum(1 for t in trees.values() for n in t["nodes"].values() if n["att"] == "SUCCESS")
    patch = sum(1 for t in trees.values() for n in t["nodes"].values() if n["def"] == "SUCCESS")
    nodes = sum(len(t["nodes"]) for t in trees.values())
    subs = len(glob.glob(os.path.join(SUB_DIR, "*.json")))
    return {
        "trees": trees, "feed": feed,
        "counters": {"trees": len(trees), "nodes": nodes, "pov": pov, "patch": patch,
                     "submissions": subs, "llm_calls": llm_calls,
                     "cost_usd": round(cost, 4), "prompt_tokens": ptok, "completion_tokens": ctok},
        "now": time.time(),
    }


HTML = """<!doctype html><html><head><meta charset=utf-8><title>SANITY live</title>
<style>
 body{margin:0;background:#0b0e14;color:#cdd6e4;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace}
 header{padding:10px 16px;background:#11151f;border-bottom:1px solid #232a38;display:flex;gap:18px;flex-wrap:wrap;align-items:center}
 header b{color:#7dd3fc}.k{color:#8892a6}.v{color:#e8eef7;font-weight:700}
 .wrap{display:flex;gap:14px;padding:14px;align-items:flex-start}
 .trees{flex:2;display:flex;flex-wrap:wrap;gap:12px}
 .tree{background:#11151f;border:1px solid #232a38;border-radius:8px;padding:10px;min-width:280px}
 .tree h3{margin:0 0 8px;font-size:12px;color:#9aa4b8}
 .node{display:flex;align-items:center;gap:8px;padding:3px 0;border-top:1px solid #1a2030}
 .tn{flex:1;color:#c7d0e0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 .dot{width:11px;height:11px;border-radius:50%;flex:none}
 .lab{width:14px;color:#5b6478;font-size:10px;text-align:center}
 .feed{flex:1;background:#11151f;border:1px solid #232a38;border-radius:8px;padding:10px;max-height:82vh;overflow:auto}
 .feed h3{margin:0 0 8px;font-size:12px;color:#9aa4b8}
 .ev{display:flex;gap:8px;padding:2px 0;border-top:1px solid #1a2030;font-size:12px}
 .ev .c{color:#7dd3fc;width:30px}.ev .s{width:64px}.ev .sc{color:#8892a6;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 .PENDING{background:#4b5563}.RUNNING{background:#3b82f6;animation:p 1s infinite}
 .SUCCESS{background:#22c55e}.FAIL{background:#ef4444}.none{background:#232a38}
 .tSUCCESS{color:#22c55e}.tFAIL{color:#ef4444}.tRUNNING{color:#3b82f6}.tPENDING{color:#9aa4b8}
 @keyframes p{0%,100%{opacity:1}50%{opacity:.35}}
 .legend{margin-left:auto;display:flex;gap:10px;font-size:11px;color:#8892a6}
</style></head><body>
<header>
 <b>SANITY live</b>
 <span class=k>trees <span class=v id=c_trees>0</span></span>
 <span class=k>nodes <span class=v id=c_nodes>0</span></span>
 <span class=k>PoV <span class=v id=c_pov style=color:#22c55e>0</span></span>
 <span class=k>Patch <span class=v id=c_patch style=color:#22c55e>0</span></span>
 <span class=k>submit <span class=v id=c_sub>0</span></span>
 <span class=k>LLM <span class=v id=c_llm>0</span></span>
 <span class=k>$ <span class=v id=c_cost>0</span></span>
 <span class=k>tok <span class=v id=c_tok>0</span></span>
 <span class=legend>att/def &nbsp; <span class=dot style="display:inline-block;background:#3b82f6"></span>RUN
   <span class=dot style="display:inline-block;background:#22c55e"></span>OK
   <span class=dot style="display:inline-block;background:#ef4444"></span>FAIL</span>
</header>
<div class=wrap>
 <div class=trees id=trees></div>
 <div class=feed><h3>attack / defense feed</h3><div id=feed></div></div>
</div>
<script>
const cls=s=>s||'none';
async function tick(){
 let d; try{ d=await (await fetch('/api/state')).json(); }catch(e){ return; }
 const c=d.counters;
 c_trees.textContent=c.trees; c_nodes.textContent=c.nodes; c_pov.textContent=c.pov;
 c_patch.textContent=c.patch; c_sub.textContent=c.submissions; c_llm.textContent=c.llm_calls;
 c_cost.textContent=c.cost_usd; c_tok.textContent=c.prompt_tokens+c.completion_tokens;
 // trees
 let h='';
 for(const [tid,t] of Object.entries(d.trees)){
   h+=`<div class=tree><h3>🌳 ${tid} · ${t.order.length} nodes</h3>`;
   for(const tn of t.order){ const n=t.nodes[tn];
     h+=`<div class=node><span class=lab>A</span><span class="dot ${cls(n.att)}" title="attack ${n.att||'-'}"></span>`
       +`<span class=lab>D</span><span class="dot ${cls(n.def)}" title="defense ${n.def||'-'}"></span>`
       +`<span class=tn title="${tn}">${tn}</span></div>`;
   }
   h+='</div>';
 }
 trees.innerHTML=h||'<div class=tree><h3>대기 중… (runner로 트리 인입하면 여기 나타남)</h3></div>';
 // feed
 let f='';
 for(const e of d.feed){ const t=new Date(e.ts*1000).toLocaleTimeString();
   f+=`<div class=ev><span class=c>${e.comp}</span><span class="s t${e.state||''}">${e.event=='artifact'?'📦artifact':e.state||''}</span>`
     +`<span class=sc title="${e.scope}">${e.scope}</span><span style=color:#5b6478>${t}</span></div>`;
 }
 feed.innerHTML=f;
}
tick(); setInterval(tick,1500);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, body: bytes, ctype: str):
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/state"):
            self._send(json.dumps(collect()).encode(), "application/json")
        else:
            self._send(HTML.encode(), "text/html; charset=utf-8")

    def log_message(self, *a):  # 조용히
        pass


if __name__ == "__main__":
    print(f"SANITY viewer → http://localhost:{PORT}  (logs={LOG_DIR}, submissions={SUB_DIR})")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
