#!/usr/bin/env python3
"""
SANITY live attack-tree viewer.

The viewer combines two data sources:
  * Redis state DB: st:tree:* contains the generated attack trees.
  * SANITY JSONL logs: comp*.jsonl contains per-node RUNNING/SUCCESS/FAIL events.

Run:
  SANITY_LOG_DIR=/logs REDIS_URL_STATE=redis://redis:6379/1 python tools/viewer.py
  open http://localhost:8090
"""
from __future__ import annotations

import glob
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOG_DIR = os.getenv("SANITY_LOG_DIR", "./logs")
SUB_DIR = os.getenv("SANITY_SUB_DIR", "./submissions")
STATE_URL = os.getenv("REDIS_URL_STATE", "")
PORT = int(os.getenv("SANITY_VIEWER_PORT", "8090"))

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover - optional dependency in lightweight mode.
    redis = None


def parse_scope(scope_id: str) -> tuple[str | None, str | None, str | None]:
    """Parse 'att:t_ab:r/0/1' into kind, tree_id, tnode_id."""
    if not scope_id:
        return (None, None, None)
    parts = scope_id.split(":", 2)
    if len(parts) == 3 and parts[0] in {"att", "def"}:
        return (parts[0], parts[1], parts[2])
    return ("other", scope_id, None)


def _status_rank(state: str | None) -> int:
    return {"RUNNING": 1, "FAIL": 2, "SUCCESS": 3}.get(state or "", 0)


def read_trees() -> dict[str, dict[str, Any]]:
    """Read full attack trees from Redis. Returns empty dict if Redis is unavailable."""
    if not STATE_URL or redis is None:
        return {}
    try:
        r = redis.Redis.from_url(STATE_URL, decode_responses=True, socket_timeout=2)
        out: dict[str, dict[str, Any]] = {}
        for key in r.scan_iter("st:tree:*"):
            raw = r.get(key)
            if not raw:
                continue
            try:
                out[key.split("st:tree:", 1)[1]] = json.loads(raw)
            except json.JSONDecodeError:
                continue
        return out
    except Exception:
        return {}


def read_logs() -> dict[str, Any]:
    status: dict[str, dict[str, dict[str, Any]]] = {}
    feed: list[dict[str, Any]] = []
    llm_calls = 0
    cost = 0.0
    prompt_tokens = 0
    completion_tokens = 0

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
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event_type = event.get("event_type")
                state = event.get("state")
                ts = float(event.get("ts") or 0)
                component = str(event.get("component", ""))
                scope_id = event.get("scope_id", "")

                if event_type == "llm_call":
                    llm_calls += 1
                    cost += float(event.get("cost_usd") or event.get("cost") or 0)
                    prompt_tokens += int(event.get("prompt_tokens") or 0)
                    completion_tokens += int(event.get("completion_tokens") or 0)

                kind, tree_id, tnode_id = parse_scope(scope_id)
                if kind in {"att", "def"} and tree_id and tnode_id and event_type == "status":
                    tree_status = status.setdefault(tree_id, {})
                    node = tree_status.setdefault(
                        tnode_id,
                        {
                            "att": None,
                            "def": None,
                            "att_ts": 0.0,
                            "def_ts": 0.0,
                            "last": {},
                            "events": [],
                        },
                    )
                    node["events"].append(event)
                    ts_key = f"{kind}_ts"
                    # Keep the newest event. If timestamps tie, SUCCESS wins over FAIL/RUNNING.
                    if state and (
                        ts > float(node.get(ts_key) or 0)
                        or (
                            ts == float(node.get(ts_key) or 0)
                            and _status_rank(state) >= _status_rank(node.get(kind))
                        )
                    ):
                        node[kind] = state
                        node[ts_key] = ts
                        node["last"] = {
                            "component": component,
                            "state": state,
                            "tool": event.get("tool"),
                            "action": event.get("action"),
                            "params": event.get("params"),
                            "rationale": event.get("rationale"),
                            "oracle_reason": event.get("oracle_reason") or event.get("oracle"),
                            "note": event.get("note"),
                            "before": event.get("before"),
                            "after": event.get("after"),
                        }

                if event_type in {"status", "artifact"} and (state or event_type == "artifact"):
                    feed.append(
                        {
                            "ts": ts,
                            "component": component,
                            "event_type": event_type,
                            "state": state,
                            "scope_id": scope_id,
                            "tool": event.get("tool"),
                            "action": event.get("action"),
                            "note": event.get("note") or event.get("oracle_reason") or "",
                        }
                    )

    feed.sort(key=lambda item: item["ts"], reverse=True)
    return {
        "status": status,
        "feed": feed[:250],
        "llm": {
            "calls": llm_calls,
            "cost_usd": round(cost, 5),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        },
    }


def _walk_tree(node: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def rec(cur: dict[str, Any]) -> None:
        out.append(cur)
        for child in cur.get("children") or []:
            if isinstance(child, dict):
                rec(child)

    rec(node)
    return out


def collect() -> dict[str, Any]:
    trees = read_trees()
    logs = read_logs()
    status = logs["status"]
    tree_ids = sorted(set(trees) | set(status))

    merged: dict[str, Any] = {}
    total_nodes = 0
    success_nodes = 0
    failed_nodes = 0
    running_nodes = 0

    for tree_id in tree_ids:
        node_status = status.get(tree_id, {})
        full_tree = trees.get(tree_id)
        if full_tree:
            total_nodes += len(_walk_tree(full_tree))
        else:
            total_nodes += len(node_status)
        for node in node_status.values():
            att = node.get("att")
            if att == "SUCCESS":
                success_nodes += 1
            elif att == "FAIL":
                failed_nodes += 1
            elif att == "RUNNING":
                running_nodes += 1
        merged[tree_id] = {"tree": full_tree, "status": node_status}

    submissions = len(glob.glob(os.path.join(SUB_DIR, "*.json")))
    return {
        "trees": merged,
        "feed": logs["feed"],
        "counters": {
            "trees": len(tree_ids),
            "nodes": total_nodes,
            "success": success_nodes,
            "fail": failed_nodes,
            "running": running_nodes,
            "submissions": submissions,
            "llm_calls": logs["llm"]["calls"],
            "cost_usd": logs["llm"]["cost_usd"],
            "tokens": logs["llm"]["prompt_tokens"] + logs["llm"]["completion_tokens"],
        },
        "now": time.time(),
        "redis_enabled": bool(STATE_URL and redis is not None),
    }


HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SANITY Attack Tree Live</title>
<style>
:root{
  --bg:#080d12; --panel:#101821; --panel2:#0d141c; --line:#223042; --muted:#8b98aa;
  --text:#e8eef7; --cyan:#6dd3ff; --green:#31d07b; --red:#ff6464; --blue:#4c8dff;
  --amber:#f5c451; --shadow:rgba(0,0,0,.35);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:13px/1.45 ui-sans-serif,system-ui,Segoe UI,Arial,sans-serif}
header{position:sticky;top:0;z-index:4;background:#0b1219;border-bottom:1px solid var(--line);padding:10px 14px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
header b{color:#fff;font-size:14px}
.metric{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--muted)}
.metric span{color:#fff;font-weight:700}
.ok{color:var(--green)!important}.bad{color:var(--red)!important}.run{color:var(--blue)!important}
.wrap{display:grid;grid-template-columns:minmax(0,1fr) 380px;gap:12px;padding:12px}
.main{min-width:0}.side{background:var(--panel);border:1px solid var(--line);border-radius:8px;max-height:calc(100vh - 74px);overflow:auto}
.tree-card{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin-bottom:12px;box-shadow:0 10px 30px var(--shadow);overflow:hidden}
.tree-head{display:flex;gap:10px;align-items:center;padding:10px 12px;border-bottom:1px solid var(--line);background:#0d151e}
.tree-title{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--cyan);font-size:12px}
.tree-summary{color:#d8e2ee;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tree-body{padding:12px;overflow:auto}
.node{position:relative;margin:4px 0 4px calc(var(--depth)*22px);border:1px solid var(--line);border-left-width:4px;border-radius:7px;background:var(--panel2);padding:8px 10px}
.node:before{content:"";position:absolute;left:-18px;top:18px;width:14px;border-top:1px solid #31445a;display:block}
.node.depth0:before{display:none}
.node.path{border-left-color:var(--green);box-shadow:inset 0 0 0 1px rgba(49,208,123,.18)}
.node.failonly{border-left-color:var(--red)}
.node.running{border-left-color:var(--blue)}
.node .top{display:flex;gap:8px;align-items:center;min-width:0}
.node .id{font-family:ui-monospace,Menlo,Consolas,monospace;color:#9fb2ca;font-size:11px;white-space:nowrap}
.node .logic{font-family:ui-monospace,Menlo,Consolas,monospace;color:#111;background:#9fb2ca;border-radius:4px;padding:1px 5px;font-size:10px}
.node .summary{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.node .meta{margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.pill{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10px;padding:2px 6px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.pill.SUCCESS{border-color:rgba(49,208,123,.55);color:var(--green)}
.pill.FAIL{border-color:rgba(255,100,100,.55);color:var(--red)}
.pill.RUNNING{border-color:rgba(76,141,255,.65);color:var(--blue)}
.detail{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#b9c5d6;background:#0a1118;border-top:1px solid var(--line);margin:7px -10px -8px;padding:7px 10px;white-space:pre-wrap;word-break:break-word}
.side h3{margin:0;padding:10px 12px;border-bottom:1px solid var(--line);font-size:12px;color:#c9d6e5}
.feed-row{padding:8px 10px;border-bottom:1px solid #182333;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px}
.feed-row .scope{color:#dbe7f5;word-break:break-all}.feed-row .note{color:var(--muted);margin-top:3px;word-break:break-word}
.empty{padding:22px;color:var(--muted)}
@media(max-width:980px){.wrap{grid-template-columns:1fr}.side{max-height:none}.node{margin-left:calc(var(--depth)*14px)}}
</style>
</head>
<body>
<header>
  <b>SANITY Attack Tree Live</b>
  <span class="metric">trees <span id="mTrees">0</span></span>
  <span class="metric">nodes <span id="mNodes">0</span></span>
  <span class="metric">success <span id="mSuccess" class="ok">0</span></span>
  <span class="metric">fail <span id="mFail" class="bad">0</span></span>
  <span class="metric">running <span id="mRun" class="run">0</span></span>
  <span class="metric">LLM <span id="mLlm">0</span></span>
  <span class="metric">tokens <span id="mTok">0</span></span>
</header>
<div class="wrap">
  <main class="main" id="trees"></main>
  <aside class="side"><h3>Live Event Feed</h3><div id="feed"></div></aside>
</div>
<script>
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short = (v, n=160) => { v = String(v ?? ""); return v.length > n ? v.slice(0,n-1) + "..." : v; };
function hasSuccess(node, status){
  const id = node.tnode_id || "";
  if ((status[id] || {}).att === "SUCCESS") return true;
  return (node.children || []).some(c => hasSuccess(c, status));
}
function hasRunning(node, status){
  const id = node.tnode_id || "";
  if ((status[id] || {}).att === "RUNNING") return true;
  return (node.children || []).some(c => hasRunning(c, status));
}
function stateClass(meta){
  if (meta.att === "SUCCESS") return "path";
  if (meta.att === "RUNNING") return "running";
  if (meta.att === "FAIL") return "failonly";
  return "";
}
function nodeDetail(meta){
  if (!meta || !meta.last || !Object.keys(meta.last).length) return "";
  const last = meta.last;
  const lines = [];
  if (last.tool) lines.push(`tool: ${last.tool}`);
  if (last.action) lines.push(`action: ${last.action}`);
  if (last.params) lines.push(`params: ${JSON.stringify(last.params)}`);
  if (last.oracle_reason) lines.push(`oracle: ${last.oracle_reason}`);
  if (last.note) lines.push(`note: ${last.note}`);
  return lines.length ? `<div class="detail">${esc(lines.join("\n"))}</div>` : "";
}
function renderNode(node, status, depth=0){
  const id = node.tnode_id || "?";
  const meta = status[id] || {};
  const inSuccessPath = hasSuccess(node, status);
  const inRunningPath = hasRunning(node, status);
  const klass = inSuccessPath ? "path" : (inRunningPath ? "running" : stateClass(meta));
  const logic = node.logic ? `<span class="logic">${esc(node.logic)}</span>` : "";
  const att = meta.att || "PENDING";
  const def = meta.def || "PENDING";
  const summary = node.summary || node.objective || id;
  let html = `<div class="node depth${depth} ${klass}" style="--depth:${depth}">`;
  html += `<div class="top"><span class="id">${esc(id)}</span>${logic}<span class="summary" title="${esc(summary)}">${esc(summary)}</span></div>`;
  html += `<div class="meta"><span class="pill ${att}">A ${esc(att)}</span><span class="pill ${def}">D ${esc(def)}</span></div>`;
  html += nodeDetail(meta);
  html += `</div>`;
  for (const child of (node.children || [])) html += renderNode(child, status, depth + 1);
  return html;
}
function renderFallback(tid, status){
  const keys = Object.keys(status).sort();
  if (!keys.length) return '<div class="empty">No node status yet.</div>';
  return keys.map(id => {
    const meta = status[id] || {};
    const att = meta.att || "PENDING";
    const def = meta.def || "PENDING";
    return `<div class="node ${stateClass(meta)}" style="--depth:0"><div class="top"><span class="id">${esc(id)}</span><span class="summary">status-only node</span></div><div class="meta"><span class="pill ${att}">A ${esc(att)}</span><span class="pill ${def}">D ${esc(def)}</span></div>${nodeDetail(meta)}</div>`;
  }).join("");
}
function renderTrees(data){
  const cards = [];
  for (const [tid, item] of Object.entries(data.trees || {})){
    const tree = item.tree;
    const status = item.status || {};
    const summary = tree ? (tree.summary || tree.objective || "") : "Redis tree missing; rendering log statuses only";
    const body = tree ? renderNode(tree, status, 0) : renderFallback(tid, status);
    cards.push(`<section class="tree-card"><div class="tree-head"><span class="tree-title">${esc(tid)}</span><span class="tree-summary" title="${esc(summary)}">${esc(short(summary, 220))}</span></div><div class="tree-body">${body}</div></section>`);
  }
  trees.innerHTML = cards.join("") || '<section class="tree-card"><div class="empty">No attack tree yet. Run the scenario generator and attack driver first.</div></section>';
}
function renderFeed(data){
  const rows = (data.feed || []).slice(0, 120).map(e => {
    const state = e.state || e.event_type || "";
    const note = [e.tool, e.action, e.note].filter(Boolean).join(" | ");
    return `<div class="feed-row"><div><span class="${state === 'SUCCESS' ? 'ok' : state === 'FAIL' ? 'bad' : state === 'RUNNING' ? 'run' : ''}">${esc(state)}</span> <span>${esc(new Date((e.ts || 0)*1000).toLocaleTimeString())}</span></div><div class="scope">${esc(e.scope_id)}</div>${note ? `<div class="note">${esc(note)}</div>` : ""}</div>`;
  });
  feed.innerHTML = rows.join("") || '<div class="empty">No events yet.</div>';
}
async function tick(){
  let data;
  try { data = await (await fetch('/api/state', {cache:'no-store'})).json(); }
  catch (err) { return; }
  const c = data.counters || {};
  mTrees.textContent = c.trees || 0;
  mNodes.textContent = c.nodes || 0;
  mSuccess.textContent = c.success || 0;
  mFail.textContent = c.fail || 0;
  mRun.textContent = c.running || 0;
  mLlm.textContent = c.llm_calls || 0;
  mTok.textContent = c.tokens || 0;
  renderTrees(data);
  renderFeed(data);
}
tick();
setInterval(tick, 1500);
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.startswith("/api/state"):
            self._send(json.dumps(collect()).encode("utf-8"), "application/json")
            return
        self._send(HTML.encode("utf-8"), "text/html; charset=utf-8")

    def log_message(self, *_args: Any) -> None:
        return


def main() -> None:
    print(
        f"SANITY viewer -> http://localhost:{PORT} "
        f"(logs={LOG_DIR}, redis={STATE_URL or 'disabled'})",
        flush=True,
    )
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
