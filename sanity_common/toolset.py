# sanity_common/toolset.py — 실제 Toolset은 stdio FastMCP. 호출부는 §2.1 run_sync로 동기화.
import os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

def _payload(resp: dict) -> dict:
    """봉투에서 diagnostics(실 payload)를 꺼낸다. 실패는 예외로."""
    if not resp.get("ok"):
        raise RuntimeError(f"toolset {resp.get('tool_id')} {resp.get('status')}: {resp.get('summary')}")
    return resp.get("diagnostics", {})

class Toolset:
    def __init__(self, toolset_root: str | None = None):
        self.params = StdioServerParameters(
            command="python", args=["-m", "toolset_mcp.server"],
            env={**os.environ, "PYTHONPATH": toolset_root or os.getenv("TOOLSET_ROOT", "/opt/Toolset")})
    async def call(self, tool: str, args: dict) -> dict:
        """MCP stdio 1회 호출 → 봉투 dict. 호출부는 _await(ts.call(...))로 동기 실행(§2.1)."""
        async with stdio_client(self.params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.call_tool(tool, args)
                import json
                raw = res.structuredContent or (json.loads(res.content[0].text) if res.content else {})
                return raw
    # diag: 성공 전제 도구(create_workspace/build/apply_patch/export_evidence)용 — 실패 시 예외.
    async def diag(self, tool: str, args: dict) -> dict:
        return _payload(await self.call(tool, args))
    # sig: 관측형 도구(reproduce_pov/run_tests/run_sanitizer 등)용 — 실패(ok=False)도 정상 결과이므로
    #      예외 없이 (ok, diagnostics)를 돌려준다. 게이트 계산은 반드시 이걸 쓴다.
    async def sig(self, tool: str, args: dict) -> tuple[bool, dict]:
        r = await self.call(tool, args)
        return bool(r.get("ok")), r.get("diagnostics", {})
    async def list_tools(self, kind=None, priority=None, trace_id=None) -> list[dict]:
        return (await self.diag("list_tools", {"kind": kind, "priority": priority})).get("tools", [])
