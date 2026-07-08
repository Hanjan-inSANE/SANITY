"""
6번 GatewayClient 단위 테스트 — 가짜(mock) 프록시로 네트워크 없이 검증.
검사 항목:
  - B1: complete_json 자가수리가 '원래 질문 + 나쁜 응답'을 포함해 재요청하는가
  - B2: 캐시 토큰이 로그에 캡처되는가
  - 성공 경로: 비용/토큰/폴백 표시가 맞는가
실행:  cd gateway_log && PYTHONPATH=src python tests/test_client_mock.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
os.environ.setdefault("LITELLM_API_BASE", "http://localhost:1")   # 실제 호출 안 함
os.environ.setdefault("LITELLM_API_KEY", "sk-dummy")

from sanity_llm import GatewayClient
from sanity_log import LogWriter


# ---------- 가짜 프록시 응답 부품 ----------
class _Msg:
    def __init__(self, c): self.content = c; self.finish_reason = "stop"
class _Choice:
    def __init__(self, c): self.message = _Msg(c)
class _Details:
    cached_tokens = 80
class _Usage:
    prompt_tokens = 100
    completion_tokens = 10
    prompt_tokens_details = _Details()
    cache_creation_input_tokens = 5
class _Resp:
    def __init__(self, c): self.choices = [_Choice(c)]; self.usage = _Usage(); self.model = "claude-sonnet-4-6"
class _Raw:
    def __init__(self, c): self._c = c; self.headers = {"x-litellm-response-cost": "0.0021"}
    def parse(self): return _Resp(self._c)

class _FakeCreate:
    def __init__(self, scripted): self.scripted = scripted; self.calls = []
    def create(self, model, messages, max_tokens, extra_body):
        self.calls.append({"model": model, "messages": messages, "metadata": extra_body.get("metadata")})
        return _Raw(self.scripted[min(len(self.calls) - 1, len(self.scripted) - 1)])
class _FakeClient:
    def __init__(self, scripted):
        self.chat = type("C", (), {})()
        self.chat.completions = type("D", (), {})()
        self.chat.completions.with_raw_response = _FakeCreate(scripted)


def _new_gw(scripted, log):
    gw = GatewayClient(component="3", log=log)     # 여기서 openai 클라 생성(네트워크 X)
    gw._client = _FakeClient(scripted)             # 가짜로 교체
    return gw


def test_b1_json_repair_keeps_context(tmp_path):
    """첫 응답이 깨진 JSON → 두 번째(수리) 요청에 원 질문과 나쁜 응답이 들어가야 한다."""
    log = LogWriter("3", log_dir=str(tmp_path))
    # 1) 깨진 JSON, 2) 올바른 JSON
    gw = _new_gw(["설명 곁들임... {oops not json ,,}", '{"ok": true}'], log)
    out = gw.complete_json("sane-sonnet", user="공격트리를 JSON으로 만들어줘", system="너는 분석가")
    fake = gw._client.chat.completions.with_raw_response
    assert out == {"ok": True}, out
    assert len(fake.calls) == 2, f"수리 재요청이 없었다: {len(fake.calls)}"
    repair = fake.calls[1]["messages"]
    roles = [m["role"] for m in repair]
    assert "assistant" in roles, f"나쁜 응답이 대화에 없음: {roles}"
    assert any("공격트리를 JSON으로" in m["content"] for m in repair), "원 질문이 수리요청에 없음"
    print("OK B1: 자가수리가 원 질문+나쁜응답을 포함해 재요청함 →", out)


def test_b2_cache_tokens_captured(tmp_path):
    """캐시 토큰(read=80, creation=5)이 결과와 로그에 잡혀야 한다."""
    log = LogWriter("3", log_dir=str(tmp_path))
    gw = _new_gw(['{"ok":1}'], log)
    res = gw.complete("sane-sonnet", user="hi", trace_id="t1", scope_id="tree3.node7.attacker")
    assert res.cache_read_tokens == 80, res.cache_read_tokens
    assert res.cache_creation_tokens == 5, res.cache_creation_tokens
    assert res.cost_usd == 0.0021, res.cost_usd
    assert res.provider == "anthropic", res.provider     # B7: 빈문자 아님
    log.close()
    rec = json.loads(log.path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert rec["cache_read_tokens"] == 80 and rec["cost_usd"] == 0.0021
    print("OK B2/B7: 캐시토큰·비용·provider가 결과와 로그에 정상 기록")


def test_mask_bearer():
    from sanity_log import redact_text
    out = redact_text("Authorization: Bearer abc123nonSkToken")
    assert "abc123nonSkToken" not in out, out
    print("OK B8: 'Bearer <비-sk토큰>'도 가려짐 →", out)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        test_b1_json_repair_keeps_context(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_b2_cache_tokens_captured(Path(d))
    test_mask_bearer()
    print("ALL PASS")
