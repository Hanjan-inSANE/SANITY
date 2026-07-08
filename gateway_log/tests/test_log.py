"""
7번 로그 기본 테스트 — AI나 도커 없이 바로 돌려볼 수 있다.
실행:  cd gateway_log && PYTHONPATH=src python -m pytest tests/ -q
(또는)  PYTHONPATH=src python tests/test_log.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sanity_log import LogWriter, LLMCallRecord, redact_text


def test_mask_hides_secrets():
    out = redact_text("api_key=sk-abcdef123456 and token: sk-zzzzzzzz")
    assert "sk-abcdef123456" not in out
    assert "<redacted>" in out


def test_writer_appends_jsonl(tmp_path):
    log = LogWriter(component="3", log_dir=str(tmp_path))
    log.event("status", trace_id="t1", state="RUNNING", scope_id="tree3.node7.attacker")
    log.llm_call(LLMCallRecord(
        component="3", trace_id="t1", scope_id="tree3.node7.attacker",
        model="sane-sonnet", provider="anthropic",
        prompt_tokens=100, completion_tokens=20, cost_usd=0.0012,
    ))
    log.close()

    lines = log.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    ev0 = json.loads(lines[0])
    assert ev0["event_type"] == "status" and ev0["trace_id"] == "t1"
    ev1 = json.loads(lines[1])
    assert ev1["event_type"] == "llm_call" and ev1["model"] == "sane-sonnet"
    assert ev1["cost_usd"] == 0.0012
    print("OK: 로그 2줄 정상 기록 + 마스킹 동작")


if __name__ == "__main__":
    import tempfile
    test_mask_hides_secrets()
    with tempfile.TemporaryDirectory() as d:
        test_writer_appends_jsonl(Path(d))
    print("ALL PASS")
