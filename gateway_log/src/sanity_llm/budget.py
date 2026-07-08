"""
6.2 예산키 발급 — "2.2 Allocator" 대행 stub.

원래 선불카드(가상키) 발급은 2.2 Allocator가 하지만, 아직 담당/구현이 없다(설계 §2.6).
그래서 6쪽에서 "얇은 발급 함수"를 두어, 2.2 없이도 전체 흐름을 테스트할 수 있게 한다.
2.2가 생기면 이 함수를 그쪽에서 호출하기만 하면 된다.

동작: 마스터키로 프록시의 /key/generate 를 호출해 (tree×role)용 가상키를 만든다.
근거: Buttercup README 의 `POST /key/generate -d '{"max_budget":...}'`
"""
from __future__ import annotations

import os
from typing import Any, Optional

import requests


def issue_key(
    key_alias: str,                       # 예: "tree3.attacker" (tree × role)
    max_budget: Optional[float] = None,   # 이 카드의 달러 상한(직접 지정) — 또는 token_budget로 산정
    models: Optional[list[str]] = None,   # 허용 모델 화이트리스트
    rpm_limit: Optional[int] = None,
    tpm_limit: Optional[int] = None,
    budget_duration: Optional[str] = None,  # 예: "1h" (롤링 창)
    metadata: Optional[dict[str, Any]] = None,
    base_url: Optional[str] = None,
    master_key: Optional[str] = None,
    timeout: float = 20.0,
    token_budget: Optional[int] = None,       # DM-11 BudgetGrant.token_budget (토큰 단위)
    token_price_per_1k: float = 0.003,        # 토큰→USD 사상 단가(모델별, config에서 주입)
) -> str:
    """가상키(선불카드)를 발급받아 그 키 문자열을 돌려준다.

    2.2 Allocator 연동(DM-11): ``token_budget``(토큰)만 주면 ``max_budget``(USD)을
    ``token_budget/1000 * token_price_per_1k`` 로 결정론적으로 환산해 LiteLLM에 강제시킨다
    (FR-GW-02: token_budget 강제). ``max_budget``을 직접 주면 그 값을 우선한다.
    ``token_budget``도 metadata에 실어 감사 가능하게 한다."""
    base = (base_url or os.environ["LITELLM_API_BASE"]).rstrip("/")
    master = master_key or os.environ["SANITY_LITELLM_MASTER_KEY"]

    if max_budget is None:
        if token_budget is None:
            raise ValueError("issue_key: max_budget 또는 token_budget 중 하나는 반드시 지정해야 한다")
        max_budget = round(token_budget / 1000.0 * token_price_per_1k, 4)   # DM-11 → USD 강제
    if token_budget is not None:
        metadata = {**(metadata or {}), "token_budget": token_budget}       # 감사용 원본 토큰 예산

    body: dict[str, Any] = {"key_alias": key_alias, "max_budget": max_budget}
    if models:
        body["models"] = models
    if rpm_limit is not None:
        body["rpm_limit"] = rpm_limit
    if tpm_limit is not None:
        body["tpm_limit"] = tpm_limit
    if budget_duration:
        body["budget_duration"] = budget_duration
    if metadata:
        body["metadata"] = metadata

    resp = requests.post(
        f"{base}/key/generate",
        headers={"Authorization": f"Bearer {master}", "Content-Type": "application/json"},
        json=body,
        timeout=timeout,
    )
    resp.raise_for_status()
    key = resp.json().get("key")
    if not key:
        raise RuntimeError(f"/key/generate 응답에 key가 없음: {resp.text[:200]}")
    return key
