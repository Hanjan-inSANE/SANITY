# sanity_common/errors.py — 공용 예외 계층
"""SANITY 전 컴포넌트가 공유하는 예외 계층.

모든 SANITY 예외는 SanityError 를 상속한다 → 상위에서 `except SanityError` 하나로 포괄 가능.
컴포넌트별 세부 예외는 각 패키지에서 이 계층을 상속해 확장한다.
"""
from __future__ import annotations


class SanityError(Exception):
    """모든 SANITY 예외의 루트."""


class ConfigError(SanityError):
    """설정 로드/검증 실패 (§11 config)."""


class BusError(SanityError):
    """메시지 버스(Redis Streams) 관련 실패 (§5)."""


class StateError(SanityError):
    """State Store(Redis) 관련 실패 (§6)."""


class ToolsetError(SanityError):
    """Toolset(8) 호출 실패 — 봉투 ok=False 등 (§8)."""


class BudgetExhausted(SanityError):
    """토큰/레이트/wall-clock 예산 소진 (FR-SR-BUDGET-01/02, DM-11)."""


class MaxRetryExceeded(SanityError):
    """MAX_RETRY(기본 8) 초과 — 재시도 루프 종료 + FAIL 방출 (FR-SR-BUDGET-02)."""
