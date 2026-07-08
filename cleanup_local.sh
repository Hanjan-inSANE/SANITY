#!/usr/bin/env bash
# 로컬 물리 정리 — 당신 컴퓨터(권한 있음)에서 한 번만 실행.
# (Cowork 마운트는 파일 삭제가 막혀 있어 여기서 대신 캐시/빌드 산출물을 실제로 지운다.)
# ⚠ deploy/.env(비밀)는 건드리지 않는다. 이 스크립트는 재실행해도 안전(idempotent).
set +e
cd "$(dirname "$0")" || exit 1
echo "정리 위치: $(pwd)"

# 파이썬 캐시 / 빌드 산출물
find . -type d -name '__pycache__'  -exec rm -rf {} + 2>/dev/null
find . -type d -name '*.egg-info'   -exec rm -rf {} + 2>/dev/null
rm -rf .pytest_cache .mypy_cache .ruff_cache 2>/dev/null

# 개발 중 남은 잔여물
rm -rf SANITY_IMPL_GUIDE 2>/dev/null          # 내용은 _archive_dev / docs / tools 로 이미 이동됨
rm -f  threat_modeler/__wtest.md 2>/dev/null   # 개발용 임시 파일

echo "완료. 남은 캐시/egg-info: $(find . -type d \( -name __pycache__ -o -name '*.egg-info' \) 2>/dev/null | wc -l) 개"
echo "※ deploy/.env 는 보존됨(비밀). github에는 .gitignore 로 자동 제외됨."
