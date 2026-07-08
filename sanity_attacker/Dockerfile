# sanity_attacker/Dockerfile — 3. Attacker 이미지 (Allocator가 동적 스폰: image=sanity_attacker:latest)
# ─────────────────────────────────────────────────────────────────────────────
# 빌드 컨텍스트 = 리포지토리 루트(SANITY/). 예:
#     docker build -f sanity_attacker/Dockerfile -t sanity_attacker:latest .
# 이미지는 sanity_common(루트) · sanity_llm/sanity_log(gateway_log) · threat_modeler(threat_modeler) ·
#   Toolset(stdio 자식, /opt/Toolset)을 포함한다(§00-2 토폴로지, §00-8.1).
# ⚠ SR-STACK-02: 프로바이더 키를 이미지에 주입하지 않는다. dispatch 의 budget.virtual_key 만 사용.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir --upgrade pip

# 1) 모노레포 소스 복사. Toolset 은 stdio PYTHONPATH 루트(/opt/Toolset)로.
COPY gateway_log/ /app/gateway_log/
COPY threat_modeler/ /app/threat_modeler/
COPY Toolset/Toolset/ /opt/Toolset/
COPY pyproject.toml /app/pyproject.toml
COPY sanity_common/ /app/sanity_common/
COPY sanity_attacker/ /app/sanity_attacker/

# 2) 설치 순서 고정(§00-1): gateway_log(6/7) → threat_modeler(threat_modeler=1) → 루트(sanity_*)
RUN pip install --no-cache-dir -e ./gateway_log
RUN pip install --no-cache-dir -e ./threat_modeler
RUN pip install --no-cache-dir -e .
# 3) 런타임 추가 의존: Toolset 레지스트리(YAML) 파서. (langgraph/mcp 등은 루트 deps 로 설치됨)
RUN pip install --no-cache-dir pyyaml

# Toolset stdio 서버 PYTHONPATH(§00-8.5). Allocator 가 동적 스폰 시 동일 값을 env 로 주입한다(§02-5.5).
ENV TOOLSET_ROOT=/opt/Toolset

# 엔트리(§03-2): SANITY_SCOPE_ID(env)로 dispatch:attacker:{scope_id} 1건 소비 → 그래프 1회 실행 후 종료.
CMD ["python", "-m", "sanity_attacker.main"]
