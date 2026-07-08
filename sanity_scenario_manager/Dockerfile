# sanity_scenario_manager/Dockerfile — 2. Scenario Manager 이미지
# ─────────────────────────────────────────────────────────────────────────────
# 빌드 컨텍스트 = 리포지토리 루트(SANITY/). 예:
#     docker build -f sanity_scenario_manager/Dockerfile -t sanity_scenario_manager:latest .
# compose 는 build.context=.. / build.dockerfile=이 파일 로 지정한다(deploy/docker-compose.yml).
# 이미지는 sanity_common(루트) · sanity_llm/sanity_log(gateway_log) · threat_modeler(threat_modeler) ·
#   Toolset(stdio 자식, /opt/Toolset)을 모두 포함한다(§00-2 토폴로지, §00-8.1).
# ⚠ SR-STACK-02: 프로바이더 키를 이미지에 주입하지 않는다. 가상키(Allocator 발급)만 사용.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir --upgrade pip

# 1) 모노레포 소스 복사(빌드 캐시 위해 의존 큰 것 먼저). Toolset 은 stdio PYTHONPATH 루트(/opt/Toolset)로.
COPY gateway_log/ /app/gateway_log/
COPY threat_modeler/ /app/threat_modeler/
COPY Toolset/Toolset/ /opt/Toolset/
COPY pyproject.toml /app/pyproject.toml
COPY sanity_common/ /app/sanity_common/
COPY sanity_scenario_manager/ /app/sanity_scenario_manager/

# 2) 설치 순서 고정(§00-1): gateway_log(6/7) → threat_modeler(threat_modeler=1) → 루트(sanity_*)
RUN pip install --no-cache-dir -e ./gateway_log
RUN pip install --no-cache-dir -e ./threat_modeler
RUN pip install --no-cache-dir -e .
# 3) 런타임 추가 의존: Allocator 동적 스폰용 docker SDK + Toolset 레지스트리(YAML) 파서.
#    (langgraph/langchain-core/mcp 등은 루트 pyproject dependencies 로 이미 설치됨)
RUN pip install --no-cache-dir docker pyyaml

# Toolset stdio 서버는 PYTHONPATH=TOOLSET_ROOT 에서 `python -m toolset_mcp.server` 로 뜬다(§00-8.5).
# cfg.toolset_root 기본값(/opt/Toolset)과 정합. compose 가 동일 값으로 override 한다.
ENV TOOLSET_ROOT=/opt/Toolset

# 엔트리(§02-2): sanity:tree:inbox 소비 → 트리당 ScenarioManager 스레드 스폰.
CMD ["python", "-m", "sanity_scenario_manager.main"]
