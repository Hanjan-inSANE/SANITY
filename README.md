# SANITY

무인이동체(UxV)를 대상으로 **위협모델링 → 자율 공격(PoV) → 자율 방어(패치·검증) → 제출**을 수행하는
에이전트 기반 자율 공방 시스템.

---

## 아키텍처

| # | 컴포넌트 | 패키지 | 역할 |
|---|----------|--------|------|
| 1 | Threat Modeler | `threat_modeler` | OpenXSAM++ DFD → RAG(ATT&CK/SPARTA/CVE/CWE) grounding → AND/OR 공격트리 생성 |
| 2 | Scenario Manager | `sanity_scenario_manager` | 트리를 실행 경로로 분해, 공격/방어 에이전트 오케스트레이션(트리당 1 인스턴스) |
| 3 | Attacker | `sanity_attacker` | 노드별 도구 선택·exploit·검증, 성공 시 PoV 생성 (crash / logic 클래스) |
| 4 | Defender | `sanity_defender` | 성공 공격에 대한 패치·하드닝 생성·적용·검증(무력화 ∧ 무회귀) |
| 5 | Attack-RAG | (외부 서비스) | 컴포넌트별 TTP/CVE/CWE 근거 검색 |
| 6 | LLM Gateway | `sanity_llm` (LiteLLM) | 모델 라우팅·가상키·예산 |
| 7 | Log | `sanity_log` | JSONL 이벤트 로깅(기록 전 시크릿 마스킹) |
| 8 | Toolset | `Toolset/Toolset` | MCP 도구 레지스트리·실행기·evidence ledger |
| 9 | Target | `sanity_infra/target` | DVD SITL 타겟 |
| 0 | DAH Runner | `sanity_infra/dah` | 위협모델러 실행 → 트리 발행 |

공용 인프라: State/Bus(Redis) · 관측/제어 웹 GUI(`tools/viewer.py`, `tools/control.py`).

```
DVD.openxsampp.xml
      │  (0) DAH Runner
      ▼
Threat Modeler(1) ──RAG(5)──▶ 공격트리 ──bus──▶ Scenario Manager(2)
                                                     │  가상키(6) 발급 + 동적 스폰
                                        ┌────────────┴────────────┐
                                        ▼                         ▼
                                   Attacker(3) ──Toolset(8)──▶  Target(9)
                                        │  PoV
                                        ▼
                                   Defender(4) ──patch/verify──▶ 제출
```

---

## 저장소 구조

```
SANITY/
├── threat_modeler/           # 1. 위협모델러 (공격트리 생성 엔진 + 웹 UI: index.html)
├── sanity_common/            # 공용 계약·버스·상태·ids·config·toolset 클라이언트
├── sanity_scenario_manager/  # 2. Scenario Manager (Allocator/Manager/TaskManager/Submitter)
├── sanity_attacker/          # 3. Attacker (LangGraph 에이전트)
├── sanity_defender/          # 4. Defender (LangGraph 에이전트)
├── sanity_infra/             # 0. DAH Runner + 9. Target(DVD SITL) 빌드 컨텍스트
├── gateway_log/              # 6. LLM Gateway 클라이언트 + 7. Log + LiteLLM 설정
├── Toolset/Toolset/          # 8. Toolset (MCP 서버·레지스트리·어댑터·mavlink/net 스크립트)
├── deploy/                   # docker-compose(+override/demo) · .env.example
├── tools/                    # viewer.py(관측), control.py(제어 GUI), sanity_dvd_attack.py(실물 DVD 드라이버)
├── docs/                     # QUICKSTART · RUN_NOW · FIXLOG
├── tests/                    # 통합 테스트
├── index.html                # threat_modeler 웹 UI
├── DVD.openxsampp.xml         # DVD 시스템 모델(OpenXSAM++)
├── pyproject.toml            # 루트 패키지(sanity_*)
└── requirements.txt          # 서드파티 의존(참조용)
```

---

## 요구사항

- Docker Engine + Docker Compose v2
- Python ≥ 3.11 (러너/도구를 호스트에서 실행할 경우)
- LLM 제공자 자격증명 1종 이상: Anthropic · OpenAI 호환 · Ollama Cloud
- (선택) Attack-RAG 서비스 엔드포인트 — 없으면 `SANITY_USE_RAG=0`으로 비활성

---

## 설치

로컬 모노레포 패키지는 **고정된 순서**로 editable 설치한다.

```bash
pip install -e ./gateway_log      # sanity_llm, sanity_log (6/7)
pip install -e ./threat_modeler   # threat_modeler (1)
pip install -e .                  # sanity_common + 2/3/4 + sanity_infra
```

서드파티 의존만 별도로 잡으려면 `pip install -r requirements.txt`를 함께 사용한다.
컨테이너 실행만 하는 경우 각 이미지의 Dockerfile이 위 설치를 수행하므로 호스트 설치는 러너/드라이버/도구 실행 시에만 필요하다.

---

## 구성

### 1. 모델 (`gateway_log/gateway/config.yaml`)

에이전트는 별칭 `sane-sonnet` / `sane-opus` / `sane-haiku`만 호출하고 LiteLLM이 실모델로 라우팅한다.
별칭 5종(`sane-sonnet`, `sane-opus`, `sane-haiku`, `sane-oai-fallback`, `sane-local`)은 모두 정의되어야 한다.
전 컴포넌트의 모델은 이 파일만 수정하면 바뀐다(코드 무변경).

```yaml
# 예: Anthropic Claude Sonnet 으로 통일
model_list:
  - { model_name: sane-sonnet,       litellm_params: { model: anthropic/claude-sonnet-4-5, api_key: os.environ/ANTHROPIC_API_KEY } }
  - { model_name: sane-opus,         litellm_params: { model: anthropic/claude-sonnet-4-5, api_key: os.environ/ANTHROPIC_API_KEY } }
  - { model_name: sane-haiku,        litellm_params: { model: anthropic/claude-sonnet-4-5, api_key: os.environ/ANTHROPIC_API_KEY } }
  - { model_name: sane-oai-fallback, litellm_params: { model: anthropic/claude-sonnet-4-5, api_key: os.environ/ANTHROPIC_API_KEY } }
  - { model_name: sane-local,        litellm_params: { model: anthropic/claude-sonnet-4-5, api_key: os.environ/ANTHROPIC_API_KEY } }
litellm_settings: { num_retries: 2, request_timeout: 600, drop_params: true }
general_settings: { master_key: os.environ/SANITY_LITELLM_MASTER_KEY, database_url: os.environ/DATABASE_URL }
```

Ollama Cloud Gemma로 바꾸려면 각 `litellm_params`를
`{ model: openai/gemma3:12b, api_base: os.environ/OLLAMA_CLOUD_BASE_URL, api_key: os.environ/OLLAMA_CLOUD_API_KEY }`로 지정한다.

### 2. 시크릿 (`deploy/.env`)

```bash
cp deploy/.env.example deploy/.env
```

| 키 | 용도 |
|----|------|
| `SANITY_LITELLM_MASTER_KEY` | LiteLLM 관리 마스터키(가상키 발급·게이트웨이 부팅) |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | 제공자 키(게이트웨이 컨테이너 전용) |
| `OLLAMA_CLOUD_BASE_URL` / `OLLAMA_CLOUD_API_KEY` | Ollama Cloud 사용 시 |
| `SANITY_RAG_URL` | Attack-RAG 엔드포인트(선택) |

프로바이더 실키는 **게이트웨이 컨테이너에만** 주입되며, 에이전트는 Allocator가 발급한 가상키만 사용한다.

---

## 실행

### 스택 기동

```bash
cd deploy
docker compose up -d
docker compose ps
```

생성 서비스: `redis`, `gateway`(LiteLLM), `gateway-db`(Postgres), `scenario-manager`,
`target-sitl-a`/`target-sitl-b`, `viewer`, `control-ui`.

동적 스폰되는 `sanity_attacker` / `sanity_defender`는 이미지가 사전 빌드되어 있어야 한다.

```bash
docker build -t sanity_attacker:latest -f sanity_attacker/Dockerfile .
docker build -t sanity_defender:latest -f sanity_defender/Dockerfile .
```

게이트웨이 상태 확인:

```bash
curl -f http://localhost:4000/health/liveliness
```

### 파이프라인 실행

DVD 모델을 위협모델러에 투입하면 트리가 생성되어 Scenario Manager로 발행되고, 노드별 에이전트가 스폰된다.

- **웹 GUI**: `http://localhost:8092`(Control)에서 `DVD.openxsampp.xml` 선택 후 실행. 진행 상황은
  같은 화면과 `http://localhost:8090`(Viewer)에서 노드별 공격(A)/방어(D) 상태로 관측된다.
- **CLI**:

  ```bash
  SANITY_LITELLM_MASTER_KEY=<master> \
  LITELLM_API_BASE=http://localhost:4000 \
  REDIS_URL_BUS=redis://localhost:6379/0 \
  REDIS_URL_STATE=redis://localhost:6379/1 \
  SANITY_USE_RAG=0 \
  python -m sanity_infra.dah.runner DVD.openxsampp.xml
  ```

### 위협모델러 단독 실행 (시나리오/트리 검토)

```bash
python -m threat_modeler serve --host 127.0.0.1 --port 8077
```

`http://localhost:8077`에서 OpenXSAM++ 모델 입력 → Derive(시나리오) → 공격트리 생성.
공격트리는 SVG/PNG로 내보낼 수 있다(`--out-svg-prefix`, `--png`; PNG는 `cairosvg` 필요).

---

## 실물 DVD 타겟 공격

컨테이너 내장 SITL 대신 실제 DVD 시뮬레이터를 대상으로 공격을 수행한다.

```bash
# 1) DVD 기동
git clone https://github.com/nicholasaleks/Damn-Vulnerable-Drone
cd Damn-Vulnerable-Drone && sudo ./start.sh --mode lite --no-wifi
# 웹 콘솔(http://localhost:8000)에서 Boot → Arm & Take-Off → Autopilot Flight

# 2) 공격트리를 redis에 적재(러너 1회 실행) 후, 드라이버 실행
docker run --rm --network simulator \
  -v sanity-logs:/logs -v "$PWD/tools":/t \
  -e LITELLM_API_BASE=http://gateway:4000 \
  -e REDIS_URL_STATE=redis://redis:6379/1 \
  -e SANITY_LITELLM_MASTER_KEY=<master> \
  -e SANITY_MAV_ENDPOINT=tcp:10.13.0.3:5760 \
  python:3.11-slim bash -c 'pip install -q pymavlink redis && python3 /t/sanity_dvd_attack.py'
```

`tools/sanity_dvd_attack.py`는 redis의 공격트리를 읽어 노드마다 LLM이 선택한 실제 MAVLink 공격을
드론에 발사하고, 전/후 텔레메트리로 성공 여부를 오라클 판정한다. 결과는 `sanity-logs` 볼륨에 기록되어
Control/Viewer GUI에 노드별로 표시된다.

---

## 모델 실험

`config.yaml`의 별칭 매핑을 교체하고 게이트웨이만 재시작하면 전 파이프라인 모델이 바뀐다.

```bash
docker compose restart gateway
```

동일 조건 비교 시 재실행 사이에 redis 상태를 초기화한다.

```bash
docker exec -i $(docker ps -qf name=redis) redis-cli -n 1 flushdb
```

---

## 테스트

```bash
python -m pytest threat_modeler/ tests/ -q
python -m pytest gateway_log/tests -q
python -m pytest sanity_common/tests -q
python -m pytest Toolset/Toolset/tests -q
```

---

## 포트

| 포트 | 서비스 |
|------|--------|
| 4000 | LLM Gateway (LiteLLM) |
| 6379 | Redis (bus db0 / state db1) |
| 8090 | Viewer GUI |
| 8092 | Control GUI |
| 8077 | Threat Modeler 웹 UI(단독 실행 시) |
| 8000 | DVD 웹 콘솔 |

---
