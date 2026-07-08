# SANITY — 브링업 디버깅 & 통합 로그 (FIXLOG)

이 문서는 SANITY를 실제로 기동하며 발견한 **런타임 버그·근본원인·수정**, 그리고 **새로 추가한 관측/제어 GUI와 실제 DVD 타겟 연동** 작업을 정리한다.
다른 팀원이 이어서 보고 수정할 수 있도록 파일 경로·증상·수정 코드를 함께 남긴다.

- 대상 환경: Kali Linux, Docker + docker compose v2, LLM = Ollama Cloud Gemma (LiteLLM 게이트웨이 경유)
- 타겟: **Damn Vulnerable Drone (DVD)** = nicholasaleks/Damn-Vulnerable-Drone (ArduPilot SITL/MAVLink)

---

## A. 코드 런타임 버그 (발견 → 수정)

각 항목: **파일 · 증상 · 근본원인 · 수정**.

### 1. `_extract_json` 함수가 잘려 있어 `import sanity_llm` 전체 실패
- 파일: `gateway_log/src/sanity_llm/client.py`
- 증상: `IndentationError: expected an indented block after 'for' statement on line 230`. `sanity_llm` import 시점에 터져 SM/attacker/defender 컨테이너가 부팅하자마자 죽음.
- 원인: 파일이 `for cand in (...):` 에서 본문 없이 잘림(생성 중 truncation 추정).
- 수정: for 루프 본문 복구 —
  ```python
  for cand in (t, re.sub(r",(\s*[}\]])", r"\1", t)):
      try:
          return json.loads(cand)
      except Exception:
          continue
  raise ValueError("JSON parse failed")
  ```

### 2. SM이 fresh redis에서 `NOGROUP`으로 부팅 즉시 크래시
- 파일: `sanity_scenario_manager/main.py`
- 증상: `redis.exceptions.ResponseError: NOGROUP ...` — `docker compose down -v` 직후(빈 redis) SM이 뜨자마자 죽음.
- 원인: `bus.reclaim(...)`(xautoclaim)을 **consumer group 생성 전에** 호출.
- 수정: reclaim 앞에 그룹 보장 —
  ```python
  bus.ensure_group("sanity:tree:inbox", "g:scenario-manager")
  bus.reclaim("sanity:tree:inbox", "g:scenario-manager", "sm-main")
  ```

### 3. bus consume가 블로킹 타임아웃/일시 끊김에 죽음
- 파일: `sanity_common/bus.py`
- 증상: `redis.exceptions.TimeoutError: Timeout reading from socket` — 트리 대기 중 SM 크래시.
- 원인: `xreadgroup(block=...)` 대기 중 소켓 타임아웃/재접속 예외를 안 잡음.
- 수정: consume 루프에서 `try/except (redis.exceptions.TimeoutError, redis.exceptions.ConnectionError): continue`.

### 4. LiteLLM `/key/generate` 400 — `sane-local` 별칭 누락
- 파일: `gateway_log/gateway/config.yaml`
- 증상: `400 Client Error: Bad Request for url: .../key/generate`.
- 원인: `cfg.gateway_models` 에 `sane-local`이 있는데 config.yaml `model_list`엔 정의 없음 → LiteLLM이 미정의 별칭 거부.
- 수정: `sane-local` 별칭을 다른 sane-* 와 동일 모델(Gemma)로 추가.

### 5. 러너 가상키 별칭 중복으로 재실행 시 400
- 파일: `sanity_infra/dah/runner.py`
- 증상: 첫 실행은 OK, 재실행 시 `/key/generate` 400.
- 원인: `key_alias="tm"` 고정. LiteLLM 키는 gateway-db(Postgres)에 영속되어 재실행 시 "이미 존재".
- 수정: `key_alias=f"tm-{int(time.time())}"` (매 실행 고유). *(SM Allocator의 scope별 키도 tree_id가 결정론적이라 재실행 시 충돌 → 근본적으로는 down -v 또는 별칭 고유화 필요. 아래 C.4 참고.)*

### 6. 트리 발행이 스트리밍이 아니라 일괄
- 파일: `sanity_infra/dah/runner.py`
- 증상: 6개 시나리오 트리가 **전부** 만들어진 뒤에야 SM에 넘어감(`[done]` 전까지 뷰어 빈 화면).
- 원인: `run_pipeline(...)`는 리스트 반환. 러너가 반환 리스트를 순회하며 끝에 발행.
- 수정: `run_pipeline`이 이미 제공하는 **`on_tree` 콜백**으로 트리 조립 즉시 발행(threat_modeler 무수정) —
  ```python
  def _on_tree(si, tr):
      bus.publish("sanity:tree:inbox", {"tree": tr.tree})
  run_pipeline(model, opts, config=config, on_tree=_on_tree)
  ```

### 7. Allocator `create_workspace` 인자 검증 실패로 스폰 스레드 사망
- 파일: `sanity_scenario_manager/allocator.py`
- 증상: SM 로그에 `RuntimeError: toolset toolset.create_workspace failure`. 트리는 소비되나 attacker가 안 뜸(스폰 스레드가 데몬이라 SM은 살아있고 조용함).
- 원인: `workspace_id=scope_id`(`"att:{tree}:r/0/1"`)에 `:`/`/` 포함. `create_workspace`는 `[A-Za-z0-9_-]`만 허용.
- 수정: 위생처리 — `{"workspace_id": scope_id.replace(":","_").replace("/","_")}`.
  - 추가: 스폰 컨테이너 이름도 `/` 포함 시 docker가 거부 → `name=f"{role}-{scope_id.replace(':','_').replace('/','_')}"`.

### 8. Allocator가 스폰 에이전트를 `target`(SITL) 네트워크에 안 붙임
- 파일: `sanity_scenario_manager/allocator.py` (`_spawn_container`)
- 증상: logic 클래스 공격이 SITL에 연결 불가.
- 원인: `network="control"`만 지정. SITL 타겟은 `target` 네트워크.
- 수정: 컨테이너 객체를 받아 target 네트워크에도 연결 —
  ```python
  _cli = docker.from_env()
  _c = _cli.containers.run(... network="control" ...)
  try: _cli.networks.get("target").connect(_c)
  except Exception: pass
  ```

### 9. Defender LangGraph 미선언 채널 → KeyError
- 파일: `sanity_defender/agent.py`
- 증상: 모든 defender 실행이 `KeyError: '_pov'`.
- 원인: `_pov`, `_target_files`, `gateway_url`가 `DefenderState` TypedDict에 미선언 → LangGraph가 노드 업데이트를 버림.
- 수정: `DefenderState`에 `gateway_url: str; _pov: dict; _target_files: list` 선언.

### 10. Defender init에 gateway_url 누락
- 파일: `sanity_defender/main.py`
- 증상: logic 방어 검증에서 `KeyError('LITELLM_API_BASE')`.
- 원인: dispatch에 `gateway_url`이 오는데 init state에 안 넣음 → GatewayClient가 env fallback 시도.
- 수정: init에 `gateway_url=p["gateway_url"]` 추가.

### 11. Defender `compare_baseline`를 `diag`로 호출(실패=예외)
- 파일: `sanity_defender/verifier.py`
- 원인: `compare_baseline`의 `"defense_failed"`는 정상 결과인데 `ts.diag`가 `ok=False`에 예외 → 재방어 경로 불능.
- 수정: `ts.sig`로 변경(`_okc, cmp = _await(ts.sig("compare_baseline", ...))`).

### 12. Attacker `collect_findings`를 `diag`로 호출(무크래시=예외)
- 파일: `sanity_attacker/executor.py`
- 원인: 퍼징이 크래시 못 찾으면 `ok=False`(정상)인데 `ts.diag`가 예외.
- 수정: `ts.sig`(`_okf, find = _await(ts.sig("collect_findings", ...))`).

---

## B. 배포/인프라 함정 (원인 → 해결)

### 1. Docker 빌드 캐시가 옛 truncated client.py를 계속 제공
- 증상: `--no-cache`로 재빌드해도 SM 이미지 안 client.py가 여전히 잘림.
- 원인 2가지:
  - **이미지 이름 불일치**: 수동 `docker build -t sanity_scenario_manager:latest`(언더스코어)는 compose가 쓰는 이미지가 아님. compose 서비스는 `sanity-scenario-manager`(하이픈) 이미지를 씀.
  - **buildkit 캐시**가 COPY 레이어를 stale하게 물고 있었음.
- 해결: `docker builder prune -af` 후 **compose로** 재빌드 —
  ```
  docker compose build --no-cache scenario-manager
  ```
  (attacker/defender는 Allocator가 `sanity_attacker:latest`/`sanity_defender:latest`로 스폰하므로 수동 `docker build --no-cache -t ...` 필요.)

### 2. `localhost`(IPv6) vs `127.0.0.1`
- 증상: host에서 gateway/redis로 `Connection refused`.
- 원인: `localhost`가 `::1`(IPv6)로 해석되는데 게시 포트는 IPv4에만 열림.
- 해결: 러너/스크립트 env에서 `LITELLM_API_BASE=http://127.0.0.1:4000`, `REDIS_URL_BUS=redis://127.0.0.1:6379/0`.

### 3. 재실행 시 키 별칭 충돌
- 원인: `tree_id`가 결정론적 해시 → Allocator scope 키 별칭이 재실행마다 동일 → LiteLLM 400.
- 해결(현재): 실행 전 `docker compose down -v`로 gateway-db 초기화. **TODO**: Allocator `_issue_key`도 실행별 nonce로 고유화.

### 4. 로그 볼륨을 host에서 못 읽음
- 원인: `sanity-logs`는 docker named volume. host의 viewer가 `./logs`를 보면 비어있음.
- 해결: viewer/control-ui를 **컨테이너로** 띄워 `sanity-logs` 볼륨을 마운트해서 읽음(`deploy/docker-compose.override.yml`).

---

## C. 새로 추가한 것 (관측 · 제어 · DVD 연동)

### 1. `deploy/docker-compose.override.yml`
- `viewer`(8090): 로그 뷰어(컨테이너, sanity-logs 마운트).
- `control-ui`(8092): 아래 control.py 를 host 네트워크로 구동(gateway/redis/RAG를 host처럼 접근), sanity-logs·sanity_infra·tools 마운트.
- `submissions` 볼륨 + gateway에 Ollama Cloud env 주입.

### 2. `tools/control.py` — 제어 GUI (http://localhost:8092)
- DVD 업로드 → Run(러너 서브프로세스 실행, RAG/트리 생성 콘솔 스트리밍).
- redis `st:tree:*`를 읽어 **시나리오→노드 트리** 렌더(클릭 가능), 노드별 공격(A)/방어(D) 상태 dot.
- 노드 클릭 시 상세: **summary / attack_context / evidence(CVE·CWE·ATT&CK) / AND·OR / 실시간 타임라인**.
- ⚠ 트리 필드명 주의: 노드 텍스트는 `label`이 아니라 **`summary`**, 공격설명 `attack_context`, 근거 `evidence`, 게이트 `logic`. 시나리오명 = 루트 노드 `summary`.
- Run/Reset 시 이전 로그·`st:tree:*`를 비워 **카운터 세션 초기화**.

### 3. 실제 DVD 타겟 연동 (진행 중)
- 기존 `sanity_infra/target/Dockerfile`은 **placeholder(`sleep infinity`)** — 실제 드론 아님(컴포넌트 9 미구현). 실제 타겟은 **DVD 프로젝트**를 별도 기동해 사용.
- DVD 구동(Lite, GPU 불필요): `git clone .../Damn-Vulnerable-Drone && sudo ./start.sh --mode lite --no-wifi`.
- DVD Lite 토폴로지: 네트워크 `simulator`(10.13.0.0/24). flight-controller-lite=`10.13.0.2`, companion=`10.13.0.3`(MAVLink UDP: 관측된 리스닝 14540, 17910–17913), GCS=`10.13.0.4`. 관리 콘솔 `http://localhost:8000`.
- `Toolset/Toolset/toolset_core/mavlink_dvd.py`: **실제 MAVLink 공격 + DVD-근거 오라클** (엔드포인트 자동탐색, pymavlink). 공격 action(set_mode/disarm/gps_inject/set_home/reposition/param_set/command_long) + `oracle(intent, before, after)` = 실제 텔레메트리 상태변화로 성공 판정.
- `tools/sanity_dvd_attack.py`: **단일 실행 드라이버** — SANITY 공격자 방식(트리 노드+RAG evidence+일반 도구목록만 보고 LLM이 도구 선택 → 진짜 MAVLink 공격 → 오라클 판정)을 실제 DVD에 실행, 결과를 SANITY 로그로 남김.
  - 실행: DVD의 `simulator` 네트워크 + SANITY `control` 네트워크에 함께 붙여야 함(gateway/redis + DVD 동시 접근).

### ⚠ 과학적 타당성 경계 (반드시 유지)
- attacker(LLM)는 **DVD wiki/시나리오 walkthrough/알려진 공격 스크립트/성공조건을 절대 보면 안 됨**. 입력은 오직: 공격트리 노드(summary/attack_context) + RAG evidence(ATT&CK/CVE/CWE) + 일반 도구목록.
- 성공/실패 판정(오라클)은 **DVD 명세 기반 실제 상태변화**로만 하고, 그 성공조건을 attacker 프롬프트에 유출하지 않음(오라클은 코드에만).

---

## D. 남은 작업 (다음 담당자)

1. `mavlink_dvd.py`의 실 MAVLink 도구/오라클을 **영속 attacker/defender 에이전트 그래프**에 정식 배선(현재는 `sanity_dvd_attack.py` 드라이버가 원리를 시연). Toolset MCP 도구 등록(`toolset_mcp/server.py` + `registry/tools.yaml`) + attacker executor(logic) + verifier 오라클 교체 + 이미지에 `pymavlink` 추가 + 재빌드.
2. DVD-Lite의 **정확한 GCS-facing MAVLink 엔드포인트 확정**(companion 10.13.0.3의 UDP; `simulator` 네트워크 안에서 프로브). `mavlink_dvd._CANDIDATES` 확정.
3. Allocator `_issue_key` 실행별 nonce 고유화(재실행 시 down -v 불필요하게).
4. DVD 시나리오 6범주별 오라클 성공조건 정밀화(Protocol Tampering / Injection / DoS / Exfiltration 등). Defender는 "실제 상태 복원" 검증으로.
5. 컴포넌트 9(`sanity_infra/target`)를 DVD 연동 어댑터로 정식화(placeholder 제거).

---

## E. 기동 요약 (현재 동작 순서)

```
# 1) SANITY
cd ~/SANITY/deploy && docker compose up -d           # gateway/redis/SM/viewer/control-ui
#    (모델 교체는 gateway_log/gateway/config.yaml 의 sane-* 별칭만 수정)
# 2) DVD (별도)
cd ~/Damn-Vulnerable-Drone && sudo ./start.sh --mode lite --no-wifi   # http://localhost:8000 에서 Arm & Takeoff
# 3) 제어 GUI: http://localhost:8092 → DVD 업로드 → Run (RAG→트리→공격/방어)
# 4) 실제 DVD 공격 드라이버(simulator+control 네트워크):
docker create --name sanity-dvd --network simulator -v sanity-logs:/logs -v ~/SANITY/tools:/t \
  -e LITELLM_API_BASE=http://gateway:4000 -e REDIS_URL_STATE=redis://redis:6379/1 \
  -e SANITY_LITELLM_MASTER_KEY="$(grep -E '^SANITY_LITELLM_MASTER_KEY=' ~/SANITY/deploy/.env | cut -d= -f2)" \
  python:3.11-slim bash -c 'pip install -q pymavlink redis; python3 /t/sanity_dvd_attack.py'
docker network connect control sanity-dvd
docker start -a sanity-dvd
```
