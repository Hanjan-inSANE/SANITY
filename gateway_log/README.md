# gateway_log — 수연 파트 (6. LLM Gateway + 7. Log)

이 폴더가 **수연이 맡은 두 컴포넌트(6·7)의 실제 구현물**이다.
설계 근거: `../SANITY_6_7_설계명세_LLMGateway_Log.md` (v1.1).

---

## 0. 한눈에

- **6. LLM Gateway** = 우리 AI 일꾼들이 외부 AI(Claude)를 쓰러 나가는 **유일한 통제 창구**.
  실체는 **LiteLLM 프록시**(직접 만들지 않고 설정만 함) + 에이전트가 쓰는 얇은 **클라이언트 라이브러리**.
- **7. Log** = 일어난 모든 일을 **한 줄씩 append**하는 일지(JSONL).

---

## 1. 폴더 구조

```
gateway_log/
├─ gateway/                 # 6. 창구 배치물 (코드가 아니라 "설정 + 배포")
│  ├─ config.yaml           #   창구 규칙표: 모델 메뉴, 재시도, 예산 등
│  ├─ docker-compose.yml    #   창구 실행: LiteLLM 프록시 + Postgres
│  └─ .env.example          #   키/주소 템플릿 (복사해서 .env 로)
├─ src/
│  ├─ sanity_llm/           # 6. 에이전트가 쓰는 클라이언트 라이브러리
│  │  ├─ client.py          #   ★ 창구 경유 AI 호출 + 폴백 + 자동로그 + JSON수리
│  │  ├─ budget.py          #   선불카드(가상키) 발급 함수 (2.2 대행 stub)
│  │  └─ errors.py          #   실패 종류 분류(rate/context/content...)
│  └─ sanity_log/           # 7. 로그 라이브러리
│     ├─ schema.py          #   로그 한 줄의 모양(Event, LLMCallRecord)
│     ├─ writer.py          #   ★ append-only JSONL 기록기(프로세스별 파일)
│     └─ mask.py            #   비밀번호/키 가리기
└─ tests/
   └─ test_log.py           # 로그 기본 테스트 (AI·도커 없이 실행 가능)
```

★ = 가장 중요한 두 파일.

---

## 2. 어떻게 맞물리나 (그림)

```
[에이전트]  --import-->  sanity_llm.GatewayClient
    |                         |
    | complete("sane-sonnet", ...)      (선불카드=가상키로 요청)
    v                         v
   6. LiteLLM 프록시(gateway/) ---> 외부 AI(Claude/GPT)
    |                         ^
    | (호출 결과)              | (진짜 키는 프록시만 보유)
    v
 sanity_log.LogWriter  --->  logs/comp3.*.jsonl   (7. 일지)
```

- 에이전트는 `GatewayClient` 하나만 쓰면 된다. 그 안에서 창구 호출 + 로그가 자동으로 된다.
- 진짜 프로바이더 키는 **프록시(도커)만** 가진다. 에이전트는 가상키+주소만.

---

## 3. 실행 순서 (이대로 따라 하면 됨)

### (A) 지금 당장, AI·도커 없이 — 7번 로그부터 확인
```bash
cd gateway_log
PYTHONPATH=src python tests/test_log.py       # → ALL PASS 나오면 성공
```

### (B) 6번 창구 띄우기 (V-GW-0 스모크 테스트)
```bash
cd gateway_log/gateway
cp .env.example .env        # .env 열어서 ANTHROPIC_API_KEY, MASTER_KEY 채우기
docker compose --env-file .env up -d
curl -f http://localhost:4000/health/liveliness         # 200 나오면 창구 살아있음
# 선불카드(가상키) 발급 테스트:
curl -s http://localhost:4000/key/generate \
  -H "Authorization: Bearer $SANITY_LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key_alias":"tree3.attacker","max_budget":25,"models":["sane-sonnet","sane-haiku"]}'
```
> 여기서 막히면(이미지 entrypoint/DB 문제 등) `docker compose logs litellm` 으로 원인 확인 후
> `docker-compose.yml`을 정정한다. **이 단계 통과가 "창구가 돈다"의 기준(V-GW-0).**

### (C) 클라이언트로 실제 AI 호출 (창구가 뜬 뒤)
```bash
pip install openai requests
export LITELLM_API_BASE=http://localhost:4000
export LITELLM_API_KEY=<위에서 받은 가상키>
```
```python
from sanity_llm import GatewayClient
from sanity_log import LogWriter

log = LogWriter(component="3")
gw = GatewayClient(component="3", log=log)
res = gw.complete("sane-sonnet", user="한 문장으로 자기소개",
                  trace_id="demo1", scope_id="tree3.node7.attacker")
print(res.text, "| 비용:", res.cost_usd)
log.close()
# → logs/comp3.*.jsonl 에 호출 기록이 남는다
```

### (D) 위협모델러(threat_modeler) 연결 (6의 첫 실물 작업)
- `threat_modeler/llm.py`가 지금은 프로바이더를 직접 부른다.
- 그걸 `GatewayClient` 경유로 바꾸면 끝(설계 §2.9). 최소 변경으로 창구 뒤로 들어간다.

---

## 4. 지금 상태 / 다음

- ✅ **7. Log**: 동작 확인됨(테스트 통과). schema/writer/mask 완성.
- ✅ **6. Gateway 클라이언트**: 작성 완료(`openai` 설치 후 사용).
- ⏳ **6. Gateway 창구**: (B) V-GW-0 스모크로 실기동 확인 필요(도커·키 필요).
- ⏳ **web_search**: `sane-ground`가 창구를 통과하는지 실측(V-GW-5). 근본해소는 RAG 이전.
- ⏳ **2.2 연결**: `budget.issue_key`가 대행 중. 2.2 담당 정해지면 그쪽에서 호출.

---

## 5. 미결(설계 §6과 동일)

1. compose 실기동(V-GW-0) — 실제 도커로 확인.
2. web_search의 LiteLLM 통과(V-GW-5).
3. 실제 예산/RPM·TPM 수치 — 대회 공개 후 config 주입.
4. key-scope 입도((tree×role)) 와 Log↔EvidenceLedger 미러 계약 — 리드/광수와 확정.
