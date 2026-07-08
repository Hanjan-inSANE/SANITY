# RUN_NOW — 처음부터 깨끗하게 전체 SANITY 돌려 눈으로 보기

**리포를 다시 clone 하지 말 것** (→ .env 키 소실 + client.py 버그 재발).
아래는 기존 `~/SANITY`에서 스택만 깨끗이 내렸다 올리는 절차. 각 STEP 확인 포인트 통과 후 다음으로.

전제(이미 완료): Gateway+Gemma 동작, `deploy/.env`에 master key/Ollama 키, `config.yaml` = Gemma.
RAG 서버(5) = `http://100.95.158.13:9843` (당신 Tailscale).

터미널 2개: (T1) 빌드·기동·러너, (T2) 로그 관찰. 뷰어는 이제 컨테이너라 따로 실행 안 함.

---

## STEP 1 (T1) — 스택 내리기(깨끗이 시작)
```
cd ~/SANITY/deploy && docker-compose down
```
(컨테이너만 정리. 이미지·볼륨·.env 는 보존.)

## STEP 2 (T1) — 뷰어/제출 볼륨을 붙이는 override 생성 (한 번만; 재실행 안전)
```
cat > ~/SANITY/deploy/docker-compose.override.yml <<'YAML'
services:
  gateway:
    environment:
      OLLAMA_CLOUD_BASE_URL: ${OLLAMA_CLOUD_BASE_URL:-https://ollama.com/v1}
      OLLAMA_CLOUD_API_KEY: ${OLLAMA_CLOUD_API_KEY:-}
  scenario-manager:
    volumes:
      - "submissions:/submissions"
  viewer:
    image: python:3.11-slim
    command: ["python3", "/app/tools/viewer.py"]
    ports: ["8090:8090"]
    environment:
      SANITY_LOG_DIR: /logs
      SANITY_SUB_DIR: /submissions
    volumes:
      - "sanity-logs:/logs:ro"
      - "submissions:/submissions:ro"
      - "../tools:/app/tools:ro"
    networks: [control]
volumes:
  submissions:
    name: submissions
YAML
echo "override written"
```

## STEP 3 (T1) — client.py 패치 확인(이미 됐으면 ALREADY OK; 안전)
```
python3 - <<'PY'
p="/home/Doom07/SANITY/gateway_log/src/sanity_llm/client.py"
s=open(p,encoding="utf-8").read()
if "return json.loads(cand)" not in s:
    if not s.endswith("\n"): s+="\n"
    s+='        try:\n            return json.loads(cand)\n        except Exception:\n            continue\n    raise ValueError("JSON parse failed")\n'
    open(p,"w",encoding="utf-8").write(s); print("PATCHED")
else:
    print("ALREADY OK")
PY
```

## STEP 4 (T1) — 파이썬 이미지 3개 재빌드 (패치 반영; 캐시라 빠름)
```
cd ~/SANITY && docker build -t sanity_scenario_manager:latest -f sanity_scenario_manager/Dockerfile . && docker build -t sanity_attacker:latest -f sanity_attacker/Dockerfile . && docker build -t sanity_defender:latest -f sanity_defender/Dockerfile .
```
- ✅ 세 개 다 `Successfully tagged ... :latest` 로 끝나면 OK.

## STEP 5 (T1) — 전체 스택 기동 (redis/gateway/SM/target + 뷰어)
```
cd ~/SANITY/deploy && docker-compose up -d && sleep 20 && docker-compose ps
```
- ✅ `redis / gateway(healthy) / gateway-db / scenario-manager / target-sitl-a / target-sitl-b / viewer` 전부 Up 이면 OK.

## STEP 6 — 뷰어 열기 (그냥 브라우저만; sudo 불필요)
브라우저에서 **http://localhost:8090** — 아직 비어 있으면 정상(트리 주입 전).

## STEP 7 (T1) — 전체 SANITY 가동 = RAG→트리→공격→방어
```
cd ~/SANITY && MK=$(grep -E '^SANITY_LITELLM_MASTER_KEY=' deploy/.env | cut -d= -f2) && SANITY_LITELLM_MASTER_KEY="$MK" SANITY_RAG_URL=http://100.95.158.13:9843 LITELLM_API_BASE=http://localhost:4000 REDIS_URL_BUS=redis://localhost:6379/0 python3 -m sanity_infra.dah.runner DVD.openxsampp.xml
```
- T1에 RAG enrich → 시나리오 → "tree assembled" 로그가 뜸(= TM 정상).
- 각 "tree assembled" 시 트리가 redis로 발행 → SM이 소비 → 공격/방어 시작.

## STEP 8 (T2) — 흐름 관찰
- **브라우저 http://localhost:8090 새로고침** → 노드가 뜨고 공격/방어 상태로 색이 변함.
- 원문 로그:
```
cd ~/SANITY/deploy && docker-compose logs -f scenario-manager
```
→ 트리 수신 → 경로 분해 → attacker/defender 컨테이너 스폰 로그.

---

## 자주 나는 문제
- **뷰어가 비어있다** → 트리 주입(STEP 7) 전이면 정상. 주입 후에도 비면 `docker-compose logs viewer` 로 뷰어 컨테이너 상태 확인.
- **KeyError: SANITY_LITELLM_MASTER_KEY** → STEP 7의 `MK=...` 앞부분 빠뜨린 것. 통째로 복붙할 것.
- **runner가 import 에러** → STEP 3 패치 안 된 것.
- **공격이 타겟에 안 붙음** → target-sitl-a/b Up 인지 `docker-compose ps` 확인.
