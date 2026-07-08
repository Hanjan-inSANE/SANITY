#!/usr/bin/env bash
set -e
cd ~/SANITY

echo "=== [1/7] 스택 내리기 ==="
( cd deploy && docker-compose down -v ) || true

echo "=== [2/7] client.py 패치 ==="
python3 - <<'PY'
p="gateway_log/src/sanity_llm/client.py"
s=open(p,encoding="utf-8").read()
if "return json.loads(cand)" not in s:
    if not s.endswith("\n"): s+="\n"
    s+='        try:\n            return json.loads(cand)\n        except Exception:\n            continue\n    raise ValueError("JSON parse failed")\n'
    open(p,"w",encoding="utf-8").write(s); print("client.py PATCHED")
else:
    print("client.py OK")
PY

echo "=== [3/7] config.yaml sane-local 추가 ==="
python3 - <<'PY'
import re
p="gateway_log/gateway/config.yaml"
s=open(p,encoding="utf-8").read()
if "model_name: sane-local" in s:
    print("sane-local OK")
else:
    m=re.search(r"model_name:\s*sane-sonnet.*?\n(\s*litellm_params:.*)\n", s, re.S)
    params=m.group(1).strip()
    block="  - model_name: sane-local\n    "+params+"\n\n"
    s=s.replace("litellm_settings:", block+"litellm_settings:",1)
    open(p,"w",encoding="utf-8").write(s); print("sane-local ADDED")
PY

echo "=== [4/7] 뷰어 override 생성 ==="
cat > deploy/docker-compose.override.yml <<'YAML'
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
echo "override OK"

echo "=== [5/7] 파이썬 이미지 3개 재빌드 ==="
docker build -t sanity_scenario_manager:latest -f sanity_scenario_manager/Dockerfile .
docker build -t sanity_attacker:latest     -f sanity_attacker/Dockerfile .
docker build -t sanity_defender:latest     -f sanity_defender/Dockerfile .

echo "=== [6/7] 기동 + gateway 대기 ==="
( cd deploy && docker-compose up -d )
ok=""
for i in $(seq 1 40); do
  code=$(curl -s -4 -o /dev/null -w "%{http_code}" http://127.0.0.1:4000/health/liveliness || true)
  echo "  gateway health try $i: $code"
  if [ "$code" = "200" ]; then ok=1; break; fi
  sleep 3
done
( cd deploy && docker-compose ps )
if [ -z "$ok" ]; then
  echo "!! gateway 200 실패. 원인 로그:"
  ( cd deploy && docker-compose logs --tail=30 gateway )
  exit 1
fi

echo "=== [7/7] 전체 SANITY 실행 (뷰어: http://localhost:8090) ==="
MK=$(grep -E '^SANITY_LITELLM_MASTER_KEY=' deploy/.env | cut -d= -f2)
SANITY_LITELLM_MASTER_KEY="$MK" SANITY_RAG_URL=http://100.95.158.13:9843 LITELLM_API_BASE=http://127.0.0.1:4000 REDIS_URL_BUS=redis://127.0.0.1:6379/0 python3 -m sanity_infra.dah.runner DVD.openxsampp.xml
