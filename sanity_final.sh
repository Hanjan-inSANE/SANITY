#!/usr/bin/env bash
set -e
cd ~/SANITY
RAG_URL="http://100.95.158.13:9843"
WANT_MODEL="gemma4:31b"

echo "############ [1/6] 소스 패치 ############"
python3 - <<'PY'
import re
def patch(path, old, new, marker, label):
    try: s=open(path,encoding="utf-8").read()
    except FileNotFoundError: print("  [없음]",label); return
    if marker in s: print("  [이미]",label); return
    if old not in s: print("  [!!못찾음]",label,path); return
    open(path,"w",encoding="utf-8").write(s.replace(old,new,1)); print("  [적용]",label)
p="gateway_log/src/sanity_llm/client.py"; s=open(p,encoding="utf-8").read()
if "return json.loads(cand)" not in s:
    if not s.endswith("\n"): s+="\n"
    s+='        try:\n            return json.loads(cand)\n        except Exception:\n            continue\n    raise ValueError("JSON parse failed")\n'
    open(p,"w",encoding="utf-8").write(s); print("  [적용] client.py")
else: print("  [이미] client.py")
patch("sanity_scenario_manager/main.py",
  '    bus.reclaim("sanity:tree:inbox", "g:scenario-manager", "sm-main")',
  '    bus.ensure_group("sanity:tree:inbox", "g:scenario-manager")\n    bus.reclaim("sanity:tree:inbox", "g:scenario-manager", "sm-main")',
  'bus.ensure_group("sanity:tree:inbox", "g:scenario-manager")', "SM ensure_group")
patch("sanity_scenario_manager/allocator.py",
  '        import docker\n        docker.from_env().containers.run(',
  '        import docker\n        _cli = docker.from_env()\n        _c = _cli.containers.run(',
  '_c = _cli.containers.run(', "allocator capture")
patch("sanity_scenario_manager/allocator.py",
  '''            name=f"{role}-{scope_id.replace(':','_')}", remove=True)''',
  '''            name=f"{role}-{scope_id.replace(':','_')}", remove=True)\n        try:\n            _cli.networks.get("target").connect(_c)\n        except Exception:\n            pass''',
  '_cli.networks.get("target").connect(_c)', "allocator target-net")
patch("sanity_defender/agent.py",
  '    workspace_root: str; mav_endpoint: str        # Attacker와 동일 workspace(crash) + 방어검증 SITL(logic)',
  '    workspace_root: str; mav_endpoint: str        # Attacker와 동일 workspace(crash) + 방어검증 SITL(logic)\n    gateway_url: str; _pov: dict; _target_files: list',
  '_pov: dict; _target_files: list', "defender channels")
patch("sanity_defender/main.py",
  '            workspace_root=p["workspace_root"], mav_endpoint=p["mav_endpoint"],  # Attacker와 동일 workspace',
  '            workspace_root=p["workspace_root"], mav_endpoint=p["mav_endpoint"], gateway_url=p["gateway_url"],  # Attacker와 동일 workspace',
  'gateway_url=p["gateway_url"], ', "defender init gateway_url")
patch("sanity_defender/verifier.py",
  '        cmp = _await(ts.diag("compare_baseline", {"workspace_root": ws,',
  '        _okc, cmp = _await(ts.sig("compare_baseline", {"workspace_root": ws,',
  '_okc, cmp = _await(ts.sig("compare_baseline"', "defender compare sig")
patch("sanity_attacker/executor.py",
  '            find = _await(ts.diag("collect_findings", {"workspace_root": ws, "fuzz_output_dir": fuzz_out, "trace_id": tid}))',
  '            _okf, find = _await(ts.sig("collect_findings", {"workspace_root": ws, "fuzz_output_dir": fuzz_out, "trace_id": tid}))',
  '_okf, find = _await(ts.sig("collect_findings"', "attacker collect sig")
p="gateway_log/gateway/config.yaml"; s=open(p,encoding="utf-8").read()
if "model_name: sane-local" not in s:
    m=re.search(r"model_name:\s*sane-sonnet.*?\n(\s*litellm_params:.*)\n", s, re.S)
    s=s.replace("litellm_settings:", "  - model_name: sane-local\n    "+m.group(1).strip()+"\n\nlitellm_settings:",1)
    open(p,"w",encoding="utf-8").write(s); print("  [적용] sane-local")
else: print("  [이미] sane-local")
PY

echo "############ [2/6] override ############"
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

echo "############ [3/6] 모델 ############"
OK_KEY=$(grep -E '^OLLAMA_CLOUD_API_KEY=' deploy/.env | cut -d= -f2)
resp=$(curl -s -m 25 https://ollama.com/v1/chat/completions -H "Authorization: Bearer $OK_KEY" -H "Content-Type: application/json" -d "{\"model\":\"$WANT_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" || true)
if echo "$resp" | grep -q '"content"'; then
  sed -i "s#model: openai/gemma[^,]*,#model: openai/$WANT_MODEL,#g" gateway_log/gateway/config.yaml
  echo "  모델 -> $WANT_MODEL"
else
  echo "  !! '$WANT_MODEL' 무효 → 기존 유지."
fi

echo "############ [4/6] 이미지 캐시무시 재빌드 ############"
( cd deploy && docker-compose build --no-cache scenario-manager )
docker build --no-cache -t sanity_attacker:latest -f sanity_attacker/Dockerfile .
docker build --no-cache -t sanity_defender:latest -f sanity_defender/Dockerfile .

echo "############ [5/6] 기동 + SM 부팅검증 ############"
( cd deploy && docker-compose down -v ) || true
( cd deploy && docker-compose up -d )
ok=""
for i in $(seq 1 50); do
  code=$(curl -s -4 -o /dev/null -w "%{http_code}" http://127.0.0.1:4000/health/liveliness || true)
  echo "  gateway health try $i: $code"; [ "$code" = "200" ] && { ok=1; break; }; sleep 3
done
[ -z "$ok" ] && { echo "!! gateway 실패"; ( cd deploy && docker-compose logs --tail=30 gateway ); exit 1; }
sleep 6
echo "  --- SM 부팅 로그 ---"
smlog=$( cd deploy && docker-compose logs --tail=15 scenario-manager )
echo "$smlog"
if echo "$smlog" | grep -q "Traceback"; then echo "!! SM 아직 죽음. 중단."; exit 1; fi
echo "  >>> SM 정상 부팅"
( cd deploy && docker-compose ps )

echo "############ [6/6] 실행 (뷰어 http://localhost:8090) ############"
MK=$(grep -E '^SANITY_LITELLM_MASTER_KEY=' deploy/.env | cut -d= -f2)
SANITY_LITELLM_MASTER_KEY="$MK" SANITY_RAG_URL="$RAG_URL" LITELLM_API_BASE=http://127.0.0.1:4000 REDIS_URL_BUS=redis://127.0.0.1:6379/0 python3 -m sanity_infra.dah.runner DVD.openxsampp.xml
