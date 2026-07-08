# SANITY 빠른 실행 (QUICKSTART) — 완전 초보자용, 따라만 하세요

> 목표: **컴퓨터 준비 → SANITY + DVD 올리기 → 공격·방어를 눈으로 확인.**
> 위에서 아래로 **한 줄씩 복붙**하고, 각 단계의 **✅(이게 보이면 성공)** 만 확인하고 다음으로 가세요.
> 명령 앞의 `$` 는 "여기부터 붙여넣기"라는 표시입니다(`$`는 빼고 붙이세요).
> 모델은 **Ollama Cloud Gemma**로 설정돼 있습니다.
>
> ⚠ 전제: SANITY 컴포넌트 코드(세션 0~3, `_archive_dev/SESSION_PROMPTS.md`)가 이미 구현돼 있어야 합니다. 아직이면 그것부터.

---

## STEP 0 — 어떤 컴퓨터가 필요한가 (그리고 어떻게 구하나)

SANITY는 도커 여러 개(창구·드론 시뮬레이터·에이전트)를 돌리므로 **리눅스 + 넉넉한 사양**이 필요합니다.

**사양 (목적별):**
| 목적 | vCPU | RAM | 디스크 |
|---|---|---|---|
| "일단 돌아가는지" 데모 | 4 | 16GB | 60GB |
| 제대로 실험(퍼징 포함) | 16+ | 32GB+ | 100GB+ |

> LLM(Gemma)은 **클라우드(Ollama)**가 돌리므로 GPU는 필요 없습니다. CPU/RAM만 있으면 됩니다.

**컴퓨터 구하는 3가지 방법 — 하나만 고르세요:**

**(방법 1) 클라우드 VM 빌리기 — 가장 쉬움, 추천.**
아무 클라우드(AWS EC2 / GCP / Azure / Vultr / Lambda 등)에서:
- **이미지**: Ubuntu Server **22.04 LTS**
- **크기**: 데모면 4 vCPU/16GB, 실험이면 16 vCPU/32GB (예: AWS `m5.4xlarge`, GCP `e2-standard-16`)
- **디스크**: 60~100GB
- 만들 때 **SSH 키**를 받아두고, 방화벽에서 **22번(SSH)** 허용.
- 내 노트북 터미널에서 접속:
  ```
  $ ssh -i 내키.pem ubuntu@<서버_공인IP>
  ```
  (윈도우면 PowerShell이나 PuTTY로 동일하게)

**(방법 2) 내 리눅스 PC가 이미 있으면** 그 위에서 그대로 진행. 터미널만 열면 됩니다.

**(방법 3) 윈도우 PC면 WSL2**로 리눅스를 켜기 (PC가 16GB+ RAM일 때):
  ```
  # 윈도우 PowerShell(관리자)에서 한 번:
  wsl --install -d Ubuntu-22.04
  # 재부팅 후 "Ubuntu 22.04" 앱 실행 → 아래부터 리눅스 명령
  ```

**✅ 이게 되면 성공:** 리눅스(우분투 22.04) 터미널에 프롬프트가 떠 있고, `$ whoami` 가 사용자 이름을 출력.

---

## STEP 1 — Docker 설치 (한 번만)

우분투 터미널에서 그대로 복붙:
```
$ curl -fsSL https://get.docker.com | sudo sh
$ sudo usermod -aG docker $USER
$ newgrp docker          # (또는 로그아웃 후 재접속) — 이래야 sudo 없이 docker 사용
```
확인:
```
$ docker version
$ docker compose version
```
**✅ 이게 보이면 성공:** 두 명령이 버전 숫자를 출력(예: `Docker version 27...`, `Docker Compose version v2...`).
Python도 확인(우분투 22.04엔 기본 있음):
```
$ python3 --version && pip3 --version || sudo apt-get update && sudo apt-get install -y python3-pip
```

---

## STEP 2 — SANITY 코드 가져오기

프로젝트 폴더를 이 서버로 올립니다. **둘 중 하나:**

**(A) git이면:**
```
$ git clone <당신의_SANITY_저장소_주소> SANITY
$ cd SANITY
```
**(B) 내 PC의 SANITY 폴더를 서버로 복사(방법 1 클라우드일 때):**
```
# 내 노트북 터미널에서:
$ scp -i 내키.pem -r /path/to/SANITY ubuntu@<서버IP>:~/SANITY
# 그다음 서버에서:
$ cd ~/SANITY
```
**✅ 이게 보이면 성공:** `$ ls` 하면 `threat_modeler  gateway_log  Toolset  SANITY_IMPL_GUIDE  deploy  DVD.openxsampp.xml` 등이 보임.

---

## STEP 3 — 파이썬 패키지 설치 (한 번만)

SANITY 리포 루트(`~/SANITY`)에서 **순서대로**:
```
$ pip3 install -e ./gateway_log        # 6.Gateway·7.Log (sanity_llm, sanity_log)
$ pip3 install -e ./threat_modeler        # 1.위협모델러 (threat_modeler)
$ pip3 install -e .                    # sanity_common + 2/3/4 컴포넌트
```
**✅ 이게 보이면 성공:**
```
$ python3 -c "import sanity_common, sanity_llm, sanity_log, threat_modeler; print('import OK')"
```
가 `import OK` 출력. (에러 나면 STEP 2에서 코드가 다 왔는지, 순서를 지켰는지 확인.)

---

## STEP 4 — 키 채우기 (2분)

```
$ cp gateway_log/gateway/.env.example deploy/.env
$ nano deploy/.env        # 편집기(Ctrl+O 저장, Ctrl+X 종료)
```
아래 **두 줄만** 실제 값으로 바꿉니다:
```
SANITY_LITELLM_MASTER_KEY=아무거나-강한-랜덤-문자열-여기에
OLLAMA_CLOUD_API_KEY=여기에-Ollama-Cloud-키
```
> 마스터키는 아무 문자열이나 강하게(예: `$ openssl rand -hex 24` 결과를 붙여넣기). Ollama 키는 https://ollama.com 계정에서 발급.

그리고 **Gemma 모델 태그 확인** — `gateway_log/gateway/config.yaml` 안의 `gemma3:4b` 를 **당신 Ollama Cloud 계정이 실제 쓸 수 있는 태그**로. 모르면 STEP 6에서 확인 후 고쳐도 됩니다.

**✅ 이게 되면 성공:** `deploy/.env` 에 두 값이 채워짐.

---

## STEP 5 — (선택, 1분) 도구 설치 확인

crash 실험용 CLI(빌드·디버거)가 있는지 빠르게:
```
$ python3 Toolset/Toolset/env/check_environment.py --priority P0
```
**✅:** cmake/clang/gdb 등이 `available`. `missing` 이 많으면:
```
$ bash Toolset/Toolset/env/install-ubuntu.sh
```

---

## STEP 6 — 창구(Gateway) 켜고 Gemma 연결 확인 (3분)

```
$ cd deploy
$ docker compose --env-file .env up -d gateway gateway-db
$ sleep 25
$ curl -f http://localhost:4000/health/liveliness       # 200이면 창구 살아있음
```
Gemma가 실제로 답하는지:
```
$ export MK=$(grep SANITY_LITELLM_MASTER_KEY .env | cut -d= -f2)
$ export KEY=$(curl -s http://localhost:4000/key/generate \
   -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
   -d '{"key_alias":"smoke","models":["sane-sonnet"]}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"])')
$ curl -s http://localhost:4000/chat/completions -H "Authorization: Bearer $KEY" \
   -H "Content-Type: application/json" \
   -d '{"model":"sane-sonnet","messages":[{"role":"user","content":"say hi in 3 words"}]}'
```
**✅ 이게 보이면 성공:** 마지막 명령이 Gemma의 짧은 답을 반환.
**❌ `model not found`:** `config.yaml`의 `gemma3:4b`를 실제 태그로 고치고 → `$ docker compose restart gateway` → 다시.

---

## STEP 7 — 엔진 2분 스모크: "공격·방어가 실제로 닫히나"

DVD를 올리기 전, Toolset이 사는지 가장 빠르게 확인(가장 확실한 성공 신호):
```
$ cd ..     # 리포 루트로
$ python3 -m pytest Toolset/Toolset/tests/test_golden_contract.py -q
```
**✅ 이게 보이면 성공:** 테스트 통과(`passed`) → crash 공격·방어 파이프라인 계층이 산다.

---

## STEP 8 — DVD + SANITY 전체 올리기 (5분)

**드론을 눈으로 볼 거면 (권장)** — 관측 오버레이까지 함께:
```
$ cd deploy
$ docker compose -f docker-compose.yml -f docker-compose.demo.yml --env-file .env up -d
```
(격리만 유지하고 볼 필요 없으면 `docker compose --env-file .env up -d`)

상태 확인:
```
$ docker compose ps
$ docker compose logs target-sitl-a | tail    # ArduPilot SITL(=DVD) 부팅 로그
```
**✅ 이게 보이면 성공:** 모든 서비스 `running`, `target-sitl-a` 부팅 로그가 보임.

---

## STEP 9 — 눈으로 볼 준비 (뷰어 + 드론화면)

### (C) SANITY 흐름 뷰어 — 어느 노드에서 공격/방어가 되는지
새 터미널에서(리포 루트):
```
$ python3 tools/viewer.py
```
브라우저에서 **http://localhost:8090** 열기.
> ⚠ **클라우드 서버(방법 1)면** 내 노트북에서 이 포트를 봐야 하니, 노트북 터미널에서 터널을 하나 여세요:
> ```
> $ ssh -i 내키.pem -L 8090:localhost:8090 -L 5760:localhost:5760 ubuntu@<서버IP>
> ```
> 그러면 노트북 브라우저에서 `localhost:8090` 이 서버 뷰어를 보여줍니다.

### (A) QGroundControl — 드론 자체 반응(arm/모드/위치)
- 내 노트북에 **QGroundControl** 설치(무료).
- 앱 설정 → Comm Links → Add → **TCP**, Host `127.0.0.1`, Port `5760`(공격용) → Connect.
  (위 SSH 터널로 5760이 노트북까지 넘어와 있어야 함. 방법 2/3처럼 서버=내PC면 바로 됨.)

**✅:** 뷰어 페이지가 뜨고(아직 비어 있음 정상), QGC가 SITL에 연결돼 드론이 보임.

---

## STEP 10 — 실행! (핵심 한 줄)

또 다른 터미널에서(리포 루트):
```
$ python3 -m sanity_infra.dah.runner DVD.openxsampp.xml
```
이 순간부터 자동으로: **위협모델링 → 공격트리 → 공격자 스폰·공격 → 성공 시 방어자 스폰·방어·검증 → 제출.**

**이제 눈으로:**
- **뷰어(localhost:8090)**: 트리 노드의 `A`(공격)·`D`(방어) 점이 **회색→파랑(진행)→초록(성공)/빨강(실패)**로 실시간 변함. 하단에 공격·방어 이벤트가 흐름.
- **QGC**: 로직 공격이 들어가면 드론의 arm/모드/GPS 위치가 실제로 바뀜.
- 텍스트로도 보고 싶으면: `$ tail -f logs/comp*.jsonl`

**✅ 이게 보이면 성공(엔진이 돈다):** 뷰어에 노드가 생기고 점 색이 바뀌며, `docker ps` 에 `attacker-*`/`defender-*` 컨테이너가 떴다 사라짐.

---

## STEP 11 — 결과 확인

```
$ ls -la submissions/                         # 성공한 공격/방어 번들
$ cat submissions/*.json | python3 -m json.tool | head -40
$ grep -c '"state": "SUCCESS"' logs/comp*.jsonl   # 성공 이벤트 수
```
**✅ 최종 성공:** `submissions/` 에 번들이 최소 1개.

---

## STEP 12 — "잘 됐나?" 체크리스트

- [ ] STEP1: `docker compose version` 출력
- [ ] STEP3: `import OK`
- [ ] STEP6: Gemma가 답함
- [ ] STEP7: 골든 테스트 통과
- [ ] STEP8: `target-sitl-a` running
- [ ] STEP10: 뷰어에서 노드 색이 바뀜
- [ ] STEP11: `submissions/` 에 번들

전부 되면 **SANITY가 DVD 상대로 실제로 돌아간 것**입니다. 🎉

---

## 문제 해결 (자주 나오는 것)

| 증상 | 조치 |
|---|---|
| `docker: permission denied` | STEP1의 `newgrp docker` 안 함 → 재접속 또는 `newgrp docker` |
| Gateway `model not found` | `config.yaml`의 `gemma3:4b`→실제 태그, `docker compose restart gateway` |
| `import threat_modeler`/`sanity_common` 실패 | STEP3 세 줄을 **순서대로** 다시 |
| 뷰어가 빈 화면 | 아직 트리 인입 전이면 정상. runner 실행 후 새로고침 |
| 클라우드에서 localhost:8090 안 열림 | STEP9의 SSH 터널(`-L 8090:localhost:8090`) 필요 |
| QGC 연결 안 됨 | 5760 포트 터널(`-L 5760:localhost:5760`) + demo 오버레이로 up 했는지 |
| SUCCESS가 0개 | **정상일 수 있음** — Gemma 4B는 JSON·패치 품질이 낮아 실패율↑. 엔진 검증엔 문제없음(품질은 나중에 sonnet으로 비교). |

---

## 끝내기 / 정리

```
$ cd deploy
$ docker compose -f docker-compose.yml -f docker-compose.demo.yml down    # 스택 내리기
# 뷰어/터널은 각 터미널에서 Ctrl+C
```

---

### 3줄 요약
```
STEP0~2  컴퓨터·Docker·코드 준비
STEP3~7  pip 설치 → 키 → Gateway/Gemma 확인 → 엔진 스모크
STEP8~11 docker compose up(+demo) → viewer & QGC → runner 실행 → submissions 확인
```
> 솔직히: Gemma 4B로는 **"파이프라인이 끝까지 도는가"** 를 보는 게 목적입니다. 실제 취약점 발견·방어 성공률은
> 낮을 수 있고, 이는 모델 한계지 시스템 결함이 아닙니다. 같은 절차를 sonnet으로 돌리면 품질이 올라갑니다.