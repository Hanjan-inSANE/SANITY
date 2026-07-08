# SANITY

**S**ecurity **A**gent for **N**etworked **I**ntelligent unmanned s**Y**stems — 무인이동체(UxV)를 대상으로
**위협모델링 → 자율 공격(PoV) → 자율 방어(패치·검증) → 제출**을 수행하는 에이전트 기반 사이버 추론 시스템(CRS).

대상 예선 시나리오: 클라우드에 배포된 라이브 시뮬레이터 **DVD(Damn Vulnerable Drone = ArduPilot SITL/MAVLink)**.
설계는 AIxCC 결승 **ATLANTIS**([Team-Atlanta/aixcc-afc-atlantis](https://github.com/Team-Atlanta/aixcc-afc-atlantis))의
CRS 구조와 DefenseWeaver(위협모델링)를 참고했다.

---

## 무엇을 하나

1. **위협모델링(1)** — 시스템 모델(OpenXSAM++ DFD)을 받아 RAG(ATT&CK/SPARTA/CVE/CWE) grounding 위에서 AND/OR **공격트리**를 생성.
2. **시나리오 관리(2)** — 트리를 실행 경로로 분해하고 공격/방어 에이전트를 오케스트레이션(트리당 1 인스턴스).
3. **공격(3)** — 노드별로 도구 선택·exploit·검증. 성공 시 PoV 생성. **crash 클래스**(퍼징·소스빌드)와 **logic 클래스**(MAVLink/GPS) 분기.
4. **방어(4)** — 성공한 공격에 대해 패치/하드닝 생성·적용·검증(무력화 ∧ 무회귀). crash는 6-게이트 `compare_baseline`.
5. **제출** — 검증된 PoV/Patch를 번들로 로컬 sink 저장(예선).

공용 인프라: **LLM Gateway(6, LiteLLM)** · **Log(7)** · **Toolset(8, MCP)** · **State/Bus(Redis)** · **DB(5, Attack-RAG)** · **Target(9, DVD SITL)**.

---

## 저장소 구조

```
SANITY/
├── threat_modeler/          # 1. 위협모델러 (구 uxvweaver) — 공격트리 생성. import 이름: threat_modeler
├── sanity_common/           # 공용 계약·버스·상태·ids·toolset 클라이언트·config
├── sanity_scenario_manager/ # 2. Scenario Manager
├── sanity_attacker/         # 3. Attacker
├── sanity_defender/         # 4. Defender
├── sanity_infra/            # 0. DAH 인입 러너 + 9. Target(DVD SITL) 배치
├── gateway_log/             # 6. LLM Gateway + 7. Log (sanity_llm / sanity_log) + LiteLLM 설정
├── Toolset/Toolset/         # 8. Toolset (MCP 서버·도구 레지스트리·evidence ledger)
├── deploy/                  # docker-compose (+ 관측용 demo 오버레이)
├── docs/QUICKSTART.md       # 처음부터 끝까지 따라 하는 실행 가이드
├── tools/viewer.py          # 공격/방어 실시간 흐름 웹 뷰어
├── examples/                # OpenXSAM++ 샘플 (DVD / PX4 / UGV)
└── _archive_dev/            # 개발용 설계·구현 가이드 문서(참고용; 배포 불필요)
```

---

## 빠른 시작

전체 절차(컴퓨터 준비 → Docker → 키 → 기동 → 실행 → 눈으로 확인)는 **[`docs/QUICKSTART.md`](docs/QUICKSTART.md)** 를 따르세요.

요지:
```bash
# 1) 설치 (순서 고정)
pip install -e ./gateway_log        # 6/7: sanity_llm, sanity_log
pip install -e ./threat_modeler     # 1: threat_modeler
pip install -e .                    # sanity_common + 2/3/4 + infra

# 2) 키
cp gateway_log/gateway/.env.example deploy/.env    # OLLAMA_CLOUD_API_KEY / master key 채우기

# 3) 기동 + 실행
cd deploy && docker compose up -d
python -m sanity_infra.dah.runner DVD.openxsampp.xml

# 4) 눈으로: 흐름 뷰어
python tools/viewer.py    # http://localhost:8090
```

> LLM은 현재 **Ollama Cloud Gemma**로 설정(`gateway_log/gateway/config.yaml`의 별칭 `sane-*`). 다른 모델은 이 파일만 바꾸면 됨.

---

## 모델 구성 (config만 바꿈)

에이전트는 `sane-sonnet`/`sane-opus`/`sane-haiku` 같은 **별칭**만 부르고 LiteLLM이 실모델로 라우팅한다.
`gateway_log/gateway/config.yaml`에서 별칭↔실모델 매핑을 바꾸면 전 컴포넌트 모델이 바뀐다(코드 무변경).

---

## 보안·격리

- 대상(`target-*`)은 제어평면과 **분리 네트워크**(SR-SEC-02).
- 에이전트에는 프로바이더 키를 넣지 않는다(가상키만; SR-STACK-02).
- 대상/RAG 텍스트는 프롬프트에 **데이터로만** 주입(prompt-injection 방어; SR-SEC-01).
- 키·비밀은 `deploy/.env`(gitignore)와 secret store로만. **로그는 기록 전 자동 마스킹.**

---

## 테스트

```bash
python -m pytest threat_modeler/ tests/ -q                    # 위협모델러
python -m pytest gateway_log/tests -q                          # 6/7
python -m pytest Toolset/Toolset/tests/test_golden_contract.py # 8 crash 파이프라인
python -m pytest sanity_common/tests -q                        # 공용 라이브러리
```

---

## 라이선스 / 크레딧

- Toolset(8)은 AIxCC/ATLANTIS식 도구 계층, LLM Gateway는 [LiteLLM](https://github.com/BerriAI/litellm)(MIT).
- 위협모델러는 DefenseWeaver(arXiv:2504.18083) 위협모델링 단계를 UxV로 이식.
- 각 컴포넌트 폴더의 README/설계문서 참조.
