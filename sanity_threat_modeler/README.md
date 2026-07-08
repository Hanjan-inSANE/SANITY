# Threat Modeler — UxV 위협모델링 엔진 (모듈형 Python + 브라우저 UI)

DefenseWeaver 논문(arXiv:2504.18083, *"Automating Function-Level TARA for Automotive
Full-Lifecycle Security"*)의 **위협모델링 단계**를 무인이동체(UxV) 도메인으로 이식한 도구입니다.
**OpenXSAM++**(`.openxsampp.xml`) 데이터플로우 다이어그램(DFD)을 입력받아 — 토폴로지·컴포넌트별
설정(Software/Hardware/Interface)·레이아웃이 한 파일에 담깁니다 — **DefenseWeaver식 공격트리(attack
tree)** 를 생성합니다. 출력은 JSON + SVG(브라우저 렌더, PNG/SVG 다운로드)입니다.

> 이 도구는 **위협모델링(공격트리 생성)까지만** 구현합니다. 실제 fuzzing/exploit/patch, 그리고
> DefenseWeaver의 Risk Assessor(feasibility/impact/risk-level, §IV-C3)는 설계상 **범위 밖**입니다.

모든 로직은 **책임별로 하나의 Python 모듈**로 분리되어 있고(`threat_modeler/`), 브라우저(`index.html`)는
로컬 서버를 통해 이 Python 엔진을 호출하는 얇은 클라이언트입니다. 파싱·경로추출·atom분해·OpenXSAM++·
LLM 단계가 전부 Python 모듈에서 실행됩니다.

---

## 빠른 시작

```bash
# Anthropic(Claude) 사용 시에만 필요. openai/ollama 프로바이더는 이 패키지 불필요.
pip install anthropic

# 브라우저 모드 (권장) — 서버가 뜨고 브라우저 탭이 자동으로 열립니다.
python -m threat_modeler serve
#   옵션: --port 8000  --host 127.0.0.1  --no-browser
```

브라우저에서 전 과정을 진행합니다: `.openxsampp.xml` 업로드 → 노드 설정 → 시나리오 도출 → Run → 트리 확인/다운로드.
입력한 API 키는 **본인의 로컬 서버로만** 요청마다 전송되고 저장되지 않습니다.

명령줄(CLI)로도 쓸 수 있습니다(입력은 OpenXSAM++ `.xml`; 설정은 파일에 내장되며 `-c`로 덮어쓸 수 있음):

```bash
python -m threat_modeler models                      # 선택 가능한 프로바이더/모델
python -m threat_modeler openxsampp  example1_px4_quad.openxsampp.xml
python -m threat_modeler paths       example1_px4_quad.openxsampp.xml --entry <guid> --endpoint <guid>
python -m threat_modeler run         example1_px4_quad.openxsampp.xml \
        --provider anthropic --model claude-sonnet-4-6 \
        --out-json trees.json --out-svg-prefix tree_
```

`openxsampp`·`paths`는 API 키·추가 의존성 없이 동작합니다(결정론 코어). `run`만 LLM 호출입니다.

---

## 모듈 구성

```
threat_modeler/
  dfd.py           Node / Edge / SystemModel            핵심 DFD 자료구조
  config_schema.py NODE_FIELDS / EDGE_FIELDS            §IV-B1 설정 필드(출처 태그 포함)
  graph.py         build_engine_graph / all_simple_paths / scenario_paths / build_atoms
  openxsampp.py    generate_openxsampp / parse_openxsampp   결정론적 OpenXSAM++ XML 입출력
  models.py        모델/프로바이더 카탈로그 (anthropic / openai / ollama)
  llm.py           call_claude / call_openai / call_ollama / call_and_parse  (네트워크 담당)
  stages.py        rag_enrich_components / derive_scenarios / construct_subtree / assemble
  validator.py     validate_attack_tree(...)            결정론적 트리 구조 검증
  pipeline.py      run_pipeline(...)                    전체 오케스트레이션
  render.py        layout / render_tree_svg / svg_to_png
  server.py        로컬 웹서버: 브라우저 UI <-> Python 엔진 (표준 라이브러리만)
  cli.py, __main__.py   명령줄 진입점 (serve 서브커맨드 포함)
index.html         브라우저 클라이언트 (DFD/트리 렌더, 서버 JSON API 호출)
tests/             결정론 코어·검증기·프로바이더 단위 테스트 (총 23개)
example*.openxsampp.xml   샘플 DFD + 내장 설정 (토폴로지·설정·레이아웃 통합)
```

**초록 = 결정론 코드**(파서·그래프·atom·OpenXSAM++·렌더·검증기), **주황 = LLM 단계**(지식수집·시나리오도출·
Constructor·Assembler). 결정론 단계만 재현 가능합니다.

---

## 파이프라인 (동작 순서)

```
 OpenXSAM++ DFD -> parse_openxsampp -> build_engine_graph(config)      [결정론]
          -> rag_enrich_components (컴포넌트별 · 코퍼스별 RAG 근거)     [Attack-RAG · 옵션]
          -> derive_scenarios: (objective, entryIds, endpointId)       [LLM · RAG 근거 기반 도출]
          -> scenario_paths (DFS, 비순환 entry->endpoint)             [결정론]
          -> build_atoms (노드 + exit 채널 1개)                        [결정론]
          -> construct_subtree (atom 1개 -> sub-tree 1개)             [LLM · atom마다 독립]
          -> assemble (sub-tree들 -> AND/OR 트리 하나로 병합)          [LLM]
          -> validate_attack_tree (구조 검증)                          [결정론]
          -> render_tree_svg                                          [결정론]
```

### 용어 정의
- **atom** = 부품(노드) 1개 + 그 부품의 인접 채널들, **나가는(exit) 채널마다 분할** → 각 atom은 로컬 공격목표 1개.
  나가는 채널이 여러 개인 노드는 atom(→sub-tree)이 여러 개가 됩니다. 종점 노드는 exit 없는 *terminal atom* 1개.
- **sub-tree** = atom 1개를 LLM이 키운 작은 트리 = **root(로컬 목표) + method 리프들 + AND/OR 논리노드**.
- **전체 tree** = sub-tree들을 Assembler(LLM)가 **entry→endpoint AND/OR 중첩 트리**로 병합한 결과(순서는 부모/자식 중첩).

---

## 프로바이더 / 모델 선택

| provider | 방식 | API 키 | base URL |
|---|---|---|---|
| `anthropic` | Claude API | 필요 | — |
| `openai` | **OpenAI 호환 호스팅 API** (OpenRouter/Groq/Together/Fireworks/DeepInfra, 로컬 vLLM/LM Studio) | 필요 | 서비스 엔드포인트 |
| `ollama-cloud` | **Ollama Cloud** (`https://ollama.com`, Gemma 등) | 필요 | `https://ollama.com` |
| `ollama` | 로컬 Ollama 데몬 | 불필요 | `http://localhost:11434` |

`python -m threat_modeler models`로 전체 목록을 볼 수 있습니다. 카탈로그에 없는 id도 `--model`(또는 UI 입력)로
그대로 넘길 수 있으니, 새 모델이 나와도 코드 수정 없이 사용 가능합니다.

- **Anthropic Sonnet 계열**: `claude-sonnet-4-6`(기본), `claude-sonnet-4-5`, `claude-sonnet-4-0`.
  (참고: 원 스펙 예시의 `claude-sonnet-5`는 실제로 없는 id라 404가 나므로 넣지 않았습니다.)
- **OpenAI 호환(호스팅 오픈모델)**: llama/qwen/mistral 제안 id 제공. **모델 id는 서비스마다 다릅니다**(예:
  OpenRouter `meta-llama/llama-3.1-70b-instruct`, Together `meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo`).
- **Ollama Cloud**: `https://ollama.com`에 API 키로 접속해 Gemma 등 호스팅 오픈모델 사용. 모델 필드에 계정이
  받을 수 있는 태그(신규 Gemma 포함)를 그대로 입력 가능.

### 예시 — 호스팅 llama 3.1 70b (로컬 설치 없이)
```bash
export OPENAI_API_KEY=<서비스 키>
python -m threat_modeler run example1_px4_quad.openxsampp.xml \
  --provider openai --base-url https://openrouter.ai/api/v1 \
  --model meta-llama/llama-3.1-70b-instruct
```
브라우저에서는 Run 탭 → Provider `OpenAI-compatible API` → base URL 프리셋 선택 → 키·모델 id 입력.

---

## 브라우저 사용법

`python -m threat_modeler serve` 후 자동으로 열리는 탭에서:

0. **0·Engine config** — LLM 프로바이더/API 키/모델/base URL과 Attack-RAG 사용 여부·URL을 설정. 이 값이
   Derive와 Run 모두에 적용됩니다.
1. **1·System** — `.openxsampp.xml` 업로드(드롭 또는 Load config) → DFD 렌더. 노드/채널 클릭해 Software/Hardware/Interface 입력.
   RAG 보강 후 각 컴포넌트를 클릭하면 검색된 근거(코퍼스별 청크)를 확인할 수 있습니다. DFD는 **휠 확대 + 드래그 이동** 가능.
2. **2·Scenarios** — `Derive scenarios`(RAG 근거 기반 LLM 자동 도출). 컴포넌트별·코퍼스별 RAG 쿼리와 회수 청크가
   아래 로그에 스트리밍됩니다(수동 입력 없음).
3. **3·Run engine** — `Run`으로 전체 파이프라인 실행. 진행 로그가 **실시간 스트리밍**되고, 시나리오별 트리가 완성되는
   대로 4번 탭에 하나씩 나타납니다.
4. **4·Attack tree** — 시나리오별 트리 확인. **휠 확대/드래그 이동**, **노드 클릭 시 좌측 상세 패널**(잘리지 않은
   전체 라벨·종류·경로·하위 method 수), `JSON`·`Download SVG`·`Download PNG`.

### 설정 JSON 불러오기/내보내기
- 브라우저: **Load config / Save config** 버튼. 데모를 열면 짝이 되는 `*_annotations.json`도 자동 적용.
- CLI: `openxsampp`/`paths`/`run`에 `-c <file>.json`.
- 형식: `{ "<guid>": { "sw.os": "...", "hw.chips": "a\nb", "__custom": [{"k","v"}] } }`.
  감싼 형식 `{ "config": { ... } }`(샘플 annotation 파일 형식)도 자동 인식합니다(내보내기는 감싼 형식).

---

## 설정 필드는 지어낸 게 아니라 §IV-B1에 근거

`config_schema.py`의 필드는 OpenXSAM++ 확장(§IV-B1)에 1:1 대응하며, 각 필드에 출처 태그(`src`)가 붙습니다.

| 필드 키 | OpenXSAM++ | §IV-B1 표현 |
|---|---|---|
| `sw.os` / `sw.sbom` / `sw.services` | Software/OS·SBOM·Services | "operating system" / "software bill of materials" / "active network services" |
| `hw.chips` / `hw.modules` / `hw.debug` | Hardware/* | "chips" / "hardware modules" / "debugging capabilities" |
| `ch.tech` / `ch.interface` / `ch.data` | Channel / Interface / DataFlow | "Channel ... and Interface" |

DFD에 없는 세부정보는 직접 입력하지 않으면 `unspecified`로 방출됩니다 — **날조하지 않습니다.** 자유형 `__custom`
속성도 허용(경직된 하드코딩 회피).

---

## DefenseWeaver 대비 바뀐 핵심 알고리즘

결정론 부분(OpenXSAM++ · DFS 논리경로 · atom 분해)은 논문 §IV-B와 **동일하게** 유지하고, 아래가 달라졌습니다.

1. **Assembler = AND/OR 트리(순서는 부모/자식 중첩)** — 논문 Assembler의 병합을 유지하되 SEQ 노드나
   `stage_index` 없이 **entry→endpoint를 AND/OR 중첩으로 분해**합니다. 선행 단계는 그 단계가 가능케 하는
   노드의 **조상**으로 표현(부모 목표 달성은 자식 하위목표 선행을 요구). 노드 종류는 `objective`/`logic`/`method` 뿐.
2. **엄격한 노드 의미(Req 3·4)** — 각 노드는 **정확히 하나**의 공격 목표(objective/logic) 또는 하나의 공격
   방법(method)만 표현하고, 노드 간 의미 중복을 금지합니다. **method 리프는 근거 id(CVE/CWE/ATT&CK/SPARTA)를
   인용한 단일 실행가능 공격**이어야 하며, 추상적이거나 근거 없는 리프는 생성하지 않습니다.
3. **결정론적 외부 검증기(`validator.py`)** — LLM 출력 위에 규칙 후검증: **DFD 경로 밖 컴포넌트·채널** 참조,
   수동 릴레이의 "compromise" 과표기, **method 리프의 근거 id 누락**, 근거 없는 추정 취약점(CVE 미인용),
   빈약한 OR 등을 `err`/`warn`으로 표시하고 `validationIssues`로 첨부합니다.
4. **수동 릴레이 = "통과/신뢰 남용"으로 모델링** — 순수 중계 노드를 "장악"으로 과표기하지 않도록 Constructor에 지시.
5. **(설계 결정)** Risk Assessor(§IV-C3) 전면 제외 · 위협 시나리오는 **RAG 근거 위에서 에이전트 도출** ·
   지식보강은 **Attack-RAG(코퍼스별 검색: ATT&CK/SPARTA/CVE/CWE)** · **멀티 프로바이더**(Anthropic/OpenAI호환/Ollama/Ollama Cloud).

---

## 검증 (결정론, 정량적, 재현 가능)

```bash
python -m unittest discover -s tests -v
```

**23개 테스트 통과.** 네트워크·`anthropic` 의존성 없이 결정론 코어를 검사하며, 가능한 항목은 **독립 재계산과 대조**합니다.

- **`parse_openxsampp`**: OpenXSAM++ 예제를 재파싱해 노드/간선/설정 왕복이 보존되는지 확인.
- **`all_simple_paths`**: 별도로 작성한 재귀 DFS 오라클과 경로 집합 일치, 순환 제외(의도적 C↔D 순환 그래프로 확인),
  `max_len` 상한 준수.
- **`build_atoms`**: propagate atom 수 = 경로상 방향 간선 수, terminal atom 수 = 종점 노드 수(불변식 독립 재계산).
- **`generate_openxsampp`**: 출력이 well-formed XML로 재파싱, 컴포넌트 수 = 노드 수, 빈 필드는 `unspecified`,
  주입한 설정값 그대로 반영.
- **`validator`**: 유효 AND/OR 트리 통과 · 경로 밖 참조 탐지 · **method 리프 근거 id 규칙** · 추정 취약점 CVE 요구 · 빈약한 OR.
- **`render`**: layout이 상수 반환, 독립 실행형 SVG 재파싱.
- **`llm`(프로바이더 디스패치)**: 로컬 스텁 서버로 `openai`(`/v1/chat/completions`, Bearer)·`ollama`(`/api/chat`) 경로 확인.

---

## 한계 (사용 전 반드시 인지)

1. **LLM 비결정성** — 4개 LLM 단계는 같은 입력에도 매번 다른 트리를 냅니다. **재현성 보장 없음**(DefenseWeaver도
   동일, 논문에 재현성 수치 없음). 결정론 단계만 재현 가능. 생성된 트리는 검증해야 할 **가설**로 다루세요.
2. **OpenXSAM++는 재구성** — 논문은 산문 서술만 하고 완전한 XSD를 공개하지 않으며 DefenseWeaver 저장소는 비공개.
   본 XML은 "원본 ASRG/openXSAM 뼈대 + §IV-B1 추가분"이며 필드 형식은 설계 선택(XML 헤더에 명시).
3. **입력 포맷은 OpenXSAM++** — 이 도구는 `.openxsampp.xml`(토폴로지·설정·레이아웃 통합)만 입력받습니다.
   Microsoft TMT `.tm7` 직접 입력은 지원하지 않습니다.
4. **Risk/feasibility 없음** — 설계상 제외. 어느 경로를 먼저 팔지에 대한 내장 신호가 없으므로, 그 판단은 이후
   exploitation 단계에서 별도로 붙여야 합니다(범위 밖).
5. **지식보강은 Attack-RAG에 의존** — 실시간 웹 검색은 없습니다. TTP/CVE/CWE 근거는 Attack-RAG 서버에서만
   오며, 서버 미연결 시 근거 없이(모델 자체 지식으로) 진행됩니다.
6. **오픈모델의 JSON 준수** — llama/qwen 등은 Sonnet보다 STRICT JSON이 약할 수 있습니다. `call_and_parse`에
   "깨진 JSON 1회 자동 교정" 로직이 있어 대부분 통과하지만, 반복 실패 시 재시도하거나 트리/시나리오 크기를 줄이세요.
7. **PNG 내보내기** — CLI의 `--png`는 `cairosvg` 필요(없으면 SVG만). 브라우저 PNG는 canvas로 생성하므로 추가 설치 불필요.

---

## 자신감 점수

**80/100.** 결정론 코어는 깨끗한 모듈로 분리되어 독립 재계산과 대조해 검증됩니다(23개 테스트). 단계↔논문 매핑과
§IV-B1 필드 출처는 추적 가능하고, 프로바이더 디스패치·검증기 로직은 스텁/단위 테스트로 확인했습니다. 감점 요인:
(a) 4개 LLM 단계는 비결정적이며 라이브 키 없이는 종단 검증 불가, (b) OpenXSAM++는 문서화된 재구성, (c) 오픈모델의
출력 품질(특히 STRICT JSON)은 모델·서비스에 따라 편차가 있어 실제 라이브 실행 재현성은 보장되지 않습니다.
