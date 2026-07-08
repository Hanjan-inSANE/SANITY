# Toolset

DAH 프로젝트의 Toolset 전용 형상관리 루트. Toolset은 "fuzzer 목록"이나 도구 이미지 저장소가
아니라, **에이전트가 안전하게 외부 도구를 호출하고 그 결과를 재현 가능한 증거로 남기는 실행 계층**이다.

- **Registry** (`registry/`): 도구 서술자(ToolDescriptor) — 종류/실행 계약/입출력/보안 정책.
- **Executor** (`toolset_core/`): argv-only 실행, workspace 격리, timeout, env allowlist, 증거 기록.
- **Evidence Ledger**: 모든 실행을 `trace_id`·command·exit code·로그·artifact sha256·시각으로 append.
- **MCP** (`toolset_mcp/`): 에이전트가 부를 함수. 전용 파이프라인 함수 + **범용 `run_tool`**.
- **Skills / Scripts** (`skills/`, `scripts/`): 호출 절차서 + 도구가 실행하는 글루 스크립트.

> 실제 도구 실행 파일(`cmake`, `afl-fuzz`, `gdb`, `nmap`, `pymavlink` 등)은 이 폴더에 없다.
> 운영 서버에 **설치되어 있어야** 하며(§운영자 체크리스트), 없으면 `status: missing`으로 남는다.

구현 원칙·순서는 [TOOLSET_구현지침.md](TOOLSET_구현지침.md), OS별 설치·마이그레이션은
[env/README.md](env/README.md), 글루 스크립트 사용법은 [scripts/README.md](scripts/README.md).

## 구성

| 폴더 | 내용 |
|---|---|
| `registry/` | `tools.yaml`(도구 서술자 49개), `profiles.yaml`(target_kind→도구 매핑) |
| `schemas/` | ToolDescriptor / tool_result / artifacts / evidence_bundle JSON schema |
| `toolset_core/` | registry, executor, workspace, artifacts, evidence, policy, `adapters/` |
| `toolset_mcp/` | `server.py`(MCP 함수), `models.py`(공통 응답) |
| `scripts/` | MAVLink/네트워크/디버그 글루 스크립트(descriptor가 참조) |
| `skills/` | 상황별 MCP 호출 절차서 5종 |
| `env/` | OS별 설치 스크립트 + `check_environment.py` |
| `config/` | host별 도구 경로 alias 예시 |
| `tests/` | registry/policy/artifact/evidence/MCP/golden 테스트 |

## 도구 인벤토리 (49)

`kind`는 registry의 분류(팀 role과 동일 개념). 기본 12종 + **네트워크 계열 2종 확장**:
`network_scanner`(정찰), `network_attacker`(능동 네트워크/프로토콜 공격).

| kind | 도구 | 실행 경로 |
|---|---|---|
| builder | cmake, make, ninja | `toolset.build` |
| test_runner | ctest, pytest / **junit** | `toolset.run_tests`(ctest·pytest) / `run_tool`(junit) |
| fuzzer | aflpp, libfuzzer, **honggfuzz, aflnet, boofuzz** | `toolset.start_fuzz` |
| debugger | gdb / **lldb, rr** | `toolset.debug_gdb`(gdb) / `run_tool`(lldb·rr) |
| tracer | strace / **ltrace, bpftrace, tcpdump** | `toolset.trace_runtime`(strace) / `run_tool` |
| sanitizer | asan, ubsan / **valgrind** | `toolset.run_sanitizer`(asan·ubsan) / `run_tool`(valgrind) |
| coverage | gcov, llvm_cov | `toolset.measure_coverage` |
| static_analyzer | **semgrep, codeql, cppcheck, bandit** | `toolset.static_scan` |
| patcher | git_apply | `toolset.apply_patch` |
| reporter | toolset_reporter | `toolset.generate_report`(internal) |
| **network_scanner** | nmap, mav_heartbeat, ffuf | `run_tool` |
| **network_attacker** | pymavlink_inject, mavproxy, gps_input_spoof, scapy, hping3, hydra, sshpass, curl, netcat | `run_tool` |
| config_hardener | mavlink_signing, ardupilot_param_harden, sshd_harden, fail2ban, iptables, failsafe_trigger | `run_tool` |
| ids_rule_validator | suricata, snort | `run_tool` |

전체 목록·필터: `python env/check_environment.py` 또는 MCP `toolset.list_tools(priority=None)`.

## 실행 방법

### 1) 전용 파이프라인 (소스/crash 루프, P0)
`build → run_tests → build_harness → start_fuzz → collect_findings → reproduce_pov →
debug_gdb → trace_runtime → run_sanitizer → measure_coverage → apply_patch →
compare_baseline → export_evidence → generate_report`. 절차서는 `skills/`.

### 2) 범용 실행기 `toolset.run_tool`
등록된 **모든** 도구를 서술자의 `command_template` 자리표시자만 채워 실행한다. argv-only,
evidence 기록, workspace 격리를 그대로 따른다. `{toolset_root}`는 자동 주입된다.

```python
from toolset_mcp import server
ws   = server.create_workspace(base_dir="/opt/dah/ws")
root = ws["diagnostics"]["workspace_root"]

# 네트워크 정찰
server.run_tool(root, "nmap",
    params={"scan_target": "10.13.0.5", "report": "scan.xml"}, output_paths=["scan.xml"])

# MAVLink 주입 (COMMAND_LONG = MAV_CMD_COMPONENT_ARM_DISARM 예)
server.run_tool(root, "pymavlink_inject",
    params={"mav_endpoint": "udpin:0.0.0.0:14550", "target_system": 1, "target_component": 1,
            "mav_msg": "COMMAND_LONG",
            "params_json": '{"command":400,"confirmation":0,"param1":1,"param2":0,'
                           '"param3":0,"param4":0,"param5":0,"param6":0,"param7":0}'})

# GPS 스푸핑
server.run_tool(root, "gps_input_spoof",
    params={"mav_endpoint": "udpin:0.0.0.0:14550", "lat": 37.5, "lon": 127.0, "hz": 5})

# 방어: MAVLink2 서명 활성
server.run_tool(root, "mavlink_signing",
    params={"mav_endpoint": "udpin:0.0.0.0:14550", "sign_key": "team-secret"})
```

응답: `{ok, trace_id, tool_id, status(success|failure|timeout|missing|skipped), artifact_refs,
summary, diagnostics{exit_code, resolved_command, ...}}`. 자리표시자 누락 → `failure` +
`diagnostics.unresolved`. 도구 미설치 → `missing`.

### 3) 글루 스크립트
`python {..._script}` 계열 도구는 `scripts/` 아래 번들 스크립트를 실행한다(자세한 인자: `scripts/README.md`).
`scapy_attack.py`·`boofuzz_session.py`는 **템플릿**이므로 대상 프로토콜/페이로드에 맞게 수정해야 한다.

## 운영자 체크리스트

1. **도구 설치** (실행 호스트에서):
   ```bash
   cd /path/to/DAH/Toolset
   bash env/install-ubuntu.sh            # P0 + 확장(A/B/C) 도구, best-effort
   # codeql(CLI), snort, aflnet 은 apt 미제공 → 각 docs_url 참고해 수동/소스 설치
   ```
2. **가용성 검증**:
   ```bash
   python env/check_environment.py --write-config   # config/toolset.local.json 생성
   python env/check_environment.py                  # available / missing / probe_failed
   ```
3. **경로 alias** — PATH 밖 도구는 `config/toolset.local.json`의 `tool_aliases`에 지정.
   `python`이 `python3`뿐이면 `"python": "python3"` 도 넣는다. 격리가 필요한 네트워크 도구는
   docker/wsl 래퍼를 alias로: 예 `"strace": ["docker","run","--rm","--network=none","ubuntu:24.04","strace"]`.
4. **Python 의존성** (설치 스크립트가 pip로 처리): `pymavlink MAVProxy boofuzz scapy semgrep bandit`.
5. **MCP 연결** — 런타임이 있으면 `python toolset_mcp/server.py`를 MCP 서버로 등록,
   없으면 `from toolset_mcp import server` 후 함수 직접 호출(둘 다 동일 JSON 계약).
6. **DVD/드론 타깃 준비** — ArduPilot SITL 또는 Damn Vulnerable Drone을 **샌드박스 네트워크**에
   기동하고 MAVLink endpoint(예 `udpin:0.0.0.0:14550`)를 확보. 네트워크 도구 서술자는
   `security_profile.network: sandbox`지만 **executor가 네트워크를 강제 격리하지는 않으므로**,
   실제 격리는 docker `--network` / 전용 서브넷 / 방화벽으로 운영자가 보장한다.
7. **실행 & 증적** — 위 §실행 방법대로 호출. 모든 실행은 `artifacts/evidence/ledger.jsonl`에 남고,
   `toolset.export_evidence` → `toolset.generate_report`로 제출용 번들을 만든다.

## 로컬 검증 (개발/CI)

```bash
python -m unittest discover -s tests -p "test_*.py"        # 외부 도구 없이 통과
TOOLSET_INTEGRATION=1 python -m unittest Toolset.tests.test_golden_contract   # 실제 toolchain
```

## 보안·주의

- MAVLink/네트워크 스크립트는 **본인이 소유·통제하는 인가된 테스트베드 전용**이다.
- 에이전트에 raw shell을 노출하지 않는다. 모든 실행은 registry 등록 도구 + argv 계약을 통과한다.
- `resource_limits`·`network`는 서술자 메타데이터이며 executor가 강제하지 않는다(격리는 래퍼로).
- secret/token/password는 로그·evidence 기록 전 마스킹된다.

## 작업 원칙

- Toolset 관련 파일은 `Toolset/` 밖에 생성·수정하지 않는다.
- `설계요구사항/`은 참조용(읽기 전용). 예외는 사유를 문서화하고 승인 후 진행.
