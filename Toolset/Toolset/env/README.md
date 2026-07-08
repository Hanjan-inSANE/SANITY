# Toolset Environment Setup and Migration Guide

## 판정

`Toolset/`의 Python/MCP/Skill 파일만으로는 외부 fuzzing, debugging, tracing 프로그램이 자동으로 생기지 않는다. 현재 Toolset은 `cmake`, `afl-fuzz`, `gdb`, `strace`, `clang`, `llvm-cov` 같은 프로그램을 안전하게 호출하고 evidence를 남기는 계층이다. 실제 운영 서버에는 해당 실행 파일 또는 wrapper가 설치되어 있어야 한다.

## 운영자가 해야 할 일

1. 대상 OS에 맞는 설치 스크립트를 실행한다.
2. `check_environment.py`로 registry의 P0 도구가 실제 PATH 또는 alias로 해석되는지 확인한다.
3. 설치 경로가 표준 PATH와 다르면 `Toolset/config/toolset.local.json`에 `tool_aliases`를 지정한다.
4. 하네스 또는 에이전트 런타임에서 `Toolset/toolset_mcp/server.py`를 MCP 서버로 등록하거나, 동일 함수를 Python module로 import한다.
5. 챌린지 workspace는 Toolset workspace 내부 또는 Toolset이 허용한 workspace root로 넘긴다. Toolset executor는 argv list만 실행하고 shell string은 거부한다.

## OS별 설치

### Ubuntu / Debian

```bash
cd /path/to/DAH/Toolset
bash env/install-ubuntu.sh --dry-run
bash env/install-ubuntu.sh
```

AFL++를 source-only로 직접 빌드하려면:

```bash
bash env/install-ubuntu.sh --with-afl-source
```

공식 AFL++ 문서는 Docker pull 또는 Debian/Ubuntu dependency 설치 후 source build를 제시한다. 운영 환경에서 root 권한이 제한되면 Docker image `aflplusplus/aflplusplus` 또는 별도 build runner를 쓰고, `tool_aliases`로 wrapper를 지정한다.

### macOS

```bash
cd /path/to/DAH/Toolset
bash env/install-macos.sh --dry-run
bash env/install-macos.sh
```

AFL++ source-only build:

```bash
bash env/install-macos.sh --with-afl-source
```

주의:

- macOS에는 Linux `strace`가 없다. `toolset.trace_runtime`은 Linux/WSL/Docker runner를 쓰지 않으면 `missing`으로 남는 것이 정상이다.
- Homebrew GDB는 로컬 프로세스 디버깅 전에 macOS code signing이 필요할 수 있다.
- AFL++ 공식 문서는 macOS에서 Homebrew LLVM/coreutils PATH 조정과 `afl-system-config`를 요구한다.

### Windows

PowerShell에서:

```powershell
cd C:\path\to\DAH\Toolset
.\env\install-windows.ps1 -DryRun
.\env\install-windows.ps1
```

MSYS2 패키지까지 설치:

```powershell
.\env\install-windows.ps1 -InstallMsys2Packages
```

주의:

- Windows native 환경에는 Linux `strace`가 없다.
- AFL++와 `strace`가 필요한 P0 fuzz/trace path는 WSL2, Docker, 또는 Linux runner 사용을 권장한다.
- Windows native path에 설치된 도구는 `Toolset/config/toolset.local.json`에서 absolute path alias로 지정한다.

예:

```json
{
  "tool_aliases": {
    "cmake": "C:\\Program Files\\CMake\\bin\\cmake.exe",
    "ninja": "C:\\Program Files\\Ninja\\ninja.exe",
    "clang": "C:\\Program Files\\LLVM\\bin\\clang.exe",
    "gdb": "C:\\msys64\\ucrt64\\bin\\gdb.exe",
    "afl-fuzz": ["wsl", "-e", "afl-fuzz"],
    "strace": ["wsl", "-e", "strace"]
  }
}
```

## 확장 도구 프로비저닝 (A 확장 + B/C DVD)

기본 P0(소스/crash) 외에 registry 확장으로 아래 도구가 추가되었다.

**Ubuntu/Debian** — `install-ubuntu.sh`가 P0에 더해 다음을 best-effort 설치한다:
`maven lldb rr ltrace bpftrace valgrind cppcheck honggfuzz nmap hydra hping3 sshpass curl
ffuf netcat-openbsd tcpdump fail2ban iptables suricata` + pip `pymavlink MAVProxy boofuzz
scapy semgrep bandit`. apt 미제공인 **codeql(CLI)·snort·aflnet은 수동/소스 설치**(각 도구 docs_url 참고).

**macOS / Windows** — `install-macos.sh`/`install-windows.ps1`은 아직 확장 도구를 자동 설치하지
않는다. 확장 도구 다수(`strace ltrace bpftrace rr aflnet suricata snort iptables fail2ban hping3`)가
**Linux 전용**이므로, B/C(네트워크·드론)와 fuzz/trace 경로는 **Linux / WSL2 / Docker runner**에서
실행하길 권장한다. 크로스플랫폼 가능한 일부(`nmap curl semgrep bandit` + pip `pymavlink scapy`)는
brew/winget/pip로 개별 설치하고, 필요 시 `Toolset/config/toolset.local.json`의 `tool_aliases`로 경로를 지정한다.

**글루 스크립트** — `python {..._script}` 계열(MAVLink 주입/스푸핑/서명·GPS·failsafe 등)과
gdb/lldb/bpftrace batch 스크립트는 `Toolset/scripts/`에 번들되어 있고 registry가 `{toolset_root}`로
참조한다. 필요 Python 패키지: `pymavlink`(MAVLink), `scapy`, `boofuzz`. 인자·용도는
[../scripts/README.md](../scripts/README.md). `scapy_attack.py`·`boofuzz_session.py`는 템플릿이므로
대상 프로토콜에 맞게 수정한다.

## 환경 검사

```bash
python env/check_environment.py --write-config
python env/check_environment.py
python env/check_environment.py --json
```

CI나 운영 배포 gate에서는:

```bash
python env/check_environment.py --fail-on-missing
```

검사 상태는 다음처럼 해석한다.

- `available`: 실행 파일이 해석되고 probe 명령 exit code가 0이다.
- `missing`: 실행 파일 자체가 PATH 또는 alias에서 해석되지 않는다.
- `probe_failed`: 실행 파일은 있지만 probe 명령이 실패했다. 예: `python`은 있으나 `pytest` 모듈이 없는 경우.

단, macOS/Windows에서 `strace` 또는 AFL++를 intentionally missing으로 둘 수 있다. 그 경우에는 `--fail-on-missing` 대신 JSON 결과를 읽어 target profile별 필수 도구만 gate로 삼는다.

## Alias 구성

기본 config 위치:

```text
Toolset/config/toolset.local.json
```

다른 위치를 쓰려면:

```bash
export TOOLSET_CONFIG=/secure/path/toolset.local.json
```

PowerShell:

```powershell
$env:TOOLSET_CONFIG = "D:\ops\toolset.local.json"
```

`tool_aliases`는 실행 파일 첫 번째 argv만 치환한다. 값은 문자열 또는 argv prefix list다.

```json
{
  "tool_aliases": {
    "afl-fuzz": "/opt/aflplusplus/bin/afl-fuzz",
    "strace": ["docker", "run", "--rm", "--network=none", "ubuntu:24.04", "strace"]
  }
}
```

Docker wrapper는 target workspace volume mount까지 포함해야 하므로, 실제 운영에서는 별도 wrapper script를 만들고 그 script 경로를 alias로 지정하는 쪽이 더 안전하다.

## 하네스/에이전트 통합 지침

### MCP 서버로 등록

MCP 런타임이 있는 환경에서는 `Toolset/toolset_mcp/server.py`를 서버 entrypoint로 등록한다.

```bash
python /path/to/DAH/Toolset/toolset_mcp/server.py
```

MCP package가 없다면 같은 함수를 직접 import해도 된다.

```python
from pathlib import Path
import sys

toolset_root = Path("/path/to/DAH/Toolset")
sys.path.insert(0, str(toolset_root))

from toolset_mcp import server

workspace = server.create_workspace(base_dir="/tmp/dah-toolset")
tools = server.list_tools(target="c", priority="P0")
probe = server.probe_tool("cmake", workspace_root=workspace["diagnostics"]["workspace_root"])
```

### Registry 참조 경로

하네스가 도구 목록을 직접 읽어야 한다면 아래 파일을 source of truth로 둔다.

```text
Toolset/registry/tools.yaml
Toolset/registry/profiles.yaml
```

단, 직접 subprocess를 호출하지 말고 `toolset_mcp.server` 또는 `toolset_core.ToolExecutor`를 통해 호출해야 한다. 그래야 workspace containment, missing status, stdout/stderr artifact, sha256, evidence ledger가 유지된다.

### Skill 참조 경로

에이전트는 아래 Skill을 절차서로 읽고 MCP tool을 순서대로 호출한다.

```text
Toolset/skills/toolset-target-triage/SKILL.md
Toolset/skills/harness-build-fuzz/SKILL.md
Toolset/skills/pov-reproduce-debug/SKILL.md
Toolset/skills/defense-patch-verify/SKILL.md
Toolset/skills/evidence-report/SKILL.md
```

## 공식 문서 확인 위치

각 도구의 공식 문서 URL은 `registry/tools.yaml`의 `docs_url` 필드가 **정본**이다(도구 추가 시 함께 갱신).
아래는 자주 쓰는 시작점.

**패키지 매니저** — Homebrew: https://brew.sh/ · WinGet: https://learn.microsoft.com/windows/package-manager/winget/ · MSYS2: https://www.msys2.org/

**P0 (소스/crash)**
- AFL++: https://aflplus.plus/docs/install/ · libFuzzer: https://llvm.org/docs/LibFuzzer.html
- CMake/CTest: https://cmake.org/cmake/help/latest/manual/ · GDB: https://sourceware.org/gdb/current/onlinedocs/gdb.html/
- strace: https://man7.org/linux/man-pages/man1/strace.1.html · Clang Sanitizers(ASan/UBSan): https://clang.llvm.org/docs/
- gcov: https://gcc.gnu.org/onlinedocs/gcc/Gcov.html · llvm-cov: https://clang.llvm.org/docs/SourceBasedCodeCoverage.html

**A 확장 (소스/crash)**
- honggfuzz: https://github.com/google/honggfuzz/blob/master/docs/USAGE.md · aflnet: https://github.com/aflnet/aflnet
- LLDB: https://lldb.llvm.org/use/tutorial.html · rr: https://rr-project.org/ · ltrace: https://man7.org/linux/man-pages/man1/ltrace.1.html
- bpftrace: https://bpftrace.org/docs/ · Valgrind: https://valgrind.org/docs/manual/mc-manual.html
- CodeQL: https://codeql.github.com/docs/ · Semgrep: https://semgrep.dev/docs/ · cppcheck: https://cppcheck.sourceforge.io/manual.pdf · Bandit: https://bandit.readthedocs.io/
- JUnit(Maven): https://junit.org/junit5/docs/current/user-guide/

**B — DVD/네트워크 공격**
- Nmap: https://nmap.org/book/man.html · ffuf: https://github.com/ffuf/ffuf · curl: https://curl.se/docs/manpage.html · netcat: https://man.openbsd.org/nc.1
- pymavlink: https://mavlink.io/en/mavgen_python/ · MAVLink 메시지: https://mavlink.io/en/messages/common.html · GPS_INPUT: https://mavlink.io/en/messages/common.html#GPS_INPUT
- MAVProxy: https://ardupilot.org/mavproxy/ · boofuzz: https://boofuzz.readthedocs.io/ · Scapy: https://scapy.readthedocs.io/
- hping3: https://man.he.net/man8/hping3 · Hydra: https://github.com/vanhauser-thc/thc-hydra · sshpass: https://linux.die.net/man/1/sshpass

**C — DVD/네트워크 방어**
- MAVLink 서명: https://mavlink.io/en/guide/message_signing.html · ArduPilot 파라미터: https://ardupilot.org/copter/docs/parameters.html · Failsafe/RTL: https://ardupilot.org/copter/docs/radio-failsafe.html
- sshd_config: https://man.openbsd.org/sshd_config · fail2ban: https://www.fail2ban.org/ · iptables: https://man7.org/linux/man-pages/man8/iptables.8.html
- Suricata: https://docs.suricata.io/ · Snort: https://docs.snort.org/ · tcpdump: https://www.tcpdump.org/manpages/tcpdump.1.html

## 운영상 한계

- 모든 OS에서 동일한 P0 도구가 native로 제공되지는 않는다. 특히 `strace`는 Linux 중심이고, Windows/macOS에서는 Linux runner가 필요하다.
- AFL++는 Linux runner 또는 Docker가 가장 이식성이 높다.
- libFuzzer는 별도 daemon 프로그램이 아니라 Clang으로 `-fsanitize=fuzzer`를 링크한 target binary 자체가 fuzzer가 된다.
- Toolset은 설치를 강제하지 않는다. 누락 도구는 `status: missing`으로 evidence에 남기고, 에이전트가 target과 ToolPlan에 따라 다른 도구를 선택해야 한다.
