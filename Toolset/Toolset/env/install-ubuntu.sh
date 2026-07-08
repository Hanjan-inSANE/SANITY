#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
WITH_AFL_SOURCE=0
WITH_PYTEST=1

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --with-afl-source) WITH_AFL_SOURCE=1 ;;
    --without-pytest) WITH_PYTEST=0 ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '[dry-run] %q ' "$@"
    printf '\n'
  else
    "$@"
  fi
}

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

echo "Installing DAH Toolset P0 host dependencies for Ubuntu/Debian."
run "${SUDO[@]}" apt-get update
run "${SUDO[@]}" apt-get install -y \
  build-essential \
  automake \
  bison \
  cargo \
  clang \
  cmake \
  cpio \
  curl \
  flex \
  g++ \
  gcc \
  gdb \
  git \
  lld \
  llvm \
  llvm-dev \
  make \
  ninja-build \
  python3 \
  python3-dev \
  python3-pip \
  strace \
  wget

if [[ "$WITH_PYTEST" == "1" ]]; then
  run python3 -m pip install --user pytest
fi

if [[ "$WITH_AFL_SOURCE" == "1" ]]; then
  WORK="${TOOLSET_THIRD_PARTY_DIR:-$HOME/.local/src}"
  run mkdir -p "$WORK"
  if [[ ! -d "$WORK/AFLplusplus/.git" ]]; then
    run git clone https://github.com/AFLplusplus/AFLplusplus "$WORK/AFLplusplus"
  fi
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] cd $WORK/AFLplusplus && make source-only && sudo make install"
  else
    make -C "$WORK/AFLplusplus" source-only
    "${SUDO[@]}" make -C "$WORK/AFLplusplus" install
  fi
else
  echo "AFL++ source build skipped. Re-run with --with-afl-source or use Docker image aflplusplus/aflplusplus."
fi

echo "Installing SANITY extended toolset (A-source/crash + B/C DVD net/drone). Best-effort."
run "${SUDO[@]}" apt-get install -y \
  maven lldb rr ltrace bpftrace valgrind cppcheck honggfuzz \
  nmap hydra hping3 sshpass curl ffuf netcat-openbsd tcpdump fail2ban iptables suricata || true
run python3 -m pip install --user pymavlink MAVProxy boofuzz scapy semgrep bandit || true
echo "NOTE: codeql(CLI), snort, aflnet 는 apt 미제공 → 수동/소스 설치(각 도구 docs_url 참고)."

python3 "$(dirname "$0")/check_environment.py" --write-config
