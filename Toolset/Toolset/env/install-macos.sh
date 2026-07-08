#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
WITH_AFL_SOURCE=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --with-afl-source) WITH_AFL_SOURCE=1 ;;
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

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required. Install from https://brew.sh/ and re-run this script." >&2
  exit 2
fi

echo "Installing DAH Toolset P0 host dependencies for macOS via Homebrew."
run brew update
run brew install cmake coreutils gdb git llvm make ninja python wget

echo "Note: macOS does not provide Linux strace. Toolset trace_runtime will report strace as missing unless you run inside Linux/WSL/Docker."
echo "Note: Homebrew GDB normally needs macOS code signing before it can debug local processes."

if [[ "$WITH_AFL_SOURCE" == "1" ]]; then
  WORK="${TOOLSET_THIRD_PARTY_DIR:-$HOME/.local/src}"
  run mkdir -p "$WORK"
  if [[ ! -d "$WORK/AFLplusplus/.git" ]]; then
    run git clone https://github.com/AFLplusplus/AFLplusplus "$WORK/AFLplusplus"
  fi
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] PATH will include Homebrew llvm/coreutils before make source-only"
  else
    HOMEBREW_PREFIX="$(brew --prefix)"
    export PATH="$HOMEBREW_PREFIX/opt/coreutils/libexec/gnubin:$HOMEBREW_PREFIX/opt/llvm/bin:$HOMEBREW_PREFIX/bin:$PATH"
    export CC=clang
    export CXX=clang++
    make -C "$WORK/AFLplusplus" source-only
    sudo make -C "$WORK/AFLplusplus" install
  fi
else
  echo "AFL++ source build skipped. Re-run with --with-afl-source or use a Linux VM/Docker image for AFL++."
fi

python3 "$(dirname "$0")/check_environment.py" --write-config
