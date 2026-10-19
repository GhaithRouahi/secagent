#!/usr/bin/env bash
# Run the full SecAgent test suite and print a clear pass/fail summary.
#
#   ./run_tests.sh               all tests (unit + integration)
#   ./run_tests.sh unit          unit tests only (no privileges needed)
#   ./run_tests.sh integration   simulated-attack integration tests
#   sudo ./run_tests.sh          as root: also runs eBPF, setuid, kill and nftables tests
#
# Uses a virtualenv at $SECAGENT_VENV (default: .venv, or ~/.venvs/secagent when the
# repo lives on a Windows drive under WSL, where venvs don't work well).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

case "$(pwd)" in
  /mnt/*) DEFAULT_VENV="$HOME/.venvs/secagent" ;;
  *)      DEFAULT_VENV=".venv" ;;
esac
VENV="${SECAGENT_VENV:-$DEFAULT_VENV}"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "==> creating virtualenv in $VENV"
  python3 -m venv "$VENV" || { echo "python3 -m venv failed (apt-get install python3-venv)"; exit 1; }
fi
if ! "$VENV/bin/python" -c 'import yaml, pytest, fastapi, httpx' 2>/dev/null; then
  echo "==> installing test dependencies"
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q "pyyaml>=6" "pytest>=8" "httpx>=0.27" "fastapi>=0.110" "uvicorn>=0.29"
fi

case "${1:-all}" in
  unit)        TARGET=tests/unit ;;
  integration) TARGET=tests/integration ;;
  all)         TARGET=tests ;;
  *)           TARGET="$*" ;;
esac

echo "==> environment"
echo "    kernel:   $(uname -r)"
echo "    python:   $("$VENV/bin/python" --version)"
echo "    user:     $(id -un) (uid $(id -u))$([[ $(id -u) -ne 0 ]] && echo '  <- run with sudo to include eBPF/root tests')"
echo "    bpftrace: $(command -v bpftrace >/dev/null && bpftrace --version || echo 'not installed (eBPF tests will be skipped)')"
echo

"$VENV/bin/python" -m pytest "$TARGET" -v -rs -p no:cacheprovider -W ignore::DeprecationWarning \
  --tb=short --durations=5
STATUS=$?

echo
if [[ $STATUS -eq 0 ]]; then
  printf '\033[1;32m========================  ALL TESTS PASSED  ========================\033[0m\n'
else
  printf '\033[1;31m========================  TESTS FAILED (exit %d)  ===================\033[0m\n' "$STATUS"
fi
exit $STATUS
