#!/usr/bin/env bash
# SecAgent installer for Debian/Ubuntu (systemd).
#
#   sudo ./install.sh                 install + enable + start secagentd
#   sudo ./install.sh --no-start      install, but don't start the service
#   sudo ./install.sh --no-ebpf       don't install bpftrace (agent uses /proc polling)
#   sudo ./install.sh --uninstall     remove the service and program files
#   sudo ./install.sh --uninstall --purge   ...also remove /etc/secagent and /var/lib/secagent
#
# Layout:
#   /opt/secagent/            source + virtualenv (/opt/secagent/venv)
#   /usr/local/bin/secagentd, /usr/local/bin/secagentctl   -> venv entry points
#   /etc/secagent/policy.yaml          policy (never overwritten; new defaults -> .dpkg-style .new)
#   /var/lib/secagent/secagent.db      alerts, events, FIM baseline (0700)
#   /run/secagent/secagentd.sock       control socket (0600)
#   /etc/systemd/system/secagentd.service
set -euo pipefail

PREFIX=/opt/secagent
ETC=/etc/secagent
UNIT=/etc/systemd/system/secagentd.service
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

START=1; EBPF=1; UNINSTALL=0; PURGE=0
for arg in "$@"; do
  case "$arg" in
    --no-start) START=0 ;;
    --no-ebpf) EBPF=0 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

info() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0 $*)"
[[ "$(uname -s)" == "Linux" ]] || die "SecAgent only supports Linux"

if [[ $UNINSTALL -eq 1 ]]; then
  info "stopping and removing secagentd"
  systemctl disable --now secagentd 2>/dev/null || true
  rm -f "$UNIT" /usr/local/bin/secagentd /usr/local/bin/secagentctl
  systemctl daemon-reload || true
  rm -rf "$PREFIX"
  nft delete table inet secagent 2>/dev/null || true   # active-response blocks, if any
  if [[ $PURGE -eq 1 ]]; then
    info "purging $ETC and /var/lib/secagent"
    rm -rf "$ETC" /var/lib/secagent
  else
    info "kept $ETC and /var/lib/secagent (use --purge to remove)"
  fi
  exit 0
fi

# ---------------------------------------------------------------- prerequisites
PY=$(command -v python3 || true)
[[ -n "$PY" ]] || die "python3 not found (apt-get install python3)"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "Python >= 3.11 required, found $("$PY" --version)"
if ! "$PY" -m venv --help >/dev/null 2>&1 || ! "$PY" -c 'import ensurepip' 2>/dev/null; then
  if command -v apt-get >/dev/null; then
    info "installing python3-venv"
    apt-get install -y -qq python3-venv >/dev/null
  else
    die "python3 venv module missing"
  fi
fi

if [[ $EBPF -eq 1 ]] && ! command -v bpftrace >/dev/null; then
  if command -v apt-get >/dev/null; then
    info "installing bpftrace (eBPF backend; skip with --no-ebpf)"
    apt-get install -y -qq bpftrace >/dev/null || warn "bpftrace install failed; falling back to /proc polling"
  else
    warn "bpftrace not available; process/network monitors will use /proc polling"
  fi
fi
[[ -e /sys/kernel/btf/vmlinux ]] || warn "kernel BTF missing: eBPF backend unavailable, /proc polling will be used"

# ---------------------------------------------------------------- program files
info "installing program files to $PREFIX"
mkdir -p "$PREFIX"
rm -rf "$PREFIX/src"
mkdir -p "$PREFIX/src"
cp -r "$SRC/secagent" "$SRC/pyproject.toml" "$SRC/README.md" "$PREFIX/src/"
find "$PREFIX/src" -name '__pycache__' -prune -exec rm -rf {} +
[[ -d "$PREFIX/venv" ]] || "$PY" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q "$PREFIX/src[dashboard]"
ln -sf "$PREFIX/venv/bin/secagentd" /usr/local/bin/secagentd
ln -sf "$PREFIX/venv/bin/secagentctl" /usr/local/bin/secagentctl

# ---------------------------------------------------------------- config + state
install -d -m 0755 "$ETC"
if [[ -f "$ETC/policy.yaml" ]]; then
  install -m 0640 "$SRC/secagent/policy/default_policy.yaml" "$ETC/policy.yaml.new"
  info "kept existing $ETC/policy.yaml (new defaults written to policy.yaml.new)"
else
  install -m 0640 "$SRC/secagent/policy/default_policy.yaml" "$ETC/policy.yaml"
  info "created $ETC/policy.yaml"
fi
/usr/local/bin/secagentctl --policy "$ETC/policy.yaml" policy validate
install -d -m 0700 /var/lib/secagent

# ---------------------------------------------------------------- systemd
install -m 0644 "$SRC/systemd/secagentd.service" "$UNIT"
systemctl daemon-reload
systemctl enable secagentd >/dev/null 2>&1
if [[ $START -eq 1 ]]; then
  info "starting secagentd"
  systemctl restart secagentd
  for _ in $(seq 1 60); do
    [[ -S /run/secagent/secagentd.sock ]] && break
    sleep 0.5
  done
  /usr/local/bin/secagentctl status || { journalctl -u secagentd -n 30 --no-pager; die "secagentd failed to start"; }
fi

cat <<EOF

$(printf '\033[1;32m')SecAgent installed.$(printf '\033[0m')
  status      sudo secagentctl status
  live feed   sudo secagentctl tail
  alerts      sudo secagentctl alerts --since 1h
  dashboard   http://127.0.0.1:8787   (local only; ssh -L 8787:127.0.0.1:8787 for remote)
  policy      $ETC/policy.yaml  ->  sudo secagentctl policy reload
  logs        journalctl -u secagentd -f
EOF
