#!/usr/bin/env bash
# stalwart/gate/entrypoint.sh with a stub server (no Docker): every case of
# the start gate (mail provider plan P3), the recovery-mode refusal, the
# bootstrap job's own normal start and the store lock. Run in lint (needs
# flock, util-linux). Replaces core's .github/ci/mail-gate-entrypoint.sh,
# which drove core's former mail service.
set -euo pipefail
cd "$(dirname "$0")/../.."
GATE="$PWD/stalwart/gate/entrypoint.sh"
SH="${GATE_SH:-sh}"   # the image's /bin/sh is dash
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
FAILS=0
S="$T/slot"           # the Hub's _mail/ files
J="$T/job/session"    # the bootstrap job's tmpfs session file
K="$T/job/job"        # the job's mark (bootstrap.sh), same tmpfs
L="$T/store/.portcullis.lock"
mkdir -p "$T/job" "$T/store"
printf '#!/bin/sh\necho "STARTED $#:$*"\n' > "$T/server"
chmod +x "$T/server"

reset() {
  chmod -R u+rwx "$S" 2>/dev/null || true
  rm -rf "$S" "$J" "$K"
  mkdir -p "$S"
}

# run NAME WANT(start|refused) [VAR=value ...]: the wrapper with a clean
# environment plus the given variables; "start" = the stub ran with the
# argv unchanged, "refused" = exit 1 and a "refused" line.
run() {
  local name="$1" want="$2" out rc
  shift 2
  set +e
  out=$(env -i PATH="$PATH" PORTCULLIS_MAIL_SLOT_DIR="$S" STALWART_GATE_JOB_SESSION="$J" STALWART_GATE_JOB_MARK="$K" STALWART_GATE_LOCK="$L" "$@" \
    "$SH" "$GATE" "$T/server" --config "/a b/config.json" 2>&1)
  rc=$?
  set -e
  # The lock wait's one notice is expected on a start.
  [ "$want" = start ] && out=$(grep -vxF "stalwart gate: the store is locked (the bootstrap job is running): waiting" <<<"$out" || true)
  case "$want" in
    start)
      if [ "$rc" = 0 ] && [ "$out" = "STARTED 2:--config /a b/config.json" ]; then echo "PASS $name"
      else echo "FAIL $name: rc $rc: $out"; FAILS=$((FAILS + 1)); fi ;;
    refused)
      if [ "$rc" = 1 ] && grep -q 'refused$' <<<"$out" && ! grep -q STARTED <<<"$out"; then echo "PASS $name"
      else echo "FAIL $name: rc $rc: $out"; FAILS=$((FAILS + 1)); fi ;;
  esac
}

N=0123456789abcdef

# .present
reset; run "absent: no slot files" refused
reset; rmdir "$S"; run "absent: no slot directory" refused
reset; printf 'portcullis-mail-gate' > "$S/.present"; run ".present exact" start
reset; printf 'portcullis-mail-gate\n' > "$S/.present"; run ".present with one trailing newline" start
reset; printf 'portcullis-mail-gate\n\n' > "$S/.present"; run ".present with two trailing newlines" refused
reset; printf 'portcullis-mail-gat' > "$S/.present"; run "wrong .present" refused
reset; printf 'portcullis-mail-gate ' > "$S/.present"; run ".present with a trailing space" refused
reset; printf 'portcullis-mail-gate\0' > "$S/.present"; run ".present with a NUL" refused
reset; : > "$S/.present"; run "empty .present" refused
reset; mkdir "$S/.present"; run ".present a directory" refused
if [ "$(id -u)" != 0 ]; then
  reset; printf 'portcullis-mail-gate' > "$S/.present"; chmod 000 "$S/.present"; run "unreadable .present" refused
  reset; printf 'portcullis-mail-gate' > "$S/.present"; chmod 000 "$S"; run "unreadable slot directory" refused
else
  echo "SKIP unreadable cases (root reads everything)"
fi

# void-pending
reset; : > "$S/void-pending"; run "void-pending without a session" refused PORTCULLIS_MAIL_VOID_SESSION="$N"
reset; : > "$S/void-pending"; : > "$S/void-session"; run "void-pending with an empty session" refused PORTCULLIS_MAIL_VOID_SESSION=
reset; : > "$S/void-pending"; printf '%s' "$N" > "$S/void-session"; run "void-pending, no nonce in the env" refused
reset; : > "$S/void-pending"; printf '%s' "$N" > "$S/void-session"; run "void-pending, wrong nonce" refused PORTCULLIS_MAIL_VOID_SESSION=0123456789abcdee
reset; : > "$S/void-pending"; printf '%s\n' "$N" > "$S/void-session"; run "void-pending, nonce differs by a newline" refused PORTCULLIS_MAIL_VOID_SESSION="$N"
reset; : > "$S/void-pending"; printf '%s' "$N" > "$S/void-session"; run "void-pending, right nonce" start PORTCULLIS_MAIL_VOID_SESSION="$N"
reset; ln -s nowhere "$S/void-pending"; printf '%s' "$N" > "$S/void-session"; run "void-pending a dangling symlink, no nonce" refused
reset; printf 'portcullis-mail-gate' > "$S/.present"; : > "$S/void-pending"; run ".present with void-pending, no nonce" refused
reset; printf 'portcullis-mail-gate' > "$S/.present"; : > "$S/void-pending"; printf '%s' "$N" > "$S/void-session"
run ".present with void-pending, wrong nonce" refused PORTCULLIS_MAIL_VOID_SESSION=x
reset; printf 'portcullis-mail-gate' > "$S/.present"; : > "$S/void-pending"; printf '%s' "$N" > "$S/void-session"
run ".present with void-pending, right nonce" start PORTCULLIS_MAIL_VOID_SESSION="$N"

# Recovery mode: only inside the bootstrap job, with its nonce.
reset; printf 'portcullis-mail-gate' > "$S/.present"
run "recovery mode outside the job (gate open)" refused STALWART_RECOVERY_MODE=1 MAILCTL_RECOVERY_SESSION="$N"
run "recovery admin alone outside the job" refused STALWART_RECOVERY_ADMIN=a:b
run "any STALWART_RECOVERY_ variable outside the job" refused STALWART_RECOVERY_X=
printf '%s' "$N" > "$J"
run "recovery mode, job session, no nonce" refused STALWART_RECOVERY_MODE=1
run "recovery mode, job session, wrong nonce" refused STALWART_RECOVERY_MODE=1 MAILCTL_RECOVERY_SESSION=x
run "recovery mode, job session, right nonce" start STALWART_RECOVERY_MODE=1 STALWART_RECOVERY_ADMIN=a:b MAILCTL_RECOVERY_SESSION="$N"
: > "$J"
run "recovery mode, empty job session, empty nonce" refused STALWART_RECOVERY_MODE=1 MAILCTL_RECOVERY_SESSION=

# The job's own normal start (no gate, no lock: the job holds it).
reset; printf '%s' "$N" > "$K"
exec 8>"$L"; flock 8   # the job's lock, held while it runs
run "the job's normal start (no session file: an image-update start), gate closed, store locked" start MAILCTL_JOB_SESSION_FILE="$J"
run "job session file named differently" refused MAILCTL_JOB_SESSION_FILE="$J.other"
run "the job's mark without MAILCTL_JOB_SESSION_FILE" refused
: > "$K"
run "the job's start with an empty mark" refused MAILCTL_JOB_SESSION_FILE="$J"
rm -f "$K"; printf '%s' "$N" > "$J"
run "the job's start with a session file but no mark" refused MAILCTL_JOB_SESSION_FILE="$J"

# The store lock: a gated start waits while the job holds it.
reset; printf 'portcullis-mail-gate' > "$S/.present"
( sleep 2; flock -u 8 ) &
start=$(date +%s)
run "a gated start waits for the job's lock" start
waited=$(( $(date +%s) - start ))
exec 8>&-
wait
if [ "$waited" -ge 1 ]; then echo "PASS the start waited ${waited}s for the lock"; else echo "FAIL the start didn't wait (${waited}s)"; FAILS=$((FAILS + 1)); fi
run "a gated start, lock free" start
# The server keeps the lock (fd 9 across exec): a second opener can't take it.
printf '#!/bin/sh\nif flock -n 7 7<"%s"; then echo "STARTED unlocked"; else echo "STARTED locked"; fi\n' "$L" > "$T/server"
out=$(env -i PATH="$PATH" PORTCULLIS_MAIL_SLOT_DIR="$S" STALWART_GATE_LOCK="$L" "$SH" "$GATE" "$T/server" 2>&1 || true)
if [ "$out" = "STARTED locked" ]; then echo "PASS the server's lock blocks another opener"; else echo "FAIL lock not held by the server: $out"; FAILS=$((FAILS + 1)); fi

# --check: the predicate only (the bootstrap job's gate), never a server,
# never the job's bypasses.
chk() {
  local name="$1" want="$2" rc
  shift 2
  set +e
  env -i PATH="$PATH" PORTCULLIS_MAIL_SLOT_DIR="$S" STALWART_GATE_JOB_SESSION="$J" STALWART_GATE_JOB_MARK="$K" \
    STALWART_GATE_LOCK="$L" "$@" "$SH" "$GATE" --check >/dev/null 2>&1
  rc=$?
  set -e
  if [ "$rc" = "$want" ]; then echo "PASS $name"; else echo "FAIL $name: rc $rc"; FAILS=$((FAILS + 1)); fi
}
reset; printf 'portcullis-mail-gate' > "$S/.present"
exec 8>"$L"; flock 8
chk "--check, gate open, store locked: 0 at once" 0
exec 8>&-
reset; chk "--check, gate closed: 1" 1
reset; printf '%s' "$N" > "$K"; printf '%s' "$N" > "$J"
chk "--check ignores the job's mark: 1" 1 MAILCTL_JOB_SESSION_FILE="$J"
chk "--check ignores recovery mode: 1" 1 STALWART_RECOVERY_MODE=1 MAILCTL_RECOVERY_SESSION="$N"
reset; : > "$S/void-pending"; printf '%s' "$N" > "$S/void-session"
chk "--check in the Hub's void mode: 0" 0 PORTCULLIS_MAIL_VOID_SESSION="$N"

# No server command at all.
set +e
out=$(env -i PATH="$PATH" PORTCULLIS_MAIL_SLOT_DIR="$S" "$SH" "$GATE" 2>&1); rc=$?
set -e
if [ "$rc" = 1 ]; then echo "PASS no server command: refused"; else echo "FAIL no server command: rc $rc $out"; FAILS=$((FAILS + 1)); fi

if [ "$FAILS" -gt 0 ]; then echo "$FAILS failure(s)"; exit 1; fi
echo "all gate cases passed"
