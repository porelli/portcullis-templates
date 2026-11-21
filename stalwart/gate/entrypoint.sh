#!/bin/sh
# The stalwart server's start gate (contract §19.4, mail provider plan P3),
# the entrypoint of the `stalwart` service and of the bootstrap job's
# server child. Usage: entrypoint.sh <server argv...> (exec'd unchanged);
# entrypoint.sh --check runs only the slot predicate and exits 0 (the
# bootstrap job's own gate, bootstrap.sh).
#
# Every start first needs the P3 predicate over the Hub's slot files
# ($SLOT, the override's PORTCULLIS_MAIL_SLOT_DIR):
#   - void-pending absent and .present exactly "portcullis-mail-gate" (one
#     optional trailing newline, nothing else);
#   - or void-pending present, void-session non-empty and equal to
#     $PORTCULLIS_MAIL_VOID_SESSION byte for byte.
# Anything else, an unreadable file included, exits 1 before the server
# starts. Then, in this order:
#
# 1. Recovery mode (any STALWART_RECOVERY_* variable set): only inside the
#    bootstrap job. Its job-only tmpfs holds the session nonce the job made
#    ($JOB_SESSION), and the job passes the same nonce to its server child
#    as MAILCTL_RECOVERY_SESSION; both must be non-empty and equal byte for
#    byte. No store lock: the job already holds it (a second flock on a new
#    descriptor would wait for the job itself).
# 2. The job's normal starts (the recovery login refused; after a server
#    image change, the role-permission update): MAILCTL_JOB_SESSION_FILE is
#    exactly $JOB_SESSION and the job's mark $JOB_MARK (bootstrap.sh writes
#    it into the same job-only tmpfs before mailctl runs) is non-empty. No
#    store lock (the job holds it). The job is gated too: the predicate is
#    checked here again, at the child's start (review L9).
# 3. Every other start: the store lock ($LOCK, flock on fd 9, inherited by
#    the server through exec and held for its lifetime) waits up to 600 s
#    while the bootstrap job holds it (Ruling T3-a): two openers of the
#    RocksDB store never overlap. Then exec.
#
# The job's paths are fixed here (no variable moves them; the test runs a
# rewritten copy). Forging case 1 or 2 on the `stalwart` service needs a
# compose change (a tmpfs at /run/portcullis/bootstrap holding the nonce or
# the mark, plus the variables): that is a template change, which holds a
# wired provider until an admin re-confirms it (plan P4).
set -u
export LC_ALL=C

SLOT="${PORTCULLIS_MAIL_SLOT_DIR:-/run/portcullis/mail/slot}"
JOB_SESSION=/run/portcullis/bootstrap/session
JOB_MARK=/run/portcullis/bootstrap/job
LOCK=/var/lib/stalwart/.portcullis.lock
SENTINEL=portcullis-mail-gate
NL='
'

refuse() { echo "stalwart gate: $*: refused" >&2; exit 1; }

[ "$#" -gt 0 ] || refuse "no server command"

# read_exact FILE: R = the file's bytes exactly (every trailing newline
# kept: $(cat) would strip them), at most 4096 bytes; fails when the file
# can't be read, is larger, or holds a NUL (the shell drops those).
read_exact() {
  R="$(head -c 4097 "$1" 2>/dev/null && printf x)" || return 1
  R="${R%x}"
  n="$(wc -c < "$1" 2>/dev/null)" || return 1
  [ "${#R}" -le 4096 ] && [ "$n" -eq "${#R}" ]
}

if [ -e "$SLOT/void-pending" ] || [ -L "$SLOT/void-pending" ]; then
  read_exact "$SLOT/void-session" || refuse "the mail gate is closed: a void is owed and this isn't the Hub's void mode"
  if [ -z "$R" ] || [ -z "${PORTCULLIS_MAIL_VOID_SESSION:-}" ] || [ "$R" != "$PORTCULLIS_MAIL_VOID_SESSION" ]; then
    refuse "the mail gate is closed: a void is owed and this isn't the Hub's void mode"
  fi
else
  read_exact "$SLOT/.present" || refuse "the mail gate isn't readable: the slot's files are missing (is this instance wired?)"
  [ "$R" = "$SENTINEL" ] || [ "$R" = "$SENTINEL$NL" ] || refuse "the mail gate is closed: .present isn't the gate sentinel"
fi

[ "$1" != --check ] || exit 0

# The read-only mail admin view (contract §19.13): Stalwart serves its web
# admin's sign-in only to its trusted host, the admin view's hostname the
# Hub's override passes.
if [ -n "${PORTCULLIS_MAIL_ADMIN_HOST:-}" ]; then
  case "$PORTCULLIS_MAIL_ADMIN_HOST" in
    *[!a-z0-9.-]* | .* | *. ) refuse "PORTCULLIS_MAIL_ADMIN_HOST isn't a hostname" ;;
  esac
  export STALWART_PUBLIC_URL="https://$PORTCULLIS_MAIL_ADMIN_HOST"
fi

if env | grep -q '^STALWART_RECOVERY_'; then
  read_exact "$JOB_SESSION" || refuse "a recovery-mode start outside the bootstrap job"
  if [ -z "$R" ] || [ -z "${MAILCTL_RECOVERY_SESSION:-}" ] || [ "$R" != "$MAILCTL_RECOVERY_SESSION" ]; then
    refuse "a recovery-mode start outside the bootstrap job"
  fi
  exec "$@"
fi

if [ "${MAILCTL_JOB_SESSION_FILE:-}" = "$JOB_SESSION" ] && read_exact "$JOB_MARK" && [ -n "$R" ]; then
  exec "$@"
fi

{ : >> "$LOCK"; } 2>/dev/null || refuse "the store lock $LOCK can't be created"
exec 9<"$LOCK" || refuse "the store lock $LOCK isn't readable"
if ! flock -n 9; then
  echo "stalwart gate: the store is locked (the bootstrap job is running): waiting" >&2
  flock -w 600 9 || refuse "the store stayed locked for 600 s"
fi
exec "$@"
