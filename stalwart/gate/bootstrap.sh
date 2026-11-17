#!/bin/sh
# The stalwart template's bootstrap job (contract §19.4 via the stalwart
# app page; Rulings T3-a, T3-b, T17-a): runs in the Stalwart image as uid
# 2000 with primary gid 2010 (mailkey), cap_drop ALL and no capability,
# before `stalwart` and `adapter` (service_completed_successfully).
#
# 1. The store lock: the job takes $LOCK with flock -n and holds it (fd 9,
#    inherited by mailctl) for its whole run. When it's busy, the server is
#    running on this store (a later `up` re-runs the job): exit 0 without
#    opening the store; RocksDB's own LOCK stays the backstop.
# 2. `mailctl bootstrap --job` (the binary the adapter-bin job copied from
#    the pinned adapter image) starts the server as its own child, through
#    the gate wrapper, in recovery mode with a password made inside the job,
#    applies the base plan (re-run on every cold start, Ruling T3-b), writes
#    Stalwart's API key into $MAILCTL_DATA (this job's key volume), then
#    starts the server normally once and exits 0 only when the recovery
#    login is refused there.
# 3. The key is made 0640 (group mailkey): the adapter reads it through its
#    read-only mount of the key volume with group_add mailkey. No other
#    service mounts that volume (Ruling T17-a).
set -eu
umask 027
LOCK=/var/lib/stalwart/.portcullis.lock
KEY="${MAILCTL_DATA:?MAILCTL_DATA is required}/api-key"

: >> "$LOCK"
exec 9<"$LOCK"
if ! flock -n 9; then
  echo "bootstrap: the store is in use (the server is running): nothing to do"
  exit 0
fi

/portcullis/bin/mailctl bootstrap --job -- \
  /bin/sh /portcullis/gate/entrypoint.sh /usr/local/bin/stalwart --config /portcullis/config/config.json &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' TERM INT
rc=0
wait "$pid" || rc=$?
# A signal interrupts the first wait: wait again for mailctl to stop its server.
while kill -0 "$pid" 2>/dev/null; do wait "$pid" || rc=$?; done
[ "$rc" -eq 0 ] || { echo "bootstrap: mailctl bootstrap failed (exit $rc)" >&2; exit "$rc"; }

[ -s "$KEY" ] || { echo "bootstrap: no API key at $KEY" >&2; exit 1; }
chmod 0640 "$KEY"
echo "bootstrap: done"
