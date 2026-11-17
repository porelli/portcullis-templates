#!/bin/sh
# The stalwart template's bootstrap job (contract §19.4 via the stalwart
# app page; Rulings T3-a, T17-a, T17-c): runs in the Stalwart image as uid
# 2000 with primary gid 2010 (mailkey), cap_drop ALL and no capability,
# before `stalwart` and `adapter` (service_completed_successfully).
#
# 0. The slot gate (entrypoint.sh --check): unwired, or a void owed
#    outside the Hub's void mode, the job exits 1 before opening the store.
# 1. The server's store lock: the job takes $LOCK with flock -n (fd 9,
#    inherited by mailctl, held for the whole run). When it's busy, the
#    server is running on this store (a later `up` re-runs the job): exit 0
#    without opening the store; RocksDB's own LOCK stays the backstop.
# 2. The job's mark in its job-only tmpfs: the gate wrapper lets the job's
#    own server child start without the slot gate and the store lock.
# 3. `mailctl bootstrap --job` (the binary adapter-bin copied from the
#    pinned adapter image) takes its own lock in the store
#    ($MAILCTL_STORE_DIR) and runs the base plan once per store: the server
#    as its own child through the gate wrapper, in recovery mode with a
#    password made inside the job, the plan, the API key written 0640
#    (group mailkey) to $MAILCTL_API_KEY_FILE in the key volume, a normal
#    start that must refuse the recovery login, then the store's marker. A
#    marked store with its key starts nothing (after a server image change,
#    one start with the role-permission update).
set -eu
# The job is gated too (it gets the slot files: the base plan reads the
# metrics secret there): the P3 predicate before anything else.
/bin/sh /portcullis/gate/entrypoint.sh --check
LOCK="${MAILCTL_STORE_DIR:?MAILCTL_STORE_DIR is required}/.portcullis.lock"
MARK=/run/portcullis/bootstrap/job

: >> "$LOCK"
exec 9<"$LOCK"
if ! flock -n 9; then
  echo "bootstrap: the store is in use (the server is running): nothing to do"
  exit 0
fi
(umask 077; head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$MARK")

exec /portcullis/bin/mailctl bootstrap --job -- \
  /bin/sh /portcullis/gate/entrypoint.sh /usr/local/bin/stalwart --config /portcullis/config/config.json
