#!/usr/bin/env bash
# shellcheck disable=SC2034 # variables used inside eval'd checks
# Unit tests of portcullis-sync (contract §13.17), the converge script the
# Samba and Time Machine templates share. Every tool the script calls that
# changes the system or needs Samba is a stub on PATH that records its argv
# (one line per call in $LOG); the file system is a scratch tree the script
# sees through PORTCULLIS_SYNC_ROOT. Runs on Linux and macOS, no root, no
# Docker:
#
#   bash tests/sync/test_portcullis_sync.sh [test_name ...]
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO=$PWD
SCRIPT="$REPO/timemachine/bin/portcullis-sync"

ORIG_PATH=$PATH
PASS=0
FAIL=0
FAILED=()
TAB=$(printf '\t')

# 32-hex NT hashes (test values, uppercase like the Hub's).
H_ALICE=0123456789ABCDEF0123456789ABCDEF
H_ALICE2=FEDCBA9876543210FEDCBA9876543210
H_BOB=AAAABBBBCCCCDDDDEEEEFFFF00001111
H_CAROL=1111222233334444555566667777AAAA

# ── scratch tree + stubs ─────────────────────────────────────
setup() {
  T=$(mktemp -d "${TMPDIR:-/tmp}/psync.XXXXXX")
  R="$T/root"
  STUBS="$T/stubs"
  LOG="$T/argv.log"
  : > "$LOG"
  mkdir -p "$R/portcullis/data" "$R/portcullis/secrets" "$R/opt" "$R/etc/samba" \
    "$R/run/portcullis" "$R/var/lib/samba/private" "$R/proc/self" "$STUBS"
  : > "$R/proc/self/mountinfo"
  # The image's own accounts (a few) and nothing managed.
  printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\navahi:x:86:86::/dev/null:/sbin/nologin\n' > "$R/etc/passwd"
  printf 'root:x:0:\nwheel:x:10:root\nusers:x:100:\nnogroup:x:65533:\nnobody:x:65534:\n' > "$R/etc/group"
  : > "$T/owners"     # fake stat: "<path> <uid> <gid> <mode> <dev>"
  : > "$T/smbstatus"  # fake sessions: "<pid> <uid>"
  write_stubs
  export PATH="$STUBS:$ORIG_PATH"
  export PORTCULLIS_SYNC_ROOT="$R" STUB_LOG="$LOG" STUB_T="$T"
  export PORTCULLIS_FLAVOUR=timemachine PORTCULLIS_INSTANCE=tm1
  export PORTCULLIS_LOCAL_NETWORKS='192.168.0.0/16,fd00:1::/64'
  export PORTCULLIS_SMB_PORT=445
  export PORTCULLIS_USERNAME_PATTERN='^[a-z_][a-z0-9_.-]{0,31}$'
  export PORTCULLIS_USERNAME_RESERVED='root bin daemon nobody timemachine wheel users'
  export MIMIC_MODEL='TimeCapsule8,119'
  unset STUB_TESTPARM_DROP STUB_TESTPARM_SET STUB_SMBD_RUNNING STUB_SMBSTATUS_FAIL STUB_SMBSTATUS_STICKY STUB_CP_FAIL 2>/dev/null || true
  for n in 1 2 3 4 5 6 7 8; do unset "PORTCULLIS_FOLDER_GID_SHARE${n}_FOLDER" 2>/dev/null || true; done
  SLEEPERS=()
}

teardown() {
  local p
  for p in ${SLEEPERS[@]+"${SLEEPERS[@]}"}; do kill -KILL "$p" 2>/dev/null || true; done
  rm -rf "$T"
}

stub() {  # stub <name> <body>: records argv, then runs body
  {
    printf '#!/bin/sh\n'
    printf 'printf "%%s" "%s" >> "$STUB_LOG"; for a in "$@"; do printf " %%s" "$a" >> "$STUB_LOG"; done; printf "\\n" >> "$STUB_LOG"\n' "$1"
    printf '%s\n' "$2"
  } > "$STUBS/$1"
  chmod +x "$STUBS/$1"
}

write_stubs() {
  # s6-applyuidgid: drop the id flags, run the command (the uid drop is
  # what production does; here it is only recorded).
  stub s6-applyuidgid 'while [ $# -gt 0 ]; do case "$1" in -u|-g|-G) shift 2 ;; *) break ;; esac; done; exec "$@"'
  stub timeout 'shift; exec "$@"'
  stub flock ':'
  # cp: the real one, or a failure (STUB_CP_FAIL) mid-run.
  REAL_CP=$(env PATH="$ORIG_PATH" sh -c "command -v cp")
  stub cp "[ -z \"\${STUB_CP_FAIL:-}\" ] || exit 1; exec $REAL_CP \"\$@\""
  # chown <uid>:<gid> <path>: what stat then reports for the path.
  stub chown 'o=${1%%:*}; g=${1#*:}; echo "$2 $o $g 700 1" >> "$STUB_T/owners"'
  stub s6-svc ':'
  stub smbcontrol ':'
  # "running" without a pid: the script's fail-closed kill finds nothing real.
  stub pidof '[ -n "${STUB_SMBD_RUNNING:-}" ] && exit 0; exit 1'
  # stat -c '%u %g %a %d' PATH: from the owners table, else the caller.
  stub stat 'p=; for a do p=$a; done; l=$(awk -v p="$p" '"'"'$1 == p { l = $2 " " $3 " " $4 " " $5 } END { print l }'"'"' "$STUB_T/owners"); if [ -n "$l" ]; then echo "$l"; else echo "$(id -u) $(id -g) 700 1"; fi'
  # smbstatus -p -n: the live sessions (like the real one, which drops
  # dead processes); STUB_SMBSTATUS_STICKY lists dead ones too (a session
  # that survived), STUB_SMBSTATUS_FAIL fails.
  stub smbstatus '[ -z "${STUB_SMBSTATUS_FAIL:-}" ] || exit 1; echo; echo "Samba version 4.23.8"; echo "PID     Username     Group        Machine"; echo "-------------------------------------"; while read -r pid uid; do [ -n "$pid" ] || continue; [ -n "${STUB_SMBSTATUS_STICKY:-}" ] || kill -0 "$pid" 2>/dev/null || continue; echo "$pid     $uid        $uid        192.168.1.20 (ipv4:192.168.1.20:50000)  SMB3_11  AES-128-GCM  partial(AES-128-GMAC)"; done < "$STUB_T/smbstatus"; exit 0'
  # Accounts: the busybox tools, writing the scratch /etc files.
  stub addgroup 'g=; n=; while [ $# -gt 0 ]; do case "$1" in -g) g=$2; shift 2 ;; *) n=$1; shift ;; esac; done; echo "$n:x:$g:" >> "$PORTCULLIS_SYNC_ROOT/etc/group"'
  stub adduser 'u=; n=; while [ $# -gt 0 ]; do case "$1" in -u|-G|-s|-h) [ "$1" = -u ] && u=$2; shift 2 ;; -*) shift ;; *) n=$1; shift ;; esac; done; echo "$n:x:$u:$u::/nonexistent:/bin/false" >> "$PORTCULLIS_SYNC_ROOT/etc/passwd"'
  stub deluser 'f=$PORTCULLIS_SYNC_ROOT/etc/passwd; awk -F: -v n="$1" '"'"'$1 != n'"'"' "$f" > "$f.t" && mv "$f.t" "$f"'
  stub delgroup 'f=$PORTCULLIS_SYNC_ROOT/etc/group; awk -F: -v n="$1" '"'"'$1 != n'"'"' "$f" > "$f.t" && mv "$f.t" "$f"'
  # testparm -s -v [FILE]: a small model of the real one. It prints every
  # parameter of the file with testparm's normalised spellings (mandatory ->
  # required, yes -> Yes, never -> Never), the global defaults the script
  # checks, and a share's parameters only when they differ from the
  # defaults. STUB_TESTPARM_DROP=<param> leaves one out, STUB_TESTPARM_SET
  # ="<section>|<param>|<value>" adds/overrides one (a tampered config).
  cat > "$STUBS/testparm" << 'EOF'
#!/bin/sh
printf "testparm" >> "$STUB_LOG"; for a in "$@"; do printf " %s" "$a" >> "$STUB_LOG"; done; printf "\n" >> "$STUB_LOG"
f="$PORTCULLIS_SYNC_ROOT/etc/samba/smb.conf"
for a in "$@"; do case "$a" in -*) ;; *) f=$a ;; esac; done
[ -f "$f" ] || { echo "Can't load $f" >&2; exit 1; }
echo "Load smb config files from $f" >&2
awk -v drop="${STUB_TESTPARM_DROP:-}" -v set="${STUB_TESTPARM_SET:-}" '
function norm(v,  l) {
  l = tolower(v)
  if (l == "yes") return "Yes"
  if (l == "no") return "No"
  if (l == "mandatory") return "required"
  if (l == "never") return "Never"
  return v
}
function emit(s, k, v) {
  if (k == drop) return
  if (s != "global" && ((k == "guest ok" && v == "No") || (k == "read only" && v == "Yes"))) return
  out[s] = out[s] "\t" k " = " v "\n"
}
BEGIN { split(set, st, "|") }
/^[ \t]*[#;]/ || /^[ \t]*$/ { next }
/^\[/ { s = $0; sub(/^\[/, "", s); sub(/\][ \t]*$/, "", s); if (!(s in seen)) { order[++n] = s; seen[s] = 1 }; next }
{
  line = $0; sub(/^[ \t]+/, "", line)
  i = index(line, "="); if (i == 0) next
  k = substr(line, 1, i - 1); v = substr(line, i + 1)
  sub(/[ \t]+$/, "", k); sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
  if (k == "smb ports") k = "server smb transports"   # a synonym (Samba 4.23)
  if (st[1] == s && st[2] == k) next
  emit(s, k, norm(v))
}
END {
  if (st[1] != "") { if (!(st[1] in seen)) order[++n] = st[1]; emit(st[1], st[2], st[3]) }
  print "# Global parameters"
  print "[global]"
  printf "%s", out["global"]
  if (drop != "config backend") print "\tconfig backend = file"
  if (drop != "registry shares") print "\tregistry shares = No"
  print "\tinclude = "
  for (j = 1; j <= n; j++) if (order[j] != "global") { printf "\n[%s]\n%s", order[j], out[order[j]] }
}' "$f"
EOF
  chmod +x "$STUBS/testparm"
}

# ── fixtures ─────────────────────────────────────────────────
people() {  # people <line>...: people.tsv with version + instance first
  { printf 'version\t1\ninstance\t%s\n' "${PORTCULLIS_INSTANCE}"; printf '%s\n' "$@" | sed 's/|/\t/g'; } > "$R/portcullis/data/people.tsv"
}
nt() { printf '%s\n' "$2" > "$R/portcullis/secrets/$1.nt"; }
own() { echo "$1 $2 $3 $4 ${5:-1}" >> "$T/owners"; }      # own <path> <uid> <gid> <mode> [dev]
session() {  # session <uid> [ignore-term]: a live process smbstatus lists for uid
  if [ "${2:-}" = ignore-term ]; then (trap '' TERM; while :; do sleep 1; done) & else sleep 300 & fi
  local p=$!
  disown "$p" 2>/dev/null || true
  SLEEPERS+=("$p")
  mkdir -p "$R/proc/$p"; echo smbd > "$R/proc/$p/comm"
  echo "$p $1" >> "$T/smbstatus"
  LAST_PID=$p
}
alive() { kill -0 "$1" 2>/dev/null; }

run() {  # run [args]: OUT, ERR, RC
  set +e
  "$SCRIPT" "$@" > "$T/out" 2> "$T/err" < /dev/null
  RC=$?
  set -e
  OUT=$(cat "$T/out"); ERR=$(cat "$T/err")
}
report() { sed -n 's/^PORTCULLIS-REPORT //p' "$T/out"; }
conf() { cat "$R/etc/samba/smb.conf"; }
passdb() { cat "$R/var/lib/samba/private/smbpasswd" 2>/dev/null || true; }

ok() { PASS=$((PASS + 1)); }
no() { FAIL=$((FAIL + 1)); FAILED+=("$CUR: $*"); echo "    FAIL: $*"; }
check() { if eval "$1"; then ok; else no "${2:-$1}"; fi; }
has() { case "$1" in *"$2"*) return 0 ;; esac; return 1; }

# ── tests ────────────────────────────────────────────────────
test_hardened_global() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  run --boot
  check '[ "$RC" = 0 ]' "boot exits 0 (rc $RC: $ERR)"
  local l
  for l in 'server min protocol = SMB3' 'server smb encrypt = required' 'server signing = mandatory' \
      'ntlm auth = ntlmv2-only' 'lanman auth = no' 'map to guest = never' 'restrict anonymous = 2' \
      'disable netbios = yes' 'smb ports = 445' 'wide links = no' \
      'hosts allow = 192.168.0.0/16 fd00:1::/64' 'hosts deny = 0.0.0.0/0 ::/0' 'guest ok = no'; do
    check 'conf | sed -n "/^\[global\]/,/^\[/p" | grep -qxF "   $l"' "[global] has '$l'"
  done
  check '! conf | grep -qi "^[[:space:]]*include"' "no include"
  # A testparm that drops one hardened line: exit 4, naming it, and the
  # config already in place is left as it was.
  cp "$R/etc/samba/smb.conf" "$T/before"
  people 'person|alice|uid|20000' 'person|bob|uid|20001'
  nt bob "$H_BOB"
  STUB_TESTPARM_DROP='server smb encrypt' run
  check '[ "$RC" = 4 ]' "dropped server smb encrypt: exit 4 (rc $RC)"
  check 'has "$ERR" "server smb encrypt"' "the error names the parameter: $ERR"
  check 'cmp -s "$R/etc/samba/smb.conf" "$T/before"' "smb.conf unchanged after a refused verification"
  check '! has "$OUT" PORTCULLIS-REPORT' "no report on failure"
  # A weakened value (hosts allow opened up) is refused too.
  STUB_TESTPARM_SET='global|hosts allow|0.0.0.0/0' run
  check '[ "$RC" = 4 ]' "weakened hosts allow: exit 4 (rc $RC)"
  # include / registry config in the effective configuration: exit 4.
  STUB_TESTPARM_SET='global|include|/tmp/evil.conf' run
  check '[ "$RC" = 4 ] && has "$ERR" include' "an include: exit 4 (rc $RC: $ERR)"
  STUB_TESTPARM_SET='global|config backend|registry' run
  check '[ "$RC" = 4 ]' "config backend registry: exit 4 (rc $RC)"
  # A share that testparm says opens guest access: exit 4.
  STUB_TESTPARM_SET='TimeMachine-alice|guest ok|Yes' run
  check '[ "$RC" = 4 ]' "a guest share: exit 4 (rc $RC)"
  # A share testparm sees that we never rendered: exit 4.
  STUB_TESTPARM_SET='printers|path|/tmp' run
  check '[ "$RC" = 4 ]' "an extra share: exit 4 (rc $RC)"
  # At hook time a refused verification stops smbd (fail closed).
  : > "$LOG"
  STUB_SMBD_RUNNING=1 STUB_TESTPARM_DROP='server signing' run
  check '[ "$RC" = 4 ] && grep -q "^s6-svc -d" "$LOG"' "hook-time refusal brings smbd down"
}

test_no_empty_valid_users() {
  people
  run --boot
  check '[ "$RC" = 0 ]' "nobody: exit 0 (rc $RC: $ERR)"
  check '! conf | grep -q "^\[TimeMachine"' "nobody eligible: no share stanza"
  check '! conf | grep -qE "^ +valid users"' "no valid users line at all"
  check '[ -z "$(passdb)" ]' "nobody: empty passdb"
  check '! grep -q "^adduser" "$LOG"' "nobody: no account added"
  # A person refused by name gets no stanza; the others do.
  people 'person|alice|uid|20000' 'person|Bad.Name|uid|20001' 'person|-rf|uid|20002' 'person|root|uid|20003' \
    'person|../etc|uid|20004'
  nt alice "$H_ALICE"
  run
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check 'conf | grep -qxF "[TimeMachine-alice]"' "alice served"
  check '[ "$(conf | grep -c "^\[")" = 2 ]' "only [global] and alice's share"
  check '! conf | grep -qE "^\[.*(Bad|root|rf|etc)"' "no refused name in a stanza"
  check 'conf | grep -A3 "^\[TimeMachine-alice\]" | grep -qxF "   valid users = alice"' "valid users = alice"
  local r; r=$(report)
  check 'has "$r" "\"code\":\"name_refused\",\"severity\":\"info\",\"subject\":\"Bad.Name\""' "Bad.Name reported name_refused: $r"
  check 'has "$r" "\"subject\":\"root\""' "root (reserved) reported"
  check 'grep -q "portcullis-read $R/portcullis/secrets alice$" "$LOG"' "the hash reader gets the valid names only: $(grep portcullis-read "$LOG")"
  check '! grep -vE "^(testparm|s6-applyuidgid -u 10001 -g 10001 -G 10001 cat) " "$LOG" | grep -qE "(^| |/)(Bad\.Name|-rf|\.\./etc|opt/root)( |$|/)"' "a refused name is never used (as a path or an account)"
}

test_empty_local_networks_refused() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  PORTCULLIS_LOCAL_NETWORKS='' run --boot
  check '[ "$RC" = 3 ]' "empty: exit 3 (rc $RC)"
  check 'has "$ERR" "Local networks is empty; file sharing is off"' "message: $ERR"
  check '[ ! -e "$R/etc/samba/smb.conf" ]' "no smb.conf written"
  check '[ -z "$(passdb)" ]' "no passdb written"
  PORTCULLIS_LOCAL_NETWORKS=' , ' run --boot
  check '[ "$RC" = 3 ]' "only separators: exit 3 (rc $RC)"
  PORTCULLIS_LOCAL_NETWORKS='0.0.0.0/0' run --boot
  check '[ "$RC" = 3 ] && [ ! -e "$R/etc/samba/smb.conf" ]' "allow-all /0 refused (rc $RC)"
  PORTCULLIS_LOCAL_NETWORKS='192.168.0.0/16 ,10.0.0.0/8' run --boot
  check '[ "$RC" = 3 ]' "a space inside the list refused (rc $RC)"
  PORTCULLIS_LOCAL_NETWORKS='192.168.0.0/16,ALL' run --boot
  check '[ "$RC" = 3 ]' "a keyword refused (rc $RC)"
}

test_former_account_not_served() {
  people 'person|alice|uid|20000' 'person|bob|uid|20001'
  nt alice "$H_ALICE"; nt bob "$H_BOB"
  mkdir "$R/opt/alice" "$R/opt/bob" "$R/opt/carol"
  own "$R/opt/alice" 20023 20023 700
  own "$R/opt/bob" 20001 20001 700
  own "$R/opt/carol" 20009 20009 700
  run
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check '! conf | grep -q "TimeMachine-alice"' "no [TimeMachine-alice]"
  check 'conf | grep -qxF "[TimeMachine-bob]"' "bob served"
  local r; r=$(report)
  check 'has "$r" "{\"code\":\"former_account\",\"severity\":\"warning\",\"subject\":\"alice\",\"message\":\"alice'"'"'s Time Machine folder belongs to a former account (uid 20023)\",\"option\":\"storage\",\"uid\":20023}"' "former_account finding: $r"
  check 'has "$r" "{\"option\":\"storage\",\"name\":\"alice\",\"uid\":20023,\"former\":true,"' "alice's folder listed former"
  check 'has "$r" "{\"option\":\"storage\",\"name\":\"bob\",\"uid\":20001,\"former\":false,"' "bob's folder listed current"
  check 'has "$r" "{\"option\":\"storage\",\"name\":\"carol\",\"uid\":20009,\"former\":true,"' "a former member's folder listed former"
  check '! grep -q "^chown.*opt/alice" "$LOG"' "alice's folder never chowned"
}

test_folder_checks() {
  people 'person|alice|uid|20000' 'person|bob|uid|20001' 'person|dan|uid|20003' 'person|eve|uid|20004'
  nt alice "$H_ALICE"; nt bob "$H_BOB"; nt dan "$H_CAROL"; nt eve "$H_CAROL"
  mkdir "$R/opt/bob" "$R/opt/dan" "$R/opt/eve"
  own "$R/opt/bob" 20001 100 755
  own "$R/opt/dan" 20003 20003 500
  own "$R/opt/eve" 20004 100 755 7      # its own filesystem
  run
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check '[ -d "$R/opt/alice" ] && grep -qx "chown 20000:20000 $R/opt/alice" "$LOG"' "missing folder created and chowned uid:uid"
  check 'conf | grep -qxF "[TimeMachine-bob]"' "wrong owner still served"
  local r; r=$(report)
  check 'has "$r" "\"code\":\"wrong_owner\",\"severity\":\"warning\",\"subject\":\"bob\""' "bob wrong_owner: $r"
  check 'has "$r" "\"code\":\"owner_unwritable\",\"severity\":\"problem\",\"subject\":\"dan\""' "dan owner_unwritable"
  check 'has "$r" "\"subject\":\"eve\",\"message\":\"eve'"'"'s Time Machine folder is its own filesystem"' "eve's own filesystem named"
  check '! grep -q "^chown.*opt/\(bob\|dan\|eve\)" "$LOG"' "existing folders never chowned"
  # A chown that fails leaves no root-owned folder behind.
  people 'person|fay|uid|20005'
  nt fay "$H_CAROL"
  stub chown 'exit 1'
  run
  check '[ ! -e "$R/opt/fay" ] && has "$(report)" "\"code\":\"owner_unwritable\",\"severity\":\"problem\",\"subject\":\"fay\""' "failed chown: folder removed, owner_unwritable"
  stub chown 'o=${1%%:*}; g=${1#*:}; echo "$2 $o $g 700 1" >> "$STUB_T/owners"'
  people 'person|alice|uid|20000' 'person|bob|uid|20001' 'person|dan|uid|20003' 'person|eve|uid|20004'
  # A symlink in place of a folder is never served.
  rm -rf "$R/opt/alice"; ln -s /etc "$R/opt/alice"
  run
  check '! conf | grep -q "TimeMachine-alice"' "a symlink folder isn't served"
}

test_removed_person_dropped() {
  people 'person|alice|uid|20000' 'person|bob|uid|20001'
  nt alice "$H_ALICE"; nt bob "$H_BOB"
  run --boot
  check '[ "$RC" = 0 ]' "boot (rc $RC: $ERR)"
  check 'grep -q "^alice:x:20000:" "$R/etc/passwd" && grep -q "^bob:x:20001:" "$R/etc/passwd"' "accounts made with the Hub uid"
  check 'grep -q "^adduser -D -H -h /nonexistent -u 20000 -G alice -s /bin/false alice" "$LOG"' "adduser argv"
  check 'grep -q "^addgroup -g 20000 alice" "$LOG"' "addgroup argv"
  check 'passdb | grep -q "^alice:20000:X\{32\}:$H_ALICE:\[U          \]:LCT-"' "alice in passdb"
  session 20000; local pa=$LAST_PID
  session 20001; local pb=$LAST_PID
  session 20001 ignore-term; local pb2=$LAST_PID
  rm "$R/portcullis/secrets/bob.nt"
  : > "$LOG"
  STUB_SMBD_RUNNING=1 run
  check '[ "$RC" = 0 ]' "hook (rc $RC: $ERR)"
  check '! passdb | grep -q "^bob:"' "bob gone from passdb"
  check 'passdb | grep -q "^alice:"' "alice still in passdb"
  check 'grep -qx "deluser bob" "$LOG"' "deluser bob"
  check '! grep -q "^bob:" "$R/etc/passwd"' "bob's Unix account gone"
  check '! conf | grep -q TimeMachine-bob' "bob's share gone"
  check 'grep -qx "smbcontrol all reload-config" "$LOG"' "live reload"
  check '! alive "$pb" && ! alive "$pb2"' "bob's sessions ended (TERM, then KILL)"
  check 'alive "$pa"' "alice's session kept"
  check 'grep -q "^smbstatus -p -n" "$LOG"' "sessions from smbstatus -p -n"
  # Accounts are removed before sessions end (a revocation must be quick).
  check '[ "$(grep -n "^deluser bob" "$LOG" | cut -d: -f1)" -lt "$(grep -n "^smbstatus" "$LOG" | head -n 1 | cut -d: -f1)" ]' "deluser before smbstatus"
  # Managed leftovers (uid in the managed range, not in the Hub's file) go too.
  echo 'mallory:x:30000:30000::/:/bin/false' >> "$R/etc/passwd"
  echo 'mallory:x:30000:' >> "$R/etc/group"
  run
  check '! grep -q "^mallory:" "$R/etc/passwd" "$R/etc/group"' "a stray managed account is removed"
  check 'grep -q "^nobody:" "$R/etc/passwd" && grep -q "^nogroup:" "$R/etc/group"' "image accounts kept"
  # Removal from people.tsv (left the population) drops alice too.
  people
  STUB_SMBD_RUNNING=1 run
  check '[ -z "$(passdb)" ] && ! alive "$pa"' "nobody left: empty passdb, alice's session ended"
}

test_session_end_fails_closed() {
  people 'person|alice|uid|20000' 'person|bob|uid|20001'
  nt alice "$H_ALICE"; nt bob "$H_BOB"
  run --boot
  session 20001
  rm "$R/portcullis/secrets/bob.nt"
  : > "$LOG"
  # smbstatus fails while bob's sessions must end: not applied live.
  STUB_SMBD_RUNNING=1 STUB_SMBSTATUS_FAIL=1 run
  check '[ "$RC" != 0 ]' "smbstatus failing: non-zero exit (rc $RC)"
  check 'has "$ERR" "can'"'"'t list the SMB sessions"' "a fixed message: $ERR"
  check 'grep -q "^s6-svc -d" "$LOG"' "smbd brought down"
  check '! has "$OUT" PORTCULLIS-REPORT' "no report"
  check '! grep -qiE "[0-9a-f]{32}" "$T/out" "$T/err"' "no hash printed"
  # A session that survives TERM and KILL: non-zero, named by username.
  session 20000
  nt alice "$H_ALICE2"
  : > "$LOG"
  STUB_SMBD_RUNNING=1 STUB_SMBSTATUS_STICKY=1 run
  check '[ "$RC" != 0 ]' "a surviving session: non-zero exit (rc $RC)"
  check 'has "$ERR" "a session of alice couldn'"'"'t be ended"' "logged by username: $ERR"
  check '! has "$ERR" 20000' "by username only, no uid: $ERR"
  check 'grep -q "^s6-svc -d" "$LOG"' "smbd brought down"
  check '! grep -qiE "[0-9a-f]{32}" "$T/out" "$T/err"' "no hash printed"
}

test_failure_after_a_change_stops_smbd() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  run --boot
  people 'person|alice|uid|20000' 'person|bob|uid|20001'
  nt bob "$H_BOB"
  : > "$LOG"
  # A plain command failing (set -e) after the passdb changed.
  STUB_SMBD_RUNNING=1 STUB_CP_FAIL=1 run
  check '[ "$RC" != 0 ]' "cp failing mid-run: non-zero exit (rc $RC)"
  check 'grep -q "^s6-svc -d" "$LOG"' "smbd brought down by the exit trap"
  check '! has "$OUT" PORTCULLIS-REPORT' "no report"
  # The same failure at boot: nothing to bring down, still non-zero.
  : > "$LOG"
  STUB_CP_FAIL=1 run --boot
  check '[ "$RC" != 0 ] && ! grep -q "^s6-svc" "$LOG"' "boot: non-zero, no s6-svc (rc $RC)"
}

test_stale_tmpfs_files_removed() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  mkdir -p "$R/run/portcullis/work.OLD1"
  echo "$H_ALICE" > "$R/run/portcullis/work.OLD1/hashes"
  echo "alice:20000:X:$H_ALICE:" > "$R/var/lib/samba/private/.smbpasswd.OLD2"
  echo junk > "$R/etc/samba/.smb.conf.OLD3"
  run --boot
  check '[ "$RC" = 0 ]' "boot (rc $RC: $ERR)"
  check '[ ! -e "$R/run/portcullis/work.OLD1" ]' "a killed run's work dir removed"
  check '[ ! -e "$R/var/lib/samba/private/.smbpasswd.OLD2" ]' "a killed run's passdb temp removed"
  check '[ ! -e "$R/etc/samba/.smb.conf.OLD3" ]' "a killed run's smb.conf temp removed"
  check '[ -z "$(find "$R/run/portcullis" -maxdepth 1 -name "work.*")" ]' "no work dir left after the run"
}

test_live_work_dir_kept() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  run --boot
  # The first run is in its report phase (lock released, its work dir in
  # use); a dead run's dir is a leftover.
  sleep 300 & local live=$!
  disown "$live" 2>/dev/null || true
  SLEEPERS+=("$live")
  mkdir -p "$R/run/portcullis/work.$live.aaaaaa" "$R/run/portcullis/work.999999.bbbbbb"
  echo x > "$R/run/portcullis/work.$live.aaaaaa/sizes"
  run
  check '[ "$RC" = 0 ]' "second run (rc $RC: $ERR)"
  check '[ -f "$R/run/portcullis/work.$live.aaaaaa/sizes" ]' "the live run's work dir is left alone"
  check '[ ! -e "$R/run/portcullis/work.999999.bbbbbb" ]' "a dead run's work dir is removed"
  # --check never cleans up.
  mkdir -p "$R/run/portcullis/work.999998.cccccc"
  run --check
  check '[ "$RC" = 0 ] && [ -d "$R/run/portcullis/work.999998.cccccc" ]' "--check removes nothing (rc $RC)"
}

test_report_failure_keeps_smbd() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  mkdir -p "$R/opt/alice"; own "$R/opt/alice" 20000 20000 700
  run --boot
  rm -f "$R/run/portcullis/state/sizes"; mkdir -p "$R/run/portcullis/state/sizes"   # the sizes cache can't be written
  : > "$LOG"
  STUB_SMBD_RUNNING=1 run
  check '[ "$RC" = 0 ]' "the converge applied: exit 0 (rc $RC: $ERR)"
  check '! grep -q "^s6-svc -d" "$LOG"' "smbd left up"
  check 'has "$ERR" "the report failed"' "logged: $ERR"
  check '! has "$OUT" PORTCULLIS-REPORT' "no report line"
}

test_share_group_names_refused() {
  people 'person|pfg60001|uid|20000' 'person|pfg1|uid|20001' 'person|pfgx|uid|20002'
  nt pfg60001 "$H_ALICE"; nt pfg1 "$H_BOB"; nt pfgx "$H_CAROL"
  run
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check '[ "$(passdb | cut -d: -f1)" = pfgx ]' "pfg<digits> names refused, pfgx kept: $(passdb | cut -d: -f1 | tr '\n' ' ')"
  check 'has "$(report)" "\"code\":\"name_refused\",\"severity\":\"info\",\"subject\":\"pfg60001\""' "reported name_refused"
}

test_account_match_is_exact() {
  # A managed account whose name is a regex-alike of a person's must not
  # count as that person's account.
  people 'person|a.b|uid|20000'
  nt a.b "$H_ALICE"
  echo 'axb:x:20000:20000::/nonexistent:/bin/false' >> "$R/etc/passwd"
  echo 'axb:x:20000:' >> "$R/etc/group"
  run --boot
  check '[ "$RC" = 0 ]' "boot (rc $RC: $ERR)"
  check '! grep -q "^axb:" "$R/etc/passwd" "$R/etc/group"' "the look-alike account and group removed"
  check 'grep -q "^a.b:x:20000:20000:" "$R/etc/passwd" && grep -qx "addgroup -g 20000 a.b" "$LOG"' "a.b created for real"
}

test_size_budget() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  mkdir -p "$R/opt/alice"; own "$R/opt/alice" 20000 20000 700
  run
  check 'grep -qE "^timeout (20|1[0-9]|[1-9]) s6-applyuidgid -u 20000 .* du -sk" "$LOG"' "du under timeout <= 20: $(grep du "$LOG" | head -1)"
  check 'grep -q "^SIZE_BUDGET=30 " "$SCRIPT"' "budget 30 s"
}

test_uid_rules() {
  people 'person|alice|uid|0' 'person|bob|uid|20001' 'person|carol|uid|20001' 'person|dan|uid|65534' 'person|eve|uid|2x0' 'person|fay|uid|20005'
  nt alice "$H_ALICE"; nt bob "$H_BOB"; nt carol "$H_CAROL"; nt dan "$H_CAROL"; nt eve "$H_CAROL"; nt fay "$H_CAROL"
  run --boot
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check '[ "$(passdb | cut -d: -f1)" = fay ]' "only fay (uid 0, a shared uid, 65534 and garbage refused): $(passdb | cut -d: -f1 | tr '\n' ' ')"
  # A bad hash file is not an account.
  printf 'nothex\n' > "$R/portcullis/secrets/fay.nt"
  run
  check '[ -z "$(passdb)" ]' "a malformed .nt is refused"
}

test_hash_never_on_argv() {
  people 'person|alice|uid|20000' 'person|bob|uid|20001'
  nt alice "$H_ALICE"; nt bob "$H_BOB"
  run --boot
  STUB_SMBD_RUNNING=1 run
  nt alice "$H_ALICE2"
  STUB_SMBD_RUNNING=1 run
  check '[ "$RC" = 0 ]' "runs ok (rc $RC: $ERR)"
  check '! grep -qiE "[0-9a-f]{32}" "$LOG"' "no stub argv holds a 32-hex string"
  check 'grep -q "^s6-applyuidgid -u 10001 -g 10001 -G 10001 cat -- $R/portcullis/data/people.tsv" "$LOG"' "people file read as 10001"
  check 'grep -q "^s6-applyuidgid -u 10001 -g 10001 -G 10001 /bin/sh -c" "$LOG"' "hash files read as 10001"
  check '! grep -qiE "[0-9a-f]{32}" "$T/out" "$T/err"' "no output holds one"
  check '! grep -rqiE "$H_ALICE|$H_ALICE2|$H_BOB" "$R/run/portcullis"' "no hash left under /run/portcullis"
  check '[ "$(find "$R/run/portcullis" -type f -perm -004 | wc -l | tr -d " ")" = 0 ]' "nothing world-readable under /run/portcullis"
}

test_regenerated_hash_ends_sessions() {
  people 'person|alice|uid|20000' 'person|bob|uid|20001'
  nt alice "$H_ALICE"; nt bob "$H_BOB"
  run --boot
  session 20000; local pa=$LAST_PID
  session 20001; local pb=$LAST_PID
  nt alice "$H_ALICE2"
  : > "$LOG"
  STUB_SMBD_RUNNING=1 run
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check 'passdb | grep -q "^alice:20000:X\{32\}:$H_ALICE2:"' "new hash imported"
  check '! passdb | grep -q "$H_ALICE"' "old hash gone"
  check '! alive "$pa"' "alice's session ended"
  check 'alive "$pb"' "bob's session kept"
  check '[ "$(grep -n "^smbstatus" "$LOG" | head -1 | cut -d: -f1)" -gt 0 ]' "smbstatus queried"
  # An unchanged hash ends nothing.
  session 20000; local pa2=$LAST_PID
  STUB_SMBD_RUNNING=1 run
  check 'alive "$pa2"' "unchanged hash: session kept"
}

test_share_removal_ends_sessions() {
  people 'person|alice|uid|20000' 'value|share_prefix|TimeMachine'
  nt alice "$H_ALICE"
  run --boot
  session 20000; local pa=$LAST_PID
  people 'person|alice|uid|20000' 'value|share_prefix|Backups'
  STUB_SMBD_RUNNING=1 run
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check 'conf | grep -qxF "[Backups-alice]" && ! conf | grep -q TimeMachine-alice' "share renamed"
  check '! alive "$pa"' "her old share is gone: session ended"
  session 20000; local pa2=$LAST_PID
  mkdir -p "$R/opt/alice"; own "$R/opt/alice" 20077 20077 700
  STUB_SMBD_RUNNING=1 run
  check '! conf | grep -q Backups-alice && ! alive "$pa2"' "folder now a former account's: share gone, session ended"
}

test_avahi_file() {
  people 'person|alice|uid|20000' 'person|bob|uid|20001' 'value|advertise|true'
  nt alice "$H_ALICE"; nt bob "$H_BOB"
  mkdir -p "$R/portcullis/avahi"
  local f="$R/portcullis/avahi/portcullis-tm1.service"
  run
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check '[ -f "$f" ]' "service file written"
  check 'grep -q "<type>_smb._tcp</type>" "$f" && grep -q "<port>445</port>" "$f"' "_smb._tcp on 445"
  check 'grep -q "<type>_adisk._tcp</type>" "$f"' "_adisk._tcp"
  check 'grep -q "<txt-record>dk0=adVN=TimeMachine-alice,adVF=0x82</txt-record>" "$f" && grep -q "<txt-record>dk1=adVN=TimeMachine-bob,adVF=0x82</txt-record>" "$f"' "one dk entry per share"
  check 'grep -q "<txt-record>sys=adVF=0x100</txt-record>" "$f"' "sys=adVF=0x100"
  check 'grep -q "<txt-record>model=TimeCapsule8,119</txt-record>" "$f"' "_device-info model"
  check '! grep -q "host-name" "$f"' "no <host-name>"
  check '[ -z "$(find "$R/portcullis/avahi" -name ".*")" ]' "no temp file left"
  PORTCULLIS_SMB_PORT=1445 run
  check 'grep -q "<port>1445</port>" "$f"' "published port followed"
  # advertise off: removed.
  people 'person|alice|uid|20000' 'person|bob|uid|20001' 'value|advertise|false'
  run
  check '[ ! -e "$f" ]' "advertise false: file removed"
  # The finish script's --stop removes it too.
  people 'person|alice|uid|20000' 'value|advertise|true'
  run
  check '[ -f "$f" ]' "back on"
  run --stop
  check '[ "$RC" = 0 ] && [ ! -e "$f" ]' "--stop removes it (rc $RC)"
  # Not mounted: nothing written anywhere.
  rm -rf "$R/portcullis/avahi"
  run
  check '[ "$RC" = 0 ] && [ ! -e "$R/portcullis/avahi" ]' "unmounted: no directory created"
}

test_reserved_share_name_refused() {
  export PORTCULLIS_FLAVOUR=samba
  mkdir -p "$R/homes" "$R/shares/1" "$R/shares/2" "$R/shares/3" "$R/shares/4" "$R/shares/5"
  export PORTCULLIS_FOLDER_GID_SHARE1_FOLDER=60001 PORTCULLIS_FOLDER_GID_SHARE2_FOLDER=60002 \
    PORTCULLIS_FOLDER_GID_SHARE3_FOLDER=60003 PORTCULLIS_FOLDER_GID_SHARE4_FOLDER=60004 PORTCULLIS_FOLDER_GID_SHARE5_FOLDER=60005
  people 'person|alice|uid|20000' 'person|bob|uid|20001' \
    'value|share1_name|Family' 'value|share1_readers|alice' 'value|share1_writers|bob' \
    'value|share2_name|HOMES' 'value|share2_readers|alice' \
    'value|share3_name|family' 'value|share3_readers|alice' \
    'value|share4_name|Global' 'value|share4_writers|bob' \
    'value|share5_name|Home' 'value|share5_writers|bob'
  nt alice "$H_ALICE"; nt bob "$H_BOB"
  run
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check 'conf | grep -qxF "[Family]"' "Family served"
  check '! conf | grep -qixE "\[(homes|global|family)\]" || [ "$(conf | grep -ciE "^\[(family)\]")" = 1 ]' "no reserved stanza, family once"
  check '[ "$(conf | grep -ciE "^\[home\]")" = 1 ]' "only our own [Home]"
  local r; r=$(report)
  check 'has "$r" "\"code\":\"name_refused\",\"severity\":\"info\",\"subject\":\"HOMES\""' "HOMES refused: $r"
  check 'has "$r" "\"subject\":\"Global\""' "Global refused"
  check 'has "$r" "\"subject\":\"Home\""' "Home refused"
  check 'has "$r" "\"subject\":\"family\""' "duplicate family refused"
  check 'conf | sed -n "/^\[Family\]/,/^\[/p" | grep -qxF "   valid users = alice bob"' "valid users = readers ∪ writers"
  check 'conf | sed -n "/^\[Family\]/,/^\[/p" | grep -qxF "   write list = bob"' "write list = writers"
  check 'conf | sed -n "/^\[Family\]/,/^\[/p" | grep -qxF "   force group = pfg60001"' "force group = the folder gid"
  check 'grep -q "^addgroup -g 60001 pfg60001" "$LOG"' "folder group made"
  check 'conf | sed -n "/^\[Home\]/,/^\[/p" | grep -qxF "   path = /homes/%u"' "[Home] path %u"
  check 'conf | sed -n "/^\[Home\]/,/^\[/p" | grep -qxF "   valid users = alice bob"' "[Home] explicit valid users"
  # A slot without a served user, a folder or a gid isn't rendered.
  people 'person|alice|uid|20000' 'value|share1_name|Family' 'value|share1_readers|zed' \
    'value|share6_name|Six' 'value|share6_readers|alice'
  run
  check '! conf | grep -q "^\[Family\]" && ! conf | grep -q "^\[Six\]"' "no stanza without users / folder"
}

test_check_mode() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  run --boot
  run --check
  check '[ "$RC" = 0 ]' "--check passes on the installed config (rc $RC: $ERR)"
  STUB_TESTPARM_DROP='hosts deny' run --check
  check '[ "$RC" = 4 ]' "--check refuses a weakened config (rc $RC)"
}

test_bad_env_refused() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  PORTCULLIS_FLAVOUR=other run --boot
  check '[ "$RC" = 2 ]' "unknown flavour (rc $RC)"
  PORTCULLIS_INSTANCE='../x' run --boot
  check '[ "$RC" = 2 ]' "bad instance id (rc $RC)"
  PORTCULLIS_USERNAME_PATTERN='' run --boot
  check '[ "$RC" = 2 ]' "no username pattern (rc $RC)"
  MIMIC_MODEL=$'Mac\n[evil]' run --boot
  check '[ "$RC" = 2 ]' "a model with a newline (rc $RC)"
  PORTCULLIS_SMB_PORT=0 run --boot
  check '[ "$RC" = 2 ]' "port 0 (rc $RC)"
  check '[ ! -e "$R/etc/samba/smb.conf" ]' "nothing written"
  # A people file for another instance serves nobody.
  PORTCULLIS_INSTANCE=tm2 run --boot
  check '[ "$RC" = 0 ] && [ -z "$(passdb)" ]' "another instance's file: nobody (rc $RC)"
}

test_size_limit() {
  people 'person|alice|uid|20000' 'person|alice|size_limit|512000' 'person|bob|uid|20001' 'person|bob|size_limit|unlimited'
  nt alice "$H_ALICE"; nt bob "$H_BOB"
  run
  check '[ "$RC" = 0 ]' "exit 0 (rc $RC: $ERR)"
  check 'conf | sed -n "/^\[TimeMachine-alice\]/,/^\[/p" | grep -qxF "   fruit:time machine max size = 512000M"' "alice's limit in MiB"
  check '! conf | sed -n "/^\[TimeMachine-bob\]/,/^\[/p" | grep -q "max size"' "unlimited: no max size"
  check 'conf | sed -n "/^\[TimeMachine-bob\]/,/^\[/p" | grep -qxF "   fruit:time machine = yes"' "time machine share"
}

test_folder_sizes() {
  people 'person|alice|uid|20000'
  nt alice "$H_ALICE"
  mkdir -p "$R/opt/alice"; own "$R/opt/alice" 20000 20000 700
  head -c 5000 /dev/zero > "$R/opt/alice/f"
  run
  local r; r=$(report)
  check 'printf "%s" "$r" | grep -qE "\"name\":\"alice\",\"uid\":20000,\"former\":false,\"bytes\":[1-9][0-9]*"' "bytes from du: $r"
  check 'grep -q "^timeout 20 s6-applyuidgid -u 20000 -g 20000 -G 20000 du -sk" "$LOG"' "du as the owner under timeout 20"
  # The Hub reads the report as JSON.
  check 'printf "%s" "$r" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"version\"] == 1"' "report is JSON"
}

# ── runner ───────────────────────────────────────────────────
ALL=$(declare -F | awk '{print $3}' | grep '^test_')
SEL=${*:-$ALL}
for CUR in $SEL; do
  echo "--- $CUR"
  setup
  "$CUR" || no "test function returned non-zero"
  teardown
done
echo
echo "$PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then printf '  %s\n' "${FAILED[@]}"; exit 1; fi
