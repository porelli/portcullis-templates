#!/usr/bin/env bash
# Test: Time Machine (router-less file sharing over hardened SMB3, contract
# §13.17). No Hub in templates CI: the test writes what the Hub would — the
# tsv people file, the per-person .nt hash files (uid 10001, 0600) and the
# env — boots the template and talks SMB to it with the runner's smbclient,
# run inside client containers' network namespaces (nsenter) so Samba sees
# their addresses: one inside the test Local networks, one outside.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
# shellcheck disable=SC2034 # read by tests/lib.sh
TEST_NAME="timemachine"
section "Time Machine"

APP_ID=timemachine
C=portcullis-timemachine-1
COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
DIR=$(dirname "$COMPOSE")
MANIFEST="$DIR/manifest.yaml"
IMAGE=$(yq -r '.services.timemachine.image' "$COMPOSE")

# ── static ───────────────────────────────────────────────────
if [[ "$IMAGE" =~ ^mbentley/timemachine:smb-[0-9]{8}@sha256:[0-9a-f]{64}$ ]]; then
  pass "image pinned: $IMAGE"
else
  fail "image must be mbentley/timemachine:smb-YYYYMMDD@sha256:<index digest>: $IMAGE"
fi
if [ "$(yq -r '.services.timemachine.entrypoint | join(" ")' "$COMPOSE")" = /portcullis/bin/start ] \
    && [ "$(yq -r '.services.timemachine.command | length' "$COMPOSE")" = 0 ]; then
  pass "entrypoint /portcullis/bin/start, no command: mbentley's /entrypoint.sh never runs"
else
  fail "entrypoint / command"
fi
CAPS=$(yq -r '.services.timemachine.cap_add | sort | join(",")' "$COMPOSE")
if [ "$(yq -r '.services.timemachine.cap_drop | join(",")' "$COMPOSE")" = ALL ] \
    && [ "$CAPS" = CHOWN,NET_BIND_SERVICE,SETGID,SETUID ]; then
  pass "cap_drop ALL, cap_add $CAPS"
else
  fail "capabilities: drop $(yq -r '.services.timemachine.cap_drop' "$COMPOSE"), add $CAPS"
fi
if [ "$(yq -r '.services.timemachine.security_opt | join(",")' "$COMPOSE")" = no-new-privileges:true ] \
    && [ "$(yq -r '.services.timemachine.networks | join(",")' "$COMPOSE")" = default ]; then
  pass "no-new-privileges, default network only"
else
  fail "security_opt / networks"
fi
TMPFS=$(yq -r '.services.timemachine.tmpfs | map(sub(":.*"; "")) | sort | join(" ")' "$COMPOSE")
if [ "$TMPFS" = "/run/portcullis /run/samba /var/cache/samba /var/lib/samba /var/log/samba" ]; then
  pass "passdb and Samba state on tmpfs"
else
  fail "tmpfs: $TMPFS"
fi
for k in EXTERNAL_CONF CUSTOM_SMB_CONF PASSWORD TM_USERNAME PORTCULLIS_SYNC_ROOT; do
  if yq -e ".services.timemachine.environment.$k" "$COMPOSE" > /dev/null 2>&1; then
    fail "compose sets $k"
  else
    pass "compose doesn't set $k"
  fi
done
if [ "$(yq -r '.hooks[] | select(.name == "sync") | [.service, (.command | join(" ")), (.when | join(",")), .timeout] | join("|")' "$MANIFEST")" \
    = 'timemachine|/portcullis/bin/portcullis-sync|start,settings_change,membership_change,credential_change|60s' ]; then
  pass "sync hook: portcullis-sync on start, settings, membership and credential changes"
else
  fail "hooks: sync"
fi

# The image's own accounts and groups are reserved usernames.
docker pull -q "$IMAGE" > /dev/null
RESERVED=" $(yq -r '.settings.options[] | select(.key == "share_password") | .username.reserved | join(" ")' "$MANIFEST") "
MISSING=
for n in $(docker run --rm --network none --entrypoint cat "$IMAGE" /etc/passwd /etc/group | cut -d: -f1 | sort -u); do
  case $RESERVED in *" $n "*) ;; *) MISSING="$MISSING $n" ;; esac
done
if [ -z "$MISSING" ]; then
  pass "username.reserved covers every account and group in the image"
else
  fail "username.reserved misses:$MISSING"
fi

# ── fixtures ─────────────────────────────────────────────────
command -v smbclient > /dev/null || { sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq smbclient > /dev/null; }
info "$(smbclient --version)"

WORK=$(mktemp -d)
PEOPLE_DIR="$WORK/appfiles/timemachine/people"
SECRETS_DIR="$WORK/secrets/timemachine/share_password"
AVAHI_DIR="$WORK/avahi"
OVERRIDE="$WORK/override.yml"
NET=192.168.231
TM_IP=$NET.10
IN_IP=$NET.50
OUT_IP=$NET.70
export PORTCULLIS_LOCAL_NETWORKS="$NET.48/28,fd00:1::/64"

cleanup() {
  docker rm -f tm-cli-in tm-cli-out > /dev/null 2>&1 || true
  COMPOSE_OVERRIDE="$OVERRIDE" compose_down "$APP_ID" > /dev/null 2>&1 || true
  docker volume rm portcullis_timemachine-data > /dev/null 2>&1 || true
  sudo rm -rf "$WORK"
  report
}
trap cleanup EXIT

sudo mkdir -p "$PEOPLE_DIR" "$SECRETS_DIR" "$AVAHI_DIR"
sudo chown 10001:10001 "$WORK/appfiles" "$WORK/appfiles/timemachine" "$PEOPLE_DIR" "$WORK/secrets" "$WORK/secrets/timemachine" "$SECRETS_DIR"
sudo chmod 0750 "$WORK/appfiles" "$WORK/appfiles/timemachine" "$PEOPLE_DIR"
sudo chmod 0700 "$WORK/secrets" "$WORK/secrets/timemachine" "$SECRETS_DIR"
sudo chown 0:0 "$AVAHI_DIR"
sudo chmod 0755 "$AVAHI_DIR"

# people <tsv line>...: the Hub's people file (version + instance first,
# the rest sorted), 0640 uid 10001, atomically.
people() {
  local tmp="$WORK/people.tmp"
  { printf 'version\t1\ninstance\ttimemachine\n'; printf '%s\n' "$@" | sed 's/|/\t/g' | LC_ALL=C sort; } > "$tmp"
  sudo install -o 10001 -g 10001 -m 0640 "$tmp" "$PEOPLE_DIR/.people.tsv.tmp"
  sudo mv -f "$PEOPLE_DIR/.people.tsv.tmp" "$PEOPLE_DIR/people.tsv"
  rm -f "$tmp"
}
# nthash <password>: uppercase hex MD4(UTF-16LE(password)), like the Hub.
nthash() {
  python3 - "$1" << 'PY'
import struct, sys
def md4(m):
    def f(x, y, z): return (x & y) | (~x & z)
    def g(x, y, z): return (x & y) | (x & z) | (y & z)
    def h(x, y, z): return x ^ y ^ z
    def rol(v, s): v &= 0xffffffff; return ((v << s) | (v >> (32 - s))) & 0xffffffff
    l = len(m) * 8
    m += b"\x80" + b"\x00" * ((55 - len(m)) % 64) + struct.pack("<Q", l)
    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for i in range(0, len(m), 64):
        x = struct.unpack("<16I", m[i:i + 64]); aa, bb, cc, dd = a, b, c, d
        for k in range(16):
            s = (3, 7, 11, 19)[k % 4]
            if k % 4 == 0: a = rol(a + f(b, c, d) + x[k], s)
            elif k % 4 == 1: d = rol(d + f(a, b, c) + x[k], s)
            elif k % 4 == 2: c = rol(c + f(d, a, b) + x[k], s)
            else: b = rol(b + f(c, d, a) + x[k], s)
        for k in range(16):
            j = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)[k]; s = (3, 5, 9, 13)[k % 4]
            t = 0x5a827999
            if k % 4 == 0: a = rol(a + g(b, c, d) + x[j] + t, s)
            elif k % 4 == 1: d = rol(d + g(a, b, c) + x[j] + t, s)
            elif k % 4 == 2: c = rol(c + g(d, a, b) + x[j] + t, s)
            else: b = rol(b + g(c, d, a) + x[j] + t, s)
        for k in range(16):
            j = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[k]; s = (3, 9, 11, 15)[k % 4]
            t = 0x6ed9eba1
            if k % 4 == 0: a = rol(a + h(b, c, d) + x[j] + t, s)
            elif k % 4 == 1: d = rol(d + h(a, b, c) + x[j] + t, s)
            elif k % 4 == 2: c = rol(c + h(d, a, b) + x[j] + t, s)
            else: b = rol(b + h(c, d, a) + x[j] + t, s)
        a, b, c, d = (a + aa) & 0xffffffff, (b + bb) & 0xffffffff, (c + cc) & 0xffffffff, (d + dd) & 0xffffffff
    return struct.pack("<4I", a, b, c, d)
assert md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
print(md4(sys.argv[1].encode("utf-16-le")).hex().upper())
PY
}
nt() {  # nt <user> <password>: the person's hash file, 0600 uid 10001
  local tmp="$WORK/nt.tmp"
  printf '%s\n' "$(nthash "$2")" > "$tmp"
  sudo install -o 10001 -g 10001 -m 0600 "$tmp" "$SECRETS_DIR/.$1.nt.tmp"
  sudo mv -f "$SECRETS_DIR/.$1.nt.tmp" "$SECRETS_DIR/$1.nt"
  rm -f "$tmp"
}
PW_ALICE=Abcd-EFGH-jkmn-PQRS-tuvw-XY23
PW_ALICE2=Zz23-4567-89AB-CDEF-GHJK-LMNP
PW_BOB=Qwer-Tyup-asdf-ghjk-zxcv-bnm2
PW_CAROL=Cccc-Dddd-Eeee-Ffff-Gggg-Hhh4

write_override() {  # write_override [extra volume lines] [extra service keys]
  cat > "$OVERRIDE" << EOF
services:
  timemachine:
    volumes:
      - {type: bind, source: $PEOPLE_DIR, target: /portcullis/data, read_only: true}
      - {type: bind, source: $SECRETS_DIR, target: /portcullis/secrets, read_only: true}
      - {type: bind, source: $AVAHI_DIR, target: /portcullis/avahi}
${1:-}
    networks:
      default:
        ipv4_address: $TM_IP
${2:-}
networks:
  default:
    ipam:
      config:
        - subnet: $NET.0/24
EOF
}

# logs_have <text>: the container log holds text (read whole first: grep -q
# would close a pipe from docker logs early and fail it under pipefail).
logs_have() { docker logs "$C" > "$WORK/container.log" 2>&1; grep -qF -- "$1" "$WORK/container.log"; }
listening() { docker exec "$C" sh -c 'grep -qE "^ *[0-9]+: [0-9A-F]+:01BD [0-9A-F]+:0000 0A" /proc/net/tcp /proc/net/tcp6' 2> /dev/null; }
wait_listening() {
  local _
  for _ in $(seq 1 60); do listening && return 0; sleep 1; done
  docker logs --tail 40 "$C" 2>&1 || true
  return 1
}
boot() {  # boot [extra volume lines] [extra service keys]: a fresh container
  docker rm -f tm-cli-in tm-cli-out > /dev/null 2>&1 || true
  COMPOSE_OVERRIDE="$OVERRIDE" compose_down "$APP_ID" > /dev/null 2>&1 || true
  docker volume rm portcullis_timemachine-data > /dev/null 2>&1 || true
  docker network rm portcullis_default > /dev/null 2>&1 || true
  write_override "${1:-}" "${2:-}"
  COMPOSE_OVERRIDE="$OVERRIDE" compose_up "$APP_ID"
}
client() {  # client <name> <ip>: a container whose netns smbclient runs in
  docker rm -f "$1" > /dev/null 2>&1 || true
  docker run -d --name "$1" --network portcullis_default --ip "$2" --entrypoint sleep "$IMAGE" 3600 > /dev/null
}
# smb <client> <share> <user> <password> [smbclient args] -- <command>
smb() {
  local cli=$1 share=$2 user=$3 pw=$4 pid
  shift 4
  pid=$(docker inspect -f '{{.State.Pid}}' "$cli")
  sudo nsenter --net="/proc/$pid/ns/net" env PASSWD="$pw" timeout 30 smbclient "//$TM_IP/$share" -U "$user" \
    --use-kerberos=disabled -m SMB3 --option='client min protocol=SMB2_02' --option='client smb encrypt=required' "$@" 2>&1
}
hook() {  # hook [trigger]: run the sync hook like the Hub (stdin HookInput)
  printf '{"trigger":"%s","version":1,"instance":"timemachine","values":{},"people":{},"groups":{},"entries":{},"secrets":{},"credentials":{}}' \
    "${1:-membership_change}" | docker exec -i "$C" /portcullis/bin/portcullis-sync
}
sessions_of() { docker exec "$C" smbstatus -p -n 2> /dev/null | awk -v u="$1" '$1 ~ /^[0-9]+$/ && $2 == u { print $1 }'; }
# long_session <user> <password> <share>: a client session that stays open
long_session() {
  local pid
  pid=$(docker inspect -f '{{.State.Pid}}' tm-cli-in)
  # shellcheck disable=SC2024 # the log is the runner user's own file
  (while :; do echo 'ls' 2> /dev/null || exit 0; sleep 1; done) | sudo nsenter --net="/proc/$pid/ns/net" env PASSWD="$2" timeout 120 \
    smbclient "//$TM_IP/$3" -U "$1" --use-kerberos=disabled -m SMB3 --option='client smb encrypt=required' > "$WORK/long-$1.log" 2>&1 &
  LONG_PID=$!
}
wait_sessions() {  # wait_sessions <uid> <want: some|none> <seconds>
  local _
  for _ in $(seq 1 "$3"); do
    if [ "$2" = some ] && [ -n "$(sessions_of "$1")" ]; then return 0; fi
    if [ "$2" = none ] && [ -z "$(sessions_of "$1")" ]; then return 0; fi
    sleep 1
  done
  return 1
}

# ── nobody eligible ──────────────────────────────────────────
people 'value|share_prefix|TimeMachine' 'value|advertise|false'
boot
if wait_listening; then pass "smbd listens on 445 with nobody eligible"; else fail "smbd not listening"; exit 1; fi
HEALTH=
for _ in $(seq 1 45); do
  HEALTH=$(docker inspect -f '{{.State.Health.Status}}' "$C" 2> /dev/null || true)
  [ "$HEALTH" = healthy ] && break
  sleep 2
done
if [ "$HEALTH" = healthy ]; then pass "healthcheck: healthy (smb.conf verifies, smbd runs)"; else fail "healthcheck: $HEALTH"; fi
if [ -z "$(docker exec "$C" pdbedit -L 2> /dev/null)" ]; then pass "nobody: pdbedit -L empty"; else fail "nobody: passdb has $(docker exec "$C" pdbedit -L)"; fi
if docker exec "$C" grep -q '^timemachine:' /etc/passwd; then fail "the image's timemachine account exists"; else pass "no timemachine account (nobody eligible)"; fi
if [ -n "$(docker exec "$C" awk -F: '$3 >= 10000 && $3 < 65534' /etc/passwd)" ]; then fail "an account with uid >= 10000 exists"; else pass "no person account"; fi
if docker exec "$C" grep -q '^\[' /etc/samba/smb.conf && [ "$(docker exec "$C" grep -c '^\[' /etc/samba/smb.conf)" = 1 ]; then
  pass "smb.conf has [global] only"
else
  fail "smb.conf sections: $(docker exec "$C" grep '^\[' /etc/samba/smb.conf | tr '\n' ' ')"
fi
PS=$(docker exec "$C" ps)
if grep -qE 'nmbd|avahi|dbus' <<< "$PS"; then fail "nmbd, avahi or dbus runs"; else pass "only smbd runs (no nmbd, avahi, dbus)"; fi
CAPEFF=$(docker exec "$C" awk '/^CapEff/ { print $2 }' /proc/1/status)
CAPDEC=$((16#$CAPEFF))
if [ $((CAPDEC & 6)) = 0 ]; then pass "CapEff $CAPEFF: no DAC_OVERRIDE, no DAC_READ_SEARCH"; else fail "CapEff $CAPEFF has DAC_OVERRIDE / DAC_READ_SEARCH"; fi
if [ "$CAPDEC" = $(((1 << 0) | (1 << 6) | (1 << 7) | (1 << 10))) ]; then
  pass "CapEff is exactly CHOWN SETGID SETUID NET_BIND_SERVICE"
else
  fail "CapEff $CAPEFF"
fi
# Captured whole first: grep -q on a pipe can SIGPIPE testparm (pipefail).
TP=$(docker exec "$C" testparm -s -v 2> /dev/null || true)
if grep -qxF $'\thosts allow = '"$NET.48/28 fd00:1::/64" <<< "$TP"; then
  pass "testparm keeps the IPv6 CIDR as written (hosts allow = $NET.48/28 fd00:1::/64)"
else
  fail "testparm hosts allow: $(grep 'hosts allow' <<< "$TP")"
fi

# ── people ───────────────────────────────────────────────────
people 'value|share_prefix|TimeMachine' 'value|advertise|true' \
  'person|alice|uid|20000' 'person|alice|size_limit|10240' \
  'person|bob|uid|20001' 'person|bob|size_limit|unlimited' \
  'person|carol|uid|20002'
nt alice "$PW_ALICE"; nt bob "$PW_BOB"
OUT=$(hook start) && RC=0 || RC=$?
if [ "$RC" = 0 ] && grep -q '^PORTCULLIS-REPORT {"version":1,' <<< "$OUT"; then pass "hook applied, one report line"; else fail "hook rc $RC: $OUT"; fi
if [ "$(grep -c '^PORTCULLIS-REPORT ' <<< "$OUT")" = 1 ]; then pass "exactly one PORTCULLIS-REPORT line"; else fail "report lines: $OUT"; fi
REPORT=$(sed -n 's/^PORTCULLIS-REPORT //p' <<< "$OUT")
if python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["version"] == 1 and {f["name"] for f in d["folders"]} == {"alice", "bob"}, d' "$REPORT"; then
  pass "report: alice's and bob's folders"
else
  fail "report: $REPORT"
fi
if grep -qiE '[0-9a-f]{32}' <<< "$OUT"; then fail "hook output holds a 32-hex string"; else pass "no hash in the hook output"; fi
if [ "$(docker exec "$C" pdbedit -L 2> /dev/null | cut -d: -f1,2 | sort | tr '\n' ' ')" = "alice:20000 bob:20001 " ]; then
  pass "passdb: alice and bob (carol has no password)"
else
  fail "passdb: $(docker exec "$C" pdbedit -L 2> /dev/null)"
fi
if docker exec "$C" grep -q '^timemachine:' /etc/passwd; then fail "the timemachine account exists"; else pass "no timemachine account (with people)"; fi
if [ "$(docker exec "$C" stat -c '%u:%g %a' /opt/alice)" = "20000:20000 700" ]; then pass "/opt/alice is 20000:20000 0700"; else fail "/opt/alice: $(docker exec "$C" stat -c '%u:%g %a' /opt/alice)"; fi
if docker exec "$C" grep -qxF '   fruit:time machine max size = 10240M' /etc/samba/smb.conf; then pass "alice's limit: 10240M"; else fail "max size missing"; fi
if [ -n "$(docker exec "$C" find /run/portcullis /etc/samba /tmp -type f -exec grep -lE "$(nthash "$PW_ALICE")" {} + 2> /dev/null)" ]; then
  fail "a hash outside the passdb"
else
  pass "no hash left under /run/portcullis, /etc/samba or /tmp"
fi
if [ "$(docker exec "$C" stat -c '%u %a' /var/lib/samba/private/smbpasswd)" = "0 600" ]; then pass "passdb root 0600"; else fail "passdb mode"; fi

client tm-cli-in "$IN_IP"
client tm-cli-out "$OUT_IP"
if O=$(smb tm-cli-in TimeMachine-alice alice "$PW_ALICE" -c ls) && ! grep -q NT_STATUS <<< "$O"; then
  pass "alice lists her share over encrypted SMB3"
else
  fail "alice SMB3: $O"
fi
echo hello > "$WORK/hello.txt"
if O=$(smb tm-cli-in TimeMachine-alice alice "$PW_ALICE" -c "put $WORK/hello.txt hello.txt") \
    && [ "$(docker exec -u 20000:20000 "$C" stat -c '%u' /opt/alice/hello.txt)" = 20000 ]; then
  pass "a file alice writes is owned by her uid"
else
  fail "write: $O"
fi
refused() {  # refused <label> <smb args...>
  local label=$1 o
  shift
  if o=$(smb "$@") && ! grep -q NT_STATUS <<< "$o"; then fail "$label: accepted"; else pass "$label: refused ($(grep -o 'NT_STATUS_[A-Z_]*' <<< "$o" | head -1))"; fi
}
refused "-m SMB2" tm-cli-in TimeMachine-alice alice "$PW_ALICE" -m SMB2 -c ls
refused "-m NT1" tm-cli-in TimeMachine-alice alice "$PW_ALICE" -m NT1 --option='client min protocol=NT1' -c ls
refused "NTLMv1 (client ntlmv2 auth=no)" tm-cli-in TimeMachine-alice alice "$PW_ALICE" --option='client ntlmv2 auth=no' -c ls
refused "a wrong password" tm-cli-in TimeMachine-alice alice "$PW_BOB" -c ls
refused "bob on alice's share" tm-cli-in TimeMachine-alice bob "$PW_BOB" -c ls
refused "guest" tm-cli-in TimeMachine-alice guest "" -N -c ls
refused "a client outside Local networks ($OUT_IP)" tm-cli-out TimeMachine-alice alice "$PW_ALICE" -c ls
if logs_have "Denied connection from $OUT_IP"; then pass "smbd logged the denied address"; else info "no 'Denied connection' line in the log"; fi
if [ -f "$AVAHI_DIR/portcullis-timemachine.service" ] && grep -q 'dk0=adVN=TimeMachine-alice,adVF=0x82' "$AVAHI_DIR/portcullis-timemachine.service"; then
  pass "Bonjour file written with _adisk entries"
else
  fail "Bonjour file: $(cat "$AVAHI_DIR/portcullis-timemachine.service" 2> /dev/null)"
fi

# A client that asks for no encryption: the server's encrypt = required
# still encrypts the session (Samba's client follows the server), so every
# session smbstatus lists is AES-encrypted.
pid=$(docker inspect -f '{{.State.Pid}}' tm-cli-in)
# shellcheck disable=SC2024 # the log is the runner user's own file
(while :; do echo 'ls' 2> /dev/null || exit 0; sleep 1; done) | sudo nsenter --net="/proc/$pid/ns/net" env PASSWD="$PW_ALICE" timeout 120 \
  smbclient //$TM_IP/TimeMachine-alice -U alice --use-kerberos=disabled -m SMB3 --option='client smb encrypt=off' > "$WORK/noenc.log" 2>&1 &
LONG_PID=$!
if wait_sessions 20000 some 15; then
  ENC=$(docker exec "$C" smbstatus -p -n 2> /dev/null | awk '$1 ~ /^[0-9]+$/ && $2 == 20000')
  if [ -n "$ENC" ] && ! grep -qvE 'AES-(128|256)-(GCM|CCM)' <<< "$ENC"; then
    pass "a client asking for no encryption is encrypted anyway: $(awk '{ print $6, $7 }' <<< "$ENC" | sort -u | tr '\n' ' ')"
  else
    fail "an unencrypted session: $ENC"
  fi
else
  pass "a client asking for no encryption is refused ($(grep -o 'NT_STATUS_[A-Z_]*' "$WORK/noenc.log" | head -1))"
fi
kill "$LONG_PID" 2> /dev/null || true
wait_sessions 20000 none 15 || true
SESS=$(docker exec "$C" smbstatus -p -n 2> /dev/null | awk '$1 ~ /^[0-9]+$/')
if [ -n "$SESS" ] && grep -qvE 'AES-(128|256)-(GCM|CCM)' <<< "$SESS"; then
  fail "a session without encryption: $(docker exec "$C" smbstatus -p -n 2> /dev/null)"
else
  pass "no unencrypted session in smbstatus"
fi

# ── regenerated password: the old one and its sessions stop (F29) ──
long_session alice "$PW_ALICE" TimeMachine-alice
if wait_sessions 20000 some 15; then pass "alice has an open session"; else fail "no open session for alice: $(cat "$WORK/long-alice.log")"; fi
nt alice "$PW_ALICE2"
hook credential_change > /dev/null
if wait_sessions 20000 none 10; then pass "regenerated: alice's open session dropped within 10 s"; else fail "regenerated: session still open"; fi
kill "$LONG_PID" 2> /dev/null || true
refused "the old password" tm-cli-in TimeMachine-alice alice "$PW_ALICE" -c ls
if O=$(smb tm-cli-in TimeMachine-alice alice "$PW_ALICE2" -c ls) && ! grep -q NT_STATUS <<< "$O"; then pass "the new password works"; else fail "new password: $O"; fi

# ── fewer shares: sessions end (F28) ─────────────────────────
long_session bob "$PW_BOB" TimeMachine-bob
wait_sessions 20001 some 15 || fail "no open session for bob"
people 'value|share_prefix|Backups' 'value|advertise|true' \
  'person|alice|uid|20000' 'person|alice|size_limit|10240' 'person|bob|uid|20001'
hook settings_change > /dev/null
if wait_sessions 20001 none 10; then pass "share renamed: bob's open session dropped"; else fail "share renamed: bob's session still open"; fi
kill "$LONG_PID" 2> /dev/null || true
refused "the old share name" tm-cli-in TimeMachine-bob bob "$PW_BOB" -c ls
if O=$(smb tm-cli-in Backups-bob bob "$PW_BOB" -c ls) && ! grep -q NT_STATUS <<< "$O"; then pass "bob's renamed share works"; else fail "Backups-bob: $O"; fi

# ── revocation: removed hash -> account and sessions gone within 8 s ──
long_session alice "$PW_ALICE2" Backups-alice
wait_sessions 20000 some 15 || fail "no open session for alice"
sudo rm -f "$SECRETS_DIR/alice.nt"
T0=$(date +%s%N)
hook credential_change > /dev/null
T1=$(date +%s%N)
MS=$(((T1 - T0) / 1000000))
if [ "$MS" -lt 8000 ]; then pass "credential_change run took ${MS} ms (< 8 s)"; else fail "credential_change run took ${MS} ms"; fi
if wait_sessions 20000 none 10; then pass "revoked: alice's open session dropped within 10 s (root signals smbd without CAP_KILL)"; else fail "revoked: alice's session still open"; fi
kill "$LONG_PID" 2> /dev/null || true
refused "alice after revocation" tm-cli-in Backups-alice alice "$PW_ALICE2" -c ls
if docker exec "$C" grep -q '^alice:' /etc/passwd; then fail "alice's Unix account still exists"; else pass "alice's Unix account removed"; fi
PDB=$(docker exec "$C" pdbedit -L 2> /dev/null || true)
if grep -q '^alice:' <<< "$PDB"; then fail "alice still in passdb"; else pass "alice removed from passdb"; fi
if docker exec "$C" test -d /opt/alice; then pass "alice's folder stays on disk"; else fail "alice's folder was removed"; fi

# From here on every check reports (no early exit), whatever fails.
set +e

# ── a former account's folder isn't served ───────────────────
nt carol "$PW_CAROL"
# chmod before chown: root has CHOWN but not FOWNER.
docker exec "$C" sh -c 'mkdir -p -m 0700 /opt/carol && chown 20099:20099 /opt/carol' || fail "can't make carol's former-account folder"
people 'value|share_prefix|Backups' 'value|advertise|true' 'person|bob|uid|20001' 'person|carol|uid|20002'
OUT=$(hook membership_change)
if grep -q '"code":"former_account","severity":"warning","subject":"carol"' <<< "$OUT" \
    && ! docker exec "$C" grep -q '^\[Backups-carol\]' /etc/samba/smb.conf; then
  pass "carol's folder belongs to uid 20099: not served, reported former_account"
else
  fail "former account: $OUT"
fi

# ── hook-time fail closed under s6 ───────────────────────────
# smb.conf replaced by a directory: the run changes the passdb, then the
# installed config doesn't verify (exit 4) and smbd is brought down
# (s6-svc -d, KILL, the down marker). A valid smb.conf put back behind the
# script's back still doesn't start it until a run converges again.
SVC=/run/portcullis-s6/smbd
docker exec "$C" sh -c 'cp /etc/samba/smb.conf /tmp/good.conf && rm -f /etc/samba/smb.conf && mkdir /etc/samba/smb.conf'
OUT=$(hook settings_change 2>&1); RC=$?
if [ "$RC" = 4 ] && grep -q "the installed smb.conf doesn't verify" <<< "$OUT" && grep -q 'bringing smbd down (fail closed)' <<< "$OUT"; then
  pass "hook-time refusal: exit 4, smbd brought down"
else
  fail "hook-time refusal: rc $RC: $OUT"
fi
docker exec "$C" sh -c 'rm -rf /etc/samba/smb.conf && cp /tmp/good.conf /etc/samba/smb.conf'
HEARD=
for _ in $(seq 1 15); do listening && HEARD=1; sleep 1; done
SVST=$(docker exec "$C" s6-svstat "$SVC" 2>&1); SVRC=$?
if [ -z "$HEARD" ] && ! docker exec "$C" pidof smbd > /dev/null && [ "$SVRC" = 0 ] && grep -q '^down' <<< "$SVST"; then
  pass "after a fail-closed stop smbd stays down, s6-svstat: $SVST"
else
  fail "after a fail-closed stop: heard=${HEARD:-no} s6-svstat rc $SVRC: $SVST"
fi
if docker exec "$C" pidof s6-supervise > /dev/null; then pass "s6-supervise stays alive"; else fail "s6-supervise is gone"; fi
CK=$(docker exec "$C" /portcullis/bin/portcullis-sync --check 2>&1); RC=$?
if [ "$RC" = 4 ] && grep -q 'brought down (fail closed)' <<< "$CK"; then pass "--check refuses after a fail-closed stop"; else fail "--check: rc $RC: $CK"; fi
OUT=$(hook settings_change 2>&1); RC=$?
if [ "$RC" = 0 ] && wait_listening; then pass "the next good run brings smbd back ($(docker exec "$C" s6-svstat "$SVC" 2>&1))"; else fail "after the fail-closed stop: rc $RC: $OUT"; fi
if docker exec "$C" /portcullis/bin/portcullis-sync --check > /dev/null 2>&1; then pass "--check passes again"; else fail "--check still refuses"; fi

# ── stop: the Bonjour file goes ──────────────────────────────
docker stop -t 20 "$C" > /dev/null
if [ ! -e "$AVAHI_DIR/portcullis-timemachine.service" ]; then pass "container stop removes the Bonjour file"; else fail "Bonjour file left after stop"; fi

# ── removed while the container was down ─────────────────────
# /etc/passwd lives on the container layer and survives a restart; the
# boot converge must drop bob's account before smbd starts.
sudo rm -f "$SECRETS_DIR/bob.nt"
docker start "$C" > /dev/null
if wait_listening; then
  PW=$(docker exec "$C" cat /etc/passwd)
  if grep -q '^bob:' <<< "$PW"; then fail "bob's account survived a removal while down"; else pass "removed while down: bob's account gone after the restart"; fi
  PDB=$(docker exec "$C" pdbedit -L 2> /dev/null || true)
  if grep -q '^bob:' <<< "$PDB"; then fail "bob still in passdb after the restart"; else pass "removed while down: bob not in passdb"; fi
  refused "bob's old password after a removal while down" tm-cli-in Backups-bob bob "$PW_BOB" -c ls
else
  fail "no smbd after the restart"
fi
nt bob "$PW_BOB"   # back for the tamper checks

# ── tamper: the image's own knob can't weaken it ─────────────
boot "" "    environment:
      CUSTOM_SMB_PROTO: SMB2
      CUSTOM_SMB_AUTH: ntlmv1-permitted"
if wait_listening; then
  client tm-cli-in "$IN_IP"
  refused "SMB2 with CUSTOM_SMB_PROTO=SMB2 injected" tm-cli-in Backups-bob bob "$PW_BOB" -m SMB2 -c ls
  if O=$(smb tm-cli-in Backups-bob bob "$PW_BOB" -c ls) && ! grep -q NT_STATUS <<< "$O"; then pass "SMB3 still works"; else fail "SMB3: $O"; fi
else
  fail "no smbd with the image's knobs set"
fi

# ── tamper: a read-only smb.conf the script can't own ────────
printf '[global]\n   server min protocol = NT1\n   map to guest = bad user\n[open]\n   path = /opt\n   guest ok = yes\n' > "$WORK/weak.conf"
chmod 644 "$WORK/weak.conf"
boot "      - {type: bind, source: $WORK/weak.conf, target: /etc/samba/smb.conf, read_only: true}"
# exited_nonzero: the container stopped with a non-zero code at least once
# (restart: unless-stopped then loops), and 445 never listened.
exited_nonzero() {
  local _ heard=
  for _ in $(seq 1 15); do
    if listening; then heard=1; fi
    sleep 1
  done
  STATE=$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}}' "$C" 2> /dev/null || echo missing)
  [ -z "$heard" ] && { grep -q 'restarts=[1-9]' <<< "$STATE" || ! grep -q 'exit=0' <<< "$STATE"; }
}
if exited_nonzero; then pass "read-only weakened smb.conf: exits non-zero, nothing listens on 445 ($STATE)"; else fail "weakened smb.conf: $STATE"; fi
if logs_have "can't replace /etc/samba/smb.conf"; then pass "portcullis-sync refuses to serve a config it can't own"; else fail "no refusal in the log: $(docker logs --tail 5 "$C" 2>&1)"; fi

# ── empty Local networks: the container doesn't start ────────
PORTCULLIS_LOCAL_NETWORKS='' boot
if exited_nonzero && logs_have 'Local networks is empty; file sharing is off'; then
  pass "empty Local networks: refused, nothing listens ($STATE)"
else
  fail "empty Local networks: $STATE"
fi
