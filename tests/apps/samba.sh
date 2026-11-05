#!/usr/bin/env bash
# Test: Samba (router-less file sharing over hardened SMB3, contract
# §13.17): per-person Home shares and up to 8 shared-folder slots with
# reader and writer groups. No Hub in templates CI: the test writes what the
# Hub would — the tsv people file (readers / writers already expanded to
# members), the per-person .nt hash files (uid 10001, 0600), each slot's
# shared folder (root:<gid> 2770, bind-mounted at /shares/<n>) and its
# PORTCULLIS_FOLDER_GID_SHARE<n>_FOLDER — boots the template and talks SMB
# to it with the runner's smbclient, run inside client containers' network
# namespaces (nsenter) so Samba sees their addresses: one inside the test
# Local networks, one outside.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
# shellcheck disable=SC2034 # read by tests/lib.sh
TEST_NAME="samba"
section "Samba"

APP_ID=samba
C=portcullis-samba-1
COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
DIR=$(dirname "$COMPOSE")
MANIFEST="$DIR/manifest.yaml"
IMAGE=$(yq -r '.services.samba.image' "$COMPOSE")

# ── static ───────────────────────────────────────────────────
if [[ "$IMAGE" =~ ^ghcr\.io/servercontainers/samba:smbd-only-a[0-9.]+-s[0-9.]+-r[0-9]+@sha256:[0-9a-f]{64}$ ]]; then
  pass "image pinned: $IMAGE"
else
  fail "image must be ghcr.io/servercontainers/samba:smbd-only-a<alpine>-s<samba>-r<n>@sha256:<index digest>: $IMAGE"
fi
if [ "$(yq -r '.services.samba.entrypoint | join(" ")' "$COMPOSE")" = /portcullis/bin/start ] \
    && [ "$(yq -r '.services.samba.command | length' "$COMPOSE")" = 0 ]; then
  pass "entrypoint /portcullis/bin/start, no command: the image's entrypoint.sh never runs (F59)"
else
  fail "entrypoint / command"
fi
CAPS=$(yq -r '.services.samba.cap_add | sort | join(",")' "$COMPOSE")
if [ "$(yq -r '.services.samba.cap_drop | join(",")' "$COMPOSE")" = ALL ] \
    && [ "$CAPS" = CHOWN,NET_BIND_SERVICE,SETGID,SETUID ]; then
  pass "cap_drop ALL, cap_add $CAPS"
else
  fail "capabilities: drop $(yq -r '.services.samba.cap_drop' "$COMPOSE"), add $CAPS"
fi
if [ "$(yq -r '.services.samba.security_opt | join(",")' "$COMPOSE")" = no-new-privileges:true ] \
    && [ "$(yq -r '.services.samba.networks | join(",")' "$COMPOSE")" = default ]; then
  pass "no-new-privileges, default network only"
else
  fail "security_opt / networks"
fi
TMPFS=$(yq -r '.services.samba.tmpfs | map(sub(":.*"; "")) | sort | join(" ")' "$COMPOSE")
if [ "$TMPFS" = "/run/portcullis /run/samba /shares /var/cache/samba /var/lib/samba /var/log/samba" ]; then
  pass "passdb and Samba state on tmpfs, /shares a tmpfs (only assigned folders served)"
else
  fail "tmpfs: $TMPFS"
fi
BAD_ENV=$(yq -r '.services.samba.environment | keys | .[]' "$COMPOSE" | grep -E '^(ACCOUNT_|UID_|GROUP_|GROUPS_|SAMBA_|AVAHI_|WSDD2_|NETBIOS_|PORTCULLIS_SYNC_ROOT$)' || true)
if [ -z "$BAD_ENV" ]; then pass "compose sets no ACCOUNT_* / GROUP_* / SAMBA_* / image knob"; else fail "compose sets: $BAD_ENV"; fi
GIDS_OK=1
for n in 1 2 3 4 5 6 7 8; do
  v=$(yq -r ".services.samba.environment.PORTCULLIS_FOLDER_GID_SHARE${n}_FOLDER" "$COMPOSE")
  [ "$v" = "\${PORTCULLIS_FOLDER_GID_SHARE${n}_FOLDER}" ] || { GIDS_OK=; fail "slot $n gid env: $v"; }
  t=$(yq -r ".settings.options[] | select(.key == \"share${n}_folder\") | [.target.mount, (.requires_any | join(\",\")), .folder.joins_group, .folder.runs_as.uid_from] | join(\"|\")" "$MANIFEST")
  [ "$t" = "/shares/$n|share${n}_readers,share${n}_writers|template|uid" ] || { GIDS_OK=; fail "slot $n folder option: $t"; }
  for k in readers writers; do
    d=$(yq -r ".settings.options[] | select(.key == \"share${n}_$k\") | [.type, (.delivery[0].file.name), (.delivery[0].file.render.expand_members | tostring)] | join(\"|\")" "$MANIFEST")
    [ "$d" = "groups|people|true" ] || { GIDS_OK=; fail "slot $n $k: $d"; }
  done
done
[ -z "$GIDS_OK" ] || pass "8 slots: /shares/<n>, requires_any readers/writers, expanded groups, PORTCULLIS_FOLDER_GID_SHARE<n>_FOLDER in env"
if [ "$(yq -r '.hooks[] | select(.name == "sync") | [.service, (.command | join(" ")), (.when | join(",")), .timeout] | join("|")' "$MANIFEST")" \
    = 'samba|/portcullis/bin/portcullis-sync|start,settings_change,membership_change,credential_change|60s' ]; then
  pass "sync hook: portcullis-sync on start, settings, membership and credential changes"
else
  fail "hooks: sync"
fi
if cmp -s "$DIR/bin/portcullis-sync" timemachine/bin/portcullis-sync; then pass "bin/portcullis-sync is byte-identical to timemachine's"; else fail "bin/portcullis-sync differs from timemachine's"; fi

docker pull -q "$IMAGE" > /dev/null
# The image's own accounts and groups are reserved usernames.
RESERVED=" $(yq -r '.settings.options[] | select(.key == "share_password") | .username.reserved | join(" ")' "$MANIFEST") "
IMAGE_USERS=$(docker run --rm --network none --entrypoint cat "$IMAGE" /etc/passwd | cut -d: -f1 | sort | tr '\n' ' ')
MISSING=
for n in $(docker run --rm --network none --entrypoint cat "$IMAGE" /etc/passwd /etc/group | cut -d: -f1 | sort -u); do
  case $RESERVED in *" $n "*) ;; *) MISSING="$MISSING $n" ;; esac
done
if [ -z "$MISSING" ]; then pass "username.reserved covers every account and group in the image"; else fail "username.reserved misses:$MISSING"; fi
# The privilege drop (Task 16 carry): busybox setpriv can't change ids;
# the image must have s6-applyuidgid, chpst or util-linux setpriv.
TOOLS=$(docker run --rm --network none --entrypoint sh "$IMAGE" -c \
  'for t in s6-applyuidgid chpst sv runsvdir flock timeout sha256sum smbstatus smbcontrol testparm adduser addgroup deluser delgroup; do command -v $t > /dev/null && printf "%s " $t; done; setpriv --help 2>&1 | grep -q -e --reuid && printf "util-linux-setpriv "' || true)
if grep -qw chpst <<< "$TOOLS" || grep -qw s6-applyuidgid <<< "$TOOLS" || grep -qw util-linux-setpriv <<< "$TOOLS"; then
  pass "a privilege-drop tool is in the image ($(grep -oE 's6-applyuidgid|chpst|util-linux-setpriv' <<< "$TOOLS" | tr '\n' ' '))"
else
  fail "no s6-applyuidgid / chpst / util-linux setpriv in the image: $TOOLS"
fi
NEED_MISSING=
for t in sv runsvdir flock timeout sha256sum smbstatus smbcontrol testparm adduser addgroup deluser delgroup; do
  grep -qw -- "$t" <<< "$TOOLS" || NEED_MISSING="$NEED_MISSING $t"
done
if [ -z "$NEED_MISSING" ]; then pass "every tool portcullis-sync and start use is in the image"; else fail "missing in the image:$NEED_MISSING"; fi
# F59, at the pinned digest: the image's own entrypoint (which the template
# never runs) with no ACCOUNT_* creates no account and no share, and its
# /.initialized path changes nothing on a second start.
F59=$(docker run --rm --network none "$IMAGE" sh -c \
  'cp /etc/passwd /tmp/p1; cp /etc/group /tmp/g1; cp /etc/samba/smb.conf /tmp/c1
   [ -f /.initialized ] && echo INITIALIZED
   /container/scripts/entrypoint.sh true > /dev/null 2>&1
   cmp -s /tmp/p1 /etc/passwd && cmp -s /tmp/g1 /etc/group && cmp -s /tmp/c1 /etc/samba/smb.conf && echo RESTART_SAME
   echo "USERS $(cut -d: -f1 /etc/passwd | sort | tr "\n" " ")"
   echo "SECTIONS $(grep "^\[" /etc/samba/smb.conf | tr "\n" " ")"
   echo "PASSDB $(pdbedit -L 2> /dev/null | wc -l)"' 2> /dev/null || true)
if grep -qx INITIALIZED <<< "$F59" && grep -qx RESTART_SAME <<< "$F59" \
    && grep -qxF "USERS $IMAGE_USERS" <<< "$F59" && grep -qxF 'SECTIONS [global] ' <<< "$F59" && grep -qx 'PASSDB 0' <<< "$F59"; then
  pass "F59: the image's entrypoint with no ACCOUNT_* adds no account, no share, no passdb entry, and a restart (/.initialized) re-adds nothing"
else
  fail "F59: $F59"
fi

# ── fixtures ─────────────────────────────────────────────────
command -v smbclient > /dev/null || { sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq smbclient > /dev/null; }
info "$(smbclient --version)"

WORK=$(mktemp -d)
PEOPLE_DIR="$WORK/appfiles/samba/people"
SECRETS_DIR="$WORK/secrets/samba/share_password"
AVAHI_DIR="$WORK/avahi"
FAMILY="$WORK/folders/family"   # slot 1, folder gid 60001
PHOTOS="$WORK/folders/photos"   # slot 2, folder gid 60002
OVERRIDE="$WORK/override.yml"
NET=192.168.232
SMB_IP=$NET.10
IN_IP=$NET.50
OUT_IP=$NET.70
export PORTCULLIS_LOCAL_NETWORKS="$NET.48/28,fd00:2::/64"
export PORTCULLIS_FOLDER_GID_SHARE1_FOLDER=60001 PORTCULLIS_FOLDER_GID_SHARE2_FOLDER=60002

cleanup() {
  docker rm -f smb-cli-in smb-cli-out > /dev/null 2>&1 || true
  COMPOSE_OVERRIDE="$OVERRIDE" compose_down "$APP_ID" > /dev/null 2>&1 || true
  docker volume rm portcullis_samba-homes > /dev/null 2>&1 || true
  sudo rm -rf "$WORK"
  report
}
trap cleanup EXIT

sudo mkdir -p "$PEOPLE_DIR" "$SECRETS_DIR" "$AVAHI_DIR" "$WORK/folders"
sudo chown 10001:10001 "$WORK/appfiles" "$WORK/appfiles/samba" "$PEOPLE_DIR" "$WORK/secrets" "$WORK/secrets/samba" "$SECRETS_DIR"
sudo chmod 0750 "$WORK/appfiles" "$WORK/appfiles/samba" "$PEOPLE_DIR"
sudo chmod 0700 "$WORK/secrets" "$WORK/secrets/samba" "$SECRETS_DIR"
sudo chown 0:0 "$AVAHI_DIR"
sudo chmod 0755 "$AVAHI_DIR"
# What the Hub's folder apply makes of a shared folder: root:<gid>, setgid.
sudo install -d -o 0 -g 60001 -m 2770 "$FAMILY"
sudo install -d -o 0 -g 60002 -m 2770 "$PHOTOS"

# people <tsv line>...: the Hub's people file (version + instance first,
# the rest sorted), 0640 uid 10001, atomically.
people() {
  local tmp="$WORK/people.tmp"
  { printf 'version\t1\ninstance\tsamba\n'; printf '%s\n' "$@" | sed 's/|/\t/g' | LC_ALL=C sort; } > "$tmp"
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
PW_DAVE=Dddd-2345-Wxyz-abcd-EFGH-jkm6
PW_EVE=Eeee-Ffff-2345-6789-abcd-efgh

write_override() {  # write_override [extra volume lines] [extra service keys]
  cat > "$OVERRIDE" << EOF
services:
  samba:
    volumes:
      - {type: bind, source: $PEOPLE_DIR, target: /portcullis/data, read_only: true}
      - {type: bind, source: $SECRETS_DIR, target: /portcullis/secrets, read_only: true}
      - {type: bind, source: $AVAHI_DIR, target: /portcullis/avahi}
      - {type: bind, source: $FAMILY, target: /shares/1, bind: {create_host_path: false}}
      - {type: bind, source: $PHOTOS, target: /shares/2, bind: {create_host_path: false}}
${1:-}
    networks:
      default:
        ipv4_address: $SMB_IP
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
wait_healthy() {
  local _
  HEALTH=
  for _ in $(seq 1 45); do
    HEALTH=$(docker inspect -f '{{.State.Health.Status}}' "$C" 2> /dev/null || true)
    [ "$HEALTH" = "$1" ] && return 0
    sleep 2
  done
  return 1
}
boot() {  # boot [extra volume lines] [extra service keys]: a fresh container
  docker rm -f smb-cli-in smb-cli-out > /dev/null 2>&1 || true
  COMPOSE_OVERRIDE="$OVERRIDE" compose_down "$APP_ID" > /dev/null 2>&1 || true
  docker volume rm portcullis_samba-homes > /dev/null 2>&1 || true
  docker network rm portcullis_default > /dev/null 2>&1 || true
  write_override "${1:-}" "${2:-}"
  COMPOSE_OVERRIDE="$OVERRIDE" compose_up "$APP_ID"
}
client() {  # client <name> <ip>: a container whose netns smbclient runs in
  docker rm -f "$1" > /dev/null 2>&1 || true
  docker run -d --name "$1" --network portcullis_default --ip "$2" --entrypoint sleep "$IMAGE" 3600 > /dev/null
}
# smb <client> <share> <user> <password> [smbclient args]
smb() {
  local cli=$1 share=$2 user=$3 pw=$4 pid
  shift 4
  pid=$(docker inspect -f '{{.State.Pid}}' "$cli")
  sudo nsenter --net="/proc/$pid/ns/net" env PASSWD="$pw" timeout 30 smbclient "//$SMB_IP/$share" -U "$user" \
    --use-kerberos=disabled -m SMB3 --option='client min protocol=SMB2_02' --option='client smb encrypt=required' "$@" 2>&1
}
works() {  # works <label> <smb args...>: no NT_STATUS error
  local label=$1 o
  shift
  if o=$(smb "$@") && ! grep -q NT_STATUS <<< "$o"; then pass "$label"; else fail "$label: $o"; fi
}
refused() {  # refused <label> <smb args...>
  local label=$1 o
  shift
  if o=$(smb "$@") && ! grep -q NT_STATUS <<< "$o"; then fail "$label: accepted"; else pass "$label: refused ($(grep -o 'NT_STATUS_[A-Z_]*' <<< "$o" | head -1))"; fi
}
hook() {  # hook [trigger]: run the sync hook like the Hub (stdin HookInput)
  printf '{"trigger":"%s","version":1,"instance":"samba","values":{},"people":{},"groups":{},"entries":{},"secrets":{},"credentials":{}}' \
    "${1:-membership_change}" | docker exec -i "$C" /portcullis/bin/portcullis-sync
}
sessions_of() { docker exec "$C" smbstatus -p -n 2> /dev/null | awk -v u="$1" '$1 ~ /^[0-9]+$/ && $2 == u { print $1 }'; }
# long_session <user> <password> <share>: a client session that stays open
long_session() {
  local pid
  pid=$(docker inspect -f '{{.State.Pid}}' smb-cli-in)
  # shellcheck disable=SC2024 # the log is the runner user's own file
  (while :; do echo 'ls' 2> /dev/null || exit 0; sleep 1; done) | sudo nsenter --net="/proc/$pid/ns/net" env PASSWD="$2" timeout 120 \
    smbclient "//$SMB_IP/$3" -U "$1" --use-kerberos=disabled -m SMB3 --option='client smb encrypt=required' > "$WORK/long-$1.log" 2>&1 &
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
# section_of <name>: testparm -s -v's lines of one section
section_of() { awk -v s="[$1]" '$0 == s { on = 1; next } /^\[/ { on = 0 } on' <<< "$TP"; }
passwd_names() { docker exec "$C" cut -d: -f1 /etc/passwd | sort | tr '\n' ' '; }

# From here on every check reports (no early exit), whatever fails.
set +e

# ── nobody eligible ──────────────────────────────────────────
people 'value|advertise|false' 'value|connect_address|nas.example' \
  'value|share1_name|Family' 'value|share1_readers|bob' 'value|share1_writers|alice'
boot
if wait_listening; then pass "smbd listens on 445 with nobody eligible"; else fail "smbd not listening"; exit 1; fi
if wait_healthy healthy; then pass "healthcheck: healthy (smb.conf verifies, smbd runs)"; else fail "healthcheck: $HEALTH"; fi
if [ -z "$(docker exec "$C" pdbedit -L 2> /dev/null)" ]; then pass "nobody: pdbedit -L empty"; else fail "nobody: passdb has $(docker exec "$C" pdbedit -L)"; fi
if [ "$(passwd_names)" = "$IMAGE_USERS" ]; then pass "no default account: /etc/passwd is the image's own"; else fail "accounts: $(passwd_names) (image: $IMAGE_USERS)"; fi
SECTIONS=$(docker exec "$C" grep '^\[' /etc/samba/smb.conf | tr '\n' ' ')
if [ "$SECTIONS" = "[global] " ]; then pass "smb.conf has [global] only (a slot without people isn't rendered)"; else fail "smb.conf sections: $SECTIONS"; fi
if docker exec "$C" test -e /.initialized || docker exec "$C" test -e /etc/avahi/services/samba.service || logs_have 'Welcome to the ghcr.io/servercontainers/samba'; then
  fail "the image's entrypoint ran (/.initialized, samba.service or its banner)"
else
  pass "the image's entrypoint never ran (no /.initialized, no samba.service, no banner)"
fi
PS=$(docker exec "$C" ps -o comm)
if grep -qE 'nmbd|avahi|wsdd2|dbus' <<< "$PS"; then fail "nmbd, avahi, wsdd2 or dbus runs"; else pass "only smbd runs under runit (no nmbd, avahi, wsdd2)"; fi
if grep -qx runsvdir <<< "$PS" && grep -qx runsv <<< "$PS"; then pass "runit supervises smbd (runsvdir, runsv)"; else fail "no runit: $(tr '\n' ' ' <<< "$PS")"; fi
CAPEFF=$(docker exec "$C" awk '/^CapEff/ { print $2 }' /proc/1/status)
CAPDEC=$((16#$CAPEFF))
if [ "$CAPDEC" = $(((1 << 0) | (1 << 6) | (1 << 7) | (1 << 10))) ]; then
  pass "CapEff is exactly CHOWN SETGID SETUID NET_BIND_SERVICE (no DAC_OVERRIDE / DAC_READ_SEARCH)"
else
  fail "CapEff $CAPEFF"
fi
# Captured whole first: grep -q on a pipe can SIGPIPE testparm (pipefail).
TP=$(docker exec "$C" testparm -s -v 2> /dev/null)
if grep -qxF $'\thosts allow = '"$NET.48/28 fd00:2::/64" <<< "$TP"; then
  pass "testparm: hosts allow = $NET.48/28 fd00:2::/64"
else
  fail "testparm hosts allow: $(grep 'hosts allow' <<< "$TP")"
fi

# ── people ───────────────────────────────────────────────────
# Family (slot 1): alice writes, bob reads. Photos (slot 2): alice reads.
# dave is in the population with a password, in neither group. carol has
# no password yet.
PEOPLE_ALL=('value|advertise|true' 'value|connect_address|nas.example'
  'person|alice|uid|20000' 'person|bob|uid|20001' 'person|carol|uid|20002' 'person|dave|uid|20003')
people "${PEOPLE_ALL[@]}" \
  'value|share1_name|Family' 'value|share1_readers|bob' 'value|share1_writers|alice' \
  'value|share2_name|Photos' 'value|share2_readers|alice' 'value|share2_writers|'
nt alice "$PW_ALICE"; nt bob "$PW_BOB"; nt dave "$PW_DAVE"
OUT=$(hook start); RC=$?
if [ "$RC" = 0 ] && [ "$(grep -c '^PORTCULLIS-REPORT {"version":1,' <<< "$OUT")" = 1 ]; then pass "hook applied, exactly one report line"; else fail "hook rc $RC: $OUT"; fi
REPORT=$(sed -n 's/^PORTCULLIS-REPORT //p' <<< "$OUT")
if python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["version"] == 1 and {(f["option"], f["name"]) for f in d["folders"]} == {("homes", "alice"), ("homes", "bob"), ("homes", "dave")}, d' "$REPORT"; then
  pass "report: the three home folders"
else
  fail "report: $REPORT"
fi
if grep -qiE '[0-9a-f]{32}' <<< "$OUT"; then fail "hook output holds a 32-hex string"; else pass "no hash in the hook output"; fi
if [ "$(docker exec "$C" pdbedit -L 2> /dev/null | cut -d: -f1,2 | sort | tr '\n' ' ')" = "alice:20000 bob:20001 dave:20003 " ]; then
  pass "passdb: alice, bob, dave (carol has no password)"
else
  fail "passdb: $(docker exec "$C" pdbedit -L 2> /dev/null)"
fi
EXTRA=$(docker exec "$C" awk -F: '$3 >= 1000 && $3 < 65534 { print $1 ":" $3 }' /etc/passwd | sort | tr '\n' ' ')
if [ "$EXTRA" = "alice:20000 bob:20001 dave:20003 " ]; then pass "accounts: only the people served, no default account"; else fail "accounts: $EXTRA"; fi
GROUPS_NOW=$(docker exec "$C" awk -F: '$3 >= 10000 && $3 <= 60999 { print $1 ":" $3 }' /etc/group | sort | tr '\n' ' ')
if [ "$GROUPS_NOW" = "alice:20000 bob:20001 dave:20003 pfg60001:60001 pfg60002:60002 " ]; then
  pass "groups: each person's private group and pfg60001 / pfg60002 for the folders"
else
  fail "groups: $GROUPS_NOW"
fi
SECTIONS=$(docker exec "$C" grep '^\[' /etc/samba/smb.conf | tr '\n' ' ')
if [ "$SECTIONS" = "[global] [Home] [Family] [Photos] " ]; then pass "smb.conf: [global] [Home] [Family] [Photos]"; else fail "smb.conf sections: $SECTIONS"; fi
TP=$(docker exec "$C" testparm -s -v 2> /dev/null)
S_HOME=$(section_of Home); S_FAM=$(section_of Family); S_PH=$(section_of Photos)
if grep -qxF $'\tpath = /homes/%u' <<< "$S_HOME" && grep -qxF $'\tvalid users = alice bob dave' <<< "$S_HOME"; then
  pass "testparm [Home]: path = /homes/%u, valid users = alice bob dave (explicit)"
else
  fail "testparm [Home]: $S_HOME"
fi
if grep -qxF $'\tpath = /shares/1' <<< "$S_FAM" && grep -qxF $'\tvalid users = alice bob' <<< "$S_FAM" \
    && grep -qxF $'\twrite list = alice' <<< "$S_FAM" && grep -qxF $'\tforce group = pfg60001' <<< "$S_FAM"; then
  pass "testparm [Family]: /shares/1, valid users = alice bob, write list = alice, force group = pfg60001"
else
  fail "testparm [Family]: $S_FAM"
fi
if grep -qxF $'\tvalid users = alice' <<< "$S_PH" && grep -qxF $'\tforce group = pfg60002' <<< "$S_PH" && ! grep -q 'write list' <<< "$S_PH"; then
  pass "testparm [Photos]: valid users = alice (read list), force group = pfg60002, no write list"
else
  fail "testparm [Photos]: $S_PH"
fi
if grep -qE $'^\t(read only = No|guest ok = Yes)' <<< "$S_FAM$S_PH"; then fail "a shared folder is writable for all or guest"; else pass "shared folders: read only = yes, guest ok = no (testparm defaults)"; fi
if [ -n "$(docker exec "$C" find /run/portcullis /etc/samba /tmp -type f -exec grep -lE "$(nthash "$PW_ALICE")" {} + 2> /dev/null)" ]; then
  fail "a hash outside the passdb"
else
  pass "no hash left under /run/portcullis, /etc/samba or /tmp"
fi
if [ "$(docker exec "$C" stat -c '%u %a' /var/lib/samba/private/smbpasswd)" = "0 600" ]; then pass "passdb root 0600"; else fail "passdb mode"; fi
if [ "$(docker exec "$C" stat -c '%u:%g %a' /homes/alice)" = "20000:20000 700" ]; then pass "/homes/alice is 20000:20000 0700"; else fail "/homes/alice: $(docker exec "$C" stat -c '%u:%g %a' /homes/alice)"; fi

client smb-cli-in "$IN_IP"
client smb-cli-out "$OUT_IP"
echo hello > "$WORK/hello.txt"

# ── Home ─────────────────────────────────────────────────────
works "alice lists Home over encrypted SMB3" smb-cli-in Home alice "$PW_ALICE" -c ls
works "alice writes to Home" smb-cli-in Home alice "$PW_ALICE" -c "put $WORK/hello.txt alice-home.txt"
if [ "$(docker exec -u 20000:20000 "$C" stat -c '%u:%g' /homes/alice/alice-home.txt)" = 20000:20000 ]; then
  pass "a file alice writes to Home is 20000:20000"
else
  fail "Home file: $(docker exec -u 20000:20000 "$C" stat -c '%u:%g %a' /homes/alice/alice-home.txt 2>&1)"
fi
O=$(smb smb-cli-in Home bob "$PW_BOB" -c ls)
if ! grep -q NT_STATUS <<< "$O" && ! grep -q alice-home.txt <<< "$O"; then pass "bob's Home is his own folder (alice's file not there)"; else fail "bob's Home: $O"; fi
refused "bob reading ../alice/alice-home.txt from his Home" smb-cli-in Home bob "$PW_BOB" -c "get ../alice/alice-home.txt $WORK/stolen.txt"
if [ -s "$WORK/stolen.txt" ]; then fail "bob got alice's home file"; fi
refused "bob opening a share named alice" smb-cli-in alice bob "$PW_BOB" -c ls
refused "bob opening a share named homes" smb-cli-in homes bob "$PW_BOB" -c ls

# ── shared folders ───────────────────────────────────────────
works "alice (writer) writes to Family" smb-cli-in Family alice "$PW_ALICE" -c "put $WORK/hello.txt alice.txt; mkdir albums"
if [ "$(docker exec -u 20001:60001 "$C" stat -c '%u:%g %a' /shares/1/alice.txt)" = "20000:60001 660" ]; then
  pass "alice's new file in Family is 20000:60001 mode 0660 (force group, create mask)"
else
  fail "Family file: $(docker exec -u 20001:60001 "$C" stat -c '%u:%g %a' /shares/1/alice.txt 2>&1)"
fi
DST=$(docker exec -u 20001:60001 "$C" stat -c '%u:%g %a' /shares/1/albums)
if [ "${DST%% *}" = 20000:60001 ] && [ "${DST##* }" = 2770 ]; then pass "alice's new directory is 20000:60001 mode 2770"; else fail "Family directory: $DST"; fi
O=$(smb smb-cli-in Family bob "$PW_BOB" -c "get alice.txt $WORK/bob-read.txt")
if ! grep -q NT_STATUS <<< "$O" && cmp -s "$WORK/hello.txt" "$WORK/bob-read.txt"; then pass "bob (reader) reads alice's file"; else fail "bob read: $O"; fi
refused "bob (reader) writing to Family" smb-cli-in Family bob "$PW_BOB" -c "put $WORK/hello.txt bob.txt"
refused "bob (reader) making a directory in Family" smb-cli-in Family bob "$PW_BOB" -c "mkdir bobdir"
refused "bob (reader) deleting alice's file" smb-cli-in Family bob "$PW_BOB" -c "del alice.txt"
if docker exec -u 20001:60001 "$C" test -e /shares/1/bob.txt; then fail "bob's file landed in Family"; else pass "nothing of bob's in Family"; fi
O=$(smb smb-cli-in Family dave "$PW_DAVE" -c ls)
if grep -q NT_STATUS_ACCESS_DENIED <<< "$O"; then pass "dave (in neither group) on Family: NT_STATUS_ACCESS_DENIED"; else fail "dave on Family: $O"; fi
works "alice (reader) lists Photos" smb-cli-in Photos alice "$PW_ALICE" -c ls
refused "alice (reader) writing to Photos" smb-cli-in Photos alice "$PW_ALICE" -c "put $WORK/hello.txt alice.txt"
refused "bob (no group) on Photos" smb-cli-in Photos bob "$PW_BOB" -c ls

# ── hardened SMB ─────────────────────────────────────────────
refused "-m SMB2" smb-cli-in Home alice "$PW_ALICE" -m SMB2 -c ls
refused "-m NT1 (SMB1)" smb-cli-in Home alice "$PW_ALICE" -m NT1 --option='client min protocol=NT1' -c ls
refused "NTLMv1 (client ntlmv2 auth=no)" smb-cli-in Home alice "$PW_ALICE" --option='client ntlmv2 auth=no' -c ls
refused "a wrong password" smb-cli-in Home alice "$PW_BOB" -c ls
refused "guest on Home" smb-cli-in Home guest "" -N -c ls
refused "guest on Family" smb-cli-in Family guest "" -N -c ls
refused "anonymous share list" smb-cli-in IPC\$ "" "" -N -c ls
refused "a client outside Local networks ($OUT_IP)" smb-cli-out Home alice "$PW_ALICE" -c ls
if logs_have "Denied connection from $OUT_IP"; then pass "smbd logged the denied address"; else info "no 'Denied connection' line in the log"; fi
long_session alice "$PW_ALICE" Family
if wait_sessions 20000 some 15; then
  ENC=$(docker exec "$C" smbstatus -p -n 2> /dev/null | awk '$1 ~ /^[0-9]+$/')
  if [ -n "$ENC" ] && ! grep -qvE 'AES-(128|256)-(GCM|CCM)' <<< "$ENC"; then pass "every session is AES-encrypted"; else fail "an unencrypted session: $ENC"; fi
else
  fail "no open session for alice: $(cat "$WORK/long-alice.log")"
fi
kill "$LONG_PID" 2> /dev/null
wait_sessions 20000 none 15

# ── Bonjour ──────────────────────────────────────────────────
BJ="$AVAHI_DIR/portcullis-samba.service"
if [ -f "$BJ" ] && grep -q '<type>_smb._tcp</type>' "$BJ" && grep -q '<port>445</port>' "$BJ" && ! grep -q _adisk "$BJ"; then
  pass "Bonjour: portcullis-samba.service with _smb._tcp on 445 (no _adisk)"
else
  fail "Bonjour file: $(cat "$BJ" 2> /dev/null)"
fi

# ── regenerated password: the old one and its sessions stop (F29) ──
long_session alice "$PW_ALICE" Family
if wait_sessions 20000 some 15; then pass "alice has an open session"; else fail "no open session for alice: $(cat "$WORK/long-alice.log")"; fi
nt alice "$PW_ALICE2"
hook credential_change > /dev/null
if wait_sessions 20000 none 10; then pass "regenerated: alice's open session dropped within 10 s"; else fail "regenerated: session still open"; fi
kill "$LONG_PID" 2> /dev/null
refused "the old password" smb-cli-in Family alice "$PW_ALICE" -c ls
works "the new password works" smb-cli-in Family alice "$PW_ALICE2" -c ls

# ── a share-group removal ends that person's sessions (F28) ──
long_session bob "$PW_BOB" Family
if wait_sessions 20001 some 15; then pass "bob has an open Family session"; else fail "no open session for bob: $(cat "$WORK/long-bob.log")"; fi
people "${PEOPLE_ALL[@]}" \
  'value|share1_name|Family' 'value|share1_readers|' 'value|share1_writers|alice' \
  'value|share2_name|Photos' 'value|share2_readers|alice' 'value|share2_writers|'
hook membership_change > /dev/null
if wait_sessions 20001 none 10; then pass "bob left Family's readers: his open session dropped"; else fail "bob's session still open after leaving the readers"; fi
kill "$LONG_PID" 2> /dev/null
O=$(smb smb-cli-in Family bob "$PW_BOB" -c ls)
if grep -q NT_STATUS_ACCESS_DENIED <<< "$O"; then pass "bob on Family after leaving its readers: ACCESS_DENIED"; else fail "bob on Family: $O"; fi
works "bob keeps his Home" smb-cli-in Home bob "$PW_BOB" -c ls

# ── a writer demoted to reader: sessions end, no more writes ─
long_session alice "$PW_ALICE2" Family
if wait_sessions 20000 some 15; then pass "alice (writer) has an open Family session"; else fail "no open session for alice: $(cat "$WORK/long-alice.log")"; fi
people "${PEOPLE_ALL[@]}" \
  'value|share1_name|Family' 'value|share1_readers|alice' 'value|share1_writers|' \
  'value|share2_name|Photos' 'value|share2_readers|alice' 'value|share2_writers|'
hook membership_change > /dev/null
if wait_sessions 20000 none 10; then pass "alice demoted to reader: her open session dropped"; else fail "alice's writer session still open after the demotion"; fi
kill "$LONG_PID" 2> /dev/null
refused "alice (now a reader) writing to Family in a new session" smb-cli-in Family alice "$PW_ALICE2" -c "put $WORK/hello.txt demoted.txt"
if docker exec -u 20001:60001 "$C" test -e /shares/1/demoted.txt; then fail "a demoted writer's file landed in Family"; else pass "nothing written after the demotion"; fi
works "alice still reads Family" smb-cli-in Family alice "$PW_ALICE2" -c ls

# ── a writer's files in a renamed slot keep the folder gid ───
people "${PEOPLE_ALL[@]}" \
  'value|share1_name|Household' 'value|share1_writers|alice' \
  'value|share2_name|Photos' 'value|share2_readers|alice' 'value|share2_writers|'
hook settings_change > /dev/null
refused "the old share name Family" smb-cli-in Family alice "$PW_ALICE2" -c ls
works "the renamed share Household" smb-cli-in Household alice "$PW_ALICE2" -c "put $WORK/hello.txt second.txt"
if [ "$(docker exec -u 20000:60001 "$C" stat -c '%u:%g %a' /shares/1/second.txt)" = "20000:60001 660" ]; then pass "a writer's file is 20000:60001 0660 again"; else fail "second.txt: $(docker exec -u 20000:60001 "$C" stat -c '%u:%g %a' /shares/1/second.txt 2>&1)"; fi

# ── reserved and duplicate share names (F41) ─────────────────
people "${PEOPLE_ALL[@]}" \
  'value|share1_name|Homes' 'value|share1_writers|alice' \
  'value|share2_name|Photos' 'value|share2_readers|alice' 'value|share2_writers|'
OUT=$(hook settings_change)
if grep -q '"code":"name_refused","severity":"info","subject":"Homes"' <<< "$OUT" && ! docker exec "$C" grep -qi '^\[homes\]' /etc/samba/smb.conf; then
  pass "share name Homes refused, reported name_refused"
else
  fail "Homes: $OUT"
fi
people "${PEOPLE_ALL[@]}" \
  'value|share1_name|photos' 'value|share1_writers|alice' \
  'value|share2_name|Photos' 'value|share2_readers|alice' 'value|share2_writers|'
OUT=$(hook settings_change)
if grep -q '"code":"name_refused","severity":"info","subject":"Photos"' <<< "$OUT" \
    && [ "$(docker exec "$C" grep -ci '^\[photos\]' /etc/samba/smb.conf)" = 1 ] \
    && docker exec "$C" grep -qx '   path = /shares/1' /etc/samba/smb.conf && ! docker exec "$C" grep -qx '   path = /shares/2' /etc/samba/smb.conf; then
  pass "duplicate name Photos (slot 2) refused; slot 1's photos served once"
else
  fail "duplicate: $OUT"
fi
people "${PEOPLE_ALL[@]}" \
  'value|share1_name|Family' 'value|share1_readers|bob' 'value|share1_writers|alice' \
  'value|share2_name|Photos' 'value|share2_readers|alice' 'value|share2_writers|'
hook settings_change > /dev/null

# ── revocation: removed hash -> account and sessions gone within 8 s ──
long_session alice "$PW_ALICE2" Family
wait_sessions 20000 some 15 || fail "no open session for alice"
sudo rm -f "$SECRETS_DIR/alice.nt"
T0=$(date +%s%N)
hook credential_change > /dev/null
T1=$(date +%s%N)
MS=$(((T1 - T0) / 1000000))
if [ "$MS" -lt 8000 ]; then pass "credential_change run took ${MS} ms (< 8 s)"; else fail "credential_change run took ${MS} ms"; fi
if wait_sessions 20000 none 10; then pass "revoked: alice's open session dropped within 10 s"; else fail "revoked: alice's session still open"; fi
kill "$LONG_PID" 2> /dev/null
refused "alice on Family after revocation" smb-cli-in Family alice "$PW_ALICE2" -c ls
refused "alice on Home after revocation" smb-cli-in Home alice "$PW_ALICE2" -c ls
if docker exec "$C" grep -q '^alice:' /etc/passwd; then fail "alice's Unix account still exists"; else pass "alice's Unix account removed"; fi
if docker exec "$C" pdbedit -L 2> /dev/null | grep -q '^alice:'; then fail "alice still in passdb"; else pass "alice removed from passdb"; fi
TP=$(docker exec "$C" testparm -s -v 2> /dev/null)
if grep -qxF $'\tvalid users = bob' <<< "$(section_of Family)" && ! grep -q 'write list' <<< "$(section_of Family)" \
    && ! docker exec "$C" grep -q '^\[Photos\]' /etc/samba/smb.conf; then
  pass "Family serves bob alone (no writer left), Photos (alice only) no longer rendered"
else
  fail "after revocation: $(docker exec "$C" grep -A4 '^\[' /etc/samba/smb.conf)"
fi
if docker exec "$C" test -d /homes/alice && docker exec -u 20001:60001 "$C" test -e /shares/1/alice.txt; then
  pass "alice's home and her files in Family stay on disk"
else
  fail "alice's data was removed"
fi

# ── a former account's home isn't served ─────────────────────
nt carol "$PW_CAROL"
# chmod before chown: root has CHOWN but not FOWNER.
docker exec "$C" sh -c 'mkdir -p -m 0700 /homes/carol && chown 20099:20099 /homes/carol' || fail "can't make carol's former-account folder"
OUT=$(hook membership_change)
TP=$(docker exec "$C" testparm -s -v 2> /dev/null)
if grep -q '"code":"former_account","severity":"warning","subject":"carol"' <<< "$OUT" \
    && grep -qxF $'\tvalid users = bob dave' <<< "$(section_of Home)"; then
  pass "carol's home belongs to uid 20099: not in [Home], reported former_account"
else
  fail "former account: $OUT / $(section_of Home)"
fi
O=$(smb smb-cli-in Home carol "$PW_CAROL" -c ls)
if grep -q NT_STATUS <<< "$O"; then pass "carol can't open Home ($(grep -o 'NT_STATUS_[A-Z_]*' <<< "$O" | head -1))"; else fail "carol opened the former account's Home: $O"; fi

# ── runit keeps a failed check down (fail closed) ────────────
# A config changed behind the script's back: smbd's run script re-verifies
# it before every start, so after a crash smbd stays down.
docker exec "$C" sh -c 'printf "\n[open]\n   path = /shares\n   guest ok = yes\n" >> /etc/samba/smb.conf'
docker exec "$C" sh -c 'for p in $(pidof smbd); do kill -KILL $p; done'
HEARD=
for _ in $(seq 1 12); do listening && HEARD=1; sleep 1; done
if [ -z "$HEARD" ] && ! docker exec "$C" pidof smbd > /dev/null; then pass "tampered smb.conf: runit's restart refuses (--check), nothing listens on 445"; else fail "smbd came back on a tampered smb.conf"; fi
if wait_healthy unhealthy; then pass "healthcheck: unhealthy while smb.conf doesn't verify"; else fail "healthcheck: $HEALTH"; fi
hook settings_change > /dev/null
if wait_listening; then pass "the next hook run rewrites smb.conf and smbd is back"; else fail "smbd not back after the hook"; fi
# runit's view of a stop (diagnostic only: fail closed doesn't rely on it).
SVD=$(docker exec "$C" sv down /run/portcullis-sv/smbd 2>&1; echo "rc=$?")
sleep 3
info "sv down: $(tr '\n' ' ' <<< "$SVD")/ sv status: $(docker exec "$C" sv status /run/portcullis-sv/smbd 2>&1)"
docker exec "$C" sv up /run/portcullis-sv/smbd > /dev/null 2>&1
wait_listening > /dev/null || docker exec "$C" sh -c 'for p in $(pidof smbd); do kill -KILL $p; done'
if wait_listening; then pass "smbd serves again after the diagnostic"; else fail "smbd not back after sv up"; fi

# ── hook-time fail closed under runit ────────────────────────
# smb.conf replaced by a directory: the run changes the passdb, then the
# installed config doesn't verify (exit 4) and smbd is brought down. A
# valid smb.conf put back behind the script's back still doesn't start it:
# --check refuses until a run converges again (whatever runit does).
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
if [ -z "$HEARD" ] && ! docker exec "$C" pidof smbd > /dev/null; then
  pass "after a fail-closed stop smbd stays down, even with a valid smb.conf back ($(docker exec "$C" sv status /run/portcullis-sv/smbd 2>&1))"
else
  fail "smbd came back after a fail-closed stop: $(docker exec "$C" sv status /run/portcullis-sv/smbd 2>&1)"
fi
CK=$(docker exec "$C" /portcullis/bin/portcullis-sync --check 2>&1); RC=$?
if [ "$RC" = 4 ] && grep -q 'brought down (fail closed)' <<< "$CK"; then pass "--check refuses after a fail-closed stop"; else fail "--check: rc $RC: $CK"; fi
OUT=$(hook settings_change 2>&1); RC=$?
if [ "$RC" = 0 ] && wait_listening; then pass "the next good run brings smbd back"; else fail "after the fail-closed stop: rc $RC: $OUT"; fi
if docker exec "$C" /portcullis/bin/portcullis-sync --check > /dev/null 2>&1; then pass "--check passes again"; else fail "--check still refuses"; fi

# ── stop: the Bonjour file goes ──────────────────────────────
docker stop -t 20 "$C" > /dev/null
if [ ! -e "$BJ" ]; then pass "container stop removes the Bonjour file"; else fail "Bonjour file left after stop"; fi
if [ "$(docker inspect -f '{{.State.ExitCode}}' "$C")" = 0 ]; then pass "a docker stop exits 0"; else fail "stop exit code $(docker inspect -f '{{.State.ExitCode}}' "$C")"; fi

# ── removed while the container was down; restart adds nothing ──
sudo rm -f "$SECRETS_DIR/bob.nt"
docker start "$C" > /dev/null
if wait_listening; then
  if docker exec "$C" grep -q '^bob:' /etc/passwd; then fail "bob's account survived a removal while down"; else pass "removed while down: bob's account gone after the restart"; fi
  if docker exec "$C" pdbedit -L 2> /dev/null | grep -q '^bob:'; then fail "bob still in passdb after the restart"; else pass "removed while down: bob not in passdb"; fi
  refused "bob's old password after a removal while down" smb-cli-in Home bob "$PW_BOB" -c ls
  EXTRA=$(docker exec "$C" awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' /etc/passwd | sort | tr '\n' ' ')
  if [ "$EXTRA" = "carol dave " ]; then pass "a restart re-adds no default account (carol, dave only)"; else fail "accounts after restart: $EXTRA"; fi
  if docker exec "$C" test -e /.initialized; then fail "/.initialized after a restart"; else pass "no /.initialized after a restart"; fi
else
  fail "no smbd after the restart"
fi
nt bob "$PW_BOB"   # back for the tamper checks

# ── tamper: the image's own knobs do nothing ─────────────────
boot "" "    environment:
      ACCOUNT_eve: $PW_EVE
      UID_eve: \"20050\"
      SAMBA_GLOBAL_CONFIG_server_SPACE_min_SPACE_protocol: NT1
      SAMBA_GLOBAL_CONFIG_map_SPACE_to_SPACE_guest: Bad User
      SAMBA_VOLUME_CONFIG_open: \"[open]; path = /shares/1; guest ok = yes; read only = no\""
if wait_listening; then
  client smb-cli-in "$IN_IP"
  if docker exec "$C" grep -q '^eve:' /etc/passwd || docker exec "$C" pdbedit -L 2> /dev/null | grep -q '^eve:'; then
    fail "ACCOUNT_eve created an account"
  else
    pass "ACCOUNT_eve injected: no eve account, no passdb entry"
  fi
  refused "eve with her injected password" smb-cli-in Home eve "$PW_EVE" -c ls
  refused "SMB2 with SAMBA_GLOBAL_CONFIG server min protocol=NT1 injected" smb-cli-in Home bob "$PW_BOB" -m SMB2 -c ls
  refused "the injected [open] share as guest" smb-cli-in open guest "" -N -c ls
  if docker exec "$C" grep -qi '^\[open\]' /etc/samba/smb.conf; then fail "the injected [open] share is in smb.conf"; else pass "no injected share in smb.conf"; fi
  works "SMB3 still works for bob" smb-cli-in Home bob "$PW_BOB" -c ls
else
  fail "no smbd with the image's knobs set"
fi

# exited_with <code>: the container stopped with that exit code at least
# once (restart: unless-stopped then loops), and 445 never listened.
exited_with() {
  local _ heard='' seen=''
  for _ in $(seq 1 20); do
    if listening; then heard=1; fi
    [ "$(docker inspect -f '{{.State.ExitCode}}' "$C" 2> /dev/null)" = "$1" ] && seen=1
    sleep 1
  done
  STATE=$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}}' "$C" 2> /dev/null || echo missing)
  [ -z "$heard" ] && [ -n "$seen" ]
}

# ── tamper: a read-only smb.conf the script can't own → exit 4 ──
printf '[global]\n   server min protocol = NT1\n   map to guest = bad user\n[open]\n   path = /shares\n   guest ok = yes\n' > "$WORK/weak.conf"
chmod 644 "$WORK/weak.conf"
boot "      - {type: bind, source: $WORK/weak.conf, target: /etc/samba/smb.conf, read_only: true}"
if exited_with 4; then pass "read-only weakened smb.conf: exit 4, nothing listens on 445 ($STATE)"; else fail "weakened smb.conf: $STATE"; fi
if logs_have "can't replace /etc/samba/smb.conf"; then pass "portcullis-sync refuses to serve a config it can't own"; else fail "no refusal in the log: $(docker logs --tail 5 "$C" 2>&1)"; fi

# ── empty Local networks: refused to start → exit 3 ──────────
PORTCULLIS_LOCAL_NETWORKS='' boot
if exited_with 3 && logs_have 'Local networks is empty; file sharing is off'; then
  pass "empty Local networks: exit 3, nothing listens ($STATE)"
else
  fail "empty Local networks: $STATE"
fi
