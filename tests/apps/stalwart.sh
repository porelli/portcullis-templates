#!/usr/bin/env bash
# Test: Stalwart, the mail provider template (contract §3.5, §19). Static:
# the template is only ever started by the Hub's wiring (ports, the provider
# API network, the slot files, the certificate), which templates CI doesn't
# emulate; core's e2e-mail scenarios boot it wired. Never contacts port 25
# or any mail host.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
# shellcheck disable=SC2034 # read by tests/lib.sh
TEST_NAME="stalwart"
section "Stalwart (mail provider)"

APP_ID=stalwart
COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
DIR=$(dirname "$COMPOSE")
MANIFEST="$DIR/manifest.yaml"
PYTHON="${PYTHON:-python3}"
y() { yq -r "$1" "$COMPOSE"; }

# ── the validator and compose ─────────────────────────────────
if ! "$PYTHON" -c 'import sys; sys.path.insert(0, "tests"); import validate' >/dev/null 2>&1; then
  info "validator dependencies missing (tests/requirements.txt): validate.py runs in lint"
elif "$PYTHON" tests/validate.py "$APP_ID" >/tmp/stalwart-validate.log 2>&1; then
  pass "validate.py accepts the template (mail: block included)"
else
  fail "validate.py refuses the template: $(tail -5 /tmp/stalwart-validate.log)"
fi
if [ -f tests/compose-config.sh ] && docker compose version >/dev/null 2>&1; then
  if out=$(bash tests/compose-config.sh "$APP_ID" 2>&1); then pass "docker compose config: $out"; else fail "docker compose config: $out"; fi
elif [ "${CI:-}" = true ]; then
  fail "no docker compose in CI: compose-config can't run"
else
  info "no docker compose: compose-config runs elsewhere"
fi

# ── images ────────────────────────────────────────────────────
STALWART_IMAGE=$(y '.services.stalwart.image')
ADAPTER_IMAGE=$(y '.services.adapter.image')
if [[ "$STALWART_IMAGE" =~ ^docker\.io/stalwartlabs/stalwart:v[0-9.]+@sha256:[0-9a-f]{64}$ ]] \
    && [ "$(y '.services.bootstrap.image')" = "$STALWART_IMAGE" ] \
    && [ "$(y '.services.bootstrap.environment.MAILCTL_SERVER_IMAGE')" = "$STALWART_IMAGE" ]; then
  pass "Stalwart pinned, the same image (and MAILCTL_SERVER_IMAGE) in the bootstrap job: $STALWART_IMAGE"
else
  fail "the Stalwart image / the job's image / MAILCTL_SERVER_IMAGE differ or are unpinned"
fi
# Core's CI rewrites exactly this line shape to its locally built adapter (plan P2).
if [[ "$ADAPTER_IMAGE" =~ ^ghcr\.io/porelli/portcullis-mailctl:(main-[0-9a-f]{7}|[0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$ ]] \
    && [ "$(y '.services.adapter-bin.image')" = "$ADAPTER_IMAGE" ] && [ "$(y '.services.key-init.image')" = "$ADAPTER_IMAGE" ] \
    && [ "$(y '.services.admin-view.image')" = "$ADAPTER_IMAGE" ] \
    && [ "$(grep -c "image: ghcr.io/porelli/portcullis-mailctl:" "$COMPOSE")" = 4 ]; then
  pass "adapter pinned, adapter-bin, key-init and admin-view run the same mailctl image: $ADAPTER_IMAGE"
else
  fail "adapter image must be ghcr.io/porelli/portcullis-mailctl:main-<sha7> or :X.Y.Z @sha256:<digest> (never a dev- tag), the same in adapter-bin, key-init and admin-view"
fi

# ── hardening, every service ──────────────────────────────────
SERVICES=$(y '.services | keys | .[]' | sort | tr '\n' ' ')
[ "$SERVICES" = "adapter adapter-bin admin-view bootstrap key-init resolver stalwart " ] && pass "services: $SERVICES" || fail "services: $SERVICES"
for s in $SERVICES; do
  bad=""
  [ "$(y ".services.\"$s\".cap_drop | join(\",\")")" = ALL ] || bad+=" cap_drop"
  caps=$(y ".services.\"$s\".cap_add // [] | join(\",\")")
  case "$s:$caps" in stalwart:NET_BIND_SERVICE|bootstrap:NET_BIND_SERVICE|adapter:|adapter-bin:|admin-view:|key-init:|resolver:) ;; *) bad+=" cap_add=$caps" ;; esac
  [ "$(y ".services.\"$s\".read_only")" = true ] || bad+=" read_only"
  [ "$(y ".services.\"$s\".security_opt | join(\",\")")" = no-new-privileges:true ] || bad+=" security_opt"
  [[ "$(y ".services.\"$s\".pids_limit")" =~ ^[1-9][0-9]*$ ]] || bad+=" pids_limit"
  [ "$(y ".services.\"$s\" | has(\"ports\")")" = false ] || bad+=" ports"
  [ "$(y ".services.\"$s\".labels // {} | length")" = 0 ] || bad+=" labels"
  u=$(y ".services.\"$s\".user // \"\"")
  { [ -n "$u" ] && { [[ "$u" != 0* ]] || [ "$s:$u" = "key-init:0:2010" ]; }; } || bad+=" user"
  [ "$(y ".services.\"$s\".depends_on // {} | to_entries | map(select(.value.restart == true)) | length")" = 0 ] || bad+=" depends_on.restart"
  if [ -z "$bad" ]; then pass "$s: cap_drop ALL ($caps), read-only, no-new-privileges, pids_limit, no ports / labels, non-root (key-init: root without caps, T17-e)"; else fail "$s:$bad"; fi
done
if ! grep -qE '(^|[[:space:]])&[A-Za-z]|\*[A-Za-z]|<<:' "$COMPOSE"; then pass "no YAML anchors, aliases or merge keys"; else fail "anchors / aliases in compose.yml"; fi

# ── users, the key volume (Ruling T17-a) ──────────────────────
[ "$(y '.services.bootstrap.user')" = "2000:2010" ] && [ "$(y '.services.stalwart.user')" = "2000:2000" ] \
  && [ "$(y '.services.adapter.user')" = "10010:10010" ] && [ "$(y '.services.adapter.group_add | join(",")')" = 2010 ] \
  && [ "$(y '.services.bootstrap.group_add | join(",")')" = 2011 ] && [ "$(y '.services.key-init.group_add | join(",")')" = 2011 ] \
  && [ "$(y '.services.admin-view.user')" = "10010:10010" ] && [ "$(y '.services.admin-view.group_add | join(",")')" = 2011 ] \
  && pass "bootstrap 2000:2010 (mailkey) + mailview, stalwart 2000, adapter 10010 + mailkey, admin-view 10010 + mailview" || fail "users / group_add"
mounters=$(yq -r '.services | to_entries[] | .key as $s | .value.volumes[]? | select(test("^adapter_key:")) | $s + "=" + .' "$COMPOSE" | sort | tr '\n' ' ')
if [ "$mounters" = "adapter=adapter_key:/run/portcullis/stalwart-key:ro bootstrap=adapter_key:/run/portcullis/stalwart-key key-init=adapter_key:/run/portcullis/key-init " ]; then
  pass "the key volume: key-init prepares it, the job writes, the adapter reads, nobody else; never at an image path (T17-e)"
else
  fail "adapter_key mounts: $mounters"
fi
# The viewer key volume (contract §19.13): the admin view's password only;
# the job writes it, admin-view reads it, the adapter never mounts it.
mounters=$(yq -r '.services | to_entries[] | .key as $s | .value.volumes[]? | select(test("^viewer_key:")) | $s + "=" + .' "$COMPOSE" | sort | tr '\n' ' ')
if [ "$mounters" = "admin-view=viewer_key:/run/portcullis/viewer-key:ro bootstrap=viewer_key:/run/portcullis/viewer-key key-init=viewer_key:/run/portcullis/viewer-init " ] \
    && [ "$(y '.services.bootstrap.environment.MAILCTL_VIEWER_SECRET_FILE')" = /run/portcullis/viewer-key/viewer-password ] \
    && [ "$(y '.services.admin-view.environment.MAILCTL_VIEWER_SECRET_FILE')" = /run/portcullis/viewer-key/viewer-password ] \
    && [ "$(y '.services.bootstrap.environment.MAILCTL_ADMINVIEW_IP')" = 172.31.255.5 ] \
    && [ "$(y '.services.admin-view.environment.MAILCTL_ADMINVIEW_UPSTREAM')" = https://172.31.255.2:8443 ] \
    && [ "$(y '.services.admin-view.volumes | join(" ")')" = "viewer_key:/run/portcullis/viewer-key:ro admin_view_data:/data" ] \
    && [ "$(y '.services.admin-view.environment.MAILCTL_ADMINVIEW_USED_FILE')" = /data/used-tickets.json ] \
    && [ "$(y '.services.admin-view.command | join(" ")')" = admin-view ]; then
  pass "the viewer key volume: key-init prepares it, the job writes, admin-view (its only mount) reads; the adapter never (contract §19.13)"
else
  fail "viewer_key mounts / admin-view: $mounters"
fi
mounters=$(yq -r '.services | to_entries[] | .key as $s | .value.volumes[]? | select(test("^data:")) | $s + "=" + .' "$COMPOSE" | sort | tr '\n' ' ')
[ "$mounters" = "bootstrap=data:/var/lib/stalwart stalwart=data:/var/lib/stalwart " ] \
  && pass "the store: bootstrap and stalwart only" || fail "data mounts: $mounters"
mounters=$(yq -r '.services | to_entries[] | .key as $s | .value.volumes[]? | select(test("^job_data:")) | $s + "=" + .' "$COMPOSE" | sort | tr '\n' ' ')
[ "$(y '.services.bootstrap.environment.MAILCTL_DATA')" = /etc/stalwart ] && [ "$mounters" = "bootstrap=job_data:/etc/stalwart " ] \
  && [ "$(y '.services.adapter.environment.MAILCTL_DATA')" = /data ] \
  && pass "MAILCTL_DATA: the job's own job_data, adapter_data in the adapter (the key volume holds the key alone)" || fail "MAILCTL_DATA / job_data: $mounters"
[ "$(y '.services.bootstrap.environment.MAILCTL_API_KEY_FILE')" = /run/portcullis/stalwart-key/api-key ] \
  && [ "$(y '.services.adapter.environment.MAILCTL_API_KEY_FILE')" = /run/portcullis/stalwart-key/api-key ] \
  && [ "$(y '.services.bootstrap.environment.MAILCTL_STORE_DIR')" = /var/lib/stalwart ] \
  && pass "MAILCTL_API_KEY_FILE in the key volume (job rw, adapter ro); MAILCTL_STORE_DIR the store" || fail "MAILCTL_API_KEY_FILE / MAILCTL_STORE_DIR"
tmpfs_job=$(y '.services.bootstrap.tmpfs | map(select(test("^/run/portcullis/bootstrap"))) | length')
tmpfs_all=$(yq -r '[.services[].tmpfs[]? | select(test("^/run/portcullis/bootstrap"))] | length' "$COMPOSE")
[ "$tmpfs_job" = 1 ] && [ "$tmpfs_all" = 1 ] && [ "$(y '.services.bootstrap.environment.MAILCTL_JOB_SESSION_FILE')" = /run/portcullis/bootstrap/session ] \
  && pass "the session tmpfs is the job's only" || fail "the bootstrap session tmpfs"
[ "$(y '.services.bootstrap.environment.MAILCTL_JOB_LOCAL_URL')" = http://127.0.0.1:8080 ] \
  && pass "the job dials its own server over loopback (Ruling T17-b)" || fail "MAILCTL_JOB_LOCAL_URL"

# ── networks (pins outside ip_range) ──────────────────────────
[ "$(y '.networks.internal.internal')" = true ] && [ "$(y '.networks.internal.ipam.config[0].subnet')" = 172.31.255.0/28 ] \
  && [ "$(y '.networks.internal.ipam.config[0].ip_range')" = 172.31.255.8/29 ] \
  && pass "internal: internal, 172.31.255.0/28, dynamic range .8/29" || fail "the internal network"
pins="$(y '.services.stalwart.networks.internal.ipv4_address') $(y '.services.adapter.networks.internal.ipv4_address') $(y '.services.resolver.networks.internal.ipv4_address') $(y '.services.admin-view.networks.internal.ipv4_address')"
[ "$pins" = "172.31.255.2 172.31.255.3 172.31.255.4 172.31.255.5" ] && pass "pinned: stalwart .2, adapter .3, resolver .4, admin-view .5 (outside the range)" || fail "pins: $pins"
[ "$(y '.services.bootstrap.networks | join(",")')" = internal ] && [ "$(y '.services.adapter.networks | keys | join(",")')" = internal ] \
  && [ "$(y '.services.admin-view.networks | keys | join(",")')" = internal ] \
  && [ "$(y '.services.adapter-bin.network_mode')" = none ] && [ "$(y '.services.key-init.network_mode')" = none ] \
  && pass "egress only for stalwart and the resolver" || fail "networks of bootstrap / adapter / adapter-bin"
grep -q 'access-control: 172.31.255.0/28 allow' "$DIR/unbound/unbound.conf" && pass "unbound allows the internal network" || fail "unbound access-control"

# ── the gate wiring ───────────────────────────────────────────
[ "$(y '.services.stalwart.entrypoint | join(" ")')" = "/bin/sh /portcullis/gate/entrypoint.sh" ] \
  && [ "$(y '.services.stalwart.command | join(" ")')" = "/usr/local/bin/stalwart --config /portcullis/config/config.json" ] \
  && pass "stalwart starts through the gate wrapper" || fail "stalwart entrypoint / command"
grep -q '^/bin/sh /portcullis/gate/entrypoint.sh --check$' "$DIR/gate/bootstrap.sh" \
  && pass "the job checks the slot gate first" || fail "bootstrap.sh: no gate check"
grep -q '/bin/sh /portcullis/gate/entrypoint.sh /usr/local/bin/stalwart --config /portcullis/config/config.json' "$DIR/gate/bootstrap.sh" \
  && pass "the job's server child starts through the same wrapper" || fail "bootstrap.sh server argv"
[ "$(yq -r '.mail.gated | join(",")' "$MANIFEST")" = stalwart,adapter,bootstrap ] && [ "$(yq -r '.mail.tls | join(",")' "$MANIFEST")" = stalwart,adapter,bootstrap ] && [ "$(yq -r '.jobs | join(",")' "$MANIFEST")" = adapter-bin,key-init,bootstrap ] \
  && pass "gated and tls: stalwart, adapter, bootstrap (its base plan reads the certificate and the metrics secret); jobs: adapter-bin, key-init, bootstrap" || fail "manifest gated / jobs"
if bash tests/mail/test_gate_entrypoint.sh >/tmp/stalwart-gate.log 2>&1; then
  pass "gate wrapper: $(tail -1 /tmp/stalwart-gate.log)"
else
  fail "gate wrapper: $(grep -E '^FAIL' /tmp/stalwart-gate.log | head -5)"
fi
