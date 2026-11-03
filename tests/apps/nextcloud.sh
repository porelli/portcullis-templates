#!/usr/bin/env bash
# Test: Nextcloud (native OIDC via user_oidc, no password login)
# Static checks of compose, manifest and the scripts, then a real start:
# install, user_oidc, local accounts disabled, password login refused on
# every path spelling through Traefik.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="nextcloud"
section "Nextcloud"

APP_ID=nextcloud

COMPOSE=$(_find_compose "$APP_ID") || true
if [ -n "$COMPOSE" ]; then
  pass "compose.yml found: $COMPOSE"
else
  fail "compose.yml not found for $APP_ID"
  exit 1
fi
DIR="$(dirname "$COMPOSE")"
MANIFEST="$DIR/manifest.yaml"
SETUP="$DIR/setup.sh"
CRON="$DIR/cron.sh"

# Traefik routing enabled
if grep -q 'traefik.enable.*true' "$COMPOSE"; then
  pass "Traefik routing enabled"
else
  fail "Traefik routing not configured"
fi

# Native OIDC: one host-wide router without forward-auth (sync clients,
# WebDAV, share links). No path-scoped router: nothing relies on Traefik's
# path matching (case, repeated slashes, /index.php differ from Nextcloud's).
if grep -E '^[[:space:]]*traefik\.http\.routers\.nextcloud\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker'; then
  fail "host-wide router uses forward-auth (breaks clients behind native OIDC)"
else
  pass "host-wide router has no forward-auth"
fi
if grep -E '^[[:space:]]*traefik\.http\.routers\.[^.]+\.rule:' "$COMPOSE" | grep -q 'Path'; then
  fail "a router uses path matchers (no password form may depend on them)"
else
  pass "no path-scoped routers"
fi

# Keycloak client with the user_oidc callback
if grep -q 'method: native-oidc' "$MANIFEST" && grep -q '{{HOST_NEXTCLOUD}}/apps/user_oidc/code' "$MANIFEST"; then
  pass "manifest: native-oidc with the user_oidc redirect URI"
else
  fail "manifest must be native-oidc with https://{{HOST_NEXTCLOUD}}/apps/user_oidc/code"
fi

# X-Forwarded-For trusted from Traefik only
assert_traefik_only_trust "$COMPOSE" TRUSTED_PROXIES

# Identity = LLDAP username, never email; no linking to local accounts
for want in '--unique-uid=0' '--mapping-uid=preferred_username' \
    'soft_auto_provision --type=boolean --value=false' \
    '--group-restrict-login-to-whitelist=1' '--group-provisioning=1' \
    'PORTCULLIS_ACCESS_GROUP|$PORTCULLIS_ADMIN_GROUP' \
    'allow_multiple_user_backends --type=string --value=0' \
    'token_auth_enforced --type=boolean --value=true' \
    'hide_login_form --type=boolean --value=true' \
    '--clientsecret-env=NEXTCLOUD_OIDC_SECRET' \
    '"Database"' 'occ user:disable'; do
  if grep -qF -- "$want" "$SETUP"; then
    pass "setup.sh: $want"
  else
    fail "setup.sh lacks $want"
  fi
done

# Hostname re-applied at every start from the instance variable
for key in trusted_domains overwrite.cli.url overwritehost overwriteprotocol; do
  if grep -Eq "config:system:set $key " "$SETUP"; then
    pass "setup.sh re-applies $key"
  else
    fail "setup.sh does not re-apply $key"
  fi
done
if grep -q 'before-starting' "$COMPOSE" && grep -q 'PORTCULLIS_HOST_NEXTCLOUD: ${PORTCULLIS_HOST_NEXTCLOUD:-' "$COMPOSE"; then
  pass "setup.sh runs as a before-starting hook with the instance hostname"
else
  fail "setup.sh is not installed as a before-starting hook / hostname not passed"
fi

# user_oidc pinned by version + sha256
if grep -Eq '^UO_VERSION=[0-9]+\.[0-9]+\.[0-9]+$' "$SETUP" && grep -Eq '^UO_SHA256=[0-9a-f]{64}$' "$SETUP" \
    && grep -q 'sha256sum -c' "$SETUP"; then
  pass "user_oidc pinned (version + sha256 checked)"
else
  fail "user_oidc must be pinned by version and sha256"
fi

# The OIDC client secret never appears on a command line
if grep -q -- '--clientsecret=' "$SETUP"; then
  fail "setup.sh passes the client secret in argv"
else
  pass "client secret passed by environment only"
fi
assert_compose_setting "$COMPOSE" NEXTCLOUD_ADMIN_USER nc-breakglass

# Admin group mapping only touches SSO accounts
if grep -q 'group:adduser admin' "$CRON" && grep -q '"backend":"user_oidc"' "$CRON" && grep -q 'disable_local_accounts' "$CRON"; then
  pass "cron.sh maps the admin group to Nextcloud admins (SSO accounts only) and disables local accounts"
else
  fail "cron.sh admin mapping missing"
fi

# Fail closed: setup.sh stops (Apache never starts) when a local account
# stays enabled or occ fails. Run its local-accounts block with a stub occ.
if command -v php >/dev/null 2>&1; then
  BLOCK=$(sed -n '/^# >>> local-accounts/,/^# <<< local-accounts/p' "$SETUP")
  run_block() {  # $1 = what user:disable does: ok | noop | fail; $2 = what user:list does: ok | fail
    STATE=$(mktemp)
    printf 'nc-breakglass\n' > "$STATE"
    sh -c '
      STATE=$1 DISABLE=$2 LIST=$3
      occ() {
        case "$1" in
          user:list)
            [ "$LIST" = ok ] || return 1
            printf "{"; sep=""
            for u in nc-breakglass other; do
              if grep -qx "$u" "$STATE"; then en=true; else en=false; fi
              printf "%s\"%s\":{\"backend\":\"Database\",\"enabled\":%s}" "$sep" "$u" "$en"; sep=,
            done
            printf ",\"sso\":{\"backend\":\"user_oidc\",\"enabled\":true}}" ;;
          user:disable)
            case "$DISABLE" in
              ok) grep -vx "$2" "$STATE" > "$STATE.n" || true; mv "$STATE.n" "$STATE" ;;
              noop) : ;;
              *) return 1 ;;
            esac ;;
        esac
      }
      eval "$4"
    ' sh "$STATE" "$1" "$2" "$BLOCK" >/dev/null 2>&1
    rc=$?
    rm -f "$STATE" "$STATE.n"
    return $rc
  }
  if run_block ok ok; then pass "local accounts disabled: setup.sh continues"; else fail "setup.sh stops although every local account was disabled"; fi
  if run_block noop ok; then fail "setup.sh continues while a local account stays enabled"; else pass "a local account still enabled: setup.sh exits non-zero (no Apache)"; fi
  if run_block fail ok; then fail "setup.sh continues after occ user:disable failed"; else pass "occ user:disable failure: setup.sh exits non-zero"; fi
  if run_block ok fail; then fail "setup.sh continues when the accounts can't be listed"; else pass "occ user:list failure: setup.sh exits non-zero"; fi
else
  info "php not installed: setup.sh local-accounts test skipped"
fi

# The Hub's apply-settings hook (manifest hooks[]): mounted from the
# template, run as www-data with an argv (no shell), on start and saves.
APPLY="$DIR/apply-settings.php"
if grep -qF -- '- ./templates/nextcloud/apply-settings.php:/portcullis/apply-settings.php:ro' "$COMPOSE" \
    && [ "$(yq -r '.hooks[] | select(.name == "apply-settings") | [.service, .user, (.command | join(" ")), (.when | join(","))] | join("|")' "$MANIFEST")" \
       = 'nextcloud|www-data|php /portcullis/apply-settings.php|start,settings_change' ]; then
  pass "apply-settings hook declared (www-data, php /portcullis/apply-settings.php, start + settings_change) and mounted"
else
  fail "apply-settings hook or its mount missing / changed"
fi
# Its logic against a stub occ (state in a JSON file): idempotent, applies
# both options, refuses bad input and fails on an occ failure.
if command -v php >/dev/null 2>&1; then
  if php -l "$APPLY" >/dev/null; then pass "apply-settings.php parses"; else fail "apply-settings.php has a syntax error"; fi
  STUB=$(mktemp -d)
  cat > "$STUB/occ" <<'PHP'
<?php
$st = getenv('STUB_DIR') . '/state.json';
$s = file_exists($st) ? json_decode(file_get_contents($st), true) : [];
$a = array_values(array_filter(array_slice($argv, 1), fn($x) => $x !== '--no-interaction' && $x !== '--no-ansi'));
$set = $a[0] === 'config:app:set' || $a[0] === 'config:system:set';
if ($set && getenv('STUB_FAIL')) { fwrite(STDERR, "stub failure\n"); exit(2); }
if ($set) { file_put_contents(getenv('STUB_DIR') . '/sets', $a[0] . "\n", FILE_APPEND); }
switch ($a[0]) {
  case 'status': echo json_encode(['installed' => true, 'maintenance' => false, 'needsDbUpgrade' => false]), "\n"; break;
  case 'config:app:get': if (!isset($s["a.$a[2]"])) exit(1); echo $s["a.$a[2]"], "\n"; break;
  case 'config:system:get': if (!isset($s["s.$a[1]"])) exit(1); echo $s["s.$a[1]"], "\n"; break;
  case 'config:app:set': $s["a.$a[2]"] = substr($a[3], 8); break;
  case 'config:system:set': $s["s.$a[1]"] = substr($a[2], 8); break;
  default: exit(3);
}
file_put_contents($st, json_encode($s));
PHP
  sed "s|^const OCC = '/var/www/html/occ';|const OCC = '$STUB/occ';|" "$APPLY" > "$STUB/apply.php"
  hook() { STUB_DIR="$STUB" php "$STUB/apply.php" <<< "$1" >/dev/null 2>&1; }
  IN='{"trigger":"settings_change","version":1,"instance":"nextcloud","values":{"default_quota":7,"trash_retention":12},"people":{},"groups":{},"entries":{},"secrets":{}}'
  if hook "$IN" && [ "$(jq -r '.["a.default_quota"] + "|" + .["s.trashbin_retention_obligation"]' "$STUB/state.json")" = '7 GB|auto, 12' ]; then
    pass "stub occ: default_quota 7 GiB -> \"7 GB\", trash 12 days -> \"auto, 12\""
  else
    fail "stub occ: values not applied"
  fi
  : > "$STUB/sets"
  if hook "$IN" && [ ! -s "$STUB/sets" ]; then pass "stub occ: second run sets nothing (idempotent)"; else fail "stub occ: second run not idempotent"; fi
  if hook '{"version":1,"values":{"default_quota":"none"}}' && [ "$(jq -r '.["a.default_quota"]' "$STUB/state.json")" = none ]; then
    pass "stub occ: unlimited -> none"
  else
    fail "stub occ: unlimited not applied as none"
  fi
  for bad in 'not json' '{"version":2,"values":{}}' '{"version":1,"values":{"default_quota":1.5}}' '{"version":1,"values":{"trash_retention":0}}'; do
    if hook "$bad"; then fail "stub occ: accepted bad input $bad"; else pass "stub occ: bad input refused ($bad)"; fi
  done
  if STUB_FAIL=1 hook '{"version":1,"values":{"default_quota":9}}'; then fail "stub occ: an occ failure exits 0"; else pass "stub occ: an occ failure exits non-zero"; fi
  rm -rf "$STUB"
else
  info "php not installed: apply-settings.php stub test skipped"
fi

# Shell syntax of the support scripts
for f in "$SETUP" "$CRON"; do
  if sh -n "$f"; then pass "$(basename "$f") parses"; else fail "$(basename "$f") has a syntax error"; fi
done

# Service port matches Traefik label
if grep -q 'loadbalancer.server.port.*80' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 80"
else
  fail "Traefik loadbalancer port mismatch"
fi

# Public exceptions (auth.public_access; the Hub generates the router).
if [ -z "$(public_routed_prefixes "$MANIFEST" listed)" ]; then
  pass "listed mode without listed shares opens nothing"
else
  fail "listed mode without listed shares opens paths"
fi
TOK=AbCdEfGh2345678
ROUTED=$(public_routed_prefixes "$MANIFEST" listed "$TOK")
if echo "$ROUTED" | grep -qx "/s/$TOK" && echo "$ROUTED" | grep -qx "/public.php/dav/files/$TOK" && ! echo "$ROUTED" | grep -qx '/s'; then
  pass "listed share expands /s/{token} and public WebDAV per token only"
else
  fail "listed share expansion wrong: $ROUTED"
fi
if echo "$ROUTED" | grep -q '^/apps/text'; then
  fail "share-wide /apps/text opened in listed mode"
else
  pass "share-wide /apps/text only in mode all"
fi
if public_routed_prefixes "$MANIFEST" all | grep -qxE '/index\.php|/ocs(/.*)?|/remote\.php(/.*)?|/apps|/core|/public\.php|/login'; then
  fail "mode all opens a broad Nextcloud prefix"
else
  pass "mode all stays off /index.php, /ocs, /remote.php, /apps, /core, /login"
fi
# Supporting paths are static files only (except the one justified exact
# route), and logins never ride the public router.
if echo "$ROUTED" | grep -qx '[~]/apps/theming' && echo "$ROUTED" | grep -qx '=/core/mimeicon'; then
  pass "supporting paths are static-only / exact"
else
  fail "supporting paths not static-only: $ROUTED"
fi
for c in nc_username nc_token nc_session_id; do
  if _manifest_public_list "$MANIFEST" credential_cookies | grep -qx "$c"; then
    pass "login cookie $c excluded from the public router"
  else
    fail "login cookie $c not declared in credential_cookies"
  fi
done

# ── Runtime ──
compose_up "$APP_ID"
C=portcullis-nextcloud-1
occ() { docker exec -u www-data "$C" php occ "$@"; }
info "Waiting for the Nextcloud install and setup.sh (first start)..."
for _ in $(seq 1 120); do
  docker logs "$C" 2>&1 | grep -q 'portcullis: Nextcloud configured' && break
  docker logs "$C" 2>&1 | grep -q 'Failed at executing script' && break
  sleep 5
done
if docker logs "$C" 2>&1 | grep -q 'portcullis: Nextcloud configured'; then
  pass "setup.sh ran (install, user_oidc, provider)"
else
  fail "setup.sh did not finish"
  docker logs "$C" 2>&1 | tail -40 || true
fi
if docker logs "$C" 2>&1 | grep -q "${NEXTCLOUD_OIDC_SECRET:-x-never-x}"; then
  fail "the OIDC client secret appears in the container log"
else
  pass "the OIDC client secret is not logged"
fi

if occ user:info nc-breakglass --output=json 2>/dev/null | grep -q '"enabled":false'; then
  pass "local admin nc-breakglass is disabled"
else
  fail "local admin nc-breakglass is not disabled"
fi
for kv in "hide_login_form:true" "token_auth_enforced:true" "overwritehost:$PORTCULLIS_HOST_NEXTCLOUD" \
    "overwrite.cli.url:https://$PORTCULLIS_HOST_NEXTCLOUD" "trusted_domains:$PORTCULLIS_HOST_NEXTCLOUD"; do
  key=${kv%%:*}; want=${kv#*:}
  got=$(occ config:system:get "$key" 2>/dev/null | head -1 || true)
  if [ "$got" = "$want" ]; then pass "config $key = $want"; else fail "config $key = '$got', expected '$want'"; fi
done
PROVIDER=$(occ user_oidc:provider Portcullis --output=json 2>/dev/null || true)
if echo "$PROVIDER" | grep -q 'preferred_username' && echo "$PROVIDER" | grep -q "\"clientId\":\"${PORTCULLIS_OIDC_CLIENT_ID}\""; then
  pass "user_oidc provider Portcullis: client ${PORTCULLIS_OIDC_CLIENT_ID}, uid preferred_username"
else
  fail "user_oidc provider not as expected: $PROVIDER"
fi

# A local account created in the Users page is disabled within a minute
docker exec -u www-data -e OC_PASS='Ci-Local-Pass-1234567' "$C" php occ user:add --password-from-env ci-local >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  occ user:info ci-local --output=json 2>/dev/null | grep -q '"enabled":false' && break
  sleep 5
done
if occ user:info ci-local --output=json 2>/dev/null | grep -q '"enabled":false'; then
  pass "new local account disabled by nextcloud-cron"
else
  fail "new local account still enabled after 150s"
fi

section "apply-settings hook in the running container"
# What the Hub does (docker exec as www-data, HookInput on stdin).
apply() { docker exec -i -u www-data "$C" php /portcullis/apply-settings.php; }
IN='{"trigger":"settings_change","version":1,"instance":"nextcloud","values":{"default_quota":7,"trash_retention":12},"people":{},"groups":{},"entries":{},"secrets":{}}'
if out=$(apply <<< "$IN" 2>&1); then
  pass "apply-settings exited 0"
else
  fail "apply-settings failed: $out"
fi
got=$(occ config:app:get files default_quota 2>/dev/null || true)
if [ "$got" = "7 GB" ]; then pass "occ config:app:get files default_quota = 7 GB"; else fail "files default_quota = '$got', expected '7 GB'"; fi
got=$(occ config:system:get trashbin_retention_obligation 2>/dev/null || true)
if [ "$got" = "auto, 12" ]; then pass "trashbin_retention_obligation = auto, 12"; else fail "trashbin_retention_obligation = '$got', expected 'auto, 12'"; fi
if out=$(apply <<< "$IN" 2>&1) && ! grep -q ' set to ' <<< "$out"; then
  pass "apply-settings again: nothing changed (idempotent)"
else
  fail "apply-settings second run: $out"
fi
if out=$(apply <<< '{"trigger":"settings_change","version":1,"values":{"default_quota":"none"}}' 2>&1) \
    && [ "$(occ config:app:get files default_quota 2>/dev/null || true)" = none ]; then
  pass "unlimited -> files default_quota none"
else
  fail "unlimited not applied: $out"
fi
if apply <<< '{"version":1,"values":{"default_quota":"7 GB; rm"}}' >/dev/null 2>&1; then
  fail "apply-settings accepted a malformed quota"
else
  pass "apply-settings refuses a malformed quota (non-zero)"
fi

section "Password login through Traefik"
HOST="$PORTCULLIS_HOST_NEXTCLOUD"
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /status.php)
  case "${out%% *}" in 000|404|502|503) sleep 2 ;; *) break ;; esac
done
out=$(via_traefik "$HOST" /login); loc=${out#* }
if echo "$loc" | grep -q '/apps/user_oidc/login/'; then
  pass "/login redirects to user_oidc ($loc)"
else
  fail "/login does not redirect to user_oidc: $out"
fi
JAR=$(mktemp)
for path in /login /LOGIN /login/ //login /index.php/login /index.php//login /index.php/LOGIN; do
  for who in "nc-breakglass:$NEXTCLOUD_ADMIN_PASSWORD" "ci-local:Ci-Local-Pass-1234567"; do
    : > "$JAR"
    tok=$(curl -sk -c "$JAR" -b "$JAR" --resolve "$HOST:443:127.0.0.1" "https://$HOST/csrftoken" 2>/dev/null \
      | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    curl -sk -o /dev/null -c "$JAR" -b "$JAR" --resolve "$HOST:443:127.0.0.1" -H "Origin: https://$HOST" \
      --data-urlencode "user=${who%%:*}" --data-urlencode "password=${who#*:}" --data-urlencode "requesttoken=$tok" \
      "https://$HOST$path" 2>/dev/null || true
    code=$(curl -sk -o /dev/null -w '%{http_code}' -b "$JAR" --resolve "$HOST:443:127.0.0.1" -H 'OCS-APIRequest: true' \
      "https://$HOST/ocs/v2.php/cloud/user?format=json" 2>/dev/null || echo 000)
    if [ "$code" = 401 ]; then
      pass "POST $path as ${who%%:*}: no session (OCS 401)"
    else
      fail "POST $path as ${who%%:*}: OCS answered $code (signed in?)"
    fi
  done
done
rm -f "$JAR"

compose_down "$APP_ID"
