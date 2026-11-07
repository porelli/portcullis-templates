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

# ── AI support (contracts §3.2, §15.5): static ──────────────
HOOK_PHP="$DIR/portcullis/mcp-token.php"
MCP_IMAGE=$(sed -n 's/^    image: \(ghcr\.io\/cbcoutinho\/nextcloud-mcp-server:[^[:space:]]*\)$/\1/p' "$COMPOSE")
if [[ "$MCP_IMAGE" =~ ^ghcr\.io/cbcoutinho/nextcloud-mcp-server:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]]; then
  pass "nextcloud-mcp pinned tag@digest ($MCP_IMAGE)"
else
  fail "nextcloud-mcp must be the published image pinned tag@sha256 (got '$MCP_IMAGE')"
fi
MCP_SVC=$(awk '/^  nextcloud-mcp:/{f=1; next} f && /^  [a-z]/{f=0} f' "$COMPOSE")
if grep -q 'MCP_DEPLOYMENT_MODE: multi_user_basic$' <<<"$MCP_SVC" && grep -q 'NEXTCLOUD_HOST: http://nextcloud-internal$' <<<"$MCP_SVC" \
  && ! grep -qE 'NEXTCLOUD_USERNAME|NEXTCLOUD_PASSWORD|OIDC|TOKEN_ENCRYPTION|traefik\.|ports:|portcullis-proxy' <<<"$MCP_SVC"; then
  pass "nextcloud-mcp: multi-user Basic pass-through to nextcloud-internal, no credential of its own, no labels / ports / proxy network"
else
  fail "nextcloud-mcp: needs MCP_DEPLOYMENT_MODE multi_user_basic, NEXTCLOUD_HOST nextcloud-internal and no credential, labels, ports or portcullis-proxy"
fi
if [ "$(yq -r '[.hooks[] | select(.name == "mcp-mint" or .name == "mcp-revoke") | [.service, .user, (.command | join(" ")), (.when | join(","))] | join("|")] | join(";")' "$MANIFEST")" \
     = 'nextcloud|www-data|php /portcullis/mcp-token.php mint|ai;nextcloud|www-data|php /portcullis/mcp-token.php revoke|ai' ] \
  && grep -qF -- '- ./templates/nextcloud/portcullis/mcp-token.php:/portcullis/mcp-token.php:ro' "$COMPOSE"; then
  pass "mint/revoke hooks run in the nextcloud service as www-data (script mounted read-only)"
else
  fail "mcp-mint / mcp-revoke must run in the nextcloud service as www-data with mcp-token.php mounted read-only"
fi
if command -v php >/dev/null 2>&1; then
  if php -l "$HOOK_PHP" >/dev/null; then pass "mcp-token.php parses"; else fail "mcp-token.php has a syntax error"; fi
fi
# occ gets argv lists only (proc_open, no shell) and never a password option.
if grep -q 'proc_open(\$cmd' "$HOOK_PHP" && ! grep -qE 'shell_exec|passthru|system\(|exec\(|popen|password-from-env|OC_PASS|NC_PASS' "$HOOK_PHP"; then
  pass "mcp-token.php runs occ without a shell and passes no password"
else
  fail "mcp-token.php must run occ through proc_open argv lists only"
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

section "AI support: hooks and the nextcloud-mcp companion"
TMP=$(mktemp -d)
NC_IP=$(app_container_ip "$APP_ID" nextcloud)
hook() { docker exec -i -u www-data "$C" php /portcullis/mcp-token.php "$1"; }
if docker exec "$C" php -m | grep -qx pcntl; then
  pass "the nextcloud image has pcntl (the hook cleans up an interrupted mint on TERM / INT / HUP)"
else
  fail "the nextcloud image lacks pcntl: mcp-token.php refuses to run"
fi
rand12() { openssl rand -hex 6; }
mint_in() { # user [scopes-json]
  printf '{"action":"mint","user":"%s","instance":"nextcloud","companion":"nextcloud","name":"portcullis-ai-%s","mode":"read_write","scopes":%s}' "$1" "$(rand12)" "${2:-[]}"
}
# basic_cfg USER PASSWORD: a curl config (stdin) with the credential, never argv.
basic_cfg() { printf 'user = "%s:%s"\n' "$1" "$2"; }
# ocs_as USER CRED: HTTP code of /ocs/v2.php/cloud/user; body in $TMP/body.
ocs_as() {
  basic_cfg "$1" "$2" | curl --config - -s -o "$TMP/body" -w '%{http_code}' -H 'OCS-APIRequest: true' \
    "http://${NC_IP}/ocs/v2.php/cloud/user?format=json" || echo 000
}
dav_put() { # USER CRED NAME CONTENT
  printf '%s' "$4" > "$TMP/put"
  basic_cfg "$1" "$2" | curl --config - -s -o /dev/null -w '%{http_code}' -T "$TMP/put" \
    "http://${NC_IP}/remote.php/dav/files/$1/$3" || echo 000
}
ai_tokens() { # USER: number of portcullis-ai-* app passwords
  occ user:auth-tokens:list --output=json -- "$1" | jq '[.[] | select(.name | startswith("portcullis-ai-"))] | length'
}

# People as the template's OIDC login creates them (user_oidc backend,
# uid = preferred_username); no SSO in a shell test, so the rows go into
# user_oidc's table directly.
for u in alice bob; do
  docker exec -u www-data "$C" php -r '$db = new PDO("sqlite:/var/www/html/data/nextcloud.db");
    $st = $db->prepare("INSERT INTO oc_user_oidc (user_id, display_name) VALUES (?, ?)"); exit($st->execute([$argv[1], ucfirst($argv[1])]) ? 0 : 1);' "$u"
done
if [ "$(occ user:info --output=json alice | jq -r '.backend + "|" + .user_id')" = 'user_oidc|alice' ]; then
  pass "alice and bob are user_oidc accounts"
else
  fail "test people not created as user_oidc accounts"
fi

declare -A CRED ID
for u in alice bob; do
  if OUT=$(mint_in "$u" | hook mint) && CRED[$u]=$(jq -er '.credential' <<<"$OUT") && ID[$u]=$(jq -er '.id' <<<"$OUT") \
    && [ "$(jq -r 'keys | join(",")' <<<"$OUT")" = "credential,id" ] && [[ "${CRED[$u]}" =~ ^[A-Za-z0-9]{72}$ ]]; then
    pass "mint for $u -> {credential, id} (id ${ID[$u]})"
  else
    fail "mint for $u failed"; CRED[$u]=x; ID[$u]=0
  fi
done
NAME=$(occ user:auth-tokens:list --output=json -- alice | jq -r --arg id "${ID[alice]}" '.[] | select((.id | tostring) == $id) | .name')
[[ "$NAME" =~ ^portcullis-ai-[a-z0-9]{12}$ ]] && pass "the app password is named $NAME in Nextcloud" || fail "alice's app password ${ID[alice]} is named '$NAME'"
CODE=$(ocs_as alice "${CRED[alice]}")
if [ "$CODE" = 200 ] && [ "$(jq -r .ocs.data.id "$TMP/body")" = alice ]; then
  pass "the credential authorizes as alice (Basic alice:<app password>)"
else
  fail "the minted credential: OCS -> $CODE $(head -c 200 "$TMP/body")"
fi
CODE=$(ocs_as bob "${CRED[alice]}")
[ "$CODE" = 401 ] && pass "alice's app password with the username bob -> 401" || fail "alice's app password as bob: $CODE"
for u in alice bob; do
  CODE=$(dav_put "$u" "${CRED[$u]}" "$u-secret.txt" "private to $u")
  [ "$CODE" = 201 ] || [ "$CODE" = 204 ] || fail "uploading $u's file: HTTP $CODE"
done

set +e; mint_in nobody | hook mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" = 3 ] && pass "mint for a person without a Nextcloud account -> exit 3" || fail "mint for nobody: exit $RC, want 3"
set +e; mint_in '-help' | hook mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" = 3 ] && pass "mint for a name that can't be a uid -> exit 3" || fail "mint for '-help': exit $RC, want 3"
set +e; mint_in ALICE | hook mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" = 3 ] && pass "mint for another spelling of alice -> exit 3 (uid must match exactly)" || fail "mint for ALICE: exit $RC, want 3"
set +e; mint_in ci-local | hook mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" != 0 ] && [ "$RC" != 3 ] && pass "mint for a local (non-OIDC) account refused (exit $RC)" || fail "mint for ci-local: exit $RC"
set +e; mint_in alice '["files"]' | hook mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" != 0 ] && [ "$RC" != 3 ] && pass "mint with scopes refused (exit $RC)" || fail "mint with scopes: exit $RC"
set +e; printf '{"action":"mint","user":"alice"}' | hook mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" != 0 ] && [ "$RC" != 3 ] && pass "malformed mint input refused (exit $RC)" || fail "malformed mint input: exit $RC"
set +e; printf '{"action":"revoke","user":"nobody","ids":[]}' | hook revoke >/dev/null 2>&1; RC=$?; set -e
[ "$RC" = 0 ] && pass "revoke for a person without an account -> exit 0" || fail "revoke for nobody: exit $RC"
set +e; printf '{"action":"revoke","user":"alice","ids":[7]}' | hook revoke >/dev/null 2>&1; RC=$?; set -e
[ "$RC" != 0 ] && pass "revoke with a numeric (not string) id refused" || fail "revoke with ids [7] accepted"

# Fail closed, with a stand-in occ (a copy of the hook pointing at it):
#   fail-info:  user:info fails -> mint and revoke exit 1 (not 3, not "revoked")
#   fail-list:  the id lookup after add fails -> exit 1 and the new app
#               password is deleted again
docker exec -u www-data "$C" sh -ec '
  mkdir -p /tmp/stub
  sed "s|^const OCC = .*|const OCC = \"/tmp/stub/occ\";|" /portcullis/mcp-token.php > /tmp/stub/hook.php
  cat > /tmp/stub/occ <<"PHP"
<?php
$a = array_slice($argv, 1);
$mode = trim((string) @file_get_contents("/tmp/stub/mode"));
if ($mode === "fail-info" && in_array("user:info", $a, true)) { fwrite(STDERR, "simulated failure\n"); exit(2); }
if (in_array("user:auth-tokens:add", $a, true)) { touch("/tmp/stub/added"); }
if ($mode === "fail-list" && in_array("user:auth-tokens:list", $a, true) && file_exists("/tmp/stub/added")) {
  unlink("/tmp/stub/added"); fwrite(STDERR, "simulated failure\n"); exit(2);
}
chdir("/var/www/html");
$p = proc_open(array_merge([PHP_BINARY, "/var/www/html/occ"], $a), [0 => STDIN, 1 => STDOUT, 2 => STDERR], $pipes);
exit(proc_close($p));
PHP'
stub_hook() { docker exec -i -u www-data "$C" sh -c 'printf %s "$1" > /tmp/stub/mode; rm -f /tmp/stub/added; exec php /tmp/stub/hook.php "$2"' sh "$1" "$2"; }
set +e; printf '{"action":"revoke","user":"alice","ids":["%s"]}' "${ID[alice]}" | stub_hook fail-info revoke >/dev/null 2>&1; RC=$?; set -e
if [ "$RC" != 0 ] && [ "$(ocs_as alice "${CRED[alice]}")" = 200 ]; then
  pass "revoke while occ user:info fails -> exit $RC (not reported as revoked)"
else
  fail "revoke with a failing occ user:info: exit $RC, want non-zero"
fi
set +e; mint_in alice | stub_hook fail-info mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" != 0 ] && [ "$RC" != 3 ] && pass "mint while occ user:info fails -> exit $RC (not 3)" || fail "mint with a failing occ user:info: exit $RC"
BEFORE=$(ai_tokens alice)
set +e; mint_in alice | stub_hook fail-list mint > "$TMP/stub-out" 2>/dev/null; RC=$?; set -e
if [ "$RC" != 0 ] && [ "$RC" != 3 ] && [ ! -s "$TMP/stub-out" ] && [ "$(ai_tokens alice)" = "$BEFORE" ]; then
  pass "mint failing after occ created the app password -> exit $RC, nothing printed, the app password deleted again"
else
  fail "mint failing after add: exit $RC, $(ai_tokens alice) portcullis-ai-* tokens (before: $BEFORE)"
fi
docker exec -u www-data "$C" rm -rf /tmp/stub

# The companion (started with the template).
MCP_IP=$(app_container_ip "$APP_ID" nextcloud-mcp)
wait_for_url "http://${MCP_IP}:8000/health/live" 180 nextcloud-mcp || docker logs portcullis-nextcloud-mcp-1 2>&1 | tail -30
# mcp_init USER CRED VERSION: initializes a session; its id in $TMP/sid, the
# negotiated version printed. mcp USER CRED BODY: the JSON-RPC answer (SSE
# or JSON); HTTP code in $TMP/mcpcode. An empty USER sends no credential.
MCP_VERSION=2025-11-25
mcp_post() {
  printf '%s' "$3" > "$TMP/mcpreq"
  local sid=(); [ -s "$TMP/sid" ] && sid=(-H "Mcp-Session-Id: $(cat "$TMP/sid")")
  { [ -z "$1" ] || basic_cfg "$1" "$2"; } \
    | curl --config - -s -D "$TMP/mcphdr" -o "$TMP/mcpout" -w '%{http_code}' -X POST "http://${MCP_IP}:8000/mcp" \
      -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
      -H "MCP-Protocol-Version: $MCP_VERSION" ${sid[@]+"${sid[@]}"} --data-binary "@$TMP/mcpreq" > "$TMP/mcpcode" || echo 000 > "$TMP/mcpcode"
  if grep -q '^data: ' "$TMP/mcpout"; then sed -n 's/^data: //p' "$TMP/mcpout" | tail -1; else cat "$TMP/mcpout"; fi
}
mcp_init() {
  : > "$TMP/sid"
  local r
  r=$(mcp_post "$1" "$2" "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"$3\",\"capabilities\":{},\"clientInfo\":{\"name\":\"ci\",\"version\":\"1\"}}}")
  tr -d '\r' < "$TMP/mcphdr" | sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: //p' > "$TMP/sid"
  MCP_VERSION=$3
  mcp_post "$1" "$2" '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
  jq -r '.result.protocolVersion // empty' <<<"$r" 2>/dev/null || true
}
mcp() { mcp_post "$@"; }
for v in 2026-07-28 2025-11-25; do
  GOT=$(mcp_init alice "${CRED[alice]}" "$v")
  [ "$GOT" = "$v" ] && pass "nextcloud-mcp speaks MCP $v" || fail "initialize with $v -> '$GOT'"
done
LS='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nc_webdav_list_directory","arguments":{"path":"/"}}}'
mcp_init alice "${CRED[alice]}" 2025-11-25 >/dev/null
R=$(mcp alice "${CRED[alice]}" "$LS")
if grep -q 'alice-secret.txt' <<<"$R" && ! grep -q 'bob-secret.txt' <<<"$R"; then
  pass "nextcloud-mcp with alice's app password lists alice's files only (bob's absent)"
else
  fail "nextcloud-mcp list as alice: $(head -c 400 <<<"$R")"
fi
# The same session with bob's credential acts as bob (identity is the
# request's Authorization, never the session).
R=$(mcp bob "${CRED[bob]}" "$LS")
if grep -q 'bob-secret.txt' <<<"$R" && ! grep -q 'alice-secret.txt' <<<"$R"; then
  pass "the same session with bob's app password lists bob's files only"
else
  fail "nextcloud-mcp list as bob: $(head -c 400 <<<"$R")"
fi
mcp alice "${CRED[alice]}" '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' > "$TMP/tools.json"
R=$(mcp "" "" "$LS")
grep -q 'alice-secret\|bob-secret' <<<"$R" && fail "nextcloud-mcp without a credential returned files" || pass "nextcloud-mcp without a credential sees no file"
mcp alice "notTheAppPassword0000" "$LS" >/dev/null
[ "$(cat "$TMP/mcpcode")" = 401 ] && pass "nextcloud-mcp: a credential Nextcloud rejects -> 401" || fail "nextcloud-mcp with a bad credential: HTTP $(cat "$TMP/mcpcode")"

# Tool classes against the real tools.
yq -o=json '.ai.mcp[0].tools' "$MANIFEST" > "$TMP/classes.json"
if python3 - "$TMP/classes.json" "$TMP/tools.json" <<'PY'
import fnmatch, json, sys
c = json.load(open(sys.argv[1]))
tools = {t["name"].lower(): (t.get("annotations") or {}) for t in json.load(open(sys.argv[2]))["result"]["tools"]}
m = lambda pats, t: any(fnmatch.fnmatchcase(t, p.lower()) for p in pats)
bad = []
print("  INFO %d tools" % len(tools))
for t, a in sorted(tools.items()):
    print("  INFO   %s%s%s" % (t, " [readOnly]" if a.get("readOnlyHint") else "", " [destructive]" if a.get("destructiveHint") else ""))
if not tools:
    bad.append("no tools listed")
for k in ("writes", "confirm", "never"):
    for p in c[k]:
        if not any(fnmatch.fnmatchcase(t, p.lower()) for t in tools):
            bad.append("%s pattern %r matches no real tool" % (k, p))
for t, a in tools.items():
    if a.get("readOnlyHint") and m(c["writes"], t):
        bad.append("read-only tool %s is matched by writes" % t)
    if not a.get("readOnlyHint") and not m(c["writes"], t):
        bad.append("tool %s (no readOnlyHint) is not in writes" % t)
    if (a.get("destructiveHint") or "delete" in t) and not m(c["confirm"], t):
        bad.append("tool %s (delete / destructiveHint) is not in confirm" % t)
    if "share" in t and not a.get("readOnlyHint") and not (m(c["confirm"], t) or m(c["never"], t)):
        bad.append("sharing tool %s is neither confirm nor never" % t)
for b in bad:
    print("  FAIL " + b)
sys.exit(1 if bad else 0)
PY
then
  pass "tool classes match nextcloud-mcp's real tools (writes = no readOnlyHint, deletes and sharing confirmed or never)"
else
  fail "tool classes do not match nextcloud-mcp's tools (above)"
fi

# revoke: the app password is refused afterwards, by Nextcloud and through the companion.
if printf '{"action":"revoke","user":"alice","ids":["%s"]}' "${ID[alice]}" | hook revoke \
  && [ "$(ocs_as alice "${CRED[alice]}")" = 401 ] && [ "$(ai_tokens alice)" = 0 ]; then
  pass "revoke -> alice's app password deleted and refused (401)"
else
  fail "revoke: the credential still works or the hook failed"
fi
R=$(mcp alice "${CRED[alice]}" "$LS")
grep -q 'alice-secret.txt' <<<"$R" && fail "nextcloud-mcp still lists alice's files with the revoked app password" \
  || pass "nextcloud-mcp with the revoked app password lists nothing (HTTP $(cat "$TMP/mcpcode"))"

# revoke_all: every portcullis-ai-* app password of every person, nothing else.
OWN=$(docker exec -u www-data "$C" php occ --no-interaction user:auth-tokens:add --name=bob-own -- bob | tail -1)
for _ in 1 2; do mint_in alice | hook mint >/dev/null; done
set +e; printf '{"action":"revoke_all","prefix":"portcullis-"}' | hook revoke >/dev/null 2>&1; RC=$?; set -e
if [ "$RC" != 0 ] && [ "$(ai_tokens alice)" = 2 ]; then
  pass "revoke_all with another prefix refused (exit $RC), nothing deleted"
else
  fail "revoke_all with prefix portcullis-: exit $RC"
fi
if printf '{"action":"revoke_all","prefix":"portcullis-ai-"}' | hook revoke; then
  pass "revoke_all exited 0"
else
  fail "revoke_all failed"
fi
CB=$(ocs_as bob "${CRED[bob]}"); CS=$(ocs_as bob "$OWN")
if [ "$(ai_tokens alice)" = 0 ] && [ "$(ai_tokens bob)" = 0 ] && [ "$CB" = 401 ] && [ "$CS" = 200 ]; then
  pass "revoke_all: no portcullis-ai-* app password left (bob's refused); bob's own app password kept"
else
  fail "revoke_all: alice $(ai_tokens alice), bob $(ai_tokens bob) left; bob's AI credential $CB, own $CS"
fi
rm -rf "$TMP"

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
