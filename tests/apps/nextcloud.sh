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
