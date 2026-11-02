#!/usr/bin/env bash
# Test: Nextcloud (native OIDC via user_oidc)
# Nextcloud takes a while to initialize and downloads user_oidc at first
# start — static checks of compose, manifest and setup.sh only.
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

# Native OIDC: the host-wide router carries no forward-auth (sync clients,
# WebDAV, share links); only the exact login paths are gated.
if grep -E '^[[:space:]]*traefik\.http\.routers\.nextcloud\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker'; then
  fail "host-wide router uses forward-auth (breaks clients behind native OIDC)"
else
  pass "host-wide router has no forward-auth"
fi
LOGIN_RULE=$(grep -E '^[[:space:]]*traefik\.http\.routers\.nextcloud-login\.rule:' "$COMPOSE" || true)
LOGIN_MW=$(grep -E '^[[:space:]]*traefik\.http\.routers\.nextcloud-login\.middlewares:' "$COMPOSE" || true)
if echo "$LOGIN_RULE" | grep -q 'Path(`/login`)' && echo "$LOGIN_RULE" | grep -q 'Path(`/index.php/login`)' \
    && ! echo "$LOGIN_RULE" | grep -q 'PathPrefix' \
    && echo "$LOGIN_MW" | grep -q 'portcullis-auth@docker,portcullis-groups@docker'; then
  pass "/login and /index.php/login (exact) behind forward-auth + group-gate"
else
  fail "login router must gate exactly /login and /index.php/login with forward-auth + group-gate"
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
    'token_auth_enforced --type=boolean --value=true'; do
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

# Admin group mapping only touches SSO accounts
if grep -q 'group:adduser admin' "$CRON" && grep -q '"backend":"user_oidc"' "$CRON"; then
  pass "cron.sh maps the admin group to Nextcloud admins (SSO accounts only)"
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
