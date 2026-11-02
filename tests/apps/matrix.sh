#!/usr/bin/env bash
# Test: Matrix (Synapse native OIDC, group-restricted; Element behind
# forward-auth + group-gate; federation off)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="matrix"
section "Matrix"

APP_ID=matrix

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
DIR="$(dirname "$COMPOSE")"
START="$DIR/synapse-start.py"

# ── Static ────────────────────────────────────────────────────────
router_mw() { grep -E "^[[:space:]]*traefik\.http\.routers\.$1\.middlewares:" "$COMPOSE" || true; }
if router_mw matrix | grep -q 'portcullis-auth@docker'; then
  fail "homeserver host router uses forward-auth (breaks mobile clients and the OIDC login)"
else
  pass "homeserver host router has no forward-auth (native OIDC)"
fi
if router_mw element | grep -q 'portcullis-auth@docker,portcullis-groups@docker'; then
  pass "Element is behind forward-auth + group-gate"
else
  fail "Element router must use portcullis-auth@docker,portcullis-groups@docker"
fi
if router_mw matrix-admin | grep -q 'portcullis-auth@docker,portcullis-groups@docker' \
    && grep -q 'PathPrefix(`/_synapse/admin`)' "$COMPOSE" && grep -q '/_synapse/admin' "$DIR/manifest.yaml"; then
  pass "Admin API gated and listed in auth.admin_paths"
else
  fail "/_synapse/admin must be gated (matrix-admin router + auth.admin_paths)"
fi
for needle in '"password_config": {"enabled": False}' '"enable_registration": False' '"allow_existing_users": False' \
    '"localpart_template": "{{ user.preferred_username }}"' '"attribute_requirements": [{"attribute": "groups", "value": access_group}]' \
    '"federation_domain_whitelist": federation' 'resources = ["client", "federation"] if federation else ["client"]' \
    '"trusted_key_servers": []'; do
  if grep -qF "$needle" "$START"; then
    pass "synapse-start.py: $needle"
  else
    fail "synapse-start.py lacks $needle"
  fi
done
if grep -q 'email_template"' "$START"; then
  fail "synapse-start.py imports the (user-editable) email"
else
  pass "no email_template (email not imported)"
fi

# ── Runtime ───────────────────────────────────────────────────────
compose_up "$APP_ID"
MATRIX="$PORTCULLIS_HOST_MATRIX"
ELEMENT="$PORTCULLIS_HOST_ELEMENT"

if INIT_RC=$(timeout 120 docker wait portcullis-synapse-init-1 2>/dev/null) && [ "$INIT_RC" = 0 ]; then
  pass "synapse-init exited 0"
else
  fail "synapse-init did not finish successfully (rc=${INIT_RC:-none})"
fi

IP=$(app_container_ip "$APP_ID" synapse)
if ! wait_for_url "http://${IP}:8008/health" 240 "synapse"; then
  docker logs portcullis-synapse-1 2>&1 | tail -30 || true
fi

if [ "$(docker inspect -f '{{.Config.User}}' portcullis-synapse-1)" = "991:991" ]; then
  pass "synapse runs as 991:991"
else
  fail "synapse must run as 991:991"
fi

FLOWS=$(curl -sf "http://${IP}:8008/_matrix/client/v3/login" 2>/dev/null || echo "{}")
if echo "$FLOWS" | grep -q '"m.login.sso"' && ! echo "$FLOWS" | grep -q '"m.login.password"'; then
  pass "login flows: SSO only, no password ($FLOWS)"
else
  fail "login flows must offer m.login.sso and no m.login.password: $FLOWS"
fi
if echo "$FLOWS" | grep -q '"oidc-portcullis"'; then
  pass "OIDC provider oidc-portcullis offered"
else
  fail "OIDC provider oidc-portcullis missing: $FLOWS"
fi

REG=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' \
  "http://${IP}:8008/_matrix/client/v3/register" 2>/dev/null || echo 000)
if [ "$REG" = 403 ]; then
  pass "open registration refused (403)"
else
  fail "POST /register -> expected 403, got $REG"
fi

FED=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:8008/_matrix/federation/v1/version" 2>/dev/null || echo 000)
KEY=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:8008/_matrix/key/v2/server" 2>/dev/null || echo 000)
if [ "$FED" = 404 ] && [ "$KEY" = 404 ]; then
  pass "federation API not served (federation off)"
else
  fail "federation off: expected 404 for /_matrix/federation and /_matrix/key, got $FED / $KEY"
fi

WK=$(curl -sf "http://${IP}:8008/.well-known/matrix/client" 2>/dev/null || echo "")
if echo "$WK" | grep -qF "https://${MATRIX}/"; then
  pass ".well-known/matrix/client points at https://${MATRIX}/"
else
  fail ".well-known/matrix/client: $WK"
fi

if docker exec portcullis-synapse-1 test -s /data/signing.key; then
  pass "signing key persisted in the data volume"
else
  fail "no /data/signing.key"
fi
if docker exec portcullis-synapse-1 sh -c 'test ! -e /data/homeserver.yaml'; then
  pass "config (with secrets) not written to the data volume"
else
  fail "/data/homeserver.yaml exists"
fi

# Element: healthy only while serving the generated config.
EIP=$(app_container_ip "$APP_ID" element)
wait_for_url "http://${EIP}:8080/config.json" 120 "element" || true
ECONF=$(curl -sf "http://${EIP}:8080/config.json" 2>/dev/null || echo "{}")
if echo "$ECONF" | grep -qF "\"base_url\": \"https://${MATRIX}\"" && echo "$ECONF" | grep -q '"disable_custom_urls": true' \
    && ! echo "$ECONF" | grep -q 'matrix.org'; then
  pass "Element config.json points at https://${MATRIX} only"
else
  fail "Element config.json: $ECONF"
fi
if [ "$(docker inspect -f '{{.Config.User}}' portcullis-element-1)" != root ] \
    && [ "$(docker exec portcullis-element-1 id -u)" != 0 ]; then
  pass "Element runs as non-root"
else
  fail "Element runs as root"
fi

# Through Traefik: Element redirects to Keycloak; the homeserver's client
# API and SSO redirect are reachable without forward-auth; the Admin API is gated.
# Traefik routes a container only once its healthcheck reports healthy
# (Synapse's image checks every 15 s), so wait for both hosts.
for host in "$ELEMENT" "$MATRIX"; do
  for _ in $(seq 1 60); do
    out=$(via_traefik "$host" /_matrix/client/versions); [ "${out%% *}" != 404 ] && break; sleep 2
  done
done
assert_gated_path "$ELEMENT" /
assert_gated_path "$MATRIX" /_synapse/admin/v1/server_version
out=$(via_traefik "$MATRIX" /_matrix/client/versions)
if [ "${out%% *}" = 200 ]; then
  pass "client API reachable through Traefik without forward-auth"
else
  fail "GET https://$MATRIX/_matrix/client/versions -> $out"
fi
out=$(via_traefik "$MATRIX" "/_matrix/client/v3/login/sso/redirect/oidc-portcullis?redirectUrl=https%3A%2F%2F${ELEMENT}%2F")
if echo "${out#* }" | grep -q "auth\.$DOMAIN/realms/portcullis/protocol/openid-connect/auth"; then
  pass "SSO redirect goes to Keycloak ($MATRIX native OIDC)"
else
  fail "SSO redirect: $out"
fi

# A second `compose up` reruns the one-shot synapse-init on a volume that is
# already 991's: it must still exit 0, or Synapse never starts again.
compose_up "$APP_ID"
if INIT_RC=$(timeout 120 docker wait portcullis-synapse-init-1 2>/dev/null) && [ "$INIT_RC" = 0 ]; then
  pass "synapse-init exited 0 on the second compose up"
else
  fail "synapse-init failed on the second compose up (rc=${INIT_RC:-none})"
fi
IP=$(app_container_ip "$APP_ID" synapse)
wait_for_url "http://${IP}:8008/health" 240 "synapse (after restart)" || true

compose_down "$APP_ID"
