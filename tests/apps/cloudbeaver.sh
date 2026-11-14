#!/usr/bin/env bash
# Test: CloudBeaver (header-auth behind nginx gate + forward-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="cloudbeaver"
section "CloudBeaver"

APP_ID=cloudbeaver

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8978" 60 "$APP_ID"

# CloudBeaver should return HTML
BODY=$(curl -sf "http://${IP}:8978/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "cloudbeaver\|<html"; then
  pass "/ -> CloudBeaver page returned"
else
  fail "/ -> CloudBeaver page not found"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

# Static: CloudBeaver logs in by username (X-Forwarded-User), never email.
# cloudbeaver-config writes the runtime config CloudBeaver reads.
PATCH="$(dirname "$COMPOSE")/patch-runtime-conf.py"
if grep -q '"user-header": "X-Forwarded-User"' "$PATCH" && ! grep -qi 'X-Forwarded-Email' "$PATCH"; then
  pass "reverseProxy user-header is X-Forwarded-User (LLDAP username)"
else
  fail "reverseProxy must use user-header X-Forwarded-User and no email header"
fi
if grep -q 'proxy_set_header X-Forwarded-Email ""' "$COMPOSE" && grep -q 'http_x_forwarded_email' "$COMPOSE"; then
  pass "gate rejects foreign X-Forwarded-Email and strips it"
else
  fail "gate does not handle X-Forwarded-Email"
fi

# Static: CloudBeaver itself stays off portcullis-proxy; only the gate is
# routed by Traefik and it trusts X-Forwarded-User from Traefik alone
assert_traefik_only_trust "$COMPOSE" PORTCULLIS_TRAEFIK_SOURCE
CB_NETS=$(docker compose -f "$COMPOSE" --project-directory "$PROJECT_DIR" config --format json 2>/dev/null \
  | jq -r '.services.cloudbeaver.networks // {} | keys | join(",")' 2>/dev/null || echo "")
if [ "$CB_NETS" = "default" ]; then
  pass "cloudbeaver is on the default network only"
else
  fail "cloudbeaver networks: expected 'default', got '$CB_NETS'"
fi

# The local administrator (automatic server configuration) has a generated
# per-instance name, and the gate never lets a header login use it.
if grep -q 'CB_ADMIN_NAME: cbadmin-${CLOUDBEAVER_ADMIN_SUFFIX:?' "$COMPOSE" \
    && grep -A2 'key: CLOUDBEAVER_ADMIN_SUFFIX' "$(dirname "$COMPOSE")/manifest.yaml" | grep -q 'generate: random'; then
  pass "local administrator name is cbadmin-<generated suffix>"
else
  fail "CB_ADMIN_NAME must be cbadmin-\${CLOUDBEAVER_ADMIN_SUFFIX} with a generated suffix"
fi
if grep -qF 'if (\$$http_x_forwarded_user ~* "^cbadmin") { return 403; }' "$COMPOSE"; then
  pass "gate refuses X-Forwarded-User starting with cbadmin (static)"
else
  fail "gate does not refuse X-Forwarded-User cbadmin*"
fi

# Runtime (what CloudBeaver serves, not what a file says): configured (no
# setup wizard), anonymous access off, reverseProxy enabled.
gql() { curl -s --max-time 10 -H 'Content-Type: application/json' -d "{\"query\":\"$1\"}" "http://${IP}:8978/api/gql" 2>/dev/null || true; }
CFG=""
for _ in $(seq 1 40); do
  CFG=$(gql '{ serverConfig { configurationMode anonymousAccessEnabled enabledAuthProviders } }')
  jq -e '.data.serverConfig.configurationMode == false' <<< "$CFG" >/dev/null 2>&1 && break
  sleep 3
done
if jq -e '.data.serverConfig.configurationMode == false' <<< "$CFG" >/dev/null 2>&1; then
  pass "server configured automatically (configurationMode false: no setup wizard)"
else
  fail "CloudBeaver is in configuration mode (setup wizard): $CFG"
fi
if jq -e '.data.serverConfig.anonymousAccessEnabled == false' <<< "$CFG" >/dev/null 2>&1; then
  pass "anonymous access off (serverConfig)"
else
  fail "anonymous access is not off: $CFG"
fi
if jq -e '.data.serverConfig.enabledAuthProviders | index("reverseProxy")' <<< "$CFG" >/dev/null 2>&1; then
  pass "reverseProxy auth provider enabled (serverConfig)"
else
  fail "reverseProxy auth provider not enabled: $CFG"
fi
if grep -q 'app\["anonymousAccessEnabled"\] = False' "$PATCH"; then
  pass "cloudbeaver-config forces anonymous access off at every start"
else
  fail "patch-runtime-conf.py must force anonymousAccessEnabled off"
fi
# The gate is healthy (= routed by Traefik) only in that state.
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' portcullis-cloudbeaver-gate-1 2>/dev/null)" = healthy ] && break
  sleep 3
done
if [ "$(docker inspect -f '{{.State.Health.Status}}' portcullis-cloudbeaver-gate-1 2>/dev/null)" = healthy ]; then
  pass "cloudbeaver-gate healthy (CloudBeaver configured, no anonymous access)"
else
  fail "cloudbeaver-gate not healthy: $(docker inspect -f '{{json .State.Health}}' portcullis-cloudbeaver-gate-1 2>/dev/null | head -c 600)"
fi

GATE_IP=$(app_container_ip "$APP_ID" cloudbeaver-gate)
assert_http_code "http://${GATE_IP}:8978/" 200
assert_spoofed_identity_rejected "http://${GATE_IP}:8978/" 403
assert_spoofed_email_rejected "http://${GATE_IP}:8978/" 403

compose_down "$APP_ID"
