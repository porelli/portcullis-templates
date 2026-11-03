#!/usr/bin/env bash
# Test: Grafana (header-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="grafana"
section "Grafana"

APP_ID=grafana

# Public exception ON in listed mode with one listed dashboard token: the
# override the Hub would generate (tests/lib.sh quirk #12), every router of
# the host on the default policy's tier (authaware@file).
TOKEN=$(openssl rand -hex 16)
OTHER=$(openssl rand -hex 16)
MANIFEST="$(dirname "$(_find_compose "$APP_ID")")/manifest.yaml"
ROUTED=()
while read -r p; do ROUTED+=("$p"); done < <(public_routed_prefixes "$MANIFEST" listed "$TOKEN")
COMPOSE_OVERRIDE=$(mktemp)
export COMPOSE_OVERRIDE
# Core's real public guard checks paths and credentials: give it the
# policy-file entry the Hub would publish (at the version core's group-gate serves, tests/lib.sh policy_version).
write_public_policy grafana "$MANIFEST" listed
# shellcheck disable=SC2016 # ${PORTCULLIS_HOST_GRAFANA} is for compose to expand
write_public_override "$APP_ID" dashboards '${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}' authaware@file "$COMPOSE_OVERRIDE" "${ROUTED[@]}"

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID" dashboards)
wait_for_url "http://${IP}:3000" 60 "$APP_ID"

# Grafana login page should return HTML
BODY=$(curl -sf "http://${IP}:3000/login" 2>/dev/null || echo "")
# Here-string, not echo | grep -q: grep exits at the first match and the
# echo's broken pipe would fail the test under pipefail.
if grep -qi "grafana" <<< "$BODY"; then
  pass "/login -> Grafana login page returned"
else
  fail "/login -> Grafana login page not found"
fi

# Verify proxy auth is enabled in the container environment
GF_PROXY=$(docker exec "portcullis-dashboards-1" printenv GF_AUTH_PROXY_ENABLED 2>/dev/null || echo "")
if [ "$GF_PROXY" = "true" ]; then
  pass "GF_AUTH_PROXY_ENABLED=true"
else
  fail "GF_AUTH_PROXY_ENABLED expected 'true', got '$GF_PROXY'"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
assert_traefik_only_trust "$COMPOSE" GF_AUTH_PROXY_WHITELIST

# The CI host is not Traefik: a spoofed identity header must not log in
assert_spoofed_identity_rejected "http://${IP}:3000/api/user" non-2xx

if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

# Identity is the username only; never map an email header (account
# linking). The only extra mapping is the Role setting's header delivery.
if grep -q 'GF_AUTH_PROXY_HEADER_PROPERTY: username' "$COMPOSE" \
    && [ "$(grep -c 'GF_AUTH_PROXY_HEADERS' "$COMPOSE")" = 1 ] \
    && grep -qx '      GF_AUTH_PROXY_HEADERS: Role:X-Forwarded-Attr-Grafana-Role' "$COMPOSE"; then
  pass "Grafana header login keyed on username; only Role mapped (no email)"
else
  fail "Grafana must use HEADER_PROPERTY username and GF_AUTH_PROXY_HEADERS exactly Role:X-Forwarded-Attr-Grafana-Role"
fi
# Runtime: the role header mapping and per-request sync are in the env.
GF_HEADERS=$(docker exec "portcullis-dashboards-1" printenv GF_AUTH_PROXY_HEADERS 2>/dev/null || echo "")
GF_TTL=$(docker exec "portcullis-dashboards-1" printenv GF_AUTH_PROXY_SYNC_TTL 2>/dev/null || echo "")
if [ "$GF_HEADERS" = "Role:X-Forwarded-Attr-Grafana-Role" ] && [ "$GF_TTL" = 0 ]; then
  pass "GF_AUTH_PROXY_HEADERS=Role:X-Forwarded-Attr-Grafana-Role, GF_AUTH_PROXY_SYNC_TTL=0"
else
  fail "role header mapping: GF_AUTH_PROXY_HEADERS='$GF_HEADERS' GF_AUTH_PROXY_SYNC_TTL='$GF_TTL'"
fi

section "Public exception through Traefik"
HOST="grafana.$DOMAIN"
# Traefik picks the container up from the docker provider within seconds.
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /)
  case "${out%% *}" in 000|404|502) sleep 1 ;; *) break ;; esac
done
if docker inspect "portcullis-dashboards-1" --format '{{json .Config.Labels}}' | grep -q 'portcullis-public-strip-grafana.headers.customrequestheaders.X-Forwarded-User'; then
  pass "public router strips X-Forwarded-User (GF_AUTH_PROXY_HEADER_NAME)"
else
  fail "public router lacks the X-Forwarded-User strip"
fi
# The Role setting's header delivery never reaches Grafana from a client on
# the public router (the Hub strips every header delivery, both spellings).
LABELS=$(docker inspect "portcullis-dashboards-1" --format '{{json .Config.Labels}}')
if grep -q 'portcullis-public-strip-grafana.headers.customrequestheaders.X-Forwarded-Attr-Grafana-Role"' <<< "$LABELS" \
    && grep -q 'portcullis-public-strip-grafana.headers.customrequestheaders.X_Forwarded_Attr_Grafana_Role"' <<< "$LABELS"; then
  pass "public router strips X-Forwarded-Attr-Grafana-Role (and its underscore form)"
else
  fail "public router lacks the X-Forwarded-Attr-Grafana-Role strip"
fi
# Listed dashboard: answered by Grafana without Keycloak.
assert_public_path "$HOST" "/public-dashboards/$TOKEN"
assert_public_path "$HOST" "/api/public/dashboards/$TOKEN"
# Unlisted dashboard, a non-public path, and a segment-boundary near miss
# stay behind forward-auth.
assert_gated_path "$HOST" "/public-dashboards/$OTHER"
assert_gated_path "$HOST" "/api/public/dashboards/$OTHER"
assert_gated_path "$HOST" "/public-dashboards/${TOKEN}x"
assert_gated_path "$HOST" "/"
assert_gated_path "$HOST" "/api/user"
# Supporting paths serve static files only.
assert_gated_path "$HOST" "/public/build/"
# Logins never ride the public router: core's public guard refuses
# requests carrying a Grafana credential (403, no redirect), with cookie /
# query names normalised the way PHP does (and case-insensitively).
for h in "Cookie: grafana_session=stolen" "Cookie: a=1; grafana%5Fsession=stolen" "Cookie: GRAFANA_SESSION=stolen" \
         "Cookie:  grafana.session=stolen" "Cookie: renderKey=stolen" "Authorization: Basic YWRtaW46YWRtaW4=" \
         "Authorization: Bearer glsa_stolen" "X-Access-Token: stolen"; do
  assert_public_refused "$HOST" "/public-dashboards/$TOKEN" -H "$h"
done
for q in "auth_token=stolen" "auth.token=stolen" "+auth_token=stolen" "auth_token%5B%5D=stolen" "auth%5Ftoken=stolen"; do
  assert_public_refused "$HOST" "/public-dashboards/$TOKEN?$q"
done

clear_public_policy
compose_down "$APP_ID"
rm -f "$COMPOSE_OVERRIDE"

