#!/usr/bin/env bash
# Test: DokuWiki (native OIDC via the oauth + oauthgeneric plugins)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="dokuwiki"
section "DokuWiki"

APP_ID=dokuwiki

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
INIT="$(dirname "$COMPOSE")/init.sh"

# Static: identity is the username (the oauth plugin keys accounts on "mail")
if grep -q '"json-mail" => "preferred_username"' "$INIT" && grep -q '"json-user" => "preferred_username"' "$INIT" \
    && grep -q 'profile,profile_delete' "$INIT"; then
  pass "oauth account key (mail) and name = preferred_username, profile edits off"
else
  fail "init.sh must map json-mail/json-user to preferred_username and disable profile edits"
fi
if grep -E '^[[:space:]]*traefik\.http\.routers\.dokuwiki\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker'; then
  fail "host-wide router uses forward-auth"
else
  pass "host-wide router has no forward-auth"
fi
if bash -n "$INIT"; then pass "init.sh parses"; else fail "init.sh has a syntax error"; fi

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
# DokuWiki (linuxserver image) listens on port 80; init.sh downloads the
# plugins first.
wait_for_url "http://${IP}:80" 150 "$APP_ID"

C=portcullis-dokuwiki-1
if docker exec "$C" test -f /config/dokuwiki/lib/plugins/oauth/plugin.info.txt \
    && docker exec "$C" test -f /config/dokuwiki/lib/plugins/oauthgeneric/plugin.info.txt; then
  pass "oauth + oauthgeneric plugins installed"
else
  fail "oauth plugins missing"
  docker logs "$C" 2>&1 | grep -i portcullis | tail -10 || true
fi

# Hostname from the instance variable, OIDC backend, admin group
PROT=$(docker exec "$C" cat /config/dokuwiki/conf/local.protected.php 2>/dev/null || true)
if echo "$PROT" | grep -qF "\$conf['baseurl'] = 'https://${PORTCULLIS_HOST_DOKUWIKI}';" \
    && echo "$PROT" | grep -qF "\$conf['authtype'] = 'oauth';" \
    && echo "$PROT" | grep -qF "\$conf['superuser'] = '@${PORTCULLIS_ADMIN_GROUP}';"; then
  pass "local.protected.php: baseurl, authtype oauth, superuser @${PORTCULLIS_ADMIN_GROUP}"
else
  fail "local.protected.php not as expected"
fi

# ACL: anonymous nothing, access group edits
ACL=$(docker exec "$C" cat /config/dokuwiki/conf/acl.auth.php 2>/dev/null || true)
TAB=$'\t'
if echo "$ACL" | grep -q "^\*${TAB}@ALL${TAB}0${TAB}" && echo "$ACL" | grep -q "^\*${TAB}@${PORTCULLIS_ACCESS_GROUP}${TAB}8${TAB}"; then
  pass "ACL: * @ALL 0, * @${PORTCULLIS_ACCESS_GROUP} 8"
else
  fail "ACL not as expected: $ACL"
fi

# install.php gone
assert_http_code "http://${IP}:80/install.php" 404

# Login goes straight to Keycloak with this instance's client
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://${IP}:80/doku.php?do=login" 2>/dev/null || true)
if echo "$LOC" | grep -q "/realms/portcullis/protocol/openid-connect/auth" && echo "$LOC" | grep -q "client_id=${PORTCULLIS_OIDC_CLIENT_ID}"; then
  pass "?do=login redirects to Keycloak (client ${PORTCULLIS_OIDC_CLIENT_ID})"
else
  fail "?do=login does not redirect to Keycloak: '$LOC'"
fi

# Anonymous visitors can't read
BODY=$(curl -s "http://${IP}:80/doku.php?id=start" 2>/dev/null || true)
if echo "$BODY" | grep -qi 'permission denied\|login'; then
  pass "anonymous read refused"
else
  fail "anonymous visitors can read pages"
fi

compose_down "$APP_ID"
