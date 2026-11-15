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

# Fail closed: run init.sh against a temporary DokuWiki tree (needs php).
if command -v php >/dev/null 2>&1; then
  T=$(mktemp -d)
  mkdir -p "$T/dw/conf" "$T/app"
  printf '*\t@ALL\t1\n' > "$T/dw/conf/acl.auth.php"
  printf '<?php\n' > "$T/app/install.php"
  run_init() {
    env PORTCULLIS_DW_ROOT="$T/dw" PORTCULLIS_DW_APP="$T/app" PORTCULLIS_DW_PLUGIN_SRC="$1" \
      PORTCULLIS_DOMAIN=example.org PORTCULLIS_HOST_DOKUWIKI=wiki.example.org PORTCULLIS_OIDC_CLIENT_ID=dokuwiki \
      PORTCULLIS_ACCESS_GROUP=users_dokuwiki PORTCULLIS_ADMIN_GROUP=admin_dokuwiki \
      PORTCULLIS_TRAEFIK_SOURCE=172.31.250.2/32 DOKUWIKI_OIDC_SECRET=s3cr3t bash "$INIT" >/dev/null 2>&1
  }
  # 1. The plugins can't be installed: the wiki must stay locked down.
  if run_init "$T/missing"; then
    fail "init.sh succeeded without its plugins"
  else
    pass "init.sh fails without its plugins"
  fi
  if grep -q "'portcullislocked'" "$T/dw/conf/local.protected.php" && grep -q "disableactions.*login" "$T/dw/conf/local.protected.php" \
      && ! grep -q "oauth" "$T/dw/conf/local.protected.php" && [ ! -e "$T/app/install.php" ]; then
    pass "failed init leaves the wiki locked down (no auth backend, login disabled, install.php gone)"
  else
    fail "failed init does not leave the wiki locked down"
  fi
  # 1b. No php at all (the lookup comes after the lockdown): still locked down.
  printf '<?php\n' > "$T/app/install.php"
  BIN="$T/bin"; mkdir -p "$BIN"
  for b in env bash rm mkdir cat mv chmod sed cp grep; do ln -s "$(command -v "$b")" "$BIN/$b"; done
  rm -f "$T/dw/conf/local.protected.php"
  if PATH="$BIN" run_init "$T/missing"; then
    fail "init.sh succeeded without php"
  elif grep -q "'portcullislocked'" "$T/dw/conf/local.protected.php" 2>/dev/null && [ ! -e "$T/app/install.php" ]; then
    pass "no php: init.sh fails and the lockdown is already in place"
  else
    fail "no php: the lockdown was not written before the failure"
  fi
  # 2. Normal run: working configuration, ACL without anonymous rights.
  if run_init "$(dirname "$INIT")/plugins" && grep -q "'authtype'] = 'oauth'" "$T/dw/conf/local.protected.php" \
      && grep -q "'baseurl'] = 'https://wiki.example.org'" "$T/dw/conf/local.protected.php" \
      && [ -f "$T/dw/lib/plugins/oauth/auth.php" ] && [ -f "$T/dw/lib/plugins/oauthgeneric/action.php" ] \
      && grep -q "^\*.@ALL.0.# Portcullis" "$T/dw/conf/acl.auth.php" && ! grep -q "^\*.@ALL.1" "$T/dw/conf/acl.auth.php"; then
    pass "init.sh configures OIDC, installs the vendored plugins and denies anonymous access"
  else
    fail "init.sh normal run did not produce the expected configuration"
  fi
  rm -rf "$T"
else
  info "php not installed: init.sh fail-closed test skipped"
fi

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
# DokuWiki matches ACL groups in auth_nameencode() form: "_" is %5f.
ACL_GROUP=${PORTCULLIS_ACCESS_GROUP//_/%5f}
if echo "$ACL" | grep -q "^\*${TAB}@ALL${TAB}0${TAB}" && echo "$ACL" | grep -qF "*${TAB}@${ACL_GROUP}${TAB}8${TAB}"; then
  pass "ACL: * @ALL 0, * @${ACL_GROUP} 8"
else
  fail "ACL not as expected: $ACL"
fi

# install.php gone
assert_http_code "http://${IP}:80/install.php" 404

# Login goes straight to Keycloak with this instance's client (the oauth
# plugin first redirects to its own ?oauthlogin=generic step)
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://${IP}:80/doku.php?do=login" 2>/dev/null || true)
if echo "$LOC" | grep -q 'oauthlogin=generic'; then
  LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://${IP}:80/doku.php?${LOC#*\?}" 2>/dev/null || true)
fi
if echo "$LOC" | grep -q "/realms/portcullis/protocol/openid-connect/auth" && echo "$LOC" | grep -q "client_id=${PORTCULLIS_OIDC_CLIENT_ID}"; then
  pass "?do=login leads to Keycloak (client ${PORTCULLIS_OIDC_CLIENT_ID})"
else
  fail "?do=login does not lead to Keycloak: '$LOC'"
fi

# Anonymous visitors can't read: the page is denied (singleService turns
# the denial into a redirect to the Portcullis login), never shown
T=$(mktemp)
OUT=$(curl -s -o "$T.body" -w '%{http_code} %{redirect_url}' "http://${IP}:80/doku.php?id=start" 2>/dev/null || true)
if { [ "${OUT%% *}" = 302 ] && echo "$OUT" | grep -q 'oauthlogin\|do=login'; } \
    || { [ "${OUT%% *}" = 200 ] && grep -qi 'permission denied' "$T.body"; } || [ "${OUT%% *}" = 403 ]; then
  pass "anonymous read refused ($OUT)"
else
  fail "anonymous visitors can read pages ($OUT)"
fi
rm -f "$T" "$T.body"

compose_down "$APP_ID"
