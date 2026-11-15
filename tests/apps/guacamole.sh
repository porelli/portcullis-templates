#!/usr/bin/env bash
# Test: Apache Guacamole (forward-auth + HTTP header auth)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="guacamole"
section "Guacamole"

APP_ID=guacamole

COMPOSE=$(_find_compose "$APP_ID" || true)

# Static: header auth uses the image's HEADER_ENABLED switch, behind forward-auth
if grep -q 'HEADER_ENABLED: "true"' "$COMPOSE" && grep -q 'HTTP_AUTH_HEADER: X-Forwarded-User' "$COMPOSE"; then
  pass "Header auth enabled (HEADER_ENABLED + HTTP_AUTH_HEADER)"
else
  fail "Header auth not configured (expected HEADER_ENABLED and HTTP_AUTH_HEADER)"
fi

if grep -q 'portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Forward-auth + group-gate middleware missing"
fi

# Static: default guacadmin/guacadmin password is replaced at DB init
if grep -q "WHERE e.name = 'guacadmin'" "$COMPOSE" && grep -q 'GUACAMOLE_ADMIN_PASSWORD' "$COMPOSE"; then
  pass "guacadmin default password replaced at DB init"
else
  fail "guacadmin default password is not replaced"
fi

# Static: the header extension has no allowlist; a Tomcat RewriteValve
# rejects X-Forwarded-User from any peer other than Traefik
assert_traefik_only_trust "$COMPOSE" PORTCULLIS_TRAEFIK_SOURCE
if grep -q 'org.apache.catalina.valves.rewrite.RewriteValve' "$COMPOSE" && grep -q 'RewriteRule .\* - \[F\]' "$COMPOSE"; then
  pass "RewriteValve forbids X-Forwarded-User from non-Traefik peers"
else
  fail "RewriteValve guarding X-Forwarded-User is missing"
fi

# Static: the built-in administrator is guacadmin-<generated suffix>, and the
# valve refuses any X-Forwarded-User starting with guacadmin (the runtime
# check is the sign-in e2e's refused_users: [guacadmin-x])
if grep -q 'GUACAMOLE_ADMIN_SUFFIX:?' "$COMPOSE" \
    && grep -A2 'key: GUACAMOLE_ADMIN_SUFFIX' "$(dirname "$COMPOSE")/manifest.yaml" | grep -q 'generate: random'; then
  pass "local administrator name is guacadmin-<generated suffix>"
else
  fail "the built-in administrator must be renamed guacadmin-\${GUACAMOLE_ADMIN_SUFFIX} (generated)"
fi
if grep -qF "echo 'RewriteCond %{HTTP:X-Forwarded-User} ^guacadmin.* [NC]'" "$COMPOSE"; then
  pass "valve refuses X-Forwarded-User starting with guacadmin (static)"
else
  fail "valve does not refuse X-Forwarded-User guacadmin*"
fi

# The Administrator setting (type user: any LLDAP username) is checked by
# guacamole-init before it is written: a guacadmin* name (the valve refuses
# such header logins) or other characters stop the init (fail closed). Run
# the init's own check on sample values ($$ unescaped as compose does).
ADMIN_CHECK=$(yq -r '.services["guacamole-init"].command[0]' "$COMPOSE" \
  | sed -n '/case "\$\${GUACAMOLE_ADMIN_USER}" in/,/esac/p' | sed 's/\$\$/$/g')
admin_ok() { GUACAMOLE_ADMIN_USER="$1" sh -c "set -eu; $ADMIN_CHECK" >/dev/null 2>&1; }
if [ -n "$ADMIN_CHECK" ] && admin_ok alice && admin_ok "" && admin_ok first.last@x; then
  pass "guacamole-init accepts admin_user alice / empty / first.last@x"
else
  fail "guacamole-init's admin_user check missing or refuses a valid username"
fi
for bad in guacadmin guacadmin-x GuacAdmin2 'a b' "x'y" 'a;b'; do
  if admin_ok "$bad"; then fail "guacamole-init accepts admin_user '$bad'"; else pass "guacamole-init refuses admin_user '$bad'"; fi
done

# Static: the DB healthcheck takes the password from the env, not argv
if grep -q 'MYSQL_PWD=' "$COMPOSE" && ! grep -qE '"-p\$\{?GUACAMOLE_DB_PASSWORD' "$COMPOSE"; then
  pass "DB healthcheck passes the password via MYSQL_PWD"
else
  fail "DB healthcheck must not put the password on argv"
fi

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8080/guacamole/" 90 "$APP_ID"

# Homepage should return the Guacamole login page
BODY=$(curl -sf "http://${IP}:8080/guacamole/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "guacamole"; then
  pass "/ → Guacamole login page returned"
else
  fail "/ → Guacamole login page not found"
fi

# The CI host is not Traefik: the token endpoint must refuse a spoofed header
assert_spoofed_identity_rejected "http://${IP}:8080/guacamole/api/tokens" 403 -X POST

compose_down "$APP_ID"
