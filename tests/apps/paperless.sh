#!/usr/bin/env bash
# Test: Paperless-ngx (native OIDC via django-allauth, SSO-only)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="paperless"
section "Paperless-ngx"

APP_ID=paperless
COMPOSE=$(_find_compose "$APP_ID" || true)
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"

# ── Static ───────────────────────────────────────────────
assert_compose_setting "$COMPOSE" PAPERLESS_DISABLE_REGULAR_LOGIN true
assert_compose_setting "$COMPOSE" PAPERLESS_REDIRECT_LOGIN_TO_SSO true
assert_compose_setting "$COMPOSE" PAPERLESS_ACCOUNT_ALLOW_SIGNUPS false
assert_compose_setting "$COMPOSE" PAPERLESS_SOCIAL_ACCOUNT_SYNC_GROUPS true
if grep -q '"EMAIL_AUTHENTICATION": false' "$COMPOSE"; then
  pass "allauth never links SSO logins by email"
else
  fail "PAPERLESS_SOCIALACCOUNT_PROVIDERS must set EMAIL_AUTHENTICATION false"
fi
if grep -Eq 'PAPERLESS_(AUTO_LOGIN_USERNAME|ENABLE_HTTP_REMOTE_USER|ADMIN_PASSWORD)' "$COMPOSE"; then
  fail "auto-login, remote-user auth or a bootstrap admin password is configured"
else
  pass "no auto-login, remote-user auth or bootstrap admin password"
fi
if grep -q 'routers.paperless-sso.rule:.*PathPrefix(`/accounts/oidc`)' "$COMPOSE" \
  && grep -q 'routers.paperless-sso.middlewares:.*portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "SSO start + callback behind forward-auth + group-gate"
else
  fail "/accounts/oidc is not behind forward-auth + group-gate"
fi
if grep -q 'routers.paperless-admin.middlewares:.*portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE" \
  && grep -qE '^  admin_paths: \["/admin"\]' "$MANIFEST"; then
  pass "/admin behind forward-auth + group-gate with admin_group"
else
  fail "/admin router or auth.admin_paths missing"
fi
if grep -q '^  group_access: true' "$MANIFEST" && grep -q '^  access_group: users_paperless' "$MANIFEST"; then
  pass "group_access: true with users_paperless"
else
  fail "manifest must set group_access: true and access_group: users_paperless"
fi

# ── Runtime ──────────────────────────────────────────────
compose_up "$APP_ID"

# paperless-init (migrations + lockdown) must succeed, or Paperless never starts.
if INIT_RC=$(timeout 600 docker wait "portcullis-paperless-init-1" 2>/dev/null) && [ "$INIT_RC" = "0" ]; then
  pass "paperless-init exited 0"
else
  fail "paperless-init did not finish successfully (rc=${INIT_RC:-none})"
  docker logs "portcullis-paperless-init-1" 2>&1 | tail -20 || true
fi

wait_for_container "portcullis-paperless-1" 120
IP=$(app_container_ip "$APP_ID")
HOST="paperless.$DOMAIN"
# Paperless only answers its own hostname (PAPERLESS_ALLOWED_HOSTS).
app_get() { curl -s --max-time 15 -H "Host: $HOST" "$@" 2>/dev/null || true; }
# Without the Host header Paperless answers 400 (ALLOWED_HOSTS).
info "Waiting for $APP_ID..."
up=""
for _ in $(seq 1 420); do
  [ "$(app_get -o /dev/null -w '%{http_code}' "http://${IP}:8000/accounts/login/")" = 200 ] && { up=1; break; }
  sleep 1
done
if [ -n "$up" ]; then pass "paperless answers on its hostname"; else fail "Timeout waiting for $APP_ID (http://${IP}:8000/accounts/login/, Host: $HOST)"; fi

# Login page: SSO button only, no username / password inputs.
LOGIN=$(app_get "http://${IP}:8000/accounts/login/")
if echo "$LOGIN" | grep -q '/accounts/oidc/portcullis/login/'; then
  pass "login page offers the Portcullis SSO provider"
else
  fail "login page has no /accounts/oidc/portcullis/login/ form"
fi
if echo "$LOGIN" | grep -qiE 'type="password"|name="password"'; then
  fail "login page shows a password field"
else
  pass "login page has no password field"
fi

# Signup closed (a placeholder account exists, ACCOUNT_ALLOW_SIGNUPS false).
SIGNUP=$(app_get "http://${IP}:8000/accounts/signup/")
if echo "$SIGNUP" | grep -qiE 'type="password"|name="password1"'; then
  fail "/accounts/signup/ offers a local signup form"
else
  pass "/accounts/signup/ offers no local signup"
fi

# No password works: a password set through Django is discarded by the trigger.
PW_CHECK=$(docker exec -i "portcullis-paperless-1" python3 manage.py shell 2>/dev/null <<'PY' | tail -1 || true
from django.contrib.auth.models import User
u = User.objects.get(username="paperless-bootstrap")
u.set_password("portcullis-test-password")
u.save()
u.refresh_from_db()
print("usable" if u.has_usable_password() or u.check_password("portcullis-test-password") else "unusable")
PY
)
if [ "$PW_CHECK" = "unusable" ]; then
  pass "password hashes are replaced by an unusable one (no password login)"
else
  fail "a password set on an account stays usable (got '${PW_CHECK:-nothing}')"
fi
# ... so HTTP Basic auth and the token endpoint refuse it.
CODE=$(app_get -o /dev/null -w '%{http_code}' -u "paperless-bootstrap:portcullis-test-password" "http://${IP}:8000/api/documents/")
if [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
  pass "Basic auth with a password refused (HTTP $CODE)"
else
  fail "Basic auth with a password: expected 401/403, got $CODE"
fi
CODE=$(app_get -o /dev/null -w '%{http_code}' -X POST -d "username=paperless-bootstrap&password=portcullis-test-password" "http://${IP}:8000/api/token/")
if [ "$CODE" = "400" ] || [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
  pass "/api/token/ with a password refused (HTTP $CODE)"
else
  fail "/api/token/ with a password: expected 400/401/403, got $CODE"
fi

# Through Traefik: the SSO start path goes to Portcullis sign-in first.
for _ in $(seq 1 60); do
  out=$(via_traefik "$HOST" /accounts/login/)
  case "${out%% *}" in 000|404|502|503) sleep 2 ;; *) break ;; esac
done
assert_gated_path "$HOST" /accounts/oidc/portcullis/login/
assert_gated_path "$HOST" /accounts/oidc/portcullis/login/callback/
assert_gated_path "$HOST" /admin/
out=$(via_traefik "$HOST" /api/); loc=${out#* }
if echo "$loc" | grep -q "auth\.$DOMAIN"; then
  fail "/api/ is behind forward-auth (API tokens and mobile apps would break)"
else
  pass "/api/ answered by Paperless (HTTP ${out%% *}), not gated"
fi

compose_down "$APP_ID"
