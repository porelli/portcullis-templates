#!/usr/bin/env bash
# Test: Firefox Sync (public host for Firefox's anonymous requests; only the
# Mozilla accounts of the Allowed accounts setting get a tokenserver row)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="firefox-sync"
section "Firefox Sync"

APP_ID=firefox-sync
SERVICE=firefox-sync

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
GUARD="$(dirname "$COMPOSE")/guard.sql"

# Static: public host without the gateway, rate-limited
if grep -q 'portcullis-auth@docker\|portcullis-groups@docker' "$COMPOSE"; then
  fail "a router uses the Portcullis gateway (Firefox's Sync requests carry no cookie)"
else
  pass "no gateway middlewares (auth.method custom, no native_login)"
fi
assert_compose_setting "$COMPOSE" traefik.http.routers.firefox-sync.tls.options 'public@file'
assert_compose_setting "$COMPOSE" traefik.http.routers.firefox-sync.middlewares 'rate-limit@file,security-headers@file'
assert_compose_setting "$COMPOSE" traefik.http.routers.firefox-sync-token.middlewares 'rate-limit-auth@file,security-headers@file'
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
if grep -q '^  method: custom' "$MANIFEST" && ! grep -q '^  native_login:' "$MANIFEST"; then
  pass "manifest: method custom without native_login (the gateway would break Firefox)"
else
  fail "manifest must be method custom without native_login"
fi
# The internet-facing server: same image as the migrations, runs none, app role.
IMG_APP=$(yq -r '.services["firefox-sync"].image' "$COMPOSE")
IMG_MIG=$(yq -r '.services["firefox-sync-migrate"].image' "$COMPOSE")
if [ "$IMG_APP" = "$IMG_MIG" ]; then
  pass "firefox-sync and firefox-sync-migrate run the same image"
else
  fail "image mismatch: $IMG_APP vs $IMG_MIG"
fi
if [ "$(yq -r '.services["firefox-sync"].environment.SYNC_TOKENSERVER__RUN_MIGRATIONS' "$COMPOSE")" = false ]; then
  pass "public server: SYNC_TOKENSERVER__RUN_MIGRATIONS false"
else
  fail "public server runs tokenserver migrations"
fi
URLS=$(yq -r '.services["firefox-sync"].environment | to_entries[] | select(.key | test("DATABASE_URL")) | .value' "$COMPOSE")
if [ "$(echo "$URLS" | grep -c '^postgres://firefoxsync_app:')" = 2 ]; then
  pass "public server connects as firefoxsync_app"
else
  fail "public server database URLs: $URLS"
fi
assert_compose_setting "$COMPOSE" FIREFOX_SYNC_ALLOWED_ACCOUNTS '\$\{FIREFOX_SYNC_ALLOWED_ACCOUNTS:-\}'
if grep -q 'BEFORE INSERT OR UPDATE OF email ON users' "$GUARD"; then
  pass "guard.sql: allowlist trigger on users"
else
  fail "guard.sql: allowlist trigger missing"
fi

# Shell env wins over --env-file: two listed accounts.
ALLOWED_A=0123456789abcdef0123456789abcdef
ALLOWED_B=fedcba9876543210fedcba9876543210
OUTSIDER=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export FIREFOX_SYNC_ALLOWED_ACCOUNTS="$ALLOWED_A, ${ALLOWED_B^^}"

compose_up "$APP_ID"
HOST="$PORTCULLIS_HOST_FIREFOX_SYNC"

for job in firefox-sync-migrate firefox-sync-init; do
  if RC=$(timeout 300 docker wait "portcullis-${job}-1" 2>/dev/null) && [ "$RC" = 0 ]; then
    pass "$job exited 0"
  else
    fail "$job did not finish successfully (rc=${RC:-none})"
    docker logs "portcullis-${job}-1" 2>&1 | tail -20 || true
  fi
done
docker logs "portcullis-firefox-sync-init-1" 2>&1 | grep 'portcullis-guard' || true

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:8000/__heartbeat__" 180 "$APP_ID"

db() {
  docker exec portcullis-firefox-sync-db-1 psql -X -U firefoxsync -d firefoxsync -tAc "$1" 2>&1
}
# Runs guard.sql as firefox-sync-init does, with another Allowed accounts value.
guard() {
  docker exec -i -e FIREFOX_SYNC_ALLOWED_ACCOUNTS="$1" -e "FIREFOX_SYNC_NODE_URL=https://$HOST" \
    -e FIREFOX_SYNC_APP_DB_PASSWORD \
    portcullis-firefox-sync-db-1 psql -X -q -t -v ON_ERROR_STOP=1 --single-transaction \
    -U firefoxsync -d firefoxsync -f - < "$GUARD" 2>&1
}
# A users row as the tokenserver's post_user writes it.
insert_user() {
  db "INSERT INTO users (service, email, generation, client_state, created_at, nodeid)
      SELECT s.id, '$1@api.accounts.firefox.com', 1, 'aaaa', 1, n.id FROM services s JOIN nodes n ON n.service = s.id
      WHERE s.service = 'sync-1.5' AND n.node = 'https://$HOST' RETURNING uid"
}

LIST=$(db "SELECT string_agg(uid, ',' ORDER BY uid) FROM sync_allowed_accounts")
if [ "$LIST" = "$ALLOWED_A,$ALLOWED_B" ]; then
  pass "allowlist = the setting (lowercased)"
  BY=$(db "SELECT DISTINCT added_by FROM sync_allowed_accounts")
  [ "$BY" = "Allowed accounts setting" ] && pass "rows in firefox-sync's sync_allowed_accounts layout (added_by)" \
    || fail "added_by: $BY"
else
  fail "allowlist: $LIST"
fi
NODE=$(db "SELECT count(*) FROM nodes WHERE node = 'https://$HOST' AND downed = 0 AND capacity = 2147483647")
[ "$NODE" = 1 ] && pass "sync node https://$HOST, capacity 2147483647" || fail "sync node missing or capacity not raised ($NODE)"

# The server's role can't touch the guard (socket connection as firefoxsync_app).
app_sql() {
  docker exec portcullis-firefox-sync-db-1 psql -X -U firefoxsync_app -d firefoxsync -tAc "$1" 2>&1
}
for stmt in "DROP TRIGGER portcullis_allowed_account ON users" \
            "ALTER TABLE users DISABLE TRIGGER ALL" \
            "SET session_replication_role = replica" \
            "INSERT INTO sync_allowed_accounts (uid, added_at, added_by) VALUES ('$OUTSIDER', 1, 'x')" \
            "DELETE FROM sync_allowed_accounts" \
            "DROP EVENT TRIGGER portcullis_app_no_ddl" \
            "CREATE FUNCTION public.split_part(varchar, text, integer) RETURNS text LANGUAGE sql AS \$\$ SELECT 'x' \$\$" \
            "CREATE TABLE public.portcullis_x (a int)"; do
  OUT=$(app_sql "$stmt" || true)
  if echo "$OUT" | grep -Eqi 'permission denied|must be owner|may not create|must be superuser'; then
    pass "firefoxsync_app refused: ${stmt:0:40}"
  else
    fail "firefoxsync_app could: $stmt -> $OUT"
  fi
done
OUT=$(app_sql "CREATE TABLE IF NOT EXISTS __diesel_schema_migrations (version VARCHAR(50) PRIMARY KEY NOT NULL, run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)" || true)
if echo "$OUT" | grep -qi 'error'; then
  fail "diesel's no-op migration check refused for firefoxsync_app: $OUT"
else
  pass "diesel's no-op migration check allowed for firefoxsync_app"
fi

OUT=$(insert_user "$OUTSIDER" || true)
if echo "$OUT" | grep -q "portcullis: Firefox account $OUTSIDER is not in the Allowed accounts setting"; then
  pass "an account not on the list gets no tokenserver row"
else
  fail "outsider row not refused: $OUT"
fi
OUT=$(insert_user "$ALLOWED_A" || true)
if echo "$OUT" | grep -Eq '^[0-9]+'; then
  pass "a listed account gets its row"
else
  fail "listed account refused: $OUT"
fi

# Fail closed: an invalid value aborts the transaction, the list stays.
OUT=$(guard "$ALLOWED_A,not-a-uid" || true)
if echo "$OUT" | grep -q 'portcullis: Allowed accounts: not-a-uid is not a Mozilla account uid'; then
  pass "invalid Allowed accounts value refused"
else
  fail "invalid value not refused: $OUT"
fi
[ "$(db "SELECT count(*) FROM sync_allowed_accounts")" = 2 ] && pass "refused run changed nothing" \
  || fail "refused run changed the allowlist"

# Removal: a start without the account deletes its rows; empty = nobody.
guard "$ALLOWED_B" > /dev/null
[ "$(db "SELECT count(*) FROM users")" = 0 ] && pass "removed account's tokenserver rows deleted" \
  || fail "removed account still has rows"
guard "" > /dev/null
OUT=$(insert_user "$ALLOWED_B" || true)
if echo "$OUT" | grep -q 'not in the Allowed accounts setting'; then
  pass "empty Allowed accounts: nobody"
else
  fail "empty list let an account in: $OUT"
fi
guard "$FIREFOX_SYNC_ALLOWED_ACCOUNTS" > /dev/null

# The tokenserver wants a Mozilla OAuth token; storage wants Hawk.
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:8000/1.0/sync/1.5" || echo 000)
[ "$CODE" = 401 ] && pass "GET /1.0/sync/1.5 without a token -> 401" || fail "GET /1.0/sync/1.5 without a token -> $CODE (expected 401)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer not-a-token' "http://${IP}:8000/1.0/sync/1.5" || echo 000)
[ "$CODE" = 401 ] && pass "GET /1.0/sync/1.5 with a bogus token -> 401" || fail "GET /1.0/sync/1.5 with a bogus token -> $CODE (expected 401)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:8000/1.5/1/info/collections" || echo 000)
[ "$CODE" = 401 ] && pass "storage without Hawk -> 401" || fail "storage without Hawk -> $CODE (expected 401)"

# Through Traefik, once healthy: public, no Keycloak redirect.
for _ in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${SERVICE}-1" 2>/dev/null)" = healthy ] && break
  sleep 3
done
out=$(via_traefik "$HOST" /__heartbeat__)
[ "${out%% *}" = 200 ] && pass "https://$HOST/__heartbeat__ -> 200 via Traefik" || fail "heartbeat via Traefik: $out"
out=$(via_traefik "$HOST" /1.0/sync/1.5)
if [ "${out%% *}" = 401 ] && ! echo "${out#* }" | grep -q "auth\.$DOMAIN"; then
  pass "tokenserver via Traefik -> 401 from the app (no Portcullis redirect)"
else
  fail "tokenserver via Traefik: $out"
fi

# No proxy body cap (see compose.yml): an oversized upload is answered by
# syncstorage-rs without being stored anywhere. Unauthenticated, the Hawk
# extractor refuses it before the body extractor runs; authenticated, the
# body extractors check Content-Length and stream-limit the read to
# max_request_bytes (2.5 MiB + 4 KiB) and answer 413 (upstream's unit tests).
OUT=$(head -c 67108864 /dev/zero | curl -sk -o /dev/null -w '%{http_code} %{time_total} %{size_upload}' --max-time 60 \
  -H 'Content-Type: application/json' -H 'Expect:' --data-binary @- \
  --resolve "$HOST:443:127.0.0.1" "https://$HOST/1.5/1/storage/bookmarks" 2>/dev/null || echo "000 0 0")
read -r CODE SECS SENT <<< "$OUT"
info "64 MiB POST through Traefik: HTTP $CODE in ${SECS}s, $SENT bytes sent"
if { [ "$CODE" = 401 ] || [ "$CODE" = 413 ]; } && awk "BEGIN{exit !($SECS < 15)}"; then
  pass "oversized unauthenticated upload refused by syncstorage-rs ($CODE) without a proxy cap"
else
  fail "oversized upload: HTTP $CODE in ${SECS}s"
fi

compose_down "$APP_ID"
