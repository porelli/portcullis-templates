#!/usr/bin/env bash
# Test: Firefox Sync (public host for Firefox's anonymous requests; only the
# Mozilla accounts of the Hub's allowlist.json data file get a tokenserver
# row: the uids access-group members entered, plus Other allowed accounts)
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
if [ "$(yq -r '.services["firefox-sync"].environment.SYNC_TOKENSERVER__INIT_NODE_URL // ""' "$COMPOSE")" = "" ]; then
  pass "public server creates no node (no INIT_NODE_URL; firefox-sync-migrate does)"
else
  fail "public server sets SYNC_TOKENSERVER__INIT_NODE_URL (needs INSERT on nodes)"
fi
if grep -q 'BEFORE INSERT OR UPDATE OF email ON users' "$GUARD"; then
  pass "guard.sql: allowlist trigger on users"
else
  fail "guard.sql: allowlist trigger missing"
fi
# Settings: who syncs is a person-entered uid (access-group members) plus an
# admin list, delivered as the data file the init reads at every start.
if [ "$(yq -r '.auth.access_group' "$MANIFEST")" = users_firefox-sync ] \
    && [ "$(yq -r '.auth.group_access' "$MANIFEST")" = false ]; then
  pass "manifest: access_group users_firefox-sync (who may enter a uid), group_access false"
else
  fail "manifest: access_group / group_access"
fi
if [ "$(yq -r '.files[] | select(.name == "allowlist") | [.service, .mount, .on_membership_change] | join("|")' "$MANIFEST")" = 'firefox-sync-init|/portcullis|restart' ]; then
  pass "files: allowlist -> firefox-sync-init at /portcullis, restart on membership change"
else
  fail "files: allowlist entry missing or changed"
fi
UID_OPT=$(yq -r '.settings.options[] | select(.key == "mozilla_uid") | [.type, .scope, .pattern, .unique, .admin_override, .applies, .delivery[0].file.name] | join("|")' "$MANIFEST")
if [ "$UID_OPT" = 'string|person_entered|^[0-9a-f]{32}$|true|true|restart|allowlist' ]; then
  pass "mozilla_uid: person_entered, unique, pattern, file allowlist"
else
  fail "mozilla_uid option: $UID_OPT"
fi
if grep -q 'FIREFOX_SYNC_ALLOWED_ACCOUNTS' "$COMPOSE" "$GUARD"; then
  fail "the old Allowed accounts env is still used"
else
  pass "no FIREFOX_SYNC_ALLOWED_ACCOUNTS env (the data file is the only source)"
fi
if [ "$(yq -r '.services["firefox-sync-init"].group_add[0]' "$COMPOSE")" = 10001 ] \
    && grep -q '^\\set allowlist_doc `cat /portcullis/allowlist.json`$' "$GUARD"; then
  pass "firefox-sync-init reads /portcullis/allowlist.json (group 10001)"
else
  fail "firefox-sync-init must read /portcullis/allowlist.json with group_add 10001"
fi

# The Hub's data file (contract §13.7): alice and bob entered a uid, one
# other account is listed by the admin.
ALLOWED_A=0123456789abcdef0123456789abcdef
ALLOWED_B=fedcba9876543210fedcba9876543210
ALLOWED_C=5d41402abc4b2a76b9719d911017c592
OUTSIDER=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
allowlist() {  # $1 = entries JSON array, $2 = extra_accounts JSON array, [$3 = instance]
  printf '{"version":1,"instance":"%s","values":{"extra_accounts":%s},"people":{},"groups":{},"entries":{"mozilla_uid":%s}}' \
    "${3:-firefox-sync}" "$2" "$1"
}
DOC=$(allowlist "[{\"user\":\"alice\",\"value\":\"$ALLOWED_A\"},{\"user\":\"bob\",\"value\":\"$ALLOWED_B\"}]" "[\"$ALLOWED_C\"]")
COMPOSE_OVERRIDE=$(mktemp)
export COMPOSE_OVERRIDE
write_appfiles_override "$APP_ID" allowlist "$DOC" "$COMPOSE_OVERRIDE"

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
# The next start of the init (same container, mounts and env as the Hub's
# restart gives it) with another allowlist.json; $1 = the file's content, or
# "-" for no file at all. Prints the init's output, returns its exit code.
guard() {
  if [ "$1" = - ]; then rm -f "$APPFILES_DIR/$APP_ID/allowlist/allowlist.json"
  else write_appfile "$APP_ID" allowlist "$1"; fi
  docker start -a portcullis-firefox-sync-init-1 2>&1
}
# As the public server connects (socket, role firefoxsync_app).
app_sql() {
  docker exec portcullis-firefox-sync-db-1 psql -X -U firefoxsync_app -d firefoxsync -tAc "$1" 2>&1
}
# A users row as the tokenserver's post_user writes it, as the server's role.
insert_user() {
  app_sql "INSERT INTO users (service, email, generation, client_state, created_at, nodeid)
      SELECT s.id, '$1@api.accounts.firefox.com', 1, 'aaaa', 1, n.id FROM services s JOIN nodes n ON n.service = s.id
      WHERE s.service = 'sync-1.5' AND n.node = 'https://$HOST' RETURNING uid"
}

LIST=$(db "SELECT string_agg(uid || '=' || added_by, ',' ORDER BY uid) FROM sync_allowed_accounts")
if [ "$LIST" = "$ALLOWED_A=alice,$ALLOWED_C=Other allowed accounts setting,$ALLOWED_B=bob" ]; then
  pass "allowlist = entries.mozilla_uid + values.extra_accounts (added_by = who entered it)"
else
  fail "allowlist: $LIST"
fi
NODE=$(db "SELECT count(*) FROM nodes WHERE node = 'https://$HOST' AND downed = 0 AND capacity = 2147483647")
[ "$NODE" = 1 ] && pass "sync node https://$HOST, capacity 2147483647" || fail "sync node missing or capacity not raised ($NODE)"

# The server's role can't touch the guard or what it doesn't need.
for stmt in "DROP TRIGGER portcullis_allowed_account ON users" \
            "ALTER TABLE users DISABLE TRIGGER ALL" \
            "SET session_replication_role = replica" \
            "SET event_triggers = off" \
            "UPDATE nodes SET node = 'https://evil.example'" \
            "UPDATE nodes SET capacity = 0" \
            "INSERT INTO nodes (service, node, available, current_load, capacity, downed, backoff) VALUES (1, 'https://evil.example', 1, 0, 1, 0, 0)" \
            "DELETE FROM users" \
            "UPDATE users SET uid = uid + 1000" \
            "UPDATE users SET email = 'x@api.accounts.firefox.com'" \
            "UPDATE users SET nodeid = 0" \
            "DELETE FROM __diesel_schema_migrations" \
            "INSERT INTO services (service, pattern) VALUES ('x', 'y')" \
            "SELECT setval('users_uid_seq', 1)" \
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
OUT=$(app_sql "UPDATE nodes SET current_load = current_load, available = available WHERE node = 'https://$HOST'; UPDATE users SET generation = generation, keys_changed_at = keys_changed_at, replaced_at = replaced_at WHERE false" || true)
if echo "$OUT" | grep -qi 'error'; then
  fail "firefoxsync_app can't update a node's load: $OUT"
else
  pass "firefoxsync_app may update a node's load and a user's generation / keys_changed_at / replaced_at"
fi
OUT=$(app_sql "CREATE TABLE IF NOT EXISTS __diesel_schema_migrations (version VARCHAR(50) PRIMARY KEY NOT NULL, run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)" || true)
if echo "$OUT" | grep -qi 'error'; then
  fail "diesel's no-op migration check refused for firefoxsync_app: $OUT"
else
  pass "diesel's no-op migration check allowed for firefoxsync_app"
fi

OUT=$(insert_user "$OUTSIDER" || true)
if echo "$OUT" | grep -q "portcullis: Firefox account $OUTSIDER is not on the allowlist"; then
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

OUT=$(insert_user "$ALLOWED_B" || true)
if echo "$OUT" | grep -Eq '^[0-9]+'; then pass "bob's entered account gets its row"; else fail "bob's account refused: $OUT"; fi

# Fail closed: a bad, unparsable, foreign or missing file stops the start
# (non-zero exit: the Sync server's depends_on keeps it down) and changes
# nothing.
for bad in "$(allowlist "[{\"user\":\"alice\",\"value\":\"not-a-uid\"}]" '[]')" \
           "$(allowlist "[{\"user\":\"alice\"}]" '[]')" \
           "$(allowlist '[]' "[\"${ALLOWED_C^^}\"]")" \
           "$(allowlist '{}' '[]')" \
           "$(allowlist '[]' '[]' other-instance)" \
           '{"version":2}' 'not json' '' -; do
  if OUT=$(guard "$bad"); then
    fail "init accepted allowlist.json '${bad:0:60}': $OUT"
  else
    pass "init refused allowlist.json '${bad:0:40}' (exit non-zero)"
  fi
done
[ "$(db "SELECT count(*) FROM sync_allowed_accounts")" = 3 ] && [ "$(db "SELECT count(*) FROM users")" = 2 ] \
  && pass "refused runs changed nothing" || fail "a refused run changed the allowlist or the users"

# Removal: alice left the access group (the Hub delivers her entry no more):
# at the next start her account loses its rows; empty = nobody.
if guard "$(allowlist "[{\"user\":\"bob\",\"value\":\"$ALLOWED_B\"}]" "[\"$ALLOWED_C\"]")" > /dev/null; then
  pass "init accepted the new allowlist"
else
  fail "init refused a valid allowlist"
fi
[ "$(db "SELECT count(*) FROM users WHERE email LIKE '$ALLOWED_A@%'")" = 0 ] \
  && [ "$(db "SELECT count(*) FROM users WHERE email LIKE '$ALLOWED_B@%'")" = 1 ] \
  && pass "uid removed from the file: its tokenserver rows deleted, the others kept" \
  || fail "removed uid still has rows, or another lost them"
guard "$(allowlist null null)" > /dev/null || fail "init refused an empty allowlist (null lists)"
[ "$(db "SELECT count(*) FROM users")" = 0 ] && pass "empty allowlist: every row deleted" || fail "rows left with an empty allowlist"
OUT=$(insert_user "$ALLOWED_B" || true)
if echo "$OUT" | grep -q 'not on the allowlist'; then
  pass "empty allowlist: nobody"
else
  fail "empty list let an account in: $OUT"
fi
guard "$DOC" > /dev/null || fail "init refused the original allowlist"

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
rm -rf "$COMPOSE_OVERRIDE" "$APPFILES_DIR"
