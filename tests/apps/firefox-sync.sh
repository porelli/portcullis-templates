#!/usr/bin/env bash
# Test: Firefox Sync (public host for Firefox's anonymous requests; only the
# Mozilla accounts of the Hub's allowlist.json data file get a tokenserver
# row: the uids access-group members entered, plus Other allowed accounts),
# and its admin UI on a host of its own behind Portcullis sign-in,
# the admin group and its own OpenID Connect sign-in
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="firefox-sync"
section "Firefox Sync"

APP_ID=firefox-sync
SERVICE=firefox-sync

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
GUARD="$(dirname "$COMPOSE")/guard.sql"

# Static: the sync host without the gateway, rate-limited; the gateway only
# on the admin host's router.
ADMIN_SVC=firefox-sync-admin
SYNC_HOST_ROUTERS=$(yq -r '[.services[].labels // {} | to_entries[] | select(.key | test("^traefik[.]http[.]routers[.][^.]+[.]rule$"))
  | select(.value | test("PORTCULLIS_HOST_FIREFOX_SYNC:-")) | .key | capture("routers[.](?<r>[^.]+)[.]rule").r] | sort | join(" ")' "$COMPOSE")
if [ "$SYNC_HOST_ROUTERS" = "firefox-sync firefox-sync-root firefox-sync-token" ]; then
  pass "sync host routers: firefox-sync, firefox-sync-root (exactly /), firefox-sync-token"
else
  fail "sync host routers: $SYNC_HOST_ROUTERS"
fi
for r in $SYNC_HOST_ROUTERS; do
  MW=$(yq -r "[.services[].labels // {} | .[\"traefik.http.routers.$r.middlewares\"] | select(. != null)] | .[0]" "$COMPOSE")
  TLS=$(yq -r "[.services[].labels // {} | .[\"traefik.http.routers.$r.tls.options\"] | select(. != null)] | .[0]" "$COMPOSE")
  if echo "$MW" | grep -q 'portcullis-'; then
    fail "sync host router $r uses the Portcullis gateway ($MW): Firefox's Sync requests carry no cookie"
  elif [ "$TLS" != public@file ]; then
    fail "sync host router $r: tls.options $TLS (Firefox presents no client certificate)"
  else
    pass "sync host router $r: no gateway, public@file ($MW)"
  fi
done
assert_compose_setting "$COMPOSE" traefik.http.routers.firefox-sync-root.rule \
  'Host\(`\$\{PORTCULLIS_HOST_FIREFOX_SYNC:-firefox-sync\.portcullis\.local\}`\) && Path\(`/`\)'
assert_compose_setting "$COMPOSE" traefik.http.middlewares.firefox-sync-root-redirect.redirectregex.replacement \
  'https://\$\{PORTCULLIS_HOST_FIREFOX_SYNC_ADMIN:-firefox-sync-admin\.portcullis\.local\}/'
assert_compose_setting "$COMPOSE" traefik.http.routers.firefox-sync-admin.rule \
  'Host\(`\$\{PORTCULLIS_HOST_FIREFOX_SYNC_ADMIN:-firefox-sync-admin\.portcullis\.local\}`\)'
assert_compose_setting "$COMPOSE" traefik.http.routers.firefox-sync-admin.middlewares \
  'client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file'
assert_compose_setting "$COMPOSE" traefik.http.routers.firefox-sync.tls.options 'public@file'
assert_compose_setting "$COMPOSE" traefik.http.routers.firefox-sync.middlewares 'rate-limit@file,security-headers@file'
assert_compose_setting "$COMPOSE" traefik.http.routers.firefox-sync-token.middlewares 'rate-limit-auth@file,security-headers@file'
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
if grep -q '^  method: custom' "$MANIFEST" && ! grep -q '^  native_login:' "$MANIFEST"; then
  pass "manifest: method custom without native_login (the gateway would break Firefox)"
else
  fail "manifest must be method custom without native_login"
fi
# The admin host: group-gate requires the admin group on every path (the
# Hub publishes path_groups from admin_paths), and the admin UI admits only
# that group, by the groups claim of its OIDC sign-in.
ADMIN_GROUP_M=$(yq -r '.auth.admin_group' "$MANIFEST")
if [ "$(yq -r '.auth.admin_paths | join(",")' "$MANIFEST")" = / ] && [ "$ADMIN_GROUP_M" = admin_firefox-sync ]; then
  pass "manifest: admin_paths [/] with admin_group $ADMIN_GROUP_M (group-gate on every admin-host path)"
else
  fail "manifest: admin_paths / admin_group"
fi
ADMIN_ENV() { yq -r ".services[\"$ADMIN_SVC\"].environment.$1 // \"<unset>\"" "$COMPOSE"; }
[ "$(ADMIN_ENV ADMIN_PASSWORD)" = "" ] && pass "admin UI: ADMIN_PASSWORD empty (no password sign-in)" \
  || fail "admin UI: ADMIN_PASSWORD is $(ADMIN_ENV ADMIN_PASSWORD | head -c 3)..."
for k in ADMIN_AUTH_HEADER ADMIN_AUTH_GROUPS_HEADER ADMIN_TRUSTED_PROXIES ADMIN_ALLOWED_USERS ALERT_EMAIL SMTP_HOST ADMIN_NOTIFY; do
  case "$(ADMIN_ENV "$k")" in ""|"<unset>") pass "admin UI: $k empty" ;; *) fail "admin UI: $k is set" ;; esac
done
[ "$(ADMIN_ENV ADMIN_ALLOWED_GROUPS)" = '${PORTCULLIS_ADMIN_GROUP:-admin_firefox-sync}' ] \
  && pass "admin UI: ADMIN_ALLOWED_GROUPS = the instance's admin group" || fail "admin UI: ADMIN_ALLOWED_GROUPS $(ADMIN_ENV ADMIN_ALLOWED_GROUPS)"
[ "$(ADMIN_ENV ADMIN_OIDC_ISSUER)" = 'https://auth.${PORTCULLIS_DOMAIN:-portcullis.local}/realms/portcullis' ] \
  && [ "$(ADMIN_ENV ADMIN_OIDC_GROUPS_CLAIM)" = groups ] && [ "$(ADMIN_ENV ADMIN_OIDC_TRUST_UNVERIFIED_EMAIL)" = false ] \
  && pass "admin UI: issuer Portcullis's realm, groups claim, unverified email not trusted" \
  || fail "admin UI: OIDC issuer / groups claim / unverified email setting"
# The redirect URI the admin UI sends is exactly the client's registered one.
REG_URI=$(yq -r '.keycloak_clients[] | select(.client_id == "firefox-sync-admin") | .redirect_uri' "$MANIFEST")
if [ "$REG_URI" = 'https://{{HOST_FIREFOX_SYNC_ADMIN}}/auth/callback' ] \
    && [ "$(yq -r '.keycloak_clients[] | select(.client_id == "firefox-sync-admin") | .redirect_uris // "none"' "$MANIFEST")" = none ] \
    && [ "$(ADMIN_ENV ADMIN_OIDC_REDIRECT_URL)" = 'https://${PORTCULLIS_HOST_FIREFOX_SYNC_ADMIN:-firefox-sync-admin.portcullis.local}/auth/callback' ]; then
  pass "OIDC client firefox-sync-admin: one redirect URI, https://<admin host>/auth/callback, = ADMIN_OIDC_REDIRECT_URL"
else
  fail "OIDC redirect URI: manifest $REG_URI vs compose $(ADMIN_ENV ADMIN_OIDC_REDIRECT_URL)"
fi
if [ "$(yq -r ".services[\"$ADMIN_SVC\"].ports // [] | length" "$COMPOSE")" = 0 ]; then
  pass "admin UI: no published port"
else
  fail "admin UI publishes a port"
fi
# Access managed elsewhere: in the admin UI and porelli's init, which gets no
# list and no limit of its own and runs as the owner (no app role to hand
# the tables to).
DBI() { yq -r ".services[\"firefox-sync-db-init\"].environment.$1 // \"<unset>\"" "$COMPOSE"; }
if [ "$(ADMIN_ENV ADMIN_ACCESS_EXTERNAL)" = 1 ] && [ "$(DBI ADMIN_ACCESS_EXTERNAL)" = 1 ] \
    && [ "$(ADMIN_ENV SYNC_ALLOWED_ACCOUNTS)" = "" ] && [ "$(DBI SYNC_ALLOWED_ACCOUNTS)" = "" ] \
    && [ "$(DBI MAX_USERS)" = unlimited ] && [ "$(DBI POSTGRES_SYNC_USER)" = "" ]; then
  pass "ADMIN_ACCESS_EXTERNAL=1 in the admin UI and firefox-sync-db-init; no SYNC_ALLOWED_ACCOUNTS, MAX_USERS unlimited, no app role as owner"
else
  fail "access managed elsewhere settings of the admin UI / firefox-sync-db-init"
fi
if [ "$(yq -r '.services["firefox-sync-init"].depends_on | keys | join(",")' "$COMPOSE")" = firefox-sync-db-init ] \
    && [ "$(yq -r '.services["firefox-sync-db-init"].depends_on | keys | join(",")' "$COMPOSE")" = firefox-sync-migrate ]; then
  pass "order: firefox-sync-migrate, firefox-sync-db-init (porelli's), firefox-sync-init (guard.sql)"
else
  fail "init order"
fi
# The internet-facing server: same image as the migrations, runs none, app role.
IMG_APP=$(yq -r '.services["firefox-sync"].image' "$COMPOSE")
IMG_MIG=$(yq -r '.services["firefox-sync-migrate"].image' "$COMPOSE")
if [ "$IMG_APP" = "$IMG_MIG" ] && [[ "$IMG_APP" == *:syncstorage-rs-postgres-0.25.2@sha256:* ]]; then
  pass "firefox-sync and firefox-sync-migrate run the same image (syncstorage-rs 0.25.2)"
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
ADMIN_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_ADMIN"

for job in firefox-sync-migrate firefox-sync-db-init firefox-sync-init; do
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

# No role but the owner may run porelli's allowlist functions or write the
# allowlist: after both inits, and after a start the guard refused.
PRIV_SQL="SELECT count(DISTINCT p.proname) || ':' || COALESCE(bool_or(has_function_privilege(r, p.oid, 'EXECUTE')), false)
  || ':' || bool_or(has_table_privilege(r, 'public.sync_allowed_accounts', 'INSERT,UPDATE,DELETE,TRUNCATE'))
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'public',
       unnest(ARRAY['firefoxsync_admin', 'firefoxsync_admin_sync', 'firefoxsync_app', 'public']) r
  WHERE p.proname IN ('ffs_allow_account', 'ffs_remove_allowed_account', 'ffs_reject_account')"
priv_check() {  # $1 = when
  local out
  out=$(db "$PRIV_SQL")
  [ "$out" = "3:false:false" ] && pass "$1: no admin role, app role or PUBLIC may run ffs_allow_account / ffs_remove_allowed_account / ffs_reject_account or write sync_allowed_accounts" \
    || fail "$1: allowlist privileges $out (want 3:false:false: functions found, none executable, no write)"
}
priv_check "after both inits"
# porelli's init grants them again; then an invalid allowlist.json: the
# guard refuses, revoke.sql has already taken them back, and the Sync
# server and the admin UI don't start.
docker stop portcullis-firefox-sync-1 "portcullis-${ADMIN_SVC}-1" > /dev/null 2>&1 || true
write_appfile "$APP_ID" allowlist "$(allowlist "[{\"user\":\"alice\",\"value\":\"not-a-uid\"}]" '[]')"
compose_up "$APP_ID" || true
RC=$(docker inspect -f '{{.State.ExitCode}}' portcullis-firefox-sync-init-1 2>/dev/null || echo none)
RUN="$(docker inspect -f '{{.State.Running}}' portcullis-firefox-sync-1 2>/dev/null) $(docker inspect -f '{{.State.Running}}' "portcullis-${ADMIN_SVC}-1" 2>/dev/null)"
[ "$RC" != 0 ] && [ "$RUN" = "false false" ] && pass "invalid allowlist.json: firefox-sync-init exit $RC, the Sync server and the admin UI stay stopped" \
  || fail "invalid allowlist.json: init exit $RC, running (sync admin): $RUN"
priv_check "after a start with an invalid allowlist.json"
write_appfile "$APP_ID" allowlist "$DOC"
compose_up "$APP_ID"
for job in firefox-sync-db-init firefox-sync-init; do
  RC=$(timeout 300 docker wait "portcullis-${job}-1" 2>/dev/null || echo none)
  [ "$RC" = 0 ] || fail "$job after the restore: exit $RC"
done
IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:8000/__heartbeat__" 180 "$APP_ID"
priv_check "after the restart with the valid allowlist.json"

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

# The admin UI's roles (guard.sql, admin-db.sql): the trigger stays in force.
admin_sql() {  # $1 = role, $2 = database, $3 = statement (socket, as the admin UI connects)
  docker exec portcullis-firefox-sync-db-1 psql -X -U "$1" -d "$2" -tAc "$3" 2>&1
}
for stmt in "DROP TRIGGER portcullis_allowed_account ON users" \
            "ALTER TABLE users DISABLE TRIGGER ALL" \
            "SET session_replication_role = replica" \
            "CREATE TRIGGER x BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION public.portcullis_check_allowed_account()" \
            "INSERT INTO sync_allowed_accounts (uid, added_at, added_by) VALUES ('$OUTSIDER', 1, 'x')" \
            "UPDATE sync_allowed_accounts SET added_by = 'x'" \
            "DELETE FROM sync_allowed_accounts" \
            "INSERT INTO users (service, email, generation, client_state, created_at, nodeid) VALUES (1, '$OUTSIDER@api.accounts.firefox.com', 1, 'a', 1, 1)" \
            "UPDATE users SET email = '$OUTSIDER@api.accounts.firefox.com'" \
            "UPDATE nodes SET capacity = 0" \
            "DELETE FROM nodes" \
            "CREATE TABLE public.portcullis_x (a int)" \
            "UPDATE config SET config_value = '0' WHERE config_key = 'max_users'" \
            "SELECT ffs_allow_account('$OUTSIDER', 'x', 'x')" \
            "SELECT ffs_remove_allowed_account('$ALLOWED_A')" \
            "SELECT ffs_reject_account('$OUTSIDER', 'x')" \
            "CREATE FUNCTION public.split_part(varchar, text, integer) RETURNS text LANGUAGE sql AS \$\$ SELECT 'x' \$\$"; do
  OUT=$(admin_sql firefoxsync_admin_sync firefoxsync "$stmt" || true)
  if echo "$OUT" | grep -Eqi 'permission denied|must be owner'; then
    pass "firefoxsync_admin_sync refused: ${stmt:0:40}"
  else
    fail "firefoxsync_admin_sync could: $stmt -> $OUT"
  fi
done
OUT=$(admin_sql firefoxsync_admin_sync firefoxsync "SELECT count(*) FROM sync_allowed_accounts; DELETE FROM bsos WHERE false; DELETE FROM users WHERE false" || true)
if echo "$OUT" | grep -qi 'error'; then
  fail "firefoxsync_admin_sync can't read the allowlist or delete Sync rows: $OUT"
else
  pass "firefoxsync_admin_sync reads the Sync data (the allowlist too) and may delete users / storage rows"
fi
for who in "firefoxsync_admin firefoxsync" "firefoxsync_app firefoxsync_admin" "firefoxsync_admin_sync firefoxsync_admin"; do
  set -- $who
  OUT=$(admin_sql "$1" "$2" "SELECT 1" || true)
  if echo "$OUT" | grep -qi 'permission denied for database'; then
    pass "$1 may not connect to $2"
  else
    fail "$1 connects to $2: $OUT"
  fi
done
for stmt in "UPDATE config SET config_value = '0' WHERE config_key = 'max_users'" \
            "INSERT INTO sync_refused_accounts (uid, first_at, last_at) VALUES ('x', 1, 1)" \
            "SELECT ffs_allow_account('$OUTSIDER', 'x', 'x')"; do
  OUT=$(app_sql "$stmt" || true)
  if echo "$OUT" | grep -Eqi 'permission denied'; then pass "firefoxsync_app refused: ${stmt:0:40}"; else fail "firefoxsync_app could: $stmt -> $OUT"; fi
done
TRIGGERS=$(db "SELECT string_agg(tgname, ',' ORDER BY tgname) FROM pg_trigger WHERE tgrelid = 'public.users'::regclass AND NOT tgisinternal")
[ "$TRIGGERS" = before_insert_user,portcullis_allowed_account ] \
  && pass "users triggers: porelli's max-users (before_insert_user) and guard.sql's portcullis_allowed_account, no before_insert_allowed_user" \
  || fail "users triggers: $TRIGGERS"
CONF=$(db "SELECT string_agg(config_key || '=' || config_value, ',' ORDER BY config_key) FROM config WHERE config_key IN ('allowed_accounts', 'max_users')")
[ "$CONF" = "allowed_accounts=external,max_users=unlimited" ] && pass "config: $CONF (porelli's init, access managed elsewhere)" || fail "config: $CONF"
# Both inits again, in their order: ours still wins (an unlisted uid refused).
docker start -a portcullis-firefox-sync-db-init-1 > /dev/null 2>&1 && pass "firefox-sync-db-init ran again" || fail "firefox-sync-db-init failed on a second start"
guard "$DOC" > /dev/null || fail "init refused the original allowlist after firefox-sync-db-init"
OUT=$(insert_user "$OUTSIDER" || true)
echo "$OUT" | grep -q "portcullis: Firefox account $OUTSIDER is not on the allowlist" \
  && pass "after both inits: an unlisted account gets no tokenserver row" || fail "after both inits, outsider: $OUT"
[ "$(db "SELECT count(*) FROM sync_allowed_accounts")" = 3 ] && pass "after both inits: the allowlist is Portcullis's (3 rows)" || fail "allowlist rows after both inits"
# A deleted account (the admin UI's reset / delete) comes back only through
# the trigger: its next row is checked against the allowlist again.
insert_user "$ALLOWED_A" > /dev/null || true
OUT=$(admin_sql firefoxsync_admin_sync firefoxsync "DELETE FROM users WHERE email LIKE '$ALLOWED_A@%'" || true)
if echo "$OUT" | grep -q '^DELETE [1-9]'; then pass "admin reader deleted alice's tokenserver row (reset)"; else fail "reset: $OUT"; fi
OUT=$(insert_user "$ALLOWED_A" || true)
echo "$OUT" | grep -Eq '^[0-9]+' && pass "listed account after a reset: a new row, through the trigger" || fail "listed account refused after reset: $OUT"
[ "$(db "SELECT count(*) FROM sync_allowed_accounts")" = 3 ] && pass "a reset leaves the allowlist untouched" || fail "a reset changed the allowlist"

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
# Traefik adds the router only once it has seen the container healthy
# (its docker provider, a moment after the health status flips): retry
# while it still answers 404 / 502 / no answer.
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /__heartbeat__)
  case "${out%% *}" in 000|404|502) sleep 1 ;; *) break ;; esac
done
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

# Firefox's other endpoints, anonymous through Traefik: answered by
# syncstorage-rs itself, never sent to Keycloak.
for p in /__lbheartbeat__ /__version__; do
  out=$(via_traefik "$HOST" "$p")
  [ "${out%% *}" = 200 ] && pass "https://$HOST$p -> 200 via Traefik, anonymous" || fail "$p via Traefik: $out"
done
out=$(via_traefik "$HOST" /1.5/1/info/collections)
if [ "${out%% *}" = 401 ] && ! echo "${out#* }" | grep -q "auth\.$DOMAIN"; then
  pass "storage via Traefik -> 401 from the app (no Portcullis redirect)"
else
  fail "storage via Traefik: $out"
fi

# ── Admin UI ──
for _ in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${ADMIN_SVC}-1" 2>/dev/null)" = healthy ] && break
  sleep 3
done
docker logs "portcullis-${ADMIN_SVC}-1" 2>&1 | tail -5 || true
# Exactly / of the sync host: a redirect to the admin host; the sync host
# never serves the admin UI.
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /)
  case "${out%% *}" in 000|404|502) sleep 1 ;; *) break ;; esac
done
[ "$out" = "302 https://$ADMIN_HOST/" ] && pass "https://$HOST/ -> 302 https://$ADMIN_HOST/" || fail "sync host /: $out"
out=$(via_traefik "$HOST" /login)
[ "${out%% *}" = 404 ] && pass "sync host /login -> 404 (syncstorage-rs, not the admin UI)" || fail "sync host /login: $out"
# Unauthenticated, or with forged identity headers: Portcullis sign-in,
# never the admin UI (forward-auth replaces every identity header).
assert_gated_path "$ADMIN_HOST" /
assert_gated_path "$ADMIN_HOST" /users/1
assert_gated_path "$ADMIN_HOST" /auth/callback
assert_gated_path "$ADMIN_HOST" / -H 'X-Forwarded-User: e2eadmin' -H 'X-Auth-Request-User: e2eadmin' \
  -H 'X-Auth-Request-Preferred-Username: e2eadmin' -H "X-Auth-Request-Groups: $ADMIN_GROUP_M,lldap_admin" \
  -H 'X-Auth-Request-Email: e2eadmin@example.org' -H 'Remote-Email: e2eadmin@example.org' -H "Remote-Groups: $ADMIN_GROUP_M"
out=$(via_traefik "$ADMIN_HOST" /login -X POST -d 'password=aaaaaaaaaaaaaaaa')
if echo "${out#* }" | grep -q "auth\.$DOMAIN" || [ "${out%% *}" = 401 ]; then
  pass "POST https://$ADMIN_HOST/login unauthenticated -> ${out%% *} from Portcullis (never the admin UI)"
else
  fail "POST https://$ADMIN_HOST/login unauthenticated -> $out"
fi
# Straight to the admin UI (past Traefik): forged headers sign nobody in, and
# there is no password sign-in.
AIP=$(app_container_ip "$APP_ID" "$ADMIN_SVC")
CODE=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'X-Forwarded-User: e2eadmin' -H 'X-Auth-Request-Preferred-Username: e2eadmin' \
  -H "X-Auth-Request-Groups: $ADMIN_GROUP_M" -H 'Remote-Email: e2eadmin@example.org' -H "Remote-Groups: $ADMIN_GROUP_M" \
  "http://${AIP}:8080/" || echo 000)
[[ "$CODE" == "303 "*"/login" ]] && pass "admin UI with forged identity headers -> $CODE (not signed in)" || fail "admin UI with forged identity headers -> $CODE"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -d 'password=aaaaaaaaaaaaaaaa' "http://${AIP}:8080/login" || echo 000)
[ "$CODE" = 403 ] && pass "admin UI: POST /login -> 403 (no password sign-in)" || fail "admin UI: POST /login -> $CODE (expected 403)"
if curl -s "http://${AIP}:8080/login" | grep -q 'type="password"'; then
  fail "admin UI login page has a password form"
else
  pass "admin UI login page: no password form"
fi

# group-gate on the admin host, with the policy the Hub publishes from
# auth.admin_paths: a signed-in member of the access group (not the admin
# group) is refused on every path; a member of the admin group passes.
VER=$(policy_version)
ADMIN_PREFIXES=$(yq -o=json '.auth.admin_paths' "$MANIFEST")
_policy_base "$VER" | jq --arg h "$ADMIN_HOST" --arg g "$ADMIN_GROUP_M" --argjson p "$ADMIN_PREFIXES" \
  '.path_groups = {($h): ($p | map({prefix: ., group: $g}))}' | _hub_data_write
gate_probe() {  # $1 user, $2 groups, $3 path: group-gate's answer to forward-auth
  docker exec -i portcullis-group-gate-1 python3 - "$ADMIN_HOST" "$@" <<'PY'
import base64, json, sys, urllib.error, urllib.request
host, user, groups, path = sys.argv[1:5]
b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
token = b64({"alg": "none", "typ": "JWT"}) + "." + b64({"preferred_username": user, "amr": ["hwk"]}) + "."
req = urllib.request.Request("http://127.0.0.1:8080/", headers={
    "X-Forwarded-Host": host, "X-Forwarded-Uri": path, "X-Forwarded-Method": "GET", "X-Forwarded-Proto": "https",
    "X-Auth-Request-Preferred-Username": user, "X-Auth-Request-User": user, "X-Auth-Request-Groups": groups,
    "X-Forwarded-Access-Token": token})
try:
    print(urllib.request.urlopen(req, timeout=10).status)
except urllib.error.HTTPError as e:
    body = e.read().decode(errors="replace")
    part = "path-group-denied" if "not authorized to access this part" in body else "other"
    print(e.code, part, " ".join(body.split())[-300:])
PY
}
for path in / /users/1 /auth/callback /%61uth/login; do
  OUT=$(gate_probe e2emember users_firefox-sync "$path" || true)
  if [[ "$OUT" == "403 path-group-denied "* ]]; then
    pass "group-gate: e2emember (users_firefox-sync only) refused on $ADMIN_HOST$path"
  else
    fail "group-gate: e2emember on $ADMIN_HOST$path -> $OUT"
  fi
done
OUT=$(gate_probe e2eoutsider "" / || true)
[[ "$OUT" == "403 "* ]] && pass "group-gate: e2eoutsider (no group) refused" || fail "group-gate: e2eoutsider -> $OUT"
OUT=$(gate_probe e2eadmin "users_firefox-sync,$ADMIN_GROUP_M" / || true)
[ "$OUT" = 200 ] && pass "group-gate: e2eadmin ($ADMIN_GROUP_M) passes" || fail "group-gate: e2eadmin -> $OUT"
clear_public_policy

# The admin UI's own sign-in: discovery at Portcullis's issuer (through
# Traefik, trusting Portcullis's CA), then Keycloak, with exactly the
# redirect URI the Hub registers for the client (keycloak_clients).
REDIRECT="https://$ADMIN_HOST/auth/callback"
LOC=""
for _ in $(seq 1 20); do
  LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://${AIP}:8080/auth/login" || true)
  case "$LOC" in "https://auth.$DOMAIN/"*) break ;; *) sleep 3 ;; esac
done
ENC=$(jq -rn --arg u "$REDIRECT" '$u | @uri')
if [[ "$LOC" == "https://auth.$DOMAIN/realms/portcullis/protocol/openid-connect/auth?"* ]] \
    && echo "$LOC" | grep -q "redirect_uri=$ENC\(&\|$\)" && echo "$LOC" | grep -q 'client_id=firefox-sync-admin\(&\|$\)' \
    && echo "$LOC" | grep -q 'code_challenge_method=S256'; then
  pass "admin UI /auth/login -> Keycloak, client firefox-sync-admin, redirect_uri $REDIRECT, PKCE S256"
else
  fail "admin UI /auth/login -> ${LOC:-<none>} (discovery of https://auth.$DOMAIN/realms/portcullis failed?)"
fi
# Register the client as the Hub does (redirect URI from keycloak_clients),
# then Keycloak must accept the admin UI's request and refuse any other
# redirect URI.
KC_TOKEN=$(keycloak_admin_token)
CLIENT_SECRET="$FIREFOX_SYNC_ADMIN_OIDC_SECRET"
jq -n --arg uri "$(echo "$REG_URI" | sed "s|{{HOST_FIREFOX_SYNC_ADMIN}}|$ADMIN_HOST|")" --arg s "$CLIENT_SECRET" \
  '{clientId: "firefox-sync-admin", name: "Firefox Sync admin UI", enabled: true, protocol: "openid-connect",
    publicClient: false, secret: $s, redirectUris: [$uri], standardFlowEnabled: true, directAccessGrantsEnabled: false,
    defaultClientScopes: ["openid", "profile", "email", "acr", "groups"]}' \
  | curl -s -o /dev/null -w '%{http_code}\n' -X POST "$KEYCLOAK_URL/admin/realms/portcullis/clients" \
      -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") -H 'Content-Type: application/json' -d @- \
  | grep -Eq '^(201|409)$' && pass "Keycloak client firefox-sync-admin registered (as the Hub does)" || fail "could not register the Keycloak client"
AUTH_PATH="/${LOC#https://auth.$DOMAIN/}"
# Keycloak's answer to a bad client or redirect URI is its error page
# ("Invalid parameter: redirect_uri", "Client not found"); a good request
# gets Portcullis's sign-in flow (an anonymous browser: its login page).
kc_page() { curl -sk --max-time 15 --resolve "auth.$DOMAIN:443:127.0.0.1" "https://auth.$DOMAIN$1" 2>/dev/null || true; }
KC_ERR='Invalid parameter: redirect_uri|Client not found|Invalid redirect uri|invalid_redirect_uri|unauthorized_client'
PAGE=$(kc_page "$AUTH_PATH")
if [ -n "$PAGE" ] && ! echo "$PAGE" | grep -Eqi "$KC_ERR"; then
  pass "Keycloak accepts the admin UI's authorization request (client and registered redirect URI; sign-in page shown)"
else
  fail "Keycloak refused the admin UI's authorization request: $(echo "$PAGE" | grep -Eoi "$KC_ERR" | head -1)"
  info "client: $(curl -s "$KEYCLOAK_URL/admin/realms/portcullis/clients?clientId=firefox-sync-admin" \
    -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") | jq -c '.[0] | {redirectUris, defaultClientScopes, enabled}')"
  info "request: ${AUTH_PATH%%&state=*}"
fi
BAD_PATH=$(echo "$AUTH_PATH" | sed "s|redirect_uri=$ENC|redirect_uri=$(jq -rn --arg u "https://$HOST/auth/callback" '$u | @uri')|")
if [ "$BAD_PATH" != "$AUTH_PATH" ] && kc_page "$BAD_PATH" | grep -Eqi "$KC_ERR"; then
  pass "Keycloak refuses another redirect URI (the sync host's): invalid redirect_uri"
else
  fail "Keycloak did not refuse another redirect URI"
fi
CID=$(curl -s "$KEYCLOAK_URL/admin/realms/portcullis/clients?clientId=firefox-sync-admin" \
  -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") | jq -r '.[0].id // empty')
[ -n "$CID" ] && curl -s -o /dev/null -X DELETE "$KEYCLOAK_URL/admin/realms/portcullis/clients/$CID" \
  -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN")

# Access managed elsewhere, as the admin UI shows and enforces it. The real
# container has no password sign-in, so a probe of the same image and
# environment with a test password instead of OIDC (secrets in files, never
# argv) signs in and tries the changes.
PROBE_DIR=$(mktemp -d); chmod 700 "$PROBE_DIR"
openssl rand -hex 16 | tr -d '\n' > "$PROBE_DIR/pw"
docker inspect "portcullis-${ADMIN_SVC}-1" --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep -v -E '^(ADMIN_OIDC_[A-Z_]*|ADMIN_PASSWORD|ADMIN_ALLOWED_GROUPS|PATH|HOME)=' > "$PROBE_DIR/env"
{ printf 'ADMIN_PASSWORD=%s\n' "$(cat "$PROBE_DIR/pw")"; echo ADMIN_INSECURE_COOKIE=1; } >> "$PROBE_DIR/env"
PNET=$(docker inspect portcullis-firefox-sync-db-1 --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' | awk '{print $1}')
docker run -d --name portcullis-fxadmin-probe --network "$PNET" --read-only --tmpfs /tmp --cap-drop ALL \
  --env-file "$PROBE_DIR/env" "$(docker inspect -f '{{.Config.Image}}' "portcullis-${ADMIN_SVC}-1")" > /dev/null
rm -f "$PROBE_DIR/env"
for _ in $(seq 1 30); do [ "$(docker inspect -f '{{.State.Health.Status}}' portcullis-fxadmin-probe 2>/dev/null)" = healthy ] && break; sleep 2; done
PIP=$(docker inspect portcullis-fxadmin-probe --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' | awk '{print $1}')
PB="http://$PIP:8080"; JAR="$PROBE_DIR/jar"
CODE=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{http_code} %{redirect_url}' --data-urlencode "password@$PROBE_DIR/pw" "$PB/login" || echo 000)
[ "$CODE" = "303 $PB/" ] && info "probe signed in" || fail "admin UI probe sign-in: $CODE"
PAGE=$(curl -s -c "$JAR" -b "$JAR" "$PB/" | sed 's/<[^>]*>/ /g' | tr -s ' \n' ' ')
echo "$PAGE" | grep -q 'Access managed elsewhere' && echo "$PAGE" | grep -q 'Who may sync managed elsewhere' \
  && pass "admin UI overview: Access managed elsewhere, Who may sync managed elsewhere" || fail "admin UI shows no Access managed elsewhere"
echo "$PAGE" | grep -q 'Access managed elsewhere ok' && pass "admin UI setup check Access managed elsewhere: ok (the init agrees)" \
  || fail "admin UI setup check Access managed elsewhere not ok"
CSRF=$(curl -s -c "$JAR" -b "$JAR" "$PB/" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
for form in "/sync/max-users max_users=1" "/sync/allowlist/allow uid=$OUTSIDER" "/sync/allowlist/remove uid=$ALLOWED_A"; do
  set -- $form
  RESP=$(curl -s -L -c "$JAR" -b "$JAR" -w '\n%{http_code} %{url_effective}' -d "csrf=$CSRF&$2" "$PB$1" || true)
  if echo "$RESP" | grep -q 'managed outside the admin UI (ADMIN_ACCESS_EXTERNAL): nothing changed here'; then
    pass "admin UI refuses POST $1 (managed outside the admin UI)"
  else
    fail "admin UI did not refuse POST $1 (csrf ${#CSRF} chars; last: $(echo "$RESP" | tail -1); $(echo "$RESP" | sed 's/<[^>]*>/ /g' | tr -s ' \n' ' ' | grep -o -i -E '.{0,60}(fail|refus|error|session|not )[^.]{0,80}' | head -2 | tr '\n' ' '))"
    docker logs portcullis-fxadmin-probe 2>&1 | tail -5
  fi
done
CONF=$(db "SELECT (SELECT config_value FROM config WHERE config_key = 'max_users') || ',' || (SELECT count(*) FROM sync_allowed_accounts)")
[ "$CONF" = "unlimited,3" ] && pass "after the refused POSTs: max users unlimited, the allowlist unchanged" || fail "after the POSTs: $CONF"
docker rm -f portcullis-fxadmin-probe > /dev/null 2>&1 || true
rm -rf "$PROBE_DIR"

compose_down "$APP_ID"
rm -rf "$COMPOSE_OVERRIDE" "$APPFILES_DIR"
