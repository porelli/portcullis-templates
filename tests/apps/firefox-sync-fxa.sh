#!/usr/bin/env bash
# Test: Firefox Sync + own accounts (porelli/firefox-sync's self-hosted
# Mozilla accounts with Sync storage). Every service is on the instance's
# default network; fxa-gate, a Traefik-only nginx, is the only one on
# portcullis-proxy and carries every router.
#
# STATIC_ONLY=1: the static section only (no core, no Docker).
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="firefox-sync-fxa"
# Fail closed: an exit before the last check (set -e, a syntax error, any
# unexpected failure) counts as a failure, whatever bash's exit status (bash
# 3.2 reports 0 for an eval syntax error under an EXIT trap). Chains lib.sh's
# report, which exits 1 on any failure; never replace this trap.
FXA_DONE=0
# The test's own helper containers (they carry the instance's secrets) go
# on every exit, timeouts and aborts included.
FXA_TEST_CONTAINERS=""
FXA_TEST_NETWORKS=""
fxa_exit() {
  local rc=$?
  # shellcheck disable=SC2086
  [ -z "$FXA_TEST_CONTAINERS" ] || docker rm -f $FXA_TEST_CONTAINERS > /dev/null 2>&1 || true
  # shellcheck disable=SC2086
  [ -z "$FXA_TEST_NETWORKS" ] || docker network rm $FXA_TEST_NETWORKS > /dev/null 2>&1 || true
  [ "$FXA_DONE" = 1 ] || fail "aborted before the last check (exit status $rc)"
  report
}
trap fxa_exit EXIT
section "Firefox Sync + own accounts (static)"

APP_ID=firefox-sync-fxa
COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"

FXA_IMAGE=ghcr.io/porelli/firefox-sync:fxa-mono-v1.350.0@sha256:0ec0804fe9a021496faffd78d64ae90c014ee4fa1b0ed228451e84df30a77d73
ADMIN_IMAGE=ghcr.io/porelli/firefox-sync:admin-213576ce106e@sha256:432aba9c2f7a5b9293cdd1fb5fed1be92f1ba4f08c83dc56a6e73d7005f96d2d
SYNC_IMAGE=ghcr.io/porelli/firefox-sync:syncstorage-rs-postgres-0.25.2@sha256:e31d2d17d136f5e87ccd1c88ba6e53270c3c11d1c321d22d7d31c9ed5e3d623d
SYNC_INIT_IMAGE=ghcr.io/porelli/firefox-sync:syncstorage-rs-postgres-init-0.25.1-20261124T171959@sha256:a43d7e844d66fa6cc48d7de027038b3f9029bf46c8740cbb445a7b2cab96f8d8
PAIRING_IMAGE=ghcr.io/porelli/firefox-sync:fxa-channelserver-1.6.0@sha256:cfc3319d79ba46bdc7b32922170bbfa5ea5eec3cb6549519ac0996309f320f74
MYSQL_IMAGE=mysql:9.7.4@sha256:1f2ca53a9e94ff9f1f313099fa7dc7fb2f72e180ca5b2ef83574031e451bbbf1
REDIS_IMAGE=redis:8.12.0-alpine@sha256:5af80107c1eeecb484a2269b80a26d12bfa6521787da4663bd9f19f60a163483
POSTGRES_IMAGE=postgres:17.11-alpine@sha256:3540c0362c809df084ffac0ae69fe794515f9de92692f02178bcdce0ef0302ac
NGINX_IMAGE=nginx:1.31.8-alpine@sha256:fed7e14be83cbd2661a75cdc5b872d936cf155d46c327084d30b8df19ae88d72

ENV() { yq -r ".services[\"$1\"].environment.$2 // \"<unset>\"" "$COMPOSE"; }
DEP() { yq -r ".services[\"$1\"].depends_on[\"$2\"].condition // \"<none>\"" "$COMPOSE"; }

# six_host_routers: exactly the six, each with its default subdomain (the
# Hub's per-instance naming: the router's own name, as firefox-sync's
# firefox-sync-admin; other instances get <sub>-<suffix>).
HOST_ROUTERS=$(yq -r '[.services[].labels // {} | to_entries[] | select(.key | test("^traefik[.]http[.]routers[.][^.]+[.]rule$"))
  | select(.value | test("^Host\\(`[^`]*`\\)$")) | .key | capture("routers[.](?<r>[^.]+)[.]rule").r] | sort | join(" ")' "$COMPOSE")
WANT_ROUTERS="firefox-sync-fxa firefox-sync-fxa-accounts firefox-sync-fxa-admin firefox-sync-fxa-api firefox-sync-fxa-pairing firefox-sync-fxa-profile"
if [ "$HOST_ROUTERS" = "$WANT_ROUTERS" ]; then
  pass "six_host_routers: $HOST_ROUTERS"
else
  fail "six_host_routers: got '$HOST_ROUTERS'"
fi
for r in $WANT_ROUTERS; do
  var="PORTCULLIS_HOST_$(echo "$r" | tr 'a-z-' 'A-Z_')"
  rule=$(yq -r "[.services[].labels // {} | .[\"traefik.http.routers.$r.rule\"] | select(. != null)] | .[0]" "$COMPOSE")
  if [ "$rule" = "Host(\`\${$var:-$r.portcullis.local}\`)" ]; then
    pass "six_host_routers: $r -> $r.<domain> (\$$var)"
  else
    fail "six_host_routers: $r rule is '$rule'"
  fi
done

# start_order
check_dep() {  # $1 service, $2 dependency, $3 condition
  local got
  got=$(DEP "$1" "$2")
  if [ "$got" = "$3" ]; then pass "start_order: $1 after $2 ($3)"; else fail "start_order: $1 -> $2 is $got, want $3"; fi
}
check_dep fxa-auth fxa-keys-owner service_completed_successfully
check_dep fxa-auth fxa-policy service_completed_successfully
check_dep fxa-auth fxa-redis service_healthy
check_dep fxa-policy fxa-migrations service_completed_successfully
check_dep fxa-migrations fxa-db service_healthy
check_dep fxa-content fxa-auth service_healthy
check_dep fxa-content fxa-profile service_healthy
check_dep fxa-db-users fxa-db service_healthy
check_dep fxa-auth fxa-db-users service_completed_successfully
check_dep fxa-profile fxa-db-users service_completed_successfully
check_dep firefox-sync-fxa firefox-sync-fxa-init service_completed_successfully
check_dep firefox-sync-fxa-init firefox-sync-fxa-db-init service_completed_successfully
check_dep firefox-sync-fxa-db-init firefox-sync-fxa-migrate service_completed_successfully

# only_gate_on_proxy: fxa-gate alone on portcullis-proxy, the rest on default
# only (no networks key = default); the Sync server's default-only alias.
NETS=$(yq -r '.services | to_entries[] | .key + "=" + ((.value.networks // ["default"]) | (if tag == "!!map" then keys else . end) | sort | join(","))' "$COMPOSE")
bad=""
while IFS='=' read -r svc nets; do
  if [ "$svc" = fxa-gate ]; then
    [ "$nets" = "default,portcullis-proxy" ] || bad="$bad $svc($nets)"
  else
    [ "$nets" = default ] || bad="$bad $svc($nets)"
  fi
done <<< "$NETS"
if [ -z "$bad" ]; then
  pass "only_gate_on_proxy: fxa-gate on default + portcullis-proxy, every other service on default only"
else
  fail "only_gate_on_proxy:$bad"
fi
LABELLED=$(yq -r '[.services | to_entries[] | select((.value.labels // {}) | has("traefik.enable")) | .key] | join(" ")' "$COMPOSE")
[ "$LABELLED" = fxa-gate ] && pass "only_gate_on_proxy: only fxa-gate has Traefik labels" \
  || fail "only_gate_on_proxy: Traefik labels on: $LABELLED"
ALIAS=$(yq -r '.services["firefox-sync-fxa"].networks.default.aliases // [] | join(",")' "$COMPOSE")
[ "$ALIAS" = firefox-sync-fxa-internal ] && pass "only_gate_on_proxy: firefox-sync-fxa answers as firefox-sync-fxa-internal on default" \
  || fail "only_gate_on_proxy: firefox-sync-fxa aliases '$ALIAS'"


# images_pinned
WANT_IMAGES="
fxa-keys-owner=$FXA_IMAGE fxa-migrations=$FXA_IMAGE fxa-auth=$FXA_IMAGE fxa-content=$FXA_IMAGE
fxa-profile=$FXA_IMAGE fxa-profile-worker=$FXA_IMAGE fxa-profile-static=$FXA_IMAGE
fxa-policy=$ADMIN_IMAGE ffs-admin=$ADMIN_IMAGE
firefox-sync-fxa=$SYNC_IMAGE firefox-sync-fxa-migrate=$SYNC_IMAGE
firefox-sync-fxa-db-init=$SYNC_INIT_IMAGE fxa-pairing=$PAIRING_IMAGE
fxa-db=$MYSQL_IMAGE fxa-db-users=$MYSQL_IMAGE fxa-access-sync=$MYSQL_IMAGE
fxa-redis=$REDIS_IMAGE fxa-mail-check=$REDIS_IMAGE
firefox-sync-fxa-db=$POSTGRES_IMAGE firefox-sync-fxa-init=$POSTGRES_IMAGE
fxa-gate=$NGINX_IMAGE"
SERVICES=$(yq -r '.services | keys | .[]' "$COMPOSE" | LC_ALL=C sort | tr '\n' ' ')
WANT_SERVICES=$(for e in $WANT_IMAGES; do echo "${e%%=*}"; done | LC_ALL=C sort | tr '\n' ' ')
[ "$SERVICES" = "$WANT_SERVICES" ] && pass "services: exactly the $(echo "$SERVICES" | wc -w | tr -d ' ') of the plan" \
  || fail "services: got '$SERVICES', want '$WANT_SERVICES'"
bad=""
for e in $WANT_IMAGES; do
  svc=${e%%=*}
  got=$(yq -r ".services[\"$svc\"].image // \"\"" "$COMPOSE")
  [ "$got" = "${e#*=}" ] || bad="$bad $svc($got)"
done
[ -z "$bad" ] || fail "images_pinned:$bad"
[ -z "$bad" ] && pass "images_pinned: every service's image is the pinned digest"

# env_values
check_env() {  # $1 service, $2 key, $3 value
  local got
  got=$(ENV "$1" "$2")
  if [ "$got" = "$3" ]; then pass "env_values: $1 $2=$3"; else fail "env_values: $1 $2 is '$got', want '$3'"; fi
}
check_env fxa-policy ADMIN_ACCESS_EXTERNAL 1
check_env ffs-admin ADMIN_ACCESS_EXTERNAL 1
check_env ffs-admin ADMIN_PASSWORD ""
check_env fxa-auth ACCOUNT_EVENTS_ENABLED false
check_env fxa-auth IP_PROFILING_RECENCY 0
check_env fxa-auth CLIENT_ADDRESS_DEPTH 2
check_env ffs-admin FXA_CLIENT_ADDRESS_DEPTH 2
check_env fxa-auth CUSTOMS_SERVER_URL none
check_env fxa-auth FXA_EXPIRATION_ACCESS_TOKEN "60 minutes"
check_env fxa-policy FXA_SIGNUPS allowlist
check_env fxa-policy FXA_ACCESS_DB_PASSWORD '${FXA_ACCESS_DB_PASSWORD:?FXA_ACCESS_DB_PASSWORD must be set}'
# Typed as compose reads them: strings where upstream quotes them.
[ "$(yq -r '.services["fxa-auth"].environment.CLIENT_ADDRESS_DEPTH | tag' "$COMPOSE")" = '!!str' ] \
  && [ "$(yq -r '.services["fxa-auth"].environment.IP_PROFILING_RECENCY | tag' "$COMPOSE")" = '!!int' ] \
  && pass 'env_values: CLIENT_ADDRESS_DEPTH "2" (string), IP_PROFILING_RECENCY 0 (integer)' \
  || fail "env_values: CLIENT_ADDRESS_DEPTH / IP_PROFILING_RECENCY types"
if [ "$(yq -r '[.services[].environment // {} | has("FXA_SIGNUP_ALLOWLIST")] | any' "$COMPOSE")" = true ]; then
  fail "env_values: FXA_SIGNUP_ALLOWLIST is set (fxa-access-sync owns the list)"
else
  pass "env_values: FXA_SIGNUP_ALLOWLIST absent"
fi
# no-telemetry.env inline on every running accounts service.
for svc in fxa-auth fxa-content fxa-profile fxa-profile-worker fxa-profile-static fxa-pairing; do
  if [ "$(ENV "$svc" SENTRY_DSN)" = "" ] && [ "$(ENV "$svc" GLEAN_UPLOAD_ENABLED)" = false ] \
      && [ "$(ENV "$svc" STATSD_ENABLE)" = false ] && [ "$(ENV "$svc" TRACING_OTEL_EXPORTER_ENABLED)" = false ] \
      && [ "$(ENV "$svc" NIMBUS_ENABLED)" = false ] && [ "$(ENV "$svc" AMPLITUDE_DISABLED)" = true ]; then
    pass "env_values: $svc has no-telemetry.env's settings"
  else
    fail "env_values: $svc misses no-telemetry.env's settings"
  fi
done
[ "$(ENV fxa-content GLEAN_SERVER_ENDPOINT)" = 'https://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_ACCOUNTS:-firefox-sync-fxa-accounts.portcullis.local}' ] \
  && pass "env_values: the pages' Glean pings go to the accounts host, never Mozilla" \
  || fail "env_values: GLEAN_SERVER_ENDPOINT $(ENV fxa-content GLEAN_SERVER_ENDPOINT)"

# tokenserver_internal: the Sync tokenserver checks tokens with this
# instance's own auth server, inside the instance.
for svc in firefox-sync-fxa firefox-sync-fxa-migrate; do
  check_env "$svc" SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL http://fxa-auth:9000/v1
  check_env "$svc" SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN '${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_API:-firefox-sync-fxa-api.portcullis.local}'
done

# no_root_db_credential: no internet-facing service holds the accounts'
# root password or connects as root; root stays with the one-shots
# fxa-migrations, fxa-policy and fxa-db-users (and the server itself).
ROOT_HOLDERS=$(yq -r '[.services | to_entries[] | select(.value.environment // {} | to_entries | any_c(.value | tostring | test("FXA_MYSQL_PASSWORD"))) | .key] | sort | join(" ")' "$COMPOSE")
[ "$ROOT_HOLDERS" = "fxa-db fxa-db-users fxa-migrations fxa-policy" ] \
  && pass "no_root_db_credential: the root password only in fxa-db, fxa-db-users, fxa-migrations, fxa-policy" \
  || fail "no_root_db_credential: the root password is in: $ROOT_HOLDERS"
bad=""
for svc in fxa-auth fxa-content fxa-profile fxa-profile-worker fxa-profile-static fxa-pairing firefox-sync-fxa ffs-admin; do
  roots=$(yq -r ".services[\"$svc\"].environment // {} | to_entries[] | select(.key | test(\"USER\")) | select(.value == \"root\") | .key" "$COMPOSE")
  [ -z "$roots" ] || bad="$bad $svc($roots)"
done
[ -z "$bad" ] && pass "no_root_db_credential: no internet-facing service connects as root" \
  || fail "no_root_db_credential: root user in:$bad"
check_env fxa-auth AUTH_MYSQL_USERNAME fxa_auth
check_env fxa-auth MYSQL_USERNAME fxa_auth
check_env fxa-auth PUSHBOX_MYSQL_USERNAME fxa_auth
check_env fxa-profile MYSQL_USERNAME fxa_profile
# db-users.sh grants exactly DML + EXECUTE on the services' own databases.
# M1/M3: run the script with a stub mysql (prints its stdin) and check the
# exact statements it generates.
DBU="$(dirname "$COMPOSE")/db-users.sh"
DBU_TMP=$(mktemp -d)
printf '#!/bin/sh\ncat\n' > "$DBU_TMP/mysql"
chmod +x "$DBU_TMP/mysql"
if SQL=$(PATH="$DBU_TMP:$PATH" MYSQL_HOST=localhost FXA_AUTH_DB_PASSWORD=p1 FXA_PROFILE_DB_PASSWORD=p2 sh "$DBU" 2>&1); then
  WANT_SQL="CREATE USER IF NOT EXISTS 'fxa_auth'@'%' IDENTIFIED BY 'p1';
ALTER USER 'fxa_auth'@'%' IDENTIFIED BY 'p1';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'fxa_auth'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON \`fxa\`.* TO 'fxa_auth'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON \`fxa\\_oauth\`.* TO 'fxa_auth'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON \`pushbox\`.* TO 'fxa_auth'@'%';
CREATE USER IF NOT EXISTS 'fxa_profile'@'%' IDENTIFIED BY 'p2';
ALTER USER 'fxa_profile'@'%' IDENTIFIED BY 'p2';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'fxa_profile'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON \`fxa\\_profile\`.* TO 'fxa_profile'@'%';
REVOKE IF EXISTS EXECUTE ON PROCEDURE ffs.delete_account_by_email FROM 'ffs_access'@'%';
db-users: fxa_auth (fxa, fxa_oauth, pushbox) and fxa_profile (fxa_profile) set; ffs_access narrowed (no delete_account_by_email)"
  if [ "$SQL" = "$WANT_SQL" ]; then
    pass "db-users.sh M1/M3: exactly CREATE, ALTER, REVOKE and the DML + EXECUTE grants on fxa, fxa\\_oauth, pushbox (fxa_auth) and fxa\\_profile (fxa_profile); ffs_access loses EXECUTE on ffs.delete_account_by_email"
  else
    fail "db-users.sh M1/M3: generated SQL differs from the expected statements:
$(diff <(echo "$WANT_SQL") <(echo "$SQL") || true)"
  fi
else
  fail "db-users.sh M1/M3: the script failed with the stub mysql: $SQL"
fi
rm -rf "$DBU_TMP"

# volumes
VOLS=$(yq -r '.volumes | keys | .[]' "$COMPOSE" | LC_ALL=C sort | tr '\n' ' ')
[ "$VOLS" = "firefox-sync-fxa-db-data fxa-access-state fxa-db-data fxa-keys fxa-profile-images " ] \
  && pass "volumes: exactly $VOLS" || fail "volumes: got '$VOLS'"
[ "$(yq -r '.services["fxa-redis"].volumes // [] | length' "$COMPOSE")" = 0 ] \
  && pass "volumes: fxa-redis has none" || fail "volumes: fxa-redis mounts a volume"

# M2: no service uses network_mode, but fxa-mail-check's none (it
# validates settings only; a yq error fails).
if ! NETMODE_CHECK=$(yq -r '.services | to_entries[] | select(.value | has("network_mode")) | .key + "=" + (.value.network_mode | tostring)' "$COMPOSE"); then
  fail "M2: yq error checking network_mode"
elif [ "$NETMODE_CHECK" != "fxa-mail-check=none" ]; then
  fail "M2: network_mode on: $(echo "$NETMODE_CHECK" | tr '\n' ' ') (only fxa-mail-check=none allowed)"
else
  pass "M2: no service uses network_mode, but fxa-mail-check (none)"
fi

# resources
[ "$(yq -r '.resources.min_memory_mib' "$MANIFEST")" = 4096 ] && [ "$(yq -r '.resources.min_disk_gib' "$MANIFEST")" = 18 ] \
  && pass "resources: min_memory_mib 4096, min_disk_gib 18" \
  || fail "resources: $(yq -r '.resources' "$MANIFEST" | tr '\n' ' ')"

# node_trusts_ca: every Node service of the accounts image (fxa-keys-owner
# only runs chown) trusts Portcullis's CA bundle.
CA_PATH=/etc/ssl/certs/portcullis-ca-bundle.crt
for svc in fxa-migrations fxa-auth fxa-content fxa-profile fxa-profile-worker fxa-profile-static; do
  if [ "$(ENV "$svc" NODE_EXTRA_CA_CERTS)" = "$CA_PATH" ] \
      && grep -qx "./certs/ca-bundle.crt:$CA_PATH:ro" <<< "$(yq -r ".services[\"$svc\"].volumes[]" "$COMPOSE")"; then
    pass "node_trusts_ca: $svc"
  else
    fail "node_trusts_ca: $svc needs NODE_EXTRA_CA_CERTS=$CA_PATH and ./certs/ca-bundle.crt:$CA_PATH:ro"
  fi
done

# The template rules (CONTRIBUTING): no ports / container_name / env_file /
# build; dropped capabilities, no-new-privileges, a sized tmpfs and a memory
# limit on every service.
bad=""
for svc in $SERVICES; do
  s=".services[\"$svc\"]"
  [ "$(yq -r "$s | has(\"ports\") or has(\"container_name\") or has(\"env_file\") or has(\"build\")" "$COMPOSE")" = false ] || bad="$bad $svc:forbidden-key"
  [ "$(yq -r "$s.cap_drop // [] | join(\",\")" "$COMPOSE")" = ALL ] || bad="$bad $svc:cap_drop"
  grep -qx 'no-new-privileges:true' <<< "$(yq -r "$s.security_opt // [] | .[]" "$COMPOSE")" || bad="$bad $svc:no-new-privileges"
  [ "$(yq -r "$s.tmpfs // [] | length" "$COMPOSE")" -gt 0 ] && ! grep -qv ':size=' <<< "$(yq -r "$s.tmpfs[]" "$COMPOSE")" || bad="$bad $svc:tmpfs"
  [ "$(yq -r "$s.mem_limit // \"\"" "$COMPOSE")" != "" ] || bad="$bad $svc:mem_limit"
done
[ -z "$bad" ] && pass "hardening: every service" || fail "hardening:$bad"

# Upstream's config files, vendored unmodified from 7216405.
for f in oauth-clients.js content-server.js; do
  if grep -q '7216405' <<< "$(head -n 2 "$(dirname "$COMPOSE")/fxa-config/$f")"; then
    pass "fxa-config/$f names its upstream commit"
  else
    fail "fxa-config/$f has no header naming porelli/firefox-sync 7216405"
  fi
done

# routers_exact: exactly the six host routers + six path routers.
ACTUAL_ROUTERS=$(yq -r '[.services["fxa-gate"].labels // {} | to_entries[] | select(.key | test("^traefik[.]http[.]routers[.][^.]+[.]rule$")) | .key | capture("routers[.](?<r>[^.]+)[.]rule").r] | sort | join(" ")' "$COMPOSE")
WANT_ALL="firefox-sync-fxa firefox-sync-fxa-accounts firefox-sync-fxa-accounts-change-password firefox-sync-fxa-accounts-config firefox-sync-fxa-accounts-metrics firefox-sync-fxa-accounts-root firefox-sync-fxa-admin firefox-sync-fxa-api firefox-sync-fxa-pairing firefox-sync-fxa-profile firefox-sync-fxa-signup firefox-sync-fxa-token"
if [ "$ACTUAL_ROUTERS" = "$WANT_ALL" ]; then
  pass "routers_exact: $WANT_ALL"
else
  fail "routers_exact: got '$ACTUAL_ROUTERS', want '$WANT_ALL'"
fi

# open_routers_no_gateway: the four open host routers have rate-limit + security-headers, no portcullis-auth/groups.
for r in firefox-sync-fxa firefox-sync-fxa-api firefox-sync-fxa-profile firefox-sync-fxa-pairing; do
  mws=$(yq -r ".services[\"fxa-gate\"].labels[\"traefik.http.routers.$r.middlewares\"] // \"\"" "$COMPOSE")
  if [ "$mws" = "rate-limit@file,security-headers@file" ]; then
    pass "open_routers_no_gateway: $r carries rate-limit@file,security-headers@file (no auth)"
  else
    fail "open_routers_no_gateway: $r middlewares '$mws', want 'rate-limit@file,security-headers@file'"
  fi
done

# gated_routers_gateway: the two gated host routers have the full chain.
for r in firefox-sync-fxa-accounts firefox-sync-fxa-admin; do
  mws=$(yq -r ".services[\"fxa-gate\"].labels[\"traefik.http.routers.$r.middlewares\"] // \"\"" "$COMPOSE")
  if [ "$mws" = "client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file" ]; then
    pass "gated_routers_gateway: $r carries the full chain (auth + groups)"
  else
    fail "gated_routers_gateway: $r middlewares '$mws', want 'client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file'"
  fi
done

# accounts_open_paths: four separate path routers on the accounts host, priority 990, rate-limit.
ACCOUNTS_HOST='Host(`${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_ACCOUNTS:-firefox-sync-fxa-accounts.portcullis.local}`)'
accounts_path() {  # $1 router -> its one Path()
  case "$1" in
    firefox-sync-fxa-accounts-root) echo '/' ;;
    firefox-sync-fxa-accounts-change-password) echo '/.well-known/change-password' ;;
    firefox-sync-fxa-accounts-config) echo '/.well-known/fxa-client-configuration' ;;
    firefox-sync-fxa-accounts-metrics) echo '/metrics-flow' ;;
  esac
}
accounts_open_ok=true
for router in firefox-sync-fxa-accounts-root firefox-sync-fxa-accounts-change-password firefox-sync-fxa-accounts-config firefox-sync-fxa-accounts-metrics; do
  rule=$(yq -r ".services[\"fxa-gate\"].labels[\"traefik.http.routers.$router.rule\"] // \"\"" "$COMPOSE")
  mws=$(yq -r ".services[\"fxa-gate\"].labels[\"traefik.http.routers.$router.middlewares\"] // \"\"" "$COMPOSE")
  prio=$(yq -r ".services[\"fxa-gate\"].labels[\"traefik.http.routers.$router.priority\"] // \"\"" "$COMPOSE")
  if [ "$rule" != "$ACCOUNTS_HOST && Path(\`$(accounts_path "$router")\`)" ] || [ "$mws" != "rate-limit@file,security-headers@file" ] || [ "$prio" != "990" ]; then
    fail "accounts_open_paths: $router rule='$rule' mws='$mws' prio='$prio' (want 990)"
    accounts_open_ok=false
  fi
done
$accounts_open_ok && pass "accounts_open_paths: four routers on accounts host, priority 990, rate-limit@file"

# signup router: API host && Path(/v1/account/create), priority 990, rate-limit-auth.
SIGNUP_RULE=$(yq -r '.services["fxa-gate"].labels["traefik.http.routers.firefox-sync-fxa-signup.rule"] // ""' "$COMPOSE")
SIGNUP_MW=$(yq -r '.services["fxa-gate"].labels["traefik.http.routers.firefox-sync-fxa-signup.middlewares"] // ""' "$COMPOSE")
SIGNUP_PRIO=$(yq -r '.services["fxa-gate"].labels["traefik.http.routers.firefox-sync-fxa-signup.priority"] // ""' "$COMPOSE")
WANT_SIGNUP_RULE='Host(`${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_API:-firefox-sync-fxa-api.portcullis.local}`) && Path(`/v1/account/create`)'
if [ "$SIGNUP_RULE" = "$WANT_SIGNUP_RULE" ] && [ "$SIGNUP_MW" = "rate-limit-auth@file,security-headers@file" ] && [ "$SIGNUP_PRIO" = "990" ]; then
  pass "signup router: API host && Path(/v1/account/create), priority 990, rate-limit-auth@file"
else
  fail "signup router: rule='$SIGNUP_RULE' mws='$SIGNUP_MW' prio='$SIGNUP_PRIO'"
fi

# token router: Sync host && PathPrefix(/1.0/), rate-limit-auth, priority 990.
TOKEN_RULE=$(yq -r '.services["fxa-gate"].labels["traefik.http.routers.firefox-sync-fxa-token.rule"] // ""' "$COMPOSE")
TOKEN_MW=$(yq -r '.services["fxa-gate"].labels["traefik.http.routers.firefox-sync-fxa-token.middlewares"] // ""' "$COMPOSE")
TOKEN_PRIO=$(yq -r '.services["fxa-gate"].labels["traefik.http.routers.firefox-sync-fxa-token.priority"] // ""' "$COMPOSE")
WANT_TOKEN_RULE='Host(`${PORTCULLIS_HOST_FIREFOX_SYNC_FXA:-firefox-sync-fxa.portcullis.local}`) && PathPrefix(`/1.0/`)'
if [ "$TOKEN_RULE" = "$WANT_TOKEN_RULE" ] && [ "$TOKEN_MW" = "rate-limit-auth@file,security-headers@file" ] && [ "$TOKEN_PRIO" = "990" ]; then
  pass "token router: Sync host && PathPrefix(/1.0/), rate-limit-auth@file, priority 990"
else
  fail "token router: rule='$TOKEN_RULE' mws='$TOKEN_MW' prio='$TOKEN_PRIO' (want 990)"
fi

# manifest_auth: method forward-auth, group_access true, no admin_paths.
METHOD=$(yq -r '.auth.method // ""' "$MANIFEST")
GROUP_ACCESS=$(yq -r '.auth.group_access // ""' "$MANIFEST")
ADMIN_PATHS=$(yq -r '.auth.admin_paths // [] | length' "$MANIFEST")
if [ "$METHOD" = "forward-auth" ] && [ "$GROUP_ACCESS" = "true" ] && [ "$ADMIN_PATHS" = "0" ]; then
  pass "manifest_auth: method forward-auth, group_access true, no admin_paths"
else
  fail "manifest_auth: method=$METHOD group_access=$GROUP_ACCESS admin_paths=$ADMIN_PATHS"
fi

# host_reasons: five entries with exact keys and texts (top-level hosts.reasons).
REASON_KEYS=$(yq -r '.hosts.reasons // {} | keys | sort | join(" ")' "$MANIFEST")
WANT_KEYS="firefox-sync-fxa firefox-sync-fxa-accounts firefox-sync-fxa-api firefox-sync-fxa-pairing firefox-sync-fxa-profile"
if [ "$REASON_KEYS" = "$WANT_KEYS" ]; then
  pass "host_reasons: five keys (firefox-sync-fxa, -accounts, -api, -pairing, -profile)"
else
  fail "host_reasons: got keys '$REASON_KEYS', want '$WANT_KEYS'"
fi
SYNC_REASON=$(yq -r '.hosts.reasons["firefox-sync-fxa"] // ""' "$MANIFEST")
[ "$SYNC_REASON" = "Firefox syncs in the background, without cookies; each request is signed with the account's own keys." ] \
  && pass "host_reasons: firefox-sync-fxa text matches" || fail "host_reasons: firefox-sync-fxa text is '$SYNC_REASON'"
API_REASON=$(yq -r '.hosts.reasons["firefox-sync-fxa-api"] // ""' "$MANIFEST")
[ "$API_REASON" = "Firefox and the account pages call the accounts API in the background, without cookies; the sign-up list decides who may create an account." ] \
  && pass "host_reasons: firefox-sync-fxa-api text matches" || fail "host_reasons: firefox-sync-fxa-api text is '$API_REASON'"
PROFILE_REASON=$(yq -r '.hosts.reasons["firefox-sync-fxa-profile"] // ""' "$MANIFEST")
[ "$PROFILE_REASON" = "Firefox loads account profiles and avatars in the background, without cookies." ] \
  && pass "host_reasons: firefox-sync-fxa-profile text matches" || fail "host_reasons: firefox-sync-fxa-profile text is '$PROFILE_REASON'"
PAIRING_REASON=$(yq -r '.hosts.reasons["firefox-sync-fxa-pairing"] // ""' "$MANIFEST")
[ "$PAIRING_REASON" = "An encrypted relay for pairing a phone by QR code; it can't read what it relays." ] \
  && pass "host_reasons: firefox-sync-fxa-pairing text matches" || fail "host_reasons: firefox-sync-fxa-pairing text is '$PAIRING_REASON'"
ACCOUNTS_REASON=$(yq -r '.hosts.reasons["firefox-sync-fxa-accounts"] // ""' "$MANIFEST")
[ "$ACCOUNTS_REASON" = "Firefox reads the accounts configuration and opens the start and change-password pages without cookies; everything else on this host is behind sign-in." ] \
  && pass "host_reasons: firefox-sync-fxa-accounts text matches" || fail "host_reasons: firefox-sync-fxa-accounts text is '$ACCOUNTS_REASON'"

# ── fxa-gate (Task 12): the Traefik-only nginx gate, static ──
GATE_SH="$(dirname "$COMPOSE")/fxa-gate.sh"
GS() { yq -r ".services[\"fxa-gate\"]$1" "$COMPOSE"; }
# Every upstream under a default-only -internal alias, with its port declared
# (the alias Service on Kubernetes carries it).
bad=""
for e in fxa-content=fxa-content-internal:3030 fxa-auth=fxa-auth-internal:9000 ffs-admin=ffs-admin-internal:8080,8081 \
         fxa-profile=fxa-profile-internal:1111 fxa-profile-static=fxa-profile-static-internal:1112 \
         firefox-sync-fxa=firefox-sync-fxa-internal:8000 fxa-pairing=fxa-pairing-internal:8000; do
  svc=${e%%=*} want=${e#*=}
  got="$(yq -r ".services[\"$svc\"].networks.default.aliases // [] | join(\",\")" "$COMPOSE"):$(yq -r ".services[\"$svc\"].expose // [] | join(\",\")" "$COMPOSE")"
  [ "$got" = "$want" ] || bad="$bad $svc($got, want $want)"
  grep -q "^up_[a-z]*=\$(target [a-z]* ${want%%:*} " "$GATE_SH" || bad="$bad $svc(fxa-gate.sh doesn't call ${want%%:*})"
done
[ -z "$bad" ] && pass "gate_upstreams: every service behind fxa-gate answers on default as <service>-internal, its ports exposed; fxa-gate.sh calls exactly those names" \
  || fail "gate_upstreams:$bad"
# The gate's script: cidr_ok() byte-identical to esphome/gate.sh's, allow
# PORTCULLIS_TRAEFIK_SOURCE only, no realip, every credential header and the
# forward-auth cookies stripped, the admin group map.
ref_fn=$(awk '/^cidr_ok\(\) \{$/,/^\}$/' "$(dirname "$COMPOSE")/../esphome/gate.sh")
got_fn=$(awk '/^cidr_ok\(\) \{$/,/^\}$/' "$GATE_SH")
[ -n "$ref_fn" ] && [ "$ref_fn" = "$got_fn" ] && pass "gate_script: cidr_ok() is esphome/gate.sh's, byte for byte" \
  || fail "gate_script: cidr_ok() differs from esphome/gate.sh's"
bad=""
for want in 'cidr_ok "$src" || ' '  allow ${src};' '  deny all;' 'proxy_set_header X-Forwarded-Access-Token "";' \
            'proxy_set_header X-Auth-Request-Access-Token "";' "echo '  proxy_set_header Authorization \"\";'" \
            'proxy_set_header Cookie \$pc_cookie;' 'if (\$pc_cookie_left) { return 400; }' '_oauth2_proxy|__Host-portcullis_ext' \
            'proxy_set_header X-Forwarded-For \$http_x_forwarded_for;' 'proxy_set_header Host \$http_host;' \
            'map \$http_x_auth_request_groups \$pc_admin ' 'if (\$pc_admin != 1) { return 403 ' 'if (\$http_upgrade) { return 400 ' 'return 421;'; do
  grep -qF -- "$want" "$GATE_SH" || bad="$bad [$want]"
done
grep -qE '\b(set_real_ip_from|real_ip_header|real_ip_recursive)\b' "$GATE_SH" && bad="$bad [realip]"
[ -z "$bad" ] && pass "gate_script: allow Traefik's range only, deny all, no realip; credentials and forward-auth cookies stripped; Host / X-Forwarded-For as Traefik sent them; the admin group map; 421 for other hosts" \
  || fail "gate_script: missing:$bad"
# The service: unprivileged and read-only, the six hosts and the admin group
# from the instance variables, the script read-only.
if [ "$(GS .user)" = "101:101" ] && [ "$(GS .read_only)" = true ] && [ "$(GS '.cap_drop | join(",")')" = ALL ] \
    && [ "$(GS '.cap_add // [] | length')" = 0 ] && [ "$(GS '.security_opt | join(",")')" = "no-new-privileges:true" ] \
    && [ "$(GS .pids_limit)" = 64 ] && [ "$(GS '.tmpfs | join(",")')" = "/tmp:size=16m" ] && [ "$(GS '.privileged // false')" = false ]; then
  pass "gate_hardening: fxa-gate runs as 101:101 (numeric, not root), read-only with a sized /tmp, cap_drop ALL and no cap_add, no-new-privileges, pids_limit 64"
else
  fail "gate_hardening: user=$(GS .user) read_only=$(GS .read_only) cap_drop=$(GS '.cap_drop | join(",")') cap_add=$(GS '.cap_add // [] | join(",")') security_opt=$(GS '.security_opt | join(",")') pids=$(GS .pids_limit) tmpfs=$(GS '.tmpfs | join(",")')"
fi
check_env fxa-gate PORTCULLIS_TRAEFIK_SOURCE '${PORTCULLIS_TRAEFIK_SOURCE:-172.31.250.2/32}'
check_env fxa-gate GATE_LISTEN 8080
check_env fxa-gate GATE_ADMIN_GROUP '${PORTCULLIS_ADMIN_GROUP:-admin_firefox-sync-fxa}'
for h in SYNC= ACCOUNTS=_ACCOUNTS API=_API PROFILE=_PROFILE ADMIN=_ADMIN PAIRING=_PAIRING; do
  sub=$(echo "firefox-sync-fxa${h#*=}" | tr 'A-Z_' 'a-z-')
  check_env fxa-gate "GATE_HOST_${h%%=*}" "\${PORTCULLIS_HOST_FIREFOX_SYNC_FXA${h#*=}:-$sub.portcullis.local}"
done
[ "$(GS '.entrypoint | join(" ")')" = "/bin/sh /portcullis/fxa-gate.sh" ] \
  && [ "$(GS '.volumes | join(",")')" = "./templates/firefox-sync-fxa/fxa-gate.sh:/portcullis/fxa-gate.sh:ro" ] \
  && pass "gate_hardening: entrypoint /bin/sh /portcullis/fxa-gate.sh, the script mounted read-only (nothing else)" \
  || fail "gate_hardening: entrypoint $(GS '.entrypoint | join(" ")'), volumes $(GS '.volumes | join(",")')"
[ "$(GS '.labels["traefik.http.services.firefox-sync-fxa-gate.loadbalancer.server.port"]')" = 8080 ] \
  && pass "gate: Traefik's service port 8080 = GATE_LISTEN" || fail "gate: service port $(GS '.labels["traefik.http.services.firefox-sync-fxa-gate.loadbalancer.server.port"]')"
# gate_waits_for_init (T10-M4): every one-shot completed, every service it
# calls healthy.
for job in fxa-db-users fxa-keys-owner fxa-migrations fxa-policy fxa-mail-check firefox-sync-fxa-migrate firefox-sync-fxa-db-init firefox-sync-fxa-init; do
  check_dep fxa-gate "$job" service_completed_successfully
done
for up in fxa-auth fxa-content fxa-profile fxa-profile-static fxa-pairing ffs-admin firefox-sync-fxa; do
  check_dep fxa-gate "$up" service_healthy
done
ONESHOTS=$(yq -r '[.services | to_entries[] | select(.value.restart == "no") | .key] | sort | join(" ")' "$COMPOSE")
GATE_JOBS=$(GS '.depends_on | to_entries | map(select(.value.condition == "service_completed_successfully") | .key) | sort | join(" ")')
[ "$ONESHOTS" = "$GATE_JOBS" ] && pass "gate_waits_for_init: fxa-gate waits for exactly every one-shot ($ONESHOTS)" \
  || fail "gate_waits_for_init: one-shots '$ONESHOTS', fxa-gate waits for '$GATE_JOBS'"

# ── Mail (Task 14): the server's mail provider by default, or an external
# SMTP server; the optional account cap. ──
MAIL_SELECT="$(dirname "$COMPOSE")/mail-select.sh"
MAIL_CHECK="$(dirname "$COMPOSE")/mail-check.sh"
NO_MAIL_LINE="portcullis: no mail: wire a mail provider or set an external SMTP server"

[ "$(yq -r '.mail_sender.label // ""' "$MANIFEST")" = "Firefox accounts" ] \
  && pass "mail_sender: label Firefox accounts" || fail "mail_sender: $(yq -r '.mail_sender' "$MANIFEST" | tr '\n' ' ')"

# settings: the options, their sections, types, deliveries and defaults.
[ "$(yq -r '.settings.sections | join(",")' "$MANIFEST")" = "Mail,Accounts" ] \
  && pass "settings: sections Mail, Accounts" || fail "settings: sections $(yq -r '.settings.sections' "$MANIFEST" | tr '\n' ' ')"
OPTS=$(yq -r '.settings.options[] | [.key, .section, .type, (.delivery | map(.env) | join(",")), (.default // "" | tostring), .applies] | join("|")' "$MANIFEST")
WANT_OPTS="mail_source|Mail|enum|MAIL_SOURCE|provider|restart
smtp_host|Mail|string|EXT_SMTP_HOST||restart
smtp_port|Mail|int|EXT_SMTP_PORT|587|restart
smtp_security|Mail|enum|EXT_SMTP_SECURITY|starttls|restart
smtp_user|Mail|string|EXT_SMTP_USER||restart
smtp_password|Mail|secret|EXT_SMTP_PASSWORD||restart
smtp_sender|Mail|string|EXT_SMTP_SENDER||restart
max_accounts|Accounts|int|MAX_ACCOUNTS||restart
access_email|Accounts|verified_email|||"
if [ "$OPTS" = "$WANT_OPTS" ]; then
  pass "settings: the nine options (key, section, type, env, default, applies restart; access_email by file)"
else
  fail "settings: options differ:
$(diff <(echo "$WANT_OPTS") <(echo "$OPTS") || true)"
fi
OPT() { yq -r ".settings.options[] | select(.key == \"$1\") | $2" "$MANIFEST"; }
[ "$(OPT mail_source '[.options[] | .value + "=" + .label] | join(";")')" = "provider=The server's mail provider;external=Another SMTP server" ] \
  && [ "$(OPT smtp_security '[.options[] | .value + "=" + .label] | join(";")')" = "starttls=STARTTLS (587);tls=TLS (465)" ] \
  && pass "settings: mail_source provider/external, smtp_security starttls/tls (labels)" \
  || fail "settings: enum choices $(OPT mail_source '.options') $(OPT smtp_security '.options')"
[ "$(OPT smtp_host .format)" = hostname ] && [ "$(OPT smtp_sender .format)" = email ] \
  && [ "$(OPT smtp_port '[.min, .max] | join("-")')" = 1-65535 ] && [ "$(OPT max_accounts '.min')" = 1 ] \
  && [ "$(OPT max_accounts 'has("default")')" = false ] && [ "$(OPT max_accounts 'has("required")')" = false ] \
  && pass "settings: smtp_host hostname, smtp_sender email, smtp_port 1-65535, max_accounts min 1, optional" \
  || fail "settings: formats / bounds"
[ "$(OPT smtp_user '.requires | join(",")')" = "smtp_host,smtp_sender" ] \
  && pass "settings: smtp_user requires smtp_host, smtp_sender" || fail "settings: smtp_user requires $(OPT smtp_user '.requires')"

# compose: fxa-mail-check is a validate-only one-shot fxa-auth waits for.
check_dep fxa-auth fxa-mail-check service_completed_successfully
MC='.services["fxa-mail-check"]'
[ "$(yq -r "$MC.network_mode" "$COMPOSE")" = none ] && [ "$(yq -r "$MC.read_only" "$COMPOSE")" = true ] \
  && [ "$(yq -r "$MC.cap_drop | join(\",\")" "$COMPOSE")" = ALL ] && [ "$(yq -r "$MC | has(\"cap_add\")" "$COMPOSE")" = false ] \
  && [ "$(yq -r "$MC.restart" "$COMPOSE")" = no ] && [ "$(yq -r "$MC | has(\"command\")" "$COMPOSE")" = false ] \
  && [ "$(yq -r "$MC.entrypoint | join(\" \")" "$COMPOSE")" = "/bin/sh /portcullis-bin/mail-check.sh" ] \
  && [ "$(yq -r "$MC.volumes | join(\" \")" "$COMPOSE")" = "./templates/firefox-sync-fxa/mail-check.sh:/portcullis-bin/mail-check.sh:ro ./templates/firefox-sync-fxa/mail-select.sh:/portcullis-bin/mail-select.sh:ro ./templates/firefox-sync-fxa/fxa-config/smtp-require-tls.json:/fxa-config/smtp-require-tls.json:ro" ] \
  && pass "fxa-mail-check: one-shot, no network, read-only, no capability, runs mail-check.sh (both scripts and the requireTLS overlay read-only)" \
  || fail "fxa-mail-check: $(yq -r "$MC" "$COMPOSE" -o json | tr -d '\n ')"
AUTH_CMD=$(yq -r '.services["fxa-auth"].command | join(" ")' "$COMPOSE")
case "$AUTH_CMD" in
  "sh -c . /portcullis-bin/mail-select.sh && node "*) pass "fxa-auth: its sh -c sources mail-select.sh first, every step after it" ;;
  *) fail "fxa-auth: command '$AUTH_CMD' doesn't start with '. /portcullis-bin/mail-select.sh &&'" ;;
esac
grep -qx './templates/firefox-sync-fxa/mail-select.sh:/portcullis-bin/mail-select.sh:ro' <<< "$(yq -r '.services["fxa-auth"].volumes[]' "$COMPOSE")" \
  && pass "fxa-auth: mail-select.sh mounted read-only" || fail "fxa-auth: mail-select.sh not mounted read-only"
# Both get the same inputs, every one with an empty (or the setting's) default.
WANT_MAIL_ENV="EXT_SMTP_HOST=\${EXT_SMTP_HOST:-}
EXT_SMTP_PASSWORD=\${EXT_SMTP_PASSWORD:-}
EXT_SMTP_PORT=\${EXT_SMTP_PORT:-587}
EXT_SMTP_SECURITY=\${EXT_SMTP_SECURITY:-starttls}
EXT_SMTP_SENDER=\${EXT_SMTP_SENDER:-}
EXT_SMTP_USER=\${EXT_SMTP_USER:-}
MAIL_SOURCE=\${MAIL_SOURCE:-provider}
PORTCULLIS_MAIL_SENDER_FROM=\${PORTCULLIS_MAIL_SENDER_FROM:-}
PORTCULLIS_MAIL_SENDER_HOST=\${PORTCULLIS_MAIL_SENDER_HOST:-}
PORTCULLIS_MAIL_SENDER_PASSWORD=\${PORTCULLIS_MAIL_SENDER_PASSWORD:-}
PORTCULLIS_MAIL_SENDER_PORT=\${PORTCULLIS_MAIL_SENDER_PORT:-}
PORTCULLIS_MAIL_SENDER_USER=\${PORTCULLIS_MAIL_SENDER_USER:-}"
for svc in fxa-mail-check fxa-auth; do
  got=$(yq -r ".services[\"$svc\"].environment | to_entries[] | select(.key | test(\"^(MAIL_SOURCE|EXT_SMTP_|PORTCULLIS_MAIL_SENDER_)\")) | .key + \"=\" + .value" "$COMPOSE" | LC_ALL=C sort)
  [ "$got" = "$WANT_MAIL_ENV" ] && pass "mail inputs: $svc gets MAIL_SOURCE, EXT_SMTP_* and PORTCULLIS_MAIL_SENDER_*" \
    || fail "mail inputs: $svc differs:
$(diff <(echo "$WANT_MAIL_ENV") <(echo "$got") || true)"
done
# Only those two hold a mail password; the auth server's SMTP_* come from
# mail-select.sh alone (never set in compose).
HOLDERS=$(yq -r '[.services | to_entries[] | select(.value.environment // {} | to_entries | any_c(.value | tostring | test("SMTP_PASSWORD|MAIL_SENDER_PASSWORD"))) | .key] | sort | join(" ")' "$COMPOSE")
[ "$HOLDERS" = "fxa-auth fxa-mail-check" ] && pass "mail passwords only in fxa-auth and fxa-mail-check" \
  || fail "mail passwords in: $HOLDERS"
SET_SMTP=$(yq -r '[.services | to_entries[] | select(.key != "ffs-admin") | .key as $s | .value.environment // {} | keys[] | select(test("^SMTP_(HOST|PORT|USER|PASS|SECURE|SENDER)$")) | $s + ":" + .] | join(" ")' "$COMPOSE")
[ -z "$SET_SMTP" ] && pass "SMTP_* never set in compose (mail-select.sh exports them)" || fail "SMTP_* set in compose: $SET_SMTP"
check_env fxa-auth SMTP_IGNORE_TLS false
# starttls_required (static): the overlay is exactly nodemailer's requireTLS,
# both services find it at FXA_SMTP_REQUIRE_TLS_FILE (fxa-auth through its
# read-only fxa-config mount), and CONFIG_FILES keeps oauth-clients.json.
RT_FILE="$(dirname "$COMPOSE")/fxa-config/smtp-require-tls.json"
if [ -f "$RT_FILE" ] && cmp -s "$RT_FILE" <(printf '%s\n' '{"smtp":{"requireTLS":true}}'); then
  pass 'starttls_required: fxa-config/smtp-require-tls.json is exactly {"smtp":{"requireTLS":true}}'
else
  fail "starttls_required: fxa-config/smtp-require-tls.json isn't exactly {\"smtp\":{\"requireTLS\":true}}"
fi
check_env fxa-auth FXA_SMTP_REQUIRE_TLS_FILE /fxa-config/smtp-require-tls.json
check_env fxa-mail-check FXA_SMTP_REQUIRE_TLS_FILE /fxa-config/smtp-require-tls.json
check_env fxa-auth CONFIG_FILES /fxa-keys/oauth-clients.json
grep -qx './templates/firefox-sync-fxa/fxa-config:/fxa-config:ro' <<< "$(yq -r '.services["fxa-auth"].volumes[]' "$COMPOSE")" \
  && pass "starttls_required: fxa-auth reads the overlay from its read-only fxa-config mount" \
  || fail "starttls_required: fxa-auth doesn't mount fxa-config read-only"
check_env ffs-admin SMTP_HOST ""

# mail-select.sh, sourced by the host's sh (dash in CI; MAIL_SELECT_SH picks
# another) the way both services source it; mail-check.sh with its path
# pointed at the checkout's mail-select.sh.
MS_SH="${MAIL_SELECT_SH:-sh}"
MS_TMP=$(mktemp -d)
RT="$MS_TMP/smtp-require-tls.json"
cp "$RT_FILE" "$RT"
CF0=/fxa-keys/oauth-clients.json
sed "s#/portcullis-bin/mail-select.sh#$MAIL_SELECT#" "$MAIL_CHECK" > "$MS_TMP/mail-check.sh"
# $1.. VAR=value; prints the exit status, stderr, and the SMTP_* (password
# as set/unset) and whether the input passwords survived.
ms_run() {
  env -i PATH="$PATH" CONFIG_FILES="$CF0" FXA_SMTP_REQUIRE_TLS_FILE="$RT" "$@" "$MS_SH" -c '
    . "$1" 2> "$2/err"; rc=$?
    printf "rc=%s\nerr=%s\n" "$rc" "$(cat "$2/err")"
    for v in SMTP_HOST SMTP_PORT SMTP_SECURE SMTP_USER SMTP_SENDER; do eval "printf \"%s=%s\n\" $v \"\${$v-<unset>}\""; done
    printf "SMTP_PASS=%s\n" "${SMTP_PASS:+set}"
    printf "inputs=%s%s\n" "${PORTCULLIS_MAIL_SENDER_PASSWORD+provider-pw}" "${EXT_SMTP_PASSWORD+ext-pw}"
    printf "CONFIG_FILES=%s\n" "${CONFIG_FILES-<unset>}"' _ "$MAIL_SELECT" "$MS_TMP"
}
ms_case() {  # $1 name, $2 want (lines), rest: env
  local name=$1 want=$2 got
  shift 2
  got=$(ms_run "$@")
  if [ "$got" = "$want" ]; then pass "mail-select.sh: $name"; else fail "mail-select.sh: $name:
$(diff <(echo "$want") <(echo "$got") || true)"; fi
}
REFUSED() { printf 'rc=1\nerr=%s\nSMTP_HOST=<unset>\nSMTP_PORT=<unset>\nSMTP_SECURE=<unset>\nSMTP_USER=<unset>\nSMTP_SENDER=<unset>\nSMTP_PASS=\ninputs=%s\nCONFIG_FILES=%s' "$1" "${2:-}" "${3:-$CF0}"; }
PROV=(PORTCULLIS_MAIL_SENDER_HOST=mail.example.org PORTCULLIS_MAIL_SENDER_PORT=587
  PORTCULLIS_MAIL_SENDER_USER=portcullis-app-x@example.org PORTCULLIS_MAIL_SENDER_PASSWORD=pw-provider
  'PORTCULLIS_MAIL_SENDER_FROM="Firefox accounts" <portcullis-app-x@example.org>')
EXT=(MAIL_SOURCE=external EXT_SMTP_HOST=smtp.example.net EXT_SMTP_PORT=587 EXT_SMTP_SECURITY=starttls
  EXT_SMTP_USER=fxa EXT_SMTP_PASSWORD=pw-ext EXT_SMTP_SENDER=accounts@example.net)
# refuses_without_mail (unit): provider mode, every sender variable empty.
ms_case "refuses_without_mail: provider mode without the sender env exits 1 with the exact line" \
  "$(REFUSED "$NO_MAIL_LINE" provider-pw)" MAIL_SOURCE=provider PORTCULLIS_MAIL_SENDER_HOST= PORTCULLIS_MAIL_SENDER_PORT= \
  PORTCULLIS_MAIL_SENDER_USER= PORTCULLIS_MAIL_SENDER_PASSWORD= PORTCULLIS_MAIL_SENDER_FROM=
ms_case "refuses_without_mail: no MAIL_SOURCE = provider, nothing set" "$(REFUSED "$NO_MAIL_LINE")"
ms_case "provider: a sender without its password is no sender" "$(REFUSED "$NO_MAIL_LINE" provider-pw)" \
  "${PROV[@]}" PORTCULLIS_MAIL_SENDER_PASSWORD=
ms_case "provider_used: SMTP_* from PORTCULLIS_MAIL_SENDER_*, SMTP_SECURE=false (STARTTLS), the From as is, the input password unset" \
  'rc=0
err=
SMTP_HOST=mail.example.org
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=portcullis-app-x@example.org
SMTP_SENDER="Firefox accounts" <portcullis-app-x@example.org>
SMTP_PASS=set
inputs=
CONFIG_FILES='"$CF0,$RT" "${PROV[@]}"
ms_case "provider: mode provider ignores EXT_SMTP_*" \
  'rc=0
err=
SMTP_HOST=mail.example.org
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=portcullis-app-x@example.org
SMTP_SENDER="Firefox accounts" <portcullis-app-x@example.org>
SMTP_PASS=set
inputs=
CONFIG_FILES='"$CF0,$RT" "${PROV[@]}" EXT_SMTP_HOST=smtp.example.net EXT_SMTP_PASSWORD=pw-ext
ms_case "external_used: starttls = SMTP_SECURE=false on 587, the sender as a name-addr" \
  'rc=0
err=
SMTP_HOST=smtp.example.net
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=fxa
SMTP_SENDER=Firefox accounts <accounts@example.net>
SMTP_PASS=set
inputs=
CONFIG_FILES='"$CF0,$RT" "${EXT[@]}" "${PROV[@]}"
ms_case "external: tls = SMTP_SECURE=true" \
  'rc=0
err=
SMTP_HOST=smtp.example.net
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=fxa
SMTP_SENDER=Firefox accounts <accounts@example.net>
SMTP_PASS=set
inputs=
CONFIG_FILES='"$CF0" "${EXT[@]}" EXT_SMTP_SECURITY=tls EXT_SMTP_PORT=465
ms_case "external: no user and no password (a relay that takes mail as is)" \
  'rc=0
err=
SMTP_HOST=smtp.example.net
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_SENDER=Firefox accounts <accounts@example.net>
SMTP_PASS=
inputs=
CONFIG_FILES='"$CF0,$RT" "${EXT[@]}" EXT_SMTP_USER= EXT_SMTP_PASSWORD=
EXT_NEEDS="portcullis: no mail: the external SMTP server needs a host and a sender address (settings: Mail)"
ms_case "external without a host exits 1" "$(REFUSED "$EXT_NEEDS" ext-pw)" "${EXT[@]}" EXT_SMTP_HOST=
ms_case "external without a sender exits 1" "$(REFUSED "$EXT_NEEDS" ext-pw)" "${EXT[@]}" EXT_SMTP_SENDER=
ms_case "external without host and sender, a provider wired: still refused (no fallback)" \
  "$(REFUSED "$EXT_NEEDS" provider-pwext-pw)" "${EXT[@]}" EXT_SMTP_HOST= EXT_SMTP_SENDER= "${PROV[@]}"
ms_case "external: a user without a password" \
  "$(REFUSED "portcullis: no mail: the external SMTP server has a user but no password" ext-pw)" "${EXT[@]}" EXT_SMTP_PASSWORD=
ms_case "external: a password without a user" \
  "$(REFUSED "portcullis: no mail: the external SMTP server has a password but no user" ext-pw)" "${EXT[@]}" EXT_SMTP_USER=
ms_case "external: unknown security" \
  "$(REFUSED "portcullis: no mail: the SMTP security must be starttls or tls" ext-pw)" "${EXT[@]}" EXT_SMTP_SECURITY=none
for port in 0 65536 05 abc ""; do
  [ -n "$port" ] || continue
  ms_case "external: port '$port' refused" "$(REFUSED "portcullis: no mail: the SMTP port isn't 1-65535" ext-pw)" "${EXT[@]}" EXT_SMTP_PORT="$port"
done
for host in "smtp example" "smtp;id" "-x" "a/b"; do
  ms_case "external: host '$host' refused" "$(REFUSED "portcullis: no mail: the SMTP host isn't a host name" ext-pw)" "${EXT[@]}" EXT_SMTP_HOST="$host"
done
for sender in "x" "a@b" "<a@b.c>" "a@b.c>" "a@@b.c" "a@b..c" "a b@c.d" "@b.c" "a@b.c."; do
  ms_case "external: sender '$sender' refused" \
    "$(REFUSED "portcullis: no mail: the sender of the external SMTP server isn't an email address" ext-pw)" "${EXT[@]}" EXT_SMTP_SENDER="$sender"
done
ms_case "external: a line break in the user refused" \
  "$(REFUSED "portcullis: no mail: the SMTP user holds a control character" ext-pw)" "${EXT[@]}" "EXT_SMTP_USER=fxa
RCPT TO:<x@y.z>"
ms_case "provider: a line break in the From refused" \
  "$(REFUSED "portcullis: no mail: the sender holds a control character" provider-pw)" "${PROV[@]}" "PORTCULLIS_MAIL_SENDER_FROM=a <a@b.c>
Bcc: x@y.z"
ms_case "external: a line break in the password refused" \
  "$(REFUSED "portcullis: no mail: the SMTP password holds a control character" ext-pw)" "${EXT[@]}" "EXT_SMTP_PASSWORD=pw-ext
RCPT TO:<x@y.z>"
ms_case "external: a tab in the password refused" \
  "$(REFUSED "portcullis: no mail: the SMTP password holds a control character" ext-pw)" "${EXT[@]}" "EXT_SMTP_PASSWORD=pw"$'\t'"ext"
# port_mode_mismatch: 587 is STARTTLS's, 465 TLS's from the start; the other
# mode on them is refused before the auth server starts (it would fail at the
# first code sent). Other ports take either mode.
TLS_ON_587="portcullis: no mail: port 587 is for STARTTLS, not TLS from the start: choose STARTTLS, or port 465 for TLS (settings: Mail)"
STARTTLS_ON_465="portcullis: no mail: port 465 is for TLS from the start, not STARTTLS: choose TLS, or port 587 for STARTTLS (settings: Mail)"
ms_case "port_mode_mismatch: tls on 587 refused" "$(REFUSED "$TLS_ON_587" ext-pw)" "${EXT[@]}" EXT_SMTP_SECURITY=tls EXT_SMTP_PORT=587
ms_case "port_mode_mismatch: tls with the port left at its default (587) refused" "$(REFUSED "$TLS_ON_587" ext-pw)" "${EXT[@]}" EXT_SMTP_SECURITY=tls EXT_SMTP_PORT=
ms_case "port_mode_mismatch: starttls on 465 refused" "$(REFUSED "$STARTTLS_ON_465" ext-pw)" "${EXT[@]}" EXT_SMTP_SECURITY=starttls EXT_SMTP_PORT=465
ms_case "port_mode_mismatch: the provider on 465 refused (its listener is STARTTLS)" "$(REFUSED "$STARTTLS_ON_465" provider-pw)" \
  "${PROV[@]}" PORTCULLIS_MAIL_SENDER_PORT=465
ms_case "port_mode_mismatch: starttls on another port (2525) accepted" \
  'rc=0
err=
SMTP_HOST=smtp.example.net
SMTP_PORT=2525
SMTP_SECURE=false
SMTP_USER=fxa
SMTP_SENDER=Firefox accounts <accounts@example.net>
SMTP_PASS=set
inputs=
CONFIG_FILES='"$CF0,$RT" "${EXT[@]}" EXT_SMTP_PORT=2525
ms_case "port_mode_mismatch: tls on another port (2465) accepted" \
  'rc=0
err=
SMTP_HOST=smtp.example.net
SMTP_PORT=2465
SMTP_SECURE=true
SMTP_USER=fxa
SMTP_SENDER=Firefox accounts <accounts@example.net>
SMTP_PASS=set
inputs=
CONFIG_FILES='"$CF0" "${EXT[@]}" EXT_SMTP_SECURITY=tls EXT_SMTP_PORT=2465
[ "$(OPT smtp_password .description)" = "Another SMTP server only. The password of the SMTP user; it can't contain ', \\ or a line break." ] \
  && pass "settings: smtp_password's description says ', \\ and line breaks aren't allowed (the Hub's env quoting, mail-select.sh)" \
  || fail "settings: smtp_password description '$(OPT smtp_password .description)'"
RT_REFUSED="portcullis: no mail: STARTTLS can't be required: FXA_SMTP_REQUIRE_TLS_FILE isn't a readable {\"smtp\":{\"requireTLS\":true}}"
ms_case "starttls_required: no overlay file = refused (never opportunistic)" "$(REFUSED "$RT_REFUSED" ext-pw)" "${EXT[@]}" FXA_SMTP_REQUIRE_TLS_FILE="$MS_TMP/none.json"
ms_case "starttls_required: FXA_SMTP_REQUIRE_TLS_FILE unset = refused" "$(REFUSED "$RT_REFUSED" provider-pw)" "${PROV[@]}" FXA_SMTP_REQUIRE_TLS_FILE=
printf '{"smtp":{"requireTLS":false}}\n' > "$MS_TMP/false.json"
ms_case "starttls_required: an overlay that isn't requireTLS true = refused" "$(REFUSED "$RT_REFUSED" provider-pw)" "${PROV[@]}" FXA_SMTP_REQUIRE_TLS_FILE="$MS_TMP/false.json"
ms_case "starttls_required: tls (465) needs no overlay (implicit TLS)" \
  'rc=0
err=
SMTP_HOST=smtp.example.net
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=fxa
SMTP_SENDER=Firefox accounts <accounts@example.net>
SMTP_PASS=set
inputs=
CONFIG_FILES='"$CF0" "${EXT[@]}" EXT_SMTP_SECURITY=tls EXT_SMTP_PORT=465 FXA_SMTP_REQUIRE_TLS_FILE=
ms_case "starttls_required: empty CONFIG_FILES = the overlay alone" \
  "$(printf 'rc=0\nerr=\nSMTP_HOST=mail.example.org\nSMTP_PORT=587\nSMTP_SECURE=false\nSMTP_USER=portcullis-app-x@example.org\nSMTP_SENDER="Firefox accounts" <portcullis-app-x@example.org>\nSMTP_PASS=set\ninputs=\nCONFIG_FILES=%s' "$RT")" \
  "${PROV[@]}" CONFIG_FILES=
ms_case "starttls_required: the overlay already listed is not added twice" \
  "$(printf 'rc=0\nerr=\nSMTP_HOST=mail.example.org\nSMTP_PORT=587\nSMTP_SECURE=false\nSMTP_USER=portcullis-app-x@example.org\nSMTP_SENDER="Firefox accounts" <portcullis-app-x@example.org>\nSMTP_PASS=set\ninputs=\nCONFIG_FILES=%s' "$RT,/a.json")" \
  "${PROV[@]}" CONFIG_FILES="$RT,/a.json"
ms_case "unknown mail source" "$(REFUSED "portcullis: no mail: the mail source must be provider or external")" MAIL_SOURCE=both
# mail-check.sh: exit 1 with the exact line; on success one line, no secret.
if out=$(env -i PATH="$PATH" FXA_SMTP_REQUIRE_TLS_FILE="$RT" "$MS_SH" "$MS_TMP/mail-check.sh" 2>&1); then
  fail "mail-check.sh: exit 0 without a mail server"
else
  [ "$out" = "$NO_MAIL_LINE" ] && pass "mail-check.sh: exit 1, logs exactly '$NO_MAIL_LINE'" || fail "mail-check.sh: logged '$out'"
fi
if out=$(env -i PATH="$PATH" FXA_SMTP_REQUIRE_TLS_FILE="$RT" "${EXT[@]}" "$MS_SH" "$MS_TMP/mail-check.sh" 2>&1); then
  [ "$out" = "portcullis: mail: the external SMTP server (smtp.example.net:587, STARTTLS)" ] \
    && pass "mail-check.sh: external, exit 0: '$out' (no user, no password)" || fail "mail-check.sh: external printed '$out'"
else
  fail "mail-check.sh: external exited non-zero: $out"
fi
if out=$(env -i PATH="$PATH" FXA_SMTP_REQUIRE_TLS_FILE="$RT" "${PROV[@]}" "$MS_SH" "$MS_TMP/mail-check.sh" 2>&1); then
  [ "$out" = "portcullis: mail: the server's mail provider (mail.example.org:587, STARTTLS)" ] \
    && pass "mail-check.sh: provider, exit 0: '$out'" || fail "mail-check.sh: provider printed '$out'"
else
  fail "mail-check.sh: provider exited non-zero: $out"
fi
rm -rf "$MS_TMP"

# no_cap_default: FXA_MAX_ACCOUNTS as compose renders it (docker compose
# config, no daemon), without the setting and with max_accounts 5.
cap_of() {  # $1 = MAX_ACCOUNTS value or "" (unset) -> fxa-policy's and ffs-admin's FXA_MAX_ACCOUNTS
  local keys k envs=()
  keys=$(_manifest_random_env_keys "$MANIFEST")
  for k in $keys; do envs+=("$k=x"); done
  [ -z "$1" ] || envs+=("MAX_ACCOUNTS=$1")
  env -i PATH="$PATH" HOME="${HOME:-/tmp}" ${DOCKER_CONFIG:+DOCKER_CONFIG="$DOCKER_CONFIG"} "${envs[@]}" \
    docker compose -p portcullis -f "$COMPOSE" --project-directory "$(dirname "$COMPOSE")" config --format json 2>/dev/null \
    | jq -r '[.services["fxa-policy"].environment.FXA_MAX_ACCOUNTS, .services["ffs-admin"].environment.FXA_MAX_ACCOUNTS] | join(" ")'
}
if command -v docker > /dev/null && docker compose version > /dev/null 2>&1; then
  got=$(cap_of "")
  [ "$got" = "unlimited unlimited" ] && pass "no_cap_default: FXA_MAX_ACCOUNTS unlimited without the setting (fxa-policy, ffs-admin)" \
    || fail "no_cap_default: without the setting: '$got'"
  got=$(cap_of 5)
  [ "$got" = "5 5" ] && pass "no_cap_default: FXA_MAX_ACCOUNTS 5 with max_accounts 5" || fail "no_cap_default: with 5: '$got'"
else
  fail "no_cap_default: needs docker compose (config only, no daemon)"
fi
[ "$(ENV fxa-policy FXA_MAX_ACCOUNTS)" = '${MAX_ACCOUNTS:-unlimited}' ] \
  && pass 'no_cap_default: fxa-policy FXA_MAX_ACCOUNTS: ${MAX_ACCOUNTS:-unlimited}' || fail "no_cap_default: fxa-policy $(ENV fxa-policy FXA_MAX_ACCOUNTS)"

# ── Sync (Task 15): our guard on the Sync database, its roles and the node.
# As firefox-sync/ without its allowlist: who may have an account is
# decided on the accounts side. ──
TDIR=$(dirname "$COMPOSE")
NODE_WANT='https://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA:-firefox-sync-fxa.portcullis.local}'
# node_url: one node, this instance's own Sync host (the router's default
# subdomain), everywhere it is named; the public server creates none.
check_env firefox-sync-fxa-migrate SYNC_TOKENSERVER__INIT_NODE_URL "$NODE_WANT"
check_env firefox-sync-fxa-init FIREFOX_SYNC_NODE_URL "$NODE_WANT"
check_env firefox-sync-fxa-db-init DOMAIN "$NODE_WANT"
check_env ffs-admin SYNCSTORAGE_DOMAIN "$NODE_WANT"
check_env firefox-sync-fxa SYNC_TOKENSERVER__INIT_NODE_URL "<unset>"
check_env firefox-sync-fxa SYNC_TOKENSERVER__RUN_MIGRATIONS false
check_env firefox-sync-fxa-migrate SYNC_TOKENSERVER__RUN_MIGRATIONS true
# The public server as firefoxsync_app, the migrations as the owner.
APP_URL='postgres://firefoxsync_app:${FIREFOX_SYNC_FXA_APP_DB_PASSWORD:?FIREFOX_SYNC_FXA_APP_DB_PASSWORD must be set}@firefox-sync-fxa-db:5432/firefoxsync'
OWNER_URL='postgres://firefoxsync:${FIREFOX_SYNC_FXA_DB_PASSWORD:?FIREFOX_SYNC_FXA_DB_PASSWORD must be set}@firefox-sync-fxa-db:5432/firefoxsync'
for k in SYNC_SYNCSTORAGE__DATABASE_URL SYNC_TOKENSERVER__DATABASE_URL; do
  check_env firefox-sync-fxa "$k" "$APP_URL"
  check_env firefox-sync-fxa-migrate "$k" "$OWNER_URL"
done
OWNER_HOLDERS=$(yq -r '[.services | to_entries[] | select(.value.environment // {} | to_entries | any_c(.value | tostring | test("FIREFOX_SYNC_FXA_DB_PASSWORD"))) | .key] | sort | join(" ")' "$COMPOSE")
[ "$OWNER_HOLDERS" = "firefox-sync-fxa-db firefox-sync-fxa-db-init firefox-sync-fxa-init firefox-sync-fxa-migrate" ] \
  && pass "sync roles: the Sync database owner's password only in the database and its three one-shots" \
  || fail "sync roles: the owner's password is in: $OWNER_HOLDERS"
# porelli's init: access managed elsewhere, no list, no limit, no app role
# to hand the tables to.
check_env firefox-sync-fxa-db-init ADMIN_ACCESS_EXTERNAL 1
check_env firefox-sync-fxa-db-init MAX_USERS unlimited
check_env firefox-sync-fxa-db-init SYNC_ALLOWED_ACCOUNTS ""
check_env firefox-sync-fxa-db-init POSTGRES_SYNC_USER ""
check_dep ffs-admin firefox-sync-fxa-init service_completed_successfully
# The init: revoke.sql, then guard.sql in one transaction, then admin-db.sql;
# the files read-only, the values through the environment only.
INIT_CMD=$(yq -r '.services["firefox-sync-fxa-init"].command[0]' "$COMPOSE")
WANT_INIT_CMD='set -e
psql -X -q -t -v ON_ERROR_STOP=1 --single-transaction -f /etc/portcullis/revoke.sql
psql -X -q -t -v ON_ERROR_STOP=1 --single-transaction -f /etc/portcullis/guard.sql
psql -X -q -t -v ON_ERROR_STOP=1 -f /etc/portcullis/admin-db.sql'
[ "$INIT_CMD" = "$WANT_INIT_CMD" ] && pass "firefox-sync-fxa-init: revoke.sql, guard.sql (--single-transaction), admin-db.sql, ON_ERROR_STOP" \
  || fail "firefox-sync-fxa-init command: $INIT_CMD"
[ "$(yq -r '.services["firefox-sync-fxa-init"].volumes | join(" ")' "$COMPOSE")" = "./templates/firefox-sync-fxa/revoke.sql:/etc/portcullis/revoke.sql:ro ./templates/firefox-sync-fxa/guard.sql:/etc/portcullis/guard.sql:ro ./templates/firefox-sync-fxa/admin-db.sql:/etc/portcullis/admin-db.sql:ro" ] \
  && [ "$(yq -r '.services["firefox-sync-fxa-init"] | has("group_add")' "$COMPOSE")" = false ] \
  && pass "firefox-sync-fxa-init: the three SQL files read-only, no data file (no group_add)" \
  || fail "firefox-sync-fxa-init: volumes / group_add"
check_env firefox-sync-fxa-init FIREFOX_SYNC_APP_DB_PASSWORD '${FIREFOX_SYNC_FXA_APP_DB_PASSWORD:?FIREFOX_SYNC_FXA_APP_DB_PASSWORD must be set}'
check_env firefox-sync-fxa-init FIREFOX_SYNC_ADMIN_DB_PASSWORD '${FIREFOX_SYNC_FXA_ADMIN_DB_PASSWORD:?FIREFOX_SYNC_FXA_ADMIN_DB_PASSWORD must be set}'
GUARD="$TDIR/guard.sql"
if [ ! -s "$GUARD" ] || grep -Eq 'allowlist\.json|portcullis_check_allowed_account|INSERT INTO (public\.)?sync_allowed_accounts|DELETE FROM (public\.)?sync_allowed_accounts|CREATE TABLE IF NOT EXISTS sync_allowed_accounts|CREATE (OR REPLACE )?TRIGGER' "$GUARD"; then
  fail "guard.sql: still has firefox-sync's allowlist (data file, table writes or users trigger)"
else
  pass "guard.sql: no allowlist table, data file or users trigger (the accounts side decides who signs up)"
fi
grep -q '^CREATE EVENT TRIGGER portcullis_app_no_ddl ON ddl_command_end$' "$GUARD" \
  && grep -q "^SET LOCAL log_statement = 'none';$" "$GUARD" \
  && [ "$(grep -c '^\\getenv ' "$GUARD")" = 3 ] && ! grep -q '^\\set ' "$GUARD" \
  && pass "guard.sql: the no-DDL event trigger, no statement logging, values only by \\getenv" \
  || fail "guard.sql: event trigger / log_statement / \\getenv"
# The admin UI's roles exactly as firefox-sync's: its guard.sql section, and
# revoke.sql / admin-db.sql from their first statement on, byte for byte.
admin_section() { awk '/^SELECT NOT EXISTS \(SELECT 1 FROM pg_roles WHERE rolname = .firefoxsync_admin.\)/ { on = 1 } /^SELECT .portcullis-guard: / { on = 0 } on' "$1"; }
body() { sed -n '/^SET search_path = pg_catalog, pg_temp;$/,$p' "$1"; }
FS_DIR="$TDIR/../firefox-sync"
if [ -n "$(admin_section "$GUARD")" ] && [ "$(admin_section "$GUARD")" = "$(admin_section "$FS_DIR/guard.sql")" ]; then
  pass "guard.sql: the admin UI's roles section is firefox-sync's, byte for byte"
else
  fail "guard.sql: the admin UI's roles differ from firefox-sync's:
$(diff <(admin_section "$FS_DIR/guard.sql") <(admin_section "$GUARD") | head -20)"
fi
for f in revoke.sql admin-db.sql; do
  [ -n "$(body "$TDIR/$f")" ] && [ "$(body "$TDIR/$f")" = "$(body "$FS_DIR/$f")" ] \
    && pass "$f: firefox-sync's statements, byte for byte" || fail "$f differs from firefox-sync's"
done
# The helper Firefox (tests/fxa_client.py): a password never on argv.
grep -q 'os.environ.get("FXA_PASSWORD"' tests/fxa_client.py && ! grep -Eq 'argv\[[2-9]\]' tests/fxa_client.py \
  && pass "fxa_client.py: the password from FXA_PASSWORD only, never argv" || fail "fxa_client.py: password handling"

# ── Admin (Task 16): the admin UI with OpenID Connect, only the admin group,
# access managed elsewhere. As firefox-sync's firefox-sync-admin, with this
# template's names. ──
FS_COMPOSE="$FS_DIR/compose.yml"
FS_ENV() { yq -r ".services[\"firefox-sync-admin\"].environment.$1 // \"<unset>\"" "$FS_COMPOSE"; }
ADMIN_HOST_DEFAULT='${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_ADMIN:-firefox-sync-fxa-admin.portcullis.local}'
# admin_env: the values the brief fixes.
check_env ffs-admin ADMIN_ACCESS_EXTERNAL 1
check_env ffs-admin ADMIN_PASSWORD ""
check_env ffs-admin ADMIN_ALLOWED_GROUPS '${PORTCULLIS_ADMIN_GROUP:-admin_firefox-sync-fxa}'
check_env ffs-admin ADMIN_OIDC_GROUPS_CLAIM groups
check_env ffs-admin ADMIN_OIDC_TRUST_UNVERIFIED_EMAIL false
check_env ffs-admin ADMIN_OIDC_ISSUER 'https://auth.${PORTCULLIS_DOMAIN:-portcullis.local}/realms/portcullis'
check_env ffs-admin ADMIN_OIDC_CLIENT_ID '${PORTCULLIS_OIDC_CLIENT_ID_FIREFOX_SYNC_FXA_ADMIN:-firefox-sync-fxa-admin}'
check_env ffs-admin ADMIN_OIDC_CLIENT_SECRET '${FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET:?FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET must be set}'
check_env ffs-admin ADMIN_OIDC_REDIRECT_URL "https://$ADMIN_HOST_DEFAULT/auth/callback"
check_env ffs-admin FXA_DB_HOST fxa-db
check_env ffs-admin FXA_DB_USER ffs_admin
check_env ffs-admin FXA_DB_PASSWORD '${FXA_ADMIN_DB_PASSWORD:?FXA_ADMIN_DB_PASSWORD must be set}'
check_env ffs-admin FXA_AUTH_UPSTREAM http://fxa-auth:9000
check_env ffs-admin FXA_CONTENT_URL 'https://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_ACCOUNTS:-firefox-sync-fxa-accounts.portcullis.local}'
check_env ffs-admin FXA_AUTH_URL 'https://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_API:-firefox-sync-fxa-api.portcullis.local}'
check_env ffs-admin FXA_PROFILE_URL 'https://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_PROFILE:-firefox-sync-fxa-profile.portcullis.local}'
check_env ffs-admin FXA_PAIRING_URL 'wss://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_PAIRING:-firefox-sync-fxa-pairing.portcullis.local}'
check_env ffs-admin FXA_ACCOUNT_EVENTS false
[ "$(yq -r '.services["ffs-admin"].environment.FXA_ACCOUNT_EVENTS | tag' "$COMPOSE")" = '!!str' ] \
  && [ "$(yq -r '.services["ffs-admin"].environment.FXA_CLIENT_ADDRESS_DEPTH | tag' "$COMPOSE")" = '!!str' ] \
  && pass 'admin_env: FXA_ACCOUNT_EVENTS "false", FXA_CLIENT_ADDRESS_DEPTH "2" (strings)' \
  || fail "admin_env: FXA_ACCOUNT_EVENTS / FXA_CLIENT_ADDRESS_DEPTH not strings"
# firefox-sync's admin env block: every key it sets is set here, and the
# settings that don't name the instance are the same.
bad=""
for k in $(yq -r '.services["firefox-sync-admin"].environment | keys | .[]' "$FS_COMPOSE"); do
  [ "$(ENV ffs-admin "$k")" != "<unset>" ] || bad="$bad $k(unset)"
done
for k in ADMIN_ACCESS_EXTERNAL MAX_USERS SYNC_ALLOWED_ACCOUNTS ADMIN_PASSWORD ADMIN_OIDC_ISSUER ADMIN_OIDC_SCOPES \
         ADMIN_OIDC_NAME ADMIN_OIDC_GROUPS_CLAIM ADMIN_OIDC_TRUST_UNVERIFIED_EMAIL ADMIN_ALLOWED_USERS ADMIN_AUTH_HEADER \
         SSL_CERT_FILE TOKENSERVER_DB_TYPE TOKENSERVER_DB_PORT TOKENSERVER_DB_NAME TOKENSERVER_DB_USER ADMIN_DB_USER \
         ADMIN_DB_SYNC_USER ADMIN_DB_NAME ALERT_EMAIL ADMIN_NOTIFY SMTP_HOST ADMIN_UPDATE_CHECK ADMIN_PUBLIC_CHECK ADMIN_EXPORT_PORT; do
  [ "$(ENV ffs-admin "$k")" = "$(FS_ENV "$k")" ] || bad="$bad $k($(ENV ffs-admin "$k") != $(FS_ENV "$k"))"
done
[ -z "$bad" ] && pass "admin_env: firefox-sync's admin env block (every key, the instance-free values identical)" \
  || fail "admin_env: differs from firefox-sync-admin's:$bad"
[ "$(ENV ffs-admin ADMIN_INSECURE_COOKIE)" = "<unset>" ] && pass "admin_env: no ADMIN_INSECURE_COOKIE (Secure cookies)" \
  || fail "admin_env: ADMIN_INSECURE_COOKIE is set"
grep -qx './certs/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro' <<< "$(yq -r '.services["ffs-admin"].volumes[]' "$COMPOSE")" \
  && pass "admin_env: Portcullis's CA bundle at SSL_CERT_FILE, read-only (discovery and token exchange through Traefik)" \
  || fail "admin_env: the CA bundle isn't mounted at SSL_CERT_FILE"
# The OIDC client secret: generated, only in ffs-admin, by environment only.
[ "$(yq -r '.env[] | select(.key == "FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET") | .generate' "$MANIFEST")" = random ] \
  && pass "admin secret: FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET declared with generate: random" \
  || fail "admin secret: FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET isn't a generated env entry"
OIDC_HOLDERS=$(yq -r '[.services | to_entries[] | select(.value | tostring | test("FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET")) | .key] | join(" ")' "$COMPOSE")
OIDC_ENV_ONLY=$(yq -r '[.services["ffs-admin"] | del(.environment) | tostring | test("OIDC_SECRET")] | .[0]' "$COMPOSE")
[ "$OIDC_HOLDERS" = ffs-admin ] && [ "$OIDC_ENV_ONLY" = false ] \
  && pass "admin secret: the OIDC client secret only in ffs-admin's environment (no command, entrypoint or other service)" \
  || fail "admin secret: in $OIDC_HOLDERS; outside the environment: $OIDC_ENV_ONLY"
# redirect_uri_matches: one Keycloak client, its one redirect URI the one the
# admin UI sends (ADMIN_OIDC_REDIRECT_URL), its id the client id default.
KC_CLIENTS=$(yq -o=json -I=0 '.keycloak_clients' "$MANIFEST")
WANT_KC='[{"client_id":"firefox-sync-fxa-admin","secret_env":"FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET","redirect_uri":"https://{{HOST_FIREFOX_SYNC_FXA_ADMIN}}/auth/callback","name":"Firefox Sync + own accounts admin UI"}]'
[ "$KC_CLIENTS" = "$WANT_KC" ] && pass "redirect_uri_matches: keycloak_clients is exactly the admin UI's client (one redirect URI, the secret by env)" \
  || fail "redirect_uri_matches: keycloak_clients $KC_CLIENTS"
REG_URI=$(yq -r '.keycloak_clients[0].redirect_uri' "$MANIFEST")
[ "${REG_URI/'{{HOST_FIREFOX_SYNC_FXA_ADMIN}}'/$ADMIN_HOST_DEFAULT}" = "$(ENV ffs-admin ADMIN_OIDC_REDIRECT_URL)" ] \
  && pass "redirect_uri_matches: the registered redirect URI = ADMIN_OIDC_REDIRECT_URL (https://<admin host>/auth/callback)" \
  || fail "redirect_uri_matches: registered $REG_URI, the admin UI sends $(ENV ffs-admin ADMIN_OIDC_REDIRECT_URL)"
# The admin host stays behind Portcullis sign-in and group-gate (Task 11),
# on fxa-gate; ffs-admin itself is on default only, with no published port.
[ "$(yq -r '.services["fxa-gate"].labels["traefik.http.routers.firefox-sync-fxa-admin.rule"]' "$COMPOSE")" = "Host(\`$ADMIN_HOST_DEFAULT\`)" ] \
  && pass "admin host: firefox-sync-fxa-admin router on fxa-gate (gated: gated_routers_gateway)" \
  || fail "admin host: router rule $(yq -r '.services["fxa-gate"].labels["traefik.http.routers.firefox-sync-fxa-admin.rule"]' "$COMPOSE")"
[ "$(yq -r '.auth.sso' "$MANIFEST")" = partial ] && [ "$(yq -r '.auth.group_admin' "$MANIFEST")" = true ] \
  && pass "manifest: sso partial (the admin UI signs in with Portcullis's Keycloak); group_admin true (the admin host: the admin group only)" \
  || fail "manifest: sso $(yq -r '.auth.sso' "$MANIFEST"), group_admin $(yq -r '.auth.group_admin' "$MANIFEST")"
[ "$(yq -r '.tests.signin.host + " " + .tests.signin.path' "$MANIFEST")" = "{{HOST_FIREFOX_SYNC_FXA_ACCOUNTS}} /settings" ] \
  && pass "tests.signin: the accounts host, /settings" || fail "tests.signin: $(yq -o=json -I=0 '.tests.signin' "$MANIFEST")"
[ "$(yq -r '.tests.signin.admin.host + " " + .tests.signin.admin.reach' "$MANIFEST")" = "{{HOST_FIREFOX_SYNC_FXA_ADMIN}} /auth/login" ] \
  && pass "tests.signin.admin: on the admin host, through the admin UI's own sign-in (/auth/login)" \
  || fail "tests.signin.admin: $(yq -o=json -I=0 '.tests.signin.admin' "$MANIFEST")"

# ── Access (Task 13): fxa-access-sync writes the access group's verified
# emails to the sign-up allowlist and disables the accounts of people who
# left (access-sync.sh, the hook access-sync). ──
ACCESS_SH="$TDIR/access-sync.sh"
check_dep fxa-db-users fxa-policy service_completed_successfully
check_dep fxa-access-sync fxa-policy service_completed_successfully
check_dep fxa-access-sync fxa-db-users service_completed_successfully
check_dep fxa-access-sync fxa-keys-owner service_completed_successfully
[ "$(yq -r '.services["fxa-access-sync"].depends_on["fxa-policy"].restart' "$COMPOSE")" = true ] \
  && [ "$(yq -r '.services["fxa-access-sync"].depends_on["fxa-db-users"].restart' "$COMPOSE")" = true ] \
  && pass "access compose: fxa-access-sync restarts with fxa-policy and fxa-db-users (ffs_access made again, then narrowed)" \
  || fail "access compose: fxa-access-sync's depends_on restart flags"
# The manifest: the data file, the hook and the option exactly as the plan.
[ "$(yq -o=json -I=0 '.files' "$MANIFEST")" = '[{"name":"access","service":"fxa-access-sync","mount":"/portcullis","on_membership_change":"hook"}]' ] \
  && pass "access manifest: files = access (fxa-access-sync, /portcullis, on_membership_change hook)" \
  || fail "access manifest: files $(yq -o=json -I=0 '.files' "$MANIFEST")"
[ "$(yq -o=json -I=0 '.hooks' "$MANIFEST")" = '[{"name":"access-sync","service":"fxa-access-sync","command":["/bin/sh","/portcullis-bin/access-sync.sh"],"when":["start","membership_change"],"timeout":"120s"}]' ] \
  && pass "access manifest: hooks = access-sync (fxa-access-sync, /bin/sh /portcullis-bin/access-sync.sh, start + membership_change, 120s)" \
  || fail "access manifest: hooks $(yq -o=json -I=0 '.hooks' "$MANIFEST")"
[ "$(OPT access_email '[.type, (.self_visible | tostring), (has("scope") | tostring), (has("default") | tostring)] | join(" ")')" = 'verified_email false false false' ] \
    && [ "$(yq -o=json -I=0 '.settings.options[] | select(.key == "access_email") | .delivery' "$MANIFEST")" = '[{"file":{"name":"access","field":"email"}}]' ] \
  && pass "access manifest: access_email is a verified_email, self_visible false, delivered only as the access file's email field" \
  || fail "access manifest: access_email $(yq -o=json -I=0 '.settings.options[] | select(.key == "access_email")' "$MANIFEST")"
# The service: the pinned mysql client, unprivileged, the data file's group,
# read-only, the script read-only and the state volume; the password only in
# MYSQL_PWD.
AS='.services["fxa-access-sync"]'
if [ "$(yq -r "$AS.user" "$COMPOSE")" = "10001:10001" ] && [ "$(yq -o=json -I=0 "$AS.group_add" "$COMPOSE")" = '["10001"]' ] \
    && [ "$(yq -r "$AS.read_only" "$COMPOSE")" = true ] && [ "$(yq -o=json -I=0 "$AS.command" "$COMPOSE")" = '["sleep","infinity"]' ] \
    && [ "$(yq -o=json -I=0 "$AS.entrypoint" "$COMPOSE")" = '[]' ] && [ "$(yq -r "$AS | has(\"cap_add\")" "$COMPOSE")" = false ] \
    && [ "$(yq -o=json -I=0 "$AS.volumes" "$COMPOSE")" = '["fxa-access-state:/state","./templates/firefox-sync-fxa/access-sync.sh:/portcullis-bin/access-sync.sh:ro"]' ]; then
  pass "access compose: fxa-access-sync is mysql as 10001:10001 + group 10001, read-only, sleep infinity, fxa-access-state at /state, access-sync.sh read-only"
else
  fail "access compose: fxa-access-sync $(yq -o=json -I=0 "$AS" "$COMPOSE")"
fi
[ "$(yq -o=json -I=0 "$AS.environment" "$COMPOSE")" = '{"MYSQL_HOST":"fxa-db","MYSQL_PWD":"${FXA_ACCESS_DB_PASSWORD:?FXA_ACCESS_DB_PASSWORD must be set}","PORTCULLIS_INSTANCE":"${PORTCULLIS_INSTANCE:-firefox-sync-fxa}"}' ] \
  && pass "access compose: fxa-access-sync's environment is exactly MYSQL_HOST, MYSQL_PWD (ffs_access's password) and PORTCULLIS_INSTANCE" \
  || fail "access compose: fxa-access-sync environment $(yq -o=json -I=0 "$AS.environment" "$COMPOSE")"
ACC_HOLDERS=$(yq -r '[.services | to_entries[] | select(.value | tostring | test("FXA_ACCESS_DB_PASSWORD")) | .key] | sort | join(" ")' "$COMPOSE")
[ "$ACC_HOLDERS" = "fxa-access-sync fxa-policy" ] && [ "$(yq -r "[$AS | del(.environment) | tostring | test(\"FXA_ACCESS_DB_PASSWORD\")] | .[0]" "$COMPOSE")" = false ] \
  && pass "access secret: FXA_ACCESS_DB_PASSWORD only in fxa-policy and in fxa-access-sync's environment" \
  || fail "access secret: FXA_ACCESS_DB_PASSWORD in: $ACC_HOLDERS"
[ "$(yq -o=json -I=0 '.services["fxa-keys-owner"].command' "$COMPOSE")" = '["chown","10001:10001","/fxa-keys","/fxa-access-state"]' ] \
  && grep -qx 'fxa-access-state:/fxa-access-state' <<< "$(yq -r '.services["fxa-keys-owner"].volumes[]' "$COMPOSE")" \
  && pass "access compose: fxa-keys-owner hands fxa-access-state to 10001 (a new volume is root's)" \
  || fail "access compose: fxa-keys-owner $(yq -o=json -I=0 '.services["fxa-keys-owner"]' "$COMPOSE")"
if grep -Eq -- '(^|[^A-Za-z_])(-p|--password)([= ]|$)' "$ACCESS_SH" || [ "$(grep -c '^ *mysql ' "$ACCESS_SH")" != 1 ]; then
  fail "access-sync.sh: mysql gets a password option, or is called other than through my()"
else
  pass "access-sync.sh: one mysql call site (my()), no -p / --password: the password only in MYSQL_PWD"
fi

# access-sync.sh against a stub mysql (prints what the database would and
# keeps every call's argv, MYSQL_PWD and SQL), under the host's sh (dash in
# CI; ACCESS_SYNC_SH picks another). STUB: db = the allowlist's rows,
# noacct = emails without an account, fail = tx | calls.
AS_SH="${ACCESS_SYNC_SH:-sh}"
AS_TMP=$(mktemp -d)
mkdir -p "$AS_TMP/bin" "$AS_TMP/stub" "$AS_TMP/state"
cat > "$AS_TMP/bin/mysql" <<'STUB'
#!/bin/sh
d=$STUB_DIR
i=$(($(ls "$d" | grep -c '^call\.[0-9]*\.sql$') + 1))
printf '%s\n' "$@" > "$d/call.$i.argv"
printf '%s' "${MYSQL_PWD-<unset>}" > "$d/call.$i.pwd"
cat > "$d/call.$i.sql"
if grep -q '^START TRANSACTION;$' "$d/call.$i.sql"; then
  if [ "$(cat "$d/fail" 2> /dev/null)" = tx ]; then
    echo "ERROR 1142 (42000) at line 4: DELETE command denied to user 'ffs_access'@'172.18.0.9' for table 'signup_allowlist'" >&2
    exit 1
  fi
  cat "$d/db" 2> /dev/null
  echo portcullis-access-committed
  exit 0
fi
ln=0 rc=0
while IFS= read -r l; do
  ln=$((ln + 1))
  case "$l" in
    "CALL "*)
      e=$(printf '%s\n' "$l" | sed "s/^CALL [a-z_.]*('\(.*\)');\$/\1/; s/''/'/g")
      if grep -qxF -- "$e" "$d/noacct" 2> /dev/null; then
        echo "ERROR 1644 (45000) at line $ln: no such account" >&2; rc=1
      elif [ "$(cat "$d/fail" 2> /dev/null)" = calls ]; then
        echo "ERROR 1370 (42000) at line $ln: execute command denied to user 'ffs_access'@'%' for routine 'ffs.disable_account_by_email'" >&2; rc=1
      fi ;;
    "SELECT 'portcullis-access-calls';") echo portcullis-access-calls ;;
  esac
done < "$d/call.$i.sql"
exit $rc
STUB
chmod +x "$AS_TMP/bin/mysql"
AS_STATE="$AS_TMP/state/applied.json"
# adoc user=email...: a data file as the Hub writes it (INST: its instance).
adoc() {
  jq -cn --arg i "${INST:-firefox-sync-fxa}" '{version: 1, instance: $i, values: {},
    people: ($ARGS.positional | map(capture("^(?<k>[^=]*)=(?<v>.*)$") | {key: .k, value: {email: .v}}) | from_entries),
    groups: {}, entries: {}}' --args "$@"
}
# as_run <data | "<missing>" | "<as written>"> [NAME=value...]: the script's exit status and
# output ("rc=<n>" last).
as_run() {
  local data=$1
  shift
  rm -f "$AS_TMP"/stub/call.*
  case "$data" in
    "<missing>") rm -f "$AS_TMP/access.json" ;;
    "<as written>") ;;
    *) printf '%s' "$data" > "$AS_TMP/access.json" ;;
  esac
  env -i PATH="$AS_TMP/bin:$PATH" STUB_DIR="$AS_TMP/stub" MYSQL_HOST=fxa-db MYSQL_PWD=pw-access-unit \
    PORTCULLIS_INSTANCE=firefox-sync-fxa FXA_ACCESS_FILE="$AS_TMP/access.json" FXA_ACCESS_STATE="$AS_STATE" "$@" \
    "$AS_SH" "$ACCESS_SH" < /dev/null 2>&1
  echo "rc=$?"
}
as_calls() { find "$AS_TMP/stub" -name 'call.*.sql' | grep -c . || true; }
as_state() { cat "$AS_STATE" 2> /dev/null || echo "<none>"; }
as_case() {  # $1 name, $2 want SQL of the transaction ("" = none), $3 want calls ("" = none), $4 want state, $5 output
  local name=$1 out=$5 got_tx got_calls
  got_tx=$( [ -f "$AS_TMP/stub/call.1.sql" ] && cat "$AS_TMP/stub/call.1.sql" || true)
  got_calls=$( [ -f "$AS_TMP/stub/call.2.sql" ] && sed '$d' "$AS_TMP/stub/call.2.sql" || true)
  if [ "${out##*$'\n'}" != rc=0 ]; then fail "access-sync.sh: $name: $out"; return 0; fi
  [ "$got_tx" = "$2" ] && pass "access-sync.sh: $name: the transaction's SQL" || fail "access-sync.sh: $name: transaction SQL:
$(diff <(echo "$2") <(echo "$got_tx") || true)"
  [ "$got_calls" = "$3" ] && pass "access-sync.sh: $name: the calls ($(grep -c . <<< "$3" || true))" || fail "access-sync.sh: $name: calls:
$(diff <(echo "$3") <(echo "$got_calls") || true)"
  [ "$(as_state)" = "$4" ] && pass "access-sync.sh: $name: the state" || fail "access-sync.sh: $name: state $(as_state), want $4"
  if grep -q '@' <<< "$out"; then fail "access-sync.sh: $name: an email in the log: $out"; else pass "access-sync.sh: $name: the log has counts, no email"; fi
}
TX_HEAD="SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION';
START TRANSACTION;
SELECT entry FROM ffs.signup_allowlist ORDER BY entry FOR UPDATE;"
TX_TAIL="COMMIT;
SELECT 'portcullis-access-committed';"
tx_for() {  # the transaction for the listed emails (SQL literals as given)
  local in sel
  in=$(printf "'%s'\n" "$@" | paste -sd, -)
  sel=$(printf "SELECT '%s' AS e\n" "$@" | sed '2,$s/^/UNION ALL /' | paste -sd' ' -)
  printf '%s\nDELETE FROM ffs.signup_allowlist WHERE entry NOT IN (%s);\nINSERT INTO ffs.signup_allowlist (entry) SELECT n.e FROM (%s) AS n WHERE NOT EXISTS (SELECT 1 FROM ffs.signup_allowlist a WHERE a.entry = n.e);\n%s' \
    "$TX_HEAD" "$in" "$sel" "$TX_TAIL"
}
LONG="$(printf 'a%.0s' $(seq 1 250))@x.io"
# Fail closed: no SQL at all (the stub never called), the state untouched.
printf '{"version":1,"listed":["keep@example.org"],"removed":[]}\n' > "$AS_STATE"
STATE0=$(as_state)
bad=""
as_refused() {  # $1 label, $2 data, rest env
  local label=$1 data=$2 out
  shift 2
  out=$(as_run "$data" "$@")
  if [ "${out##*$'\n'}" = rc=1 ] && [ "$(as_calls)" = 0 ] && [ "$(as_state)" = "$STATE0" ] && grep -q 'nothing changed' <<< "$out" \
      && ! grep -q '@' <<< "$out"; then
    pass "access-sync.sh: fails closed, no SQL: $label"
  else
    fail "access-sync.sh: $label: $(tr '\n' ' ' <<< "$out") (calls $(as_calls), state $(as_state))"
  fi
}
as_refused "missing_file_keeps_list (no data file)" "<missing>"
as_refused "unparsable_file_keeps_list (cut short)" '{"version":1,"instance":"firefox-sync-fxa","people":{'
as_refused "unparsable_file_keeps_list (not an object)" '[]'
as_refused "empty file" ''
as_refused "version 2" '{"version":2,"instance":"firefox-sync-fxa","people":{}}'
as_refused 'version "1" (a string)' '{"version":"1","instance":"firefox-sync-fxa","people":{}}'
as_refused "version 1.0" '{"version":1.0,"instance":"firefox-sync-fxa","people":{}}'
as_refused "no version" '{"instance":"firefox-sync-fxa","people":{}}'
as_refused "another instance's file" "$(INST=other adoc a=a@example.org)"
as_refused "no instance" '{"version":1,"people":{}}'
as_refused "PORTCULLIS_INSTANCE unset" "$(adoc a=a@example.org)" PORTCULLIS_INSTANCE=
as_refused "no people" '{"version":1,"instance":"firefox-sync-fxa"}'
as_refused "people a list" '{"version":1,"instance":"firefox-sync-fxa","people":[]}'
as_refused "a person not an object" '{"version":1,"instance":"firefox-sync-fxa","people":{"a":"a@example.org"}}'
as_refused "an email not a string" '{"version":1,"instance":"firefox-sync-fxa","people":{"a":{"email":["a@example.org"]}}}'
as_refused "a duplicate key" '{"version":1,"instance":"firefox-sync-fxa","people":{},"people":{"a":{"email":"a@example.org"}}}'
as_refused "a duplicate person field" '{"version":1,"instance":"firefox-sync-fxa","people":{"a":{"email":"a@example.org","email":"b@example.org"}}}'
as_refused "trailing data" "$(adoc a=a@example.org) {}"
as_refused "a trailing comma" '{"version":1,"instance":"firefox-sync-fxa","people":{},}'
as_refused "a comment" '{"version":1,"instance":"firefox-sync-fxa","people":{}} // x'
as_refused "a raw line break in a string" $'{"version":1,"instance":"firefox-sync-fxa","people":{"a":{"email":"a@example.org\n"}}}'
as_refused "a bad escape" '{"version":1,"instance":"firefox-sync-fxa","people":{"a":{"email":"a\x@example.org"}}}'
as_refused "NaN" '{"version":NaN,"instance":"firefox-sync-fxa","people":{}}'
as_refused "nested too deep" "{\"version\":1,\"instance\":\"firefox-sync-fxa\",\"people\":{},\"x\":$(printf '[%.0s' $(seq 1 40))$(printf ']%.0s' $(seq 1 40))}"
as_refused "larger than 4 MiB" "$(head -c 4194305 /dev/zero | tr '\0' ' ')$(adoc a=a@example.org)"
as_refused "MYSQL_PWD unset" "$(adoc a=a@example.org)" MYSQL_PWD=
printf '{"version":1,"instance":"firefox-sync-fxa","people":{"a":{"email":"a\000@example.org"}}}' > "$AS_TMP/access.json"
as_refused "a NUL byte" "<as written>"
rm -f "$AS_STATE"
# join_allows / first run without a state: every member's row, the rows of
# non-members deleted and their accounts disabled; emails lowercased,
# duplicates once, quotes doubled; what isn't a plain address (spaces, SQL,
# non-ASCII, control characters, over 254 characters) left out.
printf '%s\n' "@example.com" 'carol@example.org' 'Alice@Example.org' 'junk\\x' > "$AS_TMP/stub/db"
: > "$AS_TMP/stub/noacct"; : > "$AS_TMP/stub/fail"
OUT=$(as_run "$(adoc alice=' Alice@Example.ORG ' bob=bob@example.org odd="o'neil@example.org" s1=shared@example.org s2=shared@example.org \
  bad="x y@example.org" inj="a');DROP TABLE ffs.settings;--@example.org" uni="é@example.org" ctl=$'a\tb@example.org' long="$LONG" dq='a"b@example.org')")
as_case "first run" "$(tx_for alice@example.org bob@example.org "o''neil@example.org" shared@example.org)" \
  "CALL ffs.disable_account_by_email('carol@example.org');" \
  '{"version":1,"listed":["alice@example.org","bob@example.org","o'"'"'neil@example.org","shared@example.org"],"removed":["carol@example.org"]}' "$OUT"
grep -q '6 emails left out' <<< "$OUT" && pass "access-sync.sh: first run: 6 emails that aren't plain addresses left out (counted, not logged)" \
  || fail "access-sync.sh: first run: left-out count: $OUT"
ARGV=$(cat "$AS_TMP/stub/call.1.argv" "$AS_TMP/stub/call.2.argv")
if [ "$(head -1 "$AS_TMP/stub/call.1.argv")" = --no-defaults ] && grep -qx ffs_access <<< "$ARGV" && grep -qx -- --force "$AS_TMP/stub/call.2.argv" \
    && ! grep -qx -- --force "$AS_TMP/stub/call.1.argv" && ! grep -q 'pw-access-unit' <<< "$ARGV" \
    && [ "$(cat "$AS_TMP/stub/call.1.pwd")" = pw-access-unit ] && [ "$(cat "$AS_TMP/stub/call.2.pwd")" = pw-access-unit ]; then
  pass "access-sync.sh: mysql --no-defaults as ffs_access, the password in MYSQL_PWD only (on no argv); the transaction without --force (any error ends it), the calls with"
else
  fail "access-sync.sh: mysql argv / MYSQL_PWD: $(tr '\n' ' ' <<< "$ARGV")"
fi
# leave_disables: alice leaves: her row goes, her account is disabled; carol
# (state.removed) is disabled again.
printf '%s\n' alice@example.org bob@example.org "o'neil@example.org" shared@example.org > "$AS_TMP/stub/db"
OUT=$(as_run "$(adoc bob=bob@example.org odd="o'neil@example.org" s1=shared@example.org)")
as_case "leave" "$(tx_for bob@example.org "o''neil@example.org" shared@example.org)" \
  "CALL ffs.disable_account_by_email('alice@example.org');
CALL ffs.disable_account_by_email('carol@example.org');" \
  '{"version":1,"listed":["bob@example.org","o'"'"'neil@example.org","shared@example.org"],"removed":["alice@example.org","carol@example.org"]}' "$OUT"
# Every run: a routine run with nothing changed disables the non-members it
# knows again ("no such account" ignored) and enables nobody.
printf '%s\n' bob@example.org "o'neil@example.org" shared@example.org > "$AS_TMP/stub/db"
echo carol@example.org > "$AS_TMP/stub/noacct"
OUT=$(as_run "$(adoc bob=bob@example.org odd="o'neil@example.org" s1=shared@example.org)")
as_case "routine run (no such account ignored)" "$(tx_for bob@example.org "o''neil@example.org" shared@example.org)" \
  "CALL ffs.disable_account_by_email('alice@example.org');
CALL ffs.disable_account_by_email('carol@example.org');" \
  '{"version":1,"listed":["bob@example.org","o'"'"'neil@example.org","shared@example.org"],"removed":["alice@example.org","carol@example.org"]}' "$OUT"
grep -q '(1 without an account)' <<< "$OUT" && pass "access-sync.sh: routine run: 'no such account' counted, not an error" \
  || fail "access-sync.sh: routine run: $OUT"
# rejoin_enables: alice back: her row, then her account enabled.
OUT=$(as_run "$(adoc alice=alice@example.org bob=bob@example.org odd="o'neil@example.org" s1=shared@example.org)")
as_case "rejoin" "$(tx_for alice@example.org bob@example.org "o''neil@example.org" shared@example.org)" \
  "CALL ffs.disable_account_by_email('carol@example.org');
CALL ffs.enable_account_by_email('alice@example.org');" \
  '{"version":1,"listed":["alice@example.org","bob@example.org","o'"'"'neil@example.org","shared@example.org"],"removed":["carol@example.org"]}' "$OUT"
# admin_disable_survives: the next run with the same file enables nobody (a
# member an admin disabled stays disabled).
printf '%s\n' alice@example.org bob@example.org "o'neil@example.org" shared@example.org > "$AS_TMP/stub/db"
OUT=$(as_run "$(adoc alice=alice@example.org bob=bob@example.org odd="o'neil@example.org" s1=shared@example.org)")
as_case "admin_disable_survives (same file again)" "$(tx_for alice@example.org bob@example.org "o''neil@example.org" shared@example.org)" \
  "CALL ffs.disable_account_by_email('carol@example.org');" \
  '{"version":1,"listed":["alice@example.org","bob@example.org","o'"'"'neil@example.org","shared@example.org"],"removed":["carol@example.org"]}' "$OUT"
# A failed call (anything but "no such account") or a failed transaction:
# exit 1, the state as it was (the next run does it all again).
STATE1=$(as_state)
echo calls > "$AS_TMP/stub/fail"
OUT=$(as_run "$(adoc bob=bob@example.org)")
[ "${OUT##*$'\n'}" = rc=1 ] && [ "$(as_state)" = "$STATE1" ] && ! grep -q '@' <<< "$OUT" \
  && pass "access-sync.sh: a call refused for another reason: exit 1, the state unchanged ($(head -1 <<< "$OUT"))" \
  || fail "access-sync.sh: a refused call: $OUT; state $(as_state)"
echo tx > "$AS_TMP/stub/fail"
OUT=$(as_run "$(adoc bob=bob@example.org)")
[ "${OUT##*$'\n'}" = rc=1 ] && [ "$(as_calls)" = 1 ] && [ "$(as_state)" = "$STATE1" ] && grep -q 'nothing changed' <<< "$OUT" \
  && ! grep -q '@' <<< "$OUT" \
  && pass "access-sync.sh: a failed transaction: exit 1, no calls, the state unchanged, the database's message withheld" \
  || fail "access-sync.sh: a failed transaction: $OUT; calls $(as_calls); state $(as_state)"
: > "$AS_TMP/stub/fail"
# Nobody listed: every row deleted, every account disabled, nothing inserted.
OUT=$(as_run "$(adoc)")
as_case "nobody listed" "$TX_HEAD
DELETE FROM ffs.signup_allowlist;
$TX_TAIL" \
  "CALL ffs.disable_account_by_email('alice@example.org');
CALL ffs.disable_account_by_email('bob@example.org');
CALL ffs.disable_account_by_email('carol@example.org');
CALL ffs.disable_account_by_email('o''neil@example.org');
CALL ffs.disable_account_by_email('shared@example.org');" \
  '{"version":1,"listed":[],"removed":["alice@example.org","bob@example.org","carol@example.org","o'"'"'neil@example.org","shared@example.org"]}' "$OUT"
# state_lost_still_disables: no state, carol's row in the database only.
rm -f "$AS_STATE"
printf '%s\n' bob@example.org carol@example.org > "$AS_TMP/stub/db"
OUT=$(as_run "$(adoc bob=bob@example.org)")
as_case "state_lost_still_disables" "$(tx_for bob@example.org)" "CALL ffs.disable_account_by_email('carol@example.org');" \
  '{"version":1,"listed":["bob@example.org"],"removed":["carol@example.org"]}' "$OUT"
# An unreadable state is no state (from the database alone), never a stop.
echo garbage > "$AS_STATE"
OUT=$(as_run "$(adoc bob=bob@example.org)")
as_case "an unreadable state" "$(tx_for bob@example.org)" "CALL ffs.disable_account_by_email('carol@example.org');" \
  '{"version":1,"listed":["bob@example.org"],"removed":["carol@example.org"]}' "$OUT"
grep -q 'the state file is unreadable' <<< "$OUT" && pass "access-sync.sh: an unreadable state is reported" || fail "access-sync.sh: unreadable state: $OUT"
[ "$(find "$AS_TMP/state" -name 'applied.json' -perm 0600 | wc -l | tr -d ' ')" = 1 ] && [ -z "$(find "$AS_TMP/state" -name '.applied*')" ] \
  && pass "access-sync.sh: the state file is 0600, no temporary file left" || fail "access-sync.sh: state file mode / leftovers: $(ls -la "$AS_TMP/state")"
rm -rf "$AS_TMP"

FXA_DONE=1
if [ "${STATIC_ONLY:-}" = 1 ]; then
  exit 0
fi

# ══ Live (core running; CI's Test Apps job) ══════════════════════════════
# Task 14's mail checks against the real containers. The rest of the stack
# (fxa-gate's nginx, the access sync, ...) comes with later tasks: only the
# accounts' mail path is exercised here, fxa-auth reached inside its own
# container. Until the end, an abort is a failure again.
FXA_DONE=0

# ══ fxa-gate (Task 12) against stand-ins: the real fxa-gate.sh, as compose
# runs it (user 101, read-only, no capabilities), on a throwaway network with
# fixed addresses: one "Traefik" peer, stand-in upstreams under the
# -internal names that answer with what they received. ══
section "Firefox Sync + own accounts (gate, stand-ins)"
GT="portcullis-fxa-test-gate-$$"
GT_NET="$GT-net"
FXA_TEST_CONTAINERS="$FXA_TEST_CONTAINERS $GT-main $GT-pairing $GT-gate"
FXA_TEST_NETWORKS="$FXA_TEST_NETWORKS $GT_NET"
docker network create --subnet 10.254.78.0/24 --ip-range 10.254.78.128/25 "$GT_NET" > /dev/null
# shellcheck disable=SC2016
UPCONF='server { client_max_body_size 0; listen 3030; listen 9000; listen 8081; listen 1111; listen 1112; listen 8000; listen 8080;
  location / { default_type text/plain; return 200 "up=@NAME@ port=$server_port uri=$request_uri host=$http_host auth=[$http_authorization] xat=[$http_x_forwarded_access_token$http_x_auth_request_access_token] cookie=[$http_cookie] xff=[$http_x_forwarded_for] proto=$http_x_forwarded_proto upgrade=$http_upgrade"; } }'
for n in main pairing; do
  if [ "$n" = main ]; then
    aliases=(--network-alias fxa-content-internal --network-alias fxa-auth-internal --network-alias ffs-admin-internal
             --network-alias fxa-profile-internal --network-alias fxa-profile-static-internal --network-alias firefox-sync-fxa-internal)
  else
    aliases=(--network-alias fxa-pairing-internal)
  fi
  UPCONF="${UPCONF//@NAME@/$n}" docker run -d --name "$GT-$n" --network "$GT_NET" "${aliases[@]}" -e UPCONF \
    --entrypoint sh "$NGINX_IMAGE" -c 'printf "%s\n" "$UPCONF" > /etc/nginx/conf.d/default.conf && exec nginx -g "daemon off;"' > /dev/null
done
GH_ACC=accounts.fxa-gate.test GH_API=api.fxa-gate.test GH_PROF=profile.fxa-gate.test GH_SYNC=sync.fxa-gate.test
GH_ADMIN=admin.fxa-gate.test GH_PAIR=pairing.fxa-gate.test
GATE_ENV=(-e PORTCULLIS_TRAEFIK_SOURCE=10.254.78.2/32 -e GATE_LISTEN=8080 -e "GATE_HOST_ACCOUNTS=$GH_ACC" -e "GATE_HOST_API=$GH_API"
  -e "GATE_HOST_PROFILE=$GH_PROF" -e "GATE_HOST_SYNC=$GH_SYNC" -e "GATE_HOST_ADMIN=$GH_ADMIN" -e "GATE_HOST_PAIRING=$GH_PAIR"
  -e GATE_ADMIN_GROUP=admin_firefox-sync-fxa)
GATE_RUN=(--user 101:101 --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64
  -v "$(cd "$(dirname "$GATE_SH")" && pwd)/fxa-gate.sh:/portcullis/fxa-gate.sh:ro" --entrypoint /bin/sh)
docker run -d --name "$GT-gate" --network "$GT_NET" --ip 10.254.78.20 "${GATE_RUN[@]}" "${GATE_ENV[@]}" \
  "$NGINX_IMAGE" /portcullis/fxa-gate.sh > /dev/null
for _ in $(seq 1 20); do
  docker run --rm --network "$GT_NET" --ip 10.254.78.2 --entrypoint curl "$NGINX_IMAGE" -s -o /dev/null --max-time 2 \
    -H "Host: $GH_ACC" http://10.254.78.20:8080/ && break
  sleep 1
done
# gt <client ip> <curl args...>: "<body> [<status>]" as the client sees it.
gt() {
  local ip=$1
  shift
  docker run --rm -i --network "$GT_NET" --ip "$ip" --entrypoint curl "$NGINX_IMAGE" -s --max-time 10 --path-as-is \
    -w ' [%{http_code}]' "$@" 2>/dev/null || true
}
T_IP=10.254.78.2
G=http://10.254.78.20:8080
OUT=$(gt $T_IP -H "Host: $GH_ACC" -H 'Authorization: Bearer kc-token' -H 'X-Forwarded-Access-Token: kc' -H 'X-Auth-Request-Access-Token: kc' \
  -H 'X-Forwarded-For: 198.51.100.7' -H 'Cookie: a=1; _oauth2_proxy=s; _oauth2_proxy_1=t; __Host-portcullis_ext_csrf=u; b=2' "$G/settings")
[ "$OUT" = "up=main port=3030 uri=/settings host=$GH_ACC auth=[] xat=[] cookie=[a=1; b=2] xff=[198.51.100.7] proto=https upgrade= [200]" ] \
  && pass "gate_routes: accounts -> fxa-content-internal:3030; Authorization, the access-token headers and the forward-auth cookies stripped; Host and X-Forwarded-For unchanged" \
  || fail "gate_routes: accounts: $OUT"
OUT=$(gt $T_IP -H "Host: $GH_API" -H 'Authorization: Hawk id="x"' -H 'Cookie: _oauth2_proxy=s' "$G/v1/account/status")
[ "$OUT" = "up=main port=9000 uri=/v1/account/status host=$GH_API auth=[Hawk id=\"x\"] xat=[] cookie=[] xff=[] proto=https upgrade= [200]" ] \
  && pass "gate_routes: api -> fxa-auth-internal:9000, Firefox's own Authorization kept, the forward-auth cookie stripped" \
  || fail "gate_routes: api: $OUT"
bad=""
for p in /v1/account/create '/v1/account/create?keys=true'; do
  OUT=$(gt $T_IP -X POST -H "Host: $GH_API" "$G$p")
  case "$OUT" in "up=main port=8081 uri=$p host="*" [200]") ;; *) bad="$bad $p($OUT)" ;; esac
done
[ -z "$bad" ] && pass "signup_path_variants: exactly /v1/account/create (with or without a query) goes to the sign-up gate (ffs-admin-internal:8081)" \
  || fail "signup_path_variants: the canonical path not to the sign-up gate:$bad"
bad=""
for p in /v1/account/create/ //v1/account/create /v1//account/create /V1/Account/Create /v1/account/%63reate \
         /v1/./account/create /v1/x/../account/create /v1/account/create.json /v1/account/create/x '/v1/account/create/?keys=true' \
         /v1/account/create%2F /v1/account%2Fcreate /v1/account/%43reate /v1/%2e/account/create /v1/account/%2e/create \
         /v1/x/%2e%2e/account/create /v1/account/create%2f; do
  OUT=$(gt $T_IP -X POST -H "Host: $GH_API" "$G$p")
  [ "$OUT" = "fxa-gate: not found
 [404]" ] || bad="$bad $p($OUT)"
done
[ -z "$bad" ] && pass "signup_path_variants: every other spelling of /v1/account/create (trailing slash, a suffix, //, case, %-encoding, dot segments) -> the gate's 404, never fxa-auth or the sign-up gate" \
  || fail "signup_path_variants: not refused by the gate:$bad"
# account_creation_routes: the other routes of fxa-auth v1.350.0 that call
# db.createAccount (passwordless confirm_code, linked_account login) and
# their siblings: the gate's 403, any spelling.
bad=""
for p in /v1/account/passwordless/send_code /v1/account/passwordless/confirm_code /v1/account/passwordless/resend_code \
         /v1/linked_account/login /v1/linked_account/unlink /V1/Linked_Account/Login //v1/linked_account/login \
         /v1/account/%70asswordless/confirm_code /v1/account/passwordless /v1/account/stub /v1/account/finish_setup \
         /v1/account/set_password /V1/Account/Stub /v1/account/stub/ //v1/account/finish_setup; do
  OUT=$(gt $T_IP -X POST -H "Host: $GH_API" "$G$p")
  [ "$OUT" = "fxa-gate: accounts are created through the sign-up gate only
 [403]" ] || bad="$bad $p($OUT)"
done
[ -z "$bad" ] && pass "account_creation_routes: passwordless, linked-account (third-party) and the old stub-account routes (stub, finish_setup, set_password) -> the gate's 403, every spelling" \
  || fail "account_creation_routes: not refused:$bad"
OUT=$(gt $T_IP -X POST -H "Host: $GH_API" "$G/v1/account/passwordlessx")
case "$OUT" in "up=main port=9000 "*) pass "account_creation_routes: a neighbouring path (/v1/account/passwordlessx) still reaches fxa-auth" ;; *) fail "account_creation_routes: neighbour: $OUT" ;; esac
# email_change_routes (Task 13): adding a secondary email or making one
# primary (fxa-auth v1.350.0 lib/routes/emails.js, and the older routes the
# auth client names) is the gate's 403, any spelling; what sign-up, sign-in
# and the account pages need still reaches fxa-auth.
EMAIL_REFUSED="fxa-gate: an account's email is its Portcullis email: it can't be added or changed here"
bad=""
for p in /v1/mfa/recovery_email /v1/mfa/recovery_email/ /v1/mfa/recovery_email/destroy /v1/mfa/recovery_email/set_primary \
         /v1/mfa/recovery_email/secondary/verify_code /v1/mfa/recovery_email/secondary/resend_code /V1/MFA/Recovery_Email/Set_Primary \
         //v1/mfa/recovery_email/set_primary /v1/mfa/%72ecovery_email/set_primary /v1/x/../mfa/recovery_email \
         /v1/recovery_email /v1/recovery_email/ /v1/recovery_email/set_primary /v1/recovery_email/destroy \
         /v1/recovery_email/secondary/verify_code /v1/recovery_email/secondary/resend_code /v1/recovery_email//set_primary; do
  OUT=$(gt $T_IP -X POST -H "Host: $GH_API" "$G$p")
  [ "$OUT" = "$EMAIL_REFUSED
 [403]" ] || bad="$bad $p($OUT)"
done
[ -z "$bad" ] && pass "email_change_routes: adding, removing or making primary an email (mfa/recovery_email*, recovery_email, set_primary, secondary/*) -> the gate's 403, every spelling" \
  || fail "email_change_routes: not refused:$bad"
bad=""
for p in /v1/recovery_email/status /v1/recovery_email/verify_code /v1/recovery_email/resend_code /v1/recovery_emails /v1/mfa/otp/request; do
  OUT=$(gt $T_IP -X POST -H "Host: $GH_API" "$G$p")
  case "$OUT" in "up=main port=9000 "*) ;; *) bad="$bad $p($OUT)" ;; esac
done
[ -z "$bad" ] && pass "email_change_routes: recovery_email/status, verify_code, resend_code (sign-up and sign-in), recovery_emails (the list) and mfa/otp still reach fxa-auth" \
  || fail "email_change_routes: refused what sign-up / sign-in need:$bad"
# no_upgrade_tunnel (I1): only the pairing host passes an Upgrade.
bad=""
for h in "$GH_ACC" "$GH_API" "$GH_PROF" "$GH_SYNC" "$GH_ADMIN"; do
  for u in h2c websocket; do
    OUT=$(gt $T_IP -H "Host: $h" -H 'X-Auth-Request-Groups: admin_firefox-sync-fxa' -H 'Connection: Upgrade, HTTP2-Settings' \
      -H "Upgrade: $u" -H 'HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA' "$G/")
    [ "$OUT" = "fxa-gate: no protocol upgrade on this host
 [400]" ] || bad="$bad $h/$u($OUT)"
  done
done
[ -z "$bad" ] && pass "no_upgrade_tunnel: Upgrade: h2c / websocket on the accounts, API, profile, Sync and admin hosts -> the gate's 400 (no tunnel past its rules)" \
  || fail "no_upgrade_tunnel:$bad"
OUT=$(gt $T_IP -H "Host: $GH_API" -H 'Connection: keep-alive, Upgrade' "$G/v1/x")
case "$OUT" in *"upgrade= [200]") pass "no_upgrade_tunnel: without an Upgrade header no Upgrade reaches the service" ;; *) fail "no_upgrade_tunnel: $OUT" ;; esac
OUT=$(gt $T_IP -H "Host: $GH_API" "$G/v1/account/login")
case "$OUT" in "up=main port=9000 uri=/v1/account/login "*) pass "gate_routes: api /v1/account/login -> fxa-auth (not the sign-up gate)" ;; *) fail "gate_routes: api login: $OUT" ;; esac
OUT=$(gt $T_IP -H "Host: $GH_PROF" -H 'Authorization: Bearer fxa' "$G/v1/profile")
case "$OUT" in "up=main port=1111 uri=/v1/profile host=$GH_PROF auth=[Bearer fxa] "*) pass "gate_routes: profile -> fxa-profile-internal:1111 (Authorization kept)" ;; *) fail "gate_routes: profile: $OUT" ;; esac
OUT=$(gt $T_IP -H "Host: $GH_PROF" "$G/img/a/0123456789abcdef0123456789abcdef")
case "$OUT" in "up=main port=1112 uri=/a/0123456789abcdef0123456789abcdef "*) pass "gate_routes: profile /img/ -> fxa-profile-static-internal:1112, the prefix stripped" ;; *) fail "gate_routes: profile /img/: $OUT" ;; esac
OUT=$(gt $T_IP -H "Host: $GH_SYNC" -H 'Authorization: Hawk id="s"' "$G/1.0/sync/1.5")
case "$OUT" in "up=main port=8000 uri=/1.0/sync/1.5 host=$GH_SYNC auth=[Hawk id=\"s\"] "*) pass "gate_routes: sync -> firefox-sync-fxa-internal:8000 (Authorization kept)" ;; *) fail "gate_routes: sync: $OUT" ;; esac
OUT=$(gt $T_IP -H "Host: $GH_PAIR" -H 'Connection: Upgrade' -H 'Upgrade: websocket' "$G/v1/ws/")
case "$OUT" in "up=pairing port=8000 uri=/v1/ws/ host=$GH_PAIR "*"upgrade=websocket [200]") pass "gate_routes: pairing -> fxa-pairing-internal:8000, the websocket upgrade passed on" ;; *) fail "gate_routes: pairing: $OUT" ;; esac
BIG=$(head -c 2621440 /dev/zero | tr '\0' 'a')
OUT=$(gt $T_IP -o /dev/null -X POST -H "Host: $GH_SYNC" --data-binary @- "$G/1.5/x/storage/bookmarks" <<< "$BIG")
[ "$OUT" = " [200]" ] && pass "gate_body: a 2.5 MB body passes on the Sync host (client_max_body_size 10m)" || fail "gate_body: Sync host 2.5 MB: $OUT"
OUT=$(gt $T_IP -o /dev/null -X POST -H "Host: $GH_API" --data-binary @- "$G/v1/x" <<< "$BIG")
[ "$OUT" = " [413]" ] && pass "gate_body: 2.5 MB on the API host -> 413 (2 MB elsewhere)" || fail "gate_body: API host 2.5 MB: $OUT"
unset BIG
# The admin host: group-gate's X-Auth-Request-Groups must list the admin
# group as one exact entry.
bad=""
for g in "admin_firefox-sync-fxa=200" "users_firefox-sync-fxa,admin_firefox-sync-fxa=200" "x, admin_firefox-sync-fxa ,y=200" \
         "=403" "users_firefox-sync-fxa=403" "ADMIN_FIREFOX-SYNC-FXA=403" "admin_firefox-sync-fxa-x=403" "/admin_firefox-sync-fxa=403" \
         "xadmin_firefox-sync-fxa=403" "admin_firefox-sync-fxa2,users=403" "admin_firefox-sync-fxa;x=403" "admin_.*=403"; do
  want=${g##*=} g=${g%=*}
  if [ -n "$g" ]; then
    OUT=$(gt $T_IP -H "Host: $GH_ADMIN" -H "X-Auth-Request-Groups: $g" -H 'Authorization: Bearer kc' "$G/")
  else
    OUT=$(gt $T_IP -H "Host: $GH_ADMIN" -H 'Authorization: Bearer kc' "$G/")
  fi
  if [ "$want" = 403 ]; then
    [ "$OUT" = "fxa-gate: the admin UI is for the instance's admin group only
 [403]" ] || bad="$bad '$g'->$OUT(want the gate's 403)"
  else
    case "$OUT" in "up=main port=8080 "*" [200]") ;; *) bad="$bad '$g'->$OUT(want 200)" ;; esac
  fi
done
[ -z "$bad" ] && pass "admin_group_only: the admin host answers only when X-Auth-Request-Groups lists admin_firefox-sync-fxa exactly (missing, the access group alone, other case, prefixes, suffixes, a path form, a regex: 403)" \
  || fail "admin_group_only:$bad"
OUT=$(gt $T_IP -H "Host: $GH_ADMIN" -H 'X-Auth-Request-Groups: admin_firefox-sync-fxa' -H 'Authorization: Bearer kc' -H 'Cookie: ffs=1; _oauth2_proxy=x' "$G/users/x")
case "$OUT" in "up=main port=8080 uri=/users/x host=$GH_ADMIN auth=[] xat=[] cookie=[ffs=1] "*) pass "gate_routes: admin -> ffs-admin-internal:8080; Authorization and the forward-auth cookie stripped" ;; *) fail "gate_routes: admin: $OUT" ;; esac
bad=""
for p in /accounts/signups /accounts/max-accounts /accounts/invite /accounts/allowlist/remove /sync/max-users \
         /sync/allowlist/allow /sync/allowlist/reject /sync/allowlist/remove /accounts/signups/ /Accounts/Signups \
         //accounts/signups /accounts/%73ignups /accounts/./invite /sync/allowlist; do
  for m in POST GET; do
    OUT=$(gt $T_IP -X $m -H "Host: $GH_ADMIN" -H 'X-Auth-Request-Groups: admin_firefox-sync-fxa' "$G$p")
    [ "$OUT" = "fxa-gate: who may sign up and sync is managed in Portcullis, not in the admin UI
 [403]" ] || bad="$bad $m:$p->$OUT"
  done
done
for p in /accounts/0123/disable /users/0123/delete /connect /sync/allowlistx /accounts/signupsx; do
  OUT=$(gt $T_IP -o /dev/null -X POST -H "Host: $GH_ADMIN" -H 'X-Auth-Request-Groups: admin_firefox-sync-fxa' "$G$p")
  [ "$OUT" = " [200]" ] || bad="$bad other:$p->$OUT"
done
[ -z "$bad" ] && pass "admin_forms_403: the admin UI's sign-up and allowlist forms (and their confirmation pages) answer 403 at the gate, every spelling; its other pages pass" \
  || fail "admin_forms_403:$bad"
OUT=$(gt $T_IP -o /dev/null -H 'Host: other.fxa-gate.test' "$G/")
[ "$OUT" = " [421]" ] && pass "gate_routes: an unknown host -> 421" || fail "gate_routes: unknown host: $OUT"
OUT=$(gt $T_IP -o /dev/null -H "Host: $GH_ACC" -H "Cookie: $(printf '_oauth2_proxy_%s=x; ' 1 2 3 4 5 6 7)" "$G/")
[ "$OUT" = " [400]" ] && pass "gate_cookies: a Cookie header with more forward-auth cookies than six passes strip -> 400" || fail "gate_cookies: $OUT"
bad=""
for h in "$GH_ACC" "$GH_API" "$GH_PROF" "$GH_SYNC" "$GH_PAIR"; do
  OUT=$(gt 10.254.78.9 -o /dev/null -H "Host: $h" "$G/v1/account/create")
  [ "$OUT" = " [403]" ] || bad="$bad $h->$OUT"
done
OUT=$(gt 10.254.78.9 -o /dev/null -H "Host: $GH_ADMIN" -H 'X-Auth-Request-Groups: admin_firefox-sync-fxa' "$G/")
[ "$OUT" = " [403]" ] || bad="$bad $GH_ADMIN(forged groups)->$OUT"
[ -z "$bad" ] && pass "gate_traefik_only: a peer outside PORTCULLIS_TRAEFIK_SOURCE gets 403 on every host (forged groups on the admin host included)" \
  || fail "gate_traefik_only:$bad"
ST=$(docker exec "$GT-gate" sh -c 'id -u; grep -E "^Cap(Eff|Prm|Bnd):" /proc/1/status | tr -s "\t " " "; touch /etc/x 2>&1 || true' 2>&1 | tr '\n' ' ')
case "$ST" in "101 CapPrm: 0000000000000000 CapEff: 0000000000000000 CapBnd: 0000000000000000 "*"Read-only file system"*)
  pass "gate_unprivileged: nginx runs as uid 101 with no capabilities on a read-only filesystem" ;;
  *) fail "gate_unprivileged: $ST" ;; esac
# Fails closed: a malformed setting stops the gate before nginx starts.
bad=""
for e in "PORTCULLIS_TRAEFIK_SOURCE=172.31.250.2/24" "PORTCULLIS_TRAEFIK_SOURCE=0.0.0.0/00" "PORTCULLIS_TRAEFIK_SOURCE=" \
         "GATE_HOST_API=$GH_ACC" "GATE_HOST_ADMIN=Admin.fxa-gate.test" "GATE_HOST_SYNC=sync.fxa-gate.test;" "GATE_HOST_PAIRING=localhost" \
         "GATE_HOST_PROFILE=" "GATE_ADMIN_GROUP=" "GATE_ADMIN_GROUP=a,b" "GATE_ADMIN_GROUP= a" "GATE_LISTEN=80x"; do
  OUT=$(docker run --rm --network none "${GATE_RUN[@]}" "${GATE_ENV[@]}" -e "$e" "$NGINX_IMAGE" -c 'timeout 5 sh /portcullis/fxa-gate.sh; echo "exit=$?"' 2>&1 | tail -2 | tr '\n' ' ')
  case "$OUT" in *"exit=1 "*) case "$OUT" in *"fxa-gate: "*) ;; *) bad="$bad [$e: $OUT]" ;; esac ;; *) bad="$bad [$e: $OUT]" ;; esac
done
OUT=$(docker run --rm --network none "${GATE_RUN[@]}" "${GATE_ENV[@]}" -e "GATE_ADMIN_GROUP=$(printf 'a\tb')" "$NGINX_IMAGE" -c 'timeout 5 sh /portcullis/fxa-gate.sh; echo "exit=$?"' 2>&1 | tail -2 | tr '\n' ' ')
case "$OUT" in *"exit=1 "*) case "$OUT" in *"fxa-gate: "*) ;; *) bad="$bad [a control character in the group: $OUT]" ;; esac ;; *) bad="$bad [a control character in the group: $OUT]" ;; esac
[ -z "$bad" ] && pass "gate_fails_closed: a bad source range, hostname, duplicate host, admin group or port stops the gate (exit 1, nginx never starts)" \
  || fail "gate_fails_closed:$bad"
docker rm -f "$GT-main" "$GT-pairing" "$GT-gate" > /dev/null 2>&1 || true
docker network rm "$GT_NET" > /dev/null 2>&1 || true

section "Firefox Sync + own accounts (mail, live)"
_export_manifest_env "$COMPOSE"
_export_instance_env "$COMPOSE"
NET=portcullis_default
CATCHER=portcullis-fxa-test-smtp
AUTH_C=portcullis-fxa-auth-1
CHECK_C=portcullis-fxa-mail-check-1
DB_C=portcullis-fxa-db-1
MAIL_VARS="MAIL_SOURCE PORTCULLIS_MAIL_SENDER_HOST PORTCULLIS_MAIL_SENDER_PORT PORTCULLIS_MAIL_SENDER_USER
  PORTCULLIS_MAIL_SENDER_PASSWORD PORTCULLIS_MAIL_SENDER_FROM EXT_SMTP_HOST EXT_SMTP_PORT EXT_SMTP_SECURITY
  EXT_SMTP_USER EXT_SMTP_PASSWORD EXT_SMTP_SENDER MAX_ACCOUNTS"
# shellcheck disable=SC2086
unset $MAIL_VARS
# Test passwords: masked in CI's log, never in an argv (docker -e NAME takes
# the value from this shell's environment).
PROVIDER_PW=$(openssl rand -hex 24)
EXT_PW=$(openssl rand -hex 24)
if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$PROVIDER_PW"; echo "::add-mask::$EXT_PW"; fi
redact() { local s=$1; s=${s//"$PROVIDER_PW"/<provider password>}; s=${s//"$EXT_PW"/<external password>}; printf '%s' "$s"; }
cleanup_live() {
  docker rm -f "$CATCHER" portcullis-fxa-test-oidc portcullis-fxa-test-admin > /dev/null 2>&1 || true
  compose_down "$APP_ID" > /dev/null 2>&1 || true
  rm -rf "${TLS_DIR:-/nonexistent}"
  unset COMPOSE_OVERRIDE
}

started_at() { docker inspect -f '{{.State.StartedAt}}' "$1" 2>/dev/null || echo none; }
wait_healthy() {  # $1 container, $2 seconds
  local i st
  for i in $(seq 1 $(($2 / 5))); do
    st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1" 2>/dev/null || true)
    [ "$st" = healthy ] && return 0
    [ "$i" -gt 0 ] && sleep 5
  done
  return 1
}
auth_environ() { docker exec "$AUTH_C" cat /proc/1/environ 2>/dev/null | tr '\0' '\n'; }
envval() { printf '%s\n' "$1" | sed -n "s/^$2=//p"; }
mysql_root() {  # SQL on stdin; the root password stays in fxa-db's own environment
  docker exec -i "$DB_C" sh -c 'MYSQL_PWD=$MYSQL_ROOT_PASSWORD exec mysql -uroot -h127.0.0.1 --protocol=tcp -N -B'
}
# The SMTP catcher: a small SMTP server (node, the accounts image) on the
# instance's network. CATCHER_TLS=1: it offers STARTTLS (a certificate of a
# test CA the auth server trusts through its CA bundle, see TLS_DIR); else
# it offers none and stands for a server whose STARTTLS was stripped. AUTH
# PLAIN/LOGIN is checked against CATCHER_USER / CATCHER_PASS (environment).
# It logs CONNECT, EHLO, STARTTLS, every AUTH command, "PASSWORD SEEN" when
# any line (or a base64 word of it) holds the password, and each message,
# saved in its /tmp with whether it came over TLS.
CATCHER_JS=$(cat tests/fxa_smtp_catcher.js)
# A test CA and the catcher's certificate (CN/SAN fxa-test-smtp), and the
# auth server's CA bundle = core's bundle + the test CA (an override of its
# read-only bundle mount, as the Hub's CA bundle would carry a real
# server's CA).
TLS_DIR=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" -days 2 \
  -subj /CN=fxa-test-ca -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign > /dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/srv.csr" -subj /CN=fxa-test-smtp > /dev/null 2>&1
printf 'subjectAltName=DNS:fxa-test-smtp\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$TLS_DIR/ext.cnf"
openssl x509 -req -in "$TLS_DIR/srv.csr" -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial -days 2 \
  -extfile "$TLS_DIR/ext.cnf" -out "$TLS_DIR/cert.pem" > /dev/null 2>&1
mkdir -p "$TLS_DIR/catcher"
cp "$TLS_DIR/key.pem" "$TLS_DIR/cert.pem" "$TLS_DIR/catcher/"
chmod 0755 "$TLS_DIR" "$TLS_DIR/catcher"
chmod 0644 "$TLS_DIR/catcher/key.pem" "$TLS_DIR/catcher/cert.pem"
cat "$PROJECT_DIR/certs/ca-bundle.crt" "$TLS_DIR/ca.crt" > "$TLS_DIR/bundle.crt"
chmod 0644 "$TLS_DIR/bundle.crt"
[ -s "$TLS_DIR/catcher/cert.pem" ] && [ -s "$TLS_DIR/catcher/key.pem" ] || fail "the catcher's test certificate wasn't created"
COMPOSE_OVERRIDE="$TLS_DIR/override.yml"
printf 'services:\n  fxa-auth:\n    volumes:\n      - %s:/etc/ssl/certs/portcullis-ca-bundle.crt:ro\n' "$TLS_DIR/bundle.crt" > "$COMPOSE_OVERRIDE"
# CI only: the admin UI reaches auth.<domain> as through public DNS in
# production. CI's public-DNS stand-in (Traefik aliases) is on
# portcullis-proxy, and ffs-admin is on the instance's default network only:
# auth.<domain> -> the host's published 443 (Traefik), as ai-chat does.
printf '  ffs-admin:\n    extra_hosts:\n      - "auth.%s:host-gateway"\n' "$DOMAIN" >> "$COMPOSE_OVERRIDE"
export COMPOSE_OVERRIDE
start_catcher() {  # $1 user, $2 password, $3 tls (1 = offers STARTTLS)
  docker rm -f "$CATCHER" > /dev/null 2>&1 || true
  # CATCHER_MAIL_DIR: a host directory for the saved messages (the
  # helper Firefox reads its codes there), else they stay in its tmpfs.
  local mailv=()
  [ -z "${CATCHER_MAIL_DIR:-}" ] || mailv=(-v "$CATCHER_MAIL_DIR:/tmp/mail")
  CATCHER_USER=$1 CATCHER_PASS=$2 CATCHER_TLS=${3:-1} docker run -d --name "$CATCHER" --network "$NET" --network-alias fxa-test-smtp \
    --user 10001:10001 --read-only --tmpfs /tmp:size=8m --cap-drop ALL --security-opt no-new-privileges:true \
    ${mailv[@]+"${mailv[@]}"} -v "$TLS_DIR/catcher:/tls:ro" -e CATCHER_USER -e CATCHER_PASS -e CATCHER_TLS \
    --entrypoint node "$FXA_IMAGE" -e "$CATCHER_JS" > /dev/null
  for _ in $(seq 1 30); do grep -q 'catcher listening' <<< "$(docker logs "$CATCHER" 2>&1)" && return 0; sleep 1; done
  fail "the SMTP catcher did not start: $(docker logs "$CATCHER" 2>&1 | tail -5)"
  return 1
}
# A sign-up straight at the auth server (inside its container; the address
# put on the sign-up allowlist first, as fxa-access-sync will): Mozilla's
# accounts mail the sign-up code at once.
signup() {  # $1 address -> prints the HTTP status and the start of the answer
  printf "INSERT IGNORE INTO ffs.signup_allowlist (entry) VALUES ('%s');\n" "$1" | mysql_root > /dev/null
  docker exec "$AUTH_C" node -e '
    fetch("http://127.0.0.1:9000/v1/account/create", {method: "POST", headers: {"content-type": "application/json"},
      body: JSON.stringify({email: process.argv[1], authPW: "0".repeat(64), verificationMethod: "email-otp"})})
      .then(async r => console.log(r.status + " " + (await r.text()).slice(0, 200)), e => console.log("error " + e))' "$1" 2>&1
}
# The message the catcher got for $1 (waits up to 60 s).
caught() {
  local m i
  for i in $(seq 1 30); do
    m=$(docker exec "$CATCHER" sh -c 'cat /tmp/mail/*.eml 2>/dev/null' | awk -v want="$1" '
      /^MAIL FROM / { keep = 0; buf = "" } { buf = buf $0 "\n" } /^RCPT / { keep = index($0, want) > 0 }
      END { if (keep) printf "%s", buf }' || true)
    [ -n "$m" ] && { printf '%s' "$m"; return 0; }
    [ "$i" = 30 ] || sleep 2
  done
  return 1
}
code_arrives() {  # $1 label, $2 address, $3 envelope sender, $4 From header address
  local out msg
  out=$(signup "$2")
  case "$out" in
    200*) ;;
    *) fail "$1: the sign-up of $2 answered '$(redact "$out")'"; return 0 ;;
  esac
  if ! msg=$(caught "$2"); then
    fail "$1: no message for $2 reached the catcher; catcher: $(docker logs "$CATCHER" 2>&1 | tail -5 | tr '\n' ' '); auth: $(redact "$(docker logs --tail 15 "$AUTH_C" 2>&1 | grep -i -E 'mail|smtp' | tail -5)")"
    return 0
  fi
  if grep -q '^AUTH ok$' <<< "$msg" && grep -q '^TLS yes$' <<< "$msg" \
      && grep -q "^MAIL FROM <$3>" <<< "$msg" \
      && grep -qi "^From: .*<$4>" <<< "$msg" \
      && grep -qiE '^X-Verify-(Short-)?Code: *[0-9A-Za-z]+' <<< "$msg"; then
    pass "$1: the sign-up code for $2 arrived (over STARTTLS, authenticated, MAIL FROM $3, From <$4>, $(printf '%s\n' "$msg" | grep -iE '^X-Verify-(Short-)?Code:' | head -1 | cut -d: -f1) header)"
  else
    fail "$1: the message for $2 lacks TLS, the AUTH, MAIL FROM <$3>, From <$4> or the code header: $(redact "$(printf '%s\n' "$msg" | grep -iE '^(AUTH|TLS|MAIL FROM|RCPT|From:|X-Verify)' | tr '\n' ' ')")"
  fi
  # Nothing of the credential before the TLS handshake.
  local log
  log=$(docker logs "$CATCHER" 2>&1)
  if grep -qE '^(AUTH|PASSWORD SEEN).* plain$' <<< "$log"; then
    fail "$1: the catcher saw an AUTH or the password before STARTTLS: $(printf '%s\n' "$log" | grep -E '^(AUTH|PASSWORD SEEN)' | tr '\n' ' ')"
  elif grep -q '^STARTTLS$' <<< "$log" && grep -q '^AUTH ok user=.* tls$' <<< "$log"; then
    pass "$1: STARTTLS first, then AUTH (no AUTH, no password in the clear)"
  else
    fail "$1: the catcher logged no STARTTLS + AUTH over TLS: $(printf '%s\n' "$log" | grep -vE '^MESSAGE' | tr '\n' ' ')"
  fi
}
# starttls_required: the catcher offers no STARTTLS (stripped): the auth
# server connects (EHLO) and stops; the catcher never gets an AUTH, the
# password or a message. A pinned image that drops the requireTLS
# passthrough (an undeclared config key: smtp.requireTLS) turns this red:
# nodemailer then authenticates in the clear.
starttls_required() {  # $1 label, $2 address, $3 password
  local out log i
  out=$(signup "$2")
  for i in $(seq 1 30); do
    grep -q '^EHLO plain$' <<< "$(docker logs "$CATCHER" 2>&1)" && break
    sleep 2
  done
  sleep 5
  log=$(docker logs "$CATCHER" 2>&1)
  if ! grep -q '^EHLO plain$' <<< "$log"; then
    fail "starttls_required: $1: the auth server never reached the catcher (sign-up: $(redact "$out")): $(printf '%s\n' "$log" | tr '\n' ' ')"
  elif grep -qE '^(AUTH|PASSWORD SEEN|MESSAGE)' <<< "$log"; then
    fail "starttls_required: $1: without STARTTLS the catcher still got: $(printf '%s\n' "$log" | grep -E '^(AUTH|PASSWORD SEEN|MESSAGE)' | tr '\n' ' ')"
  elif grep -q . <<< "$(docker exec "$CATCHER" sh -c 'ls /tmp/mail' 2>/dev/null)"; then
    fail "starttls_required: $1: a message was saved without STARTTLS"
  else
    pass "starttls_required: $1: no STARTTLS offered: the auth server stopped after EHLO (sign-up answered ${out%% *}); the catcher got no AUTH, no password, no message"
  fi
}
# The auth server's effective SMTP config (no secret printed): its own
# CONFIG_FILES (from PID 1), loaded by its own config module.
effective_smtp() {
  local cf
  cf=$(envval "$(auth_environ)" CONFIG_FILES)
  docker exec -e CONFIG_FILES="$cf" "$AUTH_C" node --no-deprecation -e '
    const s = require("./config").default.get("smtp");
    console.log("RESULT requireTLS=" + s.requireTLS + " ignoreTLS=" + s.ignoreTLS)' 2>/dev/null | sed -n 's/^RESULT //p'
}
# secret_not_in_argv: no container's Path / Args / Cmd / Entrypoint, no
# process of the auth server's container, and neither service's log holds
# the password (its value only compared here, never printed).
secret_not_in_argv() {  # $1 label, $2 password
  local bad="" c meta procs logs
  for c in $(docker ps -aq); do
    meta=$(docker inspect -f '{{.Name}} {{json .Path}} {{json .Args}} {{json .Config.Cmd}} {{json .Config.Entrypoint}}' "$c" 2>/dev/null || true)
    case "$meta" in *"$2"*) bad="$bad ${meta%% *}(argv)" ;; esac
  done
  procs=$(docker exec "$AUTH_C" sh -c 'for f in /proc/[0-9]*/cmdline; do tr "\0" " " < "$f" 2>/dev/null; echo; done' 2>/dev/null || true)
  [ -n "$procs" ] || bad="$bad fxa-auth(processes unreadable)"
  case "$procs" in *"$2"*) bad="$bad fxa-auth(a process's argv)" ;; esac
  logs=$(docker logs "$AUTH_C" 2>&1; docker logs "$CHECK_C" 2>&1)
  case "$logs" in *"$2"*) bad="$bad logs" ;; esac
  if [ -z "$bad" ]; then
    pass "secret_not_in_argv: $1: the SMTP password in no container's Args / Cmd / Entrypoint, no fxa-auth process argv, no log"
  else
    fail "secret_not_in_argv: $1: the SMTP password is in:$bad"
  fi
}
max_accounts_setting() { echo "SELECT value FROM ffs.settings WHERE name = 'max_accounts';" | mysql_root 2>/dev/null || echo "<unreadable>"; }

# ── refuses_without_mail: provider mode, no sender env (no provider wired).
compose_up "$APP_ID" > /dev/null 2>&1 || true
RC=$(timeout 300 docker wait "$CHECK_C" 2>/dev/null || echo none)
LOG=$(docker logs "$CHECK_C" 2>&1 || true)
if [ "$RC" = 1 ] && [ "$LOG" = "$NO_MAIL_LINE" ]; then
  pass "refuses_without_mail: fxa-mail-check exit 1, logs exactly '$NO_MAIL_LINE'"
else
  fail "refuses_without_mail: fxa-mail-check exit $RC, logged '$(redact "$LOG")'"
fi
ST=$(started_at "$AUTH_C")
RUNNING=$(docker inspect -f '{{.State.Running}}' "$AUTH_C" 2>/dev/null || echo absent)
case "$ST" in
  none | 0001-01-01T00:00:00Z) [ "$RUNNING" != true ] && pass "refuses_without_mail: fxa-auth never started (${RUNNING/false/created, not started})" \
    || fail "refuses_without_mail: fxa-auth runs" ;;
  *) fail "refuses_without_mail: fxa-auth started at $ST" ;;
esac
# The real image's busybox sh: external mode without host / sender, and a
# complete external server (the service's own mounts, no network).
mc_run() {  # env NAME=value... -> "<exit> <output>"
  local out rc
  out=$(docker run --rm --network none --read-only --cap-drop ALL --user 10001:10001 \
    -v "$(cd "$(dirname "$COMPOSE")" && pwd)/mail-check.sh:/portcullis-bin/mail-check.sh:ro" \
    -v "$(cd "$(dirname "$COMPOSE")" && pwd)/mail-select.sh:/portcullis-bin/mail-select.sh:ro" \
    "$@" --entrypoint /bin/sh "$REDIS_IMAGE" /portcullis-bin/mail-check.sh 2>&1) && rc=0 || rc=$?
  printf '%s %s' "$rc" "$out"
}
got=$(mc_run -e MAIL_SOURCE=external -e EXT_SMTP_SENDER=a@example.net)
[ "$got" = "1 portcullis: no mail: the external SMTP server needs a host and a sender address (settings: Mail)" ] \
  && pass "fxa-mail-check (busybox): external without a host: exit 1, '${got#1 }'" || fail "fxa-mail-check (busybox): external without a host: '$got'"
got=$(mc_run -e MAIL_SOURCE=external -e EXT_SMTP_HOST=smtp.example.net)
[ "$got" = "1 portcullis: no mail: the external SMTP server needs a host and a sender address (settings: Mail)" ] \
  && pass "fxa-mail-check (busybox): external without a sender: exit 1" || fail "fxa-mail-check (busybox): external without a sender: '$got'"
got=$(EXT_SMTP_PASSWORD=$EXT_PW mc_run -e MAIL_SOURCE=external -e EXT_SMTP_HOST=smtp.example.net -e EXT_SMTP_PORT=465 \
  -e EXT_SMTP_SECURITY=tls -e EXT_SMTP_USER=u -e EXT_SMTP_PASSWORD -e EXT_SMTP_SENDER=a@example.net)
[ "$got" = "0 portcullis: mail: the external SMTP server (smtp.example.net:465, TLS)" ] \
  && pass "fxa-mail-check (busybox): a complete external server: exit 0, '${got#0 }'" || fail "fxa-mail-check (busybox): complete external: '$(redact "$got")'"
got=$(mc_run -e MAIL_SOURCE=external -e EXT_SMTP_HOST=smtp.example.net -e EXT_SMTP_PORT=587 -e EXT_SMTP_SECURITY=tls -e EXT_SMTP_SENDER=a@example.net)
[ "$got" = "1 $TLS_ON_587" ] && pass "port_mode_mismatch (busybox): fxa-mail-check refuses tls on 587: exit 1" \
  || fail "port_mode_mismatch (busybox): tls on 587: '$got'"
got=$(mc_run -e MAIL_SOURCE=external -e EXT_SMTP_HOST=smtp.example.net -e EXT_SMTP_PORT=465 -e EXT_SMTP_SECURITY=starttls -e EXT_SMTP_SENDER=a@example.net)
[ "$got" = "1 $STARTTLS_ON_465" ] && pass "port_mode_mismatch (busybox): fxa-mail-check refuses starttls on 465: exit 1" \
  || fail "port_mode_mismatch (busybox): starttls on 465: '$got'"

# ── provider_used: the Hub's PORTCULLIS_MAIL_SENDER_* (the catcher stands in
# for the provider's submission listener).
PROVIDER_USER="portcullis-app-$APP_ID@$DOMAIN"
start_catcher "$PROVIDER_USER" "$PROVIDER_PW" 1 || true
export PORTCULLIS_MAIL_SENDER_HOST=fxa-test-smtp PORTCULLIS_MAIL_SENDER_PORT=587 \
  PORTCULLIS_MAIL_SENDER_USER="$PROVIDER_USER" PORTCULLIS_MAIL_SENDER_PASSWORD="$PROVIDER_PW" \
  PORTCULLIS_MAIL_SENDER_FROM="\"Firefox accounts\" <$PROVIDER_USER>"
compose_up "$APP_ID" > /dev/null 2>&1 || true
RC=$(timeout 120 docker wait "$CHECK_C" 2>/dev/null || echo none)
[ "$RC" = 0 ] && pass "provider: fxa-mail-check exit 0 ($(docker logs "$CHECK_C" 2>&1 | tail -1))" \
  || fail "provider: fxa-mail-check exit $RC: $(redact "$(docker logs "$CHECK_C" 2>&1 | tail -3)")"
if wait_healthy "$AUTH_C" 600; then
  pass "provider: fxa-auth healthy"
  E=$(auth_environ)
  if [ "$(envval "$E" SMTP_HOST)" = "$PORTCULLIS_MAIL_SENDER_HOST" ] && [ "$(envval "$E" SMTP_SECURE)" = false ] \
      && [ "$(envval "$E" SMTP_PORT)" = 587 ] && [ "$(envval "$E" SMTP_SENDER)" = "$PORTCULLIS_MAIL_SENDER_FROM" ] \
      && [ "$(envval "$E" SMTP_USER)" = "$PROVIDER_USER" ] && [ "$(envval "$E" SMTP_PASS)" = "$PROVIDER_PW" ]; then
    pass "provider_used: fxa-auth's /proc/1/environ: SMTP_HOST = PORTCULLIS_MAIL_SENDER_HOST, SMTP_SECURE=false, SMTP_PORT=587, SMTP_SENDER = _FROM, SMTP_USER / SMTP_PASS the sender's"
  else
    fail "provider_used: SMTP_HOST=$(envval "$E" SMTP_HOST) SMTP_SECURE=$(envval "$E" SMTP_SECURE) SMTP_PORT=$(envval "$E" SMTP_PORT) SMTP_SENDER=$(envval "$E" SMTP_SENDER) SMTP_USER=$(envval "$E" SMTP_USER) SMTP_PASS $([ "$(envval "$E" SMTP_PASS)" = "$PROVIDER_PW" ] && echo matches || echo differs)"
  fi
  if grep -q '^PORTCULLIS_MAIL_SENDER_PASSWORD=' <<< "$E"; then
    fail "provider_used: the input PORTCULLIS_MAIL_SENDER_PASSWORD is still in the auth server's environment"
  else
    pass "provider_used: the password once in the auth server's environment (SMTP_PASS; the input unset)"
  fi
  CF=$(envval "$E" CONFIG_FILES)
  [ "$CF" = /fxa-keys/oauth-clients.json,/fxa-config/smtp-require-tls.json ] \
    && pass "starttls_required: provider: CONFIG_FILES = $CF (oauth-clients.json kept, the overlay last)" \
    || fail "starttls_required: provider: CONFIG_FILES '$CF'"
  EFF=$(effective_smtp)
  [ "$EFF" = "requireTLS=true ignoreTLS=false" ] && pass "starttls_required: provider: the auth server's effective smtp config: $EFF" \
    || fail "starttls_required: provider: effective smtp config '$EFF'"
  code_arrives "provider_used" "fxa-provider-test@$DOMAIN" "$PROVIDER_USER" "$PROVIDER_USER"
  secret_not_in_argv provider "$PROVIDER_PW"
else
  fail "provider: fxa-auth not healthy after 600 s: $(redact "$(docker logs --tail 30 "$AUTH_C" 2>&1)")"
fi
MAXA=$(max_accounts_setting)
[ "$MAXA" = unlimited ] && pass "no_cap_default: ffs.settings max_accounts unlimited without the setting" \
  || fail "no_cap_default: ffs.settings max_accounts '$MAXA' without the setting"

# ── external_used: another SMTP server, STARTTLS on 587; the account cap 5.
# shellcheck disable=SC2086
unset $MAIL_VARS
EXT_USER=fxa-ext
start_catcher "$EXT_USER" "$EXT_PW" 0 || true
export MAIL_SOURCE=external EXT_SMTP_HOST=fxa-test-smtp EXT_SMTP_PORT=587 EXT_SMTP_SECURITY=starttls \
  EXT_SMTP_USER="$EXT_USER" EXT_SMTP_PASSWORD="$EXT_PW" EXT_SMTP_SENDER="fxa-accounts@example.net" MAX_ACCOUNTS=5
OLD_AUTH=$(docker inspect -f '{{.Id}}' "$AUTH_C" 2>/dev/null || echo none)
compose_up "$APP_ID" > /dev/null 2>&1 || true
RC=$(timeout 120 docker wait "$CHECK_C" 2>/dev/null || echo none)
[ "$RC" = 0 ] && pass "external: fxa-mail-check exit 0 ($(docker logs "$CHECK_C" 2>&1 | tail -1))" \
  || fail "external: fxa-mail-check exit $RC: $(redact "$(docker logs "$CHECK_C" 2>&1 | tail -3)")"
NEW_AUTH=$(docker inspect -f '{{.Id}}' "$AUTH_C" 2>/dev/null || echo none)
[ "$NEW_AUTH" != "$OLD_AUTH" ] && pass "external: fxa-auth recreated with the new mail settings" || fail "external: fxa-auth not recreated"
if wait_healthy "$AUTH_C" 600; then
  E=$(auth_environ)
  if [ "$(envval "$E" SMTP_HOST)" = fxa-test-smtp ] && [ "$(envval "$E" SMTP_SECURE)" = false ] \
      && [ "$(envval "$E" SMTP_PORT)" = 587 ] && [ "$(envval "$E" SMTP_SENDER)" = "Firefox accounts <fxa-accounts@example.net>" ] \
      && [ "$(envval "$E" SMTP_USER)" = "$EXT_USER" ] && [ "$(envval "$E" SMTP_PASS)" = "$EXT_PW" ] \
      && ! grep -q '^EXT_SMTP_PASSWORD=' <<< "$E"; then
    pass "external_used: starttls: SMTP_SECURE=false, SMTP_PORT=587, SMTP_HOST the external server, SMTP_SENDER Firefox accounts <fxa-accounts@example.net>, the password once"
  else
    fail "external_used: SMTP_HOST=$(envval "$E" SMTP_HOST) SMTP_SECURE=$(envval "$E" SMTP_SECURE) SMTP_PORT=$(envval "$E" SMTP_PORT) SMTP_SENDER=$(envval "$E" SMTP_SENDER) SMTP_USER=$(envval "$E" SMTP_USER) SMTP_PASS $([ "$(envval "$E" SMTP_PASS)" = "$EXT_PW" ] && echo matches || echo differs)"
  fi
  EFF=$(effective_smtp)
  [ "$EFF" = "requireTLS=true ignoreTLS=false" ] && pass "starttls_required: external: the auth server's effective smtp config: $EFF" \
    || fail "starttls_required: external: effective smtp config '$EFF'"
  starttls_required external "fxa-stripped-test@$DOMAIN" "$EXT_PW"
  start_catcher "$EXT_USER" "$EXT_PW" 1 || true
  code_arrives "external_used" "fxa-external-test@$DOMAIN" "fxa-accounts@example.net" "fxa-accounts@example.net"
  secret_not_in_argv external "$EXT_PW"
else
  fail "external: fxa-auth not healthy after 600 s: $(redact "$(docker logs --tail 30 "$AUTH_C" 2>&1)")"
fi
MAXA=$(max_accounts_setting)
[ "$MAXA" = 5 ] && pass "no_cap_default: ffs.settings max_accounts 5 with max_accounts 5" \
  || fail "no_cap_default: ffs.settings max_accounts '$MAXA' with the setting 5"

# ══ Sync (Task 15), live: the guard's roles against the running database,
# then a Firefox (tests/fxa_client.py, PyFxA) signs up, gets a Sync token
# and round-trips a record. The helper (a container of the pinned
# syncstorage-rs image: PyFxA, requests and hawkauthlib ship in it) goes the
# public way, as a Firefox on the internet: Traefik and fxa-gate at the API
# and Sync hosts (CI's public-DNS stand-in on portcullis-proxy resolves them
# to Traefik), trusting Portcullis's CA bundle; the sign-up passes the
# sign-up gate. ══
section "Firefox Sync + own accounts (sync, live)"
SYNC_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA"
API_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA_API"
SDB=portcullis-firefox-sync-fxa-db-1
OUTSIDER=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
for job in firefox-sync-fxa-migrate firefox-sync-fxa-db-init firefox-sync-fxa-init; do
  if RC=$(timeout 300 docker wait "portcullis-${job}-1" 2>/dev/null) && [ "$RC" = 0 ]; then
    pass "$job exited 0"
  else
    fail "$job did not finish successfully (rc=${RC:-none}): $(docker logs "portcullis-${job}-1" 2>&1 | tail -5 | tr '\n' ' ')"
  fi
done
GUARD_LOG=$(docker logs portcullis-firefox-sync-fxa-init-1 2>&1 | grep 'portcullis-guard' || true)
info "init: $(echo "$GUARD_LOG" | tr '\n' ' ')"
SYNC_IP=$(app_container_ip "$APP_ID" firefox-sync-fxa)
wait_for_url "http://${SYNC_IP}:8000/__heartbeat__" 300 "firefox-sync-fxa" || true
sdb() { docker exec "$SDB" psql -X -U firefoxsync -d firefoxsync -tAc "$1" 2>&1 || true; }
as_role() { docker exec "$SDB" psql -X -U "$1" -d "$2" -tAc "$3" 2>&1; }  # socket, as the services connect

# app_role_owns_nothing: no object of any kind, no attribute, no membership.
OWN=$(sdb "SELECT (SELECT count(*) FROM pg_shdepend d JOIN pg_roles r ON r.oid = d.refobjid
             WHERE r.rolname = 'firefoxsync_app' AND d.deptype = 'o')
    || ':' || (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit
               FROM pg_roles WHERE rolname = 'firefoxsync_app')
    || ':' || (SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = 'firefoxsync_app')")
[ "$OWN" = "0:false:0" ] \
  && pass "app_role_owns_nothing: firefoxsync_app owns no object, has no superuser / createdb / createrole / replication / bypassrls / inherit, is a member of no role" \
  || fail "app_role_owns_nothing: owned objects : attributes : memberships = $OWN (want 0:false:0)"
for stmt in "DROP TRIGGER before_insert_user ON users" \
            "ALTER TABLE users DISABLE TRIGGER ALL" \
            "TRUNCATE users" \
            "SET session_replication_role = replica" \
            "SET event_triggers = off" \
            "DROP EVENT TRIGGER portcullis_app_no_ddl" \
            "ALTER ROLE firefoxsync_app SUPERUSER" \
            "CREATE ROLE portcullis_x LOGIN" \
            "UPDATE nodes SET node = 'https://evil.example'" \
            "UPDATE nodes SET capacity = 0" \
            "INSERT INTO nodes (service, node, available, current_load, capacity, downed, backoff) VALUES (1, 'https://evil.example', 1, 0, 1, 0, 0)" \
            "DELETE FROM users" \
            "UPDATE users SET uid = uid + 1000" \
            "UPDATE users SET email = 'x@$API_HOST'" \
            "UPDATE users SET nodeid = 0" \
            "DELETE FROM __diesel_schema_migrations" \
            "INSERT INTO services (service, pattern) VALUES ('x', 'y')" \
            "SELECT setval('users_uid_seq', 1)" \
            "UPDATE config SET config_value = '0' WHERE config_key = 'max_users'" \
            "INSERT INTO sync_allowed_accounts (uid, added_at, added_by) VALUES ('$OUTSIDER', 1, 'x')" \
            "INSERT INTO sync_refused_accounts (uid, first_at, last_at) VALUES ('x', 1, 1)" \
            "SELECT ffs_allow_account('$OUTSIDER', 'x', 'x')" \
            "CREATE FUNCTION public.split_part(varchar, text, integer) RETURNS text LANGUAGE sql AS \$\$ SELECT 'x' \$\$" \
            "CREATE TABLE public.portcullis_x (a int)" \
            "CREATE VIEW public.portcullis_v AS SELECT 1"; do
  OUT=$(as_role firefoxsync_app firefoxsync "$stmt" || true)
  if echo "$OUT" | grep -Eqi 'permission denied|must be owner|may not create|must be superuser'; then
    pass "app_role_owns_nothing: firefoxsync_app refused: ${stmt:0:50}"
  else
    fail "app_role_owns_nothing: firefoxsync_app could: $stmt -> $OUT"
  fi
done
# No sequence privilege at all (identity columns: an INSERT needs none), on
# every sequence of the database, not only the one setval tries.
SEQ=$(sdb "SELECT count(*) || ':' || count(*) FILTER (WHERE has_sequence_privilege('firefoxsync_app', c.oid, 'USAGE')
             OR has_sequence_privilege('firefoxsync_app', c.oid, 'SELECT') OR has_sequence_privilege('firefoxsync_app', c.oid, 'UPDATE'))
           FROM pg_class c WHERE c.relkind = 'S'")
if [[ "$SEQ" =~ ^[1-9][0-9]*:0$ ]]; then
  pass "app_role_owns_nothing: firefoxsync_app has no USAGE, SELECT or UPDATE on any of the ${SEQ%%:*} sequences"
else
  fail "app_role_owns_nothing: sequences : with a firefoxsync_app privilege = $SEQ (want n:0, n > 0)"
fi
OUT=$(as_role firefoxsync_app firefoxsync "UPDATE nodes SET current_load = current_load, available = available WHERE node = 'https://$SYNC_HOST'; UPDATE users SET generation = generation, keys_changed_at = keys_changed_at, replaced_at = replaced_at WHERE false; SELECT count(*) FROM services; CREATE TABLE IF NOT EXISTS __diesel_schema_migrations (version VARCHAR(50) PRIMARY KEY NOT NULL, run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)" || true)
if echo "$OUT" | grep -qi 'error'; then
  fail "firefoxsync_app lacks a grant the server needs (node load, users generation / keys, services, diesel's no-op check): $OUT"
else
  pass "firefoxsync_app may update a node's load and a user's generation / keys_changed_at / replaced_at, read services, run diesel's no-op check"
fi
# The admin UI's reader: reads, deletes Sync rows, nothing else.
for stmt in "DROP TRIGGER before_insert_user ON users" \
            "ALTER TABLE users DISABLE TRIGGER ALL" \
            "SET session_replication_role = replica" \
            "INSERT INTO users (service, email, generation, client_state, created_at, nodeid) VALUES (1, '$OUTSIDER@$API_HOST', 1, 'a', 1, 1)" \
            "UPDATE users SET email = '$OUTSIDER@$API_HOST'" \
            "UPDATE nodes SET capacity = 0" \
            "DELETE FROM nodes" \
            "UPDATE config SET config_value = '0' WHERE config_key = 'max_users'" \
            "INSERT INTO sync_allowed_accounts (uid, added_at, added_by) VALUES ('$OUTSIDER', 1, 'x')" \
            "SELECT ffs_allow_account('$OUTSIDER', 'x', 'x')" \
            "SELECT ffs_reject_account('$OUTSIDER', 'x')" \
            "CREATE TABLE public.portcullis_x (a int)" \
            "CREATE FUNCTION public.split_part(varchar, text, integer) RETURNS text LANGUAGE sql AS \$\$ SELECT 'x' \$\$"; do
  OUT=$(as_role firefoxsync_admin_sync firefoxsync "$stmt" || true)
  if echo "$OUT" | grep -Eqi 'permission denied|must be owner'; then
    pass "firefoxsync_admin_sync refused: ${stmt:0:50}"
  else
    fail "firefoxsync_admin_sync could: $stmt -> $OUT"
  fi
done
OUT=$(as_role firefoxsync_admin_sync firefoxsync "SELECT count(*) FROM users; SELECT count(*) FROM nodes; DELETE FROM bsos WHERE false; DELETE FROM users WHERE false" || true)
if echo "$OUT" | grep -qi 'error'; then
  fail "firefoxsync_admin_sync can't read the Sync data or delete Sync rows: $OUT"
else
  pass "firefoxsync_admin_sync reads the Sync data and may delete users / storage rows"
fi
PRIV_SQL="SELECT count(DISTINCT p.proname) || ':' || COALESCE(bool_or(has_function_privilege(r, p.oid, 'EXECUTE')), false)
  || ':' || bool_or(has_table_privilege(r, 'public.sync_allowed_accounts', 'INSERT,UPDATE,DELETE,TRUNCATE'))
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'public',
       unnest(ARRAY['firefoxsync_admin', 'firefoxsync_admin_sync', 'firefoxsync_app', 'public']) r
  WHERE p.proname IN ('ffs_allow_account', 'ffs_remove_allowed_account', 'ffs_reject_account')"
priv_check() {  # $1 = when
  local out
  out=$(sdb "$PRIV_SQL")
  [ "$out" = "3:false:false" ] && pass "$1: no admin role, app role or PUBLIC may run porelli's SECURITY DEFINER account functions or write sync_allowed_accounts" \
    || fail "$1: privileges $out (want 3:false:false: functions found, none executable, no write)"
}
priv_check "after both inits"
TRIGGERS=$(sdb "SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname), '') FROM pg_trigger WHERE tgrelid = 'public.users'::regclass AND NOT tgisinternal")
[ "$TRIGGERS" = before_insert_user ] && pass "users triggers: only porelli's max-users trigger (unlimited), no invite-only trigger" \
  || fail "users triggers: $TRIGGERS"
CONF=$(sdb "SELECT string_agg(config_key || '=' || config_value, ',' ORDER BY config_key) FROM config WHERE config_key IN ('allowed_accounts', 'max_users')")
[ "$CONF" = "allowed_accounts=external,max_users=unlimited" ] && pass "config: $CONF (porelli's init, access managed elsewhere)" || fail "config: $CONF"

# only_three_roles_connect: the Sync server's role and the admin UI's two,
# each to its own database; the owner is the only superuser.
LOGINS=$(sdb "SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE rolcanlogin")
SUPERS=$(sdb "SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE rolsuper")
CONN_SYNC=$(sdb "SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE NOT rolsuper AND has_database_privilege(oid, 'firefoxsync', 'CONNECT')")
CONN_ADMIN=$(sdb "SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE NOT rolsuper AND has_database_privilege(oid, 'firefoxsync_admin', 'CONNECT')")
if [ "$LOGINS" = firefoxsync,firefoxsync_admin,firefoxsync_admin_sync,firefoxsync_app ] && [ "$SUPERS" = firefoxsync ] \
    && [ "$CONN_SYNC" = firefoxsync_admin_sync,firefoxsync_app ] && [ "$CONN_ADMIN" = firefoxsync_admin ]; then
  pass "only_three_roles_connect: firefoxsync_app + firefoxsync_admin_sync to firefoxsync, firefoxsync_admin to firefoxsync_admin; the owner the only superuser"
else
  fail "only_three_roles_connect: login roles $LOGINS, superusers $SUPERS, CONNECT on firefoxsync $CONN_SYNC, on firefoxsync_admin $CONN_ADMIN"
fi
for who in "firefoxsync_admin firefoxsync" "firefoxsync_app firefoxsync_admin" "firefoxsync_admin_sync firefoxsync_admin" \
           "firefoxsync_app postgres" "firefoxsync_app template1"; do
  set -- $who
  OUT=$(as_role "$1" "$2" "SELECT 1" || true)
  if echo "$OUT" | grep -qi 'permission denied for database'; then
    pass "only_three_roles_connect: $1 may not connect to $2"
  else
    fail "only_three_roles_connect: $1 connects to $2: $OUT"
  fi
done
for who in "firefoxsync_app firefoxsync" "firefoxsync_admin_sync firefoxsync" "firefoxsync_admin firefoxsync_admin"; do
  set -- $who
  [ "$(as_role "$1" "$2" "SELECT 1" || true)" = 1 ] && pass "only_three_roles_connect: $1 connects to $2" \
    || fail "only_three_roles_connect: $1 can't connect to $2"
done

# node_url (live): exactly one node in rotation, this instance's Sync host,
# at the largest capacity.
NODES=$(sdb "SELECT string_agg(node || '|' || capacity, ',' ORDER BY node) FROM nodes WHERE downed = 0")
[ "$NODES" = "https://$SYNC_HOST|2147483647" ] && pass "node_url: the one node in rotation is https://$SYNC_HOST (capacity 2147483647)" \
  || fail "node_url: nodes in rotation: $NODES"

# Fail closed: an init with a bad value (as the Hub would start it, from the
# checkout's files) exits non-zero and changes nothing; revoke.sql still
# holds.
init_with() {  # NAME=value... -> the init's output; returns its exit code
  local cmd sql
  sql=$(cd "$TDIR" && pwd)
  cmd=$(yq -r '.services["firefox-sync-fxa-init"].command[0]' "$COMPOSE")
  # The values by this subshell's environment (docker -e NAME), never on an
  # argv: not even env's (the bad values are test values, set the same way).
  (
    export PGPASSWORD="$FIREFOX_SYNC_FXA_DB_PASSWORD" FIREFOX_SYNC_APP_DB_PASSWORD="$FIREFOX_SYNC_FXA_APP_DB_PASSWORD" \
      FIREFOX_SYNC_ADMIN_DB_PASSWORD="$FIREFOX_SYNC_FXA_ADMIN_DB_PASSWORD" FIREFOX_SYNC_NODE_URL="https://$SYNC_HOST"
    local a
    for a in "$@"; do export "${a%%=*}=${a#*=}"; done
    docker run --rm --network "$NET" --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges:true --user 70:70 \
      -e PGHOST=firefox-sync-fxa-db -e PGUSER=firefoxsync -e PGDATABASE=firefoxsync -e PGPASSWORD \
      -e FIREFOX_SYNC_APP_DB_PASSWORD -e FIREFOX_SYNC_ADMIN_DB_PASSWORD -e FIREFOX_SYNC_NODE_URL \
      -v "$sql/revoke.sql:/etc/portcullis/revoke.sql:ro" -v "$sql/guard.sql:/etc/portcullis/guard.sql:ro" \
      -v "$sql/admin-db.sql:/etc/portcullis/admin-db.sql:ro" \
      --entrypoint /bin/sh "$POSTGRES_IMAGE" -c "$cmd" 2>&1
  )
}
BEFORE=$(sdb "SELECT string_agg(node || '|' || downed || '|' || capacity, ',' ORDER BY id) FROM nodes")
for bad in "FIREFOX_SYNC_APP_DB_PASSWORD=short|FIREFOX_SYNC_APP_DB_PASSWORD is missing or too short" \
           "FIREFOX_SYNC_ADMIN_DB_PASSWORD=|FIREFOX_SYNC_ADMIN_DB_PASSWORD is missing or too short" \
           "FIREFOX_SYNC_NODE_URL=http://$SYNC_HOST|FIREFOX_SYNC_NODE_URL is not https://<hostname>" \
           "FIREFOX_SYNC_NODE_URL=https://other.$DOMAIN|no sync node for this hostname"; do
  if OUT=$(init_with "${bad%%|*}"); then
    fail "init_fails_closed: ${bad%%=*} '${bad#*=}' accepted (exit 0)"
  elif echo "$OUT" | grep -qF "portcullis: ${bad#*|}"; then
    pass "init_fails_closed: ${bad%%|*} -> exit non-zero ('${bad#*|}')"
  else
    fail "init_fails_closed: ${bad%%|*} -> failed without the expected reason: $(echo "$OUT" | tail -2 | tr '\n' ' ')"
  fi
done
AFTER=$(sdb "SELECT string_agg(node || '|' || downed || '|' || capacity, ',' ORDER BY id) FROM nodes")
APP_LOGIN=$(PGPASSWORD="$FIREFOX_SYNC_FXA_APP_DB_PASSWORD" docker exec -e PGPASSWORD "$SDB" psql -X -h 127.0.0.1 -U firefoxsync_app -d firefoxsync -tAc 'SELECT 1' 2>&1 || true)
[ "$BEFORE" = "$AFTER" ] && [ "$APP_LOGIN" = 1 ] \
  && pass "init_fails_closed: the refused runs changed nothing (nodes as before, firefoxsync_app's password unchanged)" \
  || fail "init_fails_closed: nodes '$BEFORE' -> '$AFTER', app login with its password: $APP_LOGIN"
priv_check "after the refused runs"
OUT=$(init_with) && pass "init: a run with the instance's values exits 0 again" || fail "init with the instance's values: $(echo "$OUT" | tail -3 | tr '\n' ' ')"

# A Firefox: sign up (the code from the mail catcher), then first_sync.
FXA_PASSWORD=$(openssl rand -hex 16)
[ -n "${GITHUB_ACTIONS:-}" ] && echo "::add-mask::$FXA_PASSWORD"
export FXA_PASSWORD
MAIL_DIR=$(mktemp -d)
chmod 0777 "$MAIL_DIR"
CATCHER_MAIL_DIR="$MAIL_DIR" start_catcher "$EXT_USER" "$EXT_PW" 1 || true
wait_healthy "$AUTH_C" 300 || fail "first_sync: fxa-auth not healthy: $(redact "$(docker logs --tail 10 "$AUTH_C" 2>&1)")"
fxa_client() {  # the helper through Traefik at the public hosts; the password by env
  docker run --rm --network portcullis-proxy --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges:true \
    --user 10001:10001 -v "$PWD/tests/fxa_client.py:/portcullis-test/fxa_client.py:ro" -v "$MAIL_DIR:/mail:ro" \
    -v "$PROJECT_DIR/certs/ca-bundle.crt:/etc/ssl/certs/portcullis-ca-bundle.crt:ro" \
    -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/portcullis-ca-bundle.crt -e SSL_CERT_FILE=/etc/ssl/certs/portcullis-ca-bundle.crt \
    -e FXA_PASSWORD -e FXA_MAIL_DIR=/mail -e FXA_AUTH_URL="https://$API_HOST" \
    -e FXA_TOKEN_URL="https://$SYNC_HOST" -e FXA_NODE_URL="https://$SYNC_HOST" -e FXA_SYNC_URL= \
    --entrypoint python3 "$SYNC_IMAGE" -I -B /portcullis-test/fxa_client.py "$@" 2>&1 | tail -1
}
jget() { printf '%s' "$1" | jq -r "$2" 2>/dev/null || echo "<not JSON>"; }
SYNC_USER="fxa-sync-test@$DOMAIN"
printf "INSERT IGNORE INTO ffs.signup_allowlist (entry) VALUES ('%s');\n" "$SYNC_USER" | mysql_root > /dev/null
OUT=$(fxa_client signup "$SYNC_USER" || true)
FXA_UID=$(jget "$OUT" '.uid // ""')
if [ "$(jget "$OUT" .verified)" = true ] && [[ "$FXA_UID" =~ ^[0-9a-f]{32}$ ]]; then
  pass "first_sync: $SYNC_USER signed up, verified with the mailed code (uid $FXA_UID)"
else
  fail "first_sync: sign-up of $SYNC_USER: $(redact "$OUT")"
fi
# A second account, for the admin section's delete / enable checks.
DEL_USER="fxa-delete-test@$DOMAIN"
printf "INSERT IGNORE INTO ffs.signup_allowlist (entry) VALUES ('%s');\n" "$DEL_USER" | mysql_root > /dev/null
OUT=$(fxa_client signup "$DEL_USER" || true)
DEL_UID=$(jget "$OUT" '.uid // ""')
[[ "$DEL_UID" =~ ^[0-9a-f]{32}$ ]] && info "second account $DEL_USER (uid $DEL_UID)" \
  || fail "first_sync: sign-up of $DEL_USER: $(redact "$OUT")"
USERS_BEFORE=$(sdb "SELECT count(*) FROM users")
OUT=$(fxa_client sync "$SYNC_USER" || true)
EP=$(jget "$OUT" '.api_endpoint // ""')
if [ "$(jget "$OUT" .token_http)" = 200 ] && [[ "$EP" =~ ^https://${SYNC_HOST//./\\.}/1\.5/[0-9]+$ ]]; then
  pass "first_sync: OAuth token with the Sync scope -> tokenserver 200, api_endpoint $EP (the Sync host)"
else
  fail "first_sync: tokenserver: $(redact "$OUT")"
fi
if [ "$(jget "$OUT" .put_http)" = 200 ] && [ "$(jget "$OUT" .get_http)" = 200 ] && [ "$(jget "$OUT" .round_trip)" = true ] \
    && [ "$(jget "$OUT" .unsigned_get_http)" = 401 ]; then
  pass "first_sync: BSO PUT 200 / GET 200 round trip with the token's Hawk key; unsigned GET 401"
else
  fail "first_sync: storage: $(redact "$OUT")"
fi
ROW=$(sdb "SELECT count(*) || ':' || COALESCE(max(n.node), '') FROM users u JOIN nodes n ON n.id = u.nodeid WHERE u.email = '$FXA_UID@$API_HOST'")
[ "$ROW" = "1:https://$SYNC_HOST" ] && pass "first_sync: one tokenserver row, $FXA_UID@$API_HOST on https://$SYNC_HOST (inserted as firefoxsync_app)" \
  || fail "first_sync: tokenserver rows for $FXA_UID@$API_HOST: $ROW"

# foreign_token_refused: another accounts server's token (a JWT signed by a
# key this instance never saw) and one of ours without the Sync scope: 401,
# no tokenserver row.
OUT=$(fxa_client foreign-token "$SYNC_USER" || true)
FSUB=$(jget "$OUT" '.foreign_sub // ""')
[ "$(jget "$OUT" .foreign_http)" = 401 ] && pass "foreign_token_refused: a foreign accounts server's token -> 401 ($(jget "$OUT" .foreign_status))" \
  || fail "foreign_token_refused: foreign token: $(redact "$OUT")"
[ "$(jget "$OUT" .wrong_scope_http)" = 401 ] && pass "foreign_token_refused: our own token without the Sync scope -> 401" \
  || fail "foreign_token_refused: wrong-scope token: $(redact "$OUT")"
[ -n "$FSUB" ] && [ "$(sdb "SELECT count(*) FROM users WHERE email LIKE '$FSUB@%'")" = 0 ] \
  && [ "$(sdb "SELECT count(*) FROM users")" = "$((USERS_BEFORE + 1))" ] \
  && pass "foreign_token_refused: no tokenserver row for the foreign account (only the first sync's)" \
  || fail "foreign_token_refused: users rows changed: $(sdb "SELECT count(*) FROM users") (before the first sync $USERS_BEFORE)"
# The password never on a container's argv.
bad=""
for c in $(docker ps -aq); do
  case "$(docker inspect -f '{{json .Path}} {{json .Args}} {{json .Config.Cmd}} {{json .Config.Entrypoint}}' "$c" 2>/dev/null)" in
    *"$FXA_PASSWORD"*) bad="$bad $c" ;;
  esac
done
[ -z "$bad" ] && pass "first_sync: the account password on no container's argv" || fail "first_sync: the account password on argv:$bad"
# The catcher and its MAIL_DIR stay for the access section's sign-ups.
unset FXA_PASSWORD

# ══ fxa-gate (Task 12), live: the real gate behind core's Traefik, from
# the CI host (via_traefik) and from another container on portcullis-proxy. ══
section "Firefox Sync + own accounts (gate, live)"
GATE_C=portcullis-fxa-gate-1
PROFILE_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA_PROFILE"
G_ACC_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA_ACCOUNTS"
G_ADMIN_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA_ADMIN"
G_PAIR_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA_PAIRING"
ST=$(docker inspect -f '{{.State.Status}} user={{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} drop={{.HostConfig.CapDrop}} add={{.HostConfig.CapAdd}} pids={{.HostConfig.PidsLimit}}' "$GATE_C" 2>/dev/null || echo absent)
[ "$ST" = "running user=101:101 ro=true drop=[ALL] add=[] pids=64" ] && pass "gate_running: fxa-gate runs unprivileged ($ST)" \
  || fail "gate_running: $ST: $(docker logs --tail 10 "$GATE_C" 2>&1 | tr '\n' ' ')"
CAPS=$(docker exec "$GATE_C" sh -c 'id -u; grep "^CapEff:" /proc/1/status' 2>&1 | tr -s '\n\t ' ' ')
[ "$CAPS" = "101 CapEff: 0000000000000000 " ] && pass "gate_running: nginx's master is uid 101 with no effective capabilities" || fail "gate_running: $CAPS"
ON_PROXY=$(docker network inspect portcullis-proxy --format '{{range .Containers}}{{.Name}} {{end}}' | tr ' ' '\n' \
  | grep -xE "portcullis-($(yq -r '.services | keys | join("|")' "$COMPOSE"))-1" | tr '\n' ' ' || true)
[ "$ON_PROXY" = "$GATE_C " ] && pass "gate_only_on_proxy: of this instance only $GATE_C is on portcullis-proxy" || fail "gate_only_on_proxy: $ON_PROXY"

# open_paths_anonymous: the open hosts answer without a cookie; the open
# paths of the accounts host are the app's, everything else there signs in.
for h in "$SYNC_HOST" "$API_HOST" "$PROFILE_HOST" "$G_PAIR_HOST"; do
  OUT=$(via_traefik "$h" /__heartbeat__)
  [ "${OUT%% *}" = 200 ] && pass "open_paths_anonymous: https://$h/__heartbeat__ -> 200 without a cookie" \
    || fail "open_paths_anonymous: https://$h/__heartbeat__ -> $OUT"
done
OUT=$(via_traefik "$PROFILE_HOST" /img/a/00000000000000000000000000000000)
[ "${OUT%% *}" = 200 ] && pass "open_paths_anonymous: the profile host's /img/ (avatars, the prefix stripped) -> 200" \
  || fail "open_paths_anonymous: profile /img/ -> $OUT"
CFG=$(curl -sk --max-time 15 --resolve "$G_ACC_HOST:443:127.0.0.1" "https://$G_ACC_HOST/.well-known/fxa-client-configuration" || true)
[ "$(jq -r '.auth_server_base_url // ""' <<< "$CFG" 2>/dev/null)" = "https://$API_HOST" ] \
  && [ "$(jq -r '.sync_tokenserver_base_url // ""' <<< "$CFG" 2>/dev/null)" = "https://$SYNC_HOST" ] \
  && pass "open_paths_anonymous: /.well-known/fxa-client-configuration (no cookie) names https://$API_HOST and https://$SYNC_HOST" \
  || fail "open_paths_anonymous: fxa-client-configuration: $(head -c 300 <<< "$CFG")"
for path in / /.well-known/change-password /metrics-flow; do
  OUT=$(via_traefik "$G_ACC_HOST" "$path"); code=${OUT%% *}
  case "$OUT" in
    *"auth.$DOMAIN"*) fail "open_paths_anonymous: accounts $path -> Keycloak ($OUT)" ;;
    000* | 403* | 421* | 5*) fail "open_paths_anonymous: accounts $path -> $OUT" ;;
    *) pass "open_paths_anonymous: accounts $path -> HTTP $code without a cookie, no Keycloak" ;;
  esac
done
OUT=$(via_traefik "$G_ACC_HOST" /settings)
case "$OUT" in *"auth.$DOMAIN"* | *"/oauth2/"*) pass "accounts_gated: accounts /settings -> Portcullis sign-in ($OUT)" ;; *) fail "accounts_gated: accounts /settings -> $OUT" ;; esac
# admin_gated
for path in / /auth/login /accounts/signups; do
  OUT=$(via_traefik "$G_ADMIN_HOST" "$path")
  case "$OUT" in *"auth.$DOMAIN"* | *"/oauth2/"*) pass "admin_gated: admin $path -> Portcullis sign-in" ;; *) fail "admin_gated: admin $path -> $OUT" ;; esac
done
OUT=$(via_traefik "$G_ADMIN_HOST" / -H "X-Auth-Request-Groups: $(yq -r '.auth.admin_group' "$MANIFEST")" -H 'X-Auth-Request-Preferred-Username: e2eadmin')
case "$OUT" in *"auth.$DOMAIN"* | *"/oauth2/"*) pass "admin_gated: forged groups / identity headers from a client still -> Portcullis sign-in" ;; *) fail "admin_gated: forged headers -> $OUT" ;; esac

# another_app_cannot_reach_auth: a container on portcullis-proxy (another
# app) neither resolves nor reaches the accounts API, and the gate refuses it.
GATE_PROXY_IP=$(docker inspect "$GATE_C" --format '{{with index .NetworkSettings.Networks "portcullis-proxy"}}{{.IPAddress}}{{end}}')
bad=""
for u in http://fxa-auth:9000/__heartbeat__ http://fxa-auth-internal:9000/__heartbeat__ http://ffs-admin-internal:8081/ \
         http://firefox-sync-fxa-internal:8000/__heartbeat__; do
  rc=0
  docker run --rm --network portcullis-proxy --entrypoint curl "$NGINX_IMAGE" -s -o /dev/null --max-time 5 "$u" > /dev/null 2>&1 || rc=$?
  case "$rc" in 6 | 7 | 28) ;; *) bad="$bad $u(curl exit $rc)" ;; esac
done
[ -z "$bad" ] && pass "another_app_cannot_reach_auth: from portcullis-proxy, fxa-auth / the -internal names don't answer (curl exit 6, 7 or 28)" \
  || fail "another_app_cannot_reach_auth: reached:$bad"
nb() {  # $1 host header, rest: curl args -> status from a portcullis-proxy neighbour straight at the gate
  local h=$1
  shift
  docker run --rm --network portcullis-proxy --entrypoint curl "$NGINX_IMAGE" -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H "Host: $h" "$@" 2>/dev/null || true
}
bad=""
[ -n "$GATE_PROXY_IP" ] || bad=" (no gate address on portcullis-proxy)"
for h in "$API_HOST" "$SYNC_HOST" "$PROFILE_HOST" "$G_PAIR_HOST" "$G_ACC_HOST"; do
  code=$(nb "$h" -X POST -H 'Content-Type: application/json' -d '{}' "http://$GATE_PROXY_IP:8080/v1/account/create")
  [ "$code" = 403 ] || bad="$bad $h->$code"
done
code=$(nb "$G_ADMIN_HOST" -H "X-Auth-Request-Groups: $(yq -r '.auth.admin_group' "$MANIFEST")" "http://$GATE_PROXY_IP:8080/")
[ "$code" = 403 ] || bad="$bad $G_ADMIN_HOST(forged groups)->$code"
[ -z "$bad" ] && pass "another_app_cannot_reach_auth: straight at fxa-gate ($GATE_PROXY_IP:8080) from portcullis-proxy: 403 on every host (POST /v1/account/create; the admin host with forged groups)" \
  || fail "another_app_cannot_reach_auth:$bad"

# spoofed_xff_same_key: a client's X-Forwarded-For never becomes the rate
# limits' address (Traefik drops it; the gate adds nothing).
RL_USER="fxa-ratelimit-test@$DOMAIN"
codes=""
last=""
for n in 1 2 3 4 5 6; do
  last=$(curl -sk --max-time 15 --resolve "$API_HOST:443:127.0.0.1" -H "X-Forwarded-For: 203.0.113.$n" \
    -H 'Content-Type: application/json' -d "{\"email\":\"$RL_USER\",\"authPW\":\"$(printf '0%.0s' $(seq 1 64))\"}" \
    -w ' %{http_code}' "https://$API_HOST/v1/account/login" || echo "error 000")
  codes="$codes ${last##* }"
done
ERRNO=$(jq -r '.errno // ""' <<< "${last% *}" 2>/dev/null || true)
if [ "${last##* }" = 429 ] && [ "$ERRNO" = 114 ]; then
  pass "spoofed_xff_same_key: 6 failed logins for one email, each with another X-Forwarded-For: the 6th -> 429 errno 114 (statuses:$codes)"
else
  fail "spoofed_xff_same_key: statuses:$codes, last errno '$ERRNO': $(head -c 200 <<< "${last% *}")"
fi
KEYS=$(docker exec portcullis-fxa-redis-1 redis-cli --scan --pattern '*203.0.113*' 2>&1 || echo "<redis-cli failed>")
[ -z "$KEYS" ] && pass "spoofed_xff_same_key: no rate-limit key holds a spoofed address (redis --scan '*203.0.113*' empty)" \
  || fail "spoofed_xff_same_key: keys with a spoofed address: $(head -c 300 <<< "$KEYS")"
# Positive control: the per-address keys of these logins exist, under the
# client's real address as Traefik saw it (rate-limit:<type>:ip_email=<ip>_<email>:accountLogin:...).
RLK=$(docker exec portcullis-fxa-redis-1 redis-cli --scan --pattern "rate-limit:*:ip_email=*$RL_USER*:accountLogin:*" 2>&1 || true)
RL_IPS=$(sed -n 's/^rate-limit:[a-z]*:ip_email=\([0-9.]*\)_.*/\1/p' <<< "$RLK" | sort -u | tr '\n' ' ')
IPK=$(docker exec portcullis-fxa-redis-1 redis-cli --scan --pattern "rate-limit:*:ip=${RL_IPS%% *}:accountLogin:*" 2>&1 || true)
if [ -n "$RLK" ] && [[ "$RL_IPS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\ $ ]] && [[ "$RL_IPS" != 203.0.113.* ]] && [ -n "$IPK" ]; then
  pass "spoofed_xff_same_key: positive control: the login attempts' ip_email and ip keys exist, under one real address (${RL_IPS% }), none spoofed"
else
  fail "spoofed_xff_same_key: positive control: ip_email keys '$(head -c 300 <<< "$RLK")', addresses '$RL_IPS', ip keys '$(head -c 200 <<< "$IPK")'"
fi

# sync_body_2_5mb: a 2.5 MB body reaches the Sync server (Hawk refuses it),
# never the gate's 413. A numeric uid: syncstorage-rs answers 404 for a
# path that names none (/1.5/x/...) before it checks Hawk.
code=$(head -c 2621440 /dev/zero | tr '\0' 'a' | curl -sk --max-time 30 --resolve "$SYNC_HOST:443:127.0.0.1" -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary @- "https://$SYNC_HOST/1.5/1/storage/bookmarks" || true)
[ "$code" = 401 ] && pass "sync_body_2_5mb: a 2.5 MB POST to /1.5/1/storage/bookmarks -> 401 (Hawk), not 413" \
  || fail "sync_body_2_5mb: -> $code (want 401)"

# pairing_websocket: the upgrade goes through Traefik and the gate.
code=$(curl -sk --http1.1 --max-time 5 --resolve "$G_PAIR_HOST:443:127.0.0.1" -o /dev/null -w '%{http_code}' \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H "Origin: https://$G_ACC_HOST" "https://$G_PAIR_HOST/v1/ws/" 2>/dev/null || true)
[ "${code:0:3}" = 101 ] && pass "pairing_websocket: wss://$G_PAIR_HOST/v1/ws/ upgrade -> 101" || fail "pairing_websocket: -> ${code:-none}"

# signup_path_variants_refused / account_creation_routes: an address not on
# the sign-up allowlist, through Traefik. Exactly /v1/account/create goes to
# the sign-up gate (refused); every other spelling is the gate's 404 (or,
# where Traefik's path sanitising merges the slashes first, it arrives as
# the canonical path: the same answer as the canonical request); the other
# account-creating routes are the gate's 403. Never 200, never an account.
NB_BODY="{\"email\":\"nobody@example.org\",\"authPW\":\"$(printf '0%.0s' $(seq 1 64))\"}"
api_post() {  # $1 path, $2 body -> "<status> <body>"
  local out
  out=$(curl -sk --path-as-is --max-time 15 --resolve "$API_HOST:443:127.0.0.1" -H 'Content-Type: application/json' \
    -d "$2" -w '\n%{http_code}' "https://$API_HOST$1" 2>/dev/null || printf '\n000')
  printf '%s %s' "$(tail -1 <<< "$out")" "$(sed '$d' <<< "$out" | tr -d '\n' | head -c 300)"
}
CANON=$(api_post /v1/account/create "$NB_BODY")
case "$CANON" in 200*) fail "signup_path_variants_refused: /v1/account/create -> 200 for an address off the allowlist" ;;
  *) pass "signup_path_variants_refused: /v1/account/create (the sign-up gate) refuses nobody@example.org: ${CANON:0:160}" ;; esac
bad=""
for path in /v1/account/create/ /V1/Account/Create /v1/account/create.json '/v1/account/create/?keys=true' \
            /v1/account/%63reate /v1/account/%43reate /v1/account%2Fcreate /v1/account/create%2F /v1/%2e/account/create \
            //v1/account/create /v1//account/create; do
  OUT=$(api_post "$path" "$NB_BODY")
  if [ "$OUT" = "404 fxa-gate: not found" ]; then
    sv="${sv:-} $path=gate-404"
  elif [ "$OUT" = "$CANON" ] && case "$path" in *//* | *%[0-9a-fA-F][0-9a-fA-F]*) true ;; *) false ;; esac; then
    # Traefik routes on the cleaned, decoded path and forwards it so: the
    # request reached the gate as exactly /v1/account/create (else the
    # gate's raw-URI check answers 404, gate_signup_variants above), on
    # the signup router (rate-limit-auth), and the sign-up gate refused it.
    sv="${sv:-} $path=canonical-after-traefik"
  else
    bad="$bad $path->${OUT:0:120}"
  fi
done
[ -z "$bad" ] && pass "signup_path_variants_refused: every other spelling -> the gate's 404, or (Traefik cleans // and decodes %xx first) the canonical path's own refusal; never fxa-auth, never 200:$sv" \
  || fail "signup_path_variants_refused:$bad"
bad=""
for path in /v1/account/passwordless/send_code /v1/account/passwordless/confirm_code /v1/linked_account/login \
            /v1/account/stub /v1/account/finish_setup /v1/account/set_password; do
  OUT=$(api_post "$path" "{\"email\":\"nobody@example.org\",\"code\":\"12345678\",\"provider\":\"google\",\"idToken\":\"x\",\"clientId\":\"5882386c6d801776\",\"authPW\":\"$(printf '0%.0s' $(seq 1 64))\"}")
  [ "$OUT" = "403 fxa-gate: accounts are created through the sign-up gate only" ] || bad="$bad $path->${OUT:0:120}"
done
[ -z "$bad" ] && pass "account_creation_routes: passwordless send / confirm, linked_account login, account/stub, finish_setup, set_password -> the gate's 403" \
  || fail "account_creation_routes:$bad"
bad=""
for path in /v1/mfa/recovery_email /v1/mfa/recovery_email/set_primary /v1/mfa/recovery_email/secondary/verify_code /v1/recovery_email/set_primary; do
  OUT=$(api_post "$path" '{"email":"nobody-else@example.org","code":"12345678"}')
  [ "$OUT" = "403 fxa-gate: an account's email is its Portcullis email: it can't be added or changed here" ] || bad="$bad $path->${OUT:0:120}"
done
[ -z "$bad" ] && pass "email_change_routes: through Traefik, adding a secondary email or setting the primary one -> the gate's 403" \
  || fail "email_change_routes (live):$bad"
# The pinned image itself: the stub-account routes are gone from fxa-auth
# (404 straight at it, inside its container), the others are its own.
bad=""
for path in /v1/account/stub /v1/account/finish_setup /v1/account/set_password; do
  code=$(docker exec "$AUTH_C" node -e '
    fetch("http://127.0.0.1:9000" + process.argv[1], {method: "POST", headers: {"content-type": "application/json"},
      body: JSON.stringify({email: "nobody@example.org", clientId: "5882386c6d801776"})})
      .then(r => console.log(r.status), e => console.log("error"))' "$path" 2>&1 || echo error)
  [ "$code" = 404 ] || bad="$bad $path->$code"
done
[ -z "$bad" ] && pass "account_creation_routes: fxa-auth v1.350.0 has no account/stub, finish_setup or set_password route (404 straight at it)" \
  || fail "account_creation_routes: straight at fxa-auth:$bad"
# Routes that reach fxa-auth and act on existing accounts only.
bad=""
for path in /v1/account/login '/v1/account/login?keys=true' /v1/password/forgot/send_otp /v1/account/status; do
  OUT=$(api_post "$path" "$NB_BODY")
  case "$OUT" in 200*) case "$path" in /v1/account/status) ;; *) bad="$bad $path->200" ;; esac ;; esac
  rt="${rt:-} $path=${OUT%% *}"
done
ROWS=$(echo "SELECT COUNT(*) FROM fxa.accounts WHERE normalizedEmail = 'nobody@example.org';" | mysql_root 2>&1)
if [ -z "$bad" ] && [ "$ROWS" = 0 ]; then
  pass "account_creation_routes: nobody@example.org after every route above (and login, login?keys, forgot-password, status:$rt): no fxa.accounts row"
else
  fail "account_creation_routes:$bad; fxa.accounts rows for nobody@example.org: $ROWS ($rt)"
fi
# I1 live: an Upgrade on the API host never reaches fxa-auth; pairing's does.
code=$(curl -sk --http1.1 --max-time 5 --resolve "$API_HOST:443:127.0.0.1" -o /dev/null -w '%{http_code}' \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  "https://$API_HOST/v1/account/status" 2>/dev/null || true)
[ "$code" = 400 ] && pass "no_upgrade_tunnel: a websocket upgrade on the API host through Traefik -> 400" || fail "no_upgrade_tunnel: API host upgrade -> ${code:-none}"

# ══ Admin (Task 16), live: the admin UI as the instance starts it, then a
# probe of the same image and environment that signs in at a stand-in
# OpenID provider (Keycloak can't sign the test users in without a browser:
# passkeys only), which shows whom the admin UI lets in by the groups claim
# and, signed in, that access is managed elsewhere. The probe is reached over
# the instance's network, and through a copy of fxa-gate in front of it. ══
section "Firefox Sync + own accounts (admin, live)"
ADMIN_C=portcullis-ffs-admin-1
ADMIN_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA_ADMIN"
ACC_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA_ACCOUNTS"
PAIRING_HOST="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA_PAIRING"
ADMIN_GROUP_M=$(yq -r '.auth.admin_group' "$MANIFEST")
ACCESS_GROUP_M=$(yq -r '.auth.access_group' "$MANIFEST")
CID_M=$(yq -r '.keycloak_clients[0].client_id' "$MANIFEST")
OIDC_C=portcullis-fxa-test-oidc
PROBE_C=portcullis-fxa-test-admin
if wait_healthy "$ADMIN_C" 300; then
  pass "ffs-admin healthy (its OIDC sign-in configured, it starts)"
else
  fail "ffs-admin not healthy: $(docker logs --tail 20 "$ADMIN_C" 2>&1 | tr '\n' ' ')"
fi
AIP=$(app_container_ip "$APP_ID" ffs-admin)
AB="http://$AIP:8080"

# post_login_403: no password sign-in; forged identity headers sign nobody in.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -d 'password=aaaaaaaaaaaaaaaa' "$AB/login" || echo 000)
[ "$CODE" = 403 ] && pass "post_login_403: POST /login -> 403 (no password sign-in)" || fail "post_login_403: POST /login -> $CODE"
LOGIN_PAGE=$(curl -s "$AB/login" || true)
if grep -q 'type="password"' <<< "$LOGIN_PAGE"; then
  fail "post_login_403: the login page has a password form"
elif grep -q 'href="/auth/login' <<< "$LOGIN_PAGE" && grep -q 'Portcullis' <<< "$LOGIN_PAGE"; then
  pass "post_login_403: the login page has no password form, only the Portcullis sign-in (/auth/login)"
else
  fail "post_login_403: the login page offers no Portcullis sign-in: $(sed 's/<[^>]*>/ /g' <<< "$LOGIN_PAGE" | tr -s ' \n' ' ' | head -c 300)"
fi
CODE=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'X-Forwarded-User: e2eadmin' -H 'X-Auth-Request-Preferred-Username: e2eadmin' \
  -H "X-Auth-Request-Groups: $ADMIN_GROUP_M" -H "X-Forwarded-Groups: $ADMIN_GROUP_M" -H 'Remote-Email: e2eadmin@example.org' \
  -H "Remote-Groups: $ADMIN_GROUP_M" "$AB/" || echo 000)
[[ "$CODE" == "303 "*"/login"* ]] && pass "post_login_403: forged identity headers -> $CODE (not signed in)" \
  || fail "post_login_403: forged identity headers -> $CODE"

# redirect_uri_matches: discovery at Portcullis's issuer (through Traefik,
# trusting Portcullis's CA), then Keycloak, with exactly the redirect URI the
# Hub registers (keycloak_clients). Keycloak must accept it and refuse any
# other; a failed registration fails (never a pass without the client).
REDIRECT="https://$ADMIN_HOST/auth/callback"
LOC=""
for _ in $(seq 1 20); do
  LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$AB/auth/login" || true)
  case "$LOC" in "https://auth.$DOMAIN/"*) break ;; *) sleep 3 ;; esac
done
ENC=$(jq -rn --arg u "$REDIRECT" '$u | @uri')
if [[ "$LOC" == "https://auth.$DOMAIN/realms/portcullis/protocol/openid-connect/auth?"* ]] \
    && grep -q "redirect_uri=$ENC\(&\|$\)" <<< "$LOC" && grep -q "client_id=$CID_M\(&\|$\)" <<< "$LOC" \
    && grep -q 'code_challenge_method=S256' <<< "$LOC" && grep -q 'scope=openid+email+profile\(&\|$\)' <<< "$LOC"; then
  pass "redirect_uri_matches: /auth/login -> Keycloak, client $CID_M, redirect_uri $REDIRECT, scope openid email profile, PKCE S256"
else
  fail "redirect_uri_matches: /auth/login -> ${LOC:-<none>} (discovery of https://auth.$DOMAIN/realms/portcullis failed? $(docker logs --tail 5 "$ADMIN_C" 2>&1 | grep -i oidc | tr '\n' ' '))"
fi
KC_TOKEN=$(keycloak_admin_token || true)
[ -n "$KC_TOKEN" ] && [ "$KC_TOKEN" != null ] || fail "redirect_uri_matches: no Keycloak admin token"
kc_api() {  # $1 method, $2 path under the realm, rest: curl arguments; the token never on argv
  local m=$1 p=$2
  shift 2
  curl -s -X "$m" "$KEYCLOAK_URL/admin/realms/portcullis$p" -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "$@"
}
kc_client_id() { kc_api GET "/clients?clientId=$CID_M" | jq -r '.[0].id // empty' 2>/dev/null || true; }
REG_REDIRECT=$(yq -r '.keycloak_clients[0].redirect_uri' "$MANIFEST")
REG_REDIRECT=${REG_REDIRECT/'{{HOST_FIREFOX_SYNC_FXA_ADMIN}}'/$ADMIN_HOST}
REG=none
if [ -z "${FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET:-}" ]; then
  # Keycloak would generate a secret of its own: never register without ours.
  fail "redirect_uri_matches: FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET is empty or unset: the client isn't registered"
else
  # A client left from an earlier run never stands in: deleted, then created.
  OLD_ID=$(kc_client_id)
  [ -z "$OLD_ID" ] || kc_api DELETE "/clients/$OLD_ID" -o /dev/null || true
  # The secret from this shell's environment (jq's env), never an argv.
  REG=$(jq -n --arg uri "$REG_REDIRECT" --arg cid "$CID_M" --arg name "$(yq -r '.keycloak_clients[0].name' "$MANIFEST")" \
    '{clientId: $cid, name: $name, enabled: true, protocol: "openid-connect", publicClient: false,
      secret: env.FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET, redirectUris: [$uri], standardFlowEnabled: true, directAccessGrantsEnabled: false,
      defaultClientScopes: ["openid", "profile", "email", "acr", "groups"]}' \
    | kc_api POST /clients -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d @- || echo 000)
fi
KC_ID=$(kc_client_id)
KC_URIS=$([ -z "$KC_ID" ] || kc_api GET "/clients/$KC_ID" | jq -c '[.redirectUris[]] | sort' 2>/dev/null || true)
KC_SECRET_OK=false
[ -z "$KC_ID" ] || [ "$(kc_api GET "/clients/$KC_ID/client-secret" | jq -r '.value // empty' 2>/dev/null || true)" != "$FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET" ] \
  || KC_SECRET_OK=true
if [ "$REG" = 201 ] && [ "$KC_URIS" = "$(jq -cn --arg u "$REG_REDIRECT" '[$u]')" ] && [ "$KC_SECRET_OK" = true ]; then
  pass "redirect_uri_matches: Keycloak client $CID_M created fresh (201) as the Hub does; read back: redirect URIs exactly [$REG_REDIRECT], the secret ours"
else
  fail "redirect_uri_matches: registering $CID_M answered $REG (want 201); read back: redirect URIs ${KC_URIS:-<none>}, secret ours: $KC_SECRET_OK"
fi
[ "$REG_REDIRECT" = "$REDIRECT" ] && pass "redirect_uri_matches: the registered redirect URI is the one the admin UI sends" \
  || fail "redirect_uri_matches: registered $REG_REDIRECT, sent $REDIRECT"
AUTH_PATH="/${LOC#https://auth.$DOMAIN/}"
kc_page() { curl -sk --max-time 15 --resolve "auth.$DOMAIN:443:127.0.0.1" "https://auth.$DOMAIN$1" 2>/dev/null || true; }
KC_ERR='Invalid parameter: redirect_uri|Client not found|Invalid redirect uri|invalid_redirect_uri|unauthorized_client'
PAGE=$(kc_page "$AUTH_PATH")
if [ -n "$PAGE" ] && [ "$AUTH_PATH" != "/" ] && ! grep -Eqi "$KC_ERR" <<< "$PAGE"; then
  pass "redirect_uri_matches: Keycloak accepts the admin UI's authorization request (client and registered redirect URI)"
else
  fail "redirect_uri_matches: Keycloak refused the admin UI's request: $(grep -Eoi "$KC_ERR" <<< "$PAGE" | head -1) (request ${AUTH_PATH%%&state=*})"
fi
BAD_PATH=${AUTH_PATH/"redirect_uri=$ENC"/"redirect_uri=$(jq -rn --arg u "https://$ACC_HOST/auth/callback" '$u | @uri')"}
if [ "$BAD_PATH" != "$AUTH_PATH" ] && grep -Eqi "$KC_ERR" <<< "$(kc_page "$BAD_PATH")"; then
  pass "redirect_uri_matches: Keycloak refuses another redirect URI (the accounts host's)"
else
  fail "redirect_uri_matches: Keycloak did not refuse another redirect URI"
fi
KC_ID=$(kc_client_id)
[ -z "$KC_ID" ] || kc_api DELETE "/clients/$KC_ID" -o /dev/null || true

# The stand-in OpenID provider (node, the accounts image) on the instance's
# network: discovery, JWKS (a fresh RSA key), an authorization endpoint that
# checks the client, the redirect URI, PKCE and the nonce, and signs in the
# person the test names (the profile parameter it adds), a token endpoint
# that checks the client secret (from ffs-admin's environment) and the PKCE
# verifier, and userinfo. It logs the profile of every code redeemed, never a
# secret.
OIDC_JS='
const http = require("http"), crypto = require("crypto");
const ISS = process.env.OIDC_ISSUER, CID = process.env.OIDC_CLIENT_ID, SECRET = process.env.OIDC_CLIENT_SECRET;
const REDIRECT = process.env.OIDC_REDIRECT, ADMIN = process.env.OIDC_ADMIN_GROUP, ACCESS = process.env.OIDC_ACCESS_GROUP;
const D = process.env.OIDC_DOMAIN;
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = Object.assign(publicKey.export({ format: "jwk" }), { kid: "stub", alg: "RS256", use: "sig" });
const b64 = o => Buffer.from(JSON.stringify(o)).toString("base64url");
const P = {
  admin: { sub: "s-admin", email: "e2eadmin@" + D, email_verified: false, groups: [ACCESS, ADMIN] },
  member: { sub: "s-member", email: "e2emember@" + D, email_verified: false, groups: [ACCESS] },
  "member-verified": { sub: "s-member-v", email: "e2emember@" + D, email_verified: true, groups: [ACCESS] },
  "no-groups": { sub: "s-nogroups", email: "e2eadmin@" + D, email_verified: true },
  "other-claim": { sub: "s-other", email: "e2eadmin@" + D, email_verified: true, roles: [ADMIN], group: ADMIN },
  "near-miss": { sub: "s-near", email: "e2eadmin@" + D, email_verified: true, groups: [ADMIN.toUpperCase(), "/" + ADMIN, ADMIN + "-x", " " + ADMIN] }
};
const codes = new Map(), tokens = new Map();
const send = (res, code, obj, headers) => { res.writeHead(code, Object.assign({ "content-type": "application/json" }, headers || {})); res.end(obj === undefined ? "" : JSON.stringify(obj)); };
http.createServer((req, res) => {
  const u = new URL(req.url, ISS);
  if (u.pathname === "/.well-known/openid-configuration") return send(res, 200, { issuer: ISS,
    authorization_endpoint: ISS + "/auth", token_endpoint: ISS + "/token", userinfo_endpoint: ISS + "/userinfo",
    jwks_uri: ISS + "/jwks", response_types_supported: ["code"], subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"], code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"] });
  if (u.pathname === "/jwks") return send(res, 200, { keys: [jwk] });
  if (u.pathname === "/auth") {
    const q = u.searchParams, name = q.get("profile"), p = P[name];
    const bad = !p ? "profile" : q.get("client_id") !== CID ? "client_id" : q.get("redirect_uri") !== REDIRECT ? "redirect_uri"
      : q.get("response_type") !== "code" ? "response_type" : q.get("code_challenge_method") !== "S256" || !q.get("code_challenge") ? "pkce"
      : !q.get("nonce") ? "nonce" : !q.get("state") ? "state" : "";
    if (bad) { console.log("AUTH refused " + bad); return send(res, 400, { error: "invalid_request", what: bad }); }
    const code = crypto.randomBytes(16).toString("hex");
    codes.set(code, { name, p, nonce: q.get("nonce"), challenge: q.get("code_challenge") });
    console.log("AUTH " + name);
    return send(res, 302, undefined, { location: REDIRECT + "?code=" + code + "&state=" + encodeURIComponent(q.get("state")) });
  }
  if (u.pathname === "/token" && req.method === "POST") {
    let body = "";
    req.on("data", d => { body += d; });
    req.on("end", () => {
      const f = new URLSearchParams(body);
      let id = f.get("client_id") || "", secret = f.get("client_secret") || "";
      const h = req.headers.authorization || "";
      if (h.startsWith("Basic ")) {
        const [a, b] = Buffer.from(h.slice(6), "base64").toString().split(":");
        id = decodeURIComponent(a || ""); secret = decodeURIComponent(b || "");
      }
      const c = codes.get(f.get("code") || ""); codes.delete(f.get("code") || "");
      const verifier = f.get("code_verifier") || "";
      const bad = !c ? "code" : id !== CID ? "client_id" : !SECRET || secret !== SECRET ? "client_secret"
        : f.get("grant_type") !== "authorization_code" ? "grant_type" : f.get("redirect_uri") !== REDIRECT ? "redirect_uri"
        : crypto.createHash("sha256").update(verifier).digest("base64url") !== c.challenge ? "code_verifier" : "";
      if (bad) { console.log("TOKEN refused " + bad); return send(res, 400, { error: "invalid_grant", what: bad }); }
      const now = Math.floor(Date.now() / 1000);
      const head = b64({ alg: "RS256", kid: "stub", typ: "JWT" });
      const body2 = b64(Object.assign({}, c.p, { iss: ISS, aud: CID, iat: now, exp: now + 300, nonce: c.nonce }));
      const sig = crypto.sign("sha256", Buffer.from(head + "." + body2), privateKey).toString("base64url");
      const access = crypto.randomBytes(16).toString("hex");
      tokens.set(access, c.p);
      console.log("TOKEN " + c.name + " client secret ok");
      send(res, 200, { access_token: access, token_type: "Bearer", expires_in: 300, id_token: head + "." + body2 + "." + sig });
    });
    return;
  }
  if (u.pathname === "/userinfo") {
    const p = tokens.get((req.headers.authorization || "").replace(/^Bearer /, ""));
    console.log("USERINFO " + (p ? p.sub : "refused"));
    return p ? send(res, 200, p) : send(res, 401, { error: "invalid_token" });
  }
  send(res, 404, { error: "not_found" });
}).listen(8090, "0.0.0.0", () => console.log("oidc stub listening"));
'
STUB_ISS=http://fxa-test-oidc:8090
docker rm -f "$OIDC_C" "$PROBE_C" > /dev/null 2>&1 || true
FXA_TEST_CONTAINERS="$FXA_TEST_CONTAINERS $OIDC_C $PROBE_C"
OIDC_CLIENT_SECRET="$FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET" docker run -d --name "$OIDC_C" --network "$NET" --network-alias fxa-test-oidc \
  --user 10001:10001 --read-only --tmpfs /tmp:size=8m --cap-drop ALL --security-opt no-new-privileges:true \
  -e OIDC_ISSUER="$STUB_ISS" -e OIDC_CLIENT_ID="$CID_M" -e OIDC_CLIENT_SECRET -e OIDC_REDIRECT="$REDIRECT" \
  -e OIDC_ADMIN_GROUP="$ADMIN_GROUP_M" -e OIDC_ACCESS_GROUP="$ACCESS_GROUP_M" -e OIDC_DOMAIN="$DOMAIN" \
  --entrypoint node "$FXA_IMAGE" -e "$OIDC_JS" > /dev/null
for _ in $(seq 1 30); do grep -q 'oidc stub listening' <<< "$(docker logs "$OIDC_C" 2>&1)" && break; sleep 1; done
STUB_IP=$(docker inspect "$OIDC_C" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' | awk '{print $1}')
grep -q 'oidc stub listening' <<< "$(docker logs "$OIDC_C" 2>&1)" && info "OpenID stand-in at $STUB_ISS ($STUB_IP)" \
  || fail "the OpenID stand-in did not start: $(docker logs "$OIDC_C" 2>&1 | tail -5 | tr '\n' ' ')"

# A probe of ffs-admin: the real container's environment (secrets in a file
# only this user reads, removed once the container has it; never argv), the
# issuer the stand-in, cookies without Secure (plain http here). $1: env
# names to drop; rest: NAME=value lines to add. Prints the container id.
probe_env() {  # $1 drop regex, rest: lines to add -> the env file's path
  local f="$PROBE_DIR/env"
  docker inspect "$ADMIN_C" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -v -E "^(PATH|HOME|$1)=" > "$f"
  shift
  printf '%s\n' "$@" >> "$f"
  printf '%s' "$f"
}
PROBE_DIR=$(mktemp -d)
chmod 700 "$PROBE_DIR"
umask_was=$(umask); umask 077
ENVF=$(probe_env 'ADMIN_OIDC_ISSUER|ADMIN_INSECURE_COOKIE' "ADMIN_OIDC_ISSUER=$STUB_ISS" ADMIN_INSECURE_COOKIE=1)
docker run -d --name "$PROBE_C" --network "$NET" --read-only --tmpfs /tmp:size=64m --cap-drop ALL \
  --security-opt no-new-privileges:true --env-file "$ENVF" "$ADMIN_IMAGE" > /dev/null || fail "the admin UI probe did not start"
rm -f "$ENVF"
umask "$umask_was"
wait_healthy "$PROBE_C" 120 || fail "the admin UI probe is not healthy: $(docker logs --tail 10 "$PROBE_C" 2>&1 | tr '\n' ' ')"
PIP=$(docker inspect "$PROBE_C" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' | awk '{print $1}')
PB="http://$PIP:8080"
# One sign-in as $1 (a stand-in profile) with cookie jar $2: the admin UI's
# /auth/login, the provider's answer, the callback, then /. Prints
# "<callback status> <its redirect> | <GET / status> <its redirect>".
oidc_signin() {
  local loc cb
  loc=$(curl -s -c "$2" -b "$2" -o /dev/null -w '%{redirect_url}' "$PB/auth/login" || true)
  case "$loc" in "$STUB_ISS/auth?"*) ;; *) printf 'no provider redirect: %s' "$loc"; return 0 ;; esac
  cb=$(curl -s -o /dev/null -w '%{redirect_url}' "http://$STUB_IP:8090${loc#"$STUB_ISS"}&profile=$1" || true)
  case "$cb" in "$REDIRECT?"*) ;; *) printf 'provider refused: %s %s' "$cb" "$(docker logs --tail 1 "$OIDC_C" 2>&1)"; return 0 ;; esac
  printf '%s | %s' "$(curl -s -c "$2" -b "$2" -o /dev/null -w '%{http_code} %{redirect_url}' "$PB/auth/callback?${cb#*\?}" || echo 000)" \
    "$(curl -s -c "$2" -b "$2" -o /dev/null -w '%{http_code} %{redirect_url}' "$PB/" || echo 000)"
}
# oidc_member_not_admin_refused: a member of the access group only, with or
# without a verified email, no groups claim (nor in userinfo), the admin
# group under another claim, or near-miss names: refused after a valid
# sign-in (the code redeemed with the client secret), no session.
for profile in member member-verified no-groups other-claim near-miss; do
  OUT=$(oidc_signin "$profile" "$PROBE_DIR/jar-$profile")
  if [[ "$OUT" == "303 $PB/login?"*"error=sso"*" | 303 $PB/login"* ]] \
      && grep -qx "TOKEN $profile client secret ok" <<< "$(docker logs "$OIDC_C" 2>&1)"; then
    pass "oidc_member_not_admin_refused: $profile: signed in at the provider, the admin UI refuses it (no session: / -> sign-in)"
  else
    fail "oidc_member_not_admin_refused: $profile: $OUT; provider: $(docker logs "$OIDC_C" 2>&1 | grep -E "(AUTH|TOKEN).*" | tail -2 | tr '\n' ' ')"
  fi
done
JAR="$PROBE_DIR/jar-admin"
OUT=$(oidc_signin admin "$JAR")
if [[ "$OUT" == "200  | 200 "* ]] && grep -qx 'TOKEN admin client secret ok' <<< "$(docker logs "$OIDC_C" 2>&1)"; then
  pass "oidc admin: a member of $ADMIN_GROUP_M (email unverified) is signed in (the groups claim alone)"
else
  fail "oidc admin: $OUT; provider: $(docker logs "$OIDC_C" 2>&1 | tail -3 | tr '\n' ' '); probe: $(docker logs --tail 5 "$PROBE_C" 2>&1 | tr '\n' ' ')"
fi
# The real container (its own issuer) has no stand-in: a callback with the
# stand-in's answer is no sign-in there.
OUT=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "$AB/auth/callback?code=x&state=y" || echo 000)
[[ "$OUT" == "303 "*"/login?error=sso" ]] && pass "oidc: the admin UI's callback without its own state -> $OUT (no session)" \
  || fail "oidc: the admin UI's callback without its state -> $OUT"

# connect_page_values: Firefox on a computer gets
# identity.fxaccounts.autoconfig.uri = the accounts host; the page names the
# accounts, Sync (tokenserver) and pairing servers.
USERJS=$(curl -s -b "$JAR" "$PB/connect/user.js" || true)
grep -qxF "user_pref(\"identity.fxaccounts.autoconfig.uri\", \"https://$ACC_HOST\");" <<< "$USERJS" \
  && pass "connect_page_values: user.js sets identity.fxaccounts.autoconfig.uri = https://$ACC_HOST" \
  || fail "connect_page_values: user.js is '$(head -c 400 <<< "$USERJS" | tr '\n' ' ')'"
CONNECT=$(curl -s -b "$JAR" "$PB/connect" | sed 's/<[^>]*>/ /g' | tr -s ' \n' ' ' || true)
if grep -qF "Accounts server https://$ACC_HOST " <<< "$CONNECT" && grep -qF "Sync server https://$SYNC_HOST/1.0/sync/1.5 " <<< "$CONNECT" \
    && grep -qF "Pairing server wss://$PAIRING_HOST " <<< "$CONNECT" && grep -qF "identity.fxaccounts.autoconfig.uri" <<< "$CONNECT"; then
  pass "connect_page_values: Connect a device names https://$ACC_HOST (autoconfig), https://$SYNC_HOST/1.0/sync/1.5 and wss://$PAIRING_HOST"
else
  fail "connect_page_values: the Connect a device page: $(grep -oE '(Accounts|Sync|Pairing) server [^ ]+' <<< "$CONNECT" | tr '\n' ' ')"
fi

# allowlist_read_only: signed in as an admin, every form that changes who
# may sign up or sync is refused server side (the admin UI answers with its
# refusal, not the change), and nothing changed in either database.
policy_state() {
  printf '%s\n' "SELECT CONCAT(name, '=', value) FROM ffs.settings ORDER BY name;" \
    "SELECT CONCAT('allow:', entry) FROM ffs.signup_allowlist ORDER BY entry;" | mysql_root 2>&1 | tr '\n' ' '
  sdb "SELECT string_agg(config_key || '=' || config_value, ',' ORDER BY config_key) FROM config"
  sdb "SELECT 'sync allowlist rows: ' || count(*) FROM sync_allowed_accounts"
}
HOME_PAGE=$(curl -s -b "$JAR" -c "$JAR" "$PB/" || true)
CSRF=$(grep -o 'name="csrf" value="[^"]*"' <<< "$HOME_PAGE" | head -1 | sed 's/.*value="//;s/"$//')
HOME_TEXT=$(sed 's/<[^>]*>/ /g' <<< "$HOME_PAGE" | tr -s ' \n' ' ')
grep -q 'Access managed elsewhere ok' <<< "$HOME_TEXT" \
  && pass "allowlist_read_only: the setup check Access managed elsewhere is ok (the admin UI and both inits agree)" \
  || fail "allowlist_read_only: no Access managed elsewhere ok on the overview: $(grep -o 'Access managed elsewhere.\{0,120\}' <<< "$HOME_TEXT" | head -1)"
BEFORE=$(policy_state)
FORMS=("/accounts/signups mode=open&allowlist=" "/accounts/max-accounts max_accounts=1"
       "/accounts/invite email=fxa-invite-test@$DOMAIN" "/accounts/allowlist/remove entry=$SYNC_USER"
       "/sync/max-users max_users=1" "/sync/allowlist/allow uid=$OUTSIDER" "/sync/allowlist/reject uid=$OUTSIDER"
       "/sync/allowlist/remove uid=$OUTSIDER")
# Through the gate (T16 -> Task 12): a copy of fxa-gate with the instance's
# hosts and admin group in front of the signed-in probe (which answers there
# as ffs-admin-internal), on a throwaway network whose fixed "Traefik"
# address the copy trusts; the admin's session cookie and group-gate's
# groups header as Traefik would pass them (headers on stdin, never argv).
AG="portcullis-fxa-test-agate-$$"
AG_NET="$AG-net"
FXA_TEST_CONTAINERS="$FXA_TEST_CONTAINERS $AG"
FXA_TEST_NETWORKS="$FXA_TEST_NETWORKS $AG_NET"
docker network create --subnet 10.254.79.0/24 --ip-range 10.254.79.128/25 "$AG_NET" > /dev/null
docker network connect --alias ffs-admin-internal "$AG_NET" "$PROBE_C"
docker run -d --name "$AG" --network "$AG_NET" --ip 10.254.79.20 "${GATE_RUN[@]}" \
  -e PORTCULLIS_TRAEFIK_SOURCE=10.254.79.2/32 -e GATE_LISTEN=8080 -e GATE_HOST_ACCOUNTS="$ACC_HOST" -e GATE_HOST_API="$API_HOST" \
  -e GATE_HOST_PROFILE="$PORTCULLIS_HOST_FIREFOX_SYNC_FXA_PROFILE" -e GATE_HOST_SYNC="$SYNC_HOST" -e GATE_HOST_ADMIN="$ADMIN_HOST" \
  -e GATE_HOST_PAIRING="$PAIRING_HOST" -e GATE_ADMIN_GROUP="$ADMIN_GROUP_M" "$NGINX_IMAGE" /portcullis/fxa-gate.sh > /dev/null
SESSION=$(awk -F'\t' '(!/^#/ || /^#HttpOnly_/) && NF >= 7 { printf "%s%s=%s", (n++ ? "; " : ""), $6, $7 }' "$JAR")
ag() {  # $1 groups header value, rest: curl args -> "<status> <body text>"
  local groups=$1
  shift
  printf 'Cookie: %s\nX-Auth-Request-Groups: %s\n' "$SESSION" "$groups" \
    | docker run --rm -i --network "$AG_NET" --ip 10.254.79.2 --entrypoint curl "$NGINX_IMAGE" -s --max-time 15 -H @- \
      -H "Host: $ADMIN_HOST" -w '\n%{http_code}' "$@" 2>/dev/null | { body=$(cat); printf '%s %s' "$(tail -1 <<< "$body")" "$(sed '$d' <<< "$body" | sed 's/<[^>]*>/ /g' | tr -s ' \n' ' ')"; } || true
}
for _ in $(seq 1 20); do [ "$(ag "$ADMIN_GROUP_M" -o /dev/null http://10.254.79.20:8080/healthz)" != "000 " ] && break; sleep 1; done
OUT=$(ag "$ADMIN_GROUP_M" http://10.254.79.20:8080/)
[ "${OUT%% *}" = 200 ] && grep -q 'Access managed elsewhere' <<< "$OUT" \
  && pass "admin_through_gate: the admin's session and the admin group pass the gate (the overview: 200)" \
  || fail "admin_through_gate: the overview through the gate: ${OUT:0:200}"
for g in "$ACCESS_GROUP_M" ""; do
  OUT=$(ag "$g" -o /dev/null http://10.254.79.20:8080/)
  [ "${OUT%% *}" = 403 ] && pass "admin_through_gate: the same session with groups '${g:-<none>}' -> 403 at the gate" \
    || fail "admin_through_gate: groups '${g:-<none>}' -> ${OUT:0:120}"
done
for form in "${FORMS[@]}"; do
  set -- $form
  OUT=$(ag "$ADMIN_GROUP_M" -o /dev/null -d "csrf=$CSRF&$2" "http://10.254.79.20:8080$1")
  [ "${OUT%% *}" = 403 ] && pass "allowlist_read_only: POST $1 through the gate -> 403 (signed-in admin, valid CSRF token)" \
    || fail "allowlist_read_only: POST $1 through the gate -> ${OUT:0:120} (want 403)"
done
docker rm -f "$AG" > /dev/null 2>&1 || true
docker network disconnect "$AG_NET" "$PROBE_C" > /dev/null 2>&1 || true
docker network rm "$AG_NET" > /dev/null 2>&1 || true
# Underneath, the admin UI refuses them itself (and ffs_admin's grants below).
for form in "${FORMS[@]}"; do
  set -- $form
  RESP=$(curl -s -L -b "$JAR" -c "$JAR" -w '\n%{http_code}' -d "csrf=$CSRF&$2" "$PB$1" || true)
  if grep -q 'managed outside the admin UI (ADMIN_ACCESS_EXTERNAL): nothing changed here' <<< "$RESP"; then
    pass "allowlist_read_only: POST $1 straight at the admin UI: refused underneath (managed outside the admin UI: nothing changed)"
  else
    fail "allowlist_read_only: POST $1 not refused (csrf ${#CSRF} chars; status $(tail -1 <<< "$RESP"); $(sed 's/<[^>]*>/ /g' <<< "$RESP" | tr -s ' \n' ' ' | grep -o -i -E '.{0,60}(refus|error|managed|invalid)[^.]{0,80}' | head -2 | tr '\n' ' '))"
  fi
done
AFTER=$(policy_state)
[ -n "$BEFORE" ] && [ "$BEFORE" = "$AFTER" ] && pass "allowlist_read_only: the sign-up policy, its allowlist and Sync's config unchanged after the refused forms" \
  || fail "allowlist_read_only: changed: '$BEFORE' -> '$AFTER'"

# ffs_admin, the admin UI's own accounts-database user (fxa-policy):
# exactly porelli's grant set with access managed elsewhere (read-only on the
# sign-up policy and its allowlist), nothing of ffs_access's.
GRANTEE="'ffs_admin'@'%'"
GRANTS=$(printf '%s\n' "SELECT CONCAT('global ', PRIVILEGE_TYPE) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\"
  UNION ALL SELECT CONCAT('global ', PRIV, IF(WITH_GRANT_OPTION = 'Y', ' grantable', '')) FROM mysql.global_grants WHERE USER = 'ffs_admin'
  UNION ALL SELECT 'global grant option' FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\" AND IS_GRANTABLE = 'YES'
  UNION ALL SELECT CONCAT('schema ', TABLE_SCHEMA, ' ', PRIVILEGE_TYPE, IF(IS_GRANTABLE = 'YES', ' grantable', '')) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\"
  UNION ALL SELECT CONCAT('role granted ', FROM_USER, '@', FROM_HOST, IF(WITH_ADMIN_OPTION = 'Y', ' admin', '')) FROM mysql.role_edges WHERE TO_USER = 'ffs_admin'
  UNION ALL SELECT CONCAT('role holder ', TO_USER, '@', TO_HOST) FROM mysql.role_edges WHERE FROM_USER = 'ffs_admin'
  UNION ALL SELECT CONCAT('default role ', DEFAULT_ROLE_USER, '@', DEFAULT_ROLE_HOST) FROM mysql.default_roles WHERE USER = 'ffs_admin'
  UNION ALL SELECT CONCAT('proxy ', Proxied_user, '@', Proxied_host) FROM mysql.proxies_priv WHERE User = 'ffs_admin'
  UNION ALL SELECT CONCAT('applicable role ', ROLE_NAME) FROM information_schema.APPLICABLE_ROLES WHERE GRANTEE = 'ffs_admin'
  UNION ALL SELECT CONCAT('table ', TABLE_SCHEMA, '.', TABLE_NAME, ' ', PRIVILEGE_TYPE, IF(IS_GRANTABLE = 'YES', ' grantable', '')) FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\"
  UNION ALL SELECT CONCAT('column ', TABLE_SCHEMA, '.', TABLE_NAME, '.', COLUMN_NAME, ' ', PRIVILEGE_TYPE, IF(IS_GRANTABLE = 'YES', ' grantable', '')) FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\"
  UNION ALL SELECT CONCAT('routine ', Db, '.', Routine_name, ' ', Routine_type, ' ', Proc_priv) FROM mysql.procs_priv WHERE User = 'ffs_admin';" \
  | mysql_root 2>&1 | LC_ALL=C sort)
WANT_GRANTS=$(printf '%s\n' "global USAGE" \
  "column fxa.accounts.createdAt SELECT" "column fxa.accounts.disabledAt SELECT" "column fxa.accounts.email SELECT" \
  "column fxa.accounts.emailVerified SELECT" "column fxa.accounts.uid SELECT" \
  "routine ffs.confirm_email PROCEDURE Execute" "routine ffs.confirm_session PROCEDURE Execute" \
  "routine ffs.delete_account PROCEDURE Execute" "routine ffs.delete_unconfirmed PROCEDURE Execute" \
  "routine ffs.disable_account PROCEDURE Execute" "routine ffs.enable_account PROCEDURE Execute" \
  "routine ffs.prune PROCEDURE Execute" "routine ffs.remove_recovery_key PROCEDURE Execute" \
  "routine ffs.remove_totp PROCEDURE Execute" "routine ffs.sign_out_all PROCEDURE Execute" \
  "routine ffs.sign_out_device PROCEDURE Execute" "routine ffs.sign_out_session PROCEDURE Execute" \
  "routine ffs.signup_allowed FUNCTION Execute" "routine ffs.signup_refusal FUNCTION Execute" \
  "table ffs.account_security SELECT" "table ffs.database_sizes SELECT" "table ffs.devices SELECT" "table ffs.emails SELECT" \
  "table ffs.ffs_setup_migrations SELECT" "table ffs.ffs_setup_state SELECT" "table ffs.schema_levels SELECT" \
  "table ffs.security_events SELECT" "table ffs.sessions SELECT" "table ffs.settings SELECT" "table ffs.signup_allowlist SELECT" \
  | LC_ALL=C sort)
if [ "$GRANTS" = "$WANT_GRANTS" ]; then
  pass "ffs_admin_grants: exactly porelli's set with access managed elsewhere (SELECT only on ffs.settings / ffs.signup_allowlist, 5 columns of fxa.accounts, ffs's views and procedures; no global, schema, role, proxy or grant option)"
else
  fail "ffs_admin_grants: differ:
$(diff <(echo "$WANT_GRANTS") <(echo "$GRANTS") || true)"
fi
# The server's own account of it: every line a plain GRANT ... ON ... TO
# ffs_admin (a granted role has no ON), no WITH GRANT OPTION; 27 lines =
# USAGE, the 11 tables / views, one for the 5 columns, the 14 routines.
SHOWN=$(printf '%s\n' "SHOW GRANTS FOR 'ffs_admin'@'%';" | mysql_root 2>&1)
if [ "$(grep -c . <<< "$SHOWN")" = 27 ] && ! grep -q 'GRANT OPTION' <<< "$SHOWN" \
    && ! grep -vqE '^GRANT .+ ON .+ TO `ffs_admin`@`%`$' <<< "$SHOWN"; then
  pass "ffs_admin_grants: SHOW GRANTS: $(grep -c . <<< "$SHOWN") GRANT ... ON lines, no role, no WITH GRANT OPTION"
else
  fail "ffs_admin_grants: SHOW GRANTS: $(tr '\n' ';' <<< "$SHOWN")"
fi
ffs_admin_sql() {  # SQL on stdin, as ffs_admin (its password through the environment)
  MYSQL_PWD="$FXA_ADMIN_DB_PASSWORD" docker exec -i -e MYSQL_PWD "$DB_C" mysql -uffs_admin -h127.0.0.1 --protocol=tcp -N -B 2>&1
}
for stmt in "INSERT INTO ffs.signup_allowlist (entry) VALUES ('fxa-admin-test@$DOMAIN')" \
            "DELETE FROM ffs.signup_allowlist" \
            "UPDATE ffs.settings SET value = 'open' WHERE name = 'signups'" \
            "UPDATE ffs.settings SET value = '0' WHERE name = 'max_accounts'" \
            "CALL ffs.disable_account_by_email('$SYNC_USER')" \
            "CALL ffs.delete_account_by_email('$SYNC_USER')" \
            "SELECT authSalt FROM fxa.accounts LIMIT 1" \
            "SELECT count(*) FROM fxa.sessionTokens" \
            "UPDATE fxa.accounts SET disabledAt = 1" \
            "DROP TRIGGER fxa.ffs_signup_policy" \
            "CREATE USER 'portcullis_x'@'%'"; do
  OUT=$(ffs_admin_sql <<< "$stmt;" || true)
  if grep -Eqi 'ERROR (1142|1143|1044|1045|1227|1370|1419)|command denied|access denied' <<< "$OUT"; then
    pass "ffs_admin_grants: refused: ${stmt:0:60} ($(grep -o 'ERROR [0-9]*' <<< "$OUT" | head -1))"
  else
    fail "ffs_admin_grants: ffs_admin could: $stmt -> $OUT"
  fi
done
OUT=$(ffs_admin_sql <<< "SELECT count(*) FROM ffs.signup_allowlist; SELECT count(*) FROM fxa.accounts; SELECT ffs.signup_allowed('$SYNC_USER');" || true)
if grep -qi 'error' <<< "$OUT"; then
  fail "ffs_admin_grants: ffs_admin can't read what the admin UI shows: $OUT"
else
  pass "ffs_admin_grants: ffs_admin reads the allowlist and the accounts and may ask the sign-up policy"
fi

# admin_reaches_past_access (fixed): ffs_admin's incident procedures don't
# reach past the access group (porelli/firefox-sync 213576c, external mode;
# both SQL SECURITY DEFINER, kept for incidents). ffs.enable_account
# re-enables a listed member's account but refuses one whose email isn't on
# the allowlist (SQLSTATE 45000 "not on the access list managed
# elsewhere..."); ffs.delete_account leaves the allowlist row alone.
acct_state() {  # the second account: <rows>:<disabled 1/0, x = none>:<allowlist rows>
  printf '%s\n' "SELECT CONCAT((SELECT COUNT(*) FROM fxa.accounts WHERE uid = UNHEX('$DEL_UID')), ':',
    IFNULL((SELECT disabledAt IS NOT NULL FROM fxa.accounts WHERE uid = UNHEX('$DEL_UID')), 'x'), ':',
    (SELECT COUNT(*) FROM ffs.signup_allowlist WHERE entry = '$DEL_USER'));" | mysql_root 2>&1
}
if [[ "$DEL_UID" =~ ^[0-9a-f]{32}$ ]]; then
  S0=$(acct_state)
  ffs_admin_sql <<< "CALL ffs.disable_account(UNHEX('$DEL_UID'));" > /dev/null || true
  S1=$(acct_state)
  OUT=$(ffs_admin_sql <<< "CALL ffs.enable_account(UNHEX('$DEL_UID'));" || true)
  S2=$(acct_state)
  if [ "$S0:$S1:$S2" = "1:0:1:1:1:1:1:0:1" ] && ! grep -qi error <<< "$OUT"; then
    pass "admin_reaches_past_access (fixed): ffs_admin's ffs.enable_account re-enables a listed member's account ($S1 -> $S2)"
  else
    fail "admin_reaches_past_access: enable of a listed account: states $S0 -> $S1 -> $S2 (want 1:0:1 -> 1:1:1 -> 1:0:1): $OUT"
  fi
  printf "DELETE FROM ffs.signup_allowlist WHERE entry = '%s';\n" "$DEL_USER" | mysql_root > /dev/null
  ffs_admin_sql <<< "CALL ffs.disable_account(UNHEX('$DEL_UID'));" > /dev/null || true
  OUT=$(ffs_admin_sql <<< "CALL ffs.enable_account(UNHEX('$DEL_UID'));" || true)
  S3=$(acct_state)
  if [ "$S3" = "1:1:0" ] && grep -q '^ERROR 1644 (45000).*: not on the access list managed elsewhere' <<< "$OUT"; then
    pass "admin_reaches_past_access (fixed): ffs_admin's ffs.enable_account refuses an account off the allowlist (45000 'not on the access list managed elsewhere'); it stays disabled ($S3)"
  else
    fail "admin_reaches_past_access: enable of an unlisted account: state $S3 (want 1:1:0): $OUT"
  fi
  printf "INSERT IGNORE INTO ffs.signup_allowlist (entry) VALUES ('%s');\n" "$DEL_USER" | mysql_root > /dev/null
  OUT=$(ffs_admin_sql <<< "CALL ffs.delete_account(UNHEX('$DEL_UID'));" || true)
  S4=$(acct_state)
  if [ "$S4" = "0:x:1" ] && ! grep -qi error <<< "$OUT"; then
    pass "admin_reaches_past_access (fixed): ffs_admin's ffs.delete_account deletes the account and leaves its sign-up allowlist row ($S4)"
  else
    fail "admin_reaches_past_access: delete: state $S4 (want 0:x:1): $OUT"
  fi
else
  fail "admin_reaches_past_access: no second account to check delete / enable on"
fi

# Fail closed: without its admin group the admin UI doesn't start (an OIDC
# sign-in with no group would let any Portcullis account in).
# A name of its own, removed on every path (the EXIT trap for aborts): a
# probe that started instead would keep running with the instance's secrets.
CLOSED_C="portcullis-fxa-test-closed-$$"
FXA_TEST_CONTAINERS="$FXA_TEST_CONTAINERS $CLOSED_C"
umask 077
ENVF=$(probe_env 'ADMIN_ALLOWED_GROUPS' ADMIN_ALLOWED_GROUPS=)
docker run -d --name "$CLOSED_C" --network "$NET" --read-only --tmpfs /tmp:size=64m --cap-drop ALL \
  --security-opt no-new-privileges:true --env-file "$ENVF" "$ADMIN_IMAGE" > /dev/null 2>&1 || true
rm -f "$ENVF"
umask "$umask_was"
RC=$(timeout 60 docker wait "$CLOSED_C" 2>/dev/null) || RC=124
OUT=$(docker logs "$CLOSED_C" 2>&1 || true)
docker rm -f "$CLOSED_C" > /dev/null 2>&1 || true
if [ "$RC" != 0 ] && [ "$RC" != 124 ] && grep -q 'needs ADMIN_ALLOWED_USERS or ADMIN_ALLOWED_GROUPS' <<< "$OUT"; then
  pass "admin_group_fails_closed: an empty ADMIN_ALLOWED_GROUPS stops the admin UI (exit $RC: $(tail -1 <<< "$OUT"))"
else
  fail "admin_group_fails_closed: an empty ADMIN_ALLOWED_GROUPS: exit $RC: $(tail -3 <<< "$OUT" | tr '\n' ' ')"
fi

# The OIDC client secret on no container's argv and in no log of the admin
# UI, the probe or the stand-in (its value only compared here).
bad=""
for c in $(docker ps -aq); do
  case "$(docker inspect -f '{{.Name}} {{json .Path}} {{json .Args}} {{json .Config.Cmd}} {{json .Config.Entrypoint}}' "$c" 2>/dev/null)" in
    *"$FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET"*) bad="$bad $c(argv)" ;;
  esac
done
case "$(docker logs "$ADMIN_C" 2>&1; docker logs "$PROBE_C" 2>&1; docker logs "$OIDC_C" 2>&1)" in
  *"$FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET"*) bad="$bad logs" ;;
esac
[ -z "$bad" ] && pass "admin secret: the OIDC client secret on no container's argv, in no log" || fail "admin secret: found in:$bad"
docker rm -f "$OIDC_C" "$PROBE_C" "$CLOSED_C" > /dev/null 2>&1 || true
rm -rf "$PROBE_DIR"

# ══ Access (Task 13), live: fxa-access-sync's hook, run as the Hub runs it
# (docker exec of the manifest's command in the service, the HookInput on
# stdin), against the Hub's data file (write_appfiles_override). Sign-ups go
# the public way (tests/fxa_client.py through Traefik and fxa-gate to the
# sign-up gate), their codes through Task 14's mail catcher as the external
# SMTP server. ══
section "Firefox Sync + own accounts (access, live)"
ACCESS_C=portcullis-fxa-access-sync-1
read -r -a HOOK_CMD <<< "$(yq -r '.hooks[] | select(.name == "access-sync") | .command | join(" ")' "$MANIFEST")"
# No account cap here (external_used set 5): the access group decides.
unset MAX_ACCOUNTS
ACC_OVR=$(mktemp)
write_appfiles_override "$APP_ID" access "$(adoc)" "$ACC_OVR"
# One override (the Hub's): the data file's mount added to the test's.
tail -n +2 "$ACC_OVR" >> "$COMPOSE_OVERRIDE"
rm -f "$ACC_OVR"
compose_up "$APP_ID" > /dev/null 2>&1 || true
for _ in $(seq 1 60); do [ "$(docker inspect -f '{{.State.Running}}' "$ACCESS_C" 2>/dev/null)" = true ] && break; sleep 2; done
wait_healthy "$AUTH_C" 300 || fail "access: fxa-auth not healthy after the restart"
wait_healthy "$ADMIN_C" 300 || fail "access: ffs-admin not healthy after the restart"
for _ in $(seq 1 60); do [ "$(via_traefik "$API_HOST" /__heartbeat__)" = "200 " ] && break; sleep 5; done
[ "$(via_traefik "$API_HOST" /__heartbeat__)" = "200 " ] || fail "access: the API host doesn't answer through Traefik"
if docker exec "$ACCESS_C" cat /portcullis/access.json > /dev/null 2>&1 \
    && [ "$(docker inspect -f '{{.Config.User}} {{.HostConfig.GroupAdd}} {{.HostConfig.ReadonlyRootfs}}' "$ACCESS_C")" = "10001:10001 [10001] true" ]; then
  pass "access: fxa-access-sync runs as 10001 (group 10001, read-only) and reads the data file at /portcullis/access.json"
else
  fail "access: fxa-access-sync: $(docker inspect -f '{{.State.Status}} {{.Config.User}} {{.HostConfig.GroupAdd}}' "$ACCESS_C" 2>&1); the data file: $(docker exec "$ACCESS_C" ls -l /portcullis 2>&1 | tr '\n' ' ')"
fi
# Every hook output, for the secret / email checks (a file: the hook runs in
# command substitutions, whose variables don't come back).
HOOK_LOG=$(mktemp)
access_hook() {  # $1 trigger -> the hook's output, "rc=<n>" last
  local doc rc=0
  doc=$(jq -c --arg t "$1" '{trigger: $t} + .' "$APPFILES_DIR/$APP_ID/access/access.json" 2>/dev/null || printf '{"trigger":"%s"}' "$1")
  OUT=$(printf '%s' "$doc" | docker exec -i "$ACCESS_C" "${HOOK_CMD[@]}" 2>&1) || rc=$?
  printf '%s\n' "$OUT" >> "$HOOK_LOG"
  printf '%s\nrc=%s' "$OUT" "$rc"
}
hook_ok() {  # $1 label, $2 trigger
  local out
  out=$(access_hook "$2")
  if [ "${out##*$'\n'}" = rc=0 ]; then info "$1: $(head -1 <<< "$out")"; return 0; fi
  fail "$1: the hook ($2) failed: $(tr '\n' ' ' <<< "$out")"
  return 1
}
people() { write_appfile "$APP_ID" access "$(adoc "$@")"; }
allowlist() { echo "SELECT COALESCE(GROUP_CONCAT(entry ORDER BY entry SEPARATOR ','), '') FROM ffs.signup_allowlist;" | mysql_root 2>&1; }
acct() {  # $1 email -> <accounts>:<disabled 1/0, x = none>:<email verified, x = none>
  printf "SELECT CONCAT(COUNT(*), ':', IFNULL(MAX(disabledAt IS NOT NULL), 'x'), ':', IFNULL(MAX(emailVerified), 'x')) FROM fxa.accounts WHERE normalizedEmail = '%s';\n" "$1" | mysql_root 2>&1
}
accounts_state() { echo "SELECT COALESCE(GROUP_CONCAT(CONCAT(normalizedEmail, '=', disabledAt IS NOT NULL) ORDER BY normalizedEmail), '') FROM fxa.accounts;" | mysql_root 2>&1; }
access_state() { docker exec "$ACCESS_C" cat /state/applied.json 2>/dev/null || echo "<none>"; }
FXA_PASSWORD=$(openssl rand -hex 16)
[ -n "${GITHUB_ACTIONS:-}" ] && echo "::add-mask::$FXA_PASSWORD"
export FXA_PASSWORD
# The sync section's catcher (and its MAIL_DIR) still runs: the auth
# server's SMTP pool keeps talking to it.
ACC_SESS=$(mktemp -d)
chmod 0777 "$ACC_SESS"
[ "$(docker inspect -f '{{.State.Running}}' "$CATCHER" 2>/dev/null)" = true ] || CATCHER_MAIL_DIR="$MAIL_DIR" start_catcher "$EXT_USER" "$EXT_PW" 1 || true
MAXA=$(max_accounts_setting)
[ "$MAXA" = unlimited ] && pass "access: no account cap (ffs.settings max_accounts unlimited)" || fail "access: max_accounts '$MAXA'"
signup_diag() { printf 'catcher: %s; auth: %s' "$(docker logs "$CATCHER" 2>&1 | grep -v '^MESSAGE' | tail -4 | tr '\n' ' ')" \
  "$(redact "$(docker logs --tail 40 "$AUTH_C" 2>&1 | grep -iE 'mail|smtp|error' | tail -4 | tr '\n' ' ')")"; }
acc_client() {  # fxa_client.py through Traefik, as fxa_client(), keeping signup's session (FXA_STATE_DIR)
  docker run --rm --network portcullis-proxy --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges:true \
    --user 10001:10001 -v "$PWD/tests/fxa_client.py:/portcullis-test/fxa_client.py:ro" -v "$MAIL_DIR:/mail:ro" -v "$ACC_SESS:/sessions" \
    -v "$PROJECT_DIR/certs/ca-bundle.crt:/etc/ssl/certs/portcullis-ca-bundle.crt:ro" \
    -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/portcullis-ca-bundle.crt -e SSL_CERT_FILE=/etc/ssl/certs/portcullis-ca-bundle.crt \
    -e FXA_PASSWORD -e FXA_MAIL_DIR=/mail -e FXA_STATE_DIR=/sessions -e FXA_AUTH_URL="https://$API_HOST" \
    -e FXA_TOKEN_URL="https://$SYNC_HOST" -e FXA_NODE_URL="https://$SYNC_HOST" -e FXA_SYNC_URL= \
    --entrypoint python3 "$SYNC_IMAGE" -I -B /portcullis-test/fxa_client.py "$@" 2>&1 | tail -1
}
ALICE=alice@example.org BOB=bob@example.org CAROL=carol@example.org ALICE2=alice2@example.org SHARED=shared@example.org

# nonmember_refused: an empty list (the first run: every row of before goes,
# the accounts on it are disabled) -> alice's sign-up is refused, no account.
people
hook_ok "nonmember_refused" start || true
[ "$(allowlist)" = "" ] && pass "nonmember_refused: nobody listed: the sign-up allowlist is empty (the rows of before deleted)" \
  || fail "nonmember_refused: the allowlist is '$(allowlist)'"
[ "$(acct "$SYNC_USER")" = "1:1:1" ] && pass "nonmember_refused: the account on a deleted row ($SYNC_USER) is disabled (the first run, no state)" \
  || fail "nonmember_refused: $SYNC_USER is $(acct "$SYNC_USER") (want 1:1:1)"
OUT=$(acc_client signup "$ALICE" || true)
if [ "$(jget "$OUT" .step)" = create ] && [ "$(jget "$OUT" .http)" = 400 ] && [ "$(acct "$ALICE")" = "0:x:x" ]; then
  pass "nonmember_refused: $ALICE's sign-up through Traefik -> 400 (errno $(jget "$OUT" .errno)), no account"
else
  fail "nonmember_refused: $ALICE's sign-up: $(redact "$OUT"); account $(acct "$ALICE")"
fi

# join_allows: alice and bob listed -> sign-up with the mailed code, a
# verified account.
people alice="$ALICE" bob="$BOB"
hook_ok "join_allows" membership_change || true
[ "$(allowlist)" = "$ALICE,$BOB" ] && pass "join_allows: the allowlist is exactly $ALICE,$BOB" || fail "join_allows: the allowlist is '$(allowlist)'"
for who in "$ALICE" "$BOB"; do
  OUT=$(acc_client signup "$who" || true)
  if [ "$(jget "$OUT" .verified)" = true ] && [ "$(acct "$who")" = "1:0:1" ]; then
    pass "join_allows: $who signed up through Traefik, verified with the mailed code: an enabled, verified account"
  else
    fail "join_allows: $who: $(redact "$OUT"); account $(acct "$who"); $(signup_diag)"
  fi
done
OUT=$(acc_client session-status "$ALICE" || true)
[ "$(jget "$OUT" .http)" = 200 ] && pass "join_allows: $ALICE's session token answers 200 (/session/status)" \
  || fail "join_allows: $ALICE's session: $(redact "$OUT")"

# leave_disables: alice leaves -> her row goes, her account is disabled and
# signed out (her session token 401); the admin UI can't enable her again.
people bob="$BOB"
hook_ok "leave_disables" membership_change || true
[ "$(allowlist)" = "$BOB" ] && pass "leave_disables: $ALICE's row deleted (the allowlist is $BOB)" || fail "leave_disables: the allowlist is '$(allowlist)'"
[ "$(acct "$ALICE")" = "1:1:1" ] && pass "leave_disables: $ALICE's account has disabledAt set" || fail "leave_disables: $ALICE is $(acct "$ALICE")"
OUT=$(acc_client session-status "$ALICE" || true)
[ "$(jget "$OUT" .http)" = 401 ] && pass "leave_disables: $ALICE's session token answers 401 (errno $(jget "$OUT" .errno))" \
  || fail "leave_disables: $ALICE's session: $(redact "$OUT")"
ALICE_UID=$(echo "SELECT LOWER(HEX(uid)) FROM fxa.accounts WHERE normalizedEmail = '$ALICE';" | mysql_root 2>/dev/null || true)
OUT=$(ffs_admin_sql <<< "CALL ffs.enable_account(UNHEX('$ALICE_UID'));" || true)
grep -q '^ERROR 1644 (45000).*: not on the access list managed elsewhere' <<< "$OUT" && [ "$(acct "$ALICE")" = "1:1:1" ] \
  && pass "leave_disables: the admin UI's ffs.enable_account refuses the leaver (45000 'not on the access list managed elsewhere'); still disabled" \
  || fail "leave_disables: ffs_admin's enable of $ALICE: $OUT; account $(acct "$ALICE")"
# Every run (defence in depth): an account of a non-member enabled behind
# the sync's back is disabled again, a member's deleted row comes back, by a
# routine run with the file unchanged.
echo "UPDATE fxa.accounts SET disabledAt = NULL WHERE normalizedEmail = '$ALICE'; DELETE FROM ffs.signup_allowlist WHERE entry = '$BOB';" | mysql_root > /dev/null || true
hook_ok "nonmember_disabled_every_run" start || true
[ "$(acct "$ALICE")" = "1:1:1" ] && pass "nonmember_disabled_every_run: $ALICE, enabled behind the sync's back, is disabled again by a routine run" \
  || fail "nonmember_disabled_every_run: $ALICE is $(acct "$ALICE")"
[ "$(allowlist)" = "$BOB" ] && pass "member_row_restored: $BOB's deleted row is back after a routine run" \
  || fail "member_row_restored: the allowlist is '$(allowlist)'"

# rejoin_enables: alice listed again -> her row, disabledAt NULL.
people alice="$ALICE" bob="$BOB"
hook_ok "rejoin_enables" membership_change || true
[ "$(allowlist)" = "$ALICE,$BOB" ] && [ "$(acct "$ALICE")" = "1:0:1" ] \
  && pass "rejoin_enables: $ALICE listed again and her account enabled (disabledAt NULL)" \
  || fail "rejoin_enables: the allowlist '$(allowlist)', $ALICE $(acct "$ALICE")"

# admin_disable_survives: an admin disables bob, who stays listed: routine
# runs (either trigger, the file unchanged) leave him disabled.
echo "CALL ffs.disable_account_by_email('$BOB');" | mysql_root > /dev/null || fail "admin_disable_survives: the admin's disable of $BOB failed"
hook_ok "admin_disable_survives" membership_change || true
hook_ok "admin_disable_survives" start || true
[ "$(acct "$BOB")" = "1:1:1" ] && [ "$(acct "$ALICE")" = "1:0:1" ] && [ "$(allowlist)" = "$ALICE,$BOB" ] \
  && pass "admin_disable_survives: $BOB, disabled by an admin and still listed, stays disabled after two routine runs ($ALICE enabled, both listed)" \
  || fail "admin_disable_survives: $BOB $(acct "$BOB"), $ALICE $(acct "$ALICE"), the allowlist '$(allowlist)'"

# missing_file_keeps_list / unparsable_file_keeps_list: exit 1, nothing
# changed (the allowlist, the accounts, the state).
SNAP() { printf '%s|%s|%s' "$(allowlist)" "$(accounts_state)" "$(access_state)"; }
BEFORE=$(SNAP)
for bad in "<missing>" '{"version":1,"instance":"firefox-sync-fxa","people":{' "$(INST=other adoc alice="$ALICE")" \
           '{"version":2,"instance":"firefox-sync-fxa","people":{}}'; do
  case "$bad" in
    "<missing>") rm -f "$APPFILES_DIR/$APP_ID/access/access.json" 2>/dev/null || sudo -n rm -f "$APPFILES_DIR/$APP_ID/access/access.json"; label=missing_file_keeps_list ;;
    *) write_appfile "$APP_ID" access "$bad"; label="unparsable_file_keeps_list (${bad:0:40})" ;;
  esac
  OUT=$(access_hook membership_change)
  if [ "${OUT##*$'\n'}" = rc=1 ] && grep -q 'nothing changed' <<< "$OUT" && [ "$(SNAP)" = "$BEFORE" ]; then
    pass "$label: the hook exits 1 ('$(head -1 <<< "$OUT")'); the allowlist, the accounts and the state unchanged"
  else
    fail "$label: $(tr '\n' ' ' <<< "$OUT"); changed: $([ "$(SNAP)" = "$BEFORE" ] && echo no || echo yes)"
  fi
done

# email_change_and_duplicates: alice's email changes -> the old one off the
# list and its account disabled, the new one listed; two people with one
# email -> one row, kept while one of them remains.
people alice="$ALICE2" bob="$BOB"
hook_ok "email_change" membership_change || true
[ "$(allowlist)" = "$ALICE2,$BOB" ] && [ "$(acct "$ALICE")" = "1:1:1" ] \
  && pass "email_change_and_duplicates: $ALICE -> $ALICE2: the new email listed, the old one's row gone and its account disabled" \
  || fail "email_change_and_duplicates: the allowlist '$(allowlist)', $ALICE $(acct "$ALICE")"
people alice="$ALICE2" bob="$BOB" s1="$SHARED" s2="$SHARED"
hook_ok "duplicates" membership_change || true
[ "$(allowlist)" = "$ALICE2,$BOB,$SHARED" ] && pass "email_change_and_duplicates: two people with $SHARED: one row" \
  || fail "email_change_and_duplicates: two with $SHARED: '$(allowlist)'"
people alice="$ALICE2" bob="$BOB" s2="$SHARED"
hook_ok "duplicates" membership_change || true
[ "$(allowlist)" = "$ALICE2,$BOB,$SHARED" ] && pass "email_change_and_duplicates: one of them left: $SHARED kept" \
  || fail "email_change_and_duplicates: one of two left: '$(allowlist)'"
people alice="$ALICE2" bob="$BOB"
hook_ok "duplicates" membership_change || true
[ "$(allowlist)" = "$ALICE2,$BOB" ] && pass "email_change_and_duplicates: both left: $SHARED's row gone" \
  || fail "email_change_and_duplicates: both left: '$(allowlist)'"

# state_lost_still_disables: carol listed and signed up; then
# fxa-access-state is recreated empty and the file no longer has her: her
# row (in the database, not in the file) is deleted and her account
# disabled.
people alice="$ALICE2" bob="$BOB" carol="$CAROL"
hook_ok "state_lost_still_disables" membership_change || true
OUT=$(acc_client signup "$CAROL" || true)
[ "$(jget "$OUT" .verified)" = true ] && [ "$(acct "$CAROL")" = "1:0:1" ] || fail "state_lost_still_disables: $CAROL's sign-up: $(redact "$OUT"); $(signup_diag)"
STATE_VOL=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/state"}}{{.Name}}{{end}}{{end}}' "$ACCESS_C" 2>/dev/null || true)
# fxa-keys-owner (exited) mounts it too.
docker rm -f "$ACCESS_C" portcullis-fxa-keys-owner-1 > /dev/null 2>&1 || true
[ -n "$STATE_VOL" ] && docker volume rm "$STATE_VOL" > /dev/null 2>&1 || fail "state_lost_still_disables: couldn't remove the state volume '$STATE_VOL'"
people alice="$ALICE2" bob="$BOB"
compose_up "$APP_ID" > /dev/null 2>&1 || true
for _ in $(seq 1 60); do [ "$(docker inspect -f '{{.State.Running}}' "$ACCESS_C" 2>/dev/null)" = true ] && break; sleep 2; done
[ "$(access_state)" = "<none>" ] && pass "state_lost_still_disables: fxa-access-state recreated empty (no state)" \
  || fail "state_lost_still_disables: the state survived: $(access_state)"
hook_ok "state_lost_still_disables" start || true
if [ "$(allowlist)" = "$ALICE2,$BOB" ] && [ "$(acct "$CAROL")" = "1:1:1" ] \
    && [ "$(access_state | jq -c '[.listed, (.removed | index("carol@example.org") != null)]' 2>/dev/null)" = '[["alice2@example.org","bob@example.org"],true]' ]; then
  pass "state_lost_still_disables: without a state, $CAROL (in the database, not in the file) is deleted from the allowlist and disabled"
else
  fail "state_lost_still_disables: the allowlist '$(allowlist)', $CAROL $(acct "$CAROL"), the state $(access_state)"
fi
ST=$(docker exec "$ACCESS_C" stat -c '%a %u' /state/applied.json 2>&1 || true)
[ "$ST" = "600 10001" ] && pass "access: the state file is 0600, owned by 10001 (fxa-keys-owner handed it the new volume)" \
  || fail "access: the state file: $ST"

# ffs_access_grants: exactly what access-sync.sh needs (porelli's fxa-policy
# grants, its EXECUTE on ffs.delete_account_by_email taken away by
# fxa-db-users): no global, schema, role, proxy or grant option.
GRANTEE="'ffs_access'@'%'"
GRANTS=$(printf '%s\n' "SELECT CONCAT('global ', PRIVILEGE_TYPE) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\"
  UNION ALL SELECT CONCAT('global ', PRIV, IF(WITH_GRANT_OPTION = 'Y', ' grantable', '')) FROM mysql.global_grants WHERE USER = 'ffs_access'
  UNION ALL SELECT 'global grant option' FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\" AND IS_GRANTABLE = 'YES'
  UNION ALL SELECT CONCAT('schema ', TABLE_SCHEMA, ' ', PRIVILEGE_TYPE, IF(IS_GRANTABLE = 'YES', ' grantable', '')) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\"
  UNION ALL SELECT CONCAT('role granted ', FROM_USER, '@', FROM_HOST, IF(WITH_ADMIN_OPTION = 'Y', ' admin', '')) FROM mysql.role_edges WHERE TO_USER = 'ffs_access'
  UNION ALL SELECT CONCAT('role holder ', TO_USER, '@', TO_HOST) FROM mysql.role_edges WHERE FROM_USER = 'ffs_access'
  UNION ALL SELECT CONCAT('default role ', DEFAULT_ROLE_USER, '@', DEFAULT_ROLE_HOST) FROM mysql.default_roles WHERE USER = 'ffs_access'
  UNION ALL SELECT CONCAT('proxy ', Proxied_user, '@', Proxied_host) FROM mysql.proxies_priv WHERE User = 'ffs_access'
  UNION ALL SELECT CONCAT('applicable role ', ROLE_NAME) FROM information_schema.APPLICABLE_ROLES WHERE GRANTEE = 'ffs_access'
  UNION ALL SELECT CONCAT('table ', TABLE_SCHEMA, '.', TABLE_NAME, ' ', PRIVILEGE_TYPE, IF(IS_GRANTABLE = 'YES', ' grantable', '')) FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\"
  UNION ALL SELECT CONCAT('column ', TABLE_SCHEMA, '.', TABLE_NAME, '.', COLUMN_NAME, ' ', PRIVILEGE_TYPE, IF(IS_GRANTABLE = 'YES', ' grantable', '')) FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE = \"$GRANTEE\"
  UNION ALL SELECT CONCAT('routine ', Db, '.', Routine_name, ' ', Routine_type, ' ', Proc_priv) FROM mysql.procs_priv WHERE User = 'ffs_access';" \
  | mysql_root 2>&1 | LC_ALL=C sort)
WANT_GRANTS=$(printf '%s\n' "global USAGE" \
  "routine ffs.disable_account_by_email PROCEDURE Execute" "routine ffs.enable_account_by_email PROCEDURE Execute" \
  "table ffs.signup_allowlist DELETE" "table ffs.signup_allowlist INSERT" "table ffs.signup_allowlist SELECT" | LC_ALL=C sort)
if [ "$GRANTS" = "$WANT_GRANTS" ]; then
  pass "ffs_access_grants: exactly SELECT, INSERT, DELETE on ffs.signup_allowlist and EXECUTE on ffs.disable_account_by_email / enable_account_by_email (no delete_account_by_email; no global, schema, column, role, proxy or grant option)"
else
  fail "ffs_access_grants: differ:
$(diff <(echo "$WANT_GRANTS") <(echo "$GRANTS") || true)"
fi
SHOWN=$(printf '%s\n' "SHOW GRANTS FOR 'ffs_access'@'%';" | mysql_root 2>&1)
if [ "$(grep -c . <<< "$SHOWN")" = 4 ] && ! grep -q 'GRANT OPTION' <<< "$SHOWN" \
    && ! grep -vqE '^GRANT .+ ON .+ TO `ffs_access`@`%`$' <<< "$SHOWN"; then
  pass "ffs_access_grants: SHOW GRANTS: 4 GRANT ... ON lines (USAGE, the table, the two procedures), no role, no WITH GRANT OPTION"
else
  fail "ffs_access_grants: SHOW GRANTS: $(tr '\n' ';' <<< "$SHOWN")"
fi
ffs_access_sql() {  # SQL on stdin, as ffs_access (its password through the environment)
  MYSQL_PWD="$FXA_ACCESS_DB_PASSWORD" docker exec -i -e MYSQL_PWD "$DB_C" mysql -uffs_access -h127.0.0.1 --protocol=tcp -N -B 2>&1
}
for stmt in "UPDATE ffs.signup_allowlist SET entry = 'x@example.org'" \
            "TRUNCATE ffs.signup_allowlist" \
            "SELECT value FROM ffs.settings" \
            "UPDATE ffs.settings SET value = 'open' WHERE name = 'signups'" \
            "SELECT email FROM fxa.accounts LIMIT 1" \
            "UPDATE fxa.accounts SET disabledAt = NULL" \
            "CALL ffs.delete_account_by_email('$BOB')" \
            "CALL ffs.enable_account(UNHEX('00000000000000000000000000000000'))" \
            "CALL ffs.disable_account(UNHEX('00000000000000000000000000000000'))" \
            "SELECT ffs.signup_allowed('$BOB')" \
            "CREATE TEMPORARY TABLE ffs.portcullis_t (a int)" \
            "DROP TRIGGER fxa.ffs_signup_policy" \
            "CREATE USER 'portcullis_y'@'%'"; do
  OUT=$(ffs_access_sql <<< "$stmt;" || true)
  if grep -Eqi 'ERROR (1142|1143|1044|1045|1227|1370|1419)|command denied|access denied' <<< "$OUT"; then
    pass "ffs_access_grants: refused: ${stmt:0:60} ($(grep -o 'ERROR [0-9]*' <<< "$OUT" | head -1))"
  else
    fail "ffs_access_grants: ffs_access could: $stmt -> $OUT"
  fi
done

# Secrets: ffs_access's password on no container's argv, in no hook output
# and no log of the service; the hook's outputs name no email.
bad=""
for c in $(docker ps -aq); do
  case "$(docker inspect -f '{{.Name}} {{json .Path}} {{json .Args}} {{json .Config.Cmd}} {{json .Config.Entrypoint}}' "$c" 2>/dev/null)" in
    *"$FXA_ACCESS_DB_PASSWORD"*) bad="$bad $c(argv)" ;;
  esac
done
HOOK_OUTS=$(cat "$HOOK_LOG")
rm -f "$HOOK_LOG"
case "$HOOK_OUTS$(docker logs "$ACCESS_C" 2>&1)" in *"$FXA_ACCESS_DB_PASSWORD"*) bad="$bad hook-output/logs" ;; esac
[ -z "$bad" ] && [ -n "$HOOK_OUTS" ] && pass "access secret: ffs_access's password on no container's argv, in no hook output or log" \
  || fail "access secret: found in:$bad"
grep -q '@' <<< "$HOOK_OUTS" && fail "access: a hook output names an email: $(grep '@' <<< "$HOOK_OUTS" | head -1)" \
  || pass "access: the hook's outputs give counts, never an email ($(grep -c 'access-sync: applied' <<< "$HOOK_OUTS") applied runs)"
rm -rf "$MAIL_DIR" "$ACC_SESS" 2>/dev/null || sudo -n rm -rf "$MAIL_DIR" "$ACC_SESS" 2>/dev/null || true
unset FXA_PASSWORD

cleanup_live
# shellcheck disable=SC2086
unset $MAIL_VARS
FXA_DONE=1
