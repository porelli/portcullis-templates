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
fxa_exit() {
  local rc=$?
  [ "$FXA_DONE" = 1 ] || fail "aborted before the last check (exit status $rc)"
  report
}
trap fxa_exit EXIT
section "Firefox Sync + own accounts (static)"

APP_ID=firefox-sync-fxa
COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"

FXA_IMAGE=ghcr.io/porelli/firefox-sync:fxa-mono-v1.350.0@sha256:0ec0804fe9a021496faffd78d64ae90c014ee4fa1b0ed228451e84df30a77d73
ADMIN_IMAGE=ghcr.io/porelli/firefox-sync:admin-37a15d0a5ba2@sha256:fb1c3d96136d8367f131f99fefbd81d39f47c338902fb8de5530c778c7030dc5
SYNC_IMAGE=ghcr.io/porelli/firefox-sync:syncstorage-rs-postgres-0.25.1@sha256:e67e05fab539e94c81ce6991d01309c2996db1178dcad8c5cd7640eca48c7e95
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
db-users: fxa_auth (fxa, fxa_oauth, pushbox) and fxa_profile (fxa_profile) set"
  if [ "$SQL" = "$WANT_SQL" ]; then
    pass "db-users.sh M1/M3: exactly CREATE, ALTER, REVOKE and the DML + EXECUTE grants on fxa, fxa\\_oauth, pushbox (fxa_auth) and fxa\\_profile (fxa_profile)"
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
      && yq -r ".services[\"$svc\"].volumes[]" "$COMPOSE" | grep -qx "./certs/ca-bundle.crt:$CA_PATH:ro"; then
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
  yq -r "$s.security_opt // [] | .[]" "$COMPOSE" | grep -qx 'no-new-privileges:true' || bad="$bad $svc:no-new-privileges"
  [ "$(yq -r "$s.tmpfs // [] | length" "$COMPOSE")" -gt 0 ] && ! yq -r "$s.tmpfs[]" "$COMPOSE" | grep -qv ':size=' || bad="$bad $svc:tmpfs"
  [ "$(yq -r "$s.mem_limit // \"\"" "$COMPOSE")" != "" ] || bad="$bad $svc:mem_limit"
done
[ -z "$bad" ] && pass "hardening: every service" || fail "hardening:$bad"

# Upstream's config files, vendored unmodified from 7216405.
for f in oauth-clients.js content-server.js; do
  if head -n 2 "$(dirname "$COMPOSE")/fxa-config/$f" | grep -q '7216405'; then
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
max_accounts|Accounts|int|MAX_ACCOUNTS||restart"
if [ "$OPTS" = "$WANT_OPTS" ]; then
  pass "settings: the eight options (key, section, type, env, default, applies restart)"
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
  && [ "$(yq -r "$MC.volumes | join(\" \")" "$COMPOSE")" = "./templates/firefox-sync-fxa/mail-check.sh:/portcullis-bin/mail-check.sh:ro ./templates/firefox-sync-fxa/mail-select.sh:/portcullis-bin/mail-select.sh:ro" ] \
  && pass "fxa-mail-check: one-shot, no network, read-only, no capability, runs mail-check.sh (both scripts read-only)" \
  || fail "fxa-mail-check: $(yq -r "$MC" "$COMPOSE" -o json | tr -d '\n ')"
AUTH_CMD=$(yq -r '.services["fxa-auth"].command | join(" ")' "$COMPOSE")
case "$AUTH_CMD" in
  "sh -c . /portcullis-bin/mail-select.sh && node "*) pass "fxa-auth: its sh -c sources mail-select.sh first, every step after it" ;;
  *) fail "fxa-auth: command '$AUTH_CMD' doesn't start with '. /portcullis-bin/mail-select.sh &&'" ;;
esac
yq -r '.services["fxa-auth"].volumes[]' "$COMPOSE" | grep -qx './templates/firefox-sync-fxa/mail-select.sh:/portcullis-bin/mail-select.sh:ro' \
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
check_env ffs-admin SMTP_HOST ""

# mail-select.sh, sourced by the host's sh (dash in CI; MAIL_SELECT_SH picks
# another) the way both services source it; mail-check.sh with its path
# pointed at the checkout's mail-select.sh.
MS_SH="${MAIL_SELECT_SH:-sh}"
MS_TMP=$(mktemp -d)
sed "s#/portcullis-bin/mail-select.sh#$MAIL_SELECT#" "$MAIL_CHECK" > "$MS_TMP/mail-check.sh"
# $1.. VAR=value; prints the exit status, stderr, and the SMTP_* (password
# as set/unset) and whether the input passwords survived.
ms_run() {
  env -i PATH="$PATH" "$@" "$MS_SH" -c '
    . "$1" 2> "$2/err"; rc=$?
    printf "rc=%s\nerr=%s\n" "$rc" "$(cat "$2/err")"
    for v in SMTP_HOST SMTP_PORT SMTP_SECURE SMTP_USER SMTP_SENDER; do eval "printf \"%s=%s\n\" $v \"\${$v-<unset>}\""; done
    printf "SMTP_PASS=%s\n" "${SMTP_PASS:+set}"
    printf "inputs=%s%s\n" "${PORTCULLIS_MAIL_SENDER_PASSWORD+provider-pw}" "${EXT_SMTP_PASSWORD+ext-pw}"' _ "$MAIL_SELECT" "$MS_TMP"
}
ms_case() {  # $1 name, $2 want (lines), rest: env
  local name=$1 want=$2 got
  shift 2
  got=$(ms_run "$@")
  if [ "$got" = "$want" ]; then pass "mail-select.sh: $name"; else fail "mail-select.sh: $name:
$(diff <(echo "$want") <(echo "$got") || true)"; fi
}
REFUSED() { printf 'rc=1\nerr=%s\nSMTP_HOST=<unset>\nSMTP_PORT=<unset>\nSMTP_SECURE=<unset>\nSMTP_USER=<unset>\nSMTP_SENDER=<unset>\nSMTP_PASS=\ninputs=%s' "$1" "${2:-}"; }
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
inputs=' "${PROV[@]}"
ms_case "provider: mode provider ignores EXT_SMTP_*" \
  'rc=0
err=
SMTP_HOST=mail.example.org
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=portcullis-app-x@example.org
SMTP_SENDER="Firefox accounts" <portcullis-app-x@example.org>
SMTP_PASS=set
inputs=' "${PROV[@]}" EXT_SMTP_HOST=smtp.example.net EXT_SMTP_PASSWORD=pw-ext
ms_case "external_used: starttls = SMTP_SECURE=false on 587, the sender as a name-addr" \
  'rc=0
err=
SMTP_HOST=smtp.example.net
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=fxa
SMTP_SENDER=Firefox accounts <accounts@example.net>
SMTP_PASS=set
inputs=' "${EXT[@]}" "${PROV[@]}"
ms_case "external: tls = SMTP_SECURE=true" \
  'rc=0
err=
SMTP_HOST=smtp.example.net
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=fxa
SMTP_SENDER=Firefox accounts <accounts@example.net>
SMTP_PASS=set
inputs=' "${EXT[@]}" EXT_SMTP_SECURITY=tls EXT_SMTP_PORT=465
ms_case "external: no user and no password (a relay that takes mail as is)" \
  'rc=0
err=
SMTP_HOST=smtp.example.net
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_SENDER=Firefox accounts <accounts@example.net>
SMTP_PASS=
inputs=' "${EXT[@]}" EXT_SMTP_USER= EXT_SMTP_PASSWORD=
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
ms_case "unknown mail source" "$(REFUSED "portcullis: no mail: the mail source must be provider or external")" MAIL_SOURCE=both
# mail-check.sh: exit 1 with the exact line; on success one line, no secret.
if out=$(env -i PATH="$PATH" "$MS_SH" "$MS_TMP/mail-check.sh" 2>&1); then
  fail "mail-check.sh: exit 0 without a mail server"
else
  [ "$out" = "$NO_MAIL_LINE" ] && pass "mail-check.sh: exit 1, logs exactly '$NO_MAIL_LINE'" || fail "mail-check.sh: logged '$out'"
fi
if out=$(env -i PATH="$PATH" "${EXT[@]}" "$MS_SH" "$MS_TMP/mail-check.sh" 2>&1); then
  [ "$out" = "portcullis: mail: the external SMTP server (smtp.example.net:587, STARTTLS)" ] \
    && pass "mail-check.sh: external, exit 0: '$out' (no user, no password)" || fail "mail-check.sh: external printed '$out'"
else
  fail "mail-check.sh: external exited non-zero: $out"
fi
if out=$(env -i PATH="$PATH" "${PROV[@]}" "$MS_SH" "$MS_TMP/mail-check.sh" 2>&1); then
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
  docker rm -f "$CATCHER" > /dev/null 2>&1 || true
  compose_down "$APP_ID" > /dev/null 2>&1 || true
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
# instance's network; no STARTTLS, AUTH PLAIN/LOGIN checked against
# CATCHER_USER / CATCHER_PASS (environment), every message saved in its /tmp.
CATCHER_JS='
const net = require("net"), fs = require("fs");
const U = process.env.CATCHER_USER || "", P = process.env.CATCHER_PASS || "";
fs.mkdirSync("/tmp/mail", {recursive: true});
let n = 0;
net.createServer(c => {
  let buf = "", data = false, from = "", rcpt = [], authed = false, step = null, user = "";
  const w = s => c.write(s + "\r\n");
  const check = (u, p) => { authed = u === U && p === P; console.log("AUTH " + (authed ? "ok" : "refused") + " user=" + u); w(authed ? "235 2.7.0 ok" : "535 5.7.8 refused"); };
  const plain = b => { const p = Buffer.from(b, "base64").toString().split("\0"); check(p[1] || "", p[2] || ""); };
  w("220 catcher ESMTP");
  c.on("error", () => {});
  c.on("data", d => {
    buf += d.toString("latin1");
    for (;;) {
      if (data) {
        const i = buf.indexOf("\r\n.\r\n");
        if (i < 0) return;
        n++;
        fs.writeFileSync("/tmp/mail/" + n + ".eml", "MAIL FROM " + from + "\nRCPT " + rcpt.join(",") + "\nAUTH " + (authed ? "ok" : "none") + "\n\n" + buf.slice(0, i));
        console.log("MESSAGE " + n + " from=" + from + " rcpt=" + rcpt.join(","));
        buf = buf.slice(i + 5); data = false; w("250 2.0.0 queued");
        continue;
      }
      const i = buf.indexOf("\r\n");
      if (i < 0) return;
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (step === "plain") { step = null; plain(line); continue; }
      if (step === "user") { user = Buffer.from(line, "base64").toString(); step = "pass"; w("334 UGFzc3dvcmQ6"); continue; }
      if (step === "pass") { step = null; check(user, Buffer.from(line, "base64").toString()); continue; }
      const a = line.split(" "), cmd = a[0].toUpperCase(), m = (a[1] || "").toUpperCase();
      if (cmd === "EHLO") c.write("250-catcher\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n");
      else if (cmd === "HELO") w("250 catcher");
      else if (cmd === "AUTH" && m === "PLAIN") { if (a[2]) plain(a[2]); else { step = "plain"; w("334 "); } }
      else if (cmd === "AUTH" && m === "LOGIN") { if (a[2]) { user = Buffer.from(a[2], "base64").toString(); step = "pass"; w("334 UGFzc3dvcmQ6"); } else { step = "user"; w("334 VXNlcm5hbWU6"); } }
      else if (cmd === "MAIL") { if (U && !authed) w("530 5.7.0 authentication required"); else { from = line.slice(10).trim(); rcpt = []; w("250 ok"); } }
      else if (cmd === "RCPT") { rcpt.push(line.slice(8).trim()); w("250 ok"); }
      else if (cmd === "DATA") { data = true; w("354 go ahead"); }
      else if (cmd === "RSET") { from = ""; rcpt = []; w("250 ok"); }
      else if (cmd === "NOOP") w("250 ok");
      else if (cmd === "QUIT") { w("221 bye"); c.end(); }
      else w("502 5.5.2 not implemented");
    }
  });
}).listen(587, "0.0.0.0", () => console.log("catcher listening on 587"));
'
start_catcher() {  # $1 user, $2 password (exported as CATCHER_USER / CATCHER_PASS)
  docker rm -f "$CATCHER" > /dev/null 2>&1 || true
  CATCHER_USER=$1 CATCHER_PASS=$2 docker run -d --name "$CATCHER" --network "$NET" --network-alias fxa-test-smtp \
    --user 10001:10001 --read-only --tmpfs /tmp:size=8m --cap-drop ALL --security-opt no-new-privileges:true \
    -e CATCHER_USER -e CATCHER_PASS --entrypoint node "$FXA_IMAGE" -e "$CATCHER_JS" > /dev/null
  for _ in $(seq 1 30); do docker logs "$CATCHER" 2>&1 | grep -q 'catcher listening' && return 0; sleep 1; done
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
  if printf '%s\n' "$msg" | grep -q '^AUTH ok$' && printf '%s\n' "$msg" | grep -q "^MAIL FROM <$3>" \
      && printf '%s\n' "$msg" | grep -qi "^From: .*<$4>" \
      && printf '%s\n' "$msg" | grep -qiE '^X-Verify-(Short-)?Code: *[0-9A-Za-z]+'; then
    pass "$1: the sign-up code for $2 arrived (authenticated, MAIL FROM $3, From <$4>, $(printf '%s\n' "$msg" | grep -iE '^X-Verify-(Short-)?Code:' | head -1 | cut -d: -f1) header)"
  else
    fail "$1: the message for $2 lacks the AUTH, MAIL FROM <$3>, From <$4> or the code header: $(redact "$(printf '%s\n' "$msg" | grep -iE '^(AUTH|MAIL FROM|RCPT|From:|X-Verify)' | tr '\n' ' ')")"
  fi
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

# ── provider_used: the Hub's PORTCULLIS_MAIL_SENDER_* (the catcher stands in
# for the provider's submission listener).
PROVIDER_USER="portcullis-app-$APP_ID@$DOMAIN"
start_catcher "$PROVIDER_USER" "$PROVIDER_PW" || true
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
  if printf '%s\n' "$E" | grep -q '^PORTCULLIS_MAIL_SENDER_PASSWORD='; then
    fail "provider_used: the input PORTCULLIS_MAIL_SENDER_PASSWORD is still in the auth server's environment"
  else
    pass "provider_used: the password once in the auth server's environment (SMTP_PASS; the input unset)"
  fi
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
start_catcher "$EXT_USER" "$EXT_PW" || true
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
      && ! printf '%s\n' "$E" | grep -q '^EXT_SMTP_PASSWORD='; then
    pass "external_used: starttls: SMTP_SECURE=false, SMTP_PORT=587, SMTP_HOST the external server, SMTP_SENDER Firefox accounts <fxa-accounts@example.net>, the password once"
  else
    fail "external_used: SMTP_HOST=$(envval "$E" SMTP_HOST) SMTP_SECURE=$(envval "$E" SMTP_SECURE) SMTP_PORT=$(envval "$E" SMTP_PORT) SMTP_SENDER=$(envval "$E" SMTP_SENDER) SMTP_USER=$(envval "$E" SMTP_USER) SMTP_PASS $([ "$(envval "$E" SMTP_PASS)" = "$EXT_PW" ] && echo matches || echo differs)"
  fi
  code_arrives "external_used" "fxa-external-test@$DOMAIN" "fxa-accounts@example.net" "fxa-accounts@example.net"
  secret_not_in_argv external "$EXT_PW"
else
  fail "external: fxa-auth not healthy after 600 s: $(redact "$(docker logs --tail 30 "$AUTH_C" 2>&1)")"
fi
MAXA=$(max_accounts_setting)
[ "$MAXA" = 5 ] && pass "no_cap_default: ffs.settings max_accounts 5 with max_accounts 5" \
  || fail "no_cap_default: ffs.settings max_accounts '$MAXA' with the setting 5"

cleanup_live
# shellcheck disable=SC2086
unset $MAIL_VARS
FXA_DONE=1
