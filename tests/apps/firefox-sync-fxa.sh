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
CATCHER_JS='
const net = require("net"), tls = require("tls"), fs = require("fs");
const U = process.env.CATCHER_USER || "", P = process.env.CATCHER_PASS || "";
const TLS = process.env.CATCHER_TLS === "1";
const ctx = TLS ? tls.createSecureContext({key: fs.readFileSync("/tls/key.pem"), cert: fs.readFileSync("/tls/cert.pem")}) : null;
fs.mkdirSync("/tmp/mail", {recursive: true});
let n = 0;
const seen = line => P && (line.includes(P) || line.split(/[ :]/).some(t => { try { return Buffer.from(t, "base64").toString("latin1").includes(P); } catch (e) { return false; } }));
function session(c, secure) {
  let buf = "", data = false, from = "", rcpt = [], authed = false, step = null, user = "";
  const w = s => c.write(s + "\r\n");
  const check = (u, p) => { authed = u === U && p === P; console.log("AUTH " + (authed ? "ok" : "refused") + " user=" + u + (secure ? " tls" : " plain")); w(authed ? "235 2.7.0 ok" : "535 5.7.8 refused"); };
  const plain = b => { const p = Buffer.from(b, "base64").toString().split("\0"); check(p[1] || "", p[2] || ""); };
  c.on("error", () => {});
  c.on("data", function onData(d) {
    buf += d.toString("latin1");
    for (;;) {
      if (data) {
        const i = buf.indexOf("\r\n.\r\n");
        if (i < 0) return;
        n++;
        fs.writeFileSync("/tmp/mail/" + n + ".eml", "MAIL FROM " + from + "\nRCPT " + rcpt.join(",") + "\nAUTH " + (authed ? "ok" : "none") + "\nTLS " + (secure ? "yes" : "no") + "\n\n" + buf.slice(0, i));
        console.log("MESSAGE " + n + " from=" + from + " rcpt=" + rcpt.join(",") + (secure ? " tls" : " plain"));
        buf = buf.slice(i + 5); data = false; w("250 2.0.0 queued");
        continue;
      }
      const i = buf.indexOf("\r\n");
      if (i < 0) return;
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (seen(line)) console.log("PASSWORD SEEN" + (secure ? " tls" : " plain"));
      if (step === "plain") { step = null; plain(line); continue; }
      if (step === "user") { user = Buffer.from(line, "base64").toString(); step = "pass"; w("334 UGFzc3dvcmQ6"); continue; }
      if (step === "pass") { step = null; check(user, Buffer.from(line, "base64").toString()); continue; }
      const a = line.split(" "), cmd = a[0].toUpperCase(), m = (a[1] || "").toUpperCase();
      if (cmd === "AUTH") console.log("AUTH command " + m + (secure ? " tls" : " plain"));
      if (cmd === "EHLO") { console.log("EHLO" + (secure ? " tls" : " plain")); c.write("250-catcher\r\n" + (TLS && !secure ? "250-STARTTLS\r\n" : "") + "250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"); }
      else if (cmd === "HELO") w("250 catcher");
      else if (cmd === "STARTTLS" && TLS && !secure) {
        w("220 2.0.0 ready");
        c.removeListener("data", onData);
        console.log("STARTTLS");
        session(new tls.TLSSocket(c, {isServer: true, secureContext: ctx}), true);
        return;
      }
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
}
net.createServer(c => { console.log("CONNECT"); c.write("220 catcher ESMTP\r\n"); session(c, false); })
  .listen(587, "0.0.0.0", () => console.log("catcher listening on 587" + (TLS ? " (STARTTLS)" : " (no STARTTLS)")));
'
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
# and round-trips a record. Until Task 12's gate the helper reaches fxa-auth
# and the Sync server over the instance's network, from a container of the
# pinned syncstorage-rs image (PyFxA, requests and hawkauthlib ship in it);
# the base URLs are its parameters. ══
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
  env PGPASSWORD="$FIREFOX_SYNC_FXA_DB_PASSWORD" FIREFOX_SYNC_APP_DB_PASSWORD="$FIREFOX_SYNC_FXA_APP_DB_PASSWORD" \
    FIREFOX_SYNC_ADMIN_DB_PASSWORD="$FIREFOX_SYNC_FXA_ADMIN_DB_PASSWORD" FIREFOX_SYNC_NODE_URL="https://$SYNC_HOST" "$@" \
    docker run --rm --network "$NET" --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges:true --user 70:70 \
      -e PGHOST=firefox-sync-fxa-db -e PGUSER=firefoxsync -e PGDATABASE=firefoxsync -e PGPASSWORD \
      -e FIREFOX_SYNC_APP_DB_PASSWORD -e FIREFOX_SYNC_ADMIN_DB_PASSWORD -e FIREFOX_SYNC_NODE_URL \
      -v "$sql/revoke.sql:/etc/portcullis/revoke.sql:ro" -v "$sql/guard.sql:/etc/portcullis/guard.sql:ro" \
      -v "$sql/admin-db.sql:/etc/portcullis/admin-db.sql:ro" \
      --entrypoint /bin/sh "$POSTGRES_IMAGE" -c "$cmd" 2>&1
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
fxa_client() {  # the helper on the instance's network; the password by env
  docker run --rm --network "$NET" --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges:true \
    --user 10001:10001 -v "$PWD/tests/fxa_client.py:/portcullis-test/fxa_client.py:ro" -v "$MAIL_DIR:/mail:ro" \
    -e FXA_PASSWORD -e FXA_MAIL_DIR=/mail -e FXA_AUTH_URL=http://fxa-auth:9000 \
    -e FXA_TOKEN_URL=http://firefox-sync-fxa-internal:8000 -e FXA_NODE_URL="https://$SYNC_HOST" \
    -e FXA_SYNC_URL=http://firefox-sync-fxa-internal:8000 \
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
rm -rf "$MAIL_DIR"
unset FXA_PASSWORD

cleanup_live
# shellcheck disable=SC2086
unset $MAIL_VARS
FXA_DONE=1
