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
DBU="$(dirname "$COMPOSE")/db-users.sh"
if [ "$(grep -c 'GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON' "$DBU")" = 1 ] \
    && [ "$(grep -o 'GRANT [A-Z ,]* ON' "$DBU" | sort -u)" = "GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON" ] \
    && grep -q '^  user fxa_auth "$FXA_AUTH_DB_PASSWORD" fxa fxa_oauth pushbox$' "$DBU" \
    && grep -q '^  user fxa_profile "$FXA_PROFILE_DB_PASSWORD" fxa_profile$' "$DBU" \
    && ! grep -Eq 'GRANT OPTION TO|WITH GRANT|ffs' <(grep -v '^#' "$DBU"); then
  pass "db-users.sh: fxa_auth (fxa, fxa_oauth, pushbox) and fxa_profile (fxa_profile), DML + EXECUTE only"
else
  fail "db-users.sh: grants changed"
fi

# volumes
VOLS=$(yq -r '.volumes | keys | .[]' "$COMPOSE" | LC_ALL=C sort | tr '\n' ' ')
[ "$VOLS" = "firefox-sync-fxa-db-data fxa-access-state fxa-db-data fxa-keys fxa-profile-images " ] \
  && pass "volumes: exactly $VOLS" || fail "volumes: got '$VOLS'"
[ "$(yq -r '.services["fxa-redis"].volumes // [] | length' "$COMPOSE")" = 0 ] \
  && pass "volumes: fxa-redis has none" || fail "volumes: fxa-redis mounts a volume"

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

if [ "${STATIC_ONLY:-}" = 1 ]; then
  exit 0
fi
