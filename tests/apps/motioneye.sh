#!/usr/bin/env bash
# Test: motionEye (forward-auth + group-gate; Traefik-only gate; motionEye's
# own admin/user login kept, with generated passwords set by motioneye-init).
# Hardware: none needed. Not covered in CI: real cameras (network URLs or
# /dev/video* devices) and the "Storage folder" host path (a Hub override).
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="motioneye"
section "motionEye"

APP_ID=motioneye
COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }

# ── Static ──────────────────────────────────────────────────
if grep -q 'portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi
nets() {
  if [ "$(yq -r ".services[\"$1\"].networks | tag" "$COMPOSE")" = '!!map' ]; then
    yq -r ".services[\"$1\"].networks | keys | join(\",\")" "$COMPOSE"
  else
    yq -r "[.services[\"$1\"].networks[]] | join(\",\")" "$COMPOSE"
  fi
}
[ "$(nets motioneye)" = default ] && pass "motionEye on the default network only" || fail "motionEye networks: $(nets motioneye)"
case "$(nets motioneye-gate)" in *portcullis-proxy*) pass "only the gate joins portcullis-proxy" ;; *) fail "gate not on portcullis-proxy" ;; esac

# ── Runtime ─────────────────────────────────────────────────
compose_up "$APP_ID"
ME=portcullis-motioneye-1
GATE=portcullis-motioneye-gate-1

init_state=""
for _ in $(seq 1 60); do
  init_state=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' portcullis-motioneye-init-1 2>/dev/null || true)
  case "$init_state" in exited*) break ;; esac
  sleep 2
done
[ "$init_state" = "exited 0" ] && pass "motioneye-init completed" || { fail "motioneye-init: $init_state"; docker logs portcullis-motioneye-init-1 2>&1 | tail -20 || true; }

health=""
for _ in $(seq 1 60); do
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$ME" 2>/dev/null || true)
  [ "$health" = healthy ] && break
  sleep 5
done
[ "$health" = healthy ] && pass "motionEye healthy (passwords set, UI answers)" || { fail "motionEye not healthy: $health"; docker logs --tail 40 "$ME" 2>&1 || true; }

if docker exec "$ME" sh -c 'grep -Eq "^# @admin_password [$]argon2" /etc/motioneye/motion.conf && grep -Eq "^# @normal_password [$]argon2" /etc/motioneye/motion.conf'; then
  pass "admin and user passwords stored as argon2 hashes"
else
  fail "motion.conf lacks hashed admin/user passwords"
fi
if docker exec -e MOTIONEYE_ADMIN_PASSWORD -e MOTIONEYE_USER_PASSWORD "$ME" sh -c \
    'printf "%s\n%s\n" "$MOTIONEYE_ADMIN_PASSWORD" "$MOTIONEYE_USER_PASSWORD" | grep -qF -f - /etc/motioneye/motion.conf'; then
  fail "a plaintext password is in motion.conf"
else
  pass "no plaintext password in motion.conf"
fi

# motionEye's login (POST /login/), straight to the container from the CI
# host: the well-known empty password is refused, the generated ones work.
ME_IP=$(app_container_ip "$APP_ID" motioneye)
login() {  # <user> <password> -> HTTP code (body on stdin, never argv)
  printf '{"username":"%s","password":"%s"}' "$1" "$2" | \
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Content-Type: application/json' --data-binary @- "http://${ME_IP}:8765/login/" || true
}
[ "$(login admin '')" = 401 ] && pass "admin with an empty password refused" || fail "admin with an empty password not refused"
[ "$(login user '')" = 401 ] && pass "user with an empty password refused" || fail "user with an empty password not refused"
[ "$(login admin "$MOTIONEYE_ADMIN_PASSWORD")" = 200 ] && pass "admin signs in with the generated password" || fail "admin login with the generated password failed"
[ "$(login user "$MOTIONEYE_USER_PASSWORD")" = 200 ] && pass "user signs in with the generated password" || fail "user login with the generated password failed"
[ "$(login admin "$MOTIONEYE_USER_PASSWORD")" = 401 ] && pass "the user password is not the admin password" || fail "admin accepted the user password"

# A second start keeps the stored passwords (an admin's change survives).
before=$(docker exec "$ME" grep -E '^# @admin_password ' /etc/motioneye/motion.conf | sha256sum)
compose_up "$APP_ID" >/dev/null
for _ in $(seq 1 30); do
  st=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' portcullis-motioneye-init-1 2>/dev/null || true)
  case "$st" in exited*) break ;; esac
  sleep 2
done
docker logs portcullis-motioneye-init-1 2>&1 | tail -1 | grep -q 'both already set' \
  && pass "motioneye-init keeps passwords already set" || fail "motioneye-init changed passwords on a second start"
after=$(docker exec "$ME" grep -E '^# @admin_password ' /etc/motioneye/motion.conf | sha256sum)
[ "$before" = "$after" ] && pass "admin password hash unchanged" || fail "admin password hash changed"

# The gate answers Traefik only.
GATE_IP=$(docker inspect "$GATE" --format '{{with index .NetworkSettings.Networks "portcullis-proxy"}}{{.IPAddress}}{{end}}')
for _ in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${GATE_IP}:8765/" 2>/dev/null || true)
  [ "$code" = 000 ] && sleep 2 || break
done
for path in / /login/ /config/list/; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${GATE_IP}:8765${path}" 2>/dev/null || true)
  [ "$code" = 403 ] && pass "gate refuses a non-Traefik peer on $path (403)" || fail "gate answered $path to a non-Traefik peer: HTTP $code"
done
on_proxy=$(docker network inspect portcullis-proxy --format '{{range .Containers}}{{.Name}} {{end}}' | tr ' ' '\n' \
  | grep -E '^portcullis-motioneye' | sort | tr '\n' ' ')
[ "$on_proxy" = "$GATE " ] && pass "only $GATE is on portcullis-proxy" || fail "on portcullis-proxy: $on_proxy"

HOST="cameras.$DOMAIN"
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /)
  case "${out%% *}" in 000|404|502) sleep 1 ;; *) break ;; esac
done
assert_gated_path "$HOST" "/"
assert_gated_path "$HOST" "/login/"

compose_down "$APP_ID"
