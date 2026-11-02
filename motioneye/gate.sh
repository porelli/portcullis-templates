#!/bin/sh
# Traefik-only gate in front of an app that has no login of its own (or
# whose own login is not the access control): the app stays on the
# instance's default network, this nginx is the only container on
# portcullis-proxy. It answers only Traefik's static address (forward-auth +
# group-gate run there); every other peer on portcullis-proxy gets 403.
# Websockets are passed through. Fails closed: a malformed address, upstream
# or port stops the container (Traefik then routes nothing).
#
# Environment: PORTCULLIS_TRAEFIK_IP (IPv4), GATE_UPSTREAM
# (http://<default-only alias>:<port>), GATE_LISTEN (port).
set -eu

ip="${PORTCULLIS_TRAEFIK_IP:-}"
case "$ip" in
  "" | *[!0-9.]* | .* | *. | *..*) echo "gate: PORTCULLIS_TRAEFIK_IP must be an IPv4 address (got '$ip')" >&2; exit 1 ;;
esac
[ "$(printf '%s' "$ip" | tr -cd . | wc -c)" -eq 3 ] || { echo "gate: PORTCULLIS_TRAEFIK_IP must be an IPv4 address" >&2; exit 1; }
case "${GATE_UPSTREAM:-}" in
  http://[a-z0-9]*:[0-9]*) ;;
  *) echo "gate: GATE_UPSTREAM must be http://<name>:<port>" >&2; exit 1 ;;
esac
case "${GATE_UPSTREAM#http://}" in
  *[!a-z0-9.:-]*) echo "gate: GATE_UPSTREAM has unexpected characters" >&2; exit 1 ;;
esac
case "${GATE_LISTEN:-}" in
  "" | *[!0-9]*) echo "gate: GATE_LISTEN must be a port number" >&2; exit 1 ;;
esac

cat > /etc/nginx/conf.d/default.conf <<EOF
map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }
server {
  listen ${GATE_LISTEN};
  server_tokens off;
  client_max_body_size 0;
  allow ${ip};
  deny all;
  # Resolve per request (Docker's DNS): the gate starts and answers 502
  # while the app is down or restarting, instead of failing to start.
  resolver 127.0.0.11 valid=10s ipv6=off;
  set \$upstream ${GATE_UPSTREAM};
  location / {
    proxy_pass \$upstream;
    proxy_http_version 1.1;
    proxy_set_header Host \$http_host;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
  }
}
EOF
exec nginx -g 'daemon off;'
