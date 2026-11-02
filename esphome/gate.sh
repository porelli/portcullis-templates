#!/bin/sh
# Traefik-only gate in front of an app that has no login of its own (or
# whose own login is not the access control): the app stays on the
# instance's default network, this nginx is the only container on
# portcullis-proxy. It answers only Traefik's static address (forward-auth +
# group-gate run there); every other peer on portcullis-proxy gets 403.
# There is no real_ip handling: the peer is the TCP peer, forwarded headers
# (X-Forwarded-For, X-Real-IP) never change it.
# Websockets are passed through. Fails closed: a malformed address, upstream
# or port stops the container (Traefik then routes nothing).
#
# Credentials of allowed requests never reach the app (its members can run
# code there: ESPHome compiles, Zigbee2MQTT extensions): Authorization
# (group-gate echoes the Keycloak bearer token), X-Forwarded-Access-Token,
# X-Auth-Request-Access-Token and the forward-auth session cookies
# (_oauth2_proxy*, __Host-portcullis_ext*, split and CSRF cookies included)
# are removed. A Cookie header that still names one after six passes is
# refused (400).
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

# One forward-auth cookie out of Cookie per pass.
strip='"~*^(?<pre>.*?)(?:^|;[ ]*)(?:_oauth2_proxy|__Host-portcullis_ext)[^=;]*=[^;]*(?<post>.*)$" "$pre$post";'

cat > /etc/nginx/conf.d/default.conf <<EOF
map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }
map \$http_cookie \$pc_c1 { ${strip} default \$http_cookie; }
map \$pc_c1 \$pc_c2 { ${strip} default \$pc_c1; }
map \$pc_c2 \$pc_c3 { ${strip} default \$pc_c2; }
map \$pc_c3 \$pc_c4 { ${strip} default \$pc_c3; }
map \$pc_c4 \$pc_c5 { ${strip} default \$pc_c4; }
map \$pc_c5 \$pc_c6 { ${strip} default \$pc_c5; }
map \$pc_c6 \$pc_cookie { "~^[ ;]*(?<rest>.*)\$" "\$rest"; }
map \$pc_c6 \$pc_cookie_left { "~*(?:^|;[ ]*)(?:_oauth2_proxy|__Host-portcullis_ext)" 1; default 0; }
server {
  listen ${GATE_LISTEN};
  server_tokens off;
  client_max_body_size 0;
  allow ${ip};
  deny all;
  if (\$pc_cookie_left) { return 400; }
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
    proxy_set_header Authorization "";
    proxy_set_header X-Forwarded-Access-Token "";
    proxy_set_header X-Auth-Request-Access-Token "";
    proxy_set_header Cookie \$pc_cookie;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
  }
}
EOF
exec nginx -g 'daemon off;'
