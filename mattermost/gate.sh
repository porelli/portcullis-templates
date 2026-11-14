#!/bin/sh
# Traefik-only gate in front of an app that has no login of its own (or
# whose own login is not the access control): the app stays on the
# instance's default network, this nginx is the only container on
# portcullis-proxy. It answers only PORTCULLIS_TRAEFIK_SOURCE, Traefik's
# address range (forward-auth + group-gate run there; Traefik's /32 on
# Docker/Podman, the pod CIDR on Kubernetes, where a NetworkPolicy admits
# only Traefik to the routed port); every other peer gets 403.
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
# Environment: PORTCULLIS_TRAEFIK_SOURCE (an IPv4 CIDR a.b.c.d/n, host bits
# zero, nothing else), GATE_UPSTREAM
# (http://<default-only alias>:<port>), GATE_LISTEN (port).
set -eu

# An IPv4 CIDR a.b.c.d/n: four decimal octets without leading zeros, a
# prefix length 0-32, no host bits set (Python's
# ipaddress.IPv4Network(strict=True) on that form); anything else fails.
cidr_ok() {
  case "$1" in *[!0-9./]* | */*/* | .* | *./* | *..*) return 1 ;; */*) ;; *) return 1 ;; esac
  set -- "${1%/*}" "${1#*/}"
  case "$2" in [0-9] | [12][0-9] | 3[0-2]) ;; *) return 1 ;; esac
  _cn=$2 _cv=0 _ck=0 _cifs=$IFS
  IFS=.
  for _co in $1; do
    case "$_co" in [0-9] | [1-9][0-9] | 1[0-9][0-9] | 2[0-4][0-9] | 25[0-5]) ;; *) IFS=$_cifs; return 1 ;; esac
    _cv=$((_cv * 256 + _co)) _ck=$((_ck + 1))
  done
  IFS=$_cifs
  [ "$_ck" -eq 4 ] && [ $((_cv % (1 << (32 - _cn)))) -eq 0 ]
}

src="${PORTCULLIS_TRAEFIK_SOURCE:-}"
cidr_ok "$src" || { echo "gate: PORTCULLIS_TRAEFIK_SOURCE must be an IPv4 CIDR a.b.c.d/n (got '$src')" >&2; exit 1; }
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
strip='"~*^(?<pre>.*?)(?:^|;)[ \t]*(?:_oauth2_proxy|__Host-portcullis_ext)[^=;]*=[^;]*(?<post>.*)$" "$pre$post";'

cat > /etc/nginx/conf.d/default.conf <<EOF
map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }
map \$http_cookie \$pc_c1 { ${strip} default \$http_cookie; }
map \$pc_c1 \$pc_c2 { ${strip} default \$pc_c1; }
map \$pc_c2 \$pc_c3 { ${strip} default \$pc_c2; }
map \$pc_c3 \$pc_c4 { ${strip} default \$pc_c3; }
map \$pc_c4 \$pc_c5 { ${strip} default \$pc_c4; }
map \$pc_c5 \$pc_c6 { ${strip} default \$pc_c5; }
map \$pc_c6 \$pc_cookie { "~^[ \t;]*(?<rest>.*)\$" "\$rest"; }
map \$pc_cookie \$pc_cookie_left { "~*(?:^|;)[ \t]*(?:_oauth2_proxy|__Host-portcullis_ext)" 1; default 0; }
server {
  listen ${GATE_LISTEN};
  server_tokens off;
  client_max_body_size 0;
  # Room for large session / app cookies (oauth2-proxy splits at 4 kB).
  large_client_header_buffers 4 32k;
  allow ${src};
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
