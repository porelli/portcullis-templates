#!/bin/sh
# fxa-gate: the Traefik-only nginx in front of every host of
# firefox-sync-fxa (the esphome/gate.sh pattern, one server block per host).
# Every other service of the instance is on its default network only; this
# nginx is the only container on portcullis-proxy, so no other app can reach
# the accounts API (fxa-auth:9000) and skip the sign-up gate (ffs-admin:8081).
# It answers only PORTCULLIS_TRAEFIK_SOURCE, Traefik's address range
# (Traefik's /32 on Docker/Podman, the pod CIDR on Kubernetes, where a
# NetworkPolicy admits only Traefik to the routed port); every other peer
# gets 403. There is no real_ip handling: the peer is the TCP peer, forwarded
# headers never change it. Fails closed: a malformed address, hostname,
# group or port stops the container (Traefik then routes nothing).
#
# Hosts (Host header, as Traefik routed it):
#   accounts  -> fxa-content-internal:3030 (the account pages)
#   api       -> fxa-auth-internal:9000; exactly /v1/account/create goes
#                to the sign-up gate, ffs-admin-internal:8081, any other
#                spelling of it is 404; the other routes that create
#                accounts (passwordless, linked_account) are 403
#   profile   -> fxa-profile-internal:1111; /img/ -> fxa-profile-static-
#                internal:1112 with the prefix stripped
#   sync      -> firefox-sync-fxa-internal:8000 (bodies up to 10 MB)
#   admin     -> ffs-admin-internal:8080, only for the instance's admin
#                group (below); the admin UI's sign-up and allowlist forms
#                answer 403 here
#   pairing   -> fxa-pairing-internal:8000 (websockets: the only host that
#                passes an Upgrade; elsewhere one is 400)
#   any other -> 421
# Host and Traefik's X-Forwarded-For are passed unchanged (the accounts'
# rate limits key on the client address Traefik put there:
# CLIENT_ADDRESS_DEPTH 2); nothing is appended.
#
# The admin host: Traefik's admin router runs portcullis-auth and
# portcullis-groups (the access group). group-gate returns the person's
# groups in X-Auth-Request-Groups, one of portcullis-groups'
# authResponseHeaders: Traefik deletes a client's copy, so the header only
# ever holds what group-gate allowed (expired memberships removed). The
# admin server block requires GATE_ADMIN_GROUP as one exact,
# comma-separated entry of it (case-sensitive, as group-gate compares);
# missing or any other value = 403.
#
# Credentials: Authorization (on the gated hosts group-gate echoes the
# Keycloak bearer token), X-Forwarded-Access-Token and
# X-Auth-Request-Access-Token never reach the account pages or the admin UI.
# The open hosts keep Authorization: it is Firefox's own Hawk / Bearer
# credential there, and no forward-auth runs on them. The forward-auth
# session cookies (_oauth2_proxy*, __Host-portcullis_ext*, split and CSRF
# cookies included; the browser sends them to every host of the domain) are
# removed on every host; a Cookie header that still names one after six
# passes is refused (400).
#
# Upstreams: names that /etc/hosts carries (Kubernetes: the alias Services'
# stable cluster addresses, hostAliases) are resolved once at start; any
# other (Docker, Podman) per request through the container's DNS server, so
# a restarted service's new address is used and an old one never is.
#
# Environment: PORTCULLIS_TRAEFIK_SOURCE (an IPv4 CIDR a.b.c.d/n, host bits
# zero, nothing else), GATE_LISTEN (port), GATE_HOST_ACCOUNTS, GATE_HOST_API,
# GATE_HOST_PROFILE, GATE_HOST_SYNC, GATE_HOST_ADMIN, GATE_HOST_PAIRING
# (lowercase hostnames, all different), GATE_ADMIN_GROUP (the instance's
# admin group). nginx runs unprivileged: everything it writes is under /tmp.
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

die() { echo "fxa-gate: $*" >&2; exit 1; }

src="${PORTCULLIS_TRAEFIK_SOURCE:-}"
cidr_ok "$src" || die "PORTCULLIS_TRAEFIK_SOURCE must be an IPv4 CIDR a.b.c.d/n (got '$src')"
case "${GATE_LISTEN:-}" in
  "" | *[!0-9]* | 0*) die "GATE_LISTEN must be a port number" ;;
esac
[ "$GATE_LISTEN" -le 65535 ] || die "GATE_LISTEN must be a port number"

# A lowercase hostname: labels of a-z 0-9 -, at least two, no empty label,
# no label starting or ending with -, at most 253 characters.
host_ok() {
  case "$1" in "" | *[!a-z0-9.-]* | .* | *. | *..* | -* | *.-* | *-.* | *-) return 1 ;; *.*) ;; *) return 1 ;; esac
  [ "${#1}" -le 253 ]
}
seen=" "
for vh in "ACCOUNTS=${GATE_HOST_ACCOUNTS:-}" "API=${GATE_HOST_API:-}" "PROFILE=${GATE_HOST_PROFILE:-}" \
  "SYNC=${GATE_HOST_SYNC:-}" "ADMIN=${GATE_HOST_ADMIN:-}" "PAIRING=${GATE_HOST_PAIRING:-}"; do
  v=${vh%%=*} h=${vh#*=}
  host_ok "$h" || die "GATE_HOST_$v must be a lowercase hostname (got '$h')"
  case "$seen" in *" $h "*) die "GATE_HOST_$v ($h) is also another host of the instance" ;; esac
  seen="$seen$h "
done

# The admin group as a PCRE of its bytes (\xHH each: no character of the
# name can mean anything in the pattern or in nginx's configuration). It
# must be one comma-separated entry: no control character, no comma, no
# white space at either end (group-gate splits on commas and strips).
group="${GATE_ADMIN_GROUP:-}"
case "$group" in "" | " "* | *" ") die "GATE_ADMIN_GROUP must be the instance's admin group (got '$group')" ;; esac
[ "${#group}" -le 255 ] || die "GATE_ADMIN_GROUP is longer than 255 characters"
group_re=""
for b in $(printf '%s' "$group" | od -An -v -tu1); do
  { [ "$b" -ge 32 ] && [ "$b" -ne 127 ] && [ "$b" -ne 44 ]; } || die "GATE_ADMIN_GROUP has a control character or a comma"
  group_re="$group_re$(printf '\\x%02x' "$b")"
done

# The container's DNS server (Docker 127.0.0.11, Podman's aardvark-dns, the
# cluster DNS on Kubernetes).
ns=$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf 2> /dev/null || true)
case "$ns" in
  *.*.*.*) cidr_ok "$ns/32" || die "the nameserver in /etc/resolv.conf is not an IPv4 address ($ns)" ;;
  *:*)
    case "$ns" in *[!0-9a-fA-F:]*) die "the nameserver in /etc/resolv.conf is not an IP address ($ns)" ;; esac
    ns="[$ns]" ;;
  *) die "no nameserver in /etc/resolv.conf" ;;
esac

run=/tmp/fxa-gate
rm -rf "$run"
mkdir -p "$run/body" "$run/proxy" "$run/fastcgi" "$run/uwsgi" "$run/scgi"
: > "$run/upstreams.conf"

# target <id> <name> <port>: the URL proxy_pass uses for an upstream.
target() {
  if awk -v n="$2" '$1 !~ /^#/ { for (i = 2; i <= NF; i++) if ($i == n) f = 1 } END { exit !f }' /etc/hosts 2> /dev/null; then
    printf 'upstream pc_%s { server %s:%s; }\n' "$1" "$2" "$3" >> "$run/upstreams.conf"
    printf 'http://pc_%s' "$1"
  else
    printf 'http://%s:%s' "$2" "$3"
  fi
}
up_content=$(target content fxa-content-internal 3030)
up_auth=$(target auth fxa-auth-internal 9000)
up_signup=$(target signup ffs-admin-internal 8081)
up_profile=$(target profile fxa-profile-internal 1111)
up_static=$(target static fxa-profile-static-internal 1112)
up_sync=$(target sync firefox-sync-fxa-internal 8000)
up_admin=$(target admin ffs-admin-internal 8080)
up_pairing=$(target pairing fxa-pairing-internal 8000)

# One forward-auth cookie out of Cookie per pass.
strip='"~*^(?<pre>.*?)(?:^|;)[ \t]*(?:_oauth2_proxy|__Host-portcullis_ext)[^=;]*=[^;]*(?<post>.*)$" "$pre$post";'

# proxy <keep Authorization: 1|0> <protocol upgrades: 1|0>: the request
# headers of every server block. Only the pairing host passes an Upgrade
# (its websockets); everywhere else a request that asks for one (websocket,
# h2c) is refused, and Upgrade / Connection never reach the service, so no
# connection can turn into a tunnel past the gate's per-request rules.
proxy() {
  cat << EOF
  proxy_http_version 1.1;
  proxy_set_header Host \$http_host;
EOF
  if [ "$2" = 1 ]; then
    cat << EOF
  proxy_set_header Upgrade \$http_upgrade;
  proxy_set_header Connection \$connection_upgrade;
EOF
  else
    cat << EOF
  if (\$http_upgrade) { return 400 "fxa-gate: no protocol upgrade on this host\\n"; }
  proxy_set_header Upgrade "";
  proxy_set_header Connection "";
EOF
  fi
  cat << EOF
  proxy_set_header X-Forwarded-For \$http_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-Access-Token "";
  proxy_set_header X-Auth-Request-Access-Token "";
  proxy_set_header Cookie \$pc_cookie;
EOF
  [ "$1" = 1 ] || echo '  proxy_set_header Authorization "";'
  cat << EOF
  if (\$pc_cookie_left) { return 400; }
EOF
}

cat > "$run/nginx.conf" << EOF
worker_processes 1;
pid $run/nginx.pid;
error_log stderr warn;
events { worker_connections 1024; }
http {
  access_log off;
  server_tokens off;
  # The gate's own refusals (return ... "text") say who refused.
  default_type text/plain;
  client_body_temp_path $run/body;
  proxy_temp_path $run/proxy;
  fastcgi_temp_path $run/fastcgi;
  uwsgi_temp_path $run/uwsgi;
  scgi_temp_path $run/scgi;
  client_max_body_size 2m;
  # Room for large session / app cookies (oauth2-proxy splits at 4 kB).
  large_client_header_buffers 4 32k;
  proxy_buffering off;
  proxy_request_buffering off;
  proxy_read_timeout 120s;
  proxy_send_timeout 120s;
  allow ${src};
  deny all;
  resolver ${ns} valid=10s ipv6=off;
  map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }
  map \$http_cookie \$pc_c1 { ${strip} default \$http_cookie; }
  map \$pc_c1 \$pc_c2 { ${strip} default \$pc_c1; }
  map \$pc_c2 \$pc_c3 { ${strip} default \$pc_c2; }
  map \$pc_c3 \$pc_c4 { ${strip} default \$pc_c3; }
  map \$pc_c4 \$pc_c5 { ${strip} default \$pc_c4; }
  map \$pc_c5 \$pc_c6 { ${strip} default \$pc_c5; }
  map \$pc_c6 \$pc_cookie { "~^[ \t;]*(?<rest>.*)\$" "\$rest"; }
  map \$pc_cookie \$pc_cookie_left { "~*(?:^|;)[ \t]*(?:_oauth2_proxy|__Host-portcullis_ext)" 1; default 0; }
  # 1 only when group-gate's groups list the admin group exactly.
  map \$http_x_auth_request_groups \$pc_admin { "~^(?:[^,]*,)*[ \t]*${group_re}[ \t]*(?:,[^,]*)*\$" 1; default 0; }
  include $run/upstreams.conf;

  server {
    listen ${GATE_LISTEN} default_server;
    server_name _;
    return 421;
  }

  # The account pages.
  server {
    listen ${GATE_LISTEN};
    server_name ${GATE_HOST_ACCOUNTS};
$(proxy 0 0)
    set \$pc_up ${up_content};
    location / { proxy_pass \$pc_up; }
  }

  # The accounts API; accounts are created only through the sign-up gate.
  # Sign-up: exactly /v1/account/create (Traefik's rate-limit-auth router)
  # to the sign-up gate; any other spelling that normalises to it (trailing
  # slash or suffix, case, //, %-encoding, dot segments) is 404 here, so it
  # reaches neither fxa-auth nor the looser API router's rate limit. The
  # other ways fxa-auth v1.350.0 creates an account (db.createAccount
  # callers: passwordless confirm_code, linked_account login) are refused.
  server {
    listen ${GATE_LISTEN};
    server_name ${GATE_HOST_API};
$(proxy 1 0)
    set \$pc_up ${up_auth};
    set \$pc_signup ${up_signup};
    location ~* ^/v1/account/create {
      if (\$request_uri !~ "^/v1/account/create(?:\\?|\$)") { return 404 "fxa-gate: not found\\n"; }
      proxy_pass \$pc_signup/v1/account/create\$is_args\$args;
    }
    location ~* ^/v1/(account/passwordless|linked_account)(?:/|\$) {
      return 403 "fxa-gate: accounts are created through the sign-up gate only\\n";
    }
    location / { proxy_pass \$pc_up; }
  }

  # Profiles; the avatars under /img/.
  server {
    listen ${GATE_LISTEN};
    server_name ${GATE_HOST_PROFILE};
$(proxy 1 0)
    set \$pc_up ${up_profile};
    set \$pc_static ${up_static};
    location /img/ {
      rewrite ^/img/(.*)\$ /\$1 break;
      proxy_pass \$pc_static;
    }
    location / { proxy_pass \$pc_up; }
  }

  # Sync storage and the tokenserver.
  server {
    listen ${GATE_LISTEN};
    server_name ${GATE_HOST_SYNC};
    client_max_body_size 10m;
$(proxy 1 0)
    set \$pc_up ${up_sync};
    location / { proxy_pass \$pc_up; }
  }

  # The admin UI: the admin group only; access is managed elsewhere, so its
  # sign-up and allowlist forms (and their confirmation pages) are refused
  # here too (the admin UI and ffs_admin's grants refuse them underneath).
  server {
    listen ${GATE_LISTEN};
    server_name ${GATE_HOST_ADMIN};
    if (\$pc_admin != 1) { return 403 "fxa-gate: the admin UI is for the instance's admin group only\\n"; }
$(proxy 0 0)
    set \$pc_up ${up_admin};
    set \$pc_managed "fxa-gate: who may sign up and sync is managed in Portcullis, not in the admin UI\\n";
    location ~* ^/accounts/(signups|max-accounts|invite|allowlist/remove)/*\$ { return 403 "\$pc_managed"; }
    location ~* ^/sync/(max-users/*\$|allowlist(/|\$)) { return 403 "\$pc_managed"; }
    location / { proxy_pass \$pc_up; }
  }

  # The pairing channel server (websockets).
  server {
    listen ${GATE_LISTEN};
    server_name ${GATE_HOST_PAIRING};
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
$(proxy 1 1)
    set \$pc_up ${up_pairing};
    location / { proxy_pass \$pc_up; }
  }
}
EOF
exec nginx -c "$run/nginx.conf" -e stderr -g 'daemon off;'
