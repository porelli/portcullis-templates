#!/bin/sh
# Entrypoint of the dashboards service: Grafana's auth-proxy allowlist.
#
# Grafana accepts X-Forwarded-User only from the addresses in
# GF_AUTH_PROXY_WHITELIST, read once at start. compose sets it to
# PORTCULLIS_TRAEFIK_SOURCE, Traefik's range (its /32 on Docker/Podman, the
# pod CIDR on Kubernetes), which forward-auth relies on: exactly an IPv4
# CIDR a.b.c.d/n with no host bits, anything else refuses the start.
# While AI support is on (PORTCULLIS_AI_ENABLED), this script adds the
# instance's trust network mcp-trust (contracts §3.2, identity_headers):
#
# - mcp-trust is internal: true and project-scoped; its only members are
#   this service and the grafana-mcp companion (validate.py and the Hub
#   refuse any other member, and the Hub refuses foreign network names, so
#   nothing outside the project can join it). Docker keeps a network's
#   subnet for the network's lifetime; the subnet is read here, at every
#   start, from this container's own interface: nothing is pinned.
# - Trusted: that exact prefix, as this container's interface reports it
#   (address and mask), without Grafana's own address (a data source
#   pointing at Grafana itself would come from it), the network and
#   broadcast addresses and the bridge gateway: the host's side of the
#   bridge, which host processes and host-network containers come from
#   (CI shows the host reaching Grafana there). The container can't read
#   the gateway (an internal network adds no route through it; IPAM data
#   isn't visible inside), so this relies on Docker's builtin IPAM, which
#   gives the gateway the prefix's first address of a network without an
#   ipam block; compose.yml can't change that (the trust network is exactly
#   {internal: true}: no ipam, no driver), and tests/apps/grafana.sh checks
#   it against `docker network inspect` and sends the header from the
#   host's namespace.
# - Refused (exit 1, Grafana doesn't start): not exactly two IPv4
#   addresses, Traefik's range overlapping neither or both networks, a default route not on
#   portcullis-proxy (or not exactly one), any route on the trust interface
#   but its connected prefix, more than one IPv4 or
#   any global IPv6 address on the trust interface, a prefix broader than
#   /16 (Docker's default pools hand out /16 and /20) or narrower than /29.
# - dashboards joins exactly portcullis-proxy and mcp-trust: the interface
#   whose subnet overlaps Traefik's range is portcullis-proxy, the other one
#   is mcp-trust. Anything else (another count of IPv4 addresses, Traefik's
#   range on neither or both, an odd prefix) refuses to start: fail closed.
set -eu

die() { printf 'portcullis-trust: %s\n' "$*" >&2; exit 1; }

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

TRAEFIK=${GF_AUTH_PROXY_WHITELIST:-}
cidr_ok "$TRAEFIK" || die "GF_AUTH_PROXY_WHITELIST must be exactly Traefik's range, an IPv4 CIDR a.b.c.d/n (got '$TRAEFIK')"

if [ "${PORTCULLIS_AI_ENABLED:-false}" != true ]; then
  printf 'portcullis-trust: AI support off; Grafana accepts X-Forwarded-User from %s only\n' "$TRAEFIK" >&2
  exec /run.sh "$@"
fi

ADDRS=$(ip -4 -o addr show scope global) || die "can't list this container's addresses"
TRUST=$(printf '%s\n' "$ADDRS" | awk -v t="$TRAEFIK" '
  function fail(m) { print "portcullis-trust: " m > "/dev/stderr"; bad = 1; exit 1 }
  function n4(s,  a, i) {
    if (split(s, a, ".") != 4) fail("bad address " s)
    for (i = 1; i <= 4; i++) if (a[i] !~ /^[0-9]+$/ || length(a[i]) > 3 || a[i] + 0 > 255) fail("bad address " s)
    return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]
  }
  function ip4(n) { return sprintf("%d.%d.%d.%d", int(n / 16777216) % 256, int(n / 65536) % 256, int(n / 256) % 256, n % 256) }
  function p2(k,  r) { r = 1; while (k-- > 0) r *= 2; return r }
  # The fewest CIDRs covering [start, start + 2^(32-len)) minus x[1..nx].
  function cover(start, len,   size, i) {
    size = p2(32 - len)
    for (i = 1; i <= nx; i++) if (x[i] >= start && x[i] < start + size) break
    if (i > nx) { out = out (out == "" ? "" : ",") ip4(start) "/" len; return }
    if (len < 32) { cover(start, len + 1); cover(start + size / 2, len + 1) }
  }
  {
    for (i = 1; i < NF; i++) if ($i == "inet") break
    if (i >= NF || split($(i + 1), p, "/") != 2 || p[2] !~ /^[0-9]+$/) fail("unreadable address line: " $0)
    n++; addr[n] = n4(p[1]); plen[n] = p[2] + 0; dev[n] = $2; sub(/:$/, "", dev[n]); sub(/@.*/, "", dev[n])
  }
  END {
    if (bad) exit 1
    if (n != 2) fail("want exactly two IPv4 addresses (portcullis-proxy and mcp-trust), got " n + 0)
    # The Traefik range t (checked above): [tb, tb + 2^(32-tl)).
    split(t, tp, "/"); tl = tp[2] + 0; tb = n4(tp[1]); te = tb + p2(32 - tl); k = 0
    for (i = 1; i <= 2; i++) {
      size = p2(32 - plen[i]); base = addr[i] - addr[i] % size
      if (tb < base + size && base < te) { proxy = i; k++ }
    }
    if (k != 1) fail("Traefik (" t ") must overlap exactly one of the two networks")
    j = 3 - proxy; len = plen[j]
    if (len < 16 || len > 29) fail("the trust network prefix /" len " is outside /16../29")
    size = p2(32 - len); self = addr[j]; base = self - self % size
    nx = 4; x[1] = base; x[2] = base + 1; x[3] = self; x[4] = base + size - 1
    cover(base, len)
    print dev[j], dev[proxy], ip4(base) "/" len, out
  }') || die "can't determine the trust network; refusing to start"
# shellcheck disable=SC2086 # four space-free fields from the awk above
set -- $TRUST
[ "$#" = 4 ] || die "can't determine the trust network; refusing to start"
DEV=$1 PROXY_DEV=$2 PREFIX=$3 TRUST=$4
# Routes: the default route goes through portcullis-proxy (Traefik's
# network), and the trust interface carries only its connected prefix —
# nothing else is reached (or trusted to be) through it.
ROUTES=$(ip -4 route show) || die "can't read the routing table; refusing to start"
printf '%s\n' "$ROUTES" | awk -v dev="$DEV" -v pdev="$PROXY_DEV" -v prefix="$PREFIX" '
  function fail(m) { print "portcullis-trust: " m > "/dev/stderr"; bad = 1; exit 1 }
  function devof(  i) { for (i = 1; i < NF; i++) if ($i == "dev") return $(i + 1); return "" }
  function has(w,  i) { for (i = 1; i <= NF; i++) if ($i == w) return 1; return 0 }
  NF == 0 { next }
  $1 == "default" { defaults++; if (devof() != pdev) fail("the default route is not on portcullis-proxy (" pdev "): " $0) }
  devof() == dev { trust++; if ($1 != prefix || has("via")) fail("the trust interface " dev " carries a route other than " prefix ": " $0) }
  END {
    if (bad) exit 1
    if (defaults != 1) fail("want exactly one default route (through portcullis-proxy), got " defaults + 0)
    if (trust != 1) fail("want exactly the connected route " prefix " on the trust interface " dev ", got " trust + 0)
  }' || die "unexpected routes; refusing to start"
# Unambiguous: the trust interface carries this one IPv4 address and no
# global IPv6 one (an IPv6 peer would not be judged by the IPv4 prefix).
[ "$(ip -4 -o addr show dev "$DEV" | grep -c ' inet ')" = 1 ] || die "the trust interface $DEV has more than one IPv4 address; refusing to start"
[ -z "$(ip -6 -o addr show dev "$DEV" scope global 2>/dev/null)" ] || die "the trust interface $DEV has a global IPv6 address; refusing to start"

GF_AUTH_PROXY_WHITELIST="$TRAEFIK,$TRUST"
export GF_AUTH_PROXY_WHITELIST
printf 'portcullis-trust: Grafana accepts X-Forwarded-User from %s\n' "$GF_AUTH_PROXY_WHITELIST" >&2
exec /run.sh "$@"
