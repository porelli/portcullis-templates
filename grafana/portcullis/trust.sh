#!/bin/sh
# Entrypoint of the dashboards service: Grafana's auth-proxy allowlist.
#
# Grafana accepts X-Forwarded-User only from the addresses in
# GF_AUTH_PROXY_WHITELIST, read once at start. compose sets it to Traefik's
# static IP (core's PORTCULLIS_TRAEFIK_IP), which forward-auth relies on.
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
#   addresses, Traefik on neither or both networks, more than one IPv4 or
#   any global IPv6 address on the trust interface, a prefix broader than
#   /16 (Docker's default pools hand out /16 and /20) or narrower than /29.
# - dashboards joins exactly portcullis-proxy and mcp-trust: the interface
#   whose subnet holds Traefik's address is portcullis-proxy, the other one
#   is mcp-trust. Anything else (another count of IPv4 addresses, Traefik
#   on neither or both, an odd prefix) refuses to start: fail closed.
set -eu

die() { printf 'portcullis-trust: %s\n' "$*" >&2; exit 1; }

TRAEFIK=${GF_AUTH_PROXY_WHITELIST:-}
printf '%s\n' "$TRAEFIK" | grep -Eq '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$' \
  || die "GF_AUTH_PROXY_WHITELIST must be exactly Traefik's IPv4 address (got '$TRAEFIK')"

if [ "${PORTCULLIS_AI_ENABLED:-false}" != true ]; then
  printf 'portcullis-trust: AI support off; Grafana accepts X-Forwarded-User from %s only\n' "$TRAEFIK" >&2
  exec /run.sh "$@"
fi

ADDRS=$(ip -4 -o addr show scope global) || die "can't list this container's addresses"
TRUST=$(printf '%s\n' "$ADDRS" | awk -v t="$TRAEFIK" '
  function fail(m) { print "portcullis-trust: " m > "/dev/stderr"; bad = 1; exit 1 }
  function n4(s,  a) { if (split(s, a, ".") != 4) fail("bad address " s); return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
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
    tn = n4(t); k = 0
    for (i = 1; i <= 2; i++) {
      size = p2(32 - plen[i]); base = addr[i] - addr[i] % size
      if (tn >= base && tn < base + size) { proxy = i; k++ }
    }
    if (k != 1) fail("Traefik (" t ") must be on exactly one of the two networks")
    j = 3 - proxy; len = plen[j]
    if (len < 16 || len > 29) fail("the trust network prefix /" len " is outside /16../29")
    size = p2(32 - len); self = addr[j]; base = self - self % size
    nx = 4; x[1] = base; x[2] = base + 1; x[3] = self; x[4] = base + size - 1
    cover(base, len)
    print dev[j], out
  }') || die "can't determine the trust network; refusing to start"
DEV=${TRUST%% *}
TRUST=${TRUST#* }
[ -n "$DEV" ] && [ -n "$TRUST" ] && [ "$DEV" != "$TRUST" ] || die "empty trust network; refusing to start"
# Unambiguous: the trust interface carries this one IPv4 address and no
# global IPv6 one (an IPv6 peer would not be judged by the IPv4 prefix).
[ "$(ip -4 -o addr show dev "$DEV" | grep -c ' inet ')" = 1 ] || die "the trust interface $DEV has more than one IPv4 address; refusing to start"
[ -z "$(ip -6 -o addr show dev "$DEV" scope global 2>/dev/null)" ] || die "the trust interface $DEV has a global IPv6 address; refusing to start"

GF_AUTH_PROXY_WHITELIST="$TRAEFIK,$TRUST"
export GF_AUTH_PROXY_WHITELIST
printf 'portcullis-trust: Grafana accepts X-Forwarded-User from %s\n' "$GF_AUTH_PROXY_WHITELIST" >&2
exec /run.sh "$@"
