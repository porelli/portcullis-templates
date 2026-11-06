#!/bin/sh
# Entrypoint of the dashboards service: Grafana's auth-proxy allowlist.
#
# Grafana accepts X-Forwarded-User only from the addresses in
# GF_AUTH_PROXY_WHITELIST, read once at start. compose sets it to Traefik's
# static IP (core's PORTCULLIS_TRAEFIK_IP), which forward-auth relies on.
# While AI support is on (PORTCULLIS_AI_ENABLED), this script adds the
# current address of this instance's mcp-grafana companion (contracts §3.2,
# identity_headers), and nothing else:
#
# - The companion is found by its alias grafana-mcp-internal, which exists
#   on the instance's own default network only (validate.py and the Hub
#   refuse a *-internal name on any other network, so no container on
#   portcullis-proxy can answer to it).
# - Each address must be directly connected (no gateway), not one of
#   Grafana's own addresses, and on another interface than the one Traefik
#   is on. Anything else is dropped.
# - No subnet is ever trusted, so no other container on either network
#   (and no host process, which comes from the network's gateway) can sign
#   in by sending the header. Docker gives the companion a new address when
#   it restarts, so a background check restarts Grafana (SIGTERM to PID 1;
#   restart: unless-stopped starts it again) when the set changes, also when
#   the companion goes away: then only Traefik is trusted again.
# Fails closed: anything unexpected leaves Traefik's address alone.
set -eu

ALIAS=grafana-mcp-internal
POLL=5    # seconds between checks
WAIT=60   # seconds to wait for the companion at start while AI is on

log() { printf 'portcullis-trust: %s\n' "$*" >&2; }

ipv4() {
  printf '%s\n' "$1" | grep -Eq '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$'
}

# The interface of a directly connected address that isn't local, else
# nothing (ip prints "local …", "broadcast …" or "… via <gw> …" otherwise).
route_dev() {
  ip -4 route get "$1" 2>/dev/null | awk -v a="$1" '
    NR == 1 && $1 == a {
      for (i = 2; i < NF; i++) { if ($i == "via") exit; if ($i == "dev") d = $(i + 1) }
      if (d != "") print d
    }' || true
}

TRAEFIK=${GF_AUTH_PROXY_WHITELIST:-}
if ! ipv4 "$TRAEFIK"; then
  log "GF_AUTH_PROXY_WHITELIST must be exactly Traefik's IPv4 address (got '$TRAEFIK')"
  exit 1
fi

# The companion's valid addresses, sorted, one per line.
companions() {
  proxy_dev=$(route_dev "$TRAEFIK")
  [ -n "$proxy_dev" ] || return 0
  getent hosts "$ALIAS" 2>/dev/null | awk '{ print $1 }' | sort -u | while read -r a; do
    ipv4 "$a" || continue
    d=$(route_dev "$a")
    if [ -n "$d" ] && [ "$d" != "$proxy_dev" ]; then printf '%s\n' "$a"; fi
  done
  return 0
}

TRUSTED=""
if [ "${PORTCULLIS_AI_ENABLED:-false}" = true ]; then
  waited=0
  while :; do
    TRUSTED=$(companions)
    [ -n "$TRUSTED" ] && break
    if [ "$waited" -ge "$WAIT" ]; then
      log "AI support is on but the companion ($ALIAS) isn't reachable yet; trusting Traefik only"
      break
    fi
    sleep "$POLL"
    waited=$((waited + POLL))
  done
fi

LIST=$TRAEFIK
for a in $TRUSTED; do LIST="$LIST,$a"; done
GF_AUTH_PROXY_WHITELIST=$LIST
export GF_AUTH_PROXY_WHITELIST
log "Grafana accepts X-Forwarded-User from: $LIST"

if [ "${PORTCULLIS_AI_ENABLED:-false}" = true ]; then
  (
    changed=0
    while sleep "$POLL"; do
      now=$(companions)
      if [ "$now" = "$TRUSTED" ]; then changed=0; continue; fi
      # Twice in a row, so a single failed lookup doesn't restart Grafana.
      changed=$((changed + 1))
      [ "$changed" -ge 2 ] || continue
      log "companion address changed ($(printf '%s' "$TRUSTED" | tr '\n' ' ') -> $(printf '%s' "$now" | tr '\n' ' ')); restarting Grafana to re-read its allowlist"
      kill -TERM 1
      exit 0
    done
  ) &
fi

exec /run.sh "$@"
