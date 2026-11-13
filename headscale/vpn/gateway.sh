#!/bin/sh
# Portcullis VPN gateway entrypoint (integration contracts §3.3): the
# official tailscale/tailscale image in userspace mode (no TUN, no
# capabilities), registered in this Headscale as tag:portcullis-gateway.
#
# When the Hub wires this instance as a VPN provider it sets
# PORTCULLIS_VPN_EDGE=<wg ip>:<port>; every tailnet connection to the
# gateway's port 443 is then forwarded there with a PROXY v2 header that
# carries the client node's tunnel address (tailscale serve --tcp 443
# --proxy-protocol 2, written as containerboot's TS_SERVE_CONFIG). Not
# wired: the node joins the tailnet and serves nothing.
#
# The first start waits for the single-use pre-auth key the gateway-key
# start hook (vpn/glue.py, in vpn-glue) writes to /run/gateway/authkey;
# later starts log in from the saved state (TS_AUTH_ONCE).
set -eu

STATE=/var/lib/tailscale/tailscaled.state
KEY=/run/gateway/authkey
SERVE=/tmp/portcullis-serve.json

edge="${PORTCULLIS_VPN_EDGE:-}"
if [ -n "$edge" ]; then
  if ! printf '%s' "$edge" | grep -Eqx '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}'; then
    echo "gateway: PORTCULLIS_VPN_EDGE must be <IPv4>:<port>" >&2
    exit 2
  fi
  printf '{"TCP":{"443":{"TCPForward":"%s","ProxyProtocol":2}}}\n' "$edge" > "$SERVE"
  export TS_SERVE_CONFIG="$SERVE"
else
  echo "gateway: not wired as a Portcullis VPN provider (no PORTCULLIS_VPN_EDGE): serving nothing" >&2
fi

# A state with a current profile = logged in before.
if ! { [ -s "$STATE" ] && grep -qa '_current-profile' "$STATE"; }; then
  echo "gateway: waiting for the pre-auth key (the gateway-key start hook writes it)" >&2
  while [ ! -s "$KEY" ]; do sleep 2; done
fi
if [ -s "$KEY" ]; then
  export TS_AUTHKEY="file:$KEY"
fi
exec /usr/local/bin/containerboot
