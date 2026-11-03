#!/bin/sh
CONFIG="/etc/netbird/management.json"
TEMPLATE="/etc/netbird/management.json.tmpl"
# What the config was generated for: "<hostname> <turn endpoint>".
# management.json is generated only once (NetBird stores its
# DataStoreEncryptionKey in it), so later changes are applied in place.
STATE_FILE="/etc/netbird/.portcullis-endpoints"
NETBIRD_DOMAIN="${NETBIRD_HOST:?NETBIRD_HOST must be set}"
# The TURN host: the "TURN public IP" setting, else the hostname. An IPv6
# address is bracketed, as stun:/turn: URIs need it before the port.
TURN_HOST="${COTURN_EXTERNAL_IP:-${NETBIRD_DOMAIN}}"
case "$TURN_HOST" in
  *:*) TURN_HOST="[$TURN_HOST]" ;;
esac
TURN_ENDPOINT="${TURN_HOST}:${COTURN_STUN_PORT:?COTURN_STUN_PORT must be set}"

# Escape a literal for a sed regex (| is the delimiter).
re_escape() { printf '%s' "$1" | sed 's/[].[*^$\\|]/\\&/g'; }

if [ ! -f "$CONFIG" ]; then
  echo "Generating management.json from template..."
  sed \
    -e "s|\${PORTCULLIS_DOMAIN}|${PORTCULLIS_DOMAIN}|g" \
    -e "s|\${NETBIRD_DOMAIN}|${NETBIRD_DOMAIN}|g" \
    -e "s|\${NETBIRD_CLIENT_ID}|${NETBIRD_CLIENT_ID}|g" \
    -e "s|\${TURN_ENDPOINT}|${TURN_ENDPOINT}|g" \
    -e "s|\${COTURN_AUTH_SECRET}|${COTURN_AUTH_SECRET}|g" \
    -e "s|\${NETBIRD_OIDC_CLIENT_SECRET}|${NETBIRD_OIDC_CLIENT_SECRET}|g" \
    "$TEMPLATE" > "$CONFIG"
  chmod 600 "$CONFIG"
  printf '%s %s\n' "$NETBIRD_DOMAIN" "$TURN_ENDPOINT" > "$STATE_FILE"
  # Do not print the generated config: it contains the TURN and OIDC secrets.
  echo "Config generated."
else
  echo "management.json already exists, skipping generation."
  [ -f "$STATE_FILE" ] || printf '%s %s\n' "$NETBIRD_DOMAIN" "$TURN_ENDPOINT" > "$STATE_FILE"
  read -r OLD_HOST OLD_TURN < "$STATE_FILE"
  if [ "$OLD_HOST" != "$NETBIRD_DOMAIN" ] || [ "$OLD_TURN" != "$TURN_ENDPOINT" ]; then
    # Hostname, STUN port or external IP changed: move the Signal URI, the
    # redirect URLs and the STUN/TURN URIs.
    echo "Endpoints changed: $OLD_HOST $OLD_TURN -> $NETBIRD_DOMAIN $TURN_ENDPOINT"
    old_host=$(re_escape "$OLD_HOST")
    old_turn=$(re_escape "$OLD_TURN")
    (umask 077 && sed \
      -e "s|\"stun:${old_turn}\"|\"stun:${TURN_ENDPOINT}\"|g" \
      -e "s|\"turn:${old_turn}\"|\"turn:${TURN_ENDPOINT}\"|g" \
      -e "s|//${old_host}/|//${NETBIRD_DOMAIN}/|g" \
      -e "s|\"${old_host}:443\"|\"${NETBIRD_DOMAIN}:443\"|g" \
      "$CONFIG" > "$CONFIG.new") \
      && mv "$CONFIG.new" "$CONFIG" \
      && printf '%s %s\n' "$NETBIRD_DOMAIN" "$TURN_ENDPOINT" > "$STATE_FILE" \
      || { echo "Rewriting management.json failed." >&2; exit 1; }
  fi
fi

exec /go/bin/netbird-mgmt management "$@"
