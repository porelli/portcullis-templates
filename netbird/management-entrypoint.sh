#!/bin/sh
CONFIG="/etc/netbird/management.json"
TEMPLATE="/etc/netbird/management.json.tmpl"
# Hostname the config was generated for (management.json is generated once:
# NetBird stores its DataStoreEncryptionKey in it).
HOST_FILE="/etc/netbird/.portcullis-host"
NETBIRD_DOMAIN="${NETBIRD_HOST:?NETBIRD_HOST must be set}"

if [ ! -f "$CONFIG" ]; then
  echo "Generating management.json from template..."
  TURN_HOST="${COTURN_EXTERNAL_IP:-${NETBIRD_DOMAIN}}"
  sed \
    -e "s|\${PORTCULLIS_DOMAIN}|${PORTCULLIS_DOMAIN}|g" \
    -e "s|\${NETBIRD_DOMAIN}|${NETBIRD_DOMAIN}|g" \
    -e "s|\${NETBIRD_CLIENT_ID}|${NETBIRD_CLIENT_ID}|g" \
    -e "s|\${TURN_HOST}|${TURN_HOST}|g" \
    -e "s|\${COTURN_AUTH_SECRET}|${COTURN_AUTH_SECRET}|g" \
    -e "s|\${NETBIRD_OIDC_CLIENT_SECRET}|${NETBIRD_OIDC_CLIENT_SECRET}|g" \
    "$TEMPLATE" > "$CONFIG"
  chmod 600 "$CONFIG"
  printf '%s\n' "$NETBIRD_DOMAIN" > "$HOST_FILE"
  # Do not print the generated config: it contains the TURN and OIDC secrets.
  echo "Config generated."
else
  echo "management.json already exists, skipping generation."
  [ -f "$HOST_FILE" ] || printf '%s\n' "$NETBIRD_DOMAIN" > "$HOST_FILE"
  OLD_HOST=$(cat "$HOST_FILE")
  if [ "$OLD_HOST" != "$NETBIRD_DOMAIN" ]; then
    # Hostname changed in the Hub: move the URLs that name it (Signal URI,
    # redirect URLs, STUN/TURN host without COTURN_EXTERNAL_IP).
    echo "Hostname changed: $OLD_HOST -> $NETBIRD_DOMAIN"
    old_re=$(printf '%s' "$OLD_HOST" | sed 's/[].[*^$\\|]/\\&/g')
    (umask 077 && sed \
      -e "s|//${old_re}/|//${NETBIRD_DOMAIN}/|g" \
      -e "s|\"${old_re}:443\"|\"${NETBIRD_DOMAIN}:443\"|g" \
      -e "s|:${old_re}:3478\"|:${NETBIRD_DOMAIN}:3478\"|g" \
      "$CONFIG" > "$CONFIG.new") \
      && mv "$CONFIG.new" "$CONFIG" \
      && printf '%s\n' "$NETBIRD_DOMAIN" > "$HOST_FILE" \
      || { echo "Rewriting management.json for the new hostname failed." >&2; exit 1; }
  fi
fi

exec /go/bin/netbird-mgmt management "$@"
