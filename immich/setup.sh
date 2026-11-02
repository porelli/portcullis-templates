#!/bin/sh
# Immich auto-setup: create initial admin user
# OAuth is pre-configured via IMMICH_CONFIG_FILE

set -e

IMMICH_URL="http://immich-server:2283"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@portcullis.local}"
ADMIN_PASSWORD="${IMMICH_ADMIN_PASSWORD:?IMMICH_ADMIN_PASSWORD must be set}"
ADMIN_NAME="${ADMIN_NAME:-Admin}"

echo "setup: Waiting for Immich..."
for _ in $(seq 1 60); do
  if wget -qO- "$IMMICH_URL/api/server/config" 2>/dev/null | grep -q '"isInitialized"'; then
    break
  fi
  sleep 3
done

# Check if already initialized
INITIALIZED=$(wget -qO- "$IMMICH_URL/api/server/config" 2>/dev/null | sed -n 's/.*"isInitialized":\([a-z]*\).*/\1/p')
if [ "$INITIALIZED" = "true" ]; then
  echo "setup: Already initialized, skipping."
  exit 0
fi

echo "setup: Creating admin user..."
# The request body (with the password) goes through a private temp file
# (--post-file), never on wget's argv (visible in ps / /proc to the host).
umask 077
BODY=$(mktemp)
trap 'rm -f "$BODY"' EXIT
printf '{"email":"%s","password":"%s","name":"%s"}' "$ADMIN_EMAIL" "$ADMIN_PASSWORD" "$ADMIN_NAME" > "$BODY"
RESULT=$(wget -qO- --post-file="$BODY" \
  --header="Content-Type: application/json" \
  "$IMMICH_URL/api/auth/admin-sign-up" 2>&1) || true
rm -f "$BODY"

if echo "$RESULT" | grep -q '"isAdmin":true'; then
  echo "setup: Admin created successfully."
else
  echo "setup: Admin creation response: $RESULT"
fi

echo "setup: Done. OAuth is configured via config file."
