#!/bin/sh
# Portcullis start wrapper for Element Web (runs as the image's nginx user).
# Writes config.json for this instance into the tmpfs (served by
# element-nginx.conf.template), then runs the image's nginx entrypoint.
# Fails closed: on any bad value nginx never starts (and the healthcheck only
# passes while nginx serves exactly this file).
set -eu

die() { echo "element-start: $*; refusing to start" >&2; exit 1; }
is_host() {
  printf '%s' "$1" | grep -Eqx '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
}

is_host "${MATRIX_HOST:-}" || die "MATRIX_HOST is empty or not a valid hostname"
is_host "${ELEMENT_HOST:-}" || die "ELEMENT_HOST is empty or not a valid hostname"
grep -q 'portcullis-element' /etc/nginx/templates/default.conf.template \
  || die "the Portcullis nginx template is not mounted"

OUT=/tmp/portcullis-element
umask 022
mkdir -p "$OUT"
# Homeserver fixed to this instance's Synapse (no server picker), SSO only
# (immediate redirect), no guests, no 3PID / password / registration UI, no
# integration manager, no identity server.
jq -n --arg hs "$MATRIX_HOST" --arg el "$ELEMENT_HOST" '{
  default_server_config: {"m.homeserver": {base_url: ("https://" + $hs), server_name: $hs}},
  disable_custom_urls: true,
  disable_guests: true,
  disable_3pid_login: true,
  sso_redirect_options: {immediate: true},
  room_directory: {servers: [$hs]},
  permalink_prefix: ("https://" + $el),
  show_labs_settings: false,
  integrations_ui_url: null,
  integrations_rest_url: null,
  integrations_widgets_urls: null,
  setting_defaults: {
    "UIFeature.registration": false,
    "UIFeature.passwordReset": false,
    "UIFeature.identityServer": false,
    "UIFeature.thirdPartyId": false
  }
}' > "$OUT/config.json.new"
mv "$OUT/config.json.new" "$OUT/config.json"
echo "element-start: config.json for homeserver https://$MATRIX_HOST"

exec /docker-entrypoint.sh nginx -g 'daemon off;'
