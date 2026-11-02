#!/bin/sh
# Portcullis: Nextcloud start-up configuration. compose.yml installs this file
# as a before-starting hook of the nextcloud image, so it runs at EVERY start,
# as www-data, after the image's install/upgrade step and before Apache.
# Everything here is derived from the instance's environment and re-applied
# on each start: a hostname, client or group change needs no action inside
# Nextcloud. Never print NEXTCLOUD_OIDC_SECRET.
set -eu

occ() { php /var/www/html/occ "$@"; }

: "${PORTCULLIS_DOMAIN:?}" "${PORTCULLIS_HOST_NEXTCLOUD:?}" "${PORTCULLIS_OIDC_CLIENT_ID:?}"
: "${PORTCULLIS_ACCESS_GROUP:?}" "${PORTCULLIS_ADMIN_GROUP:?}" "${NEXTCLOUD_OIDC_SECRET:?}"
HOST=$PORTCULLIS_HOST_NEXTCLOUD
for g in "$PORTCULLIS_ACCESS_GROUP" "$PORTCULLIS_ADMIN_GROUP"; do
  case "$g" in
    ""|*[!a-z0-9_-]*) echo "portcullis: unexpected group name '$g'" >&2; exit 1 ;;
  esac
done

# Fail closed: a non-zero exit stops the image's entrypoint before Apache
# starts, so an uninstalled Nextcloud never serves its web installer.
if ! occ status --output=json | grep -q '"installed":true'; then
  echo "portcullis: Nextcloud is not installed (the automatic install failed?); not starting the web server" >&2
  exit 1
fi

# ── Hostname (contract v2: whatever the instance's hostname is now) ──
occ config:system:delete trusted_domains >/dev/null
occ config:system:set trusted_domains 0 --value="$HOST" >/dev/null
occ config:system:set overwrite.cli.url --value="https://$HOST" >/dev/null
occ config:system:set overwritehost --value="$HOST" >/dev/null
occ config:system:set overwriteprotocol --value=https >/dev/null
occ maintenance:update:htaccess >/dev/null

# ── Logins: Portcullis (user_oidc) only, no password login at all ──
# Nextcloud has no switch that turns its password form off server-side
# (hide_login_form only hides it), so no account may have a usable
# password: every enabled local account (backend "Database": the
# break-glass admin created at install, accounts of older installs, any
# account created in the Users page) is disabled here and every minute by
# nextcloud-cron. Break-glass is occ on the server, see the manifest notes.
# Clients (desktop, mobile, WebDAV, OCS) use app passwords / Login Flow
# tokens of SSO accounts, never an account password.
occ config:system:set hide_login_form --type=boolean --value=true >/dev/null
occ config:system:set token_auth_enforced --type=boolean --value=true >/dev/null
occ config:system:set lost_password_link --value=disabled >/dev/null
# >>> local-accounts (tests/apps/nextcloud.sh runs this block with a stub occ)
# Enabled local accounts, one per line. Fails (non-zero) when occ or the
# JSON parse fails; no pipe hides occ's exit status.
enabled_local_accounts() {
  _json=$(occ user:list --info --limit=0 --output=json) || return 1
  printf '%s' "$_json" | php -r '
    $u = json_decode(stream_get_contents(STDIN), true);
    if (!is_array($u)) exit(1);
    foreach ($u as $id => $i) if (($i["backend"] ?? "") === "Database" && !empty($i["enabled"])) echo $id, "\n";
  '
}
if ! accounts=$(enabled_local_accounts); then
  echo "portcullis: cannot list local accounts; not starting the web server" >&2
  exit 1
fi
while IFS= read -r id; do
  [ -n "$id" ] || continue
  if ! occ user:disable "$id" >/dev/null; then
    echo "portcullis: cannot disable local account $id; not starting the web server" >&2
    exit 1
  fi
  echo "portcullis: disabled local account $id (Portcullis sign-in only)"
done <<ACCOUNTS
$accounts
ACCOUNTS
# Fail closed: Apache must not start while any local account could log in.
if ! left=$(enabled_local_accounts) || [ -n "$left" ]; then
  echo "portcullis: local accounts still enabled (${left:-listing failed}); not starting the web server" >&2
  exit 1
fi
# <<< local-accounts
# Background jobs run from the nextcloud-cron service.
occ background:cron >/dev/null

# ── Trust the Portcullis CA bundle for the calls to Keycloak ──
# Nextcloud's HTTP client uses its own bundle plus imported certificates; the
# import keeps the whole file. The leading comment line is needed: Nextcloud
# skips an imported file whose first bytes are "-----BEGIN".
if grep -q 'BEGIN CERTIFICATE' /portcullis/ca-bundle.crt 2>/dev/null; then
  { echo "# Portcullis CA bundle (certs/ca-bundle.crt)"; cat /portcullis/ca-bundle.crt; } > /tmp/portcullis-ca.crt
  occ security:certificates:import /tmp/portcullis-ca.crt >/dev/null
  rm -f /tmp/portcullis-ca.crt
fi

# ── user_oidc, pinned (https://github.com/nextcloud/user_oidc) ──
# Upgrade: bump both values together (release asset of
# https://github.com/nextcloud-releases/user_oidc/releases; check the
# <nextcloud min-version/max-version> of appinfo/info.xml against the image).
UO_VERSION=8.11.0
UO_SHA256=887920504c2f0e0d055abd66225ee7b66d756f50fe5a3739779d6b2ce108633f
UO_URL="https://github.com/nextcloud-releases/user_oidc/releases/download/v$UO_VERSION/user_oidc-v$UO_VERSION.tar.gz"
UO_DIR=/var/www/html/custom_apps/user_oidc
current=$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' "$UO_DIR/appinfo/info.xml" 2>/dev/null | head -n 1 || true)
if [ "$current" != "$UO_VERSION" ]; then
  echo "portcullis: installing user_oidc $UO_VERSION (found '${current:-none}')"
  tmp=$(mktemp -d)
  php -r 'exit(copy($argv[1], $argv[2]) ? 0 : 1);' "$UO_URL" "$tmp/user_oidc.tar.gz"
  echo "$UO_SHA256  $tmp/user_oidc.tar.gz" | sha256sum -c - >/dev/null
  mkdir "$tmp/app"
  tar -xzf "$tmp/user_oidc.tar.gz" -C "$tmp/app" --strip-components=1
  rm -rf "$UO_DIR"
  mv "$tmp/app" "$UO_DIR"
  rm -rf "$tmp"
fi
if occ status --output=json | grep -q '"needsDbUpgrade":true'; then
  occ upgrade
fi
occ app:enable user_oidc >/dev/null

# Accounts are created on first SSO login (auto_provision) and keyed on the
# LLDAP username: unique-uid=0 + mapping-uid=preferred_username, so the
# Nextcloud user id IS the username. soft_auto_provision=false: an SSO login
# is never attached to an account of another backend (the disabled local
# accounts), and nothing is ever matched by
# email (LLDAP emails are user-editable; the email claim only fills the
# profile). Single logout is off: the Keycloak client has no post-logout
# redirect URI, so Keycloak would refuse it.
occ config:system:set user_oidc auto_provision --type=boolean --value=true >/dev/null
occ config:system:set user_oidc soft_auto_provision --type=boolean --value=false >/dev/null
occ config:system:set user_oidc single_logout --type=boolean --value=false >/dev/null
# The login page goes straight to Portcullis (/login?direct=1 would show
# the hidden form, but no account can use it).
occ config:app:set user_oidc allow_multiple_user_backends --type=string --value=0 >/dev/null

# Groups: only the instance's access and admin groups are synced (created,
# joined and left at each login); only their members may sign in.
occ user_oidc:provider Portcullis \
  --clientid="$PORTCULLIS_OIDC_CLIENT_ID" \
  --clientsecret-env=NEXTCLOUD_OIDC_SECRET \
  --discoveryuri="https://auth.$PORTCULLIS_DOMAIN/realms/portcullis/.well-known/openid-configuration" \
  --scope="openid email profile" \
  --unique-uid=0 \
  --mapping-uid=preferred_username \
  --mapping-display-name=name \
  --mapping-email=email \
  --mapping-groups=groups \
  --group-provisioning=1 \
  --group-whitelist-regex="/^($PORTCULLIS_ACCESS_GROUP|$PORTCULLIS_ADMIN_GROUP)\$/" \
  --group-restrict-login-to-whitelist=1 \
  --check-bearer=0 \
  --bearer-provisioning=0 \
  --send-id-token-hint=1 >/dev/null
echo "portcullis: Nextcloud configured for https://$HOST (OIDC client $PORTCULLIS_OIDC_CLIENT_ID)"
