#!/bin/sh
# gitea-auth (every start, after gitea-migrate, before gitea): the
# Portcullis OAuth2 authentication source, written into Gitea's database.
#
# Why SQL and not `gitea admin auth add-oauth`: the CLI only takes the
# client secret as --secret on argv (readable in the host's process list),
# and it fetches the OIDC discovery document while creating the source,
# from a container that is not on portcullis-proxy. psql reads every value
# from the environment (\getenv), so nothing secret reaches argv or a log.
# The JSON is Gitea's oauth2.Source (services/auth/source/oauth2/source.go,
# v28.3.0); login_source.type 6 = OAuth2. Gitea loads sources when it
# starts, which is after this job.
#
# Access: RequiredClaimName/Value = the groups claim must contain the
# instance's access group, checked by Gitea at every login. Admin: Gitea
# sets or clears the site-admin flag from the admin group at every login.
# Fails closed: any error stops the chain, so Gitea (and its router) never
# starts half-configured.
set -eu

: "${GITEA_OIDC_SECRET:?GITEA_OIDC_SECRET is empty}"
: "${GITEA_OIDC_CLIENT_ID:?GITEA_OIDC_CLIENT_ID is empty}"
: "${GITEA_OIDC_DISCOVERY_URL:?GITEA_OIDC_DISCOVERY_URL is empty}"
: "${GITEA_ACCESS_GROUP:?GITEA_ACCESS_GROUP is empty}"
: "${GITEA_ADMIN_GROUP:?GITEA_ADMIN_GROUP is empty}"

# Display name and URL segment of the source: the redirect URI is
# https://<host>/user/oauth2/Portcullis/callback (manifest keycloak_clients).
export GITEA_AUTH_SOURCE=Portcullis
# Keep in sync with setup.sh.
export GITEA_BREAKGLASS_USER=portcullis-breakglass
export GITEA_HOOKS_USER=portcullis-hooks

psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
\getenv oidc_secret GITEA_OIDC_SECRET
\getenv client_id GITEA_OIDC_CLIENT_ID
\getenv discovery_url GITEA_OIDC_DISCOVERY_URL
\getenv access_group GITEA_ACCESS_GROUP
\getenv admin_group GITEA_ADMIN_GROUP
\getenv source_name GITEA_AUTH_SOURCE
\getenv breakglass GITEA_BREAKGLASS_USER
\getenv hooks GITEA_HOOKS_USER
BEGIN;
INSERT INTO login_source (type, name, is_active, is_sync_enabled, two_factor_policy, cfg, created_unix, updated_unix)
VALUES (6, :'source_name', true, false, '', json_build_object(
    'Provider', 'openidConnect',
    'ClientID', :'client_id',
    'ClientSecret', :'oidc_secret',
    'OpenIDConnectAutoDiscoveryURL', :'discovery_url',
    'CustomURLMapping', NULL,
    'IconURL', '',
    -- openid is always added; groups is a default scope of the client.
    'Scopes', json_build_array('profile', 'email'),
    'RequiredClaimName', 'groups',
    'RequiredClaimValue', :'access_group',
    'GroupClaimName', 'groups',
    'AdminGroup', :'admin_group',
    'GroupTeamMap', '',
    'GroupTeamMapRemoval', false,
    'RestrictedGroup', '',
    'SSHPublicKeyClaimName', '',
    'FullNameClaimName', '',
    -- empty: accounts are keyed on the OIDC sub
    'ExternalIDClaim', ''
  )::text, EXTRACT(EPOCH FROM now())::bigint, EXTRACT(EPOCH FROM now())::bigint)
ON CONFLICT (name) DO UPDATE SET
  type = EXCLUDED.type, is_active = true, is_sync_enabled = false,
  two_factor_policy = '', cfg = EXCLUDED.cfg, updated_unix = EXCLUDED.updated_unix;
-- Only Portcullis signs users in: any other source (added in the admin
-- panel) would bypass the access group, so it is switched off.
UPDATE login_source SET is_active = false WHERE name <> :'source_name' AND is_active;
-- The break-glass admin keeps Gitea from making the first SSO user admin
-- (setup.sh); it can never sign in.
UPDATE "user" SET is_admin = true, prohibit_login = true WHERE lower_name = lower(:'breakglass');
-- The AI hooks' admin (setup.sh): active and allowed to sign in, since
-- Gitea's API refuses a prohibited account's tokens. Only while it is the
-- local account setup.sh created (login source 0, local login type):
-- an account of that name from any other source (an SSO sign-in after
-- someone deleted it) is demoted and locked instead, and the check below
-- keeps Gitea from starting. Every start removes whatever could be a way
-- in other than a hook token (SSH keys, passkeys, TOTP, external links)
-- and keeps the account private.
UPDATE "user" SET is_admin = true, is_active = true, prohibit_login = false, must_change_password = false,
  visibility = 2
  WHERE lower_name = lower(:'hooks') AND login_source = 0 AND login_type <= 1;
UPDATE "user" SET is_admin = false, prohibit_login = true
  WHERE lower_name = lower(:'hooks') AND NOT (login_source = 0 AND login_type <= 1);
DELETE FROM external_login_user WHERE user_id IN (SELECT id FROM "user" WHERE lower_name = lower(:'hooks'));
DELETE FROM public_key WHERE owner_id IN (SELECT id FROM "user" WHERE lower_name = lower(:'hooks'));
DELETE FROM webauthn_credential WHERE user_id IN (SELECT id FROM "user" WHERE lower_name = lower(:'hooks'));
DELETE FROM two_factor WHERE uid IN (SELECT id FROM "user" WHERE lower_name = lower(:'hooks'));
COMMIT;
SQL

n=$(psql -X -tA -c "SELECT count(*) FROM \"user\" WHERE lower_name = 'portcullis-breakglass' AND is_admin AND prohibit_login")
if [ "$n" != 1 ]; then
  echo "gitea-auth: break-glass admin missing; refusing to start Gitea (the first SSO user would become admin)" >&2
  exit 1
fi
n=$(psql -X -tA -c "SELECT count(*) FROM \"user\" WHERE lower_name = 'portcullis-hooks' AND NOT (login_source = 0 AND login_type <= 1)")
if [ "$n" != 0 ]; then
  echo "gitea-auth: portcullis-hooks is not the local hook admin (another login source); demoted and locked, refusing to start Gitea. Delete that account (gitea admin user delete), then restart" >&2
  exit 1
fi
echo "gitea-auth: OAuth2 source $GITEA_AUTH_SOURCE set (client $GITEA_OIDC_CLIENT_ID, access group $GITEA_ACCESS_GROUP, admin group $GITEA_ADMIN_GROUP)"
