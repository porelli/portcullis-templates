#!/bin/sh
# gitea-migrate (every start, before gitea-auth and gitea): database schema
# and the locked break-glass admin. Runs as the image's git user after the
# image's entrypoint has written app.ini from the GITEA__* variables.
#
# Break-glass admin: Gitea makes the first account it creates a site admin,
# and never demotes the last admin when it syncs the admin group. Without a
# local admin, the first SSO user (whatever their groups) would become
# admin for good. This account exists first, so admin rights only ever
# come from the admin group. Its random password is discarded (never
# printed or stored) and gitea-auth sets prohibit_login on it at every
# start; there is no password sign-in anyway.
#
# Hook admin (AI support, portcullis/mcp-token.sh): Gitea's CLI can't list
# or delete access tokens, its API can, but only for an admin that may sign
# in (prohibit_login refuses every API call) and only with HTTP Basic. The
# mint/revoke hooks therefore use portcullis-hooks, an admin with a
# discarded random password and no way in but an access token: no password
# form, no basic auth with a password, no SSH key, no external login (the
# OAuth2 source never links an account by name). Tokens for it are only
# ever minted inside the gitea container, one per hook run, deleted by the
# same run. It never runs an AI tool call (those run as the person).
set -eu

APP_INI="${GITEA_APP_INI:-/etc/gitea/app.ini}"
# Keep in sync with auth.sh.
BREAKGLASS=portcullis-breakglass
HOOKS=portcullis-hooks

gitea -c "$APP_INI" migrate

users=$(gitea -c "$APP_INI" admin user list)
if printf '%s\n' "$users" | awk -v u="$BREAKGLASS" 'NR > 1 && tolower($2) == u { found = 1 } END { exit !found }'; then
  echo "gitea-migrate: break-glass admin $BREAKGLASS present"
else
  # stdout carries the generated password: discard it.
  gitea -c "$APP_INI" admin user create \
    --username "$BREAKGLASS" \
    --email "$BREAKGLASS@noreply.invalid" \
    --admin \
    --random-password \
    --random-password-length 64 \
    --must-change-password >/dev/null
  echo "gitea-migrate: created break-glass admin $BREAKGLASS (password discarded, login prohibited)"
fi

# Columns: ID Username Email IsActive IsAdmin 2FA Type. An existing
# account of that name must be the admin this script created: one that
# isn't an admin came from somewhere else (gitea-auth also checks its
# login source, which this CLI doesn't show, and demotes a foreign one).
hooks_admin=$(printf '%s\n' "$users" | awk -v u="$HOOKS" 'NR > 1 && tolower($2) == u { print $5; exit }')
if [ "$hooks_admin" = true ]; then
  echo "gitea-migrate: hook admin $HOOKS present"
elif [ -n "$hooks_admin" ]; then
  echo "gitea-migrate: an account named $HOOKS exists but is not the hook admin; refusing to start. Delete it (gitea admin user delete --username $HOOKS), then restart" >&2
  exit 1
else
  gitea -c "$APP_INI" admin user create \
    --username "$HOOKS" \
    --email "$HOOKS@noreply.invalid" \
    --admin \
    --random-password \
    --random-password-length 64 \
    --must-change-password=false >/dev/null
  echo "gitea-migrate: created hook admin $HOOKS (password discarded, tokens only)"
fi
