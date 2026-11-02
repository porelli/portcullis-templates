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
set -eu

APP_INI="${GITEA_APP_INI:-/etc/gitea/app.ini}"
# Keep in sync with auth.sh.
BREAKGLASS=portcullis-breakglass

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
