#!/bin/sh
# Portcullis: nextcloud-cron service (runs as www-data on the shared volume).
# - Nextcloud background jobs (cron.php) every 5 minutes, as upstream
#   recommends for Docker (https://github.com/nextcloud/docker#cron).
# - Admin mapping every minute: Nextcloud's administrators are the members
#   of its "admin" group, and user_oidc can only sync groups under their
#   OIDC names. So members of the instance's admin group (synced at each SSO
#   login) are added to "admin", and SSO accounts (backend user_oidc) that
#   are no longer in it are removed. Local accounts are never made admins.
# - Local accounts (backend Database) are disabled every minute, so an
#   account created in the Users page can't keep a usable password (setup.sh
#   does the same at every start; no password login, see the manifest).
set -u

: "${PORTCULLIS_ADMIN_GROUP:?}"
occ() { php /var/www/html/occ "$@"; }

sync_admins() {
  occ group:list --output=json 2>/dev/null | php -r '
    $g = json_decode(stream_get_contents(STDIN), true);
    if (!is_array($g)) exit(1);
    $want = $g[getenv("PORTCULLIS_ADMIN_GROUP")] ?? [];
    $have = $g["admin"] ?? [];
    foreach (array_diff($want, $have) as $u) echo "add $u\n";
    foreach (array_diff($have, $want) as $u) echo "del $u\n";
  ' | while read -r op user; do
    case "$op" in
      add)
        occ group:adduser admin "$user" >/dev/null && echo "portcullis: $user is now a Nextcloud admin" ;;
      del)
        if occ user:info "$user" --output=json 2>/dev/null | grep -q '"backend":"user_oidc"'; then
          occ group:removeuser admin "$user" >/dev/null && echo "portcullis: $user is no longer a Nextcloud admin"
        fi ;;
    esac
  done
}

disable_local_accounts() {
  occ user:list --info --limit=0 --output=json 2>/dev/null | php -r '
    $u = json_decode(stream_get_contents(STDIN), true);
    if (!is_array($u)) exit(1);
    foreach ($u as $id => $i) if (($i["backend"] ?? "") === "Database" && !empty($i["enabled"])) echo $id, "\n";
  ' | while read -r id; do
    occ user:disable "$id" >/dev/null && echo "portcullis: disabled local account $id (Portcullis sign-in only)"
  done
}

i=0
while :; do
  status=$(occ status --output=json 2>/dev/null || true)
  if echo "$status" | grep -q '"installed":true' \
      && echo "$status" | grep -q '"maintenance":false' \
      && echo "$status" | grep -q '"needsDbUpgrade":false'; then
    if [ $((i % 5)) -eq 0 ]; then
      php -f /var/www/html/cron.php || echo "portcullis: cron.php failed" >&2
    fi
    disable_local_accounts || echo "portcullis: disabling local accounts failed" >&2
    sync_admins || echo "portcullis: admin sync failed" >&2
  fi
  i=$((i + 1))
  sleep 60
done
