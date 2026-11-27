#!/bin/sh
# The accounts database's least-privilege users for the internet-facing
# accounts services, at every start (porelli/firefox-sync's own-server model,
# docs/reference/database-users.md "The accounts", with the grants narrowed
# to what a running service needs; root stays with the one-shots
# fxa-migrations and fxa-policy):
#
#   fxa_auth     fxa-auth     SELECT, INSERT, UPDATE, DELETE, EXECUTE on
#                             fxa, fxa_oauth and pushbox
#   fxa_profile  fxa-profile  the same on fxa_profile
#
# and, after fxa-policy (porelli's fxa-init) made ffs_access, the user of
# fxa-access-sync: its EXECUTE on ffs.delete_account_by_email taken away.
# What is left is what access-sync.sh needs: SELECT, INSERT, DELETE on
# ffs.signup_allowlist and EXECUTE on ffs.disable_account_by_email /
# ffs.enable_account_by_email / ffs.disable_accounts_not_allowed (the sweep,
# made with ADMIN_ACCESS_EXTERNAL only) (IF EXISTS: a grant already gone is
# fine; a missing ffs_access fails the job).
#
# Nothing else: no GRANT OPTION, no server-wide privilege (SUPER, EVENT,
# CREATE USER, FILE), no TRIGGER, CREATE ROUTINE, ALTER ROUTINE or DDL, and
# no right on ffs (the sign-up policy, the allowlist and its procedures).
# Mozilla's procedures run with their definer's rights (the migrations'
# root), so EXECUTE is enough for them.
#
# Every start: CREATE USER IF NOT EXISTS, the password set again (a rotated
# secret applies), every grant revoked, then exactly the ones above. The SQL
# goes to mysql on stdin and the root password in MYSQL_PWD: no secret in
# argv. A password with anything but [A-Za-z0-9_-] is refused (the Hub
# generates hex), so it is a plain SQL literal. Fails closed: any error stops
# the job, and the accounts services don't start.
#
# Environment: MYSQL_HOST, MYSQL_PWD (root), FXA_AUTH_DB_PASSWORD,
# FXA_PROFILE_DB_PASSWORD.
set -eu

plain() {  # $1 name, $2 value
  case "$2" in
    "" | *[!A-Za-z0-9_-]*) echo "db-users: $1 must be set, letters, digits, _ and - only" >&2; exit 1 ;;
  esac
}
plain FXA_AUTH_DB_PASSWORD "${FXA_AUTH_DB_PASSWORD:-}"
plain FXA_PROFILE_DB_PASSWORD "${FXA_PROFILE_DB_PASSWORD:-}"

user() {  # $1 user, $2 password, $3... databases
  u=$1 p=$2
  shift 2
  printf "CREATE USER IF NOT EXISTS '%s'@'%%' IDENTIFIED BY '%s';\n" "$u" "$p"
  printf "ALTER USER '%s'@'%%' IDENTIFIED BY '%s';\n" "$u" "$p"
  printf "REVOKE ALL PRIVILEGES, GRANT OPTION FROM '%s'@'%%';\n" "$u"
  for db in "$@"; do
    # M3: escape _ in database names so the grant isn't a wildcard match
    escaped=$(printf '%s' "$db" | sed 's/_/\\_/g')
    printf "GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON \`%s\`.* TO '%s'@'%%';\n" "$escaped" "$u"
  done
}

{
  user fxa_auth "$FXA_AUTH_DB_PASSWORD" fxa fxa_oauth pushbox
  user fxa_profile "$FXA_PROFILE_DB_PASSWORD" fxa_profile
  printf "REVOKE IF EXISTS EXECUTE ON PROCEDURE ffs.delete_account_by_email FROM 'ffs_access'@'%%';\n"
} | mysql --protocol=tcp -h "${MYSQL_HOST:?}" -u root --batch --silent

echo "db-users: fxa_auth (fxa, fxa_oauth, pushbox) and fxa_profile (fxa_profile) set; ffs_access narrowed (no delete_account_by_email)"
