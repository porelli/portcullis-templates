#!/bin/sh
# fxa-db-guard, one-shot at every start, after fxa-migrations and before
# fxa-policy (porelli's fxa-init): the accounts database compares emails
# byte for byte. porelli/firefox-sync does it itself since 68ea7b8 (the
# allowlist's column utf8mb4_bin, its routines in utf8mb4_bin, TRIM + LOWER,
# beyond ASCII only an entry that spells it out); this stays as defence in
# depth, and doesn't get in its way: the table is made here with porelli's
# DDL and the column changed with porelli's own ALTER, so fxa-policy finds
# it utf8mb4 / utf8mb4_bin already and converts nothing (allowlistBinary
# looks at the column first). Running it again changes nothing.
#
# Why: MySQL 9's default collation (utf8mb4_0900_ai_ci) is accent- and
# width-insensitive. Under it the sign-up allowlist's row alice@example.org
# also admits alice@exámple.org and alice@ｅxample.org (fxa-auth accepts an
# IDN domain), so someone outside the access group could sign up with a
# look-alike domain of a member's address. Two layers, idempotent:
#
# (a) The ffs database's default collation and the allowlist's column are
#     utf8mb4_bin. fxa-policy runs next and makes its routines again (DROP +
#     CREATE at every start); a routine's parameters and variables take the
#     database's collation when it is made, so ffs.signup_refusal compares
#     entry = normalized byte for byte, and so does the sign-up gate's query
#     (the column's collation wins over its parameter's). The table is made
#     here first, with porelli's DDL (68ea7b8), when it doesn't exist yet.
# (b) Triggers on fxa.accounts and fxa.emails refuse an email or
#     normalizedEmail that isn't plain ASCII, on insert and on any update
#     that changes one (an account already stored is never locked out of its
#     other updates). A look-alike can then never become an account, under
#     any collation.
# (c) Accounts stored before (b), or behind its back: every account whose
#     email or normalizedEmail, or any of whose fxa.emails rows, isn't plain
#     ASCII is disabled (disabledAt kept when already set) and signed out
#     everywhere, as ffs.disable_account / ffs.sign_out_all do it
#     (fxa.revokeAccountTokens_1, then its OAuth codes, refresh and access
#     tokens). Only the count is logged, never an address; the start goes on.
#
# The SQL goes to mysql on stdin and the root password in MYSQL_PWD: no
# secret in argv. Fails closed: any error (the check of (c) included) stops
# the job, and fxa-policy and the accounts services don't start.
#
# Environment: MYSQL_HOST, MYSQL_PWD (root).
set -eu

# ascii <expr>: true when the expression holds a character beyond ASCII
# (whatever the column's character set: counted in utf8mb4).
nonascii() { printf 'CHAR_LENGTH(CONVERT(%s USING utf8mb4)) <> LENGTH(CONVERT(%s USING utf8mb4))' "$1" "$1"; }
changed() { printf 'NOT (CAST(NEW.%s AS BINARY) <=> CAST(OLD.%s AS BINARY))' "$1" "$1"; }
MSG="SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Portcullis: an account email must be plain ASCII'"

trigger() {  # $1 table, $2 INSERT | UPDATE
  name="portcullis_ascii_email_$1_$(echo "$2" | tr 'A-Z' 'a-z')"
  if [ "$2" = INSERT ]; then
    cond="$(nonascii NEW.email) OR $(nonascii NEW.normalizedEmail)"
  else
    cond="($(changed email) AND $(nonascii NEW.email)) OR ($(changed normalizedEmail) AND $(nonascii NEW.normalizedEmail))"
  fi
  printf 'DROP TRIGGER IF EXISTS fxa.%s//\n' "$name"
  printf 'CREATE TRIGGER fxa.%s BEFORE %s ON fxa.%s FOR EACH ROW\nBEGIN\n  IF %s THEN\n    %s;\n  END IF;\nEND//\n' \
    "$name" "$2" "$1" "$cond" "$MSG"
}

sql() { mysql --no-defaults --protocol=tcp -h "${MYSQL_HOST:?}" -u root --batch --silent --skip-column-names; }

{
  echo "CREATE DATABASE IF NOT EXISTS ffs CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"
  echo "ALTER DATABASE ffs CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"
  echo "CREATE TABLE IF NOT EXISTS ffs.signup_allowlist (entry VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
  echo "ALTER TABLE ffs.signup_allowlist MODIFY entry VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;"
  echo "DELIMITER //"
  for t in accounts emails; do
    trigger "$t" INSERT
    trigger "$t" UPDATE
  done
  echo "DELIMITER ;"
} | sql

# (c): the uids, as 32 hex digits (nothing else reaches the next SQL).
uids=$(printf 'SELECT DISTINCT LOWER(HEX(uid)) FROM (SELECT uid FROM fxa.accounts WHERE %s OR %s UNION SELECT uid FROM fxa.emails WHERE %s OR %s) AS x;\n' \
  "$(nonascii email)" "$(nonascii normalizedEmail)" "$(nonascii email)" "$(nonascii normalizedEmail)" | sql)
n=0
for u in $uids; do
  case "$u" in
    *[!0-9a-f]* | "") echo "db-guard: an unexpected uid from the check: stopping" >&2; exit 1 ;;
  esac
  [ "${#u}" = 32 ] || { echo "db-guard: an unexpected uid from the check: stopping" >&2; exit 1; }
  printf '%s\n' \
    "UPDATE fxa.accounts SET disabledAt = FLOOR(UNIX_TIMESTAMP(NOW(3)) * 1000) WHERE uid = UNHEX('$u') AND disabledAt IS NULL;" \
    "CALL fxa.revokeAccountTokens_1(UNHEX('$u'));" \
    "START TRANSACTION;" \
    "DELETE FROM fxa_oauth.codes WHERE userId = UNHEX('$u');" \
    "DELETE FROM fxa_oauth.refreshTokens WHERE userId = UNHEX('$u');" \
    "DELETE FROM fxa_oauth.tokens WHERE userId = UNHEX('$u');" \
    "COMMIT;" | sql
  n=$((n + 1))
done

echo "db-guard: ffs compares emails byte for byte (utf8mb4_bin); fxa.accounts and fxa.emails take plain ASCII emails only; $n accounts with a non-ASCII email disabled and signed out"
