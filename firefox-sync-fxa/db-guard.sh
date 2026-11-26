#!/bin/sh
# fxa-db-guard, one-shot at every start, after fxa-migrations and before
# fxa-policy (porelli's fxa-init): the accounts database compares emails
# byte for byte, until porelli/firefox-sync does it itself.
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
#     here first, with porelli's DDL, when it doesn't exist yet.
# (b) Triggers on fxa.accounts and fxa.emails refuse an email or
#     normalizedEmail that isn't plain ASCII, on insert and on any update
#     that changes one (an account already stored is never locked out of its
#     other updates). A look-alike can then never become an account, under
#     any collation.
#
# The SQL goes to mysql on stdin and the root password in MYSQL_PWD: no
# secret in argv. Fails closed: any error stops the job, and fxa-policy
# and the accounts services don't start.
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

{
  echo "CREATE DATABASE IF NOT EXISTS ffs CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"
  echo "ALTER DATABASE ffs CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"
  echo "CREATE TABLE IF NOT EXISTS ffs.signup_allowlist (entry VARCHAR(255) PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
  echo "ALTER TABLE ffs.signup_allowlist MODIFY entry VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;"
  echo "DELIMITER //"
  for t in accounts emails; do
    trigger "$t" INSERT
    trigger "$t" UPDATE
  done
  echo "DELIMITER ;"
} | mysql --protocol=tcp -h "${MYSQL_HOST:?}" -u root --batch --silent

echo "db-guard: ffs compares emails byte for byte (utf8mb4_bin); fxa.accounts and fxa.emails take plain ASCII emails only"
