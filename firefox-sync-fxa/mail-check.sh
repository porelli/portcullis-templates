#!/bin/sh
# fxa-mail-check (one-shot, every start, no network): validates the mail
# settings with the same mail-select.sh fxa-auth sources, so the auth server
# never starts without a mail server it can send the sign-up and sign-in
# codes through. Exit 1 (its line on stderr) keeps fxa-auth from starting;
# exit 0 prints which server and how, never a user or a password.
set -u
# shellcheck source=mail-select.sh
. /portcullis-bin/mail-select.sh || exit 1
case "$SMTP_SECURE" in
  true) how="TLS" ;;
  *) how="STARTTLS" ;;
esac
# _pm_what: set by mail-select.sh.
# shellcheck disable=SC2154
echo "portcullis: mail: $_pm_what ($SMTP_HOST:$SMTP_PORT, $how)"
exit 0
