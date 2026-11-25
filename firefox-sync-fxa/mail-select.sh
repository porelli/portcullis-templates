# shellcheck shell=sh
# Sourced (". mail-select.sh") by fxa-mail-check (mail-check.sh) and by
# fxa-auth's command before the auth server starts: picks the server the
# accounts' mail (sign-up and sign-in codes, notices) goes through and
# exports the auth server's SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
# SMTP_SECURE and SMTP_SENDER. The status of the "." is 0 when they are set,
# 1 (one line on stderr) when they can't be: fails closed, nothing is ever
# exported half-way.
#
#   MAIL_SOURCE=provider (default): the server's mail provider, the Hub's
#     PORTCULLIS_MAIL_SENDER_* (contracts §19.14: submission on 587 with
#     STARTTLS, password only, one From). All five empty = no provider wired
#     or mail off.
#   MAIL_SOURCE=external: the admin's SMTP server, EXT_SMTP_HOST,
#     EXT_SMTP_PORT (587), EXT_SMTP_SECURITY (starttls | tls), EXT_SMTP_USER,
#     EXT_SMTP_PASSWORD, EXT_SMTP_SENDER (an address).
#   Either source: tls on 587 and starttls on 465 are refused (each port
#   speaks the other mode); any other port takes either.
#
# STARTTLS (the provider, and starttls for an external server) is required,
# never opportunistic: the auth server has no setting for nodemailer's
# requireTLS, so the read-only overlay FXA_SMTP_REQUIRE_TLS_FILE (exactly
# {"smtp":{"requireTLS":true}}) is appended to CONFIG_FILES (the existing
# files kept, the overlay last). Without it, nothing is exported. TLS (465)
# is implicit TLS: SMTP_SECURE=true, no overlay.
#
# The passwords stay in the environment only (never argv, never printed);
# once SMTP_PASS is set, the input variables holding them are unset, so the
# auth server's environment carries the password once. POSIX sh (dash in the
# accounts image, busybox ash in the check).

_pm_refuse() {
  echo "portcullis: no mail: $1" >&2
  return 1
}

# A value without control characters (a line break would split a header).
_pm_plain() {
  case "$1" in
    *[[:cntrl:]]*) return 1 ;;
  esac
  return 0
}

# A host name or IPv4 address: letters, digits, dots and dashes.
_pm_host_ok() {
  case "$1" in
    "" | *[!A-Za-z0-9.-]* | .* | -*) return 1 ;;
  esac
  return 0
}

# A port: 1-65535, decimal, no leading zero.
_pm_port_ok() {
  case "$1" in
    "" | 0* | *[!0-9]*) return 1 ;;
  esac
  [ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# CONFIG_FILES with the requireTLS overlay appended (once).
_pm_require_tls() {
  _pm_f=${FXA_SMTP_REQUIRE_TLS_FILE:-}
  if [ -z "$_pm_f" ] || [ ! -r "$_pm_f" ] || [ "$(cat "$_pm_f")" != '{"smtp":{"requireTLS":true}}' ]; then
    _pm_refuse "STARTTLS can't be required: FXA_SMTP_REQUIRE_TLS_FILE isn't a readable {\"smtp\":{\"requireTLS\":true}}"
    return 1
  fi
  case ",${CONFIG_FILES:-}," in
    *",$_pm_f,"*) _pm_config_files=${CONFIG_FILES:-} ;;
    *) _pm_config_files="${CONFIG_FILES:+$CONFIG_FILES,}$_pm_f" ;;
  esac
  return 0
}

_pm_select() {
  _pm_host="" _pm_port="" _pm_secure="" _pm_user="" _pm_pass="" _pm_sender=""
  case "${MAIL_SOURCE:-provider}" in
    provider)
      if [ -z "${PORTCULLIS_MAIL_SENDER_HOST:-}" ] || [ -z "${PORTCULLIS_MAIL_SENDER_USER:-}" ] \
          || [ -z "${PORTCULLIS_MAIL_SENDER_PASSWORD:-}" ] || [ -z "${PORTCULLIS_MAIL_SENDER_FROM:-}" ]; then
        _pm_refuse "wire a mail provider or set an external SMTP server"
        return 1
      fi
      _pm_host=$PORTCULLIS_MAIL_SENDER_HOST
      _pm_port=${PORTCULLIS_MAIL_SENDER_PORT:-587}
      # The provider's submission listener: STARTTLS (contracts §19.14).
      _pm_secure=false
      _pm_user=$PORTCULLIS_MAIL_SENDER_USER
      _pm_pass=$PORTCULLIS_MAIL_SENDER_PASSWORD
      # Already a name-addr ("Firefox accounts" <portcullis-app-x@domain>).
      _pm_sender=$PORTCULLIS_MAIL_SENDER_FROM
      _pm_what="the server's mail provider"
      ;;
    external)
      if [ -z "${EXT_SMTP_HOST:-}" ] || [ -z "${EXT_SMTP_SENDER:-}" ]; then
        _pm_refuse "the external SMTP server needs a host and a sender address (settings: Mail)"
        return 1
      fi
      _pm_host=$EXT_SMTP_HOST
      _pm_port=${EXT_SMTP_PORT:-587}
      case "${EXT_SMTP_SECURITY:-starttls}" in
        starttls) _pm_secure=false ;;
        tls) _pm_secure=true ;;
        *) _pm_refuse "the SMTP security must be starttls or tls"; return 1 ;;
      esac
      _pm_user=${EXT_SMTP_USER:-}
      _pm_pass=${EXT_SMTP_PASSWORD:-}
      if [ -n "$_pm_user" ] && [ -z "$_pm_pass" ]; then
        _pm_refuse "the external SMTP server has a user but no password"
        return 1
      fi
      if [ -z "$_pm_user" ] && [ -n "$_pm_pass" ]; then
        _pm_refuse "the external SMTP server has a password but no user"
        return 1
      fi
      # A plain address (local@domain.tld, the common characters only):
      # the From becomes a name-addr like the provider's.
      case "$EXT_SMTP_SENDER" in
        *[!A-Za-z0-9._%+@-]* | *@*@* | @* | *@ | *@.* | *..* | *.) ;;
        *@*.*) _pm_sender="Firefox accounts <$EXT_SMTP_SENDER>" ;;
      esac
      if [ -z "$_pm_sender" ]; then
        _pm_refuse "the sender of the external SMTP server isn't an email address"
        return 1
      fi
      _pm_what="the external SMTP server"
      ;;
    *)
      _pm_refuse "the mail source must be provider or external"
      return 1
      ;;
  esac
  _pm_host_ok "$_pm_host" || { _pm_refuse "the SMTP host isn't a host name"; return 1; }
  _pm_port_ok "$_pm_port" || { _pm_refuse "the SMTP port isn't 1-65535"; return 1; }
  # 465 is TLS from the start (RFC 8314), 587 STARTTLS (RFC 6409): the other
  # mode on them only fails at the first code sent. Other ports take either.
  case "$_pm_secure:$_pm_port" in
    true:587) _pm_refuse "port 587 is for STARTTLS, not TLS from the start: choose STARTTLS, or port 465 for TLS (settings: Mail)"; return 1 ;;
    false:465) _pm_refuse "port 465 is for TLS from the start, not STARTTLS: choose TLS, or port 587 for STARTTLS (settings: Mail)"; return 1 ;;
  esac
  _pm_plain "$_pm_user" || { _pm_refuse "the SMTP user holds a control character"; return 1; }
  _pm_plain "$_pm_pass" || { _pm_refuse "the SMTP password holds a control character"; return 1; }
  _pm_plain "$_pm_sender" || { _pm_refuse "the sender holds a control character"; return 1; }
  _pm_config_files=${CONFIG_FILES:-}
  if [ "$_pm_secure" = false ]; then
    _pm_require_tls || return 1
  fi

  SMTP_HOST=$_pm_host
  SMTP_PORT=$_pm_port
  SMTP_SECURE=$_pm_secure
  SMTP_USER=$_pm_user
  SMTP_PASS=$_pm_pass
  SMTP_SENDER=$_pm_sender
  CONFIG_FILES=$_pm_config_files
  export SMTP_HOST SMTP_PORT SMTP_SECURE SMTP_USER SMTP_PASS SMTP_SENDER CONFIG_FILES
  # The password once in the environment (SMTP_PASS).
  unset PORTCULLIS_MAIL_SENDER_PASSWORD EXT_SMTP_PASSWORD _pm_pass
  return 0
}

_pm_select
