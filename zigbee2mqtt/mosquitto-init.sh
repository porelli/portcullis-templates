#!/bin/sh
# One-shot before every broker start: the password file (hashed by
# mosquitto_passwd -U) and the ACL, from the instance's generated passwords.
# The passwords only travel through the environment and a 0600 temp file in
# the auth volume (printf is a shell builtin: never on a command line).
# Fails closed: a missing or malformed password stops the start.
set -eu
umask 077

check() {
  case "$2" in
    "") echo "mosquitto-init: $1 is empty" >&2; exit 1 ;;
    *[!A-Za-z0-9]*) echo "mosquitto-init: $1 must be letters and digits only" >&2; exit 1 ;;
  esac
  [ "${#2}" -ge 16 ] || { echo "mosquitto-init: $1 is shorter than 16 characters" >&2; exit 1; }
}
check Z2M_BROKER_PASSWORD "${Z2M_BROKER_PASSWORD:-}"
check Z2M_BROKER_HA_PASSWORD "${Z2M_BROKER_HA_PASSWORD:-}"

dir=/mosquitto/auth
# Never leave a half-written file behind (the plaintext stage included).
trap 'rm -f "$dir/passwd.new" "$dir/acl.new"' EXIT
rm -f "$dir/passwd.new" "$dir/acl.new"
printf 'zigbee2mqtt:%s\nhomeassistant:%s\n' "$Z2M_BROKER_PASSWORD" "$Z2M_BROKER_HA_PASSWORD" > "$dir/passwd.new"
mosquitto_passwd -U "$dir/passwd.new"
# Every line must now be <user>:$<id>$<hash> (never the plaintext).
if grep -qvE '^(zigbee2mqtt|homeassistant):[$]([0-9]+|argon2id)[$]' "$dir/passwd.new"; then
  echo "mosquitto-init: password file is not fully hashed" >&2
  rm -f "$dir/passwd.new"
  exit 1
fi
cp /portcullis/acl "$dir/acl.new"
chown 1883:1883 "$dir/passwd.new" "$dir/acl.new"
chmod 0600 "$dir/passwd.new" "$dir/acl.new"
mv -f "$dir/passwd.new" "$dir/passwd"
mv -f "$dir/acl.new" "$dir/acl"
echo "mosquitto-init: password file and ACL written (users zigbee2mqtt, homeassistant)"
