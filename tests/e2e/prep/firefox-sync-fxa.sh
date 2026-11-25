#!/usr/bin/env bash
# Sign-in e2e preparation for firefox-sync-fxa (tests/e2e/app_signin.py runs
# tests/e2e/prep/<app>.sh <work dir> before it starts the app).
#
# The accounts server doesn't start without a mail server (fxa-mail-check),
# so the e2e gives the instance one, as an admin would set "Another SMTP
# server": the test SMTP server of tests/apps/firefox-sync-fxa.sh
# (tests/fxa_smtp_catcher.js) with STARTTLS (required) and a certificate of
# a test CA, which the auth server trusts through its CA bundle (core's
# bundle + the test CA, as the Hub's bundle would carry a real server's CA).
# Like the shell test's CI override, ffs-admin reaches auth.<domain> through
# the host's published 443 (CI's public-DNS stand-in is on portcullis-proxy;
# ffs-admin is on the instance's default network only).
#
# Prints NAME=value lines for the app's environment (the SMTP password
# among them: it reaches the containers by environment, never a file or an
# argv) and COMPOSE_OVERRIDE, the compose override with the catcher service.
set -euo pipefail
work="${1:?usage: prep/firefox-sync-fxa.sh <work dir>}"
: "${PROJECT_DIR:?}" "${TEMPLATES_DIR:?}" "${PORTCULLIS_DOMAIN:?}"
cd "$TEMPLATES_DIR"
fxa_image=$(yq -r '.services["fxa-auth"].image' firefox-sync-fxa/compose.yml)
[ -n "$fxa_image" ] && [ "$fxa_image" != null ] || { echo "prep: no fxa-auth image in firefox-sync-fxa/compose.yml" >&2; exit 2; }

tls="$work/tls"
mkdir -p "$tls/catcher"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tls/ca.key" -out "$tls/ca.crt" -days 2 \
  -subj /CN=fxa-e2e-test-ca -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign > /dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$tls/catcher/key.pem" -out "$tls/srv.csr" -subj /CN=fxa-test-smtp > /dev/null 2>&1
printf 'subjectAltName=DNS:fxa-test-smtp\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$tls/ext.cnf"
openssl x509 -req -in "$tls/srv.csr" -CA "$tls/ca.crt" -CAkey "$tls/ca.key" -CAcreateserial -days 2 \
  -extfile "$tls/ext.cnf" -out "$tls/catcher/cert.pem" > /dev/null 2>&1
cat "$PROJECT_DIR/certs/ca-bundle.crt" "$tls/ca.crt" > "$tls/bundle.crt"
# The catcher runs as 10001 and reads its key; nothing else is secret here.
chmod 0755 "$work" "$tls" "$tls/catcher"
chmod 0644 "$tls/catcher/key.pem" "$tls/catcher/cert.pem" "$tls/bundle.crt"
[ -s "$tls/catcher/cert.pem" ] && [ -s "$tls/bundle.crt" ] || { echo "prep: the test certificate wasn't created" >&2; exit 2; }

cat > "$work/override.yml" << EOF
services:
  fxa-test-smtp:
    image: $fxa_image
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp:size=8m
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    mem_limit: 128m
    pids_limit: 32
    entrypoint: [node, /catcher/catcher.js]
    environment:
      CATCHER_USER: fxa-e2e
      CATCHER_PASS: \${EXT_SMTP_PASSWORD:?EXT_SMTP_PASSWORD must be set}
      CATCHER_TLS: "1"
    volumes:
      - $TEMPLATES_DIR/tests/fxa_smtp_catcher.js:/catcher/catcher.js:ro
      - $tls/catcher:/tls:ro
    restart: unless-stopped
  fxa-auth:
    volumes:
      - $tls/bundle.crt:/etc/ssl/certs/portcullis-ca-bundle.crt:ro
  ffs-admin:
    extra_hosts:
      - "auth.$PORTCULLIS_DOMAIN:host-gateway"
EOF

echo "MAIL_SOURCE=external"
echo "EXT_SMTP_HOST=fxa-test-smtp"
echo "EXT_SMTP_PORT=587"
echo "EXT_SMTP_SECURITY=starttls"
echo "EXT_SMTP_USER=fxa-e2e"
echo "EXT_SMTP_PASSWORD=$(openssl rand -hex 24)"
echo "EXT_SMTP_SENDER=fxa-accounts@example.net"
echo "COMPOSE_OVERRIDE=$work/override.yml"
