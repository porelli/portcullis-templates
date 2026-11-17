#!/bin/sh
# The adapter's entrypoint (the pinned mailctl image, uid 10010). Stalwart's
# API key is MAILCTL_API_KEY_FILE in the key volume, read-only here (0640,
# group mailkey 2010 through group_add; Ruling T17-a). The dqs_key setting
# arrives as STALWART_DQS_KEY (the instance's .env); mailctl reads it from a
# file: written to the container's tmpfs (0600), then the variable is
# dropped from mailctl's environment. Then exec mailctl with the given
# arguments (serve).
set -eu
umask 077
if [ -n "${STALWART_DQS_KEY:-}" ]; then
  printf '%s' "$STALWART_DQS_KEY" > /tmp/dqs-key
  STALWART_DQS_KEY_FILE=/tmp/dqs-key
  export STALWART_DQS_KEY_FILE
fi
unset STALWART_DQS_KEY
exec mailctl "$@"
