#!/bin/sh
# The adapter's entrypoint (the pinned mailctl image, uid 10010):
# - Stalwart's API key is the bootstrap job's, in the key volume mounted
#   read-only at /run/portcullis/stalwart-key (0640, group mailkey 2010:
#   group_add; Ruling T17-a). mailctl reads <MAILCTL_DATA>/api-key, so that
#   name is a symlink to it in the adapter's own volume.
# - The dqs_key setting arrives as STALWART_DQS_KEY (the instance's .env);
#   mailctl reads it from a file: written to the container's tmpfs (0600),
#   then the variable is dropped from mailctl's environment.
# Then exec mailctl with the given arguments (serve).
set -eu
umask 077
D="${MAILCTL_DATA:-/data}"
K=/run/portcullis/stalwart-key/api-key
if [ "$(readlink "$D/api-key" 2>/dev/null || true)" != "$K" ]; then
  rm -f "$D/api-key"
  ln -s "$K" "$D/api-key"
fi
if [ -n "${STALWART_DQS_KEY:-}" ]; then
  printf '%s' "$STALWART_DQS_KEY" > /tmp/dqs-key
  STALWART_DQS_KEY_FILE=/tmp/dqs-key
  export STALWART_DQS_KEY_FILE
fi
unset STALWART_DQS_KEY
exec mailctl "$@"
