#!/bin/sh
# The key-init job: prepares adapter_key, the volume that holds Stalwart's
# API key and nothing else (Ruling T17-a; review L10). Runs in the pinned
# adapter image as its uid 10010 with group_add 2010 (mailkey), no network,
# no capability. The volume takes the image's 10010-owned /data on its
# first mount (Docker's copy-up, Podman's first-mount chown); its owner may
# give it the group it belongs to and the mode without CHOWN or FOWNER:
# 2770 10010:2010, so the bootstrap job (uid 2000, primary gid 2010) writes
# the key there (0640, group mailkey) and the adapter reads it read-only.
# Anything else in the volume fails the start: the key volume carries the
# key alone.
set -eu
chgrp 2010 /data
chmod 2770 /data
for f in /data/* /data/.[!.]* /data/..?*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  [ "$f" = /data/api-key ] && [ -f "$f" ] && [ ! -L "$f" ] && continue
  echo "key-init: the key volume holds $(basename "$f"): refused (it carries only api-key)" >&2
  exit 1
done
