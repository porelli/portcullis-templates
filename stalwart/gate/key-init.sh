#!/bin/sh
# The key-init job: prepares adapter_key, the volume that holds Stalwart's
# API key and nothing else (Rulings T17-a, T17-e; review L10). Runs in the
# pinned adapter image as root with primary gid 2010 (mailkey), no
# capability, no network, a read-only root.
#
# No service mounts adapter_key at a path its image contains (key-init at
# /run/portcullis/key-init, bootstrap and the adapter at
# /run/portcullis/stalwart-key), so no runtime copies an image directory's
# owner into it: a fresh volume is root's on Docker; rootless Podman chowns
# an EMPTY volume to whichever container mounts it (root:2010 here,
# 2000:2010 when the bootstrap job mounts it). Ruling T17-e: key-init is
# idempotent:
#   - anything but a regular file api-key in the volume: refused (the key
#     volume carries the key alone);
#   - already group 2010 and mode 2770 (owner root, or the bootstrap job's
#     2000 after a Podman chown): nothing to do;
#   - owned by root (this job): chgrp 2010 and chmod 2770 as the owner (no
#     CHOWN or FOWNER needed);
#   - anything else: refused (fail closed).
# The bootstrap job (uid 2000, primary gid 2010) then writes the key there
# (0640, group mailkey) and the adapter reads it read-only.
set -eu
K=/run/portcullis/key-init
for f in "$K"/* "$K"/.[!.]* "$K"/..?*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  [ "$f" = "$K/api-key" ] && [ -f "$f" ] && [ ! -L "$f" ] && continue
  echo "key-init: the key volume holds $(basename "$f"): refused (it carries only api-key)" >&2
  exit 1
done
read -r owner group mode <<EOF
$(stat -c '%u %g %a' "$K")
EOF
if [ "$group" = 2010 ] && [ "$mode" = 2770 ]; then
  exit 0
fi
if [ "$owner" = 0 ]; then
  chgrp 2010 "$K"
  chmod 2770 "$K"
  exit 0
fi
echo "key-init: the key volume is $owner:$group mode $mode (want group 2010, mode 2770): refused" >&2
exit 1
