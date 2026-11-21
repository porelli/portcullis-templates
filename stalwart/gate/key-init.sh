#!/bin/sh
# The key-init job: prepares adapter_key, the volume that holds Stalwart's
# API key and nothing else (Rulings T17-a, T17-e; review L10), and
# viewer_key, the read-only admin view's password alone (contract §19.13).
# Runs in the pinned adapter image as root with primary gid 2010 (mailkey)
# and 2011 (mailview) added, no capability, no network, a read-only root.
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
# (0640, group mailkey) and the adapter reads it read-only. viewer_key gets
# the same treatment with group 2011, and is never left empty (below: the
# rootless Podman chown).
set -eu
# prepare <dir> <file> <gid>: the volume at dir carries file alone, group
# gid, mode 2770.
prepare() {
  K=$1 F=$2 G=$3
  for f in "$K"/* "$K"/.[!.]* "$K"/..?*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    [ "$f" = "$K/$F" ] && [ -f "$f" ] && [ ! -L "$f" ] && continue
    echo "key-init: the key volume $K holds $(basename "$f"): refused (it carries only $F)" >&2
    exit 1
  done
  read -r owner group mode <<EOF
$(stat -c '%u %g %a' "$K")
EOF
  if [ "$group" = "$G" ] && [ "$mode" = 2770 ]; then
    return 0
  fi
  if [ "$owner" = 0 ]; then
    chgrp "$G" "$K"
    chmod 2770 "$K"
    return 0
  fi
  echo "key-init: the key volume $K is $owner:$group mode $mode (want group $G, mode 2770): refused" >&2
  exit 1
}
prepare /run/portcullis/key-init api-key 2010
# The viewer key volume (contract §19.13): the read-only admin view's
# password alone, group 2011 (mailview: the bootstrap job writes it, the
# admin-view service reads it; the adapter never mounts it).
prepare /run/portcullis/viewer-init viewer-password 2011
# Rootless Podman chowns an EMPTY volume to every container that mounts
# it, to that container's uid and PRIMARY gid: the bootstrap job (2000:2010)
# would turn viewer_key into 2000:2010, a group the admin view isn't in and
# one this job can't chgrp back (it isn't the owner), so the next start is
# refused. adapter_key survives that (its group is the job's primary gid);
# viewer_key must never be empty after this job: an empty viewer-password
# placeholder (root:2011 0640 through the setgid directory). The job reads
# an empty file as "no password" (it sets one and renames it over the
# placeholder); admin-view starts only after the job.
if [ ! -e /run/portcullis/viewer-init/viewer-password ]; then
  ( umask 0027; : > /run/portcullis/viewer-init/viewer-password )
  chmod 0640 /run/portcullis/viewer-init/viewer-password
fi
