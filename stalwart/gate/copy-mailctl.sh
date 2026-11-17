#!/bin/sh
# The adapter-bin job: copies the pinned adapter image's static mailctl
# binary into the mailctl_bin volume, which the bootstrap job mounts
# read-only (`mailctl bootstrap --job` must run next to Stalwart, in the
# Stalwart image). Runs as the image's uid 10010, no network, on every start:
# the copy always matches the pinned image (written aside, then renamed).
set -eu
umask 022
cp /usr/local/bin/mailctl /data/.mailctl.new
chmod 0755 /data/.mailctl.new
mv -f /data/.mailctl.new /data/mailctl
chmod 0755 /data
