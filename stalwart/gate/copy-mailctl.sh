#!/bin/sh
# The adapter-bin job: copies the pinned adapter image's static mailctl
# binary (and the web admin bundle) into the mailctl_bin volume, which the
# bootstrap job and the server mount read-only (`mailctl bootstrap --job` must run next to Stalwart, in the
# Stalwart image). Runs as the image's uid 10010, no network, on every start:
# the copy always matches the pinned image (written aside, then renamed).
set -eu
umask 022
cp /usr/local/bin/mailctl /data/.mailctl.new
chmod 0755 /data/.mailctl.new
mv -f /data/.mailctl.new /data/mailctl
# The web admin bundle pinned in the same image (contract §19.13): Stalwart
# loads it from here (file://), never from the internet.
cp /usr/share/mailctl/webui.zip /data/.webui.zip.new
chmod 0644 /data/.webui.zip.new
mv -f /data/.webui.zip.new /data/webui.zip
chmod 0755 /data
