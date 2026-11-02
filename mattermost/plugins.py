#!/usr/bin/env python3
"""mattermost-plugins (Portcullis): pinned plugin bundles, before Mattermost starts.

Plugin uploads stay off (MM_PLUGINSETTINGS_ENABLEUPLOADS false): no admin,
and no stolen admin session, can put server-side code into Mattermost. The
pinned bundles below are instead written into Mattermost's file store
(/mattermost/data/plugins/<id>.tar.gz), which Mattermost installs from at
every start (app/plugin.go syncPlugins). Each bundle is a GitHub release
asset that must match its SHA-256; a mismatch fails this one-shot, and
Mattermost doesn't start (it depends on this job). mattermost-init enables
them once Mattermost is up.
"""

import hashlib
import os
import sys
import tempfile
import urllib.request

DATA_DIR = "/mattermost/data"
PLUGIN_DIR = os.path.join(DATA_DIR, "plugins")
MM_UID = MM_GID = 2000   # the mattermost image's user

# (plugin id, version, release asset, sha256)
PLUGINS = [
    # Hides Team Edition's upgrade/upsell UI (no config setting does).
    ("freemium", "2.0.0",
     "https://github.com/dy0gu/mattermost-plugin-freemium/releases/download/v2.0.0/freemium.tar.gz",
     "00726f4c3d0e639c1e0d669cc450c039003126f1c712959ed41872126ae64618"),
    # In-channel polls (/poll).
    ("com.github.matterpoll.matterpoll", "1.9.2",
     "https://github.com/matterpoll/matterpoll/releases/download/v1.9.2/com.github.matterpoll.matterpoll-1.9.2.tar.gz",
     "46ff4864a1cc4d754a39f38c6c7c29b20452afa690da34f6c606e9bbd39da416"),
]


def log(msg: str) -> None:
    print(f"portcullis-plugins: {msg}", flush=True)


def die(msg: str) -> None:
    print(f"portcullis-plugins: ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def own(path: str) -> None:
    if os.stat(path).st_uid != MM_UID:
        os.chown(path, MM_UID, MM_GID)


def main() -> None:
    # Runs as root only for ownership: on a fresh volume this job is the
    # first writer, so the data directory (and what it writes) is handed to
    # Mattermost's uid. Nothing else is chowned.
    own(DATA_DIR)
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    own(PLUGIN_DIR)
    for pid, version, url, sha256 in PLUGINS:
        dest = os.path.join(PLUGIN_DIR, f"{pid}.tar.gz")
        if os.path.exists(dest) and sha256_of(dest) == sha256:
            log(f"{pid} {version} present (sha256 verified)")
            continue
        fd, tmp = tempfile.mkstemp(dir=PLUGIN_DIR, prefix=".portcullis-")
        h = hashlib.sha256()
        try:
            with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=120) as resp:
                for chunk in iter(lambda: resp.read(1 << 20), b""):
                    h.update(chunk)
                    out.write(chunk)
            if h.hexdigest() != sha256:
                die(f"{pid}: sha256 {h.hexdigest()} != pinned {sha256}")
            os.chmod(tmp, 0o640)
            os.chown(tmp, MM_UID, MM_GID)
            os.replace(tmp, dest)
        except OSError as e:
            die(f"download of {url} failed: {e}")
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        log(f"{pid} {version} written to the file store (sha256 verified)")


if __name__ == "__main__":
    main()
