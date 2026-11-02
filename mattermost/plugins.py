#!/usr/bin/env python3
"""mattermost-plugins (Portcullis): pinned, signed plugin bundles before Mattermost starts.

Plugin uploads stay off and Mattermost requires plugin signatures
(MM_PLUGINSETTINGS_REQUIREPLUGINSIGNATURE true). The pinned bundles below
are GitHub release assets that upstream doesn't sign, so this one-shot, at
every start:

1. downloads each bundle (or reuses the file-store copy) and checks it
   against its pinned SHA-256; a mismatch fails the job (Mattermost depends
   on it and doesn't start);
2. generates a fresh OpenPGP signing key in a tmpfs GNUPGHOME (never on a
   volume; gone when the job exits), signs each verified bundle
   (<id>.tar.gz.sig next to it in Mattermost's file store, from which
   Mattermost installs plugins at startup, app/plugin.go syncPlugins), and
   writes only the PUBLIC key to the plugin-keys volume, which Mattermost
   mounts read-only (MM_PLUGINSETTINGS_SIGNATUREPUBLICKEYFILES).

Every start makes a new key, so any other bundle or a signature from an
earlier key doesn't verify and Mattermost refuses it. Mattermost-signed
bundles still verify with Mattermost's built-in key.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

DATA_DIR = "/mattermost/data"
PLUGIN_DIR = os.path.join(DATA_DIR, "plugins")
KEY_DIR = "/portcullis/keys"
PUBLIC_KEY = os.path.join(KEY_DIR, "portcullis-plugins.gpg")
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


def own(path: str, mode: int) -> None:
    os.chown(path, MM_UID, MM_GID)
    os.chmod(path, mode)


def fetch(pid: str, version: str, url: str, sha256: str) -> str:
    dest = os.path.join(PLUGIN_DIR, f"{pid}.tar.gz")
    if os.path.exists(dest) and sha256_of(dest) == sha256:
        log(f"{pid} {version} present (sha256 verified)")
        return dest
    fd, tmp = tempfile.mkstemp(dir=PLUGIN_DIR, prefix=".portcullis-")
    h = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=120) as resp:
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                h.update(chunk)
                out.write(chunk)
        if h.hexdigest() != sha256:
            die(f"{pid}: sha256 {h.hexdigest()} != pinned {sha256}")
        own(tmp, 0o640)
        os.replace(tmp, dest)
    except OSError as e:
        die(f"download of {url} failed: {e}")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    log(f"{pid} {version} written to the file store (sha256 verified)")
    return dest


def gpg(home: str, *args: str) -> None:
    # No secret on argv: the key has no passphrase and lives only in the
    # tmpfs GNUPGHOME.
    subprocess.run(["gpg", "--batch", "--quiet", "--homedir", home, *args], check=True,
                   stdin=subprocess.DEVNULL)


def main() -> None:
    # Runs as root only for ownership: on a fresh volume this job is the
    # first writer, so the data directory (and what it writes) is handed to
    # Mattermost's uid.
    if os.stat(DATA_DIR).st_uid != MM_UID:
        os.chown(DATA_DIR, MM_UID, MM_GID)
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    os.chown(PLUGIN_DIR, MM_UID, MM_GID)

    bundles = [(pid, fetch(pid, version, url, sha256)) for pid, version, url, sha256 in PLUGINS]
    # Re-check right before signing: only the pinned bytes get a signature.
    for (pid, path), (_, _, _, sha256) in zip(bundles, PLUGINS):
        if sha256_of(path) != sha256:
            die(f"{pid}: file-store copy changed before signing")

    home = tempfile.mkdtemp(dir="/tmp", prefix="gnupg-")
    try:
        os.chmod(home, 0o700)
        instance = os.environ.get("PORTCULLIS_INSTANCE", "mattermost")
        gpg(home, "--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key",
            f"Portcullis plugin signing ({instance}) <plugins@{instance}.invalid>", "rsa3072", "sign", "never")
        for pid, path in bundles:
            sig = path + ".sig"
            tmp = sig + ".portcullis-tmp"
            gpg(home, "--yes", "--digest-algo", "SHA256", "--output", tmp, "--detach-sign", path)
            own(tmp, 0o640)
            os.replace(tmp, sig)
        os.makedirs(KEY_DIR, exist_ok=True)
        tmp = PUBLIC_KEY + ".portcullis-tmp"
        gpg(home, "--yes", "--output", tmp, "--export")
        own(tmp, 0o644)
        os.replace(tmp, PUBLIC_KEY)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    log(f"{len(bundles)} bundles signed with a fresh key; public key {PUBLIC_KEY}; private key discarded")


if __name__ == "__main__":
    main()
