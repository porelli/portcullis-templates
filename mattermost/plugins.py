#!/usr/bin/env python3
"""mattermost-plugins (Portcullis): pinned, signed plugin bundles before Mattermost starts.

Plugin uploads stay off and Mattermost requires plugin signatures
(MM_PLUGINSETTINGS_REQUIREPLUGINSIGNATURE true). The pinned bundles below
are GitHub release assets that upstream doesn't sign, so this one-shot runs
before every compose-managed start of Mattermost (`docker compose up`,
which is what the Hub runs; a plain Docker restart of the Mattermost
container reuses the last signatures and key, which is safe):

1. puts a private copy of each bundle in its own root-only tmpfs directory:
   copied from Mattermost's file store (opened without following symlinks,
   regular files only) when that copy matches, downloaded otherwise; the
   SHA-256 is checked on the private copy, and only that copy is signed,
   so nothing another principal can write between check and sign ever gets
   a signature. Any mismatch, symlink or non-regular file fails the job
   (Mattermost depends on it and doesn't start), before anything is signed;
2. generates a fresh OpenPGP signing key in the same tmpfs (never on a
   volume; gone when the job exits) and signs each private copy, all in
   tmpfs; then the PUBLIC key is placed first (step 3), and only then
   bundle + signature go into the file store (Mattermost installs plugins from
   there at startup, app/plugin.go syncPlugins) with an exclusive temp file
   in the plugins directory, opened by descriptor without following
   symlinks, and a rename; a destination that is a symlink is refused;
3. only the public key leaves the tmpfs, to the plugin-keys volume, which
   Mattermost mounts read-only (MM_PLUGINSETTINGS_SIGNATUREPUBLICKEYFILES).
   Key first, signatures after: an interrupted job leaves old signatures
   that the new key doesn't verify, so Mattermost refuses those plugins
   (fail closed) until the next run completes.

Every start makes a new key, so any other bundle or a signature from an
earlier key doesn't verify and Mattermost refuses it. Mattermost-signed
bundles still verify with Mattermost's built-in key.
"""

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

DATA_DIR = "/mattermost/data"
PLUGIN_DIR_NAME = "plugins"
KEY_DIR = "/portcullis/keys"
PUBLIC_KEY_NAME = "portcullis-plugins.gpg"
MM_UID = MM_GID = 2000   # the mattermost image's user
CHUNK = 1 << 20
DOWNLOAD_DEADLINE = 600   # seconds for each whole download, not just per read

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


def open_dir(parent_fd, name: str) -> int:
    """A directory under parent_fd (None = absolute name), never through a symlink."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as e:
        die(f"{name}: not a plain directory ({e.strerror})")
    return fd


def lexists(dir_fd: int, name: str):
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def copy_stream(src, dst_fd: int, deadline: float = 0.0) -> str:
    """Copy src into dst_fd, returning the SHA-256 of what was written."""
    h = hashlib.sha256()
    with os.fdopen(os.dup(dst_fd), "wb") as out:
        for chunk in iter(lambda: src.read(CHUNK), b""):
            if deadline and time.monotonic() > deadline:
                raise TimeoutError(f"no complete download within {DOWNLOAD_DEADLINE} s")
            h.update(chunk)
            out.write(chunk)
        out.flush()
        os.fsync(out.fileno())
    return h.hexdigest()


def private_copy(store_fd: int, work: str, pid: str, version: str, url: str, sha256: str) -> str:
    path = os.path.join(work, f"{pid}.tar.gz")
    name = f"{pid}.tar.gz"
    st = lexists(store_fd, name)
    if st is not None and not stat.S_ISREG(st.st_mode):
        die(f"{PLUGIN_DIR_NAME}/{name} is not a regular file (symlink or special file): refusing")
    if st is not None:
        try:
            sfd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=store_fd)
        except OSError as e:
            die(f"{PLUGIN_DIR_NAME}/{name}: {e.strerror}: refusing")
        with os.fdopen(sfd, "rb") as src:
            if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
                die(f"{PLUGIN_DIR_NAME}/{name} is not a regular file: refusing")
            dfd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                got = copy_stream(src, dfd)
            finally:
                os.close(dfd)
        if got == sha256:
            log(f"{pid} {version}: file-store copy matches (sha256 verified on the private copy)")
            return path
        os.unlink(path)
    dfd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + DOWNLOAD_DEADLINE
        with urllib.request.urlopen(url, timeout=60) as resp:
            got = copy_stream(resp, dfd, deadline)
    except (OSError, TimeoutError) as e:
        die(f"download of {url} failed: {e}")
    finally:
        os.close(dfd)
    if got != sha256:
        die(f"{pid}: sha256 {got} != pinned {sha256}")
    log(f"{pid} {version}: downloaded (sha256 verified on the private copy)")
    return path


def place(dir_fd: int, name: str, src_path: str, mode: int, uid: int, gid: int) -> None:
    """Atomically put src_path's content at dir_fd/name (exclusive temp + rename)."""
    st = lexists(dir_fd, name)
    if st is not None and not stat.S_ISREG(st.st_mode):
        die(f"destination {name} is not a regular file (symlink?): refusing")
    tmp = f".portcullis-{os.getpid()}-{name}"
    if lexists(dir_fd, tmp) is not None:
        os.unlink(tmp, dir_fd=dir_fd)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    try:
        with open(src_path, "rb") as src:
            copy_stream(src, fd)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
    except BaseException:
        os.close(fd)
        os.unlink(tmp, dir_fd=dir_fd)
        raise
    os.close(fd)
    os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)


def gpg(home: str, *args: str) -> None:
    # No secret on argv: the key has no passphrase and lives only in the
    # tmpfs GNUPGHOME.
    subprocess.run(["gpg", "--batch", "--quiet", "--homedir", home, *args], check=True,
                   stdin=subprocess.DEVNULL)


def main() -> None:
    os.umask(0o077)
    data_fd = open_dir(None, DATA_DIR)
    # Runs as root only for ownership: on a fresh volume this job is the
    # first writer, so the data directory and the plugins directory are
    # handed to Mattermost's uid (by descriptor, never through a symlink).
    if os.fstat(data_fd).st_uid != MM_UID:
        os.fchown(data_fd, MM_UID, MM_GID)
    if lexists(data_fd, PLUGIN_DIR_NAME) is None:
        os.mkdir(PLUGIN_DIR_NAME, 0o750, dir_fd=data_fd)
    store_fd = open_dir(data_fd, PLUGIN_DIR_NAME)
    os.fchown(store_fd, MM_UID, MM_GID)
    key_fd = open_dir(None, KEY_DIR)

    work = tempfile.mkdtemp(dir="/tmp", prefix="portcullis-plugins-")   # 0700, root, tmpfs
    try:
        home = os.path.join(work, "gnupg")
        os.mkdir(home, 0o700)
        with open(os.path.join(home, "gpg-agent.conf"), "w", encoding="utf-8") as f:
            f.write("disable-scdaemon\n")
        # 1. every bundle verified (private copies) before anything is signed
        bundles = [(pid, private_copy(store_fd, work, pid, version, url, sha256))
                   for pid, version, url, sha256 in PLUGINS]
        # 2. a fresh key; sign the private copies; place bundle + signature
        instance = os.environ.get("PORTCULLIS_INSTANCE", "mattermost")
        gpg(home, "--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key",
            f"Portcullis plugin signing ({instance}) <plugins@{instance}.invalid>", "rsa3072", "sign", "never")
        for pid, path in bundles:
            gpg(home, "--passphrase", "", "--pinentry-mode", "loopback", "--digest-algo", "SHA256",
                "--output", path + ".sig", "--detach-sign", path)
        pub = os.path.join(work, PUBLIC_KEY_NAME)
        gpg(home, "--output", pub, "--export")
        # 3. the public key first, then bundles + signatures
        place(key_fd, PUBLIC_KEY_NAME, pub, 0o644, 0, 0)
        for pid, path in bundles:
            place(store_fd, f"{pid}.tar.gz", path, 0o640, MM_UID, MM_GID)
            place(store_fd, f"{pid}.tar.gz.sig", path + ".sig", 0o640, MM_UID, MM_GID)
    finally:
        subprocess.run(["gpgconf", "--homedir", os.path.join(work, "gnupg"), "--kill", "all"],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        shutil.rmtree(work, ignore_errors=True)
    log(f"{len(bundles)} bundles signed with a fresh key; public key {KEY_DIR}/{PUBLIC_KEY_NAME}; private key discarded")


if __name__ == "__main__":
    main()
