#!/usr/bin/env python3
"""homeassistant-init (Portcullis): runs before every Home Assistant start.

1. Onboarding is marked done. Home Assistant's onboarding creates a
   username/password owner account for whoever opens the instance first;
   with Portcullis there is no local password provider (configuration.yaml
   auth_providers: []) and every account comes from OpenID Connect.
2. The auth_oidc custom integration (christiaangoossens/hass-oidc-auth) is
   installed from its pinned release asset into
   /config/custom_components/auth_oidc, replacing whatever is there, after
   its SHA-256 matched. Its Python requirement joserfc (not shipped by Home
   Assistant) is installed the same way, as a pinned wheel, into
   /config/deps, which Home Assistant puts on sys.path, so Home Assistant
   never installs an unpinned copy at runtime.
3. automations.yaml / scripts.yaml / scenes.yaml exist (configuration.yaml
   includes them).

Any failure exits non-zero, and Home Assistant doesn't start (fail closed).
Downloads are cached in /config/.portcullis and re-verified every start.
No secret is read or written here.
"""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

CONFIG = "/config"
CACHE = os.path.join(CONFIG, ".portcullis")

AUTH_OIDC_VERSION = "1.2.1"
AUTH_OIDC_URL = ("https://github.com/christiaangoossens/hass-oidc-auth/releases/download/"
                 f"v{AUTH_OIDC_VERSION}/hass-oidc-auth.zip")
AUTH_OIDC_SHA256 = "e5badaaacaa63cfd6fe733924a05e76d75058836190398598fb24de57cd47ccd"

JOSERFC_VERSION = "1.7.7"
JOSERFC_URL = ("https://files.pythonhosted.org/packages/df/9f/934db284aa22f37af59708e382903860d4b81329c137b1b0ed2745daeb65/"
               f"joserfc-{JOSERFC_VERSION}-py3-none-any.whl")
JOSERFC_SHA256 = "06979cfbab78bc802f14c0358f32969826cc26720e13cb38926ffdc86bc0cb2c"

ONBOARDING_STEPS = ["user", "core_config", "analytics", "integration"]


def log(msg: str) -> None:
    print(f"portcullis-init: {msg}", flush=True)


def die(msg: str) -> None:
    print(f"portcullis-init: ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".portcullis-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def fetch_verified(url: str, sha256: str, name: str) -> bytes:
    """The cached copy if its digest matches, else a fresh download that must match."""
    cached = os.path.join(CACHE, name)
    if os.path.exists(cached):
        with open(cached, "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() == sha256:
            return data
        log(f"cached {name} does not match its pinned digest, downloading again")
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            data = resp.read()
    except OSError as e:
        die(f"download of {url} failed: {e}")
    got = hashlib.sha256(data).hexdigest()
    if got != sha256:
        die(f"{name}: sha256 {got} != pinned {sha256}")
    atomic_write(cached, data, 0o644)
    return data


def safe_extract(zf: zipfile.ZipFile, dest: str) -> None:
    root = os.path.realpath(dest)
    for info in zf.infolist():
        target = os.path.realpath(os.path.join(dest, info.filename))
        if target != root and not target.startswith(root + os.sep):
            die(f"archive entry escapes the target directory: {info.filename!r}")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            die(f"archive entry is a symlink: {info.filename!r}")
    zf.extractall(dest)


def replace_dir(src: str, dest: str) -> None:
    old = dest + ".portcullis-old"
    if os.path.lexists(old):
        shutil.rmtree(old)
    if os.path.lexists(dest):
        os.rename(dest, old)
    os.rename(src, dest)
    if os.path.lexists(old):
        shutil.rmtree(old)


def onboarding_done() -> None:
    path = os.path.join(CONFIG, ".storage", "onboarding")
    doc = None
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError):
            doc = None
    done = ((doc or {}).get("data") or {}).get("done") or []
    if doc and doc.get("key") == "onboarding" and set(ONBOARDING_STEPS) <= set(done):
        log("onboarding already marked done")
        return
    new = {"version": 4, "minor_version": 1, "key": "onboarding", "data": {"done": ONBOARDING_STEPS}}
    atomic_write(path, json.dumps(new, indent=2).encode())
    log("onboarding marked done (no local owner account is ever created)")


def install_auth_oidc() -> None:
    data = fetch_verified(AUTH_OIDC_URL, AUTH_OIDC_SHA256, f"hass-oidc-auth-{AUTH_OIDC_VERSION}.zip")
    parent = os.path.join(CONFIG, "custom_components")
    os.makedirs(parent, exist_ok=True)
    tmp = tempfile.mkdtemp(dir=parent, prefix=".auth_oidc-")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        safe_extract(zf, tmp)
    with open(os.path.join(tmp, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    if manifest.get("domain") != "auth_oidc" or manifest.get("version") != AUTH_OIDC_VERSION:
        shutil.rmtree(tmp)
        die(f"unexpected integration manifest: {manifest.get('domain')} {manifest.get('version')}")
    os.chmod(tmp, 0o755)
    replace_dir(tmp, os.path.join(parent, "auth_oidc"))
    log(f"auth_oidc {AUTH_OIDC_VERSION} installed (sha256 verified)")


def install_joserfc() -> None:
    data = fetch_verified(JOSERFC_URL, JOSERFC_SHA256, f"joserfc-{JOSERFC_VERSION}-py3-none-any.whl")
    # The same user site Home Assistant mounts (bootstrap.async_mount_local_lib_path:
    # PYTHONUSERBASE=/config/deps, python -m site --user-site).
    deps = os.path.join(CONFIG, "deps")
    env = dict(os.environ, PYTHONUSERBASE=deps)
    site = subprocess.run([sys.executable, "-m", "site", "--user-site"], env=env,
                          capture_output=True, text=True, check=True).stdout.strip()
    if not site.startswith(deps + os.sep):
        die(f"unexpected user site {site!r}")
    os.makedirs(site, exist_ok=True)
    for entry in os.listdir(site):
        if entry == "joserfc" or (entry.startswith("joserfc-") and entry.endswith(".dist-info")):
            p = os.path.join(site, entry)
            shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        safe_extract(zf, site)
    log(f"joserfc {JOSERFC_VERSION} installed into {site} (sha256 verified)")


def include_files() -> None:
    for name, empty in (("automations.yaml", "[]\n"), ("scripts.yaml", ""), ("scenes.yaml", "[]\n")):
        p = os.path.join(CONFIG, name)
        if not os.path.exists(p):
            atomic_write(p, empty.encode(), 0o644)


def main() -> None:
    if not os.path.isdir(CONFIG):
        die("/config is missing")
    os.makedirs(CACHE, exist_ok=True)
    onboarding_done()
    install_auth_oidc()
    install_joserfc()
    include_files()
    log("done")


if __name__ == "__main__":
    main()
