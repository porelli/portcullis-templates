#!/usr/bin/env python3
"""homeassistant-init (Portcullis): runs before every Home Assistant start.

1. Onboarding is marked done. Home Assistant's onboarding creates a
   username/password owner account for whoever opens the instance first;
   with Portcullis there is no local password provider (configuration.yaml
   auth_providers: []) and every account comes from OpenID Connect.
2. The auth_oidc custom integration (christiaangoossens/hass-oidc-auth) is
   installed from its pinned release asset into
   /config/custom_components/auth_oidc, replacing whatever is there, after
   its SHA-256 matched. Its Python requirements (aiofiles, jinja2, joserfc)
   ship in the pinned Home Assistant image, so nothing is installed at
   runtime; a stale /config/deps copy of joserfc from older template
   versions is removed.
3. The HTTP server config (.storage/http, which Home Assistant 2026.10 uses
   instead of the deprecated http: YAML) is rewritten as the confirmed
   ("stable") config with nothing pending: X-Forwarded-For trusted from
   Traefik's address only (HA_TRUSTED_PROXY), IP bans on. A config changed
   in the UI is discarded at the next start.
4. automations.yaml / scripts.yaml / scenes.yaml exist (configuration.yaml
   includes them).

Any failure exits non-zero, and Home Assistant doesn't start (fail closed).
Downloads are cached in /config/.portcullis and re-verified every start.
No secret is read or written here.
"""

import datetime
import hashlib
import io
import ipaddress
import json
import os
import shutil
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


def remove_stale_deps() -> None:
    deps = os.path.join(CONFIG, "deps")
    if not os.path.isdir(deps):
        return
    for root, dirs, _ in os.walk(deps):
        for d in list(dirs):
            if d == "joserfc" or (d.startswith("joserfc-") and d.endswith(".dist-info")):
                shutil.rmtree(os.path.join(root, d))
                dirs.remove(d)
                log(f"removed stale {os.path.join(root, d)}")


def http_config() -> None:
    raw = os.environ.get("HA_TRUSTED_PROXY", "")
    try:
        proxy = ipaddress.ip_address(raw)
    except ValueError:
        die(f"HA_TRUSTED_PROXY {raw!r} is not an IP address")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    stable = {
        "server_port": 8123,
        "cors_allowed_origins": ["https://cast.home-assistant.io"],
        "use_x_forwarded_for": True,
        "trusted_proxies": [str(ipaddress.ip_network(f"{proxy}/{proxy.max_prefixlen}"))],
        "login_attempts_threshold": 10,
        "ip_ban_enabled": True,
        "ssl_profile": "modern",
        "use_x_frame_options": True,
        "created_at": now,
        "error": None,
        "error_message": None,
    }
    doc = {"version": 2, "minor_version": 2, "key": "http",
           "data": {"stable": stable, "pending": None, "yaml_migration_done": True}}
    atomic_write(os.path.join(CONFIG, ".storage", "http"), json.dumps(doc, indent=2).encode())
    log(f"http config: X-Forwarded-For trusted from {proxy} only, nothing pending")


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
    remove_stale_deps()
    http_config()
    include_files()
    log("done")


if __name__ == "__main__":
    main()
