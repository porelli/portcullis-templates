#!/usr/bin/env python3
"""Install the pinned Jellyfin SSO plugin before Jellyfin starts (stdlib only).

Downloads the release zip, refuses it unless its SHA-256 matches the pin,
extracts it into /config/plugins/<name>_<version>/ and removes every other
installed version of the plugin (e.g. one installed earlier from the plugin
catalog), so Jellyfin only ever loads the pinned, verified build. Fails
closed: Jellyfin (depends_on: service_completed_successfully) doesn't start
if this exits non-zero.
"""

import hashlib
import io
import json
import os
import shutil
import sys
import time
import urllib.request
import zipfile

# Upgrade: bump all three together (sha256 of the release asset; the
# release must target the Jellyfin ABI of the pinned image).
VERSION = "4.0.0.4"
SHA256 = "c09f16ba31059a434ddd7f811e4f9608d4b4c4514cc80a5bf1ca33bee61e1107"
URL = f"https://github.com/9p4/jellyfin-plugin-sso/releases/download/v{VERSION}/sso-authentication_{VERSION}.zip"

GUID = "505ce9d1-d916-42fa-86ca-673ef241d7df"
NAME = "SSO Authentication"
PLUGINS = "/config/plugins"
TARGET = os.path.join(PLUGINS, f"{NAME}_{VERSION}")


def download():
    last = None
    for attempt in range(5):
        try:
            with urllib.request.urlopen(URL, timeout=60) as r:
                return r.read()
        except OSError as e:
            last = e
            print(f"plugin: download failed ({e}), retrying...", file=sys.stderr)
            time.sleep(3 * (attempt + 1))
    sys.exit(f"plugin: cannot download {URL}: {last}")


def plugin_guid(path):
    try:
        with open(os.path.join(path, "meta.json"), encoding="utf-8") as f:
            return json.load(f).get("guid", "").lower()
    except (OSError, ValueError):
        return ""


def main():
    data = download()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        sys.exit(f"plugin: SHA-256 mismatch for {URL}: got {digest}, pinned {SHA256}")

    os.makedirs(PLUGINS, exist_ok=True)
    # Other versions of the same plugin (catalog installs, older pins).
    for entry in os.listdir(PLUGINS):
        path = os.path.join(PLUGINS, entry)
        if path != TARGET and os.path.isdir(path) and plugin_guid(path) == GUID:
            print(f"plugin: removing {entry}")
            shutil.rmtree(path)

    tmp = TARGET + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for member in z.infolist():
            name = member.filename
            if member.is_dir() or "/" in name or "\\" in name or name.startswith("."):
                sys.exit(f"plugin: unexpected archive entry {name!r}")
            with z.open(member) as src, open(os.path.join(tmp, name), "wb") as dst:
                shutil.copyfileobj(src, dst)

    meta_path = os.path.join(tmp, "meta.json")
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    if meta.get("guid", "").lower() != GUID or meta.get("version") != VERSION:
        sys.exit(f"plugin: meta.json is not {NAME} {VERSION}")
    # Never replaced by Jellyfin's catalog updater: only this pin installs it.
    meta["autoUpdate"] = False
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=4)

    shutil.rmtree(TARGET, ignore_errors=True)
    os.rename(tmp, TARGET)
    print(f"plugin: {NAME} {VERSION} installed (sha256 verified)")


if __name__ == "__main__":
    main()
