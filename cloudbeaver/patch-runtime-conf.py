#!/usr/bin/env python3
"""Portcullis: re-enable CloudBeaver's reverseProxy sign-in before every start.

CloudBeaver applies GlobalConfiguration/.cloudbeaver.runtime.conf (shipped by
the template) only while the server is unconfigured. Once the automatic
server configuration (CB_SERVER_* / CB_ADMIN_*) or the admin UI has written
workspace/.data/.cloudbeaver.runtime.conf, that file wins, and it may lack
the reverseProxy provider or its X-Forwarded-User parameter. This edits it
as JSON (stdlib only; on the first start it seeds it): anonymous access
off, enableReverseProxyAuth on, "reverseProxy" in
enabledAuthProviders, the portcullis-proxy auth configuration present with
user-header X-Forwarded-User and no team/name headers. Anything else in the
file is kept. Exits non-zero (CloudBeaver does not start) if the file
exists but is not a JSON object.
"""
import json
import os
import sys
import tempfile

PATH = sys.argv[1]
AUTH_CONFIG = {
    "id": "portcullis-proxy",
    "provider": "reverseProxy",
    "displayName": "Portcullis SSO",
    "disabled": False,
    "parameters": {
        "user-header": "X-Forwarded-User",
        "first-name-header": "",
        "last-name-header": "",
        "team-header": "",
        "team-delimiter": "|",
    },
}

first_start = not os.path.exists(PATH)
if first_start:
    # Before the automatic server configuration: seed the runtime config
    # with the app section only (no server section, so CloudBeaver still
    # configures itself from CB_SERVER_* / CB_ADMIN_* and keeps this), so
    # the very first start already signs users in by X-Forwarded-User and
    # never serves anonymous sessions.
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    conf = {"app": {"enabledAuthProviders": ["local"]}}
else:
    with open(PATH, encoding="utf-8") as f:
        conf = json.load(f)
if not isinstance(conf, dict):
    sys.exit(f"cloudbeaver-config: {PATH} is not a JSON object")
app = conf.setdefault("app", {})
if not isinstance(app, dict):
    sys.exit(f"cloudbeaver-config: {PATH}: app is not an object")

app["enableReverseProxyAuth"] = True
# Fail closed: nobody past the gate is an anonymous CloudBeaver session.
app["anonymousAccessEnabled"] = False
providers = app.get("enabledAuthProviders")
if not isinstance(providers, list):
    providers = []
if "reverseProxy" not in providers:
    providers.append("reverseProxy")
app["enabledAuthProviders"] = providers
configs = [c for c in app.get("authConfigurations") or [] if isinstance(c, dict) and c.get("id") != AUTH_CONFIG["id"]]
app["authConfigurations"] = configs + [AUTH_CONFIG]

st = os.stat(PATH) if not first_start else os.stat(os.path.dirname(PATH))
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(PATH), prefix=".runtime-conf.")
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(conf, f, indent=2)
    f.write("\n")
os.chown(tmp, st.st_uid, st.st_gid)
os.chmod(tmp, (st.st_mode & 0o7777) if not first_start else 0o644)
os.replace(tmp, PATH)
print("cloudbeaver-config: reverseProxy sign-in (X-Forwarded-User) enabled, anonymous access off"
      + (" (seeded before the first start)" if first_start else ""))
