#!/usr/bin/env python3
"""Jellyfin auto-setup: wizard, SSO config, branding, local login off (stdlib only).

The SSO plugin itself is installed, pinned and checksum-verified, by
plugin.py before Jellyfin starts. This sidecar runs after Jellyfin is up:

1. the startup wizard (first boot only; creates the local "admin");
2. the SSO plugin configuration (client, groups, username claim);
3. switches the local admin to the SSO plugin's authentication provider, so
   Jellyfin's password login (/Users/AuthenticateByName, on the ungated
   router) refuses it, like every SSO-created account (random password,
   same provider). Later runs authenticate with an API key the first run
   created and kept in the config volume (/config/portcullis-setup.key).
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

JF = "http://jellyfin:8096"
ADMIN_PASS = os.environ["JELLYFIN_ADMIN_PASSWORD"]
OIDC_SECRET = os.environ.get("JELLYFIN_OIDC_SECRET", "")
DOMAIN = os.environ.get("PORTCULLIS_DOMAIN", "portcullis.local")
# Instance-scoped (contracts §3.1): every instance has its own client and groups.
# compose.yml sets them (with the default instance's values as defaults).
CLIENT_ID = os.environ["JELLYFIN_OIDC_CLIENT_ID"]
ACCESS_GROUP = os.environ["JELLYFIN_ACCESS_GROUP"]
ADMIN_GROUP = os.environ["JELLYFIN_ADMIN_GROUP"]

SSO_GUID = "505ce9d1-d916-42fa-86ca-673ef241d7df"
# The provider id the plugin gives every account it creates; Jellyfin has no
# provider of that name, so a password login for such an account fails.
SSO_PROVIDER = "Jellyfin.Plugin.SSO_Auth.Api.SSOController"
KEY_FILE = "/config/portcullis-setup.key"
KEY_APP = "portcullis-setup"
CLIENT_AUTH = 'MediaBrowser Client="Portcullis", Device="Setup", DeviceId="portcullis-setup", Version="1.0"'


def call(method, path, token=None, body=None, params=None, timeout=15):
    """HTTP request to Jellyfin; returns (status, parsed JSON or None)."""
    url = JF + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    # Jellyfin 12 reads only the standard Authorization header (the legacy
    # X-Emby-Authorization is ignored: "request.App" is null).
    auth = f'MediaBrowser Token="{token}"' if token else CLIENT_AUTH
    headers = {"Authorization": auth, "X-Emby-Authorization": auth}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, None


def wait_for(path, label="Jellyfin", timeout=180):
    print(f"setup: Waiting for {label}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            status, _ = call("GET", path, timeout=5)
            if status < 500:
                return True
        except OSError:
            pass
        time.sleep(3)
    print(f"setup: Timeout waiting for {label}")
    return False


def ok(status):
    return 200 <= status < 300


def is_configured():
    try:
        _, info = call("GET", "/System/Info/Public", timeout=5)
        return bool((info or {}).get("StartupWizardCompleted", False))
    except OSError:
        return False


def run_wizard():
    print("setup: Running startup wizard...")
    status, _ = call("POST", "/Startup/Configuration", body={
        "UICulture": "en-US", "MetadataCountryCode": "US", "PreferredMetadataLanguage": "en"})
    print(f"setup: Configuration: {status}")

    # Wait for Jellyfin to create the initial user after configuration
    for _ in range(20):
        try:
            if call("GET", "/Startup/User", timeout=5)[0] == 200:
                break
        except OSError:
            pass
        time.sleep(2)

    status, _ = call("POST", "/Startup/User", body={"Name": "admin", "Password": ADMIN_PASS})
    print(f"setup: User: {status}")
    status, _ = call("POST", "/Startup/RemoteAccess", body={
        "EnableRemoteAccess": True, "EnableAutomaticPortMapping": False})
    print(f"setup: RemoteAccess: {status}")
    status, _ = call("POST", "/Startup/Complete")
    print(f"setup: Complete: {status}")
    time.sleep(5)
    wait_for("/System/Info/Public", "Jellyfin post-wizard")


def stored_key():
    try:
        with open(KEY_FILE, encoding="utf-8") as f:
            key = f.read().strip()
    except OSError:
        return None
    if key and ok(call("GET", "/System/Info", token=key)[0]):
        print("setup: Authenticated with the stored API key.")
        return key
    return None


def password_login():
    status, res = call("POST", "/Users/AuthenticateByName", body={"Username": "admin", "Pw": ADMIN_PASS})
    token = (res or {}).get("AccessToken") if status == 200 else None
    if token:
        print("setup: Authenticated as the local admin (first run).")
    return token


def keep_api_key(token):
    """Create (once) the API key later runs use, and store it in the volume."""
    _, keys = call("GET", "/Auth/Keys", token=token)
    items = [k for k in (keys or {}).get("Items", []) if k.get("AppName") == KEY_APP]
    if not items:
        status, _ = call("POST", "/Auth/Keys", token=token, params={"app": KEY_APP})
        if not ok(status):
            sys.exit(f"setup: cannot create the API key ({status})")
        _, keys = call("GET", "/Auth/Keys", token=token)
        items = [k for k in (keys or {}).get("Items", []) if k.get("AppName") == KEY_APP]
    if not items or not items[0].get("AccessToken"):
        sys.exit("setup: API key not found after creating it")
    fd = os.open(KEY_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(items[0]["AccessToken"])
    os.replace(KEY_FILE + ".tmp", KEY_FILE)
    return items[0]["AccessToken"]


def sso_plugin_id(token):
    _, plugins = call("GET", "/Plugins", token=token)
    for p in plugins or []:
        if str(p.get("Id", "")).replace("-", "").lower() == SSO_GUID.replace("-", ""):
            return SSO_GUID
    return None


def drop_catalog_repo(token):
    """Earlier versions added the plugin's catalog; the pin replaces it."""
    _, repos = call("GET", "/Repositories", token=token)
    if repos is None:
        return
    kept = [r for r in repos if "jellyfin-plugin-sso" not in (r.get("Url") or "")]
    if len(kept) != len(repos):
        status, _ = call("POST", "/Repositories", token=token, body=kept)
        print(f"setup: SSO catalog repository removed: {status}")


def configure_branding(token):
    status, _ = call("POST", "/System/Configuration/branding", token=token, body={
        "LoginDisclaimer": '<form action="/sso/OID/start/keycloak"><button class="raised block emby-button button-submit">Sign in with SSO</button></form>',
        "CustomCss": "",
    })
    print(f"setup: Branding set: {status}")


def configure_sso(token, guid):
    _, current = call("GET", f"/Plugins/{guid}/Configuration", token=token)
    old = ((current or {}).get("OidConfigs") or {}).get("keycloak") or {}
    oid = {
        "OidEndpoint": f"https://auth.{DOMAIN}/realms/portcullis/.well-known/openid-configuration",
        "OidClientId": CLIENT_ID,
        "OidSecret": OIDC_SECRET,
        "Enabled": True,
        "EnableAuthorization": True,
        "EnableAllFolders": True,
        "EnabledFolders": [],
        "AdminRoles": [ADMIN_GROUP],
        "Roles": [ACCESS_GROUP, ADMIN_GROUP],
        "EnableFolderRoles": False,
        "OidScopes": ["openid", "profile", "groups"],
        "RoleClaim": "groups",
        # Accounts are created / matched by this claim: the immutable LLDAP
        # username, never the user-editable email (no email scope is
        # requested at all).
        "DefaultUsernameClaim": "preferred_username",
        "DisableHttps": False,
        # Jellyfin sits behind Traefik's TLS: without it the plugin builds
        # http:// callback/auth URLs (the browser then blocks the
        # cross-scheme /sso/OID/Auth call and nobody signs in).
        "SchemeOverride": "https",
        "DisablePushedAuthorization": True,
        "DoNotValidateEndpoints": False,
    }
    # Keep the plugin's account links (written by the plugin at login).
    if old.get("CanonicalLinks"):
        oid["CanonicalLinks"] = old["CanonicalLinks"]
    status, _ = call("POST", f"/Plugins/{guid}/Configuration", token=token,
                     body={"SamlConfigs": {}, "OidConfigs": {"keycloak": oid}})
    print(f"setup: SSO config via plugin API: {status}")
    if not ok(status):
        sys.exit("setup: SSO configuration failed")


def configure_network(token):
    """Set KnownProxies so Jellyfin trusts X-Forwarded-Proto from Traefik."""
    _, net = call("GET", "/System/Configuration/network", token=token)
    if not net:
        print("setup: Could not read network config.")
        return
    net["KnownProxies"] = ["172.16.0.0/12", "10.0.0.0/8"]
    status, _ = call("POST", "/System/Configuration/network", token=token, body=net)
    print(f"setup: Network config (KnownProxies): {status}")


def disable_local_login(token):
    """Move the local admin to the SSO provider: no password login for it."""
    _, users = call("GET", "/Users", token=token)
    for user in users or []:
        if user.get("Name") != "admin":
            continue
        policy = user.get("Policy") or {}
        if policy.get("AuthenticationProviderId") == SSO_PROVIDER:
            print("setup: Local admin password login already off.")
            return
        policy["AuthenticationProviderId"] = SSO_PROVIDER
        status, _ = call("POST", f"/Users/{user['Id']}/Policy", token=token, body=policy)
        if not ok(status):
            sys.exit(f"setup: cannot turn off the local admin's password login ({status})")
        print("setup: Local admin password login off.")
        return


def main():
    if not wait_for("/Startup/Configuration"):
        sys.exit(1)

    if is_configured():
        print("setup: Already configured, skipping wizard.")
    else:
        run_wizard()

    token = stored_key()
    if not token:
        login = password_login()
        if not login:
            sys.exit("setup: no stored API key and the local admin password login failed")
        token = keep_api_key(login)

    guid = sso_plugin_id(token)
    if not guid:
        sys.exit("setup: SSO plugin not loaded (jellyfin-plugin installs it before Jellyfin starts)")
    drop_catalog_repo(token)
    configure_sso(token, guid)
    configure_branding(token)
    configure_network(token)
    disable_local_login(token)
    print("setup: Done!")


if __name__ == "__main__":
    main()
