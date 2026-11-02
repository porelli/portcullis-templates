#!/usr/bin/env python3
"""Wiki.js setup sidecar (runs at every start, stdlib only).

1. Fresh install: completes the setup wizard (POST /finalize) with the
   break-glass local admin (WIKI_ADMIN_EMAIL / WIKI_ADMIN_PASSWORD) and the
   instance's site URL. /finalize is also behind forward-auth + group-gate in
   Traefik, so nobody else can finish the wizard first.
2. Signs in as that local admin (GraphQL) and re-applies, from the
   environment:
   - the Portcullis OIDC strategy (key "portcullis", Wiki.js' generic OpenID
     Connect module): client, Keycloak endpoints, groups claim mapping,
     self-registration without any default group;
   - the instance's access group (created once with editor permissions) and
     admin group (manage:system, re-applied every start);
   - the Guests group stripped of every permission (no anonymous access:
     the host is not behind forward-auth).
The site URL itself is written before Wiki.js boots, by wiki-init.
Never prints WIKI_OIDC_SECRET or the admin password.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

WIKI = "http://wiki:3000"
HOST = os.environ["PORTCULLIS_HOST_WIKI"]
DOMAIN = os.environ["PORTCULLIS_DOMAIN"]
CLIENT_ID = os.environ["PORTCULLIS_OIDC_CLIENT_ID"]
ACCESS_GROUP = os.environ["PORTCULLIS_ACCESS_GROUP"]
ADMIN_GROUP = os.environ["PORTCULLIS_ADMIN_GROUP"]
SECRET = os.environ["WIKI_OIDC_SECRET"]
ADMIN_EMAIL = os.environ["WIKI_ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["WIKI_ADMIN_PASSWORD"]

STRATEGY_KEY = "portcullis"  # callback: https://<host>/login/portcullis/callback
REALM = f"https://auth.{DOMAIN}/realms/portcullis"
GUESTS_ID = 2  # created by the wizard (server/setup.js), cannot be deleted

EDITOR_ROLES = ["read:pages", "read:assets", "read:comments", "write:comments",
                "write:pages", "write:assets", "read:source", "read:history"]


def log(msg):
    print(f"wiki-setup: {msg}", flush=True)


def http(method, path, body=None, token=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(WIKI + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def gql(query, variables=None, token=None):
    code, raw = http("POST", "/graphql", {"query": query, "variables": variables or {}}, token)
    if code != 200:
        raise RuntimeError(f"GraphQL HTTP {code}")
    out = json.loads(raw)
    if out.get("errors"):
        raise RuntimeError("; ".join(e.get("message", "?") for e in out["errors"]))
    return out["data"]


def mode():
    """'setup' (wizard), 'ready' (GraphQL answers) or None (not up yet)."""
    try:
        code, _ = http("POST", "/graphql", {"query": "{ __typename }"}, timeout=5)
    except (urllib.error.URLError, OSError):
        return None
    if code == 200:
        return "ready"
    if code == 404:
        return "setup"
    return None


def wait_for(want, timeout=300):
    start = time.time()
    while time.time() - start < timeout:
        m = mode()
        if m in want:
            return m
        time.sleep(3)
    log(f"timeout waiting for Wiki.js ({'/'.join(want)})")
    sys.exit(1)


def check_result(res, what):
    rr = (res or {}).get("responseResult") or {}
    if not rr.get("succeeded", False):
        raise RuntimeError(f"{what}: {rr.get('message', 'failed')}")


def ensure_groups(token):
    groups = gql("{ groups { list { id name } } }", token=token)["groups"]["list"]
    by_name = {g["name"]: g["id"] for g in groups}
    for name in (ACCESS_GROUP, ADMIN_GROUP):
        if name not in by_name:
            res = gql("mutation($n: String!) { groups { create(name: $n) { responseResult { succeeded message } group { id } } } }",
                      {"n": name}, token)["groups"]["create"]
            check_result(res, f"create group {name}")
            by_name[name] = res["group"]["id"]
            log(f"created group {name}")
            if name == ACCESS_GROUP:
                update_group(token, by_name[name], name, EDITOR_ROLES, EDITOR_ROLES)
    # Re-applied at every start: admins have full rights, guests none.
    update_group(token, by_name[ADMIN_GROUP], ADMIN_GROUP, ["manage:system"], EDITOR_ROLES)
    update_group(token, GUESTS_ID, "Guests", [], None)


def update_group(token, gid, name, permissions, page_roles):
    rules = [] if not page_roles else [
        {"id": "portcullis", "deny": False, "match": "START", "roles": page_roles, "path": "", "locales": []}]
    res = gql("mutation($id: Int!, $n: String!, $p: [String]!, $r: [PageRuleInput]!) { groups { update(id: $id, name: $n, "
              "redirectOnLogin: \"/\", permissions: $p, pageRules: $r) { responseResult { succeeded message } } } }",
              {"id": gid, "n": name, "p": permissions, "r": rules}, token)["groups"]["update"]
    check_result(res, f"update group {name}")


def ensure_strategy(token):
    q = ("{ authentication { activeStrategies { key strategy { key } displayName order isEnabled "
         "config { key value } selfRegistration domainWhitelist autoEnrollGroups } } }")
    active = gql(q, token=token)["authentication"]["activeStrategies"]
    strategies = []
    for s in active:
        if s["key"] == STRATEGY_KEY:
            continue
        # activeStrategies returns {"...prop info", "value": v}; the input wants {"v": v}.
        cfg = [{"key": c["key"], "value": json.dumps({"v": json.loads(c["value"]).get("value")})}
               for c in s.get("config") or []]
        strategies.append({
            "key": s["key"], "strategyKey": s["strategy"]["key"], "config": cfg,
            "displayName": s["displayName"], "order": s["order"], "isEnabled": s["isEnabled"],
            "selfRegistration": s["selfRegistration"], "domainWhitelist": s["domainWhitelist"] or [],
            "autoEnrollGroups": s["autoEnrollGroups"] or [],
        })
    oidc = {
        "clientId": CLIENT_ID,
        "clientSecret": SECRET,
        "authorizationURL": f"{REALM}/protocol/openid-connect/auth",
        "tokenURL": f"{REALM}/protocol/openid-connect/token",
        "userInfoURL": f"{REALM}/protocol/openid-connect/userinfo",
        "skipUserProfile": False,
        "issuer": REALM,
        # Wiki.js requires an email (it keys accounts on the OIDC sub; the
        # email only fills the profile).
        "emailClaim": "email",
        "displayNameClaim": "name",
        "pictureClaim": "picture",
        # Membership of Wiki.js groups follows the groups claim at each login
        # (only groups that exist in Wiki.js: the instance's two).
        "mapGroups": True,
        "groupsClaim": "groups",
        "logoutURL": f"{REALM}/protocol/openid-connect/logout",
        "acrValues": "",
    }
    strategies.append({
        "key": STRATEGY_KEY, "strategyKey": "oidc",
        "config": [{"key": k, "value": json.dumps({"v": v})} for k, v in oidc.items()],
        "displayName": "Portcullis", "order": 1, "isEnabled": True,
        # New accounts get no group: rights come only from the mapped groups.
        "selfRegistration": True, "domainWhitelist": [], "autoEnrollGroups": [],
    })
    res = gql("mutation($s: [AuthenticationStrategyInput]!) { authentication { updateStrategies(strategies: $s) "
              "{ responseResult { succeeded message } } } }", {"s": strategies}, token)["authentication"]["updateStrategies"]
    check_result(res, "update strategies")


def main():
    if wait_for(("setup", "ready")) == "setup":
        log("fresh install: completing the setup wizard")
        code, raw = http("POST", "/finalize", {
            "adminEmail": ADMIN_EMAIL, "adminPassword": ADMIN_PASSWORD,
            "adminPasswordConfirm": ADMIN_PASSWORD, "siteUrl": f"https://{HOST}", "telemetry": False,
        }, timeout=120)
        if code != 200 or not json.loads(raw or b"{}").get("ok"):
            log(f"setup wizard failed (HTTP {code})")
            sys.exit(1)
        time.sleep(5)
        wait_for(("ready",))

    try:
        res = gql("mutation($u: String!, $p: String!) { authentication { login(username: $u, password: $p, strategy: \"local\") "
                  "{ responseResult { succeeded message } jwt } } }", {"u": ADMIN_EMAIL, "p": ADMIN_PASSWORD})
        token = (res["authentication"]["login"] or {}).get("jwt")
    except RuntimeError as e:
        log(f"local admin login refused: {e}")
        token = None
    if not token:
        log(f"cannot sign in as the local admin {ADMIN_EMAIL}; Portcullis sign-in is NOT configured. "
            "Give that local account the WIKI_ADMIN_PASSWORD from the Hub (or create it) and restart.")
        sys.exit(0)

    ensure_groups(token)
    ensure_strategy(token)
    log(f"configured https://{HOST} (OIDC client {CLIENT_ID})")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        log(f"failed: {e}")
        sys.exit(1)
