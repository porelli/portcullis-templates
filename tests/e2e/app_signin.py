#!/usr/bin/env python3
"""Full sign-in test of one app template through Portcullis.

    python3 tests/e2e/app_signin.py <app-id>

Runs on the core stack test-apps.yml boots (Traefik, Keycloak, LLDAP,
enroll, forward-auth, group-gate; no Hub) and does what the Hub and a real
person would do, driven by the manifest's `tests.signin` block (see
CONTRIBUTING.md, "Sign-in test"):

  1. LLDAP: three users with no password: e2eadmin (access + admin group),
     e2emember (access group), e2eoutsider (no group);
  2. the Hub's side: the template's Keycloak clients (secret = the app's
     generated env value, redirect URIs with the instance hostnames) and the
     group-gate policy file (groups, admin_paths); an AI page (ai.chat)
     gets its ai-providers.json with no provider;
  3. starts the app (tests/lib.sh compose_up, same env as the shell test)
     and waits for its containers;
  4. per user, a one-time setup link (`portcullis invite <user> --to
     https://<host><path> --json`) opened in Chromium with a CDP virtual
     WebAuthn authenticator: register the passkey, land on the app, click
     through the app's own sign-in (`login` selectors) and Keycloak;
  5. asserts: e2emember is signed in (`signed_in`, with its username) and has
     no admin rights (`admin`); e2eadmin has them; e2eoutsider is refused
     (403 from group-gate, or the app's own denial). No password field on
     the way, unless the manifest documents one (`password`).

`expected_fail: {member|admin|outsider: reason}` marks a known failure: it is
reported, not fatal; if it passes, the run fails so the marker gets removed.
`skip: reason` (public / custom / mtls apps only, validate.py) skips the app.

Environment: PROJECT_DIR (core checkout with .env, certs/, the CLI),
TEMPLATES_DIR (this repo), PORTCULLIS_DOMAIN, KEYCLOAK_ADMIN,
KEYCLOAK_ADMIN_PASSWORD, LLDAP_ADMIN_PASSWORD (from core's .env if unset),
E2E_ARTIFACTS (screenshots, page HTML, traces; default e2e-artifacts),
E2E_KEEP_UP=1 (leave the app running).

Requirements: pip install --require-hashes -r tests/e2e/requirements.txt &&
playwright install chromium; the browser must trust core's root CA (NSS db,
see test-apps.yml) and resolve the app hosts to Traefik.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

import yaml

APP = sys.argv[1] if len(sys.argv) > 1 else ""
if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", APP):
    sys.exit("usage: app_signin.py <app-id>")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PROJECT_DIR = os.path.abspath(os.environ.get("PROJECT_DIR", "."))
TEMPLATES_DIR = os.path.abspath(os.environ.get("TEMPLATES_DIR", REPO))
DOMAIN = os.environ.get("PORTCULLIS_DOMAIN", "portcullis.local")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://127.0.0.1:8080")
LLDAP_URL = os.environ.get("LLDAP_URL", "http://127.0.0.1:17170")
REALM = "portcullis"
AUTH_HOST = f"auth.{DOMAIN}"
ENROLL_HOST = f"enroll.{DOMAIN}"
ART = os.path.join(os.path.abspath(os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")), APP)
TIMEOUT_MS = 30_000
os.makedirs(ART, exist_ok=True)

ROLES = ("admin", "member", "outsider")   # admin first: some apps make their first user the owner
USERS = {"admin": "e2eadmin", "member": "e2emember", "outsider": "e2eoutsider"}
PROBLEM_CODES = {404, 502, 503, 504}

results: List[Dict[str, str]] = []
SIGNED_IN: List[str] = []   # roles that got signed in (an outsider refusal needs one)
_shot = 0


def log(msg: str) -> None:
    print(msg, flush=True)


def core_env(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        try:
            with open(os.path.join(PROJECT_DIR, ".env"), encoding="utf-8") as f:
                for line in f:
                    if line.startswith(name + "="):
                        v = line.split("=", 1)[1].rstrip("\n")
                        break
        except OSError:
            pass
    return v


def log_marks() -> Dict[str, Any]:
    """Where the logs stand now: a UTC timestamp for `docker logs --since`
    and the byte size of every log_files entry, so a check reads only what
    its own flow produced."""
    sizes = {}
    for lf in SIGNIN.get("log_files") or []:
        p = subprocess.run(["docker", "exec", f"portcullis-{lf['service']}-1", "sh", "-c",
                            'wc -c < "$1" 2>/dev/null || echo 0', "sh", lf["path"]], capture_output=True, text=True)
        try:
            sizes[f"{lf['service']}:{lf['path']}"] = int((p.stdout or "0").strip() or 0)
        except ValueError:
            sizes[f"{lf['service']}:{lf['path']}"] = 0
    return {"since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1)), "sizes": sizes}


def app_logs(marks: Optional[Dict[str, Any]] = None, tag: str = "") -> str:
    """The app containers' logs and the manifest's log_files since `marks`
    (everything without), for expected_fail matching; kept as artifacts."""
    marks = marks or {"since": "", "sizes": {}}
    out = []
    for svc in (COMPOSE.get("services") or {}):
        since = ["--since", marks["since"]] if marks["since"] else ["--tail", "2000"]
        p = subprocess.run(["docker", "logs", *since, f"portcullis-{svc}-1"], capture_output=True, text=True)
        out.append(p.stdout + p.stderr)
    for lf in SIGNIN.get("log_files") or []:
        off = marks["sizes"].get(f"{lf['service']}:{lf['path']}", 0)
        p = subprocess.run(["docker", "exec", f"portcullis-{lf['service']}-1", "tail", "-c", f"+{off + 1}", lf["path"]],
                           capture_output=True, text=True)
        text = p.stdout + p.stderr
        out.append(text)
        name = f"file-{lf['service']}-{os.path.basename(lf['path'])}{'-' + tag if tag else ''}"
        with open(os.path.join(ART, re.sub(r"[^A-Za-z0-9_.-]", "_", name)), "w", encoding="utf-8") as f:
            f.write(text)
    return "\n".join(out)


def gate_denied(user: str, host: str, marks: Dict[str, Any]) -> bool:
    """group-gate itself refused `user` on `host` since `marks` (its
    DENIED log line naming the access group)."""
    p = subprocess.run(["docker", "logs", "--since", marks["since"], "portcullis-group-gate-1"],
                       capture_output=True, text=True)
    pat = re.compile(rf"DENIED user={re.escape(user)} host={re.escape(host)}\b.*need=")
    return any(pat.search(line) for line in (p.stdout + p.stderr).splitlines())


def record(check: str, ok: bool, detail: str, xfail: Optional[Dict[str, str]] = None,
           page=None, seen: Optional[List[str]] = None,
           marks: Optional[Dict[str, Any]] = None) -> None:
    """A check result. An expected failure must match xfail['match'] (and
    not xfail['not_match']) in this check's own evidence: its detail, the
    pages its flow saw and the app's logs since its flow started."""
    if xfail and ok:
        status = "xpass"
        detail += f" — passes now: remove tests.signin.expected_fail.{check} ({xfail['reason']})"
    elif xfail:
        hay = detail
        if page is not None:
            try:
                hay += "\n" + page.inner_text("body", timeout=5000)
            except Exception:  # noqa: BLE001 - a closed page has no text
                pass
        hay += "\n" + "\n".join(seen or []) + "\n" + app_logs(marks, check.replace(":", "-"))
        bad = xfail.get("not_match")
        if bad and re.search(bad, hay, re.I | re.M):
            status = "fail"
            detail += f" — NOT the expected failure: /{bad}/ (not_match) found in its evidence"
        elif re.search(xfail["match"], hay, re.I | re.M):
            status = "expected_fail"
            detail += f" — expected (matched /{xfail['match']}/): {xfail['reason']}"
        else:
            status = "fail"
            detail += f" — NOT the expected failure: /{xfail['match']}/ not found in the evidence, the pages seen or the app logs"
    else:
        status = "pass" if ok else "fail"
    results.append({"app": APP, "check": check, "status": status, "detail": detail})
    log(f"{status.upper()}: {APP} {check}: {detail}")


# ── Manifest, compose, instance env ─────────────────────────────────

def load(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


APP_DIR = os.path.join(TEMPLATES_DIR, APP)
MANIFEST = load(os.path.join(APP_DIR, "manifest.yaml"))
COMPOSE_TEXT = open(os.path.join(APP_DIR, "compose.yml"), encoding="utf-8").read()
COMPOSE = yaml.safe_load(COMPOSE_TEXT)
AUTH = MANIFEST.get("auth") or {}
SIGNIN: Dict[str, Any] = (MANIFEST.get("tests") or {}).get("signin") or {}
# expected_fail.<check> = {reason, match}: the check may fail only in the
# way `match` (regex) describes, found in the evidence, the page or the
# app's logs; any other failure is a real one.
XFAIL: Dict[str, Dict[str, str]] = SIGNIN.get("expected_fail") or {}
# group-gate decides who gets in: forward-auth / header-auth apps, and the
# native-OIDC apps whose login paths sit behind it (validate.py LOGIN_GATES:
# gitlab, litellm, vaultwarden). Their outsider must be group-gate's 403.
GATED = bool(AUTH.get("group_access")) and "portcullis-groups@docker" in COMPOSE_TEXT
REFUSED_USERS: List[str] = list(SIGNIN.get("refused_users") or [])

# Default instance (tests/lib.sh quirk #13): PORTCULLIS_HOST_<ROUTER> =
# <default sub>.<domain>, client ids and groups from the manifest.
HOSTS: Dict[str, str] = {}
for var, sub in re.findall(r"\$\{PORTCULLIS_HOST_([A-Z0-9_]+):-([a-z0-9-]+)\.portcullis\.local\}", COMPOSE_TEXT):
    HOSTS[var] = f"{sub}.{DOMAIN}"
ACCESS_GROUP = AUTH.get("access_group") or ""
ADMIN_GROUP = AUTH.get("admin_group") or ""


def export_env() -> None:
    """The generated per-app env (generate: random) and instance variables,
    unless already set: test-apps.yml generates them once per job so the
    shell test and this test share the app's secrets."""
    for e in MANIFEST.get("env") or []:
        if isinstance(e, dict) and e.get("generate") == "random" and not os.environ.get(e["key"]):
            os.environ[e["key"]] = secrets.token_hex(16)
    for var, host in HOSTS.items():
        os.environ.setdefault(f"PORTCULLIS_HOST_{var}", host)


def subst(s: str, user: str = "") -> str:
    s = s.replace("{username}", user).replace("{email}", f"{user}@{DOMAIN}" if user else "")
    s = s.replace("{access_group}", ACCESS_GROUP).replace("{admin_group}", ADMIN_GROUP)
    s = s.replace("{{DOMAIN}}", DOMAIN)
    return re.sub(r"\{\{HOST_([A-Za-z0-9_]+)\}\}", lambda m: HOSTS.get(m.group(1).upper(), m.group(0)), s)


def main_host() -> str:
    want = SIGNIN.get("host")
    if want:
        key = re.sub(r"^\{\{HOST_|\}\}$", "", want).upper()
        if key not in HOSTS:
            raise SystemExit(f"tests.signin.host {want}: no such host router in compose.yml ({sorted(HOSTS)})")
        return HOSTS[key]
    for u in MANIFEST.get("urls") or []:
        m = re.search(r"\{\{HOST_([A-Za-z0-9_]+)\}\}", str(u.get("url", "")))
        if m and m.group(1).upper() in HOSTS:
            return HOSTS[m.group(1).upper()]
    return next(iter(HOSTS.values()))


# ── HTTP helpers (stdlib; core services on the CI host) ─────────────

def http(method: str, url: str, body: Any = None, token: str = "", form: Optional[Dict[str, str]] = None,
         ok: Tuple[int, ...] = (200, 201, 204)) -> Tuple[int, Any]:
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            code = r.status
    except urllib.error.HTTPError as e:
        raw, code = e.read(), e.code
    if code not in ok:
        raise RuntimeError(f"{method} {url.split('?')[0]}: HTTP {code} {raw[:300]!r}")
    try:
        return code, json.loads(raw) if raw else None
    except ValueError:
        return code, raw.decode(errors="replace")


def lldap_setup() -> None:
    _, tok = http("POST", f"{LLDAP_URL}/auth/simple/login",
                  {"username": "admin", "password": core_env("LLDAP_ADMIN_PASSWORD")})
    token = tok["token"]

    def gql(q: str, variables: Optional[dict] = None) -> dict:
        _, out = http("POST", f"{LLDAP_URL}/api/graphql", {"query": q, "variables": variables or {}}, token)
        return out

    for g in {ACCESS_GROUP, ADMIN_GROUP} - {""}:
        gql("mutation($n: String!) { createGroup(name: $n) { id } }", {"n": g})  # error if it exists: fine
    groups = {g["displayName"]: g["id"] for g in gql("{ groups { id displayName } }")["data"]["groups"]}
    people = [(role, user) for role, user in USERS.items()] + [("refused", u) for u in REFUSED_USERS]
    for role, user in people:
        gql("mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
            {"u": {"id": user, "email": f"{user}@{DOMAIN}", "displayName": user}})
        want = {"admin": [ACCESS_GROUP, ADMIN_GROUP], "member": [ACCESS_GROUP], "outsider": [],
                "refused": [ACCESS_GROUP, ADMIN_GROUP]}[role]
        for g in want:
            if g:
                out = gql("mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }",
                          {"u": user, "g": groups[g]})
                if out.get("errors") and "already" not in json.dumps(out["errors"]).lower() \
                        and "unique" not in json.dumps(out["errors"]).lower():
                    raise RuntimeError(f"LLDAP addUserToGroup {user} {g}: {out['errors']}")
    log(f"LLDAP: {USERS['admin']} in {ACCESS_GROUP or '-'} + {ADMIN_GROUP or '-'}, "
        f"{USERS['member']} in {ACCESS_GROUP or '-'}, {USERS['outsider']} in no group"
        + (f"; {', '.join(REFUSED_USERS)} in both groups (must be refused)" if REFUSED_USERS else ""))


def keycloak_token() -> str:
    _, out = http("POST", f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token", form={
        "client_id": "admin-cli", "grant_type": "password",
        "username": core_env("KEYCLOAK_ADMIN") or "admin", "password": core_env("KEYCLOAK_ADMIN_PASSWORD")})
    return out["access_token"]


def keycloak_setup() -> None:
    """The Hub's RegisterClient (internal/keycloak): confidential client,
    standard flow only, scopes profile + email (or email-unverified) + acr +
    groups; then an LDAP sync so group memberships are current."""
    tok = keycloak_token()
    base = f"{KEYCLOAK_URL}/admin/realms/{REALM}"
    _, scopes = http("GET", f"{base}/client-scopes", token=tok)
    scope_id = {s["name"]: s["id"] for s in scopes}
    for c in MANIFEST.get("keycloak_clients") or []:
        uris = [subst(u) for u in (c.get("redirect_uris") or [c.get("redirect_uri")]) if u]
        omit_ev = c.get("email_verified_claim") is False
        want_email, drop_email = ("email-unverified", "email") if omit_ev else ("email", "email-unverified")
        rep = {"clientId": c["client_id"], "name": c.get("name") or c["client_id"], "enabled": True,
               "protocol": "openid-connect", "publicClient": False,
               "secret": os.environ.get(c.get("secret_env") or "", ""), "redirectUris": uris,
               "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
               "attributes": {"portcullis.hub.template": APP},
               "defaultClientScopes": ["profile", want_email, "acr", "groups", "basic", "roles", "web-origins"]}
        code, _ = http("POST", f"{base}/clients", rep, tok, ok=(201, 409))
        _, found = http("GET", f"{base}/clients?clientId={urllib.parse.quote(c['client_id'])}", token=tok)
        cid = found[0]["id"]
        if code == 409:
            http("PUT", f"{base}/clients/{cid}", dict(found[0], **rep), tok)
        for name in ("profile", want_email, "acr", "groups"):
            if name in scope_id:
                http("PUT", f"{base}/clients/{cid}/default-client-scopes/{scope_id[name]}", token=tok)
            else:
                log(f"WARN: Keycloak realm has no client scope {name!r}")
        if drop_email in scope_id:
            for kind in ("default", "optional"):
                http("DELETE", f"{base}/clients/{cid}/{kind}-client-scopes/{scope_id[drop_email]}", token=tok,
                     ok=(200, 204, 404))
        log(f"Keycloak: client {c['client_id']} -> {', '.join(uris)}")
    # LDAP federation: full user sync + group mapper sync (tests/lib.sh lldap_sync_keycloak).
    _, comps = http("GET", f"{base}/components?type=org.keycloak.storage.UserStorageProvider", token=tok)
    for comp in comps or []:
        if comp.get("providerId") != "ldap":
            continue
        _, mappers = http("GET", f"{base}/components?parent={comp['id']}", token=tok)
        for m in mappers or []:
            if m.get("providerId") == "group-ldap-mapper":
                http("POST", f"{base}/user-storage/{comp['id']}/mappers/{m['id']}/sync?direction=fedToKeycloak",
                     token=tok, ok=(200, 204))
        http("POST", f"{base}/user-storage/{comp['id']}/sync?action=triggerFullSync", token=tok, ok=(200, 204))


_POLICY_VERSION = None


def policy_version() -> int:
    """Core's group-gate POLICY_VERSION, read once per run (4 when unreadable)."""
    global _POLICY_VERSION
    if _POLICY_VERSION is None:
        try:
            src = open(os.path.join(PROJECT_DIR, "group-gate", "group-gate.py"), encoding="utf-8").read()
            _POLICY_VERSION = int(re.search(r"^POLICY_VERSION\s*=\s*(\d+)", src, re.M).group(1))
        except (OSError, AttributeError):
            _POLICY_VERSION = 4
    return _POLICY_VERSION


def policy_doc(ver: int) -> dict:
    """Build the policy document for the given version."""
    if ver >= 6:
        # v6: sign-in methods and templates (contract §4).
        # Default methods switched on at install (password and browser_cert off).
        methods = ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"]
        # Built-in "standard" template: any of family:passkey and family:certificate,
        # compiled against the switched-on methods (contract §4 example, lines 308-310).
        standard_template = {
            "op": "any",
            "items": [
                {"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]},
                {"op": "any", "items": ["yubikey_cert"]}
            ]
        }
        # Core hostnames: portal + the gated core subdomains (GATED_CORE_SUBDOMAINS
        # in core's group-gate; enroll, auth and mcp are core hosts but never gated,
        # and any other `core` key denies), all on the default template.
        core_hosts = {
            DOMAIN: "standard",
            f"directory.{DOMAIN}": "standard",
            f"hub.{DOMAIN}": "standard",
            f"metrics.{DOMAIN}": "standard",
            f"people.{DOMAIN}": "standard",
            f"traefik.{DOMAIN}": "standard"
        }
        # App groups and path_groups (unchanged from v5).
        groups: Dict[str, str] = {}
        paths: Dict[str, list] = {}
        for host in HOSTS.values():
            if ACCESS_GROUP and AUTH.get("group_access"):
                groups[host] = ACCESS_GROUP
            if AUTH.get("admin_paths") and ADMIN_GROUP:
                paths[host] = [{"prefix": p.rstrip("/") or "/", "group": ADMIN_GROUP} for p in AUTH["admin_paths"]]
        return {
            "version": 6,
            "methods": methods,
            "templates": {"standard": standard_template},
            "default": "standard",
            "hosts": {},
            "core": core_hosts,
            "people": {},
            "add_stronger": False,
            "extra_domains": [],
            "groups": groups,
            "path_groups": paths,
            "public_paths": {},
            "expiring": []
        }
    else:
        # v5 and earlier: factor-based default policy.
        groups: Dict[str, str] = {}
        paths: Dict[str, list] = {}
        for host in HOSTS.values():
            key = host if ver >= 5 else host[: -len(DOMAIN) - 1]
            if ACCESS_GROUP and AUTH.get("group_access"):
                groups[key] = ACCESS_GROUP
            if AUTH.get("admin_paths") and ADMIN_GROUP:
                paths[key] = [{"prefix": p.rstrip("/") or "/", "group": ADMIN_GROUP} for p in AUTH["admin_paths"]]
        return {
            "version": ver,
            "default": {"factors": ["mtls", "webauthn"], "op": "any"},
            "groups": groups,
            "path_groups": paths
        }


def keycloak_doc(ver: int) -> dict:
    """Build the signin-keycloak.json document for the given version.

    For v6+: contract §8.1, the Keycloak extension reads this file to
    decide which sign-in methods are available and enforce templates.
    """
    if ver >= 6:
        methods = ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"]
        standard_template = {
            "op": "any",
            "items": [
                {"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]},
                {"op": "any", "items": ["yubikey_cert"]}
            ]
        }
        return {
            "version": 1,
            "methods": methods,
            "add_stronger": False,
            "templates": {"standard": standard_template},
            "clients": {},
            "authenticators": {},
            "mds": {"serial": 0, "next_update": "0001-01-01T00:00:00Z"}
        }
    return {}


def write_policy() -> None:
    """The group-gate policy file the Hub writes for this app (contract §4):
    every host of the app requires access_group, admin_paths require
    admin_group too; the Hub's fresh-install default policy.

    For v6+, also writes signin-keycloak.json (contract §8.1) so the
    Keycloak extension accepts sign-ins."""
    ver = policy_version()
    doc = policy_doc(ver)
    sh("_hub_data_write", stdin=json.dumps(doc))
    log(f"group-gate policy (version {ver}): {json.dumps(doc)}")
    if ver >= 6:
        kc_doc = keycloak_doc(ver)
        sh("_hub_data_write", "signin-keycloak.json", stdin=json.dumps(kc_doc))
        log(f"signin-keycloak.json (version {ver}): {json.dumps(kc_doc)}")


def selftest() -> None:
    """Verify policy_doc and keycloak_doc build v6 correctly and keep v5 unchanged."""
    v6 = policy_doc(6)
    assert v6["version"] == 6, f"v6 version: got {v6['version']}, want 6"
    assert "standard" in v6["templates"], "v6 templates: 'standard' missing"
    v5 = policy_doc(5)
    # v5 structure check: has the factor-based default, no v6 keys.
    assert v5["version"] == 5, f"v5 version: got {v5['version']}, want 5"
    assert v5["default"] == {"factors": ["mtls", "webauthn"], "op": "any"}, f"v5 default changed: {v5['default']}"
    assert "groups" in v5 and "path_groups" in v5, "v5 missing groups or path_groups"
    assert "methods" not in v5, "v5 has v6 key 'methods'"
    assert "templates" not in v5, "v5 has v6 key 'templates'"
    assert "hosts" not in v5, "v5 has v6 key 'hosts'"
    assert "core" not in v5, "v5 has v6 key 'core'"
    assert "people" not in v5, "v5 has v6 key 'people'"
    assert "add_stronger" not in v5, "v5 has v6 key 'add_stronger'"
    # keycloak_doc v6 structure check.
    kc6 = keycloak_doc(6)
    assert kc6["version"] == 1, f"keycloak_doc v6 version: got {kc6['version']}, want 1"
    assert kc6["methods"] == ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"], \
        f"keycloak_doc v6 methods: got {kc6['methods']}"
    assert "standard" in kc6["templates"], "keycloak_doc v6 templates: 'standard' missing"
    assert kc6["clients"] == {}, f"keycloak_doc v6 clients: got {kc6['clients']}, want {{}}"
    assert kc6["authenticators"] == {}, f"keycloak_doc v6 authenticators: got {kc6['authenticators']}, want {{}}"
    assert kc6["mds"] == {"serial": 0, "next_update": "0001-01-01T00:00:00Z"}, \
        f"keycloak_doc v6 mds: got {kc6['mds']}"
    # keycloak_doc v5: no file for v5, returns empty.
    kc5 = keycloak_doc(5)
    assert kc5 == {}, f"keycloak_doc v5: got {kc5}, want {{}}"


# ── tests/lib.sh (compose with the Hub's env) ───────────────────────

def sh(func: str, *args: str, stdin: Optional[str] = None, check: bool = True) -> str:
    script = f'source tests/lib.sh; trap - EXIT; {func} "$@"'
    p = subprocess.run(["bash", "-c", script, "lib", *args], cwd=TEMPLATES_DIR, input=stdin, text=True,
                       capture_output=True, env=dict(os.environ, PROJECT_DIR=PROJECT_DIR, TEMPLATES_DIR=TEMPLATES_DIR))
    if check and p.returncode != 0:
        raise RuntimeError(f"tests/lib.sh {func} failed ({p.returncode}): {p.stdout[-2000:]} {p.stderr[-2000:]}")
    return p.stdout


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True).stdout.strip()


def wait_containers(timeout: int) -> None:
    """Every service of the app runs (healthy, if it has a healthcheck);
    one-shot init containers may have exited 0. A service with compose
    profiles: runs only when one of them is selected: COMPOSE_PROFILES when
    set, else what the setup choices' defaults start (the Hub's ProfilesFor
    without stored values; tests/lib.sh compose_up starts the same)."""
    if "COMPOSE_PROFILES" in os.environ:
        selected = {p.strip() for p in os.environ["COMPOSE_PROFILES"].split(",") if p.strip()}
    else:
        selected = set()
        for o in ((MANIFEST.get("settings") or {}).get("options") or []):
            if isinstance(o, dict) and isinstance(o.get("profiles"), dict):
                selected.update(o["profiles"].get(o.get("default")) or [])
    services = [n for n, svc in (COMPOSE.get("services") or {}).items()
                if not (svc or {}).get("profiles") or "*" in selected
                or selected & set((svc or {}).get("profiles") or [])]
    # One-shot helpers (restart: "no") must have finished successfully.
    oneshot = {n for n, svc in (COMPOSE.get("services") or {}).items() if str((svc or {}).get("restart", "")) == "no"}
    deadline = time.time() + timeout
    state: Dict[str, str] = {}
    while time.time() < deadline:
        state = {}
        for s in services:
            st = docker("inspect", "-f", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}} "
                        "{{.State.ExitCode}} {{.RestartCount}}", f"portcullis-{s}-1")
            state[s] = st
        def ready(svc: str, st: str) -> bool:
            parts = st.split()
            if not parts:
                return False
            if svc in oneshot:
                return parts[0] == "exited" and parts[-2] == "0"
            if parts[0] == "running":
                return len(parts) == 3 or parts[1] == "healthy"
            return parts[0] == "exited" and parts[-2] == "0"
        broken = [s for s in oneshot if state.get(s, "").startswith("exited") and state[s].split()[-2] != "0"]
        if broken:
            raise RuntimeError(f"one-shot service(s) {', '.join(broken)} failed: {state}")
        if all(ready(svc, st) for svc, st in state.items()):
            log(f"containers ready: {state}")
            return
        time.sleep(5)
    raise RuntimeError(f"containers not ready after {timeout}s: {state}")


def fresh_start() -> None:
    """Start from a fresh install: stop what the shell test left and drop
    the app's volumes (the default instance's portcullis_<key>), so its
    state (half-run setup sidecars, brute-force throttles from refused
    password logins) can't decide the result."""
    sh("compose_down", APP, check=False)
    for key in (COMPOSE.get("volumes") or {}):
        docker("volume", "rm", "-f", f"portcullis_{key}")


def wait_log(service: str, text: str, timeout: int) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = subprocess.run(["docker", "logs", f"portcullis-{service}-1"], capture_output=True, text=True)
        if text in out.stdout or text in out.stderr:
            log(f"setup: {service} logged {text!r}")
            return
        time.sleep(3)
    raise RuntimeError(f"{service} did not log {text!r} within {timeout}s")


def run_setup() -> None:
    """tests.signin.setup: post-start steps an admin would do (e.g.
    Headscale's API key for Headplane): run a command in a service; with
    save_env, save its last output line as that app env value and restart
    the app with it."""
    steps = SIGNIN.get("setup") or []
    if not steps:
        return
    restart = False
    for st in steps:
        if st.get("restart"):
            after = st.get("after_log") or {}
            if after:
                wait_log(after["service"], after["text"], int(SIGNIN.get("boot_timeout", 600)))
            restart = True
            log("setup: restart the app")
            continue
        user = ["-u", st["user"]] if st.get("user") else []
        out = subprocess.run(["docker", "exec", *user, f"portcullis-{st['service']}-1", *st["command"]],
                             capture_output=True, text=True, timeout=120)
        if out.returncode != 0:
            raise RuntimeError(f"setup {st['command']}: {out.stderr[-500:]}")
        if st.get("save_env"):
            val = out.stdout.strip().splitlines()[-1].strip()
            os.environ[st["save_env"]] = val
            restart = True
            log(f"setup: {st['save_env']} from `{' '.join(st['command'])}`")
        else:
            log(f"setup: ran `{' '.join(st['command'])}` in {st['service']}")
    if restart:
        sh("compose_down", APP, check=False)
        sh("compose_up", APP)


def ai_page_delivery() -> None:
    """An AI page (manifest ai.chat) reads the Hub's ai-providers.json at
    every start: deliver it like the Hub does for an instance with no
    provider selected (tests/lib.sh write_ai_providers_override)."""
    if not ((MANIFEST.get("ai") or {}).get("chat")):
        return
    out = os.path.join(tempfile.mkdtemp(prefix="e2e-ai-"), "override.yml")
    doc = json.dumps({"version": 1, "instance": APP, "providers": []})
    sh("write_ai_providers_override", APP, doc, out)
    os.environ["COMPOSE_OVERRIDE"] = out
    log(f"ai.chat: ai-providers.json delivered (no provider) via {out}")


# ── Browser ────────────────────────────────────────────────────────

class Authenticator:
    """Virtual FIDO2 security key (CTAP2, USB, resident keys, UV), answering
    every prompt; counts registrations and assertions."""

    def __init__(self, page):
        self.cdp = page.context.new_cdp_session(page)
        self.cdp.send("WebAuthn.enable", {"enableUI": False})
        self.id = self.cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "usb", "hasResidentKey": True, "hasUserVerification": True,
            "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
        self.registered = self.asserted = 0
        self.cdp.on("WebAuthn.credentialAdded", lambda _e: setattr(self, "registered", self.registered + 1))
        self.cdp.on("WebAuthn.credentialAsserted", lambda _e: setattr(self, "asserted", self.asserted + 1))


def shot(page, name: str) -> None:
    from playwright.sync_api import Error as PWError
    global _shot
    _shot += 1
    base = os.path.join(ART, f"{_shot:02d}-{re.sub(r'[^A-Za-z0-9_.-]', '_', name)}")
    try:
        page.screenshot(path=base + ".png", full_page=True)
        with open(base + ".html", "w", encoding="utf-8") as f:
            f.write(f"<!-- {page.url} -->\n" + page.content())
    except PWError:
        pass


def goto(page, url: str, attempts: int = 6):
    """page.goto, retried on transient network errors (Chromium reports
    ERR_NETWORK_CHANGED while Docker creates the app's networks)."""
    from playwright.sync_api import Error as PWError
    for i in range(attempts):
        try:
            return page.goto(url, wait_until="domcontentloaded")
        except PWError as e:
            if i == attempts - 1 or not re.search(r"ERR_(NETWORK_CHANGED|CONNECTION_|NAME_NOT_RESOLVED|EMPTY_RESPONSE)", str(e)):
                raise
            log(f"  goto {url.split('?')[0]}: {str(e).splitlines()[0]}; retrying")
            page.wait_for_timeout(3000)
    return None


def host_of(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def on_login_pages(page) -> bool:
    h = host_of(page.url)
    return h in (AUTH_HOST, ENROLL_HOST)


def visible(page, selector: str) -> bool:
    from playwright.sync_api import Error as PWError
    try:
        loc = page.locator(selector)
        return loc.count() > 0 and loc.first.is_visible()
    except PWError:
        return False


def body_text(page) -> str:
    from playwright.sync_api import Error as PWError
    try:
        return page.inner_text("body", timeout=5000)
    except PWError:
        return ""


class Flow:
    """One user's browser: setup link, passkey, the app's own sign-in."""

    def __init__(self, ctx, role: str, user: str = ""):
        self.ctx, self.role, self.user = ctx, role, user or USERS[role]
        self.expect_refused = role in ("outsider", "refused")
        self.page = ctx.new_page()
        self.key = Authenticator(self.page)
        self.nav: List[Tuple[int, str]] = []    # main-frame navigations on the app's hosts
        self.passwords: List[str] = []
        self.denied = ""
        self.landed = False                     # reached the app's host after the setup link
        self.aborted = False                    # stopped by a test failure (password field), not a refusal
        self.seen: List[str] = []               # page texts on the app's hosts, for expected_fail.match
        self.broken = ""                        # why the test itself broke (never an expected failure)
        self.marks = log_marks()                # this flow's log window
        self.page.on("response", self._on_response)

    def _on_response(self, resp) -> None:
        from playwright.sync_api import Error as PWError
        try:
            if resp.request.is_navigation_request() and resp.frame == self.page.main_frame:
                if host_of(resp.url) in HOSTS.values():
                    self.nav.append((resp.status, resp.url))
        except PWError:
            pass

    def check(self, spec: Dict[str, Any], host: str) -> Tuple[bool, str]:
        """Evaluate a signed_in / admin spec (polled for `wait` seconds);
        returns (ok, evidence)."""
        deadline = time.time() + int(spec.get("wait", 10))
        while True:
            ok, ev = self._check_once(spec, host)
            if ok or time.time() >= deadline:
                return ok, ev
            self.page.wait_for_timeout(2000)

    def _want(self, spec: Dict[str, Any], default: Any = "{username}") -> Any:
        want = spec.get("equals", default)
        return subst(want, self.user) if isinstance(want, str) else want

    def _check_once(self, spec: Dict[str, Any], host: str) -> Tuple[bool, str]:
        ok, ev = self._check_core(spec, host)
        if ok and spec.get("absent"):
            # The app's own denial page (e.g. a session without any rights).
            no = subst(spec["absent"], self.user)
            if no.lower() in body_text(self.page).lower():
                return False, f"{ev}, but the page says {no!r}"
        return ok, ev

    def _check_core(self, spec: Dict[str, Any], host: str) -> Tuple[bool, str]:
        from playwright.sync_api import Error as PWError
        page = self.page
        if spec.get("url_contains") and spec["url_contains"] not in page.url:
            return False, f"URL {page.url.split('?')[0]} lacks {spec['url_contains']!r}"
        if "json" in spec:
            j = spec["json"]
            url = subst(j["url"], self.user)
            try:
                r = page.request.get(f"https://{host}{url}", headers=j.get("headers") or {}, timeout=15_000)
            except PWError as e:
                return False, f"GET {url}: {e}"
            if not r.ok:
                return False, f"GET {url}: HTTP {r.status}"
            try:
                val: Any = r.json()
            except (PWError, ValueError):
                return False, f"GET {url}: not JSON"
            for part in str(j["field"]).split("."):
                if isinstance(val, list) and part.isdigit() and int(part) < len(val):
                    val = val[int(part)]
                elif isinstance(val, dict):
                    val = val.get(part)
                else:
                    val = None
            if "contains" in j:
                want = subst(str(j["contains"]), self.user)
                return isinstance(val, list) and want in val, f"GET {url} {j['field']} = {val!r} (want it to contain {want!r})"
            want = self._want(j)
            return val == want, f"GET {url} {j['field']} = {val!r} (want {want!r})"
        if "js" in spec:
            if spec.get("url") and not page.url.split("://", 1)[-1].endswith(host + subst(spec["url"], self.user)):
                try:
                    goto(page, f"https://{host}{subst(spec['url'], self.user)}")
                    page.wait_for_timeout(1500)
                except PWError as e:
                    return False, f"{spec['url']}: {e}"
            if host_of(page.url) != host:
                return False, f"not on {host} ({page.url.split('?')[0]})"
            try:
                val = page.evaluate(subst(spec["js"], self.user))
            except PWError as e:
                return False, f"js: {str(e).splitlines()[0]}"
            want = self._want(spec)
            return val == want, f"js = {val!r} (want {want!r})"
        if "reach" in spec:
            path = subst(spec["reach"], self.user)
            try:
                resp = page.goto(f"https://{host}{path}", wait_until="domcontentloaded")
            except PWError as e:
                return False, f"{path}: {e}"
            code = resp.status if resp else 0
            ok = 200 <= code < 300 and host_of(page.url) == host
            if ok and spec.get("text"):
                page.wait_for_timeout(1500)
                ok = subst(spec["text"], self.user) in body_text(page)
            return ok, f"{path}: HTTP {code} at {page.url.split('?')[0]}" + (
                f" (text {spec['text']!r} {'found' if ok else 'missing'})" if spec.get("text") and 200 <= code < 300 else "")
        kind = "html" if "html" in spec else "text"
        want = subst(spec.get(kind) or "", self.user)
        if spec.get("url"):
            try:
                page.goto(f"https://{host}{subst(spec['url'], self.user)}", wait_until="domcontentloaded")
            except PWError as e:
                return False, f"{spec['url']}: {e}"
        if host_of(page.url) != host or on_login_pages(page):
            return False, f"not on {host} ({page.url.split('?')[0]})"
        try:
            hay = page.content() if kind == "html" else body_text(page)
        except PWError:
            hay = ""
        return want.lower() in hay.lower(), f"{kind} {want!r} {'found' if want.lower() in hay.lower() else 'missing'} at {page.url.split('?')[0]}"

    def password_visible(self) -> bool:
        if visible(self.page, "input[type=password]"):
            where = self.page.url.split("?")[0]
            if where not in self.passwords:
                self.passwords.append(where)
                shot(self.page, f"{self.role}-password")
            return True
        return False

    def sign_in(self, link: str, host: str, deadline_s: int) -> Tuple[bool, str]:
        """Drive the setup link, Keycloak and the app's own sign-in until
        `signed_in` holds. Returns (signed_in, evidence)."""
        from playwright.sync_api import Error as PWError
        page = self.page
        goto(page, link)
        shot(page, f"{self.role}-setup-link")
        if self.user not in page.content():
            return False, "the setup link page does not name the user"
        deadline = time.time() + deadline_s
        landed_at = 0.0
        clicked: Dict[str, int] = {}
        reloads_404 = 0
        last = ""
        settle = int(SIGNIN.get("refused_after", 45))
        while time.time() < deadline:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=TIMEOUT_MS)
            except PWError:
                pass
            url = page.url
            if url.startswith("chrome-error://") and not landed_at:
                shot(page, f"{self.role}-browser-error")
                self.broken = "browser error"
                return False, f"browser error page before reaching the app (after {self.nav[-1][1] if self.nav else 'the setup link'})"
            if url.startswith("chrome-error://"):
                last = f"browser error page after {self.nav[-1][1].split('?')[0] if self.nav else link.split('/invite/')[0]}"
                page.wait_for_timeout(3000)
                try:
                    goto(page, f"https://{host}{SIGNIN.get('path', '/')}")
                except PWError as e:
                    last = f"{last}; {str(e).splitlines()[0]}"
                continue
            if on_login_pages(page):
                if self.password_visible():
                    self.aborted = True
                    self.broken = "password field"
                    return False, f"password field on the sign-in pages ({url.split('?')[0]})"
                for sel in ("#invite-continue", "#registerWebAuthn", "#authenticateWebAuthnButton"):
                    if visible(page, sel):
                        shot(page, f"{self.role}-{sel[1:]}")
                        page.click(sel)
                        page.wait_for_timeout(1500)
                        break
                else:
                    err = page.locator(".pf-m-danger, .alert-error, #input-error, .kc-feedback-text, #kc-try-again")
                    try:
                        if err.count() and err.first.is_visible():
                            shot(page, f"{self.role}-keycloak-error")
                            if landed_at:
                                self.denied = f"refused at {url.split('?')[0]}: {err.first.inner_text()[:200]!r}"
                            self.broken = "Keycloak/enroll error"
                            return False, f"Keycloak/enroll error at {url.split('?')[0]}: {err.first.inner_text()[:200]!r}"
                    except PWError:
                        pass
                    page.wait_for_timeout(700)
                continue
            if host_of(url) not in HOSTS.values():
                page.wait_for_timeout(700)   # oauth2-proxy and app redirects
                continue
            seen = body_text(page)[:4000]
            if seen and (not self.seen or self.seen[-1] != seen) and len(self.seen) < 200:
                self.seen.append(seen)
            if not landed_at:
                landed_at = time.time()
                self.landed = True
                shot(page, f"{self.role}-landed")
            if self.password_visible() and not SIGNIN.get("password"):
                self.aborted = True
                self.broken = "password field"
                return False, f"password field at {url.split('?')[0]} (no tests.signin.password documents one)"
            # v6: setup-link step-up walk - click #stepup-continue and touch the authenticator.
            if policy_version() >= 6 and visible(page, "#stepup-continue"):
                shot(page, f"{self.role}-stepup-continue")
                page.click("#stepup-continue")
                page.wait_for_timeout(1500)
                continue
            status = self.nav[-1][0] if self.nav else 0
            if status == 403:
                self.denied = f"HTTP 403 at {self.nav[-1][1].split('?')[0]}"
                if self.expect_refused:
                    shot(page, f"{self.role}-denied")
                    return False, self.denied
            # 502-504: the app is still starting, retry. A 404 is retried a
            # couple of times only: it is usually the app's answer (an error
            # page), and hammering a login URL trips the app's rate limits.
            if status in PROBLEM_CODES and (status != 404 or reloads_404 < 2):
                reloads_404 += status == 404
                last = f"HTTP {status} at {url.split('?')[0]}"
                page.wait_for_timeout(3000)
                try:
                    goto(page, f"https://{host}{SIGNIN.get('path', '/')}")
                except PWError:
                    pass
                continue
            spec = SIGNIN["signed_in"]
            # A check that opens its own page waits while the app's sign-in
            # steps are on screen (navigating away would cancel them).
            at_check = bool(spec.get("url")) and page.url.split("://", 1)[-1].endswith(
                host + subst(spec["url"], self.user))
            busy = bool(spec.get("url")) and not at_check and any(
                visible(page, sel) for sel in list(SIGNIN.get("login") or []) +
                [f["selector"] for f in SIGNIN.get("fill") or []])
            ok, last = (False, f"sign-in steps on {page.url.split('?')[0]}") if busy else self._check_once(spec, host)
            if ok:
                shot(page, f"{self.role}-signed-in")
                return True, last
            if self.expect_refused and time.time() - landed_at > settle:
                break
            for f in SIGNIN.get("fill") or []:
                sel, val = f["selector"], subst(f["value"], self.user)
                try:
                    if visible(page, sel) and page.locator(sel).first.input_value() != val:
                        page.locator(sel).first.fill(val)
                except PWError:
                    pass
            for sel in SIGNIN.get("login") or []:
                if clicked.get(sel, 0) < int(SIGNIN.get("max_clicks", 5)) and host_of(page.url) in HOSTS.values() and visible(page, sel):
                    clicked[sel] = clicked.get(sel, 0) + 1
                    shot(page, f"{self.role}-click")
                    try:
                        page.click(sel, timeout=5000)
                        page.wait_for_load_state("domcontentloaded", timeout=TIMEOUT_MS)
                    except PWError as e:
                        log(f"  click {sel}: {e}")
                    page.wait_for_timeout(2000)
                    break
            else:
                page.wait_for_timeout(1500)
        shot(page, f"{self.role}-end")
        return False, last or f"stuck at {page.url.split('?')[0]}"


def invite(user: str, landing: str) -> str:
    out = subprocess.run([os.path.join(PROJECT_DIR, "portcullis"), "invite", user, "--to", landing, "--json"],
                         cwd=PROJECT_DIR, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(f"portcullis invite {user}: {out.stderr[-500:]}")
    return json.loads(out.stdout.strip().splitlines()[-1])["url"]


def run_role(browser, role: str, host: str, user: str = "") -> None:
    path = SIGNIN.get("path", "/")
    user = user or USERS[role]
    check = role if role != "refused" else f"refused:{user}"
    ctx = browser.new_context()
    ctx.set_default_timeout(TIMEOUT_MS)
    ctx.on("page", lambda p: p.on("dialog", lambda d: d.accept(d.default_value)))
    ctx.tracing.start(screenshots=True, snapshots=True, name=check.replace(":", "-"))
    flow = Flow(ctx, role, user)
    xf = XFAIL.get(role) if role != "refused" else None
    try:
        link = invite(user, f"https://{host}{path}")
        ok, ev = flow.sign_in(link, host, int(SIGNIN.get("timeout", 240)))
        pw_note = f"; password field at {', '.join(flow.passwords)} ({SIGNIN.get('password')})" if flow.passwords else ""
        # The setup link registers exactly one passkey; anything else is a
        # broken sign-in, never an expected failure.
        if flow.key.registered != 1:
            record(check, False, f"{user}: {flow.key.registered} passkeys registered by the setup link (want 1); {ev}")
            return
        if flow.expect_refused:
            # Refused = it got through the setup link to the app (or to the
            # app's sign-in at Keycloak) and was never signed in; anything
            # that stops earlier is a broken test, not a refusal. Behind
            # group-gate the refusal is its HTTP 403, nothing else.
            refused = not ok and not flow.aborted and (flow.landed or bool(flow.denied))
            how = flow.denied or ev
            denied_host = host_of(flow.nav[-1][1]) if flow.nav else host
            if refused and role == "refused" and not flow.denied.startswith("HTTP 403"):
                refused = False
                how = f"not signed in, but no HTTP 403 ({ev})"
            elif refused and role == "outsider" and GATED:
                # Only group-gate's own refusal counts: its 403, its page,
                # and its DENIED log line for this user and host.
                page_says = "not authorized to access" in body_text(flow.page)
                logged = gate_denied(user, denied_host, flow.marks)
                if not (flow.denied.startswith("HTTP 403") and page_says and logged):
                    refused = False
                    how = (f"not signed in, but not refused by group-gate (403: {flow.denied.startswith('HTTP 403')}, "
                           f"its page: {page_says}, its DENIED log line: {logged}; {ev})")
                else:
                    how = f"{flow.denied}, group-gate DENIED user={user} host={denied_host}"
            elif not ok and not refused:
                how = f"test stopped: {ev}" if flow.aborted else f"never reached the app: {ev}"
            if refused and not SIGNED_IN and role == "outsider":
                # Nobody got in: the refusal proves nothing about the group.
                results.append({"app": APP, "check": "outsider", "status": "inconclusive",
                                "detail": f"{user} not signed in, but neither was anyone else: {how}"})
                log(f"INCONCLUSIVE: {APP} outsider: nobody could sign in ({how})")
                return
            detail = (f"{user} refused: {how}" if refused else
                      (f"{user} signed in: {ev}" if ok else f"{user}: {how}")) + pw_note
            # An expected failure here is "the outsider got in", nothing else.
            record(check, refused, detail, xf if (ok or refused) else None, flow.page, flow.seen, flow.marks)
            return
        if ok:
            SIGNED_IN.append(role)
        # A flow the test itself broke (password field, Keycloak/enroll or
        # browser error, never on the app) is never an expected failure.
        broken = flow.broken or ("" if flow.landed else "never reached the app")
        if broken and not ok:
            ev += f" [test broken: {broken}]"
            xf = None
        if role == "member":
            record("member", ok, f"{user}: {ev}{pw_note}", xf, flow.page, flow.seen, flow.marks)
            if ok and SIGNIN.get("admin"):
                is_admin, aev = flow.check(SIGNIN["admin"], host)
                record("member_not_admin", not is_admin, f"{user} admin check: {aev}")
            return
        # admin
        if not ok:
            record("admin", False, f"{user} not signed in: {ev}{pw_note}", xf, flow.page, flow.seen, flow.marks)
        elif SIGNIN.get("admin"):
            is_admin, aev = flow.check(SIGNIN["admin"], host)
            record("admin", is_admin, f"{user} signed in ({ev}); admin: {aev}{pw_note}", xf, flow.page, flow.seen, flow.marks)
        else:
            record("admin", True, f"{user} signed in ({ev}); no admin role in this app{pw_note}", xf)
    except Exception as e:  # noqa: BLE001 - a broken step is a failed check, never an expected one
        traceback.print_exc()
        record(check, False, f"{type(e).__name__}: {e}")
    finally:
        shot(flow.page, f"{check}-final")
        try:
            ctx.tracing.stop(path=os.path.join(ART, f"trace-{check.replace(':', '-')}.zip"))
        finally:
            ctx.close()


def warm_up(browser) -> None:
    """Chromium reports ERR_NETWORK_CHANGED for a while after Docker created
    the app's networks: load Keycloak until three loads in a row succeed."""
    from playwright.sync_api import Error as PWError
    ctx = browser.new_context()
    page = ctx.new_page()
    ok = 0
    deadline = time.time() + 90
    while ok < 3 and time.time() < deadline:
        try:
            r = page.goto(f"https://{AUTH_HOST}/realms/{REALM}/.well-known/openid-configuration",
                          wait_until="domcontentloaded", timeout=15_000)
            ok = ok + 1 if r and r.ok else 0
        except PWError as e:
            log(f"  warm-up: {str(e).splitlines()[0]}")
            ok = 0
        page.wait_for_timeout(2000)
    ctx.close()


def dump_logs() -> None:
    for s in (COMPOSE.get("services") or {}):
        with open(os.path.join(ART, f"container-{s}.log"), "w", encoding="utf-8") as f:
            f.write(subprocess.run(["docker", "logs", "--tail", "300", f"portcullis-{s}-1"],
                                   capture_output=True, text=True).stdout)
            f.write(subprocess.run(["docker", "logs", "--tail", "300", f"portcullis-{s}-1"],
                                   capture_output=True, text=True).stderr)


def summary() -> int:
    bad = [r for r in results if r["status"] in ("fail", "xpass")]
    with open(os.path.join(ART, "results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    lines = [f"### Sign-in e2e: {APP}", "", "| check | result | detail |", "|---|---|---|"]
    for r in results:
        lines.append(f"| {r['check']} | {r['status']} | {r['detail'].replace('|', '/')} |")
    text = "\n".join(lines) + "\n"
    log("\n" + text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    return 1 if bad else 0


def main() -> int:
    selftest()  # Verify policy_doc and keycloak_doc build correctly.
    if SIGNIN.get("skip"):
        results.append({"app": APP, "check": "signin", "status": "skip", "detail": SIGNIN["skip"]})
        return summary()
    if not SIGNIN.get("signed_in"):
        results.append({"app": APP, "check": "signin", "status": "fail",
                        "detail": "manifest has no tests.signin.signed_in (see CONTRIBUTING.md)"})
        return summary()
    export_env()
    host = main_host()
    try:
        lldap_setup()
        keycloak_setup()
        write_policy()
        ai_page_delivery()
        fresh_start()
        log(sh("compose_up", APP))
        wait_containers(int(SIGNIN.get("boot_timeout", 600)))
        run_setup()
        if SIGNIN.get("setup"):
            wait_containers(int(SIGNIN.get("boot_timeout", 600)))
    except Exception as e:  # noqa: BLE001
        traceback.print_exc()
        results.append({"app": APP, "check": "setup", "status": "fail", "detail": f"{type(e).__name__}: {e}"})
        dump_logs()
        return summary()
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])
        warm_up(browser)
        pause = int(SIGNIN.get("pause_between_users", 0))
        for i, role in enumerate(ROLES):
            if i and pause:
                log(f"  waiting {pause}s before {role} (tests.signin.pause_between_users)")
                time.sleep(pause)
            run_role(browser, role, host)
        for name in REFUSED_USERS:
            run_role(browser, "refused", host, name)
        browser.close()
    dump_logs()
    if os.environ.get("E2E_KEEP_UP") != "1":
        sh("compose_down", APP, check=False)
    return summary()


if __name__ == "__main__":
    sys.exit(main())
