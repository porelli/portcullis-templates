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
     group-gate policy file (groups, admin_paths);
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
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

import yaml
from playwright.sync_api import BrowserContext, Page, sync_playwright
from playwright.sync_api import Error as PWError

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


def record(check: str, ok: bool, detail: str, expected_fail: Optional[str]) -> None:
    if expected_fail:
        status = "xpass" if ok else "expected_fail"
        if ok:
            detail += f" — passes now: remove tests.signin.expected_fail.{check} ({expected_fail})"
        else:
            detail += f" — expected: {expected_fail}"
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
XFAIL: Dict[str, str] = SIGNIN.get("expected_fail") or {}

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
    for role, user in USERS.items():
        gql("mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
            {"u": {"id": user, "email": f"{user}@{DOMAIN}", "displayName": user}})
        want = {"admin": [ACCESS_GROUP, ADMIN_GROUP], "member": [ACCESS_GROUP], "outsider": []}[role]
        for g in want:
            if g:
                out = gql("mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }",
                          {"u": user, "g": groups[g]})
                if out.get("errors") and "already" not in json.dumps(out["errors"]).lower() \
                        and "unique" not in json.dumps(out["errors"]).lower():
                    raise RuntimeError(f"LLDAP addUserToGroup {user} {g}: {out['errors']}")
    log(f"LLDAP: {USERS['admin']} in {ACCESS_GROUP or '-'} + {ADMIN_GROUP or '-'}, "
        f"{USERS['member']} in {ACCESS_GROUP or '-'}, {USERS['outsider']} in no group")


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


def policy_version() -> int:
    try:
        src = open(os.path.join(PROJECT_DIR, "group-gate", "group-gate.py"), encoding="utf-8").read()
        return int(re.search(r"^POLICY_VERSION\s*=\s*(\d+)", src, re.M).group(1))
    except (OSError, AttributeError):
        return 4


def write_policy() -> None:
    """The group-gate policy file the Hub writes for this app (contract §4):
    every host of the app requires access_group, admin_paths require
    admin_group too; the Hub's fresh-install default policy."""
    ver = policy_version()
    groups: Dict[str, str] = {}
    paths: Dict[str, list] = {}
    for host in HOSTS.values():
        key = host if ver >= 5 else host[: -len(DOMAIN) - 1]
        if ACCESS_GROUP and AUTH.get("group_access"):
            groups[key] = ACCESS_GROUP
        if AUTH.get("admin_paths") and ADMIN_GROUP:
            paths[key] = [{"prefix": p.rstrip("/") or "/", "group": ADMIN_GROUP} for p in AUTH["admin_paths"]]
    doc = {"version": ver, "default": {"factors": ["mtls", "webauthn"], "op": "any"},
           "groups": groups, "path_groups": paths}
    sh("_hub_data_write", stdin=json.dumps(doc))
    log(f"group-gate policy (version {ver}): {json.dumps(doc)}")


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
    one-shot init containers may have exited 0."""
    services = list((COMPOSE.get("services") or {}).keys())
    deadline = time.time() + timeout
    state: Dict[str, str] = {}
    while time.time() < deadline:
        state = {}
        for s in services:
            st = docker("inspect", "-f", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}} "
                        "{{.State.ExitCode}} {{.RestartCount}}", f"portcullis-{s}-1")
            state[s] = st
        def ready(st: str) -> bool:
            parts = st.split()
            if not parts:
                return False
            if parts[0] == "running":
                return len(parts) == 3 or parts[1] == "healthy"
            return parts[0] == "exited" and parts[-2] == "0"
        if all(ready(st) for st in state.values()):
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
        sh("compose_up", APP)


# ── Browser ────────────────────────────────────────────────────────

class Authenticator:
    """Virtual FIDO2 security key (CTAP2, USB, resident keys, UV), answering
    every prompt; counts registrations and assertions."""

    def __init__(self, page: Page):
        self.cdp = page.context.new_cdp_session(page)
        self.cdp.send("WebAuthn.enable", {"enableUI": False})
        self.id = self.cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "usb", "hasResidentKey": True, "hasUserVerification": True,
            "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
        self.registered = self.asserted = 0
        self.cdp.on("WebAuthn.credentialAdded", lambda _e: setattr(self, "registered", self.registered + 1))
        self.cdp.on("WebAuthn.credentialAsserted", lambda _e: setattr(self, "asserted", self.asserted + 1))


def shot(page: Page, name: str) -> None:
    global _shot
    _shot += 1
    base = os.path.join(ART, f"{_shot:02d}-{re.sub(r'[^A-Za-z0-9_.-]', '_', name)}")
    try:
        page.screenshot(path=base + ".png", full_page=True)
        with open(base + ".html", "w", encoding="utf-8") as f:
            f.write(f"<!-- {page.url} -->\n" + page.content())
    except PWError:
        pass


def goto(page: Page, url: str, attempts: int = 6):
    """page.goto, retried on transient network errors (Chromium reports
    ERR_NETWORK_CHANGED while Docker creates the app's networks)."""
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


def on_login_pages(page: Page) -> bool:
    h = host_of(page.url)
    return h in (AUTH_HOST, ENROLL_HOST)


def visible(page: Page, selector: str) -> bool:
    try:
        loc = page.locator(selector)
        return loc.count() > 0 and loc.first.is_visible()
    except PWError:
        return False


def body_text(page: Page) -> str:
    try:
        return page.inner_text("body", timeout=5000)
    except PWError:
        return ""


class Flow:
    """One user's browser: setup link, passkey, the app's own sign-in."""

    def __init__(self, ctx: BrowserContext, role: str):
        self.ctx, self.role, self.user = ctx, role, USERS[role]
        self.page = ctx.new_page()
        self.key = Authenticator(self.page)
        self.nav: List[Tuple[int, str]] = []    # main-frame navigations on the app's hosts
        self.passwords: List[str] = []
        self.denied = ""
        self.landed = False                     # reached the app's host after the setup link
        self.aborted = False                    # stopped by a test failure (password field), not a refusal
        self.page.on("response", self._on_response)

    def _on_response(self, resp) -> None:
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
        page = self.page
        goto(page, link)
        shot(page, f"{self.role}-setup-link")
        if self.user not in page.content():
            return False, "the setup link page does not name the user"
        deadline = time.time() + deadline_s
        landed_at = 0.0
        clicked: Dict[str, int] = {}
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
                            return False, f"Keycloak/enroll error at {url.split('?')[0]}: {err.first.inner_text()[:200]!r}"
                    except PWError:
                        pass
                    page.wait_for_timeout(700)
                continue
            if host_of(url) not in HOSTS.values():
                page.wait_for_timeout(700)   # oauth2-proxy and app redirects
                continue
            if not landed_at:
                landed_at = time.time()
                self.landed = True
                shot(page, f"{self.role}-landed")
            if self.password_visible() and not SIGNIN.get("password"):
                self.aborted = True
                return False, f"password field at {url.split('?')[0]} (no tests.signin.password documents one)"
            status = self.nav[-1][0] if self.nav else 0
            if status == 403:
                self.denied = f"HTTP 403 at {self.nav[-1][1].split('?')[0]}"
                if self.role == "outsider":
                    shot(page, f"{self.role}-denied")
                    return False, self.denied
            if status in PROBLEM_CODES:
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
            busy = bool(spec.get("url")) and any(
                visible(page, sel) for sel in list(SIGNIN.get("login") or []) +
                [f["selector"] for f in SIGNIN.get("fill") or []])
            ok, last = (False, f"sign-in steps on {page.url.split('?')[0]}") if busy else self._check_once(spec, host)
            if ok:
                shot(page, f"{self.role}-signed-in")
                return True, last
            if self.role == "outsider" and time.time() - landed_at > settle:
                break
            for f in SIGNIN.get("fill") or []:
                sel, val = f["selector"], subst(f["value"], self.user)
                try:
                    if visible(page, sel) and page.locator(sel).first.input_value() != val:
                        page.locator(sel).first.fill(val)
                except PWError:
                    pass
            for sel in SIGNIN.get("login") or []:
                if clicked.get(sel, 0) < 5 and host_of(page.url) in HOSTS.values() and visible(page, sel):
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


def run_role(browser, role: str, host: str) -> None:
    path = SIGNIN.get("path", "/")
    user = USERS[role]
    ctx = browser.new_context()
    ctx.set_default_timeout(TIMEOUT_MS)
    ctx.on("page", lambda p: p.on("dialog", lambda d: d.accept(d.default_value)))
    ctx.tracing.start(screenshots=True, snapshots=True, name=role)
    flow = Flow(ctx, role)
    failed = False
    try:
        link = invite(user, f"https://{host}{path}")
        ok, ev = flow.sign_in(link, host, int(SIGNIN.get("timeout", 240)))
        if flow.key.registered != 1:
            ev += f" (passkeys registered: {flow.key.registered})"
        pw_note = f"; password field at {', '.join(flow.passwords)} ({SIGNIN.get('password')})" if flow.passwords else ""
        if role == "outsider":
            # Refused = it got through the setup link to the app (or to the
            # app's sign-in at Keycloak) and was never signed in; anything
            # that stops earlier is a broken test, not a refusal.
            refused = not ok and not flow.aborted and (flow.landed or bool(flow.denied))
            how = flow.denied or ev
            if not ok and not refused:
                how = f"test stopped: {ev}" if flow.aborted else f"never reached the app: {ev}"
            record("outsider", refused, (f"{user} refused: {how}" if refused else (f"{user} signed in: {ev}" if ok else f"{user}: {how}")) + pw_note,
                   XFAIL.get("outsider") if (ok or refused) else None)
            failed = not refused and not XFAIL.get("outsider")
            return
        if role == "member":
            record("member", ok, f"{user}: {ev}{pw_note}", XFAIL.get("member"))
            failed = not ok and not XFAIL.get("member")
            if ok and SIGNIN.get("admin"):
                is_admin, aev = flow.check(SIGNIN["admin"], host)
                record("member_not_admin", not is_admin, f"{user} admin check: {aev}", XFAIL.get("member"))
                failed = failed or (is_admin and not XFAIL.get("member"))
            return
        # admin
        if not ok:
            record("admin", False, f"{user} not signed in: {ev}{pw_note}", XFAIL.get("admin"))
            failed = not XFAIL.get("admin")
        elif SIGNIN.get("admin"):
            is_admin, aev = flow.check(SIGNIN["admin"], host)
            record("admin", is_admin, f"{user} signed in ({ev}); admin: {aev}{pw_note}", XFAIL.get("admin"))
            failed = not is_admin and not XFAIL.get("admin")
        else:
            record("admin", True, f"{user} signed in ({ev}); no admin role in this app{pw_note}", XFAIL.get("admin"))
    except Exception as e:  # noqa: BLE001 - a broken step is a failed check
        traceback.print_exc()
        record(role, False, f"{type(e).__name__}: {e}", XFAIL.get(role))
        failed = True
    finally:
        shot(flow.page, f"{role}-final")
        try:
            ctx.tracing.stop(path=os.path.join(ART, f"trace-{role}.zip"))
        finally:
            ctx.close()


def warm_up(browser) -> None:
    """Chromium reports ERR_NETWORK_CHANGED for a while after Docker created
    the app's networks: load Keycloak until three loads in a row succeed."""
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
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])
        warm_up(browser)
        for role in ROLES:
            run_role(browser, role, host)
        browser.close()
    dump_logs()
    if os.environ.get("E2E_KEEP_UP") != "1":
        sh("compose_down", APP, check=False)
    return summary()


if __name__ == "__main__":
    sys.exit(main())
