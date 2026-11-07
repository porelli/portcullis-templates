#!/usr/bin/env python3
"""mcp-hook.py: Portcullis AI support for Home Assistant's built-in MCP
Server integration (mcp_server; integration contracts §3.2 app_oauth, §15.5
hook I/O). Home Assistant is its own OAuth authorization server; people
sign in to it through Keycloak (auth_oidc). The gate is not in the path and
this hook never sees tool traffic. The hooks run it in the homeassistant
service (mounted read-only):

  on_change  stdin {"action":"on_change","enabled":true|false,"mode":"read_write","companion":"homeassistant"}
  revoke     stdin {"action":"revoke","user":"<username>","sub":"<Keycloak user id>","ids":[]}
             (one call per Keycloak id the Hub saw for the person)
             or    {"action":"revoke_all","prefix":"portcullis-ai-"}

Exit 0 = done and confirmed; anything else = failed (1), or 143 when ended
by TERM / INT / HUP. stdout is unused.

Verified against Home Assistant 2026.10.4 (homeassistant/components/
mcp_server, components/auth, components/config, auth/__init__.py):

Admin context. Home Assistant has no CLI that mints a token while it runs
(`hass --script auth` only edits the homeassistant provider's storage
offline), and a long-lived token can only be created by a signed-in user.
prestart.py (this service's entrypoint, before Home Assistant starts)
therefore provisions the system user "Portcullis hooks" (system-admin,
local_only, no credentials) with one system refresh token, new at every
start. It can't sign in interactively: it has no credential of any auth
provider (auth_oidc only finds users by their OIDC sub credential, and
skips system users when it links), the homeassistant password provider
isn't configured (auth_providers: []) and config/auth_provider/
homeassistant/create refuses system users anyway, config/auth/update and
delete refuse them, and local_only refuses its tokens from anywhere but
a local address (Home Assistant's "local network": private ranges, the
LAN included, not only loopback). Only on_change uses it (revoke and revoke_all revoke
by token value and need no admin). An on_change run reads it from
/config/.storage/auth and exchanges it:
    POST /auth/token  grant_type=refresh_token&refresh_token=<token>   (no client_id)
for an access token that lives 60 s (re-exchanged after 30 s), held in this
process only: never on an argv, in the environment, a file or the output.
Nothing is created per run, so nothing is left behind when a run dies.

on_change (REST, as the hook admin):
    GET    /api/config/config_entries/entry?domain=mcp_server
    enabled true, unless exactly one loaded, enabled entry exists:
      DELETE /api/config/config_entries/entry/<entry_id>      (each entry)
      POST   /api/config/config_entries/flow {"handler":"mcp_server"}   -> form "user"
      POST   /api/config/config_entries/flow/<flow_id> {}              -> create_entry
             (upstream creates it with require_admin true, all LLM APIs)
    then the options flow ("Require an administrator account" off, the
    Assist API only = only Assist-exposed entities):
      POST   /api/config/config_entries/options/flow {"handler":"<entry_id>"}
      POST   /api/config/config_entries/options/flow/<flow_id>
             {"all_llm_apis":false,"llm_hass_api":["assist"],"require_admin":false}
             (the form is re-rendered once when all_llm_apis changes; only the
             fields the form shows are sent)
    confirmed by: the entry's data in .storage/core.config_entries, state
    "loaded", and POST /api/mcp initialize answering 200.
    enabled false: DELETE every entry, then confirm the list is empty and
    POST /api/mcp and /api/mcp/assist both answer 404. Removing the entry at
    runtime leaves /api/mcp/<api id> served until Home Assistant restarts
    (mcp_server registers its views once): the Hub's switch-off recreates
    the container, and prestart.py removes the entry before Home Assistant
    starts, so normally both answer 404; if not, this fails ("restart").
    enabled true also requires HA_AI_ENABLED=true in this container, so a
    later start doesn't strip the entry again.

revoke (one person; ids [] = every app-side token, contract §15.5). The
person is the Home Assistant user holding the auth_oidc credential whose
data.sub equals the stdin "sub" exactly: auth_oidc keys accounts on the
OIDC sub alone (its credential stores {"sub"} and nothing else) and never
links by name or email. The user name is used for nothing (people rename
themselves: person/update_own_profile). No such credential = no Home
Assistant account (exit 0); more than one, any auth_oidc credential
without a sub (it could be the person's), or an unreadable store = exit 1.
The websocket auth/delete_refresh_token only acts on the caller's own
tokens, so every refresh token of that user (web sessions, Companion apps,
long-lived access tokens, MCP clients; whenever created) is revoked
through the OAuth revocation endpoint (RFC 7009, advertised in
/.well-known/oauth-authorization-server):
    POST /auth/revoke  token=<refresh token>
reading the tokens from .storage/auth, then read back there (polled up to
20 s: upstream saves 1 s after a change) and repeated until none remains
(at most 5 rounds, else exit 1). The account is not deactivated: a leaver
has lost the instance's access role, so Keycloak refuses their next
Home Assistant sign-in. Residual: an authorization code Home Assistant
issued before they left can still be exchanged for a new refresh token
until it expires, 10 minutes after it was issued (components/auth
__init__.py, _create_auth_code_store: "timedelta(minutes=10)"); the
Hub's revoke at its next reconcile ends that token too only if it runs
after the exchange.

revoke_all (every person's MCP tokens): every refresh token of a non-system
user of type "normal" (an OAuth client's) whose client_id isn't Home
Assistant's own web frontend (https://<HA_EXTERNAL_URL host>/) or the
official Companion apps (https://home-assistant.io/iOS, /android) is
revoked through the OAuth revocation endpoint (RFC 7009, advertised in
/.well-known/oauth-authorization-server):
    POST /auth/revoke  token=<refresh token>
reading the tokens from .storage/auth, then confirmed there (polled), and
repeated until a scan finds none (at most 5 rounds). Home Assistant's own
first-party clients are kept: web sessions, the Companion apps, and
people's long-lived access tokens (type long_lived_access_token).

Input is one JSON object, parsed by the json module (duplicate keys
refused) and checked field by field: exact key sets, the username pattern
of LLDAP (^[a-z0-9][a-z0-9._-]{0,63}$), sub a Keycloak user id
(^[0-9a-fA-F-]{1,64}$, the Hub's keycloak.ValidUserID), ids exactly [], prefix exactly
portcullis-ai-, mode read_write, companion homeassistant. Anything else
exits 1 before Home Assistant is touched. A failed authentication from
127.0.0.1 counts towards Home Assistant's IP ban (threshold 10), so the
hook never sends a credential it hasn't read from Home Assistant's own
current storage.
"""

import asyncio
import json
import os
import re
import signal
import sys
import time

import aiohttp

BASE = "http://127.0.0.1:8123"
WS_URL = "ws://127.0.0.1:8123/api/websocket"
AUTH_FILE = "/config/.storage/auth"
ENTRIES_FILE = "/config/.storage/core.config_entries"
HOOK_USER_ID = "706f727463756c6c6973686f6f6b7300"  # = prestart.py
DOMAIN = "mcp_server"
COMPANION = "homeassistant"
PREFIX = "portcullis-ai-"
ENTRY_DATA = {"all_llm_apis": False, "llm_hass_api": ["assist"], "require_admin": False}
MOBILE_CLIENTS = frozenset({"https://home-assistant.io/iOS", "https://home-assistant.io/android"})
USER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
SUB_RE = re.compile(r"[0-9a-fA-F-]{1,64}")
ENTRY_ID_RE = re.compile(r"[A-Za-z0-9]{1,64}")
FLOW_ID_RE = re.compile(r"[A-Za-z0-9]{1,64}")
EXTERNAL_RE = re.compile(r"https://[a-z0-9]([a-z0-9.-]{0,252}[a-z0-9])?(:[0-9]{1,5})?")
ACCESS_RE = re.compile(r"[A-Za-z0-9_.-]{20,4096}")
MAX_INPUT = 65536
SETTLE = 20.0
TOKEN_REUSE = 30.0
INITIALIZE = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
               "clientInfo": {"name": "portcullis-hook", "version": "1"}},
}


class Fail(Exception):
    """A failure with a message that holds no secret."""


# ── input ───────────────────────────────────────────────────

def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Fail(f"duplicate key {k!r} in the input")
        d[k] = v
    return d


def _no_constant(name):
    raise Fail(f"{name} is not JSON")


def parse_input(role: str, raw: bytes) -> dict:
    if len(raw) > MAX_INPUT:
        raise Fail("input too large")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError):
        raise Fail("the input is not one JSON object") from None
    if not isinstance(doc, dict):
        raise Fail("the input is not one JSON object")
    action = doc.get("action")
    if role == "on_change":
        if set(doc) != {"action", "enabled", "mode", "companion"} or action != "on_change":
            raise Fail("on_change: expected exactly action, enabled, mode, companion")
        if type(doc["enabled"]) is not bool:
            raise Fail("on_change: enabled must be true or false")
        if doc["mode"] != "read_write":
            raise Fail("on_change: mode must be read_write (app_oauth)")
        if doc["companion"] != COMPANION:
            raise Fail(f"on_change: companion must be {COMPANION}")
    elif action == "revoke":
        if set(doc) != {"action", "user", "sub", "ids"}:
            raise Fail("revoke: expected exactly action, user, sub, ids")
        if not isinstance(doc["user"], str) or not USER_RE.fullmatch(doc["user"]):
            raise Fail("revoke: user is not a username")
        if not isinstance(doc["sub"], str) or not SUB_RE.fullmatch(doc["sub"]):
            raise Fail("revoke: sub is not a Keycloak user id")
        if doc["ids"] != [] or not isinstance(doc["ids"], list):
            raise Fail("revoke: ids must be [] for app_oauth")
    elif action == "revoke_all":
        if set(doc) != {"action", "prefix"} or doc["prefix"] != PREFIX:
            raise Fail(f"revoke_all: expected exactly action and prefix {PREFIX}")
    else:
        raise Fail("revoke: action must be revoke or revoke_all")
    return doc


# ── Home Assistant's storage (read only) ────────────────────

def load_store(path: str, key: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        raise Fail(f"{path} is missing") from None
    except (OSError, ValueError) as e:
        raise Fail(f"{path} is unreadable: {type(e).__name__}") from None
    if not isinstance(doc, dict) or doc.get("key") != key or not isinstance(doc.get("data"), dict):
        raise Fail(f"{path} is not Home Assistant's {key} store")
    return doc["data"]


def auth_store(with_credentials=False):
    data = load_store(AUTH_FILE, "auth")
    users, tokens, creds = data.get("users"), data.get("refresh_tokens"), data.get("credentials")
    for name, v in (("users", users), ("refresh_tokens", tokens), ("credentials", creds)):
        if not isinstance(v, list) or not all(isinstance(x, dict) for x in v):
            raise Fail(f"{AUTH_FILE}: {name} is not a list of objects")
    if with_credentials:
        return users, tokens, creds
    return users, tokens


# ── Home Assistant's API ────────────────────────────────────

class HA:
    def __init__(self, session: aiohttp.ClientSession):
        self.s = session
        self._token = None
        self._at = 0.0
        self.flows = []  # (path prefix, flow_id) still open

    async def token(self) -> str:
        if self._token and time.monotonic() - self._at < TOKEN_REUSE:
            return self._token
        users, tokens = auth_store()
        u = [x for x in users if x.get("id") == HOOK_USER_ID]
        if (len(u) != 1 or u[0].get("system_generated") is not True or u[0].get("is_active") is not True
                or u[0].get("group_ids") != ["system-admin"]):
            raise Fail("the hook admin is missing (prestart.py provisions it at every start: restart the instance)")
        t = [x for x in tokens if x.get("user_id") == HOOK_USER_ID]
        if len(t) != 1 or t[0].get("token_type") != "system" or not isinstance(t[0].get("token"), str):
            raise Fail("the hook admin's token is missing (restart the instance)")
        async with self.s.post(BASE + "/auth/token",
                               data={"grant_type": "refresh_token", "refresh_token": t[0]["token"]}) as r:
            status = r.status
            body = await r.json(content_type=None) if status == 200 else None
        if status != 200 or not isinstance(body, dict):
            raise Fail(f"/auth/token: HTTP {status}")
        at = body.get("access_token")
        if not isinstance(at, str) or not ACCESS_RE.fullmatch(at):
            raise Fail("/auth/token: unexpected answer")
        self._token, self._at = at, time.monotonic()
        return at

    async def rest(self, method: str, path: str, body=None, ok=(200,)):
        headers = {"Authorization": "Bearer " + await self.token()}
        async with self.s.request(method, BASE + path, json=body, headers=headers) as r:
            status, text = r.status, await r.text()
        if status not in ok:
            raise Fail(f"{method} {path.split('?')[0]}: HTTP {status}")
        return status, text

    async def rest_json(self, method: str, path: str, body=None):
        _, text = await self.rest(method, path, body)
        try:
            return json.loads(text)
        except ValueError:
            raise Fail(f"{method} {path.split('?')[0]}: not JSON") from None

    async def mcp_status(self, path: str) -> int:
        headers = {"Authorization": "Bearer " + await self.token(),
                   "Accept": "application/json", "Content-Type": "application/json"}
        async with self.s.post(BASE + path, data=json.dumps(INITIALIZE), headers=headers) as r:
            status, text = r.status, await r.text()
        if status == 200:
            try:
                ok = isinstance(json.loads(text).get("result", {}).get("protocolVersion"), str)
            except (ValueError, AttributeError):
                ok = False
            if not ok:
                raise Fail(f"POST {path}: not an MCP initialize answer")
        return status

    async def close(self):
        for prefix, fid in list(self.flows):
            try:
                await self.rest("DELETE", f"{prefix}/{fid}", ok=(200, 404))
            except Exception:  # best effort: upstream drops abandoned flows too
                pass
        self.flows.clear()


# ── on_change ───────────────────────────────────────────────

async def entries(ha: HA) -> list:
    got = await ha.rest_json("GET", f"/api/config/config_entries/entry?domain={DOMAIN}")
    if not isinstance(got, list) or not all(isinstance(e, dict) and e.get("domain") == DOMAIN
                                            and isinstance(e.get("entry_id"), str)
                                            and ENTRY_ID_RE.fullmatch(e["entry_id"]) for e in got):
        raise Fail("unexpected config entry list")
    return got


async def delete_entry(ha: HA, eid: str):
    await ha.rest("DELETE", f"/api/config/config_entries/entry/{eid}", ok=(200, 404))


def flow_id(r) -> str:
    fid = r.get("flow_id") if isinstance(r, dict) else None
    if not isinstance(fid, str) or not FLOW_ID_RE.fullmatch(fid):
        raise Fail("unexpected flow answer")
    return fid


async def create_entry(ha: HA):
    prefix = "/api/config/config_entries/flow"
    r = await ha.rest_json("POST", prefix, {"handler": DOMAIN})
    fid = flow_id(r)
    ha.flows.append((prefix, fid))
    if r.get("type") == "form":
        r = await ha.rest_json("POST", f"{prefix}/{fid}", {})
    if not isinstance(r, dict) or r.get("type") != "create_entry":
        raise Fail(f"MCP Server config flow: {r.get('type') if isinstance(r, dict) else '?'} "
                   f"{r.get('reason', '') if isinstance(r, dict) else ''}".strip())
    ha.flows.remove((prefix, fid))


async def set_options(ha: HA, eid: str):
    prefix = "/api/config/config_entries/options/flow"
    r = await ha.rest_json("POST", prefix, {"handler": eid})
    fid = flow_id(r)
    ha.flows.append((prefix, fid))
    for _ in range(3):
        if r.get("type") == "create_entry":
            ha.flows.remove((prefix, fid))
            return
        if r.get("type") != "form" or r.get("errors"):
            raise Fail(f"MCP Server options flow: {r.get('type')} {r.get('errors') or ''}".strip())
        fields = r.get("data_schema")
        if not isinstance(fields, list):
            raise Fail("MCP Server options flow: no form fields")
        names = [f.get("name") for f in fields if isinstance(f, dict)]
        unknown = [n for n in names if n not in ENTRY_DATA]
        if unknown or len(names) != len(fields):
            raise Fail(f"MCP Server options flow: unexpected fields {unknown}")
        r = await ha.rest_json("POST", f"{prefix}/{fid}", {n: ENTRY_DATA[n] for n in names})
        if not isinstance(r, dict):
            raise Fail("MCP Server options flow: unexpected answer")
    raise Fail("MCP Server options flow did not finish")


async def wait_entry_data(eid: str):
    deadline = time.monotonic() + SETTLE
    while True:
        data = load_store(ENTRIES_FILE, "core.config_entries")
        es = [e for e in data.get("entries") or [] if isinstance(e, dict) and e.get("domain") == DOMAIN]
        if (len(es) == 1 and es[0].get("entry_id") == eid and isinstance(es[0].get("data"), dict)
                and all(es[0]["data"].get(k) == v for k, v in ENTRY_DATA.items())):
            return
        if time.monotonic() > deadline:
            raise Fail("the MCP Server entry's stored options don't match (require_admin off, Assist only)")
        await asyncio.sleep(0.5)


async def wait_no_entry():
    deadline = time.monotonic() + SETTLE
    while True:
        data = load_store(ENTRIES_FILE, "core.config_entries")
        if not any(isinstance(e, dict) and e.get("domain") == DOMAIN for e in data.get("entries") or []):
            return
        if time.monotonic() > deadline:
            raise Fail("an MCP Server entry is still stored")
        await asyncio.sleep(0.5)


async def on_change(ha: HA, enabled: bool):
    env = os.environ.get("HA_AI_ENABLED", "")
    if env not in ("true", "false"):
        raise Fail("HA_AI_ENABLED must be true or false")
    if enabled and env != "true":
        raise Fail("AI support is on but this container started with it off: restart the instance")
    es = await entries(ha)
    if enabled:
        if not (len(es) == 1 and es[0].get("state") == "loaded" and es[0].get("disabled_by") is None):
            for e in es:
                await delete_entry(ha, e["entry_id"])
            await create_entry(ha)
            es = await entries(ha)
        if len(es) != 1:
            raise Fail(f"{len(es)} MCP Server entries after setup")
        eid = es[0]["entry_id"]
        await set_options(ha, eid)
        await wait_entry_data(eid)
        es = await entries(ha)
        if len(es) != 1 or es[0].get("entry_id") != eid or es[0].get("state") != "loaded":
            raise Fail("the MCP Server entry is not loaded")
        status = await ha.mcp_status("/api/mcp")
        if status != 200:
            raise Fail(f"POST /api/mcp: HTTP {status}")
        return
    for e in es:
        await delete_entry(ha, e["entry_id"])
    if await entries(ha):
        raise Fail("an MCP Server entry is still configured")
    await wait_no_entry()
    for path in ("/api/mcp", "/api/mcp/assist"):
        status = await ha.mcp_status(path)
        if status != 404:
            raise Fail(f"POST {path} still answers (HTTP {status}): Home Assistant serves it until it "
                       "restarts; restart the instance")


# ── revoke ──────────────────────────────────────────────

def person_of(sub: str):
    """The id of the user holding the auth_oidc credential of sub; None =
    no account. Anything ambiguous fails."""
    users, _, creds = auth_store(with_credentials=True)
    oidc = [c for c in creds if c.get("auth_provider_type") == "auth_oidc"]
    if any(not isinstance(c.get("data"), dict) or not isinstance(c["data"].get("sub"), str) or not c["data"]["sub"]
           for c in oidc):
        # A credential we can't read could be the person's: never guess.
        raise Fail("an auth_oidc credential has no sub: refusing to guess")
    found = [c for c in oidc if c["data"]["sub"] == sub]
    if not found:
        return None
    uids = {c.get("user_id") for c in found}
    if len(found) != 1 or len(uids) != 1:
        raise Fail(f"{len(found)} auth_oidc credentials carry this sub: refusing to guess")
    uid = found[0].get("user_id")
    us = [u for u in users if u.get("id") == uid]
    if len(us) != 1 or us[0].get("system_generated") is not False:
        raise Fail("the credential of this sub belongs to no ordinary user")
    return uid


async def revoke_tokens(ha: HA, pick, what: str):
    """Revokes every stored refresh token pick(token, system_users) selects
    and reads the store back until none is left (at most 5 rounds)."""
    for _ in range(5):
        users, tokens = auth_store()
        system = {u.get("id") for u in users if u.get("system_generated") is not False}
        targets = [t for t in tokens if pick(t, system)]
        if not targets:
            return
        for t in targets:
            if not isinstance(t.get("token"), str) or not t["token"]:
                raise Fail("a stored refresh token has no value")
            async with ha.s.post(BASE + "/auth/revoke", data={"token": t["token"]}) as r:
                if r.status != 200:
                    raise Fail(f"/auth/revoke: HTTP {r.status}")
        ids = {t.get("id") for t in targets}
        deadline = time.monotonic() + SETTLE
        while True:
            _, tokens = auth_store()
            if not any(t.get("id") in ids for t in tokens):
                break
            if time.monotonic() > deadline:
                raise Fail(f"revoked refresh tokens of {what} are still stored")
            await asyncio.sleep(0.5)
    raise Fail(f"refresh tokens of {what} keep appearing; gave up after 5 rounds")


async def revoke(ha: HA, user: str, sub: str):
    uid = person_of(sub)
    if uid is None:
        return  # no Home Assistant account: nothing to revoke
    await revoke_tokens(ha, lambda t, system: t.get("user_id") == uid, user)


async def revoke_all(ha: HA):
    ext = os.environ.get("HA_EXTERNAL_URL", "")
    if not EXTERNAL_RE.fullmatch(ext):
        raise Fail("HA_EXTERNAL_URL is not an https origin")
    own = MOBILE_CLIENTS | {ext + "/"}
    await revoke_tokens(ha, lambda t, system: t.get("user_id") not in system
                        and t.get("token_type") == "normal" and t.get("client_id") not in own,
                        "MCP clients")


# ── main ────────────────────────────────────────────────────

async def run(role: str, doc: dict):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
        ha = HA(s)
        try:
            if role == "on_change":
                await on_change(ha, doc["enabled"])
            elif doc["action"] == "revoke":
                await revoke(ha, doc["user"], doc["sub"])
            else:
                await revoke_all(ha)
        finally:
            await ha.close()


def main(argv) -> int:
    if len(argv) != 2 or argv[1] not in ("on_change", "revoke"):
        print("usage: mcp-hook.py on_change|revoke < input.json", file=sys.stderr)
        return 1
    try:
        doc = parse_input(argv[1], sys.stdin.buffer.read(MAX_INPUT + 1))
    except Fail as e:
        print(f"mcp-hook: {e}", file=sys.stderr)
        return 1
    loop = asyncio.new_event_loop()
    task = loop.create_task(run(argv[1], doc))
    signalled = []

    def stop(sig):
        signalled.append(sig)
        task.cancel()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        loop.add_signal_handler(sig, stop, sig)
    try:
        loop.run_until_complete(task)
        return 0
    except asyncio.CancelledError:
        print("mcp-hook: ended by a signal", file=sys.stderr)
        return 143 if signalled else 1
    except Fail as e:
        print(f"mcp-hook: {str(e)[:500]}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - every other failure fails the hook
        print(f"mcp-hook: {type(e).__name__}: {str(e)[:300]}", file=sys.stderr)
        return 1
    finally:
        loop.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
