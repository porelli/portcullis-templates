#!/usr/bin/env python3
"""prestart.py (Portcullis): the homeassistant service's entrypoint. It runs
in the Home Assistant container itself, right before Home Assistant starts
(so never next to a running Home Assistant on the same /config: compose
stops the old container before it starts a new one), then execs the
image's own /init (s6-overlay, PID 1).

1. The AI hooks' admin (homeassistant/portcullis/mcp-hook.py) is
   provisioned in Home Assistant's auth storage (/config/.storage/auth):
   the system-generated user "Portcullis hooks" (id HOOK_USER_ID, group
   system-admin, local_only, no credentials, so no sign-in of any kind;
   system users are hidden from Settings > People and config/auth/update
   and config/auth/delete refuse them) with exactly one system refresh
   token whose access tokens live 60 s. Token and signing key are new at
   every start (an earlier one is removed with its user). Home Assistant
   has no CLI or API that mints an admin token while it runs, and its own
   http component creates its "Home Assistant Content" system user the
   same way. The token never leaves this file (0600, Home Assistant's
   own); the hooks exchange it at /auth/token per run.
2. With AI support off (HA_AI_ENABLED=false, from PORTCULLIS_AI_ENABLED),
   every config entry of the built-in MCP Server integration (mcp_server)
   is removed from /config/.storage/core.config_entries, so Home Assistant
   starts without it and serves no /api/mcp route at all (removing the
   entry at runtime leaves /api/mcp/<api id> served until the next start).
   An entry an administrator added by hand while AI support is off is
   removed too.

Any failure exits non-zero before /init runs: Home Assistant doesn't start
(fail closed). No secret is printed.
"""

import datetime
import json
import os
import secrets
import sys
import tempfile
import uuid

STORAGE = "/config/.storage"
AUTH = os.path.join(STORAGE, "auth")
ENTRIES = os.path.join(STORAGE, "core.config_entries")
# Fixed id ("portcullishooks" in hex): mcp-hook.py looks the user up by it.
HOOK_USER_ID = "706f727463756c6c6973686f6f6b7300"
HOOK_USER_NAME = "Portcullis hooks"
ACCESS_TOKEN_SECONDS = 60.0
SYSTEM_GROUPS = [
    {"id": "system-admin", "name": "Administrators"},
    {"id": "system-users", "name": "Users"},
    {"id": "system-read-only", "name": "Read Only"},
]


def log(msg: str) -> None:
    print(f"portcullis-prestart: {msg}", flush=True)


def die(msg: str) -> None:
    print(f"portcullis-prestart: ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def atomic_write(path: str, doc: dict, mode: int) -> None:
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".portcullis-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load(path: str, key: str):
    """The storage document at path (None if absent); refuses anything else."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        die(f"{path} is unreadable: {type(e).__name__}")
    if not isinstance(doc, dict) or doc.get("key") != key or not isinstance(doc.get("data"), dict):
        die(f"{path} is not Home Assistant's {key} store")
    return doc


def hook_admin() -> None:
    doc = load(AUTH, "auth")
    if doc is None:
        doc = {"version": 1, "minor_version": 1, "key": "auth",
               "data": {"users": [], "groups": SYSTEM_GROUPS, "credentials": [], "refresh_tokens": []}}
    data = doc["data"]
    for k in ("users", "groups", "credentials", "refresh_tokens"):
        if not isinstance(data.get(k), list) or not all(isinstance(x, dict) for x in data[k]):
            die(f"{AUTH}: data.{k} is not a list of objects")
    if not data["groups"]:
        # Home Assistant would make every non-system user an administrator
        # when it loads a store without groups (its pre-0.90 migration).
        die(f"{AUTH} has no groups")
    old = {u.get("id") for u in data["users"]
           if u.get("id") == HOOK_USER_ID or (u.get("system_generated") is True and u.get("name") == HOOK_USER_NAME)}
    data["users"] = [u for u in data["users"] if u.get("id") not in old]
    data["credentials"] = [c for c in data["credentials"] if c.get("user_id") not in old]
    data["refresh_tokens"] = [t for t in data["refresh_tokens"] if t.get("user_id") not in old]
    data["users"].append({
        "id": HOOK_USER_ID,
        "group_ids": ["system-admin"],
        "is_owner": False,
        "is_active": True,
        "name": HOOK_USER_NAME,
        "system_generated": True,
        "local_only": True,
    })
    data["refresh_tokens"].append({
        "id": uuid.uuid4().hex,
        "user_id": HOOK_USER_ID,
        "client_id": None,
        "client_name": None,
        "client_icon": None,
        "token_type": "system",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "access_token_expiration": ACCESS_TOKEN_SECONDS,
        "token": secrets.token_hex(64),
        "jwt_key": secrets.token_hex(64),
        "last_used_at": None,
        "last_used_ip": None,
        "expire_at": None,
        "credential_id": None,
        "version": None,
    })
    atomic_write(AUTH, doc, 0o600)
    log("AI hook admin provisioned (system user, new token)")


def mcp_entries_off() -> None:
    doc = load(ENTRIES, "core.config_entries")
    if doc is None:
        return
    entries = doc["data"].get("entries")
    if not isinstance(entries, list):
        die(f"{ENTRIES}: data.entries is not a list")
    keep = [e for e in entries if not (isinstance(e, dict) and e.get("domain") == "mcp_server")]
    if len(keep) == len(entries):
        log("AI support off: no MCP Server config entry")
        return
    doc["data"]["entries"] = keep
    atomic_write(ENTRIES, doc, os.stat(ENTRIES).st_mode & 0o777)
    log(f"AI support off: {len(entries) - len(keep)} MCP Server config entry removed")


def main() -> None:
    enabled = os.environ.get("HA_AI_ENABLED", "")
    if enabled not in ("true", "false"):
        die(f"HA_AI_ENABLED must be true or false, not {enabled!r}")
    if not os.path.isdir("/config"):
        die("/config is missing")
    hook_admin()
    if enabled == "false":
        mcp_entries_off()
    sys.stdout.flush()
    os.execv("/init", ["/init"])


if __name__ == "__main__":
    main()
