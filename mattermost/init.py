#!/usr/bin/env python3
"""mattermost-init (Portcullis): bootstrap system admin over local mode.

Mattermost's self sign-up is off (MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL
false), so nobody can create the first account, which Mattermost would make
a system admin. This one-shot waits for the local-mode socket and creates
one bootstrap system admin, mmadmin-<MATTERMOST_ADMIN_SUFFIX[:12]>, with
MATTERMOST_ADMIN_PASSWORD (both generated per instance).

The account is pinned by its user ID, never trusted by name:
- first run (no state file): the name must not exist yet; the account is
  created, its ID is written to the state file in the data volume, then (and
  only then) it gets system_admin. An existing account with that name and no
  state file is refused (fail closed): system_admin is never granted to an
  account found by name.
- later runs: the state file names the ID. Nothing is granted again. If the
  name now belongs to a different ID (the bootstrap admin was renamed and
  someone took the name), the run fails closed.

The password comes from the environment and goes only into the request body
(never argv, never printed).
"""

import http.client
import json
import os
import re
import socket
import sys
import tempfile
import time

SOCK = os.environ["MATTERMOST_SOCKET"]
SUFFIX = os.environ["MATTERMOST_ADMIN_SUFFIX"]
PASSWORD = os.environ["MATTERMOST_ADMIN_PASSWORD"]
STATE = os.environ.get("MATTERMOST_ADMIN_STATE", "/mattermost/data/.portcullis-bootstrap-admin.json")


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=30)
        self.path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(30)
        s.connect(self.path)
        self.sock = s


def call(method: str, path: str, body=None):
    conn = UnixConnection(SOCK)
    try:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            doc = json.loads(raw) if raw else None
        except ValueError:
            doc = None
        return resp.status, doc
    finally:
        conn.close()


def log(msg: str) -> None:
    print(f"portcullis-init: {msg}", flush=True)


def die(msg: str) -> None:
    print(f"portcullis-init: ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def write_state(uid: str, username: str) -> None:
    d = os.path.dirname(STATE)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".portcullis-")
    with os.fdopen(fd, "w") as f:
        json.dump({"id": uid, "username": username}, f)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE)


def main() -> None:
    if not re.fullmatch(r"[0-9a-f]{12,}", SUFFIX):
        die("MATTERMOST_ADMIN_SUFFIX must be at least 12 lowercase hex characters")
    if len(PASSWORD) < 16:
        die("MATTERMOST_ADMIN_PASSWORD is too short")
    username = f"mmadmin-{SUFFIX[:12]}"

    deadline = time.time() + 600
    while True:
        try:
            status, _ = call("GET", "/api/v4/system/ping")
            if status == 200:
                break
        except OSError:
            pass
        if time.time() > deadline:
            die("Mattermost local mode did not answer within 600 s")
        time.sleep(3)

    status, by_name = call("GET", f"/api/v4/users/username/{username}")
    if status not in (200, 404):
        die(f"looking up {username} failed: HTTP {status}")

    if os.path.exists(STATE):
        with open(STATE, encoding="utf-8") as f:
            pinned = json.load(f)
        pid = pinned.get("id")
        if not isinstance(pid, str) or not re.fullmatch(r"[a-z0-9]{26}", pid):
            die(f"state file {STATE} has no valid user id")
        if status == 200 and by_name.get("id") != pid:
            die(f"{username} now belongs to user {by_name.get('id')}, not the pinned bootstrap admin {pid}: "
                "refusing (rename or remove that account)")
        log(f"bootstrap admin pinned to user {pid}; nothing to do")
        return

    if status == 200:
        die(f"{username} exists but was not created by this job (no {STATE}): "
            "refusing to treat it as the bootstrap admin")

    status, doc = call("POST", "/api/v4/users", {
        "username": username,
        "email": f"{username}@mattermost.invalid",
        "password": PASSWORD,
    })
    if status != 201 or not doc or not isinstance(doc.get("id"), str):
        die(f"creating {username} failed: HTTP {status} {(doc or {}).get('id', '')}")
    uid = doc["id"]
    write_state(uid, username)
    log(f"{username} created and pinned (user {uid})")
    status, _ = call("PUT", f"/api/v4/users/{uid}/roles", {"roles": "system_user system_admin"})
    if status != 200:
        die(f"granting system_admin to {uid} failed: HTTP {status}")
    log(f"{username} is system admin")


if __name__ == "__main__":
    main()
