#!/usr/bin/env python3
"""mattermost-init (Portcullis): bootstrap system admin over local mode.

Mattermost's self sign-up is off (MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL
false), so nobody can create the first account, which Mattermost would make
a system admin. This one-shot waits for the local-mode socket, then creates
MATTERMOST_ADMIN_USER with MATTERMOST_ADMIN_PASSWORD if that account doesn't
exist yet, and makes sure it has the system_admin role. The password comes
from the environment and goes only into the request body (never argv, never
printed). Fails closed (non-zero) if Mattermost doesn't come up.
"""

import http.client
import json
import os
import socket
import sys
import time

SOCK = os.environ["MATTERMOST_SOCKET"]
USER = os.environ["MATTERMOST_ADMIN_USER"]
PASSWORD = os.environ["MATTERMOST_ADMIN_PASSWORD"]


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


def main() -> None:
    if len(PASSWORD) < 16:
        die("MATTERMOST_ADMIN_PASSWORD is too short")
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

    status, doc = call("GET", f"/api/v4/users/username/{USER}")
    if status == 200:
        uid = doc["id"]
        log(f"{USER} exists")
    elif status == 404:
        status, doc = call("POST", "/api/v4/users", {
            "username": USER,
            "email": f"{USER}@mattermost.invalid",
            "password": PASSWORD,
        })
        if status != 201 or not doc or "id" not in doc:
            die(f"creating {USER} failed: HTTP {status} {(doc or {}).get('id', '')}")
        uid = doc["id"]
        log(f"{USER} created")
    else:
        die(f"looking up {USER} failed: HTTP {status}")

    roles = (doc or {}).get("roles", "")
    if "system_admin" not in roles.split():
        status, _ = call("PUT", f"/api/v4/users/{uid}/roles", {"roles": "system_user system_admin"})
        if status != 200:
            die(f"granting system_admin to {USER} failed: HTTP {status}")
        log(f"{USER} is system admin")
    log("done")


if __name__ == "__main__":
    main()
