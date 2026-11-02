#!/usr/bin/env python3
"""Home Assistant healthcheck (Portcullis): healthy (= routed by Traefik)
only while OpenID Connect is the only sign-in and onboarding is closed.

- GET /auth/providers lists exactly the auth_oidc provider (no local
  username/password provider, no trusted networks);
- GET /api/onboarding reports no open step (the view only exists while
  onboarding is unfinished).
"""

import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8123"


def get(path: str):
    try:
        with urllib.request.urlopen(BASE + path, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def main() -> int:
    code, body = get("/auth/providers")
    if code != 200:
        print(f"/auth/providers: HTTP {code}")
        return 1
    doc = json.loads(body)
    providers = doc.get("providers", []) if isinstance(doc, dict) else doc
    types = [p.get("type") for p in providers]
    if types != ["auth_oidc"]:
        print(f"auth providers {types!r} != ['auth_oidc']")
        return 1
    code, body = get("/api/onboarding")
    if code == 200:
        try:
            steps = json.loads(body)
        except ValueError:
            steps = None
        if not isinstance(steps, list) or any(not s.get("done") for s in steps):
            print(f"onboarding open: {body[:200]!r}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
