#!/usr/bin/env python3
"""A Firefox, as far as the tests need one: PyFxA against firefox-sync-fxa.

tests/apps/firefox-sync-fxa.sh runs it in the template's pinned
syncstorage-rs image (which ships PyFxA, requests and hawkauthlib) the way a
Firefox on the internet reaches the instance: through Traefik and fxa-gate
at the public hosts (a container on portcullis-proxy, where CI's public-DNS
stand-in resolves them to Traefik), trusting Portcullis's CA bundle
(REQUESTS_CA_BUNDLE):

  signup <email>            create the account, verify it with the code the
                            mail catcher got (FXA_MAIL_DIR)
  sync <email>              sign in, OAuth token with the Sync scope, the
                            tokenserver, then a BSO PUT / GET round trip
  foreign-token <email>     tokens the tokenserver must refuse: a JWT of
                            another accounts server, and one of ours without
                            the Sync scope
  session <email>           sign in (the code the catcher got when asked)
                            and keep the session as signup does
  session-status <email>    the session token signup / session saved (FXA_STATE_DIR)
                            asks /session/status: its HTTP status (200, or
                            401 once the account is disabled)
  access-token <email>      sign in and get an OAuth access token with the
                            Sync scope, as Firefox holds one; kept 0600 in
                            FXA_STATE_DIR, never printed
  access-verify <email>     the saved access token to the accounts server's
                            /v1/verify (what the tokenserver asks): its HTTP
                            status (200 while valid, 4xx once revoked)

The password comes from FXA_PASSWORD only, never argv. With FXA_STATE_DIR
set, signup keeps the new session (uid and session token) in a 0600 file
there, for session-status. No token, key or password is ever printed: each command prints one JSON object of results
(statuses, uids, URLs) and exits 0 when everything it did succeeded, 1 when
the server refused, 2 on a usage or setup error.

Base URLs (environment; the test sets the public ones):
  FXA_AUTH_URL    the accounts API              (https://<API host>; default http://fxa-auth:9000)
  FXA_TOKEN_URL   the tokenserver's origin      (https://<Sync host>)
  FXA_NODE_URL    the node the tokenserver must hand out (https://<Sync host>)
  FXA_SYNC_URL    where storage is reached; empty (the test) = the
                  api_endpoint as is, else the api_endpoint's origin
                  FXA_NODE_URL replaced by it
  REQUESTS_CA_BUNDLE  the CA bundle every request trusts (Portcullis's)
"""

import base64
import email
import email.policy
import hashlib
import json
import os
import sys
import time
import urllib.parse

import hawkauthlib
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fxa.core import Client, Session
from fxa.errors import ClientError, ServerError
from fxa.oauth import Client as OAuthClient

FIREFOX_DESKTOP = "5882386c6d801776"
SYNC_SCOPE = "https://identity.mozilla.com/apps/oldsync"
PROFILE_SCOPE = "profile"
TIMEOUT = 30


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        raise SystemExit(usage(f"{name} is not set"))
    return value


def usage(msg):
    print(json.dumps({"error": msg}))
    return 2


def out(result, ok):
    print(json.dumps(result, sort_keys=True))
    return 0 if ok else 1


def password():
    pw = os.environ.get("FXA_PASSWORD", "")
    if len(pw) < 8:
        raise SystemExit(usage("FXA_PASSWORD is missing or shorter than 8 characters"))
    return pw


def auth_client():
    return Client(env("FXA_AUTH_URL", "http://fxa-auth:9000"))


# ── Mail (the catcher's /tmp/mail/<n>.eml: an envelope block, a blank line,
# then the message) ──

def mail_files():
    d = env("FXA_MAIL_DIR", "/mail")
    try:
        return {os.path.join(d, f) for f in os.listdir(d) if f.endswith(".eml")}
    except FileNotFoundError:
        return set()


def wait_for_code(address, seen, headers, timeout=90):
    """The first header of `headers` in a new message to `address`."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for path in sorted(mail_files() - seen):
            with open(path, encoding="latin-1") as f:
                raw = f.read()
            envelope, _, message = raw.partition("\n\n")
            rcpt = next((ln for ln in envelope.splitlines() if ln.startswith("RCPT ")), "")
            if address.lower() not in rcpt.lower():
                continue
            msg = email.message_from_string(message.replace("\r\n", "\n"), policy=email.policy.compat32)
            for h in headers:
                if msg.get(h):
                    return h, msg.get(h).strip()
        time.sleep(2)
    return None, None


def verify(session, address, seen):
    """Verify the account / session with the code mailed to `address`."""
    header, code = wait_for_code(address, seen, (
        "X-Verify-Code", "X-Signin-Verify-Code", "X-Verify-Short-Code", "X-Signin-Verify-Short-Code"))
    if code is None:
        return "no code mailed"
    if header in ("X-Verify-Code", "X-Signin-Verify-Code"):
        session.client.verify_email_code(session.uid, code)
    else:
        session.apiclient.post("/session/verify_code", {"code": code}, auth=session._auth)
    session.verified = True
    return None


# ── Commands ──

def cmd_signup(address):
    pw = password()
    seen = mail_files()
    try:
        session = auth_client().create_account(address, pw)
    except (ClientError, ServerError) as e:
        return out({"step": "create", "http": getattr(e, "code", None), "errno": getattr(e, "errno", None)}, False)
    err = verify(session, address, seen)
    if err:
        return out({"step": "verify", "uid": session.uid, "error": err}, False)
    status = session.get_email_status()
    ok = bool(status.get("verified"))
    if ok and os.environ.get("FXA_STATE_DIR"):
        save_session(address, session)
    return out({"step": "done", "uid": session.uid, "verified": ok}, ok)


def session_file(address):
    name = hashlib.sha256(address.lower().encode()).hexdigest()[:32]
    return os.path.join(env("FXA_STATE_DIR"), f"session-{name}.json")


def save_session(address, session):
    path = session_file(address)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"uid": session.uid, "token": session.token}, f)


def cmd_session(address):
    session = login(address)
    save_session(address, session)
    return out({"uid": session.uid, "saved": True}, True)


def cmd_session_status(address):
    try:
        with open(session_file(address)) as f:
            saved = json.load(f)
    except (OSError, ValueError):
        return out({"error": "no saved session (signup with FXA_STATE_DIR first)"}, False)
    session = Session(auth_client(), address, b"", saved["uid"], saved["token"])
    try:
        session.apiclient.get("/session/status", auth=session._auth)
    except ClientError as e:
        return out({"uid": saved["uid"], "http": getattr(e, "code", None), "errno": getattr(e, "errno", None)}, False)
    return out({"uid": saved["uid"], "http": 200}, True)


def access_file(address):
    name = hashlib.sha256(address.lower().encode()).hexdigest()[:32]
    return os.path.join(env("FXA_STATE_DIR"), f"access-{name}.json")


def cmd_access_token(address):
    session = login(address)
    token = oauth_token(session, SYNC_SCOPE)
    fd = os.open(access_file(address), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"uid": session.uid, "token": token}, f)
    return out({"uid": session.uid, "saved": True}, True)


def cmd_access_verify(address):
    try:
        with open(access_file(address)) as f:
            saved = json.load(f)
    except (OSError, ValueError):
        return out({"error": "no saved access token (access-token first)"}, False)
    url = env("FXA_AUTH_URL", "http://fxa-auth:9000").rstrip("/") + "/v1/verify"
    resp = requests.post(url, json={"token": saved["token"]}, timeout=TIMEOUT)
    try:
        body = resp.json()
    except ValueError:
        body = {}
    result = {"uid": saved["uid"], "http": resp.status_code, "errno": body.get("errno")}
    if resp.status_code == 200:
        result["user_matches"] = body.get("user") == saved["uid"]
        scope = body.get("scope") or []
        result["scope_sync"] = SYNC_SCOPE in (scope.split() if isinstance(scope, str) else scope)
    return out(result, resp.status_code == 200)


def login(address):
    seen = mail_files()
    session = auth_client().login(address, password())
    if not session.verified:
        err = verify(session, address, seen)
        if err:
            raise SystemExit(out({"step": "login", "uid": session.uid, "error": err}, False))
    return session


def oauth_token(session, scope):
    base = env("FXA_AUTH_URL", "http://fxa-auth:9000").rstrip("/") + "/v1"
    return OAuthClient(FIREFOX_DESKTOP, None, server_url=base).authorize_token(session, scope)


def key_id(uid):
    # X-KeyID = <keys_changed_at>-<base64url(client state)>. The tokenserver
    # can't check it against the account's keys; a stable value per account
    # keeps repeated runs on one tokenserver row.
    state = hashlib.sha256(uid.encode()).digest()[:16]
    return "1-" + base64.urlsafe_b64encode(state).decode().rstrip("=")


def tokenserver(bearer, uid):
    url = env("FXA_TOKEN_URL", "http://firefox-sync-fxa-internal:8000").rstrip("/") + "/1.0/sync/1.5"
    return requests.get(url, timeout=TIMEOUT,
                        headers={"Authorization": f"Bearer {bearer}", "X-KeyID": key_id(uid)})


def storage_url(api_endpoint):
    node = env("FXA_NODE_URL").rstrip("/")
    if not api_endpoint.startswith(node + "/1.5/"):
        return None
    sync = os.environ.get("FXA_SYNC_URL", "").rstrip("/")
    return (sync + api_endpoint[len(node):]) if sync else api_endpoint


def hawk(method, url, token, body=None):
    req = requests.Request(method, url, data=body,
                           headers={"Content-Type": "application/json"} if body is not None else {}).prepare()
    hawkauthlib.sign_request(req, token["id"], token["key"])
    s = requests.Session()
    # Session.send skips the environment (REQUESTS_CA_BUNDLE): merge it.
    return s.send(req, timeout=TIMEOUT, **s.merge_environment_settings(req.url, {}, None, None, None))


def cmd_sync(address):
    session = login(address)
    result = {"uid": session.uid}
    resp = tokenserver(oauth_token(session, SYNC_SCOPE), session.uid)
    result["token_http"] = resp.status_code
    if resp.status_code != 200:
        result["token_error"] = resp.text[:300]
        return out(result, False)
    token = resp.json()
    result["api_endpoint"] = token.get("api_endpoint")
    result["duration"] = token.get("duration")
    base = storage_url(token.get("api_endpoint") or "")
    if base is None:
        result["error"] = "api_endpoint is not on FXA_NODE_URL"
        return out(result, False)
    bso = f"{base}/storage/bookmarks/portcullis-test"
    payload = base64.b64encode(os.urandom(24)).decode()
    put = hawk("PUT", bso, token, json.dumps({"id": "portcullis-test", "payload": payload}))
    result["put_http"] = put.status_code
    got = hawk("GET", bso, token)
    result["get_http"] = got.status_code
    try:
        result["round_trip"] = got.status_code == 200 and got.json().get("payload") == payload
    except ValueError:
        result["round_trip"] = False
    unsigned = requests.get(bso, timeout=TIMEOUT)
    result["unsigned_get_http"] = unsigned.status_code
    ok = put.status_code == 200 and result["round_trip"] and unsigned.status_code == 401
    return out(result, ok)


def foreign_jwt():
    """An access token as another accounts server (Mozilla's) issues them:
    an RS256 JWT with the Sync scope for a random uid, signed by a key this
    instance has never seen."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    now = int(time.time())
    claims = {"iss": "https://accounts.firefox.com", "sub": os.urandom(16).hex(), "aud": FIREFOX_DESKTOP,
              "client_id": FIREFOX_DESKTOP, "scope": SYNC_SCOPE, "iat": now, "exp": now + 3600,
              "jti": os.urandom(16).hex(), "fxa-generation": now * 1000}
    return jwt.encode(claims, pem, algorithm="RS256", headers={"typ": "at+JWT", "kid": "20190730-15e473fd"}), claims["sub"]


def cmd_foreign_token(address):
    session = login(address)
    bearer, sub = foreign_jwt()
    foreign = tokenserver(bearer, sub)
    wrong_scope = tokenserver(oauth_token(session, PROFILE_SCOPE), session.uid)
    result = {"uid": session.uid, "foreign_sub": sub, "foreign_http": foreign.status_code,
              "foreign_status": (foreign.json() if foreign.headers.get("content-type", "").startswith("application/json") else {}).get("status"),
              "wrong_scope_http": wrong_scope.status_code}
    return out(result, foreign.status_code == 401 and wrong_scope.status_code == 401)


COMMANDS = {"signup": cmd_signup, "sync": cmd_sync, "foreign-token": cmd_foreign_token,
            "session": cmd_session, "session-status": cmd_session_status,
            "access-token": cmd_access_token, "access-verify": cmd_access_verify}


def main(argv):
    if len(argv) != 2 or argv[0] not in COMMANDS or "@" not in argv[1]:
        return usage("usage: fxa_client.py signup|sync|foreign-token|session|session-status|access-token|access-verify <email> (password in FXA_PASSWORD)")
    try:
        return COMMANDS[argv[0]](argv[1])
    except (ClientError, ServerError) as e:
        return out({"error": "accounts server refused", "http": getattr(e, "code", None),
                    "errno": getattr(e, "errno", None)}, False)
    except requests.RequestException as e:
        return out({"error": f"request failed: {type(e).__name__}",
                    "url": urllib.parse.urlsplit(getattr(e.request, "url", "") or "")._replace(query="").geturl()}, False)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
