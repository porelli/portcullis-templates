#!/usr/bin/env python3
"""Portcullis VPN glue for Headscale (integration contracts §3.3, §13.8).

Runs in the template's vpn-glue service (the official Python image, stdlib
only: the Headscale image is distroless, with no shell to run its CLI and
jq in) and talks to Headscale's REST API with the "Headscale API key"
setting. It never prints the key, a pre-auth key or a response body.

    glue.py               a vpn hook: the Hub's stdin selects the op
                          {"version":1,"trigger":"vpn","instance":"<id>","op":"devices","ranges":[...]}
                          {"version":1,"trigger":"vpn","instance":"<id>","op":"dns","records":[...]}
    glue.py gateway-key   a start hook: a pre-auth key for the gateway node

devices: prints the device document (version 1) on stdout. A node is a
person's device only when its Headscale user signed in through Portcullis
(the user's provider id is "<OIDC_ISSUER>/<sub>": Headscale 0.29
hscontrol/types/users.go OIDCClaims.Identifier = the issuer without a
trailing "/", "/", the sub, through CleanIdentifier); every other node
(local users, other issuers, tagged nodes) is left out. The node tagged
tag:portcullis-gateway is the gateway, never a device; more than one
online gateway node is refused (which address would the DNS records
name?). A node whose expiry or last-seen time can't be read is left out.

dns: writes the records to /dns/extra-records.json (Headscale's
dns.extra_records_path, read-only in the headscale service), atomically.

gateway-key: when no gateway node is online, a single-use pre-auth key
(one hour, tagged tag:portcullis-gateway, no user) is written to
/run/gateway/authkey (0600), where the gateway's entrypoint waits for it;
while one is online, a leftover key file is removed.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any, Dict, List, NoReturn, Optional

GATEWAY_TAG = "tag:portcullis-gateway"
AUTHKEY_PATH = "/run/gateway/authkey"
RECORDS_PATH = "/dns/extra-records.json"
MAX_STDIN = 1 << 20
MAX_RESPONSE = 64 << 20
MAX_DEVICES = 10_000
MAX_RECORDS = 10_000
HOSTNAME_RE = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def die(msg: str) -> NoReturn:
    print(f"headscale vpn glue: {msg}", file=sys.stderr)
    sys.exit(1)


def api(method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    key = os.environ.get("HEADSCALE_API_KEY", "").strip()
    if not key:
        die("set the Headscale API key setting (headscale apikeys create inside the headscale container), then restart the app")
    base = os.environ.get("HEADSCALE_URL", "http://headscale-internal:8080").rstrip("/")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Accept": "application/json",
                                          "Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=20) as r:
            raw = r.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            die(f"{method} {path}: HTTP {e.code}: the Headscale API key setting is invalid or expired "
                "(keys expire, 365 days by default): create a new one and restart the app")
        die(f"{method} {path}: HTTP {e.code}")
    except (urllib.error.URLError, OSError) as e:
        die(f"{method} {path}: {type(e).__name__}: {getattr(e, 'reason', e)}")
    if len(raw) > MAX_RESPONSE:
        die(f"{method} {path}: response too large")
    try:
        doc = json.loads(raw)
    except ValueError:
        die(f"{method} {path}: not JSON")
    if not isinstance(doc, dict):
        die(f"{method} {path}: not a JSON object")
    return doc


class BadTime(ValueError):
    pass


def timestamp(v: Any) -> Optional[str]:
    """An RFC 3339 UTC time (seconds), or None for no time / Go's zero time;
    BadTime for anything else (fail closed: never read as "no expiry")."""
    if v is None or v == "":
        return None
    if not isinstance(v, str):
        raise BadTime(repr(type(v)))
    try:
        t = datetime.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise BadTime("unparsable") from None
    if t.tzinfo is None:
        raise BadTime("no time zone")
    if t.year <= 1:
        return None
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sort_time(v: Any) -> str:
    try:
        return timestamp(v) or ""
    except BadTime:
        return ""


def first_ipv4(n: Dict[str, Any]) -> Optional[str]:
    for a in n.get("ipAddresses") or []:
        try:
            if isinstance(a, str) and ipaddress.ip_address(a).version == 4:
                return a
        except ValueError:
            continue
    return None


def nodes() -> List[Dict[str, Any]]:
    ns = api("GET", "/api/v1/node").get("nodes") or []
    return [n for n in ns if isinstance(n, dict)] if isinstance(ns, list) else []


def gateway_nodes(ns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Gateway nodes with an IPv4, online first, then the latest seen."""
    gws = [n for n in ns if GATEWAY_TAG in (n.get("tags") or []) and first_ipv4(n)]
    return sorted(gws, key=lambda n: (n.get("online") is True, sort_time(n.get("lastSeen"))), reverse=True)


def devices() -> None:
    issuer = os.environ.get("OIDC_ISSUER", "").strip().rstrip("/")
    if not issuer:
        die("OIDC_ISSUER is not set")
    prefix = issuer + "/"
    ns = nodes()
    gws = gateway_nodes(ns)
    if not gws:
        die(f"no gateway node ({GATEWAY_TAG}) is registered yet: the gateway-key start hook registers it")
    online = [str(n.get("id", "")) for n in gws if n.get("online") is True]
    if len(online) > 1:
        die(f"{len(online)} gateway nodes ({GATEWAY_TAG}) are online (ids {', '.join(online)}): remove all but one "
            "(headscale nodes delete)")
    out: List[Dict[str, Any]] = []
    for n in ns:
        if n.get("tags"):
            continue   # the gateway and other tagged nodes belong to no person
        user = n.get("user") if isinstance(n.get("user"), dict) else {}
        pid = user.get("providerId") or ""
        if not isinstance(pid, str) or not pid.startswith(prefix):
            continue   # a local Headscale user, or another issuer's
        owner = pid[len(prefix):]
        addr = first_ipv4(n)
        if not owner or "/" in owner or addr is None:
            continue
        try:
            last_seen, expires = timestamp(n.get("lastSeen")), timestamp(n.get("expiry"))
        except BadTime as e:
            print(f"headscale vpn glue: node {n.get('id', '')}: unreadable expiry or last-seen time ({e}): left out",
                  file=sys.stderr)
            continue
        out.append({"id": str(n.get("id", "")), "name": str(n.get("givenName") or n.get("name") or ""),
                    "address": addr, "owner": owner, "online": n.get("online") is True,
                    "last_seen": last_seen, "expires": expires})
    if len(out) > MAX_DEVICES:
        die(f"{len(out)} devices: more than {MAX_DEVICES}")
    json.dump({"version": 1, "gateway": first_ipv4(gws[0]), "devices": out}, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


def write_atomic(path: str, data: bytes, mode: int) -> None:
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def dns(records: Any) -> None:
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        die(f"records must be a list of at most {MAX_RECORDS}")
    out = []
    for i, r in enumerate(records):
        if not isinstance(r, dict) or set(r) != {"name", "type", "value"}:
            die(f"records[{i}]: want exactly name, type, value")
        name, typ, value = r["name"], r["type"], r["value"]
        if not isinstance(name, str) or not HOSTNAME_RE.fullmatch(name):
            die(f"records[{i}]: name is not a lowercase hostname")
        if typ != "A":
            die(f"records[{i}]: only type A")
        try:
            if not isinstance(value, str) or ipaddress.ip_address(value).version != 4 or str(ipaddress.ip_address(value)) != value:
                raise ValueError
        except ValueError:
            die(f"records[{i}]: value is not an IPv4 address")
        out.append({"name": name, "type": "A", "value": value})
    write_atomic(RECORDS_PATH, (json.dumps(out, indent=2) + "\n").encode(), 0o644)


def gateway_key() -> None:
    if not os.environ.get("HEADSCALE_API_KEY", "").strip():
        # A fresh install: the API key is the documented post-start step.
        print("headscale vpn glue: the gateway registers at the first start after the Headscale API key setting is set",
              file=sys.stderr)
        return
    if any(n.get("online") is True for n in gateway_nodes(nodes())):
        try:
            os.unlink(AUTHKEY_PATH)   # registered: no key lying around
        except FileNotFoundError:
            pass
        return
    exp = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    resp = api("POST", "/api/v1/preauthkey", {"reusable": False, "ephemeral": False, "expiration": exp,
                                              "aclTags": [GATEWAY_TAG]})
    key = (resp.get("preAuthKey") or {}).get("key") if isinstance(resp.get("preAuthKey"), dict) else None
    if not isinstance(key, str) or not key or "\n" in key:
        die("POST /api/v1/preauthkey: no key in the response")
    write_atomic(AUTHKEY_PATH, key.encode(), 0o600)


def main(argv: List[str]) -> None:
    raw = sys.stdin.buffer.read(MAX_STDIN + 1)
    if len(argv) == 2 and argv[1] == "gateway-key":
        gateway_key()
        return
    if len(argv) != 1:
        die("usage: glue.py [gateway-key]")
    if len(raw) > MAX_STDIN:
        die("stdin too large")
    try:
        req = json.loads(raw)
    except ValueError:
        die("stdin is not JSON")
    if not isinstance(req, dict) or type(req.get("version")) is not int or req["version"] != 1 or req.get("trigger") != "vpn":
        die('stdin must be {"version":1,"trigger":"vpn",...}')
    if req.get("op") == "devices":
        devices()
    elif req.get("op") == "dns":
        dns(req.get("records"))
    else:
        die("op must be devices or dns")


if __name__ == "__main__":
    main(sys.argv)
