#!/usr/bin/env python3
"""Static validation for Portcullis app templates.

Checks every <app-id>/manifest.yaml against schema/manifest.schema.json and
enforces the repository rules a JSON Schema cannot express (they need the
compose file, the filesystem, or more than one template at once). No Docker
needed.

    pip install pyyaml jsonschema
    python3 tests/validate.py               # all templates
    python3 tests/validate.py grafana immich  # selected templates
    python3 tests/validate.py --strict      # warnings fail too

Rules come from CLAUDE.md, CONTRIBUTING.md and the integration contracts
(https://porelli.github.io/portcullis-docs/guides/integration-contracts/).
Exit code: 0 = OK, 1 = rule violations, 2 = usage / setup error.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("validate.py needs PyYAML: pip install pyyaml jsonschema")
try:
    import jsonschema
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    sys.exit("validate.py needs jsonschema: pip install pyyaml jsonschema")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(ROOT, "schema", "manifest.schema.json")
DOCS_URL = "https://porelli.github.io/portcullis-docs/guides"

# Directories at the repo root that are not templates.
NON_TEMPLATE_DIRS = {"tests", "schema"}

# Hub idRe (contracts §3).
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Core variables the Hub copies from the core .env (contracts §2), with the
# default each must carry.
CORE_VARS = {
    "PORTCULLIS_DOMAIN": "portcullis.local",
    "PORTCULLIS_PROXY_SUBNET": "172.31.250.0/24",
    "PORTCULLIS_PROXY_IP_RANGE": "172.31.250.128/25",
    "PORTCULLIS_TRAEFIK_IP": "172.31.250.2",
}

# Subdomains owned by core (group-gate-map.conf); templates must not route them.
CORE_SUBDOMAINS = {"auth", "traefik", "hub", "directory", "enroll"}

PROXY_NET = "portcullis-proxy"
AUTH_MW = "portcullis-auth@docker"
GROUPS_MW = "portcullis-groups@docker"
TLS_OPTIONS = {"authaware@file", "public@file", "protected@file"}

# Host paths (relative to the core checkout) a template may bind-mount besides
# ./templates/<app-id>/...: path -> (requires read-only, why).
CORE_MOUNTS = {
    "./certs/ca-bundle.crt": (True, "the Hub-provided CA bundle"),
    "./docs": (True, "core's documentation directory (docs template only)"),
}

# Floating tags. Anything matching is rejected even with a digest, because
# Dependabot cannot bump it and readers cannot tell which version runs.
FLOATING_TAGS = {
    "latest", "stable", "release", "main", "master", "edge", "nightly", "dev",
    "develop", "beta", "alpha", "rc", "next", "canary", "lts", "current",
    "alpine", "slim", "bookworm", "bullseye", "trixie", "mainline",
}
FLOATING_TAG_RES = [
    re.compile(r"^v?\d+$"),                      # 2, v3
    re.compile(r"^v?\d+(-[A-Za-z]+)+$"),       # 16-alpine, 3-alpine, 4-debian
    re.compile(r"(^|[-_.])(latest|stable|master|nightly|edge)([-_.]|$)"),  # main-stable, master-omnibus
    re.compile(r"^(stable|release|production|mainline)-"),  # stable-apache
]
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")

# Trust settings that would let any peer assert identity headers.
CATCH_ALL_TRUST = [
    (re.compile(r"(^|[\s,=\"'])\*\*($|[\s,\"'])", re.M), '"**"'),
    (re.compile(r"(?<![\d.])0\.0\.0\.0/0\b"), "0.0.0.0/0"),
    (re.compile(r"(?<![0-9A-Fa-f:])::/0\b"), "::/0"),
]

# Security regression guards for native-OIDC apps whose interactive login is
# gated by forward-auth + group-gate (any realm user could otherwise sign in).
# app-id -> path prefixes that must be served only by a router carrying
# portcullis-auth@docker,portcullis-groups@docker.
LOGIN_GATES = {
    "gitlab": ["/users"],
    "litellm": ["/ui", "/sso", "/login", "/v2/login", "/fallback/login", "/onboarding"],
}


class Report:
    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def error(self, where: str, msg: str, hint: str = "") -> None:
        self.errors.append(_fmt(where, msg, hint))

    def warn(self, where: str, msg: str, hint: str = "") -> None:
        self.warnings.append(_fmt(where, msg, hint))


def _fmt(where: str, msg: str, hint: str) -> str:
    s = f"{where}: {msg}"
    if hint:
        s += f"\n      hint: {hint}"
    return s


# ── Helpers ─────────────────────────────────────────────────────────

class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys (YAML silently keeps the last)."""


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> Dict[Any, Any]:
    seen: Set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_yaml(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass


def as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def labels_of(svc: Dict[str, Any]) -> Dict[str, str]:
    raw = svc.get("labels") or {}
    if isinstance(raw, dict):
        return {str(k): "" if v is None else str(v) for k, v in raw.items()}
    out: Dict[str, str] = {}
    for item in raw:
        k, _, v = str(item).partition("=")
        out[k] = v
    return out


def networks_of(svc: Dict[str, Any]) -> List[str]:
    nets = svc.get("networks")
    if nets is None:
        return []
    if isinstance(nets, dict):
        return [str(k) for k in nets]
    return [str(n) for n in nets]


def iter_var_refs(text: str) -> Iterable[Tuple[str, str, str]]:
    """Yield (name, operator, rest) for each compose interpolation in text.

    `$$` is an escaped dollar (left for the container shell) and is skipped.
    operator is one of '', ':-', '-', ':?', '?', ':+', '+'.
    """
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c != "$":
            i += 1
            continue
        if i + 1 < n and text[i + 1] == "$":
            i += 2
            continue
        if i + 1 < n and text[i + 1] == "{":
            m = re.match(r"\{([A-Za-z_][A-Za-z0-9_]*)(:?[-?+])?", text[i + 1:])
            if m:
                # Find the matching close brace (defaults may nest ${...}).
                depth, j = 0, i + 1
                while j < n:
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                body = text[i + 2:j]
                rest = body[len(m.group(1)) + len(m.group(2) or ""):]
                yield m.group(1), m.group(2) or "", rest
                i += 2 + len(m.group(1))  # continue inside: nested refs are scanned too
                continue
        else:
            m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", text[i + 1:])
            if m:
                yield m.group(1), "", ""
                i += 1 + len(m.group(1))
                continue
        i += 1


def _scalars(node: Any) -> Iterable[str]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield str(k)
            yield from _scalars(v)
    elif isinstance(node, list):
        for v in node:
            yield from _scalars(v)
    elif node is not None:
        yield str(node)


def split_middlewares(value: str) -> List[str]:
    return [m.strip() for m in value.split(",") if m.strip()]


HOST_RE = re.compile(r"Host\(`([A-Za-z0-9-]+)\.\$\{PORTCULLIS_DOMAIN")
PATH_RE = re.compile(r"(?:PathPrefix|Path)\(`([^`]*)`\)")


def prefix_covers(prefix: str, path: str) -> bool:
    """Segment-boundary prefix match (group-gate semantics)."""
    prefix = prefix.rstrip("/") or "/"
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


# ── Checks ──────────────────────────────────────────────────────────

class Template:
    def __init__(self, app_id: str) -> None:
        self.id = app_id
        self.dir = os.path.join(ROOT, app_id)
        self.manifest_path = os.path.join(self.dir, "manifest.yaml")
        self.compose_path = os.path.join(self.dir, "compose.yml")
        self.manifest: Optional[Dict[str, Any]] = None
        self.compose: Optional[Dict[str, Any]] = None
        self.compose_text = ""
        self.compose_values = ""
        self.subdomains: Set[str] = set()
        self.volume_names: Dict[str, str] = {}

    @property
    def m_where(self) -> str:
        return f"{self.id}/manifest.yaml"

    @property
    def c_where(self) -> str:
        return f"{self.id}/compose.yml"


def check_layout(t: Template, r: Report) -> bool:
    if not ID_RE.match(t.id):
        r.error(t.id + "/", f"directory name {t.id!r} is not a valid app id",
                "use lowercase letters, digits, '-' and '_' (regex ^[a-z0-9][a-z0-9_-]{0,63}$); the Hub skips other names")
    ok = True
    for path, what in ((t.manifest_path, "manifest.yaml"), (t.compose_path, "compose.yml")):
        if not os.path.isfile(path):
            r.error(t.id + "/", f"missing {what}", "every template needs both manifest.yaml and compose.yml")
            ok = False
    if os.path.exists(os.path.join(t.dir, "compose.yaml")) or os.path.exists(os.path.join(t.dir, "docker-compose.yml")):
        r.error(t.id + "/", "compose file must be named compose.yml (the Hub ignores other names)")
    if not os.path.isfile(os.path.join(ROOT, "tests", "apps", f"{t.id}.sh")):
        r.error(t.id + "/", f"missing test script tests/apps/{t.id}.sh",
                "the integration job runs it for every changed template; see CONTRIBUTING.md for a minimal static test")
    if os.path.exists(os.path.join(t.dir, "manifest.yml")):
        r.error(t.id + "/", "manifest must be named manifest.yaml (not .yml)")
    return ok


def check_manifest_schema(t: Template, validator: Draft202012Validator, r: Report) -> None:
    try:
        data = load_yaml(t.manifest_path)
    except yaml.YAMLError as e:
        r.error(t.m_where, f"YAML does not parse: {e}")
        return
    if not isinstance(data, dict):
        r.error(t.m_where, "top level must be a mapping")
        return
    t.manifest = data
    errs = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    for e in errs:
        path = ".".join(str(p) for p in e.absolute_path) or "(top level)"
        r.error(t.m_where, f"{path}: {_schema_msg(e)}",
                f"see schema/manifest.schema.json and {DOCS_URL}/manifest-reference/")


def _schema_msg(e: jsonschema.ValidationError) -> str:
    # Make the commonest failures readable for contributors.
    if e.validator == "additionalProperties":
        return e.message + " (typo, or a field the Hub does not read?)"
    if e.validator in ("oneOf", "anyOf") and e.context:
        best = jsonschema.exceptions.best_match(e.context)
        return f"{e.message[:120]} — closest problem: {best.message}"
    if e.validator == "pattern":
        return f"{e.instance!r} does not match {e.schema.get('pattern')}"
    if e.validator == "not":
        pat = (e.validator_value or {}).get("pattern") if isinstance(e.validator_value, dict) else None
        if pat:
            return f"{e.instance!r} matches the forbidden pattern {pat} (no '..', '//' or '.' segments)"
        return f"{e.instance!r} is not allowed here"
    return e.message


def check_manifest_rules(t: Template, r: Report) -> None:
    m = t.manifest or {}
    auth = m.get("auth") or {}
    env = [e for e in (m.get("env") or []) if isinstance(e, dict)]
    random_keys = {e.get("key") for e in env if e.get("generate") == "random"}

    # Duplicate keys across settings/ports/env all land in one .env file.
    seen: Dict[str, str] = {}
    for section in ("settings", "ports", "env"):
        for item in m.get(section) or []:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                continue
            k = item["key"]
            if k in seen:
                r.error(t.m_where, f"key {k} is declared in both {seen[k]} and {section}",
                        "settings, ports and env share the per-app .env; keys must be unique")
            seen[k] = section
            if k in CORE_VARS:
                r.error(t.m_where, f"{section} key {k} shadows a core variable")

    for c in m.get("keycloak_clients") or []:
        if isinstance(c, dict) and c.get("secret_env") and c["secret_env"] not in random_keys:
            r.error(t.m_where, f"keycloak client {c.get('client_id')}: secret_env {c['secret_env']} is not an env entry with generate: random",
                    "add it under env: with generate: random so the Hub creates the secret")

    for p in m.get("ports") or []:
        if isinstance(p, dict) and p.get("bind"):
            try:
                ipaddress.ip_address(str(p["bind"]))
            except ValueError:
                r.error(t.m_where, f"port {p.get('key')}: bind {p['bind']!r} is not an IP address")
        if isinstance(p, dict) and p.get("range"):
            lo, _, hi = str(p["range"]).partition("-")
            if lo.isdigit() and hi.isdigit() and not (1 <= int(lo) <= int(hi) <= 65535):
                r.error(t.m_where, f"port {p.get('key')}: range {p['range']} is not a valid low-high port range")

    for cf in m.get("config_files") or []:
        if isinstance(cf, dict) and isinstance(cf.get("src"), str):
            if not os.path.isfile(os.path.join(t.dir, cf["src"])):
                r.error(t.m_where, f"config_files src {cf['src']} does not exist in {t.id}/")

    for u in m.get("urls") or []:
        if isinstance(u, dict) and isinstance(u.get("url"), str) and "{{DOMAIN}}" not in u["url"]:
            r.warn(t.m_where, f"url {u['url']} does not use {{{{DOMAIN}}}}",
                   "links should be https://<sub>.{{DOMAIN}}/...")

    if auth.get("method") in ("forward-auth", "header-auth") and auth.get("group_access") is False:
        r.warn(t.m_where, f"auth.method {auth['method']} with group_access: false lets every Portcullis user in",
               "set group_access: true and access_group: users_<app> unless that is intended")


def check_compose(t: Template, r: Report) -> None:
    try:
        with open(t.compose_path, encoding="utf-8") as f:
            t.compose_text = f.read()
        data = yaml.load(t.compose_text, Loader=_UniqueKeyLoader)  # noqa: S506
    except yaml.YAMLError as e:
        r.error(t.c_where, f"YAML does not parse: {e}")
        return
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict) or not data["services"]:
        r.error(t.c_where, "must be a mapping with a non-empty services: section")
        return
    t.compose = data
    # Interpolation and trust checks look at YAML scalars only, not comments.
    t.compose_values = "\n".join(_scalars(data))
    m = t.manifest or {}
    auth = m.get("auth") or {}
    method = auth.get("method")
    services: Dict[str, Any] = data["services"]

    for key in ("version",):
        if key in data:
            r.warn(t.c_where, f"top-level '{key}:' is obsolete in Compose v2; remove it")

    # Networks
    top_nets = data.get("networks") or {}
    if "portcullis" in top_nets:
        r.error(t.c_where, "network 'portcullis' is wrong; frontends join the external network 'portcullis-proxy'")
    for name, spec in top_nets.items():
        if name == PROXY_NET:
            if not (isinstance(spec, dict) and spec.get("external") is True):
                r.error(t.c_where, f"networks.{PROXY_NET} must be declared 'external: true'",
                        "core creates portcullis-proxy (fixed subnet, Traefik's static IP); templates only attach to it")
        elif name != "default":
            r.error(t.c_where, f"networks.{name}: templates may only use 'default' and '{PROXY_NET}'")

    # Volumes
    top_vols = data.get("volumes") or {}
    for vname, spec in top_vols.items():
        vol_name = spec.get("name") if isinstance(spec, dict) else None
        if not vol_name:
            r.error(t.c_where, f"volumes.{vname} needs an explicit 'name: portcullis_{vname}'",
                    "without it the name depends on the compose project and data is lost on rename")
            continue
        if not str(vol_name).startswith("portcullis_"):
            r.error(t.c_where, f"volumes.{vname}: name {vol_name!r} must start with 'portcullis_'")
        if isinstance(spec, dict) and spec.get("external"):
            r.error(t.c_where, f"volumes.{vname}: external volumes are not allowed in templates")
        t.volume_names[str(vol_name)] = vname

    if top_nets.get(PROXY_NET) is None and any(PROXY_NET in networks_of(s or {}) for s in services.values()):
        r.error(t.c_where, f"a service joins {PROXY_NET} but networks.{PROXY_NET} (external: true) is not declared")

    random_keys = {e.get("key") for e in (m.get("env") or []) if isinstance(e, dict) and e.get("generate") == "random"}
    declared = set(random_keys)
    for section in ("env", "settings", "ports"):
        for item in m.get(section) or []:
            if isinstance(item, dict) and isinstance(item.get("key"), str):
                declared.add(item["key"])

    # Variable interpolation
    for name, op, rest in iter_var_refs(t.compose_values):
        if name in CORE_VARS:
            if op != ":-":
                r.error(t.c_where, f"${{{name}}} must use the default form ${{{name}:-{CORE_VARS[name]}}}",
                        "contracts §2: always give core variables their default")
            continue
        if op in (":?", "?"):
            if name not in random_keys:
                r.error(t.c_where, f"${{{name}:?}} is required but the Hub never sets it",
                        f"required vars must be a core var or a manifest env entry with generate: random; "
                        f"otherwise use ${{{name}:-}} (optional) and declare it under env:/settings:")
        elif name not in declared:
            r.error(t.c_where, f"${{{name}}} is not a core variable and not declared in the manifest (env/settings/ports)",
                    "the Hub only writes declared keys into the per-app .env; use $$" + name +
                    " if the container shell should expand it")

    # Catch-all trust (any method)
    for rx, label in CATCH_ALL_TRUST:
        if rx.search(t.compose_values):
            r.error(t.c_where, f"compose trusts every peer ({label})",
                    "trust identity / forwarded headers only from ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}")

    if method == "header-auth":
        if "${PORTCULLIS_TRAEFIK_IP:-" not in t.compose_values:
            r.error(t.c_where, "header-auth app does not restrict identity headers to Traefik",
                    "set the app's proxy allowlist (or a gate in front of it) to ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}; see CONTRIBUTING.md")
        if "${PORTCULLIS_PROXY_SUBNET" in t.compose_values or "${PORTCULLIS_PROXY_IP_RANGE" in t.compose_values:
            r.error(t.c_where, "header-auth app references the portcullis-proxy subnet",
                    "trusting the subnet lets every app container forge X-Forwarded-User; trust PORTCULLIS_TRAEFIK_IP only")

    routers: Dict[str, Dict[str, str]] = {}
    for sname, svc in services.items():
        where = f"{t.c_where}: services.{sname}"
        if not isinstance(svc, dict):
            r.error(where, "service must be a mapping")
            continue
        check_service(t, sname, svc, where, r)
        labels = labels_of(svc)
        enabled = labels.get("traefik.enable", "").lower() == "true"
        nets = networks_of(svc)
        if svc.get("network_mode"):
            if nets:
                r.error(where, "network_mode and networks are mutually exclusive")
        elif enabled:
            if PROXY_NET not in nets or "default" not in nets:
                r.error(where, f"Traefik-routed service must use networks: [default, {PROXY_NET}]")
        elif PROXY_NET in nets:
            r.error(where, f"internal service is on {PROXY_NET}",
                    "only services with traefik.enable=true join portcullis-proxy; databases, caches and sidecars stay on default")
        for k, v in labels.items():
            mm = re.match(r"^traefik\.http\.routers\.([^.]+)\.(.+)$", k)
            if mm:
                routers.setdefault(mm.group(1), {"_service": sname})[mm.group(2)] = v
        if not enabled and any(k.startswith("traefik.http.") for k in labels):
            r.error(where, "has traefik.http.* labels but not traefik.enable: \"true\"")

    check_routers(t, routers, r)


def check_service(t: Template, sname: str, svc: Dict[str, Any], where: str, r: Report) -> None:
    if "build" in svc:
        r.error(where, "build: is not supported; the Hub only pulls images")
    if "container_name" in svc:
        r.error(where, "container_name: is not allowed (the Hub names containers portcullis-<service>-1)")
    if "ports" in svc:
        r.error(where, "publishes ports in compose.yml",
                "declare host ports in manifest.yaml under ports:; the Hub writes the bindings into a per-app override. "
                "HTTP(S) goes through Traefik, never a published port")
    if "env_file" in svc:
        r.error(where, "env_file: is not supported; the Hub writes the per-app .env from manifest env/settings")

    image = svc.get("image")
    if not isinstance(image, str) or not image:
        r.error(where, "needs an image:")
    else:
        check_image(image, where, r)

    for vol in as_list(svc.get("volumes")):
        check_mount(t, vol, where, r)

    if (svc.get("network_mode") == "host") and t.manifest:
        if not any(isinstance(p, dict) and p.get("service") == sname and p.get("network_mode_host")
                   for p in t.manifest.get("ports") or []):
            r.warn(where, "uses network_mode: host but the manifest declares no ports with network_mode_host: true",
                   "declare its ports so the Hub can detect collisions")


def check_image(image: str, where: str, r: Report) -> None:
    ref = image.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else ""
    if not tag:
        r.error(where, f"image {image!r} has no tag",
                "use an explicit version tag plus digest, e.g. grafana/grafana:13.3.0@sha256:<digest>")
        return
    if tag in FLOATING_TAGS or any(rx.search(tag) for rx in FLOATING_TAG_RES):
        r.error(where, f"image tag {tag!r} is floating",
                "pin the exact release, e.g. postgres:16.15-alpine instead of postgres:16-alpine; Dependabot proposes updates")
    if not DIGEST_RE.search(image):
        r.error(where, f"image {image!r} is not pinned by digest",
                "append @sha256:<index digest>, e.g. from `docker buildx imagetools inspect <image:tag>` "
                "or `docker manifest inspect -v`; Dependabot keeps tag and digest in sync")


def check_mount(t: Template, vol: Any, where: str, r: Report) -> None:
    if isinstance(vol, dict):
        if vol.get("type") not in (None, "bind", "volume"):
            return
        src = str(vol.get("source") or "")
        read_only = bool(vol.get("read_only"))
        if vol.get("type") == "volume" or (src and not _is_path(src)):
            return
    else:
        parts = str(vol).split(":")
        src = parts[0]
        read_only = len(parts) >= 3 and "ro" in parts[2].split(",")
        if len(parts) == 1 or not _is_path(src):
            return  # anonymous or named volume
    if not src:
        return
    if src.startswith("/"):
        return  # absolute host path (devices etc.); documented in the manifest notes
    norm = src.rstrip("/")
    if not norm.startswith("./"):
        r.error(where, f"bind mount {src!r} must start with ./templates/{t.id}/",
                "relative paths resolve against the core checkout on the host")
        return
    if "/../" in norm + "/" or norm.startswith("./.."):
        r.error(where, f"bind mount {src!r} escapes the allowed directories ('..')")
        return
    if norm == "./scripts" or norm.startswith("./scripts/"):
        r.error(where, f"bind mount {src!r}: templates must not reference core's ./scripts/")
        return
    prefix = f"./templates/{t.id}/"
    if norm.startswith("./templates/"):
        if not norm.startswith(prefix):
            r.error(where, f"bind mount {src!r} points into another template; use {prefix}<file>")
            return
        rel = norm[len(prefix):]
        if not os.path.exists(os.path.join(t.dir, rel)):
            r.error(where, f"bind mount {src!r}: {t.id}/{rel} does not exist in this template")
        return
    if norm in CORE_MOUNTS:
        need_ro, why = CORE_MOUNTS[norm]
        if need_ro and not read_only:
            r.error(where, f"bind mount {src!r} ({why}) must be read-only (:ro)")
        if norm == "./docs" and t.id != "docs":
            r.error(where, "./docs may only be mounted by the docs template")
        return
    if norm.startswith("./certs"):
        r.error(where, f"bind mount {src!r}: only ./certs/ca-bundle.crt:<path>:ro may be mounted from ./certs/")
        return
    r.error(where, f"bind mount {src!r} is outside ./templates/{t.id}/",
            f"ship the file in {t.id}/ and mount it as {prefix}<file> (the Hub copies the template dir there); "
            "never ./<file>")


def _is_path(src: str) -> bool:
    return src.startswith((".", "/", "~")) or "/" in src


def check_routers(t: Template, routers: Dict[str, Dict[str, str]], r: Report) -> None:
    auth = (t.manifest or {}).get("auth") or {}
    method = auth.get("method")
    admin_paths = auth.get("admin_paths") or []
    gated: List[Tuple[str, List[str]]] = []  # (router, path prefixes or ["/"])

    for name, rt in sorted(routers.items()):
        where = f"{t.c_where}: router {name}"
        rule = rt.get("rule", "")
        if not rule:
            r.error(where, "has no rule")
            continue
        hosts = HOST_RE.findall(rule)
        if not hosts:
            r.error(where, "rule must use Host(`<sub>.${PORTCULLIS_DOMAIN:-portcullis.local}`)",
                    "the Hub derives auth policies and group-gate entries from this exact form")
        for h in hosts:
            h = h.lower()
            if h in CORE_SUBDOMAINS:
                r.error(where, f"subdomain {h!r} belongs to core")
            t.subdomains.add(h)
        if rt.get("entrypoints") != "websecure":
            r.error(where, "entrypoints must be 'websecure'")
        tls = rt.get("tls.options")
        if tls not in TLS_OPTIONS:
            r.error(where, f"tls.options must be one of {sorted(TLS_OPTIONS)} (got {tls!r})")
        if method == "mtls" and tls != "protected@file":
            r.error(where, "auth.method mtls needs tls.options: protected@file")

        mws = split_middlewares(rt.get("middlewares", ""))
        has_auth, has_groups = AUTH_MW in mws, GROUPS_MW in mws
        if "security-headers@file" not in mws:
            r.warn(where, "middlewares should include security-headers@file")
        if has_groups and not has_auth:
            r.error(where, f"{GROUPS_MW} without {AUTH_MW}: group-gate needs the authenticated user")
        if has_auth and not has_groups:
            r.error(where, f"{AUTH_MW} without {GROUPS_MW}: group membership would not be enforced")
        if has_auth and has_groups and mws.index(AUTH_MW) > mws.index(GROUPS_MW):
            r.error(where, f"{AUTH_MW} must come before {GROUPS_MW}")
        paths = PATH_RE.findall(rule)
        host_wide = not paths

        if method in ("forward-auth", "header-auth"):
            if not (has_auth and has_groups):
                r.error(where, f"{method} router must use middlewares {AUTH_MW},{GROUPS_MW}")
        elif method == "native-oidc":
            if has_auth and host_wide:
                r.error(where, f"native-oidc router must not use {AUTH_MW} on the whole host",
                        "the app's own OIDC login, API and mobile clients break behind forward-auth; "
                        "gate only specific paths (PathPrefix) such as an admin panel or the login pages")
        elif method in ("public", "custom", "mtls"):
            if has_auth:
                r.error(where, f"auth.method {method} must not use {AUTH_MW} (use forward-auth/header-auth instead)")

        if has_auth and has_groups:
            gated.append((name, ["/"] if host_wide else paths))

    if any(True for _ in gated) and not auth.get("group_access") and not admin_paths:
        r.warn(t.m_where, "routers use group-gate but group_access is false: only authentication is enforced",
               "set group_access: true and access_group, or declare admin_paths")

    for ap in admin_paths:
        if not any(any(prefix_covers(p, ap) for p in ps) for _, ps in gated):
            r.error(t.m_where, f"auth.admin_paths {ap}: no router with {AUTH_MW},{GROUPS_MW} serves this path",
                    "group-gate only sees requests on routers that use portcullis-groups@docker; add a PathPrefix router for it")

    for p in LOGIN_GATES.get(t.id, []):
        if not any(any(prefix_covers(q, p) for q in ps) for _, ps in gated):
            r.error(t.c_where, f"security regression: {p} must be served by a router with {AUTH_MW},{GROUPS_MW}",
                    "without it any Keycloak realm user can sign in; see the auth notes in manifest.yaml")
    if t.id in LOGIN_GATES and not auth.get("group_access"):
        r.error(t.m_where, "security regression: login is gated by group-gate, so group_access must be true")


def check_cross(templates: List[Template], r: Report) -> None:
    owner: Dict[str, str] = {}
    vol_owner: Dict[str, str] = {}
    for t in templates:
        for sub in sorted(t.subdomains):
            if sub in owner and owner[sub] != t.id:
                r.error(t.c_where, f"subdomain {sub!r} is also routed by {owner[sub]}")
            owner.setdefault(sub, t.id)
        for vn in t.volume_names:
            if vn in vol_owner and vol_owner[vn] != t.id:
                r.error(t.c_where, f"volume name {vn!r} is also used by {vol_owner[vn]} (apps would share data)")
            vol_owner.setdefault(vn, t.id)


CORE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


def check_core_ref(r: Report) -> None:
    """.core-ref: the core tag (or main) CI tests against (contracts §1)."""
    path = os.path.join(ROOT, ".core-ref")
    try:
        with open(path, encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    except FileNotFoundError:
        r.error(".core-ref", "missing; it must contain the core ref CI tests against (a tag like v1.4.0, or main)")
        return
    if len(lines) != 1 or not CORE_REF_RE.match(lines[0]) or ".." in lines[0]:
        r.error(".core-ref", f"must contain exactly one git ref (tag like v1.4.0, or main), got {lines!r}")


def check_dependabot(app_ids: List[str], r: Report) -> None:
    """Every template directory must be covered by Dependabot's docker-compose entry."""
    path = os.path.join(ROOT, ".github", "dependabot.yml")
    try:
        data = load_yaml(path) or {}
    except (OSError, yaml.YAMLError) as e:
        r.error(".github/dependabot.yml", f"cannot read: {e}")
        return
    dirs: Set[str] = set()
    for u in data.get("updates") or []:
        if isinstance(u, dict) and u.get("package-ecosystem") == "docker-compose":
            dirs.update(str(d).strip("/") for d in as_list(u.get("directories")) + as_list(u.get("directory")))
    for app in app_ids:
        if app not in dirs:
            r.error(".github/dependabot.yml", f"template {app} is missing from the docker-compose directories list",
                    f'add  - "/{app}"  under directories: so Dependabot keeps its images up to date')


# ── Main ────────────────────────────────────────────────────────────

def discover() -> List[str]:
    out = []
    for e in sorted(os.listdir(ROOT)):
        p = os.path.join(ROOT, e)
        if not os.path.isdir(p) or e.startswith(".") or e in NON_TEMPLATE_DIRS:
            continue
        if any(os.path.exists(os.path.join(p, f)) for f in ("manifest.yaml", "manifest.yml", "compose.yml", "compose.yaml")):
            out.append(e)
        else:
            print(f"note: skipping {e}/ (no manifest.yaml / compose.yml)", file=sys.stderr)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("apps", nargs="*", help="template ids to check (default: all)")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = ap.parse_args(argv)

    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)

    all_ids = discover()
    ids = args.apps or all_ids
    unknown = [a for a in ids if a not in all_ids]
    if unknown:
        print(f"unknown template(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    r = Report()
    # Cross-template checks always look at every template.
    templates = {i: Template(i) for i in all_ids}
    for i, t in templates.items():
        sub = Report()
        if check_layout(t, sub):
            check_manifest_schema(t, validator, sub)
            if t.manifest is not None:
                check_manifest_rules(t, sub)
                check_compose(t, sub)
        if i in ids:
            r.errors += sub.errors
            r.warnings += sub.warnings
    check_core_ref(r)
    check_dependabot(all_ids, r)
    cross = Report()
    check_cross(list(templates.values()), cross)
    r.errors += [e for e in cross.errors if e.split("/", 1)[0] in ids]

    for w in r.warnings:
        print(f"WARN  {w}")
    for e in r.errors:
        print(f"ERROR {e}")
    failed = bool(r.errors) or (args.strict and bool(r.warnings))
    print(f"\n{len(ids)} template(s) checked: {len(r.errors)} error(s), {len(r.warnings)} warning(s)")
    if failed:
        print("See CONTRIBUTING.md for the rules and how to fix them.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
