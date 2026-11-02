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
CORE_SUBDOMAINS = {"auth", "traefik", "hub", "directory", "enroll", "metrics", "people"}  # contracts §4, §5.1

# Contract v2 (contracts §3.1): instance-scoped variables the Hub writes into
# every instance's .env. Templates use them in the default form with the
# default instance's value and never declare them in the manifest.
INSTANCE_VARS = {"PORTCULLIS_INSTANCE", "PORTCULLIS_OIDC_CLIENT_ID", "PORTCULLIS_ACCESS_GROUP", "PORTCULLIS_ADMIN_GROUP"}
INSTANCE_VAR_PREFIXES = ("PORTCULLIS_HOST_", "PORTCULLIS_OIDC_CLIENT_ID_")
V2_HINT = f"see {DOCS_URL}/integration-contracts/#31-template-contract-v2-instances-and-hostname-variables-new-contract-v2"
# Default subdomain: a single DNS label.
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_PATH_MATCHER = r"(?:PathPrefix|Path)\(`[^`]*`\)"
PATH_PART_RE = re.compile(rf"^(?:{_PATH_MATCHER}|\(\s*{_PATH_MATCHER}(?:\s*\|\|\s*{_PATH_MATCHER})*\s*\))$")
# Host(`${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}`) [&& <path matchers>]
V2_RULE_RE = re.compile(r"^Host\(`\$\{(PORTCULLIS_HOST_[A-Z0-9_]+):-([^`{}$]*)\.portcullis\.local\}`\)(?:\s*&&\s*(.+))?$", re.S)
# Conversion period, instances: single only: Host(`<sub>.${PORTCULLIS_DOMAIN:-portcullis.local}`) [&& ...]
V1_RULE_RE = re.compile(r"^Host\(`([^`{}$]*)\.\$\{PORTCULLIS_DOMAIN:-portcullis\.local\}`\)(?:\s*&&\s*(.+))?$", re.S)
HOST_PLACEHOLDER_RE = re.compile(r"\{\{HOST_([A-Za-z0-9_]*)\}\}")

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
    "paperless": ["/accounts/oidc", "/api/auth/headless/browser/v1/auth/provider",
                  "/api/auth/headless/app/v1/auth/provider"],
    "vaultwarden": ["/identity/connect/authorize", "/identity/connect/oidc-signin"],
}
# Native-OIDC templates whose separately hosted static web client is gated
# as a whole (forward-auth + group-gate on its host router) while the app's
# API host stays ungated: app-id -> router names. Only static clients that
# hold no server data and have no login of their own belong here; each
# listed router must stay gated (check_routers).
GATED_CLIENT_ROUTERS = {
    "matrix": {"element"},
}
# Host routers whose hostname is baked into the app's data at first start
# (manifest hosts.immutable; the Hub refuses to change them afterwards).
# Listed here so the declaration can't be dropped from these templates.
IMMUTABLE_HOSTS = {
    "matrix": {"matrix": "Synapse's server_name is the homeserver hostname and is part of every user and room id"},
}
# Never protect a password form or a setup wizard with these: Traefik's path
# matching differs from the app's (case, repeated slashes, /index.php).
# Nextcloud and Wiki.js have no password login at all instead (see their notes).


# Public path exceptions (auth.public_access): mirror of the Hub's
# internal/templates/public.go. Paths on the public router skip forward-auth
# and group-gate, so they are validated strictly.
PUBLIC_RESERVED = "portcullis-public-"
PUBLIC_METHODS = {"forward-auth", "header-auth", "native-oidc"}
PUBLIC_TOKEN = "{token}"
PUBLIC_SEG_RE = re.compile(r"^(/[A-Za-z0-9._~-]+)+/?$")
PUBLIC_BROAD = {
    "/api", "/apps", "/index.php", "/ocs", "/ocs/v1.php", "/ocs/v2.php", "/remote.php", "/remote.php/dav",
    "/remote.php/webdav", "/public.php", "/dav", "/webdav", "/graphql", "/rest", "/v1", "/v2", "/v3",
    "/auth", "/login", "/user", "/users", "/account", "/settings", "/identity", "/sso", "/oidc",
}
PUBLIC_FORBIDDEN = ["/oauth2", "/admin", "/.well-known"]
PUBLIC_TOKEN_PROBES = ["", ".", "..", "a/b", "/", "a`b", "a b", "%2F", "${X}", "a)b", "a\nb"]
PUBLIC_NARROW_MATCHERS = {"host", "path", "pathprefix", "method", "header", "headerregexp", "query", "queryregexp", "clientip"}
PUBLIC_HINT = f"see {DOCS_URL}/manifest-reference/#authpublic_access"


def seg_overlap(a: str, b: str) -> bool:
    if a == "/" or b == "/":
        return True
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def token_base(p: str) -> str:
    i = p.find("/" + PUBLIC_TOKEN)
    return p if i < 0 else (p[:i] or "/")


def rule_path_overlaps(kind: str, v: str, p: str) -> bool:
    """Traefik Path/PathPrefix value v vs a segment-boundary prefix p."""
    if kind == "Path":
        return v == p or v.startswith(p + "/")
    return (p + "/").startswith(v) or v.startswith(p + "/")


# Identity must never be keyed on (or linked by) the email: LLDAP lets every
# user change their own email, Keycloak marks it unverified and group-gate
# forwards it separately in X-Forwarded-Email (display / notifications only).
# X-Forwarded-User / preferred_username / sub are the identity.
EMAIL_HINT = ("key accounts on the LLDAP username (X-Forwarded-User / preferred_username) or the OIDC sub; "
              "LLDAP emails are user-editable, so email matching allows account takeover")

# (env key regex, forbidden value regex, message)
IDENTITY_ENV_FORBIDDEN = [
    (r"^(AUTHENTICATION_GUARD_HEADER|REVERSE_PROXY_USER_HEADER|HTTP_AUTH_HEADER|GF_AUTH_PROXY_HEADER_NAME|REMOTE_USER_HEADER)$",
     r"(?i)email", "identity header is the email header"),
    (r"^GF_AUTH_PROXY_HEADER_PROPERTY$", r"(?i)^email$", "Grafana auth proxy keys users on email"),
    (r"^SSO_SIGNUPS_MATCH_EMAIL$", r"(?i)^(true|1|yes)$", "Vaultwarden links SSO logins to existing accounts by email"),
    (r"^GENERIC_USER_ID_ATTRIBUTE$", r"(?i)email", "LiteLLM SSO user id is the email"),
    (r"^(OAUTH2_PROXY_USER_ID_CLAIM|OIDC_USERNAME_CLAIM|OIDC_USER_CLAIM)$", r"(?i)email", "user id claim is the email"),
    (r"^PAPERLESS_(AUTO_LOGIN_USERNAME|ENABLE_HTTP_REMOTE_USER(_API)?)$", r".",
     "Paperless auto-login / remote-user auth bypasses SSO"),
    (r"^GITEA__oauth2_client__ACCOUNT_LINKING$", r"(?i)^auto$", "Gitea links OAuth logins to existing accounts by name/email"),
    (r"^GITEA__oauth2_client__USERNAME$", r"(?i)^email$", "Gitea OAuth username is the email"),
]

# (env key that enables the feature, its value regex, required env key, required value regex, message)
IDENTITY_ENV_REQUIRED = [
    ("SSO_ENABLED", r"(?i)^true$", "SSO_SIGNUPS_MATCH_EMAIL", r"(?i)^false$",
     "Vaultwarden SSO must set SSO_SIGNUPS_MATCH_EMAIL: \"false\" (the default true links accounts by email)"),
    ("SSO_ENABLED", r"(?i)^true$", "INVITATIONS_ALLOWED", r"(?i)^false$",
     "Vaultwarden SSO must set INVITATIONS_ALLOWED: \"false\" (an email invitation creates a placeholder account the first SSO user with that email takes over)"),
    ("SSO_ENABLED", r"(?i)^true$", "SIGNUPS_ALLOWED", r"(?i)^false$",
     "Vaultwarden SSO must set SIGNUPS_ALLOWED: \"false\" (accounts only via the group-gated SSO login)"),
    ("AUTHENTICATION_GUARD", r"^remote_user_guard$", "AUTHENTICATION_GUARD_HEADER", r"^HTTP_X_FORWARDED_USER$",
     "Firefly III remote_user_guard must key users on HTTP_X_FORWARDED_USER (LLDAP username)"),
    ("FTLCONF_webserver_api_password", r"^$", "FTLCONF_webserver_acl",
     r"^\+\$\{PORTCULLIS_TRAEFIK_IP:-[0-9.]+\}(,\+127\.0\.0\.1)?(,\+\[::1\])?$",
     "Pi-hole without a password must set FTLCONF_webserver_acl to +${PORTCULLIS_TRAEFIK_IP:-172.31.250.2} "
     "(optionally +127.0.0.1,+[::1]): otherwise every container on portcullis-proxy gets the admin API"),
    ("FTLCONF_webserver_api_password", r"^$", "FTLCONF_webserver_domain", r"^\$\{PORTCULLIS_HOST_[A-Z0-9_]+:-[^}]+\}$",
     "Pi-hole without a password must set FTLCONF_webserver_domain to its PORTCULLIS_HOST_<ROUTER> "
     "(FTL refuses unknown Host names then)"),
    ("REVERSE_PROXY_AUTH", r"(?i)^true$", "REVERSE_PROXY_USER_HEADER", r"^HTTP_X_FORWARDED_USER$",
     "Kanboard reverse proxy auth must key users on HTTP_X_FORWARDED_USER (LLDAP username)"),
    ("GENERIC_CLIENT_ID", r".", "GENERIC_USER_EMAIL_ATTRIBUTE", r"^(?!email$).+",
     "LiteLLM matches SSO logins to existing users by email; map GENERIC_USER_EMAIL_ATTRIBUTE to a claim that is never sent"),
    ("PAPERLESS_SOCIALACCOUNT_PROVIDERS", r".", "PAPERLESS_DISABLE_REGULAR_LOGIN", r"(?i)^true$",
     "Paperless SSO must set PAPERLESS_DISABLE_REGULAR_LOGIN: \"true\""),
    ("GITEA__oauth2_client__ENABLE_AUTO_REGISTRATION", r"(?i)^true$", "GITEA__oauth2_client__ACCOUNT_LINKING", r"^disabled$",
     "Gitea auto-registration must set GITEA__oauth2_client__ACCOUNT_LINKING=disabled"),
    ("OIDC_AUTH_ENABLED", r"(?i)^true$", "ALLOW_PASSWORD_LOGIN", r"(?i)^false$",
     "Mealie with OIDC must set ALLOW_PASSWORD_LOGIN: \"false\""),
    ("OIDC_AUTH_ENABLED", r"(?i)^true$", "OIDC_USER_CLAIM", r"^preferred_username$",
     "Mealie with OIDC must set OIDC_USER_CLAIM: preferred_username"),
]

# image prefix -> (one-shot service that must exist in the same compose file, message)
REQUIRED_INIT_JOBS = [
    ("ghcr.io/immich-app/immich-server:", "immich-lock-local-users",
     "Immich links OAuth logins to existing users by email and cannot be told not to; keep the immich-lock-local-users job"),
    ("ghcr.io/paperless-ngx/paperless-ngx:", "paperless-init",
     "Paperless password logins (Basic auth, /api/token/) and the fresh-install signup are only closed by the paperless-init job"),
    ("ghcr.io/mealie-recipes/mealie:", "mealie-init",
     "Mealie's password endpoint, seeded admin and username/email account matching are only closed by the mealie-init guard"),
]

# (regex over every scalar of compose.yml and every text file in the template, message)
IDENTITY_TEXT_FORBIDDEN = [
    (r"omniauth_auto_link_user'\]\s*=\s*(true|\[)", "GitLab omniauth_auto_link_user links OIDC logins to accounts by email"),
    (r"(?m)^\s*auto_link_user:\s*(true|\[)", "GitLab auto_link_user links OIDC logins to accounts by email"),
    (r"(?m)^\s*email_verified_required:\s*false", "Headscale would sync the unverified, user-editable email"),
    (r"\"DefaultUsernameClaim\"\s*:\s*\"email\"", "Jellyfin SSO plugin keys users on email"),
    (r"\"AuthUserIDClaim\"\s*:\s*\"email\"", "NetBird keys users on email"),
    (r"uid_field:\s*'email'", "GitLab OIDC uid_field is the email"),
    (r"--mapping-uid[= ]['\"]?email\b", "Nextcloud user_oidc keys users on email"),
    (r"soft_auto_provision\b.*--value[= ]['\"]?(true|1)\b",
     "Nextcloud user_oidc soft auto-provisioning attaches SSO logins to existing local accounts"),
    (r"[\"']json-mail[\"']\s*=>\s*[\"']email[\"']",
     "the DokuWiki oauth plugin finds accounts by the json-mail claim; map it to preferred_username"),
    (r"[\"']allow_existing_users[\"']\s*:\s*True", "Synapse would attach SSO logins to existing accounts"),
    (r"[\"'](localpart|subject|email)_template[\"']\s*:\s*[\"']\{\{\s*user\.email",
     "Synapse keys users on email"),
    (r"[\"']subject_claim[\"']\s*:\s*[\"']email[\"']", "Synapse keys users on email"),
]


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


def is_instance_var(name: str) -> bool:
    return name in INSTANCE_VARS or name.startswith(INSTANCE_VAR_PREFIXES)


def var_key(name: str) -> str:
    """Router name / client id -> variable suffix (upper-case, '-' and '.' -> '_')."""
    return re.sub(r"[-.]", "_", name.upper())


def parse_rule(rule: str) -> Optional[Tuple[str, Optional[str], str, Optional[str]]]:
    """(form 'v2'|'v1', host variable or None, default subdomain, path part or None)."""
    rule = rule.strip()
    m = V2_RULE_RE.match(rule)
    if m:
        return "v2", m.group(1), m.group(2), m.group(3)
    m = V1_RULE_RE.match(rule)
    if m:
        return "v1", None, m.group(1), m.group(2)
    return None


def rule_hosts(rule: str) -> Set[str]:
    p = parse_rule(rule)
    return {p[2].lower()} if p else set()


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
        # Contract v2: rule form of the routers ('v2', 'v1' or None) and
        # host variable -> default subdomain of each host router.
        self.form: Optional[str] = None
        self.host_vars: Dict[str, str] = {}

    @property
    def multi(self) -> bool:
        return (self.manifest or {}).get("instances") == "multi"

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
            if is_instance_var(k):
                r.error(t.m_where, f"{section} key {k} is reserved for the Hub's instance variables",
                        "the Hub writes PORTCULLIS_INSTANCE, PORTCULLIS_HOST_*, PORTCULLIS_OIDC_CLIENT_ID*, "
                        "PORTCULLIS_ACCESS_GROUP and PORTCULLIS_ADMIN_GROUP itself; " + V2_HINT)

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
        if isinstance(u, dict) and isinstance(u.get("url"), str) and "{{DOMAIN}}" not in u["url"] \
                and not HOST_PLACEHOLDER_RE.search(u["url"]):
            r.warn(t.m_where, f"url {u['url']} uses neither {{{{HOST_<ROUTER>}}}} nor {{{{DOMAIN}}}}",
                   "links to the app should be https://{{HOST_<ROUTER>}}/...")

    if "instances" not in m:
        r.warn(t.m_where, "instances is not set (default single)",
               "set instances: multi, or instances: single with the reason in auth.notes; " + V2_HINT)
    elif m.get("instances") == "single" and not re.search(r"(?i)instance", str(auth.get("notes") or "")):
        r.warn(t.m_where, "instances: single without a reason in auth.notes",
               "a template stays single only for host-level uniqueness (e.g. fixed host devices); say why in auth.notes")

    # auth.native_login: Portcullis sign-in in front of an app's own login,
    # or (allow_without_gateway) the app's own login only. Only for apps
    # without SSO: an SSO app must never get a way around the gateway.
    nl = auth.get("native_login")
    if nl is not None:
        if auth.get("method") != "custom":
            r.error(t.m_where, f"auth.native_login is only allowed with auth.method custom (got {auth.get('method')!r})",
                    "SSO / gateway methods already sign users in through Portcullis; native_login is for apps with nothing but their own login")
        if auth.get("sso") is not False:
            r.error(t.m_where, "auth.native_login requires auth.sso: false",
                    "an app with SSO must not offer its own login without Portcullis")
    if auth.get("method") == "custom" and auth.get("group_access") and not (isinstance(nl, dict) and nl.get("supported") is True):
        r.error(t.m_where, "auth.method custom with group_access: true needs auth.native_login.supported: true",
                "group-gate only runs when the Hub puts Portcullis sign-in in front of the app (native_login)")

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

    # Volumes. single: explicit name portcullis_<key>. multi: no name; the
    # Hub's override sets portcullis_<key> for the default instance (today's
    # names) and portcullis_<instance-id>-<key> for the others (§11.2).
    top_vols = data.get("volumes") or {}
    for vname, spec in top_vols.items():
        if isinstance(spec, dict) and spec.get("external"):
            r.error(t.c_where, f"volumes.{vname}: external volumes are not allowed in templates")
        vol_name = spec.get("name") if isinstance(spec, dict) else None
        if t.multi:
            if vol_name is not None:
                r.error(t.c_where, f"volumes.{vname}: an instances: multi template must not declare name:",
                        f"the Hub names it portcullis_{vname} for the default instance and "
                        f"portcullis_<instance-id>-{vname} for the others; " + V2_HINT)
            t.volume_names[f"portcullis_{vname}"] = vname
            continue
        if not vol_name:
            r.error(t.c_where, f"volumes.{vname} needs an explicit 'name: portcullis_{vname}'",
                    "without it the name depends on the compose project and data is lost on rename")
            continue
        if str(vol_name) != f"portcullis_{vname}":
            r.error(t.c_where, f"volumes.{vname}: name {vol_name!r} must be exactly 'portcullis_{vname}'",
                    "the default instance's volumes are portcullis_<volume key> (contracts §11.2)")
        t.volume_names[str(vol_name)] = vname

    if t.multi:
        for sname, svc in services.items():
            if isinstance(svc, dict) and svc.get("privileged"):
                r.error(f"{t.c_where}: services.{sname}", "privileged: true can't be per instance (every instance gets the whole host)",
                        "pass only the devices the instance needs (devices:, from per-instance settings) with the capabilities they need; "
                        "see scrutiny/")
        for p in m.get("ports") or []:
            if isinstance(p, dict) and p.get("network_mode_host") and isinstance(p.get("key"), str) \
                    and not any(n == p["key"] for n, _, _ in iter_var_refs(t.compose_values)):
                r.error(t.c_where, f"host-network port {p['key']} is not used in compose.yml",
                        "with network_mode: host the app binds the port itself; read the per-instance value, e.g. "
                        f"--listen=${{{p['key']}:-{p.get('default') or p.get('range')}}}, so each instance can use its own")

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
        if is_instance_var(name):
            continue  # check_instance_vars
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
        check_traefik_names(t, labels, where, r)
        if not enabled and any(k.startswith("traefik.http.") for k in labels):
            r.error(where, "has traefik.http.* labels but not traefik.enable: \"true\"")

    check_routers(t, routers, r)
    check_immutable_hosts(t, r)
    check_instance_vars(t, r)
    check_own_hosts(t, services, r)
    check_public_access(t, services, routers, r)
    check_identity(t, services, r)
    check_signin_test(t, r)
    check_hub_rules(t, r)


_NAME_LABEL_RE = re.compile(r"^traefik\.(?:http|tcp|udp)\.(routers|services|middlewares)\.([^.]+)\.")


def check_traefik_names(t: Template, labels: Dict[str, str], where: str, r: Report) -> None:
    """Contract v2: the Hub renames <name> to <instance-id>_<name> per instance."""
    seen: Set[Tuple[str, str]] = set()
    for k in labels:
        mm = _NAME_LABEL_RE.match(k)
        if not mm or (mm.group(1), mm.group(2)) in seen:
            continue
        seen.add((mm.group(1), mm.group(2)))
        kind, name = mm.group(1)[:-1], mm.group(2)
        if "_" in name:
            r.error(where, f"{kind} name {name} contains '_'",
                    "use '-': the Hub prefixes names with <instance-id>_ for every instance but the default; " + V2_HINT)
        if t.multi and name.startswith("portcullis-") and not name.startswith(PUBLIC_RESERVED):
            r.error(where, f"{kind} name {name} starts with 'portcullis-'", "that prefix is reserved for core and the Hub")


def check_immutable_hosts(t: Template, r: Report) -> None:
    """hosts.immutable names host routers; required where IMMUTABLE_HOSTS says so."""
    hosts = (t.manifest or {}).get("hosts")
    listed = hosts.get("immutable") if isinstance(hosts, dict) else None
    listed = [x for x in listed if isinstance(x, str)] if isinstance(listed, list) else []
    routers = {"PORTCULLIS_HOST_" + var_key(n): n for n in listed}
    for var, name in sorted(routers.items()):
        if var not in t.host_vars:
            r.error(t.m_where, f"hosts.immutable: {name} is not a host router of this template",
                    "list the name of a router whose rule is Host() alone; host routers: "
                    + (", ".join(sorted(v[len("PORTCULLIS_HOST_"):].lower().replace("_", "-") for v in t.host_vars)) or "none"))
    for name, why in sorted(IMMUTABLE_HOSTS.get(t.id, {}).items()):
        if name not in listed:
            r.error(t.m_where, f"hosts.immutable must list {name}",
                    f"{why}: the Hub must refuse to change that hostname once the instance exists")


def check_instance_vars(t: Template, r: Report) -> None:
    """Instance variables: default form, the default instance's value, the same default everywhere."""
    m = t.manifest or {}
    auth = m.get("auth") or {}
    expected: Dict[str, str] = {"PORTCULLIS_INSTANCE": t.id}
    clients = [c.get("client_id") for c in m.get("keycloak_clients") or []
               if isinstance(c, dict) and isinstance(c.get("client_id"), str)]
    if clients:
        expected["PORTCULLIS_OIDC_CLIENT_ID"] = clients[0]
    for cid in clients:
        key = "PORTCULLIS_OIDC_CLIENT_ID_" + var_key(cid)
        if key in expected:
            r.error(t.m_where, f"keycloak clients {expected[key]} and {cid} both map to {key}", V2_HINT)
        expected[key] = cid
    for field, var in (("access_group", "PORTCULLIS_ACCESS_GROUP"), ("admin_group", "PORTCULLIS_ADMIN_GROUP")):
        if isinstance(auth.get(field), str) and auth[field]:
            expected[var] = auth[field]
    for var, sub in t.host_vars.items():
        expected[var] = f"{sub}.portcullis.local"
    reported: Set[Tuple[str, str]] = set()
    # Support files see instance variables only through a service's
    # environment: (the Hub writes them into the instance's .env, which
    # compose reads; nothing expands them inside a file).
    passed: Set[str] = set()
    for svc in ((t.compose or {}).get("services") or {}).values():
        if isinstance(svc, dict):
            passed.update(env_of(svc))
    for where, text in _template_texts(t)[1:]:
        for name in sorted(set(INSTANCE_VAR_TEXT_RE.findall(text))):
            if name not in expected:
                r.error(where, f"${{{name}}} is not set for this template",
                        "PORTCULLIS_HOST_<ROUTER> needs a host router <router>, PORTCULLIS_OIDC_CLIENT_ID* a keycloak_clients entry, "
                        "PORTCULLIS_ACCESS_GROUP / PORTCULLIS_ADMIN_GROUP auth.access_group / admin_group")
            elif name not in passed:
                r.error(where, f"uses {name}, which no service gets through environment:",
                        f"pass it in compose.yml, e.g. environment: {{{name}: ${{{name}:-{expected[name]}}}}} "
                        "(or under the app's own name), and substitute it when the file is rendered")
    for where, text in [(t.c_where, t.compose_values)]:
        for name, op, rest in iter_var_refs(text):
            if not is_instance_var(name):
                continue
            want = expected.get(name)
            if want is None:
                msg = (f"${{{name}}} is not set for this template",
                       "PORTCULLIS_HOST_<ROUTER> needs a host router <router>, PORTCULLIS_OIDC_CLIENT_ID* a keycloak_clients entry, "
                       "PORTCULLIS_ACCESS_GROUP / PORTCULLIS_ADMIN_GROUP auth.access_group / admin_group")
            elif op != ":-":
                msg = (f"${{{name}}} must use the default form ${{{name}:-{want}}}",
                       "instance variables carry the default instance's value as their default; " + V2_HINT)
            elif rest != want:
                msg = (f"${{{name}}} default must be {want} (got {rest!r})",
                       "the default is the default instance's value, the same at every use; " + V2_HINT)
            else:
                continue
            if (name, msg[0]) not in reported:
                reported.add((name, msg[0]))
                r.error(where, *msg)


INSTANCE_VAR_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9_])(PORTCULLIS_(?:INSTANCE|HOST_[A-Z0-9_]+|OIDC_CLIENT_ID(?:_[A-Z0-9_]+)?|ACCESS_GROUP|ADMIN_GROUP))(?![A-Za-z0-9_])")
_HOST_VAR_REF_RE = re.compile(r"\$\{PORTCULLIS_HOST_[A-Z0-9_]+:-[^}]*\}")
_OWN_HOST_SUFFIX = r"\.(?:\$+\{?PORTCULLIS_DOMAIN\b|PORTCULLIS_DOMAIN_PLACEHOLDER)"


def check_own_hosts(t: Template, services: Dict[str, Any], r: Report) -> None:
    """Contract v2: own hostnames only as PORTCULLIS_HOST_<ROUTER> / {{HOST_<ROUTER>}}."""
    m = t.manifest or {}
    uris: List[str] = [u["url"] for u in m.get("urls") or [] if isinstance(u, dict) and isinstance(u.get("url"), str)]
    for c in m.get("keycloak_clients") or []:
        if isinstance(c, dict):
            uris += [x for x in as_list(c.get("redirect_uri")) + as_list(c.get("redirect_uris")) if isinstance(x, str)]
    placeholders = {"HOST_" + k[len("PORTCULLIS_HOST_"):] for k in t.host_vars}
    for u in uris:
        for p in HOST_PLACEHOLDER_RE.findall(u):
            if "HOST_" + p not in placeholders:
                r.error(t.m_where, f"{u}: {{{{HOST_{p}}}}} names no host router",
                        f"host routers of this template: {', '.join(sorted(placeholders)) or 'none'}")
    if t.form != "v2":
        return
    by_sub = {sub: var for var, sub in t.host_vars.items()}
    for u in uris:
        for sub in re.findall(r"(?<![A-Za-z0-9.-])([a-z0-9-]+)\.\{\{DOMAIN\}\}", u):
            if sub in by_sub:
                r.error(t.m_where, f"{u}: use {{{{HOST_{by_sub[sub][len('PORTCULLIS_HOST_'):]}}}}} for its own host",
                        "{{DOMAIN}} is the main domain; the instance's hostname can be anywhere; " + V2_HINT)
    for where, text in _template_texts(t):
        literal = _HOST_VAR_REF_RE.sub("", text)
        for sub, var in sorted(by_sub.items()):
            if re.search(rf"(?<![A-Za-z0-9.-]){re.escape(sub)}{_OWN_HOST_SUFFIX}", text):
                r.error(where, f"names its own host {sub}.${{PORTCULLIS_DOMAIN}}",
                        f"use ${{{var}:-{sub}.portcullis.local}} (env URLs, hostname:, middleware values); " + V2_HINT)
            if re.search(rf"(?<![A-Za-z0-9.-]){re.escape(sub)}\.portcullis\.local(?![A-Za-z0-9-])", literal):
                r.error(where, f"names its own host {sub}.portcullis.local literally",
                        f"use ${{{var}:-{sub}.portcullis.local}}: the instance's hostname is whatever the admin chose; " + V2_HINT)
    if not t.multi:
        return
    auth = m.get("auth") or {}
    groups = [g for g in (auth.get("access_group"), auth.get("admin_group")) if isinstance(g, str) and g]
    clients = [c.get("client_id") for c in m.get("keycloak_clients") or []
               if isinstance(c, dict) and isinstance(c.get("client_id"), str)]
    hint = "use ${PORTCULLIS_OIDC_CLIENT_ID*}, ${PORTCULLIS_ACCESS_GROUP} or ${PORTCULLIS_ADMIN_GROUP}: every other instance has its own; " + V2_HINT
    for where, text in _template_texts(t):
        for g in groups:
            if re.search(rf"(?<![\w.-]){re.escape(g)}(?![\w.-])", text):
                r.error(where, f"hard-codes group {g}", hint)
        for cid in clients:
            if re.search(rf"(?i)(?:client[_-]?id|identifier|audience)['\"]?\s*(?:=>|[:=])\s*['\"]?{re.escape(cid)}(?![\w.-])", text):
                r.error(where, f"hard-codes Keycloak client id {cid}", hint)
    for sname, svc in services.items():
        if not isinstance(svc, dict):
            continue
        for k, val in env_of(svc).items():
            if re.search(r"(?i)client_?id|audience|identifier", k) and val.strip().strip("'\"") in clients:
                r.error(f"{t.c_where}: services.{sname}", f"{k} hard-codes Keycloak client id {val}", hint)


def env_of(svc: Dict[str, Any]) -> Dict[str, str]:
    raw = svc.get("environment") or {}
    if isinstance(raw, dict):
        return {str(k): "" if v is None else str(v) for k, v in raw.items()}
    out: Dict[str, str] = {}
    for item in raw:
        k, _, v = str(item).partition("=")
        out[k] = v
    return out


def _template_texts(t: Template) -> List[Tuple[str, str]]:
    """(where, text) for compose scalars and the template's support files."""
    out = [(t.c_where, t.compose_values)]
    for dirpath, _, files in os.walk(t.dir):
        for fn in sorted(files):
            if fn in ("compose.yml", "manifest.yaml"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8") as f:
                    out.append((f"{t.id}/{os.path.relpath(path, t.dir)}", f.read()))
            except (UnicodeDecodeError, OSError):
                continue
    return out


def check_identity(t: Template, services: Dict[str, Any], r: Report) -> None:
    for sname, svc in services.items():
        if not isinstance(svc, dict):
            continue
        where = f"{t.c_where}: services.{sname}"
        env = env_of(svc)
        for kre, vre, msg in IDENTITY_ENV_FORBIDDEN:
            for k, v in env.items():
                if re.match(kre, k) and re.search(vre, v):
                    r.error(where, f"{k}={v}: {msg}", EMAIL_HINT)
        for on_key, on_re, req_key, req_re, msg in IDENTITY_ENV_REQUIRED:
            if on_key in env and re.search(on_re, env[on_key]):
                if not re.search(req_re, env.get(req_key, "")):
                    r.error(where, msg, EMAIL_HINT)
        image = str(svc.get("image", ""))
        for prefix, job, msg in REQUIRED_INIT_JOBS:
            if image.startswith(prefix) and job not in services:
                r.error(where, msg, EMAIL_HINT)
    for where, text in _template_texts(t):
        for rx, msg in IDENTITY_TEXT_FORBIDDEN:
            if re.search(rx, text):
                r.error(where, msg, EMAIL_HINT)
    # email_verified_claim: false swaps the client's email scope for
    # email-unverified; Keycloak answers invalid_scope to a request for a
    # scope the client doesn't have, so the app must not ask for "email".
    no_ev = [c.get("client_id") for c in (t.manifest or {}).get("keycloak_clients") or []
             if isinstance(c, dict) and c.get("email_verified_claim") is False]
    if no_ev:
        for sname, svc in services.items():
            if not isinstance(svc, dict):
                continue
            for k, v in env_of(svc).items():
                if "SCOPE" in k.upper() and re.search(r"(?<![\w-])email(?![\w-])", v):
                    r.error(f"{t.c_where}: services.{sname}", f"{k}={v} requests the email scope, but client(s) "
                            f"{', '.join(map(str, no_ev))} set email_verified_claim: false (no email scope)",
                            "drop email from the requested scopes; the email-unverified default scope still sends the email claim")
    if "omniauth_providers" in t.compose_values and \
            not re.search(r"omniauth_auto_link_user'\]\s*=\s*false", t.compose_values):
        r.error(t.c_where, "GitLab OIDC needs gitlab_rails['omniauth_auto_link_user'] = false", EMAIL_HINT)


# ── tests.signin (sign-in e2e, tests/e2e/app_signin.py) ─────────────
SIGNIN_HINT = "see CONTRIBUTING.md, \"Sign-in test\""
# Methods without a Portcullis user sign-in the e2e could drive: these
# declare why in tests.signin.skip.
SIGNIN_SKIP_METHODS = {"public", "custom", "mtls"}
# Gated methods: group-gate refuses outsiders, never an expected failure.
SIGNIN_GATED_METHODS = {"forward-auth", "header-auth"}


def check_signin_test(t: Template, r: Report) -> None:
    m = t.manifest or {}
    auth = m.get("auth") or {}
    method = auth.get("method")
    si = (m.get("tests") or {}).get("signin")
    if not isinstance(si, dict):
        r.error(t.m_where, "no tests.signin block",
                "every template declares how CI signs a user in (path + signed_in), or tests.signin.skip with the "
                f"reason for public / custom / mtls apps; {SIGNIN_HINT}")
        return
    if si.get("skip"):
        if method not in SIGNIN_SKIP_METHODS:
            r.error(t.m_where, f"tests.signin.skip is only for auth.method {', '.join(sorted(SIGNIN_SKIP_METHODS))} "
                    f"(got {method!r})",
                    "apps signed in through Portcullis get a real sign-in test; mark a known failure with "
                    f"tests.signin.expected_fail.<check> instead; {SIGNIN_HINT}")
        return
    if method == "public":
        r.error(t.m_where, "auth.method public has no sign-in: set tests.signin.skip with the reason", SIGNIN_HINT)
    xfail = si.get("expected_fail") or {}
    if auth.get("group_admin") and not si.get("admin"):
        r.error(t.m_where, "auth.group_admin is true but tests.signin has no admin check",
                f"add tests.signin.admin: how to recognise the admin rights admin_group grants; {SIGNIN_HINT}")
    # A native-oidc app that can't restrict sign-in by group itself relies on
    # the Hub's Keycloak access role (keycloak_access_role; the Hub applies it
    # to group_access: false too). CI has no Hub (app_signin.py registers
    # plain clients), so those may mark expected_fail.outsider (a marker that
    # starts passing fails the run).
    open_oidc = method == "native-oidc" and (auth.get("group_access") is False
                                             or auth.get("keycloak_access_role") is True)
    if method in SIGNIN_GATED_METHODS and xfail.get("outsider"):
        r.error(t.m_where, f"tests.signin.expected_fail.outsider on a {method} app",
                "group-gate refuses users outside access_group; fix the gate instead of marking it")
    if xfail.get("outsider") and not open_oidc and method not in SIGNIN_GATED_METHODS:
        r.warn(t.m_where, "tests.signin.expected_fail.outsider on an app that restricts sign-in by group",
               "remove it once the outsider check passes")
    for name, xf in xfail.items():
        for key in ("match", "not_match"):
            if isinstance(xf, dict) and isinstance(xf.get(key), str):
                try:
                    re.compile(xf[key])
                except re.error as e:
                    r.error(t.m_where, f"tests.signin.expected_fail.{name}.{key} is not a valid regex: {e}",
                            "searched (case-insensitive) in the check's own evidence, pages and app logs")
    services = (t.compose or {}).get("services") or {}
    for lf in si.get("log_files") or []:
        if isinstance(lf, dict) and lf.get("service") not in services:
            r.error(t.m_where, f"tests.signin.log_files service {lf.get('service')!r} is not a compose service")
    host = si.get("host")
    if isinstance(host, str):
        var = "PORTCULLIS_HOST_" + host[len("{{HOST_"):-2]
        if t.host_vars and var not in t.host_vars:
            r.error(t.m_where, f"tests.signin.host {host} is not a host router of compose.yml",
                    f"use one of {', '.join('{{HOST_' + v[len('PORTCULLIS_HOST_'):] + '}}' for v in sorted(t.host_vars))}")
    env_keys = {e.get("key") for e in m.get("env") or [] if isinstance(e, dict)} | \
               {e.get("key") for e in m.get("settings") or [] if isinstance(e, dict)}
    for st in si.get("setup") or []:
        if isinstance(st, dict) and st.get("save_env") and st["save_env"] not in env_keys:
            r.error(t.m_where, f"tests.signin.setup save_env {st['save_env']} is not a settings/env key",
                    "setup steps only fill values the manifest documents (e.g. a post-start API key setting)")
        if isinstance(st, dict) and "service" in st and st.get("service") not in ((t.compose or {}).get("services") or {}):
            r.error(t.m_where, f"tests.signin.setup service {st.get('service')!r} is not a compose service")
    sig = si.get("signed_in") or {}
    if method in ("header-auth", "native-oidc") and isinstance(sig, dict):
        named = any("{username}" in str(sig.get(k, "")) or "{email}" in str(sig.get(k, "")) for k in ("text", "html")) \
            or "json" in sig or "js" in sig
        if not named:
            r.warn(t.m_where, f"tests.signin.signed_in of a {method} app does not check the username",
                   "prefer text/html with {username}, or json/js (default: equals {username}), so the test proves "
                   "the app got the right identity")


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
        check_default_credentials(image, svc, where, r)

    for vol in as_list(svc.get("volumes")):
        check_mount(t, vol, where, r)

    if (svc.get("network_mode") == "host") and t.manifest:
        if not any(isinstance(p, dict) and p.get("service") == sname and p.get("network_mode_host")
                   for p in t.manifest.get("ports") or []):
            r.warn(where, "uses network_mode: host but the manifest declares no ports with network_mode_host: true",
                   "declare its ports so the Hub can detect collisions")


# Images that ship a well-known default admin login unless told otherwise.
# Behind header auth a password login is never needed, so it must be off and
# the built-in account must get a generated password (no `admin:admin` for
# whatever else sits on portcullis-proxy).
DEFAULT_CREDENTIAL_RULES = {
    "grafana/grafana": [
        ("GF_AUTH_BASIC_ENABLED", lambda v: str(v).lower() == "false", 'must be "false" (no password logins)'),
        ("GF_SECURITY_ADMIN_PASSWORD", lambda v: isinstance(v, str) and ":?" in v, "must come from a generated secret (${VAR:?...}), not Grafana's default admin password"),
    ],
}


def check_default_credentials(image: str, svc: Dict[str, Any], where: str, r: Report) -> None:
    repo = image.split("@", 1)[0].rsplit(":", 1)[0]
    rules = DEFAULT_CREDENTIAL_RULES.get(repo)
    if not rules:
        return
    env = svc.get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) if "=" in e else (e, None) for e in env)
    for key, ok, why in rules:
        file_key = key + "__FILE"
        if key in env and ok(env[key]):
            continue
        if key.endswith("PASSWORD") and file_key in env:
            continue
        r.error(where, f"{key} {why}")


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
        if t.multi and not read_only:
            r.error(where, f"bind mount {src!r} is shared by every instance and must be read-only (:ro)",
                    "copy it into a volume in an init container if the app writes to it")
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

    check_rule_forms(t, routers, r)
    for name, rt in sorted(routers.items()):
        where = f"{t.c_where}: router {name}"
        rule = rt.get("rule", "")
        if not rule:
            continue
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
            if has_auth and host_wide and name not in GATED_CLIENT_ROUTERS.get(t.id, set()):
                r.error(where, f"native-oidc router must not use {AUTH_MW} on the whole host",
                        "the app's own OIDC login, API and mobile clients break behind forward-auth; "
                        "gate only specific paths (PathPrefix) such as an admin panel or the login pages")
        elif method in ("public", "custom", "mtls"):
            if has_auth or has_groups:
                hint = ("the Hub adds them for Portcullis sign-in (auth.native_login) through its override; "
                        "the template keeps the app's own chain") if method == "custom" else ""
                r.error(where, f"auth.method {method} must not use {AUTH_MW}/{GROUPS_MW} (use forward-auth/header-auth instead)", hint)

        if has_auth and has_groups:
            gated.append((name, ["/"] if host_wide else paths))

    if any(True for _ in gated) and not auth.get("group_access") and not admin_paths:
        r.warn(t.m_where, "routers use group-gate but group_access is false: only authentication is enforced",
               "set group_access: true and access_group, or declare admin_paths")

    for ap in admin_paths:
        if not any(any(prefix_covers(p, ap) for p in ps) for _, ps in gated):
            r.error(t.m_where, f"auth.admin_paths {ap}: no router with {AUTH_MW},{GROUPS_MW} serves this path",
                    "group-gate only sees requests on routers that use portcullis-groups@docker; add a PathPrefix router for it")

    for gr in sorted(GATED_CLIENT_ROUTERS.get(t.id, set())):
        if not any(n == gr and ps == ["/"] for n, ps in gated):
            r.error(t.c_where, f"security regression: router {gr} must be a host router with {AUTH_MW},{GROUPS_MW}",
                    "the static web client on its own host is gated as a whole; see the auth notes in manifest.yaml")

    for p in LOGIN_GATES.get(t.id, []):
        if not any(any(prefix_covers(q, p) for q in ps) for _, ps in gated):
            r.error(t.c_where, f"security regression: {p} must be served by a router with {AUTH_MW},{GROUPS_MW}",
                    "without it any Keycloak realm user can sign in; see the auth notes in manifest.yaml")
    if t.id in LOGIN_GATES and not auth.get("group_access"):
        r.error(t.m_where, "security regression: login is gated by group-gate, so group_access must be true")


def check_rule_forms(t: Template, routers: Dict[str, Dict[str, str]], r: Report) -> None:
    """Contract v2 rule form, host routers and hostname variables (§3.1)."""
    parsed: Dict[str, Tuple[str, Optional[str], str, Optional[str]]] = {}
    for name, rt in sorted(routers.items()):
        where = f"{t.c_where}: router {name}"
        rule = rt.get("rule", "")
        if not rule:
            r.error(where, "has no rule")
            continue
        p = parse_rule(rule)
        if p is None or not LABEL_RE.match(p[2]) or (p[3] is not None and not PATH_PART_RE.match(p[3].strip())):
            r.error(where, "rule must be Host(`${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}`), "
                    "optionally followed by && PathPrefix(`...`) / Path(`...`) or a parenthesised || of them",
                    "<sub> is one DNS label (the default subdomain); <ROUTER> is the host router's name upper-cased "
                    "with - and . as _; " + V2_HINT)
            continue
        parsed[name] = p
        if p[2] in CORE_SUBDOMAINS:
            r.error(where, f"subdomain {p[2]!r} belongs to core")
        if p[0] == "v1" and t.multi:
            r.error(t.c_where, f"instances: multi template uses ${{PORTCULLIS_DOMAIN}} in router {name}",
                    "use Host(`${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}`); " + V2_HINT)
        t.subdomains.add(p[2])
        if t.multi and p[3]:
            for kind, v in re.findall(r"(PathPrefix|Path)\(`([^`]*)`\)", p[3]):
                if v != "/" and rule_path_overlaps(kind, v, "/oauth2"):
                    r.error(where, f"serves {v}; /oauth2/ belongs to Portcullis on extra-domain hosts",
                            "the Hub routes /oauth2/ to the sign-in proxy there; " + V2_HINT)
    forms = {p[0] for p in parsed.values()}
    if len(forms) > 1:
        r.error(t.c_where, "mixes the PORTCULLIS_HOST_<ROUTER> and ${PORTCULLIS_DOMAIN} rule forms",
                "a template uses one rule form for all its routers; " + V2_HINT)
    t.form = forms.pop() if len(forms) == 1 else None
    # Host routers (Host() alone): one per hostname, one variable each.
    host_by_sub: Dict[str, str] = {}
    var_owner: Dict[str, str] = {}
    for name, (form, var, sub, path) in sorted(parsed.items()):
        if path is not None:
            continue
        where = f"{t.c_where}: router {name}"
        if sub in host_by_sub:
            r.error(where, f"hostname {sub} has more than one host router ({host_by_sub[sub]}, {name})",
                    "each hostname has exactly one router with Host() alone; the others add path matchers")
            continue
        host_by_sub[sub] = name
        want = "PORTCULLIS_HOST_" + var_key(name)
        if form == "v2" and var != want:
            r.error(where, f"host router {name} must use {want} (got {var})", V2_HINT)
            continue
        if want in var_owner:
            r.error(where, f"host routers {var_owner[want]} and {name} map to the same variable {want}",
                    "rename one of them; " + V2_HINT)
            continue
        var_owner[want] = name
        t.host_vars[want] = sub
    for name, (form, var, sub, path) in sorted(parsed.items()):
        if path is None:
            continue
        where = f"{t.c_where}: router {name}"
        if form == "v1":
            if sub not in host_by_sub:
                r.error(where, f"hostname {sub} has no host router (a router with Host() alone)", V2_HINT)
            continue
        if var not in t.host_vars:
            r.error(where, f"no host router uses {var}",
                    "path-scoped routers reuse their hostname's host router variable; " + V2_HINT)
        elif t.host_vars[var] != sub:
            r.error(where, f"{var} default must be {t.host_vars[var]}.portcullis.local (got {sub}.portcullis.local)",
                    "each variable has the same default everywhere it appears")


def check_public_access(t: Template, services: Dict[str, Any], routers: Dict[str, Dict[str, str]], r: Report) -> None:
    for sname, svc in services.items():
        for k in labels_of(svc if isinstance(svc, dict) else {}):
            mm = re.match(r"^traefik\.(?:http|tcp)\.(routers|middlewares)\.([^.]+)\.", k)
            if mm and mm.group(2).startswith(PUBLIC_RESERVED):
                r.error(f"{t.c_where}: services.{sname}", f"{mm.group(1)[:-1]} name {mm.group(2)} uses the prefix {PUBLIC_RESERVED}",
                        "that prefix is reserved for the router the Hub generates from auth.public_access")
    auth = (t.manifest or {}).get("auth") or {}
    pa = auth.get("public_access")
    if not isinstance(pa, dict):
        return
    w = t.m_where
    if auth.get("method") not in PUBLIC_METHODS:
        r.error(w, f"auth.public_access needs auth.method forward-auth, header-auth or native-oidc (got {auth.get('method')!r})",
                "mtls apps have no auth besides the TLS handshake; public/custom apps have no gate to skip")
        return
    if auth.get("method") == "header-auth":
        hdrs = [h for h in (auth.get("identity_headers") or []) if isinstance(h, str)]
        if not hdrs:
            r.error(w, "header-auth app with auth.public_access needs auth.identity_headers",
                    "list the headers the app trusts (e.g. X-Forwarded-User); the Hub strips them on public paths")
        envtext = t.compose_values
        for h in sorted({m.group(0) for m in re.finditer(r"\b(?:X|Remote)-[A-Za-z0-9-]+", envtext)}):
            if re.search(r"(?i)user|email|login|name|group", h) and h.lower() not in {x.lower() for x in hdrs} \
                    and not h.lower().startswith(("x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip")):
                r.error(w, f"compose.yml mentions identity-like header {h} that auth.identity_headers does not list",
                        "every header the app may read the user from must be stripped on the public router")
    paths = [p for p in (pa.get("paths") or []) if isinstance(p, dict) and isinstance(p.get("prefix"), str)]
    seen: Set[str] = set()
    norm_paths: List[Tuple[str, Dict[str, Any]]] = []
    for p in paths:
        raw = p["prefix"]
        where = f"{w}: auth.public_access {raw}"
        if raw.count(PUBLIC_TOKEN) > 1:
            r.error(where, f"more than one {PUBLIC_TOKEN}", PUBLIC_HINT)
            continue
        check = raw.replace(PUBLIC_TOKEN, "x")
        if raw.count(PUBLIC_TOKEN) == 1 and PUBLIC_TOKEN not in raw.rstrip("/").split("/"):
            r.error(where, f"{PUBLIC_TOKEN} must be a whole path segment", PUBLIC_HINT)
            continue
        if not PUBLIC_SEG_RE.match(check) or ".." in check or "." in check.split("/"):
            r.error(where, "prefix must be /segment[/segment...] of letters, digits and . _ ~ - (no /, //, .., wildcards, %, ?, #)",
                    PUBLIC_HINT)
            continue
        norm = raw.rstrip("/")
        if norm in seen:
            r.error(where, "duplicate prefix")
        seen.add(norm)
        norm_paths.append((norm, p))
        tokenised = PUBLIC_TOKEN in norm
        if tokenised and p.get("supporting"):
            r.error(where, f"a {PUBLIC_TOKEN} path cannot be supporting (supporting paths are token-free and always open)")
        if p.get("exact"):
            if tokenised:
                r.error(where, f"a {PUBLIC_TOKEN} path cannot be exact")
            if not str(p.get("justification") or "").strip():
                r.error(where, "exact path needs a justification (which app route, why the share page needs it)")
        elif p.get("supporting") and re.search(r"\.[A-Za-z0-9]{1,8}$", norm.rsplit("/", 1)[-1]):
            r.error(where, "supporting prefix names a file; supporting prefixes only serve static files below them",
                    "use exact: true (with a justification) for a single file or route")
        base = token_base(norm)
        if base == "/":
            r.error(where, "would open / in mode all", PUBLIC_HINT)
            continue
        for f in PUBLIC_FORBIDDEN:
            if seg_overlap(base.lower(), f):
                r.error(where, f"overlaps {f}, which can never be public")
        broad = base.lower() in PUBLIC_BROAD or (base.count("/") == 1 and base.lower().endswith(".php"))
        # Exact paths too: an exact /index.php is still the whole front
        # controller (PATH_INFO, query routing).
        if broad and not (p.get("broad") and str(p.get("justification") or "").strip()):
            r.error(where, f"{base} is a broad prefix (whole API / front controller)",
                    "narrow it to the share endpoints, or set broad: true with a justification")
        elif p.get("broad") and not broad:
            r.error(where, f"broad: true on {base}, which is not a broad prefix")
        for ap in auth.get("admin_paths") or []:
            if isinstance(ap, str) and seg_overlap(base, ap.rstrip("/") or "/"):
                r.error(where, f"overlaps admin path {ap}")
    if norm_paths and all(p.get("supporting") for _, p in norm_paths):
        r.error(w, "auth.public_access has only supporting paths")
    has_token = any(PUBLIC_TOKEN in n for n, _ in norm_paths)
    if pa.get("default_mode") == "listed" and not has_token:
        r.error(w, f"auth.public_access.default_mode listed needs a path with {PUBLIC_TOKEN}")
    pat = pa.get("token_pattern")
    if has_token:
        if not isinstance(pat, str) or not pat.startswith("^") or not pat.endswith("$") or pat.endswith("\\$"):
            r.error(w, "auth.public_access.token_pattern is required and must be anchored (^...$)", PUBLIC_HINT)
        else:
            try:
                rx = re.compile(pat)
            except re.error as e:
                r.error(w, f"auth.public_access.token_pattern does not compile: {e}")
            else:
                bad = [x for x in PUBLIC_TOKEN_PROBES if rx.match(x) and rx.fullmatch(x)]
                if bad:
                    r.error(w, f"auth.public_access.token_pattern accepts {bad[0]!r}",
                            "tokens may only use letters, digits and . _ ~ - and never be '.' or '..'")
    elif pat:
        r.error(w, f"auth.public_access.token_pattern is set but no path has {PUBLIC_TOKEN}")

    # Routing: the service the Hub puts the public router on, and no overlap
    # with the path matchers of the app's other routers on the same hosts.
    by_service: Dict[str, List[str]] = {}
    for name, rt in routers.items():
        by_service.setdefault(rt.get("_service", ""), []).append(name)
    svc = pa.get("service")
    if not svc:
        if len(by_service) != 1:
            r.error(w, f"auth.public_access: {len(by_service)} services have HTTP routers; set auth.public_access.service")
            return
        svc = next(iter(by_service))
    if svc not in by_service:
        r.error(w, f"auth.public_access.service {svc!r} has no HTTP router")
        return
    hosts = {h for n in by_service[svc] for h in rule_hosts(routers[n].get("rule", ""))}
    for name, rt in sorted(routers.items()):
        rule = rt.get("rule", "")
        if not hosts & rule_hosts(rule):
            continue
        opaque = sorted({m for m in re.findall(r"([A-Za-z]+)\(", rule) if m.lower() not in PUBLIC_NARROW_MATCHERS})
        if opaque or "!" in rule:
            r.error(w, f"auth.public_access: router {name} uses {', '.join(opaque) or 'a negation'}; "
                    "the Hub can't tell whether public paths overlap it", "use only Host/Path/PathPrefix (+ Method/Header/Query/ClientIP) on the app's hosts")
            continue
        for kind, v in re.findall(r"(PathPrefix|Path)\(`([^`]*)`\)", rule):
            for norm, _ in norm_paths:
                if rule_path_overlaps(kind, v, token_base(norm)):
                    r.error(w, f"auth.public_access {norm} overlaps router {name} ({kind}(`{v}`))",
                            "public paths may not cover paths another router (login gate, admin router) handles")


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


# ── Hub template rules (mirror of the Hub's templates/coreref.go) ───
# The Hub refuses a template at discovery when any of these fail (contract
# §3, "Core names are off limits"); checking them here keeps a template
# that CI accepts from being skipped by the Hub. Keep in sync with
# portcullis-hub internal/templates/coreref.go.

HUB_HINT = f"the Hub refuses this template (see {DOCS_URL}/integration-contracts/#3-template-contract)"
CORE_SERVICES = {"socket-proxy-traefik", "socket-proxy-hub", "traefik", "postgres", "vault", "lldap", "keycloak",
                 "forward-auth", "forward-auth-ext", "group-gate", "hub", "enroll", "domains", "prometheus",
                 "alertmanager", "blackbox", "textfile-exporter", "grafana"}
CORE_VOLUMES = {"postgres_data", "vault_data", "lldap_data", "hub_data", "traefik_acme", "domains_data",
                "prometheus_data", "alertmanager_data", "grafana_data"}
CORE_NETWORKS = {"portcullis", "portcullis-auth", "portcullis-certs", "portcullis-domains", "domains-egress",
                 "socket-proxy-traefik", "socket-proxy-hub", "monitoring", "alerting"}
RESERVED_REFS = ("forward-auth-ext", "portcullis-auth-ext", "portcullis-oauth2-")
CORE_CONTAINER_RE = re.compile(r"^portcullis[-_](.+)[-_][0-9]+$")
HUB_TOP_KEYS = {"services", "volumes", "networks", "name"}
HUB_SERVICE_KEYS = {
    "image", "volumes", "restart", "environment", "networks", "security_opt", "cap_drop", "cap_add",
    "pids_limit", "mem_limit", "mem_reservation", "memswap_limit", "cpus", "cpu_shares", "labels", "command", "read_only",
    "depends_on", "tmpfs", "entrypoint", "user", "group_add", "healthcheck", "shm_size", "network_mode", "working_dir",
    "hostname", "devices", "container_name", "ports", "expose", "ulimits", "stop_grace_period", "stop_signal", "init",
    "privileged", "sysctls", "logging", "tty", "stdin_open", "dns", "dns_search", "extra_hosts", "platform", "pull_policy",
    "pid", "ipc", "volumes_from", "domainname", "mac_address", "oom_score_adj", "storage_opt", "userns_mode",
    "device_cgroup_rules", "gpus", "runtime", "isolation", "blkio_config", "cgroup", "cgroup_parent", "cpuset"}
CORE_TRAEFIK_NAMES = {
    "routers": {"dashboard", "enroll", "enroll-invite", "enroll-self", "grafana-metrics", "hub", "keycloak",
                "keycloak-admin", "keycloak-resources", "lldap", "oauth2-callback", "people", "portal"},
    "middlewares": {"directory-redirect", "hub-proxy-secret", "portal-path", "portcullis-auth", "portcullis-auth-console",
                    "portcullis-auth-ext", "portcullis-groups", "portcullis-public-guard", "portcullis-self"},
    "services": {"enroll", "forward-auth", "forward-auth-ext", "grafana-metrics", "group-gate", "hub", "hub-people",
                 "keycloak", "lldap"},
}
APP_MIDDLEWARES = {"portcullis-auth", "portcullis-groups"}
FILE_MIDDLEWARES = {"client-headers", "client-cert-pem", "rate-limit", "rate-limit-auth", "security-headers"}
LABEL_SEG_RE = re.compile(r"^[A-Za-z0-9_-]+(\[[0-9]+\])?$")
LABEL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
ROUTER_ATTR_RE = re.compile(r"^(rule|entrypoints|middlewares|service|priority|tls|tls\.options|observability\.(accesslogs|metrics|tracing))$")
SERVICE_ATTR_RE = re.compile(r"^loadbalancer\.(server\.(port|scheme)|passhostheader|responseforwarding\.flushinterval|"
                             r"sticky\.cookie(\.(name|secure|httponly|samesite|maxage|path))?)$")
_SOURCE_CRITERION = r"sourcecriterion\.(requesthost|requestheadername|ipstrategy\.(depth|excludedips|ipv6subnet))"
MIDDLEWARE_ATTR_RE = {
    "addprefix": re.compile(r"^prefix$"),
    "stripprefix": re.compile(r"^(prefixes|forceslash)$"),
    "stripprefixregex": re.compile(r"^regex$"),
    "replacepath": re.compile(r"^path$"),
    "replacepathregex": re.compile(r"^(regex|replacement)$"),
    "redirectregex": re.compile(r"^(regex|replacement|permanent)$"),
    "redirectscheme": re.compile(r"^(scheme|port|permanent)$"),
    "headers": re.compile(r"^[a-z0-9_-]+(\[[0-9]+\])?(\.[a-z0-9_-]+)?$"),
    "compress": re.compile(r"^(|excludedcontenttypes|includedcontenttypes|minresponsebodybytes|encodings|defaultencoding)$"),
    "contenttype": re.compile(r"^(|autodetect)$"),
    "chain": re.compile(r"^middlewares$"),
    "ratelimit": re.compile(rf"^(average|period|burst|{_SOURCE_CRITERION})$"),
    "inflightreq": re.compile(rf"^(amount|{_SOURCE_CRITERION})$"),
    "ipallowlist": re.compile(r"^(sourcerange|rejectstatuscode|ipstrategy\.(depth|excludedips|ipv6subnet))$"),
    "buffering": re.compile(r"^(maxrequestbodybytes|memrequestbodybytes|maxresponsebodybytes|memresponsebodybytes|retryexpression)$"),
    "retry": re.compile(r"^(attempts|initialinterval)$"),
    "circuitbreaker": re.compile(r"^(expression|checkperiod|fallbackduration|recoveryduration|responsecode)$"),
    "grpcweb": re.compile(r"^alloworigins$"),
}
_INTERP_RE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$")
_OWN_HOSTVAR_RE = re.compile(r"\$\{(PORTCULLIS_HOST_[A-Z0-9_]+):-([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.portcullis\.local\}")
_ROUTER_KEY_RE = re.compile(r"^traefik\.(http|tcp|udp)\.routers\.([^.]+)\.(.+)$")
_CHAIN_KEY_RE = re.compile(r"^traefik\.http\.middlewares\.[^.]+\.chain\.middlewares$")


def fold_key(s: str) -> str:
    """Lowercase s the way Traefik compares label segments (EqualFold):
    a character whose case orbit holds an ASCII letter becomes that letter."""
    out = []
    for c in s:
        if c.isascii():
            out.append(c.lower())
            continue
        for alt in (c.lower(), c.upper(), c.casefold()):
            if len(alt) == 1 and alt.isascii() and alt.isalpha():
                out.append(alt.lower())
                break
        else:
            out.append(c)
    return "".join(out)


def _without_interp(s: str) -> str:
    return _INTERP_RE.sub("", s.replace("$$", ""))


def _interpolated(s: str) -> bool:
    return bool(_INTERP_RE.search(s.replace("$$", "")))


def reserved_dns_name(name: str) -> bool:
    n = fold_key(name.strip()).rstrip(".")
    for c in (n, n.split(".", 1)[0]):
        if c in CORE_SERVICES:
            return True
        m = CORE_CONTAINER_RE.match(c)
        if m and m.group(1) in CORE_SERVICES:
            return True
    return False


def _walk_strings(v: Any) -> Iterable[str]:
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield str(k)
            yield from _walk_strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _walk_strings(x)


def check_hub_rules(t: Template, r: Report) -> None:
    """What the Hub's discovery refuses, statically (coreref.go)."""
    data = t.compose or {}
    where = t.c_where
    # A second YAML document (compose merges them) already fails to load
    # (yaml.load expects a single document); explicit tags other than the
    # core !! ones (!reset / !override) fail SafeLoader too.
    for k in data:
        if k not in HUB_TOP_KEYS and not str(k).startswith("x-"):
            r.error(where, f"top-level key {k!r} is not allowed", HUB_HINT)
    for s in _walk_strings(data):
        low, bare = fold_key(s), fold_key(_without_interp(s))
        for ref in RESERVED_REFS:
            if ref in low or ref in bare:
                r.error(where, f"references {ref.rstrip('-')!r}: the extra-domain sign-in is rendered by the Hub only", HUB_HINT)
                break

    def literal(what: str, val: Any) -> bool:
        if isinstance(val, str) and _interpolated(val):
            r.error(where, f"{what} {val!r} must be a literal (no ${{...}} / $VAR; $$ is a literal $)", HUB_HINT)
            return False
        return True

    shared: Set[str] = set()
    for k, n in (data.get("networks") or {}).items():
        n = n if isinstance(n, dict) else {}
        if n.get("name") is not None or n.get("external") not in (None, False):
            shared.add(k)
        names = [n.get("name")]
        ext = n.get("external")
        if isinstance(ext, dict):
            names.append(ext.get("name"))
        for nm in names:
            if nm is None:
                continue
            if literal(f"networks.{k}: name", nm) and str(nm).removeprefix("portcullis_") in CORE_NETWORKS:
                r.error(where, f"networks.{k} joins the core network {nm}", HUB_HINT)
        if ext and not any(names) and str(k).removeprefix("portcullis_") in CORE_NETWORKS:
            r.error(where, f"networks.{k} is a core network (templates join only portcullis-proxy)", HUB_HINT)

    for k, v in (data.get("volumes") or {}).items():
        literal("volume key", k)
        if fold_key(str(k).strip()) in CORE_VOLUMES:
            r.error(where, f"volumes.{k} is core's (portcullis_{k})", HUB_HINT)
        v = v if isinstance(v, dict) else {}
        name = v.get("name")
        ext = v.get("external")
        if isinstance(ext, dict) and ext.get("name"):
            name = ext.get("name")
        if name is not None:
            literal(f"volumes.{k}: name", name)
        eff = fold_key(str(name if name else k).strip())
        if eff.startswith("portcullis_") and eff[len("portcullis_"):] in CORE_VOLUMES:
            r.error(where, f"volumes.{k} is named {eff}, core's volume", HUB_HINT)
        if ext and eff.startswith("portcullis"):
            r.error(where, f"volumes.{k}: external volume {eff} is core's or another instance's data", HUB_HINT)

    services = data.get("services") or {}
    own_services: Set[str] = set()
    own_middlewares: Set[str] = set()
    for svc in services.values():
        for k in labels_of(svc if isinstance(svc, dict) else {}):
            segs = fold_key(k.strip()).split(".", 4)
            if len(segs) == 5 and segs[0] == "traefik" and segs[1] == "http":
                if segs[2] == "services":
                    own_services.add(segs[3])
                elif segs[2] == "middlewares":
                    own_middlewares.add(segs[3])
    # The template's own hostname variables: those its router rules use.
    host_vars = {m for m, _ in _OWN_HOSTVAR_RE.findall(
        " ".join(v for svc in services.values() if isinstance(svc, dict)
                 for k, v in labels_of(svc).items() if k.endswith(".rule")))}

    for sname, svc in services.items():
        sw = f"{where}: services.{sname}"
        if not isinstance(svc, dict):
            continue
        for k in svc:
            if k not in HUB_SERVICE_KEYS:
                r.error(sw, f"compose key {k!r} is not allowed in templates (the Hub can't check what it does)", HUB_HINT)
        if reserved_dns_name(str(sname)):
            r.error(sw, f"the DNS name {sname!r} is core's (reserved)", HUB_HINT)
        for field in ("container_name", "hostname", "network_mode", "pid", "ipc"):
            val = svc.get(field)
            if not isinstance(val, str):
                continue
            if field == "hostname" and _interpolated(val):
                m = _OWN_HOSTVAR_RE.fullmatch(val.strip())
                if not m or m.group(1) not in host_vars or reserved_dns_name(m.group(2) + ".portcullis.local"):
                    r.error(sw, f"hostname {val!r}: only the template's own ${{PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}} may be interpolated", HUB_HINT)
            else:
                literal(field, val)
            if field in ("container_name", "hostname") and reserved_dns_name(val):
                r.error(sw, f"{field}: the DNS name {val!r} is core's (reserved)", HUB_HINT)
            if field in ("network_mode", "pid", "ipc") and val.strip().lower().startswith("container:"):
                r.error(sw, f"{field} {val} joins another container's namespace", HUB_HINT)
        for x in as_list(svc.get("volumes_from")):
            if literal("volumes_from", x) and str(x).strip().lower().startswith("container:"):
                r.error(sw, f"volumes_from {x} mounts another container's volumes", HUB_HINT)
        nets = svc.get("networks")
        for net in (nets if isinstance(nets, (list, dict)) else []):
            literal("network", net)
        if isinstance(nets, dict):
            for net, cfg in nets.items():
                cfg = cfg if isinstance(cfg, dict) else {}
                if net in shared:
                    for f in ("ipv4_address", "ipv6_address", "link_local_ips"):
                        if f in cfg:
                            r.error(sw, f"networks.{net}: {f} is not allowed on a network shared with core", HUB_HINT)
                for a in as_list(cfg.get("aliases")):
                    if literal(f"networks.{net}: alias", a) and reserved_dns_name(str(a)):
                        r.error(sw, f"network alias {a!r} is core's DNS name (reserved)", HUB_HINT)
        for k, v in labels_of(svc).items():
            check_hub_label(sw, k, v, host_vars, own_services, own_middlewares, r)


def check_hub_label(where: str, k: str, v: str, host_vars: Set[str], own_services: Set[str],
                    own_middlewares: Set[str], r: Report) -> None:
    if not k.isascii():
        r.error(where, f"label key {k!r} has non-ASCII characters (Traefik's decoder case-folds them)", HUB_HINT)
        return
    if _interpolated(k):
        r.error(where, f"label key {k!r} must be a literal", HUB_HINT)
        return
    lk = k.strip().lower()
    if not lk.startswith("traefik"):
        return
    fk = fold_key(k)
    if fk not in ("traefik.enable", "traefik.docker.network"):
        bad = [s for s in k.split(".") if not LABEL_SEG_RE.match(s)]
        if bad:
            r.error(where, f"Traefik label {k!r}: segment {bad[0]!r} is not [A-Za-z0-9_-] (+[n]); it could crash Traefik's label decoder", HUB_HINT)
            return
        segs = fk.split(".", 4)
        if len(segs) < 5 or segs[0] != "traefik":
            r.error(where, f"Traefik label {k!r} has an unsupported shape", HUB_HINT)
            return
        if segs[1] != "http" or segs[2] not in ("routers", "services", "middlewares"):
            r.error(where, f"Traefik label {k!r}: only traefik.http.<routers|services|middlewares> (no TCP/UDP, no serverstransports)", HUB_HINT)
            return
        if not LABEL_NAME_RE.match(segs[3]):
            r.error(where, f"Traefik label {k!r}: name {segs[3]!r} must match {LABEL_NAME_RE.pattern}", HUB_HINT)
        if segs[3] in CORE_TRAEFIK_NAMES[segs[2]]:
            r.error(where, f"Traefik label {k!r}: {segs[2][:-1]} {segs[3]!r} is core's (reserved)", HUB_HINT)
        attr = segs[4]
        if segs[2] == "routers" and not ROUTER_ATTR_RE.match(attr):
            r.error(where, f"Traefik label {k!r}: unsupported router attribute {attr!r}", HUB_HINT)
        elif segs[2] == "services" and not SERVICE_ATTR_RE.match(attr):
            r.error(where, f"Traefik label {k!r}: unsupported service attribute {attr!r} (a service balances over its own container)", HUB_HINT)
        elif segs[2] == "middlewares":
            typ, _, rest = attr.partition(".")
            rx = MIDDLEWARE_ATTR_RE.get(typ)
            if rx is None:
                r.error(where, f"Traefik label {k!r}: middleware type {typ!r} is not allowed in templates", HUB_HINT)
            elif not rx.match(rest):
                r.error(where, f"Traefik label {k!r}: unsupported {typ} attribute {rest!r}", HUB_HINT)
        structural = ".".join(k.split(".", 4)[:4])
        if k != k.strip() or structural != structural.lower() or (segs[2] == "routers" and k != lk):
            r.error(where, f"Traefik label key {k!r} must be lowercase (router keys entirely, others up to the name)", HUB_HINT)
    m = _ROUTER_KEY_RE.match(fk)
    is_ref = (m is not None and m.group(3) in ("service", "middlewares")) or bool(_CHAIN_KEY_RE.match(fk))
    if is_ref:
        if v != v.lower() or not v.isascii():
            r.error(where, f"label {k}: {v!r} must be lowercase (references are renamed per instance)", HUB_HINT)
        if m is not None and m.group(3) == "service":
            base, _, prov = v.strip().partition("@")
            if (prov not in ("", "docker")) or base not in own_services or base in CORE_TRAEFIK_NAMES["services"]:
                r.error(where, f"label {k}: router service {v!r} is not one this template defines", HUB_HINT)
        else:
            for mw in v.split(","):
                base, _, prov = mw.strip().partition("@")
                if not base and not prov:
                    continue
                ok = (prov == "file" and base in FILE_MIDDLEWARES) or (prov in ("", "docker") and (
                    base in APP_MIDDLEWARES or (base in own_middlewares and base not in CORE_TRAEFIK_NAMES["middlewares"])))
                if not ok:
                    r.error(where, f"label {k}: middleware {mw.strip()!r} is not allowed (own middlewares, "
                                   f"portcullis-auth@docker, portcullis-groups@docker, core's @file "
                                   f"{', '.join(sorted(FILE_MIDDLEWARES))})", HUB_HINT)
    if m is not None and m.group(1) == "http" and m.group(3) == "rule":
        return
    rest = _OWN_HOSTVAR_RE.sub(lambda mm: "h" if mm.group(1) in host_vars else mm.group(0), v)
    if _interpolated(rest):
        r.error(where, f"label {k}: {v!r} must be a literal (only HTTP router rules and the template's own host variables are interpolated)", HUB_HINT)


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
