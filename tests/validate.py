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
import unicodedata
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
    # OxiCloud can't restrict OIDC logins by group; the authorize endpoint
    # mints the login state its callback requires.
    "oxicloud": ["/api/auth/oidc/authorize"],
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
    (r"^VIKUNJA_AUTH_OPENID_PROVIDERS_[A-Z0-9_]+_(EMAILFALLBACK|USERNAMEFALLBACK)$", r"(?i)^(1|t|true)$",
     "Vikunja links OIDC logins to existing accounts by email / username"),
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
    ("OXICLOUD_OIDC_ENABLED", r"(?i)^true$", "OXICLOUD_OIDC_AUTO_LINK_EMAIL_MATCH", r"(?i)^false$",
     "OxiCloud with OIDC must set OXICLOUD_OIDC_AUTO_LINK_EMAIL_MATCH: \"false\" (the default true links SSO logins to accounts by email)"),
    ("OXICLOUD_OIDC_ENABLED", r"(?i)^true$", "OXICLOUD_AUTH_METHODS", r"^oidc$",
     "OxiCloud with OIDC must set OXICLOUD_AUTH_METHODS: oidc (no password or magic-link login next to SSO)"),
    ("VIKUNJA_AUTH_OPENID_ENABLED", r"(?i)^true$", "VIKUNJA_AUTH_LOCAL_ENABLED", r"(?i)^false$",
     "Vikunja with OIDC must set VIKUNJA_AUTH_LOCAL_ENABLED: \"false\" (local accounts: password login, sign-up, invite links)"),
    ("VIKUNJA_AUTH_OPENID_ENABLED", r"(?i)^true$", "VIKUNJA_OUTGOINGREQUESTS_ALLOWNONROUTABLEIPS", r"(?i)^false$",
     "Vikunja must set VIKUNJA_OUTGOINGREQUESTS_ALLOWNONROUTABLEIPS: \"false\" (user-supplied URLs must not reach "
     "portcullis-proxy or the host's private networks)"),
]

# image prefix -> (env key, required value regex, message): settings an image
# needs whatever else its environment says.
IMAGE_ENV_REQUIRED = [
    ("mattermost/mattermost-team-edition:", "MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL", r"(?i)^false$",
     "Mattermost must set MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL: \"false\" (self sign-up, the first account "
     "becomes system admin; also closes invite-link sign-up)"),
    ("mattermost/mattermost-team-edition:", "MM_PLUGINSETTINGS_ENABLEUPLOADS", r"(?i)^false$",
     "Mattermost must set MM_PLUGINSETTINGS_ENABLEUPLOADS: \"false\" (a plugin upload is server-side code from any "
     "system-admin session; ship pinned plugins through the file store instead)"),
    ("mattermost/mattermost-team-edition:", "MM_PLUGINSETTINGS_REQUIREPLUGINSIGNATURE", r"(?i)^true$",
     "Mattermost must set MM_PLUGINSETTINGS_REQUIREPLUGINSIGNATURE: \"true\" (otherwise any bundle in the file store "
     "is installed unsigned)"),
    ("mattermost/mattermost-team-edition:", "MM_FILESETTINGS_DRIVERNAME", r"^local$",
     "Mattermost must set MM_FILESETTINGS_DRIVERNAME: local (the file store, which plugins install from, stays on the data volume)"),
    ("mattermost/mattermost-team-edition:", "MM_FILESETTINGS_DIRECTORY", r"^/mattermost/data/?$",
     "Mattermost must set MM_FILESETTINGS_DIRECTORY: /mattermost/data/ (locks the file store to the data volume)"),
    ("mattermost/mattermost-team-edition:", "MM_PLUGINSETTINGS_DIRECTORY", r"^/mattermost/plugins/?$",
     "Mattermost must set MM_PLUGINSETTINGS_DIRECTORY: /mattermost/plugins (locks the server plugin directory)"),
    ("mattermost/mattermost-team-edition:", "MM_PLUGINSETTINGS_CLIENTDIRECTORY", r"^/mattermost/client/plugins/?$",
     "Mattermost must set MM_PLUGINSETTINGS_CLIENTDIRECTORY: /mattermost/client/plugins (locks the webapp plugin directory)"),
]

# image prefix -> (dotted manifest key, required value, message)
IMAGE_MANIFEST_REQUIRED = [
    ("ghcr.io/home-assistant/home-assistant:", "auth.keycloak_access_role", True,
     "Home Assistant needs auth.keycloak_access_role: true (auth_oidc admits admin_group members without "
     "access_group; Keycloak must restrict the client to access_group)"),
]

# image prefix -> (one-shot service that must exist in the same compose file, message)
REQUIRED_INIT_JOBS = [
    ("ghcr.io/immich-app/immich-server:", "immich-lock-local-users",
     "Immich links OAuth logins to existing users by email and cannot be told not to; keep the immich-lock-local-users job"),
    ("ghcr.io/paperless-ngx/paperless-ngx:", "paperless-init",
     "Paperless password logins (Basic auth, /api/token/) and the fresh-install signup are only closed by the paperless-init job"),
    ("ghcr.io/mealie-recipes/mealie:", "mealie-init",
     "Mealie's password endpoint, seeded admin and username/email account matching are only closed by the mealie-init guard"),
    ("ghcr.io/motioneye-project/motioneye:", "motioneye-init",
     "motionEye's admin and user accounts have empty passwords until the motioneye-init job sets generated ones"),
    ("diocrafts/oxicloud:", "oxicloud-init",
     "OxiCloud's first-run setup endpoint (a password owner for whoever calls it first) is only closed by the oxicloud-init job"),
    ("ghcr.io/home-assistant/home-assistant:", "homeassistant-init",
     "Home Assistant's onboarding (a password owner), the pinned auth_oidc install and the Traefik-only proxy trust "
     "come from the homeassistant-init job"),
    ("mattermost/mattermost-team-edition:", "mattermost-init",
     "Mattermost's bootstrap system admin (pinned by user id, never granted by name) comes from the mattermost-init job"),
    ("ghcr.io/porelli/firefox-sync:", "firefox-sync-init",
     "Firefox Sync's tokenserver takes any Mozilla account; only the firefox-sync-init allowlist trigger keeps other accounts off"),
]

# image prefix -> (one-shot the image's Traefik-routed services must wait for, message)
REQUIRED_BEFORE_ROUTED = [
    ("ghcr.io/porelli/firefox-sync:", "firefox-sync-init",
     "the public Sync server must start only after firefox-sync-init installed the allowlist "
     "(depends_on: firefox-sync-init: condition: service_completed_successfully)"),
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
    (r"(?m)^\s*automatic_user_linking:\s*true\b",
     "Home Assistant auth_oidc automatic_user_linking hands an existing account to the OIDC user with that username"),
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
# Read plain scalars as the Hub's yaml.v3 does (YAML 1.2 core schema): only
# true / false are booleans (yes / no / on / off stay strings, so
# `traefik.enable: yes` and `default: yes` are refused as the Hub refuses
# them) and timestamps stay strings.
_UniqueKeyLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp")]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()}
_UniqueKeyLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF"))


def scalar_text(v: Any) -> str:
    """A decoded YAML scalar as the Hub reads it into a string (Go's
    fmt.Sprint: booleans lowercase)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    return "" if v is None else str(v)


def load_yaml(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass


def _string_bool_keys(v: Any) -> Any:
    """Mapping keys true / false as the Hub's yaml.v3 matches struct fields:
    by their text (`render: {true: "on"}` is the field "true")."""
    if isinstance(v, dict):
        return {(scalar_text(k) if isinstance(k, bool) else k): _string_bool_keys(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_string_bool_keys(x) for x in v]
    return v


def as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def labels_of(svc: Dict[str, Any]) -> Dict[str, str]:
    raw = svc.get("labels") or {}
    if isinstance(raw, dict):
        return {str(k): scalar_text(v) for k, v in raw.items()}
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
        # Top-level manifest keys with schema errors (check_settings waits for those).
        self.schema_errors: Set[str] = set()

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
    elif check_id_shape(t.id):
        r.error(t.id + "/", f"directory name: {check_id_shape(t.id)}",
                "the Hub refuses the template (templates.CheckIDShape): Traefik's automatic service names must stay apart")
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
    data = _string_bool_keys(data)
    t.manifest = data
    errs = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    for e in errs:
        if e.absolute_path:
            t.schema_errors.add(str(e.absolute_path[0]))
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
    if e.validator == "type" and isinstance(e.instance, (dict, list)):
        return f"a {'list' if isinstance(e.instance, list) else 'mapping'} is not of type {e.validator_value!r}"
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

    # Ports and env share the per-app .env (a setting's env name colliding
    # with them is check_settings', as in the Hub's envNames).
    seen: Dict[str, str] = {}
    keyed = [(section, item.get("key")) for section in ("ports", "env") for item in m.get(section) or []
             if isinstance(item, dict) and isinstance(item.get("key"), str)]
    for section, k in keyed + [("settings", n) for n in settings_env_names(m)]:
        if section != "settings":
            if k in seen:
                r.error(t.m_where, f"key {k} is declared in both {seen[k]} and {section}",
                        "ports and env share the per-app .env; keys must be unique")
            seen[k] = section
        if k in CORE_VARS:
            r.error(t.m_where, f"{section} key {k} shadows a core variable")
        if is_instance_var(k):
            r.error(t.m_where, f"{section} key {k} is reserved for the Hub's instance variables",
                    "the Hub writes PORTCULLIS_INSTANCE, PORTCULLIS_HOST_*, PORTCULLIS_OIDC_CLIENT_ID*, "
                    "PORTCULLIS_ACCESS_GROUP and PORTCULLIS_ADMIN_GROUP itself; " + V2_HINT)

    for e in env:
        if e.get("generate") == "none":
            r.error(t.m_where, f"env {e.get('key')}: generate: none is template contract v2 — declare a setting for a value the admin enters (contract §13)",
                    "an admin-entered value is a settings option (a secret for credentials): see " + SETTINGS_HINT)

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
        elif isinstance(spec, dict) and (spec.get("name") is not None or spec.get("external") not in (None, False)):
            r.error(t.c_where, "networks.default must stay the project's own network (no name:, no external:)",
                    "a named or external default network is shared with other projects (portcullis-proxy, "
                    "another instance): every service on it, gated backends included, would be reachable there")

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
    declared = set(random_keys) | set(settings_env_names(m))
    for section in ("env", "ports"):
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
            if not NETWORK_MODE_RE.match(str(svc.get("network_mode")).strip().lower()):
                r.error(where, f"network_mode {svc.get('network_mode')!r}: only none, host or service:<own service>",
                        "any other value names a network (e.g. portcullis-proxy) the service would join unchecked")
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
    check_internal_names(t, services, r)
    check_gated_backends(t, services, r)
    check_mosquitto(t, services, r)
    check_signin_test(t, r)
    check_hub_rules(t, r)
    check_traefik_routes(t, services, r)
    check_settings(t, services, routers, r)


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
        return {str(k): scalar_text(v) for k, v in raw.items()}
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
        for prefix, key, req_re, msg in IMAGE_ENV_REQUIRED:
            if image.startswith(prefix) and not re.search(req_re, env.get(key, "")):
                r.error(where, msg, EMAIL_HINT)
        for prefix, mkey, want, msg in IMAGE_MANIFEST_REQUIRED:
            if image.startswith(prefix):
                val: Any = t.manifest or {}
                for part in mkey.split("."):
                    val = val.get(part) if isinstance(val, dict) else None
                if val != want:
                    r.error(t.m_where, msg)
        for prefix, job, msg in REQUIRED_INIT_JOBS:
            if image.startswith(prefix) and job not in services:
                r.error(where, msg, EMAIL_HINT)
        for prefix, job, msg in REQUIRED_BEFORE_ROUTED:
            if image.startswith(prefix) and str(labels_of(svc).get("traefik.enable", "")).lower() == "true":
                dep = svc.get("depends_on")
                cond = dep.get(job) if isinstance(dep, dict) else None
                if not (isinstance(cond, dict) and cond.get("condition") == "service_completed_successfully"):
                    r.error(where, msg, "compose starts a service before a one-shot it doesn't wait for; "
                            "see the template's auth.notes")
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


# Apps with no access control of their own (ESPHome Device Builder,
# Zigbee2MQTT), whose own login is only a second step (motionEye) or that
# trust a forwarded client-address header (Mattermost, X-Real-Ip): the app
# service stays on the instance's default network, and the only routed
# service is the Traefik-only nginx gate running the template's gate.sh
# (byte-identical in every template, check_cross). Value: extra
# requirements ("healthy": the gate waits for the app's healthcheck;
# "init": the app waits for that one-shot job).
GATED_BACKENDS = {   # image repository (any registry or mirror prefix)
    "esphome/esphome": {},
    "koenkk/zigbee2mqtt": {},
    "motioneye-project/motioneye": {"healthy": True, "init": "motioneye-init"},
    "mattermost/mattermost-team-edition": {},
    "mattermost/mattermost-enterprise-edition": {},
}
GATE_CAPS = {"CHOWN", "SETGID", "SETUID"}


def image_repo(image: str) -> str:
    """Repository path of an image reference without registry host, tag or
    digest, lowercase (ghcr.io/esphome/esphome:1@sha256:.. -> esphome/esphome)."""
    ref = image.split("@", 1)[0].strip().lower()
    parts = ref.split("/")
    if parts and ":" in parts[-1]:
        parts[-1] = parts[-1].split(":", 1)[0]
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    if parts[:1] == ["library"]:
        parts = parts[1:]
    return "/".join(parts)


def repo_is(image: str, repo: str) -> bool:
    """The image is that repository, also behind a mirror path prefix."""
    got = image_repo(image)
    return got == repo or got.endswith("/" + repo)
GATE_SH = "gate.sh"
GATE_SH_REQUIRED = [
    (r"(?m)^\s*allow \$\{ip\};$", "allow ${ip}; (Traefik's address only)"),
    (r"(?m)^\s*deny all;$", "deny all;"),
    (r'(?m)^\s*proxy_set_header Authorization "";$', 'proxy_set_header Authorization ""; (the Keycloak bearer token)'),
    (r'(?m)^\s*proxy_set_header X-Forwarded-Access-Token "";$', 'proxy_set_header X-Forwarded-Access-Token "";'),
    (r"(?m)^\s*proxy_set_header Cookie \\\$pc_cookie;$", "proxy_set_header Cookie $pc_cookie; (forward-auth cookies stripped)"),
    (r"_oauth2_proxy\|__Host-portcullis_ext", "the forward-auth cookie names in the Cookie maps"),
    (r"(?m)^\s*if \(\\\$pc_cookie_left\) \{ return 400; \}$", "the 400 for a Cookie header it can't fully strip"),
]
GATE_SH_FORBIDDEN = [
    (r"\b(set_real_ip_from|real_ip_header|real_ip_recursive)\b",
     "the realip module (set_real_ip_from / real_ip_header: a forwarded header would decide the peer address)"),
]
GATE_HINT = ("the app of a gated template stays on the default network; the only routed service is the nginx gate "
             "running ./templates/<id>/gate.sh (copy it from esphome/) with PORTCULLIS_TRAEFIK_IP")


def _nets(svc: Dict[str, Any]) -> List[str]:
    return sorted(str(n) for n in networks_of(svc))


def _depends(svc: Dict[str, Any], other: str) -> Optional[str]:
    dep = svc.get("depends_on")
    if isinstance(dep, dict) and other in dep:
        return str((dep[other] or {}).get("condition", "service_started"))
    if isinstance(dep, list) and other in dep:
        return "service_started"
    return None


def _has_healthcheck(svc: Dict[str, Any]) -> bool:
    hc = svc.get("healthcheck")
    if not isinstance(hc, dict) or hc.get("disable"):
        return False
    test = hc.get("test")
    if isinstance(test, list):
        return bool(test) and str(test[0]).upper() != "NONE"
    return bool(test)


# Names the gate resolves its upstream by (Docker DNS, on every network the
# gate joins, portcullis-proxy included): they end in -internal and are
# declared on the template's own default network only, and no service of any
# template may answer to such a name on another network (it would receive the
# proxied requests). Docker's DNS answers service names, container names and
# network aliases; hostname is included to be safe.
INTERNAL_SUFFIX = "-internal"
# network_mode values that join no network by name (container: is refused by
# the Hub rules); anything else is a network name.
NETWORK_MODE_RE = re.compile(r"^(none|host|service:[a-z0-9][a-z0-9_.-]*)$")
NO_DNS_MODE_RE = re.compile(r"^(none|host|service:.*|container:.*)$")
DNS_HINT = ("names ending in -internal (a gate's upstream) are declared as aliases on the default network only; "
            "a name on portcullis-proxy could catch another app's gated traffic")


def private_networks(compose: Optional[Dict[str, Any]]) -> Set[str]:
    """Service network keys that are the project's own network: 'default',
    unless the top level renames it or makes it external (then shared)."""
    spec = ((compose or {}).get("networks") or {}).get("default")
    if isinstance(spec, dict) and (spec.get("name") is not None or spec.get("external") not in (None, False)):
        return set()
    return {"default"}


def dns_names(sname: str, svc: Dict[str, Any]) -> Dict[str, Set[str]]:
    """network key -> the names other containers on it resolve to this
    service (network_mode <name> joins that network; none / host /
    service: / container: give it no DNS name of its own)."""
    mode = str(svc.get("network_mode", "") or "").strip()
    if mode and NO_DNS_MODE_RE.match(mode.lower()):
        return {}
    nets = svc.get("networks")
    if mode:
        nets = {mode: None}
    if nets is None:
        nets = {"default": None}
    if not isinstance(nets, dict):
        nets = {str(n): None for n in nets}
    common = {sname} | {str(svc[k]) for k in ("container_name", "hostname") if svc.get(k)}
    out: Dict[str, Set[str]] = {}
    for net, conf in nets.items():
        aliases = (conf or {}).get("aliases") if isinstance(conf, dict) else None
        out[str(net)] = {n.lower() for n in common | {str(a) for a in as_list(aliases)}}
    return out


def gate_upstream_host(svc: Dict[str, Any]) -> Optional[str]:
    m = re.match(r"^https?://([^/:]+)", env_of(svc).get("GATE_UPSTREAM", ""))
    return m.group(1).lower() if m else None


def check_internal_names(t: Template, services: Dict[str, Any], r: Report) -> None:
    private = private_networks(t.compose)
    for sname, svc in services.items():
        if not isinstance(svc, dict):
            continue
        for net, names in dns_names(str(sname), svc).items():
            if net in private:
                continue
            for n in sorted(names):
                if n.endswith(INTERNAL_SUFFIX):
                    r.error(f"{t.c_where}: services.{sname}",
                            f"name {n!r} ends in {INTERNAL_SUFFIX} but is on network {net!r}", DNS_HINT)


def check_gated_backends(t: Template, services: Dict[str, Any], r: Report) -> None:
    backends = {}
    for sname, svc in services.items():
        if not isinstance(svc, dict):
            continue
        image = str(svc.get("image", ""))
        for repo, extra in GATED_BACKENDS.items():
            if repo_is(image, repo) and str(svc.get("network_mode", "")) != "none":
                backends[sname] = extra
    if not backends:
        return
    for sname, extra in backends.items():
        svc = services[sname]
        where = f"{t.c_where}: services.{sname}"
        if any(k.startswith("traefik.") for k in labels_of(svc)):
            r.error(where, "an unauthenticated backend must have no traefik labels", GATE_HINT)
        mode = str(svc.get("network_mode", "")).lower()
        if mode == "host":
            r.error(where, "an unauthenticated backend must not use host networking", GATE_HINT)
        elif mode:
            # service:<gate> / container:<x> would share another network namespace.
            r.error(where, f"an unauthenticated backend must not set network_mode (got {mode!r})", GATE_HINT)
        # No networks key = the default network only, which must be the
        # project's own (not renamed / external).
        if "default" not in private_networks(t.compose):
            r.error(where, "an unauthenticated backend needs the project's own default network "
                    "(networks.default has name: or external:)", GATE_HINT)
        if mode != "host" and (_nets(svc) or ["default"]) != ["default"]:
            r.error(where, f"an unauthenticated backend must be on the default network only (got {_nets(svc)})", GATE_HINT)
        if extra.get("init") and _depends(svc, extra["init"]) != "service_completed_successfully":
            r.error(where, f"must depend on {extra['init']} with condition service_completed_successfully",
                    "the one-shot job closes the app's default login before it starts")
        if extra.get("healthy") and not _has_healthcheck(svc):
            r.error(where, "needs its healthcheck (the gate is routed only while it is healthy)")
    gates = [n for n, svc in services.items()
             if isinstance(svc, dict) and labels_of(svc).get("traefik.enable", "").lower() == "true"]
    if not gates:
        r.error(t.c_where, "a gated template needs its gate service (traefik.enable)", GATE_HINT)
    want_mount = f"./templates/{t.id}/{GATE_SH}:/portcullis/{GATE_SH}:ro"
    for g in gates:
        svc = services[g]
        where = f"{t.c_where}: services.{g}"
        if want_mount not in [str(v) for v in as_list(svc.get("volumes"))]:
            r.error(where, f"the routed service of a gated template must be the gate: mount {want_mount}", GATE_HINT)
        if f"/portcullis/{GATE_SH}" not in " ".join(str(x) for x in as_list(svc.get("entrypoint"))):
            r.error(where, f"the gate must run /portcullis/{GATE_SH} (entrypoint)", GATE_HINT)
        if env_of(svc).get("PORTCULLIS_TRAEFIK_IP") != "${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}":
            r.error(where, "the gate needs PORTCULLIS_TRAEFIK_IP: ${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}", GATE_HINT)
        up = gate_upstream_host(svc)
        if not up or not up.endswith(INTERNAL_SUFFIX):
            r.error(where, f"GATE_UPSTREAM must name a <app>{INTERNAL_SUFFIX} alias (got {up!r})", DNS_HINT)
        else:
            private = private_networks(t.compose)
            owners = [b for b in backends if up != b.lower()
                      and any(up in names for net, names in dns_names(b, services[b]).items() if net in private)]
            if not owners:
                r.error(where, f"GATE_UPSTREAM host {up!r} must be a default-network alias of the gated backend", DNS_HINT)
            for o, osvc in services.items():
                if not isinstance(osvc, dict):
                    continue
                for net, names in dns_names(str(o), osvc).items():
                    if up in names and (net not in private or o not in backends):
                        r.error(where, f"GATE_UPSTREAM host {up!r} is also services.{o} on {net!r}", DNS_HINT)
        caps_drop = [str(c).upper().removeprefix("CAP_") for c in as_list(svc.get("cap_drop"))]
        caps_add = [str(c).upper().removeprefix("CAP_") for c in as_list(svc.get("cap_add"))]
        if "ALL" not in caps_drop or not set(caps_add) <= GATE_CAPS:
            r.error(where, "the gate must drop all capabilities (cap_drop: [ALL]) and add back only CHOWN, SETGID, SETUID")
        for b, extra in backends.items():
            if extra.get("healthy") and _depends(svc, b) != "service_healthy":
                r.error(where, f"the gate must depend on {b} with condition service_healthy",
                        "Traefik must not route the app before its healthcheck passes")
            if extra.get("healthy") and not _has_healthcheck(svc):
                r.error(where, "the gate needs its healthcheck (the app's default login refused)")
    path = os.path.join(t.dir, GATE_SH)
    if not os.path.isfile(path):
        r.error(t.c_where, f"{t.id}/{GATE_SH} is missing", GATE_HINT)
        return
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for rx, what in GATE_SH_REQUIRED:
        if not re.search(rx, text):
            r.error(f"{t.id}/{GATE_SH}", f"the gate must keep {what}", GATE_HINT)
    for rx, what in GATE_SH_FORBIDDEN:
        if re.search(rx, text):
            r.error(f"{t.id}/{GATE_SH}", f"the gate must not use {what}", GATE_HINT)


def check_mosquitto(t: Template, services: Dict[str, Any], r: Report) -> None:
    """A bundled Mosquitto refuses anonymous clients and checks a password
    file that its one-shot mosquitto-init wrote before it started."""
    for sname, svc in services.items():
        if not isinstance(svc, dict) or not repo_is(str(svc.get("image", "")), "eclipse-mosquitto"):
            continue
        if str(svc.get("network_mode", "")) == "none":
            continue  # the one-shot init itself
        where = f"{t.c_where}: services.{sname}"
        if "mosquitto-init" not in services or _depends(svc, "mosquitto-init") != "service_completed_successfully":
            r.error(where, "the broker must depend on mosquitto-init with condition service_completed_successfully",
                    "mosquitto-init writes the hashed password file; without it the broker would start without one")
        conf = None
        for vol in as_list(svc.get("volumes")):
            parts = str(vol).split(":")
            if len(parts) >= 2 and parts[1] == "/mosquitto/config/mosquitto.conf" and parts[0].startswith(f"./templates/{t.id}/"):
                conf = os.path.join(t.dir, parts[0][len(f"./templates/{t.id}/"):])
        if not conf or not os.path.isfile(conf):
            r.error(where, "the broker must mount the template's mosquitto.conf at /mosquitto/config/mosquitto.conf "
                    "(the image's default config allows anonymous clients)")
            continue
        with open(conf, encoding="utf-8") as f:
            text = f.read()
        if not re.search(r"(?m)^allow_anonymous false\s*$", text) or re.search(r"(?m)^\s*allow_anonymous\s+true", text):
            r.error(f"{t.id}/{os.path.basename(conf)}", "mosquitto.conf must set allow_anonymous false (and never true)")
        acl_path = os.path.join(t.dir, "acl")
        if os.path.isfile(acl_path):
            check_ha_acl(t, acl_path, r)
        if not re.search(r"(?m)^(plugin_opt_password_file|password_file)\s+\S", text):
            r.error(f"{t.id}/{os.path.basename(conf)}", "mosquitto.conf must check a password file "
                    "(plugin_opt_password_file of mosquitto_password_file.so)")



# The homeassistant account of a bundled Zigbee2MQTT broker: exactly these
# lines are allowed (reviewed against Zigbee2MQTT 2.14's topic handlers).
# Zigbee2MQTT lowercases bridge request keys, so nothing is denylisted for
# writes; the one deny is the read of bridge/logging (exact topic: Mosquitto
# matches case-sensitively, Zigbee2MQTT publishes exactly that).
HA_ACL_ALLOWED = {
    ("read", "homeassistant/#"), ("write", "homeassistant/status"),
    ("read", "zigbee2mqtt/+"), ("read", "zigbee2mqtt/+/+"),
    ("read", "zigbee2mqtt/bridge/state"), ("read", "zigbee2mqtt/bridge/info"), ("read", "zigbee2mqtt/bridge/devices"),
    ("read", "zigbee2mqtt/bridge/groups"), ("read", "zigbee2mqtt/bridge/event"),
    ("read", "zigbee2mqtt/+/availability"), ("read", "zigbee2mqtt/+/action"),
    ("write", "zigbee2mqtt/+/set"), ("write", "zigbee2mqtt/+/set/+"),
    ("write", "zigbee2mqtt/+/get"), ("write", "zigbee2mqtt/+/get/+"),
    ("write", "zigbee2mqtt/+/+/set"), ("write", "zigbee2mqtt/+/+/set/+"),
    ("write", "zigbee2mqtt/+/+/get"), ("write", "zigbee2mqtt/+/+/get/+"),
    ("write", "zigbee2mqtt/bridge/request/permit_join"),
}
# Two-level bridge topics Zigbee2MQTT 2.14.3 publishes that Home Assistant
# doesn't use or that carry code / logged payloads: read zigbee2mqtt/+/+
# would reach them, so each needs its read deny (exact: Mosquitto matches
# case-sensitively, Zigbee2MQTT publishes exactly these).
HA_ACL_BRIDGE_DENY = ("logging", "extensions", "converters", "definitions", "health")
HA_ACL_ALLOWED |= {("deny", f"zigbee2mqtt/bridge/{x}") for x in HA_ACL_BRIDGE_DENY}
HA_ACL_HINT = ("Zigbee2MQTT matches bridge requests case-insensitively: the homeassistant account is a reviewed "
               "allowlist (validate.py HA_ACL_ALLOWED); grant only what Home Assistant's integration uses")


def check_ha_acl(t: Template, path: str, r: Report) -> None:
    """The Home Assistant account of a bundled broker is a reviewed
    allowlist; no pattern lines, no topic lines outside a user section."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    user = None
    ha: Set[Tuple[str, str]] = set()
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = f"{t.id}/{os.path.basename(path)}:{n}"
        parts = line.split()
        if parts[0] == "user":
            user = " ".join(parts[1:])
            continue
        if parts[0] == "pattern":
            r.error(where, "pattern lines are not allowed in the bundled broker's ACL (they apply to every user)", HA_ACL_HINT)
            continue
        if parts[0] != "topic":
            r.error(where, f"unexpected ACL line {line!r}", HA_ACL_HINT)
            continue
        if user is None:
            r.error(where, "topic line before any user (it would apply to every client)", HA_ACL_HINT)
            continue
        if user != "homeassistant":
            continue
        access, topic = (parts[1], parts[2]) if len(parts) == 3 else ("readwrite", parts[1] if len(parts) > 1 else "")
        ha.add((access, topic))
        levels = topic.split("/")
        if access in ("write", "readwrite") and topic.startswith("zigbee2mqtt/bridge/") \
                and topic != "zigbee2mqtt/bridge/request/permit_join":
            r.error(where, f"homeassistant may write under zigbee2mqtt/bridge/ only to request/permit_join (got {access} {topic})", HA_ACL_HINT)
        elif len(levels) > 1 and levels[0] == "zigbee2mqtt" and levels[1] == "bridge" and any(x in ("+", "#") for x in levels[1:]):
            r.error(where, f"no wildcard at or after the bridge level (got {access} {topic})", HA_ACL_HINT)
        elif access == "deny" and (access, topic) not in HA_ACL_ALLOWED:
            r.error(where, f"the homeassistant account must be an allowlist, not deny lines ({topic})", HA_ACL_HINT)
        elif (access, topic) not in HA_ACL_ALLOWED:
            r.error(where, f"{access} {topic} is not in the reviewed homeassistant allowlist (wildcard grant or new topic)", HA_ACL_HINT)
    if ("read", "zigbee2mqtt/+/+") in ha:
        missing = [x for x in HA_ACL_BRIDGE_DENY if ("deny", f"zigbee2mqtt/bridge/{x}") not in ha]
        if missing:
            r.error(f"{t.id}/{os.path.basename(path)}", "read zigbee2mqtt/+/+ also reaches the two-level bridge topics: "
                    "it needs topic deny zigbee2mqtt/bridge/" + ", zigbee2mqtt/bridge/".join(missing) +
                    " (logged payloads, JavaScript source, unused bridge data)", HA_ACL_HINT)

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
    env_keys = {e.get("key") for e in m.get("env") or [] if isinstance(e, dict)} | set(settings_env_names(m))
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
    # Zigbee2MQTT's onboarding wizard (and failure page) would configure the
    # instance for whoever reaches it first; the frontend must listen where
    # the gate expects it (all addresses of its private network).
    "ghcr.io/koenkk/zigbee2mqtt": [
        ("Z2M_ONBOARD_NO_SERVER", lambda v: v == "1", 'must be "1" (no onboarding wizard or failure page)'),
        ("ZIGBEE2MQTT_CONFIG_FRONTEND_HOST", lambda v: v is MISSING, "must not be set (the frontend is reached only through the gate)"),
    ],
}

MISSING = object()  # DEFAULT_CREDENTIAL_RULES: the variable is not set


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
        if ok(env[key] if key in env else MISSING):
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
    # No template answers to a gate's upstream name outside its own default
    # network (Docker DNS on portcullis-proxy would hand it the gate's traffic).
    upstreams: Dict[str, str] = {}
    for t in templates:
        for svc in ((t.compose or {}).get("services") or {}).values():
            if isinstance(svc, dict) and f"/portcullis/{GATE_SH}" in " ".join(str(x) for x in as_list(svc.get("entrypoint"))):
                up = gate_upstream_host(svc)
                if up:
                    upstreams.setdefault(up, t.id)
    for t in templates:
        for sname, svc in ((t.compose or {}).get("services") or {}).items():
            if not isinstance(svc, dict):
                continue
            private = private_networks(t.compose)
            for net, names in dns_names(str(sname), svc).items():
                for n in sorted(names & set(upstreams)):
                    if net not in private:
                        r.error(f"{t.c_where}: services.{sname}",
                                f"name {n!r} is {upstreams[n]}'s gate upstream (here on network {net!r})", DNS_HINT)
    # Every template's gate.sh is the same file (one reviewed gate).
    gate_ref: Optional[Tuple[str, bytes]] = None
    for t in templates:
        path = os.path.join(t.dir, GATE_SH)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        if gate_ref is None:
            gate_ref = (t.id, data)
        elif data != gate_ref[1]:
            r.error(f"{t.id}/{GATE_SH}", f"differs from {gate_ref[0]}/{GATE_SH}",
                    "every template's gate.sh must be byte-identical; copy the reviewed one")


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


# ── Settings (template contract v3, contracts §13) ──────────────────
#
# A mirror of the Hub's discover-time settings checks: portcullis-hub
# internal/templates/settings.go (ValidateSettingsSpec) and the type checks
# of internal/settings (Registry.CheckOption: kinds_*.go, formats.go,
# render.go). Messages follow the Hub's ("setting <key>: …"), so CI refuses
# what the Hub would skip, with the same reason.

SETTINGS_HINT = f"see {DOCS_URL}/integration-contracts/#13-settings"
SETTINGS_SHAPE_KEYS = ("settings", "files", "hooks", "reload")

OPTION_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")
SECTION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ]{0,31}")
FILE_HOOK_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
FIELD_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")
CLAIM_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
# policy.HeaderNameRe: group-gate's suffix form after the prefix.
HEADER_NAME_RE = re.compile(r"X-Forwarded-Attr-[A-Za-z0-9]+(-[A-Za-z0-9]+){0,30}")
ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
COLUMN_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
GROUP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
HOSTNAME_RE = re.compile(r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
ID_NORMAL_RE = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")

BUILTIN_TYPES = {"string", "int", "size", "duration", "bool", "enum", "multi_enum", "list", "table", "path",
                 "secret", "group", "groups", "user", "users"}
OLD_TYPES = {"text": "use string", "boolean": "use bool", "select": "use enum (options: [{value, label}])",
             "paths": "use path (one option per directory)"}
SCOPES = ("instance", "person", "group", "person_entered")
PERSON_ENTERED_TYPES = {"string", "int", "bool", "enum"}
PERSON_ENTERED_MAX_LEN = 256
APPLIES = {"live", "reload", "next_sign_in", "next_request", "restart", "account_creation"}
RESOLVE_TYPES: Dict[str, Optional[Set[str]]] = {
    "max": {"int", "size", "duration", "enum"}, "min": {"int", "size", "duration", "enum"}, "priority": None,
    "union": {"list", "multi_enum", "groups"}, "intersection": {"list", "multi_enum", "groups"},
    "any": {"bool"}, "all": {"bool"},
}
HOOK_TRIGGERS = ("start", "settings_change", "membership_change")
RELOAD_SIGNALS = {"HUP", "USR1", "USR2"}
GENERATE_CHARSETS = {"hex", "alphanumeric", "ascii_printable"}
CLAIM_JSON_TYPES = {"int", "string", "bool", "json"}
PLACEHOLDER_ACCESS, PLACEHOLDER_ADMIN = "{{ACCESS_GROUP}}", "{{ADMIN_GROUP}}"
FEATURE_FOLDERS, FEATURE_SHARING = "shared folders (project 2)", "file sharing (project 3)"
INDEX_SUFFIX, MAX_INDEXED = "_{n}", 64
HOOK_DEFAULT_TIMEOUT, HOOK_MAX_TIMEOUT = 30 * 10 ** 9, 10 * 60 * 10 ** 9   # ns
RESERVED_CLAIMS = {
    "sub", "iss", "aud", "exp", "nbf", "iat", "jti", "azp", "sid", "nonce", "auth_time", "at_hash", "c_hash",
    "typ", "scope", "acr", "amr", "email", "email_verified", "name", "given_name", "family_name", "middle_name",
    "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale",
    "phone_number", "phone_number_verified", "address", "updated_at", "groups", "realm_access", "resource_access",
    "allowed-origins", "session_state", "client_id", "cnf", "roles",
}
FORWARD_AUTH_MWS = ("portcullis-auth@docker", "portcullis-groups@docker")
INT64_MIN, INT64_MAX = -(1 << 63), (1 << 63) - 1


class SettingError(ValueError):
    """A value or option the Hub's settings kinds refuse (the message is the Hub's)."""


class _Unlimited:
    def __repr__(self) -> str:
        return "unlimited"


UNLIMITED = _Unlimited()   # a size's "unlimited" (settings.Unlimited{})


def is_control_rune(c: str) -> bool:
    """templates.IsControlRune: Unicode Cc, U+2028/9 and the bidi controls."""
    o = ord(c)
    return unicodedata.category(c) == "Cc" or o in (0x2028, 0x2029) or 0x202A <= o <= 0x202E or 0x2066 <= o <= 0x2069


def has_control(s: str) -> bool:
    return any(is_control_rune(c) for c in s)


def blen(s: str) -> int:
    """Go's len(): bytes."""
    return len(s.encode("utf-8", "surrogatepass"))


def _gofmt(v: Any) -> str:
    """A value as Go's %v prints it in the Hub's messages."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, list):
        return "[" + " ".join(_gofmt(x) for x in v) + "]"
    if isinstance(v, dict):
        return "map[" + " ".join(f"{k}:{_gofmt(x)}" for k, x in sorted(v.items(), key=lambda kv: str(kv[0]))) + "]"
    if v is UNLIMITED:
        return "unlimited"
    return "<nil>" if v is None else str(v)


def _type_name(v: Any) -> str:
    """Go's %T of a decoded value, for messages."""
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float64"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "[]interface {}"
    if isinstance(v, dict):
        return "map[string]interface {}"
    return "<nil>"


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _has(o: Dict[str, Any], k: str) -> bool:
    """A field the Hub sees as set: present and not YAML null (Go nil)."""
    return o.get(k) is not None


def _str(o: Dict[str, Any], k: str) -> str:
    v = o.get(k)
    return "" if v is None else scalar_text(v)


def go_clean(p: str) -> str:
    """Go's path.Clean."""
    if p == "":
        return "."
    rooted = p.startswith("/")
    out: List[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not rooted:
                out.append("..")
            continue
        out.append(seg)
    s = "/".join(out)
    return ("/" + s) if rooted else (s or ".")


def valid_mount(p: str) -> bool:
    """templates.validMount: an absolute, clean container directory, not /."""
    return p.startswith("/") and go_clean(p) == p and p != "/" and not has_control(p) and ":" not in p


def _nested(a: str, b: str) -> bool:
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


# ── Go durations ──

_GO_DUR_UNITS = {"ns": 1, "us": 10 ** 3, "µs": 10 ** 3, "μs": 10 ** 3, "ms": 10 ** 6, "s": 10 ** 9,
                 "m": 60 * 10 ** 9, "h": 3600 * 10 ** 9}
_STR2DUR_UNITS = dict(_GO_DUR_UNITS, d=86400 * 10 ** 9, w=7 * 86400 * 10 ** 9)
_DUR_PART_RE = re.compile(r"([0-9]*(?:\.[0-9]*)?)([a-zµμ]+)")


def go_parse_duration(s: str, units: Dict[str, int] = _GO_DUR_UNITS) -> int:
    """time.ParseDuration (units = _STR2DUR_UNITS: go-str2duration, + d, w),
    in nanoseconds; ValueError like Go's."""
    from fractions import Fraction
    orig, neg = s, False
    if s[:1] in ("-", "+"):
        neg, s = s[0] == "-", s[1:]
    if s == "0":
        return 0
    if s == "":
        raise ValueError(f"invalid duration {orig!r}")
    total, pos = Fraction(0), 0
    while pos < len(s):
        m = _DUR_PART_RE.match(s, pos)
        if not m or m.group(1) in ("", ".") or m.group(2) not in units:
            raise ValueError(f"invalid duration {orig!r}" if not m or m.group(1) in ("", ".") else
                             f"unknown unit {m.group(2)!r} in duration {orig!r}")
        total += Fraction(m.group(1) if not m.group(1).endswith(".") else m.group(1)[:-1]) * units[m.group(2)]
        pos = m.end()
    ns = int(total)   # Go truncates the fraction
    if ns > INT64_MAX + (1 if neg else 0):
        raise ValueError(f"invalid duration {orig!r}")
    return -ns if neg else ns


# ── string formats (settings/formats.go) ──

def _fmt_hostname(s: str) -> Optional[str]:
    return None if len(s) <= 253 and HOSTNAME_RE.fullmatch(s) else "want a lowercase DNS name such as app.example.com"


def _parse_addr(s: str) -> Optional[Any]:
    """netip.ParseAddr without zones."""
    if "%" in s or not s.isascii():
        return None
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _fmt_ip(s: str) -> Optional[str]:
    return None if _parse_addr(s) is not None else "want an IPv4 or IPv6 address"


def _fmt_cidr(s: str) -> Optional[str]:
    bad = "want an address/prefix such as 10.0.0.0/8"
    addr_s, sep, bits = s.partition("/")
    a = _parse_addr(addr_s)
    if not sep or a is None or not re.fullmatch(r"0|[1-9][0-9]{0,2}", bits) or int(bits) > a.max_prefixlen:
        return bad
    net = ipaddress.ip_network(f"{addr_s}/{bits}", strict=False)
    if net.network_address != a:
        return f"{s} has host bits set: the network is {net}"
    return None


# url.Parse + u.String() == s, statically: what Go's URL round trip keeps
# byte for byte (RFC 3986 characters only, valid %XX escapes).
_URL_PATH_CHARS = r"A-Za-z0-9\-._~!$&'()*+,;=:@\[\]/"
_URL_RE = re.compile(
    r"(https?)://"
    r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:%]*@)?"
    r"(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9\-._~!$&'()*+,;=%]+)"
    r"(?::([0-9]*))?"
    rf"((?:/(?:[{_URL_PATH_CHARS}]|%[0-9A-Fa-f]{{2}})*)?)"
    r"(\?[^#]*)?"   # Go keeps the raw query as written
    r"(#[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]*)?")


def _fmt_url(s: str) -> Optional[str]:
    bad = "want an http or https URL such as https://host/path (printable ASCII, no spaces; non-ASCII percent-encoded)"
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in s):
        return bad
    m = _URL_RE.fullmatch(s)
    if not m or re.search(r"%(?![0-9A-Fa-f]{2})", m.group(2) + m.group(4)):
        return bad
    port = m.group(3)
    if port:
        if not (port.isdigit() and 1 <= int(port) <= 65535 and str(int(port)) == port):
            return f"port {port!r} must be 1-65535"
    return None


_ATEXT = r"A-Za-z0-9!#$%&'*+/=?^_`{|}~\-\u0080-\U0010ffff"
_EMAIL_RE = re.compile(rf"[{_ATEXT}]+(?:\.[{_ATEXT}]+)*@[{_ATEXT}]+(?:\.[{_ATEXT}]+)+")


def _fmt_email(s: str) -> Optional[str]:
    """lldap.ValidEmail: one bare address (mail.ParseAddress round trip),
    a dot in the domain, ≤ 254."""
    if s == "" or len(s) > 254 or any(c in s for c in " <>\"") or not _EMAIL_RE.fullmatch(s):
        return "want a bare address such as name@example.com"
    return None


_TZ_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9][A-Za-z0-9_+-]*){0,2}")
_TZ_NAMES: Optional[Set[str]] = None


def _fmt_iana_tz(s: str) -> Optional[str]:
    global _TZ_NAMES
    bad = "want an IANA time zone such as Europe/Rome"
    if s in ("", "Local") or not _TZ_NAME_RE.fullmatch(s):
        return bad
    if _TZ_NAMES is None:
        try:
            import zoneinfo
            _TZ_NAMES = set(zoneinfo.available_timezones())
        except ImportError:  # pragma: no cover - Python < 3.9
            _TZ_NAMES = set()
    if _TZ_NAMES and s not in _TZ_NAMES:
        return bad
    return None


# BCP 47 in the canonical case x/text writes (language lowercase, Script
# titlecase, REGION uppercase, variants / extensions lowercase).
_LOCALE_RE = re.compile(
    r"(?:[a-z]{2,3}(?:-[a-z]{3}){0,3}|[a-z]{4,8})"
    r"(?:-[A-Z][a-z]{3})?"
    r"(?:-(?:[A-Z]{2}|[0-9]{3}))?"
    r"(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*"
    r"(?:-[a-wyz0-9](?:-[a-z0-9]{2,8})+)*"
    r"(?:-x(?:-[a-z0-9]{1,8})+)?")


def _fmt_locale(s: str) -> Optional[str]:
    return None if _LOCALE_RE.fullmatch(s) else "want a BCP 47 tag in canonical form such as it-IT"


_CRON_FIELDS = ((0, 59, None), (0, 23, None), (1, 31, None),
                (1, 12, ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]),
                (0, 6, ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]))
_CRON_DESCRIPTORS = {"@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}


def _cron_field_ok(field: str, lo: int, hi: int, names: Optional[List[str]]) -> bool:
    """robfig/cron getField: comma list of ranges with an optional step."""
    def num(x: str) -> Optional[int]:
        if names and x.lower() in names:
            return names.index(x.lower()) + (lo if lo == 1 and len(names) == 12 else 0)
        return int(x) if re.fullmatch(r"[0-9]+", x) else None
    for part in field.split(","):
        rng, _, step = part.partition("/")
        if rng in ("*", "?"):
            a, b = lo, hi
        else:
            x, dash, y = rng.partition("-")
            a = num(x)
            b = num(y) if dash else a
            if a is None or b is None:
                return False
            if not dash and step:
                b = hi
        if "/" in part and not re.fullmatch(r"[0-9]+", step):
            return False
        if "/" in part and int(step) == 0:
            return False
        if a < lo or b > hi or a > b:
            return False
    return True


def _fmt_cron(s: str) -> Optional[str]:
    bad = "want a five-field cron expression such as */5 * * * *"
    if " ".join(s.split()) != s or "\t" in s:
        return "fields must be separated by single spaces, without leading or trailing space"
    if s.startswith(("TZ=", "CRON_TZ=", "@every")):
        return bad
    if s.startswith("@"):
        return None if s in _CRON_DESCRIPTORS else bad
    fields = s.split(" ")
    if len(fields) != 5 or not all(_cron_field_ok(f, *spec) for f, spec in zip(fields, _CRON_FIELDS)):
        return bad
    return None


_SEMVER_ID = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_SEMVER_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
                        rf"(?:-{_SEMVER_ID}(?:\.{_SEMVER_ID})*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


def _fmt_semver(s: str) -> Optional[str]:
    return None if _SEMVER_RE.fullmatch(s) else "want MAJOR.MINOR.PATCH such as 1.2.3"


def _fmt_hex(s: str) -> Optional[str]:
    return None if re.fullmatch(r"[0-9a-fA-F]+", s) else "want hexadecimal digits"


STRING_FORMATS = {"hostname": _fmt_hostname, "ip": _fmt_ip, "cidr": _fmt_cidr, "url": _fmt_url, "email": _fmt_email,
                  "iana_tz": _fmt_iana_tz, "locale": _fmt_locale, "cron": _fmt_cron, "semver": _fmt_semver,
                  "hex": _fmt_hex}


# ── kinds (settings/kinds_*.go) ──

def _to_int(raw: Any) -> int:
    if isinstance(raw, bool) or not _is_number(raw):
        raise SettingError(f"want a whole number, not {_type_name(raw)}")
    if isinstance(raw, float):
        if raw != raw or raw in (float("inf"), float("-inf")) or raw != int(raw):
            raise SettingError(f"{_gofmt(raw)} is not a whole number")
        if raw >= 2.0 ** 63 or raw < -(2.0 ** 63):
            raise SettingError(f"{_gofmt(raw)} is too large")
        return int(raw)
    if raw > INT64_MAX or raw < INT64_MIN:
        raise SettingError(f"{raw} is too large")
    return raw


def _parse_decimal(s: str) -> int:
    if not re.fullmatch(r"-?[0-9]{1,19}", s):
        raise SettingError(f"{json.dumps(s)} is not a whole number")
    n = int(s)
    if n > INT64_MAX or n < INT64_MIN:
        raise SettingError(f"{json.dumps(s)} is out of range")
    return n


def _check_text(s: str) -> None:
    if has_control(s):
        raise SettingError("contains control characters (newlines included)")


_PATTERN_CACHE: Dict[str, Any] = {}
# What RE2 (Go's regexp) has no syntax for: Python would accept these.
_NOT_RE2 = re.compile(r"\(\?[=!>#]|\(\?<[=!]|\(\?P=|\\[1-9]|\\[Zz]|\(\?[aiLmsux-]*[aLux]")


def _compile_pattern(p: str) -> Any:
    """compilePattern: anchored ^…$, ≤ 500, applied to the whole value."""
    if p in _PATTERN_CACHE:
        return _PATTERN_CACHE[p]
    if blen(p) > 500:
        raise SettingError("pattern is longer than 500 characters")
    if not (p.startswith("^") and p.endswith("$")):
        raise SettingError(f"pattern {json.dumps(p)} must be anchored: ^…$")
    if _NOT_RE2.search(p):
        raise SettingError(f"pattern {json.dumps(p)}: lookarounds, backreferences, atomic groups, comments, \\Z and the "
                           "a / L / u / x flags are not RE2 (Go regexp) syntax")
    try:
        # re.ASCII: \d \w \s \b are ASCII in Go too. \Z: Go's $ is the end of
        # the text; Python's would also match before a final newline.
        rx = re.compile(r"(?:" + p + r")\Z", re.ASCII)
    except re.error as e:
        raise SettingError(f"pattern {json.dumps(p)}: {e}") from None
    _PATTERN_CACHE[p] = rx
    return rx


def _check_lens(min_len: Any, max_len: Any) -> None:
    for name, val in (("min_len", min_len), ("max_len", max_len)):
        if val is not None and not 0 <= val <= 65535:
            raise SettingError(f"{name} must be 0-65535")
    if min_len is not None and max_len is not None and min_len > max_len:
        raise SettingError("min_len is above max_len")


def _only_fields(o: Dict[str, Any], *allowed: str) -> None:
    """onlyFields: a type-specific field the type doesn't take is refused."""
    set_fields = [
        ("pattern", _str(o, "pattern") != ""), ("format", _str(o, "format") != ""),
        ("min_len", _has(o, "min_len")), ("max_len", _has(o, "max_len")),
        ("min_items", _has(o, "min_items")), ("max_items", _has(o, "max_items")),
        ("min", _has(o, "min")), ("max", _has(o, "max")), ("step", _has(o, "step")),
        ("unit", _str(o, "unit") != ""), ("allow_unlimited", bool(o.get("allow_unlimited"))),
        ("options", _has(o, "options")), ("items", _has(o, "items")), ("columns", _has(o, "columns")),
        ("key_column", _str(o, "key_column") != ""), ("target", _has(o, "target")),
        ("mode", _str(o, "mode") != ""), ("needs", _str(o, "needs") != ""),
    ]
    for name, on in set_fields:
        if on and name not in allowed:
            raise SettingError(f"{name} is not a constraint of type {o.get('type')}")


def _read_bounds(o: Dict[str, Any], parse: Any) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    vals: List[Optional[int]] = []
    for name in ("min", "max", "step"):
        raw = o.get(name)
        if raw is None:
            vals.append(None)
            continue
        try:
            vals.append(parse(raw))
        except SettingError as e:
            raise SettingError(f"{name}: {e}") from None
    lo, hi, step = vals
    if lo is not None and hi is not None and lo > hi:
        raise SettingError("min is above max")
    if step is not None and step <= 0:
        raise SettingError("step must be positive")
    return lo, hi, step


def _check_bounds(b: Tuple[Optional[int], Optional[int], Optional[int]], v: int, show: Any) -> None:
    lo, hi, step = b
    if lo is not None and v < lo:
        raise SettingError(f"must be at least {show(lo)}")
    if hi is not None and v > hi:
        raise SettingError(f"must be at most {show(hi)}")
    if step is not None:
        base = lo if lo is not None else 0
        if abs(v - base) % step != 0:
            if base != 0:
                raise SettingError(f"must be {show(base)} plus a multiple of {show(step)}")
            raise SettingError(f"must be a multiple of {show(step)}")


def _go_g4(x: float) -> str:
    """Go's %.4g."""
    s = f"{x:.4g}"
    if "e" in s:
        mant, exp = s.split("e")
        s = f"{mant}e{exp[0]}{int(exp[1:]):02d}"
    return s


_BINARY_LABELS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"]


def show_size(n: int) -> str:
    """units.CustomSize("%.4g %s", n, 1024, binary labels)."""
    x, i = float(n), 0
    while x >= 1024 and i < len(_BINARY_LABELS) - 1:
        x /= 1024
        i += 1
    return f"{_go_g4(x)} {_BINARY_LABELS[i]}"


def show_duration(s: int) -> str:
    if s == 0:
        return "0s"
    out = ""
    for n, label in ((86400, "d"), (3600, "h"), (60, "m"), (1, "s")):
        if s >= n:
            out += f"{s // n}{label}"
            s %= n
    return out


# sizeInputRe: a number with an optional binary unit (GB / G refused: GB
# means 10^9, never 2^30). go-units RAMInBytes accepts a superset of it.
SIZE_INPUT_RE = re.compile(r"([0-9]{1,20}(?:\.[0-9]{1,12})?) ?((?:[kmgtp]i)?b)?", re.IGNORECASE | re.ASCII)
SIZE_MULTIPLIERS = {"": 1, "b": 1, "kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40, "pib": 1 << 50}


def parse_size(raw: Any) -> int:
    """settings.parseSize: "10GiB", "10 GiB", "512" or a number of bytes.
    RAMInBytes goes through float64; the exact value must agree with it."""
    from fractions import Fraction
    if _is_number(raw):
        v = _to_int(raw)
        if v < 0:
            raise SettingError("a size can't be negative")
        return v
    if not isinstance(raw, str):
        raise SettingError(f"want a size such as 10GiB, not {_type_name(raw)}")
    m = SIZE_INPUT_RE.fullmatch(raw)
    if not m:
        raise SettingError(f"{json.dumps(raw)} is not a size: use a number with B, KiB, MiB, GiB, TiB or PiB (binary units)")
    mult = SIZE_MULTIPLIERS[(m.group(2) or "").lower()]
    approx = float(m.group(1)) * float(mult)
    exact = Fraction(m.group(1)) * mult
    if exact.denominator != 1 or not INT64_MIN <= exact.numerator <= INT64_MAX or approx >= 2.0 ** 63 \
            or int(approx) != exact.numerator:
        raise SettingError(f"{json.dumps(raw)} is not a whole number of bytes, or too large")
    return exact.numerator


MAX_SECONDS = INT64_MAX // 10 ** 9


def parse_duration_value(raw: Any) -> int:
    """settings.parseDuration: "30d", "1h30m" or a number of seconds."""
    if _is_number(raw):
        v = _to_int(raw)
        if not 0 <= v <= MAX_SECONDS:
            raise SettingError(f"a duration is 0-{MAX_SECONDS} seconds")
        return v
    if not isinstance(raw, str):
        raise SettingError(f"want a duration such as 30d or 90m, not {_type_name(raw)}")
    try:
        ns = go_parse_duration(raw, _STR2DUR_UNITS)
    except ValueError:
        raise SettingError(f"{json.dumps(raw)} is not a duration (e.g. 30d, 12h, 90m, 45s)") from None
    if ns < 0:
        raise SettingError("a duration can't be negative")
    if ns % 10 ** 9:
        raise SettingError(f"{json.dumps(raw)}: durations are whole seconds")
    return ns // 10 ** 9


def _check_choices(cs: Any) -> None:
    if not cs:
        raise SettingError("options: at least one {value, label}")
    seen: Set[str] = set()
    for c in cs:
        val, label = _str(c, "value"), _str(c, "label")
        if val == "" or blen(val) > 128 or has_control(val):
            raise SettingError(f"options: value {json.dumps(val)} must be 1-128 characters without control characters")
        if val in seen:
            raise SettingError(f"options: value {json.dumps(val)} listed twice")
        seen.add(val)
        if label == "" or blen(label) > 64 or has_control(label):
            raise SettingError(f"options: value {json.dumps(val)} needs a single-line label of at most 64 characters")


def _choice_values(cs: Any) -> List[str]:
    return [_str(c, "value") for c in cs or []]


def _parse_choice(cs: Any, raw: Any) -> str:
    vals = _choice_values(cs)
    if not isinstance(raw, str):
        raise SettingError(f"want one of {', '.join(vals)}, not {_type_name(raw)}")
    if raw not in vals:
        raise SettingError(f"{json.dumps(raw)} is not one of {', '.join(vals)}")
    return raw


def _check_item_bounds(o: Dict[str, Any]) -> None:
    for name in ("min_items", "max_items"):
        if _has(o, name) and not 0 <= o[name] <= 1000:
            raise SettingError(f"{name} must be 0-1000")
    if _has(o, "min_items") and _has(o, "max_items") and o["min_items"] > o["max_items"]:
        raise SettingError("min_items is above max_items")


def _count_items(o: Dict[str, Any], n: int) -> None:
    if n > 1000:
        raise SettingError("at most 1000 items")
    if _has(o, "min_items") and n < o["min_items"]:
        raise SettingError(f"needs at least {o['min_items']} items")
    if _has(o, "max_items") and n > o["max_items"]:
        raise SettingError(f"takes at most {o['max_items']} items")


def _sub_option(o: Dict[str, Any], spec: Any) -> Dict[str, Any]:
    """itemOption / columnOption: an item type or column as an option."""
    spec = spec if isinstance(spec, dict) else {}
    out = {"key": o.get("key"), "type": _str(spec, "type")}
    for f in ("pattern", "format", "min_len", "max_len", "min", "max", "options"):
        if f in spec:
            out[f] = spec[f]
    return out


LIST_ITEM_TYPES = ("string", "int", "bool", "enum")


def _kind_check(o: Dict[str, Any]) -> None:
    """Each kind's CheckOption (manifest-time constraints of its type)."""
    t = o.get("type")
    if t == "string":
        _only_fields(o, "pattern", "format", "min_len", "max_len")
        if _str(o, "pattern"):
            _compile_pattern(_str(o, "pattern"))
        if _str(o, "format") and _str(o, "format") not in STRING_FORMATS:
            raise SettingError(f"format {json.dumps(_str(o, 'format'))} must be one of {', '.join(sorted(STRING_FORMATS))}")
        _check_lens(o.get("min_len"), o.get("max_len"))
    elif t == "int":
        _only_fields(o, "min", "max", "step", "unit")
        unit = _str(o, "unit")
        if unit and (blen(unit) > 32 or has_control(unit)):
            raise SettingError("unit must be a single line of at most 32 characters")
        _read_bounds(o, _to_int)
    elif t == "size":
        _only_fields(o, "min", "max", "step", "allow_unlimited")
        _read_bounds(o, parse_size)
    elif t == "duration":
        _only_fields(o, "min", "max")
        _read_bounds(o, parse_duration_value)
    elif t == "bool":
        _only_fields(o)
    elif t == "enum":
        _only_fields(o, "options")
        _check_choices(o.get("options"))
    elif t == "multi_enum":
        _only_fields(o, "options", "min_items", "max_items")
        _check_choices(o.get("options"))
        _check_item_bounds(o)
    elif t == "list":
        _only_fields(o, "items", "min_items", "max_items")
        if not _has(o, "items"):
            raise SettingError("a list needs items: {type: string | int | bool | enum}")
        io = _sub_option(o, o["items"])
        if io["type"] not in LIST_ITEM_TYPES:
            raise SettingError(f"items: type {json.dumps(io['type'])} must be string, int, bool or enum")
        try:
            _kind_check(io)
        except SettingError as e:
            raise SettingError(f"items: {e}") from None
        _check_item_bounds(o)
    elif t == "table":
        _only_fields(o, "columns", "key_column", "min_items", "max_items")
        cols = o.get("columns") or []
        if not cols:
            raise SettingError("a table needs at least one column")
        seen: Set[str] = set()
        for c in cols:
            name, label = _str(c, "name"), _str(c, "label")
            if not COLUMN_NAME_RE.fullmatch(name):
                raise SettingError(f"columns: name {json.dumps(name)} must match ^{COLUMN_NAME_RE.pattern}$")
            if name in seen:
                raise SettingError(f"columns: {name} listed twice")
            seen.add(name)
            if label == "" or blen(label) > 64 or has_control(label):
                raise SettingError(f"columns: {name} needs a single-line label of at most 64 characters")
            co = _sub_option(o, c)
            if co["type"] not in LIST_ITEM_TYPES:
                raise SettingError(f"columns: {name}: type {json.dumps(co['type'])} must be string, int, bool or enum")
            try:
                _kind_check(co)
            except SettingError as e:
                raise SettingError(f"columns: {name}: {e}") from None
        kc = _str(o, "key_column")
        if kc and kc not in seen:
            raise SettingError(f"key_column {kc} is not a column")
        _check_item_bounds(o)
    elif t in ("group", "user"):
        _only_fields(o)
    elif t in ("groups", "users"):
        _only_fields(o, "min_items", "max_items")
        _check_item_bounds(o)
    elif t == "path":
        _only_fields(o, "target", "mode", "needs")
        mode, needs = _str(o, "mode"), _str(o, "needs")
        if mode not in ("", "ro", "rw"):
            raise SettingError(f"mode {json.dumps(mode)} must be ro or rw")
        if needs not in ("", "read", "write"):
            raise SettingError(f"needs {json.dumps(needs)} must be read or write")
        if mode == "ro" and needs == "write":
            raise SettingError("needs: write with mode: ro: the app could never write there")
    elif t == "secret":
        _only_fields(o, "min_len", "max_len")
        if _has(o, "default"):
            raise SettingError("a secret takes no default (set it, or declare generate)")
        _check_lens(o.get("min_len"), o.get("max_len"))


def _parse_one_name(user: bool, raw: Any) -> str:
    if not isinstance(raw, str):
        raise SettingError(f"want a name, not {_type_name(raw)}")
    if user:
        if "@" in raw:
            raise SettingError(f"{json.dumps(raw)}: want a username, not an email address")
        if not raw.isascii():
            raise SettingError(f"{json.dumps(raw)} is not a valid username (ASCII only)")
        u = raw.lower()
        if not USERNAME_RE.fullmatch(u):
            raise SettingError(f"{json.dumps(raw)} is not a valid username")
        return u
    if not GROUP_NAME_RE.fullmatch(raw):
        raise SettingError(f"{json.dumps(raw)} is not a valid group name")
    return raw


def setting_value(o: Dict[str, Any], raw: Any) -> Any:
    """Registry.Parse: raw (YAML-decoded) as a canonical value of option o
    (sizes bytes, durations seconds, UNLIMITED); SettingError if refused."""
    t = o.get("type")
    if raw is None:
        raise SettingError("no value")
    if t == "string":
        if not isinstance(raw, str):
            raise SettingError(f"want a string, not {_type_name(raw)}")
        _check_text(raw)
        n = len(raw)
        if n > 65535:
            raise SettingError("must be at most 65535 characters")
        if _has(o, "min_len") and n < o["min_len"]:
            raise SettingError(f"must be at least {o['min_len']} characters")
        if _has(o, "max_len") and n > o["max_len"]:
            raise SettingError(f"must be at most {o['max_len']} characters")
        fmt = _str(o, "format")
        if fmt:
            f = STRING_FORMATS.get(fmt)
            if f is None:
                raise SettingError(f"unknown format {json.dumps(fmt)}")
            why = f(raw)
            if why:
                raise SettingError(f"{json.dumps(raw)} is not a valid {fmt}: {why}")
        if _str(o, "pattern"):
            if not _compile_pattern(_str(o, "pattern")).match(raw):
                raise SettingError(f"{json.dumps(raw)} doesn't match the pattern {_str(o, 'pattern')}")
        return raw
    if t == "int":
        v = _parse_decimal(raw) if isinstance(raw, str) else _to_int(raw)
        _check_bounds(_read_bounds(o, _to_int), v, str)
        return v
    if t == "size":
        if raw is UNLIMITED or raw == "unlimited":
            if not o.get("allow_unlimited"):
                raise SettingError("unlimited is not allowed here")
            return UNLIMITED
        v = parse_size(raw)
        _check_bounds(_read_bounds(o, parse_size), v, show_size)
        return v
    if t == "duration":
        v = parse_duration_value(raw)
        _check_bounds(_read_bounds(o, parse_duration_value), v, show_duration)
        return v
    if t == "bool":
        if not isinstance(raw, bool):
            raise SettingError(f"want true or false, not {_gofmt(raw)}")
        return raw
    if t == "enum":
        return _parse_choice(o.get("options"), raw)
    if t == "multi_enum":
        if not isinstance(raw, list):
            raise SettingError(f"want a list, not {_type_name(raw)}")
        chosen = {_parse_choice(o.get("options"), it) for it in raw}
        out = [c for c in _choice_values(o.get("options")) if c in chosen]
        _count_items(o, len(out))
        return out
    if t == "list":
        if not isinstance(raw, list):
            raise SettingError(f"want a list, not {_type_name(raw)}")
        io = _sub_option(o, o.get("items"))
        if io["type"] not in LIST_ITEM_TYPES:
            raise SettingError(f"items: unknown type {json.dumps(io['type'])}")
        _count_items(o, len(raw))
        out, seen = [], set()
        for i, it in enumerate(raw, 1):
            try:
                val = setting_value(io, it)
            except SettingError as e:
                raise SettingError(f"item {i}: {e}") from None
            k = (type(val).__name__, val)
            if o.get("unique"):
                if k in seen:
                    raise SettingError(f"item {i}: duplicate {_gofmt(val)} (items must be unique)")
                seen.add(k)
            out.append(val)
        return out
    if t == "table":
        if not isinstance(raw, list):
            raise SettingError(f"want a list, not {_type_name(raw)}")
        _count_items(o, len(raw))
        cols = {_str(c, "name"): c for c in o.get("columns") or []}
        kc = _str(o, "key_column")
        keys: Dict[Any, int] = {}
        out = []
        for i, row in enumerate(raw, 1):
            if not isinstance(row, dict) or not all(isinstance(k, str) for k in row):
                raise SettingError(f"row {i}: want a record {{column: value}}, not {_type_name(row)}")
            for name in sorted(row):
                if name not in cols:
                    raise SettingError(f"row {i}: {name} is not a column")
            rec = {}
            for c in o.get("columns") or []:
                name = _str(c, "name")
                present = name in row
                cv = row.get(name)
                if not present or cv is None or cv == "":
                    if c.get("required") or name == kc:
                        raise SettingError(f"row {i}: {name} is required")
                    if not present or cv is None:
                        continue
                try:
                    rec[name] = setting_value(_sub_option(o, c), cv)
                except SettingError as e:
                    raise SettingError(f"row {i}: {name}: {e}") from None
            if kc:
                k = (type(rec.get(kc)).__name__, rec.get(kc))
                if k in keys:
                    raise SettingError(f"row {i}: duplicate {kc} {_gofmt(rec.get(kc))} (also in row {keys[k]})")
                keys[k] = i
            out.append(rec)
        return out
    if t in ("group", "user"):
        return _parse_one_name(t == "user", raw)
    if t in ("groups", "users"):
        if not isinstance(raw, list):
            raise SettingError(f"want a list, not {_type_name(raw)}")
        names = set()
        for i, it in enumerate(raw, 1):
            try:
                names.add(_parse_one_name(t == "users", it))
            except SettingError as e:
                raise SettingError(f"item {i}: {e}") from None
        _count_items(o, len(names))
        return sorted(names)
    if t == "path":
        if not isinstance(raw, str):
            raise SettingError(f"want a host directory as a string, not {_type_name(raw)}")
        if raw.startswith("folder:"):
            raise SettingError(f"{json.dumps(raw)} names a shared folder: shared folders arrive in project 2")
        if has_control(raw) or ":" in raw:
            raise SettingError(f"path {json.dumps(raw)} may not contain ':' or control characters")
        if not raw.startswith("/"):
            raise SettingError(f"path {json.dumps(raw)} must be absolute")
        c = go_clean(raw)
        if c == "/":
            raise SettingError(f"path {json.dumps(raw)}: the host's / can't be mounted")
        return c
    if t == "secret":
        if not isinstance(raw, str):
            raise SettingError("want a string")
        if raw == "":
            raise SettingError("a secret can't be empty (clear it instead)")
        if blen(raw) > 4096:
            raise SettingError("a secret is at most 4096 bytes")
        if "'" in raw:
            raise SettingError("a secret can't contain ' (env values are single-quoted)")
        if has_control(raw):
            raise SettingError("the secret contains control characters (newlines included)")
        if _has(o, "min_len") and len(raw) < o["min_len"]:
            raise SettingError(f"must be at least {o['min_len']} characters")
        if _has(o, "max_len") and len(raw) > o["max_len"]:
            raise SettingError(f"must be at most {o['max_len']} characters")
        return raw
    raise SettingError(f"unknown type {json.dumps(t)}")


# ── renders (settings/render.go) ──

SIZE_RENDER_UNITS = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
                     "KB": 10 ** 3, "MB": 10 ** 6, "GB": 10 ** 9, "TB": 10 ** 12}
DURATION_RENDER_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
LIST_LIKE = {"list", "multi_enum", "groups", "users"}


def scope_of(o: Dict[str, Any]) -> str:
    return _str(o, "scope") or "instance"


def render_of(d: Dict[str, Any]) -> Dict[str, Any]:
    """RenderOf: inside a claim, header or file delivery; on the delivery for env and hook."""
    for k in ("claim", "header", "file"):
        if isinstance(d.get(k), dict):
            return d[k].get("render") or {}
    return d.get("render") or {}


def delivery_name(d: Dict[str, Any]) -> str:
    if _str(d, "env"):
        return "env " + _str(d, "env")
    for k in ("claim", "header", "file"):
        if isinstance(d.get(k), dict):
            return f"{k} {_str(d[k], 'name')}"
    if _str(d, "hook"):
        return "hook " + _str(d, "hook")
    return "delivery"


def _check_render(o: Dict[str, Any], rd: Dict[str, Any]) -> None:
    t, unit = o.get("type"), _str(rd, "unit")
    if unit:
        if t == "size":
            if unit not in SIZE_RENDER_UNITS:
                raise SettingError(f"unit {json.dumps(unit)} must be B, KiB, MiB, GiB, TiB, KB, MB, GB or TB")
        elif t == "duration":
            if unit not in DURATION_RENDER_UNITS:
                raise SettingError(f"unit {json.dumps(unit)} must be s, m, h or d")
        elif t == "int":
            if unit != _str(o, "unit"):
                raise SettingError(f"unit {json.dumps(unit)} must be the option's unit {json.dumps(_str(o, 'unit'))} (an int is not converted)")
        else:
            raise SettingError("unit is for size, duration and int options")
    if rd.get("integer") and t not in ("size", "duration"):
        raise SettingError("integer is for size and duration options")
    if _has(rd, "unlimited"):
        if t != "size" or not o.get("allow_unlimited"):
            raise SettingError("unlimited is for size options with allow_unlimited")
        if _str(rd, "unlimited") == "" or has_control(_str(rd, "unlimited")):
            raise SettingError("unlimited must be a non-empty single-line string")
    elif t == "size" and o.get("allow_unlimited"):
        raise SettingError("allow_unlimited needs render.unlimited (the value the app takes for unlimited, e.g. \"-1\")")
    for name in ("true", "false"):
        if not _has(rd, name):
            continue
        if t != "bool":
            raise SettingError(f"{name} is for bool options")
        if has_control(_str(rd, name)):
            raise SettingError(f"{name} must be a single-line string")
    collection = t in LIST_LIKE or scope_of(o) == "person_entered"
    if _has(rd, "join"):
        if not collection:
            raise SettingError("join is for list, multi_enum, groups and users options (and person_entered collections)")
        if _str(rd, "join") == "" or has_control(_str(rd, "join")):
            raise SettingError("join must be a non-empty separator without newlines or control characters")
        if _str(rd, "format"):
            raise SettingError("join and format exclude each other")
    fmt = _str(rd, "format")
    if fmt in ("yaml", "csv"):
        if not collection and t != "table":
            raise SettingError(f"format {fmt} is for list, multi_enum, groups, users and table options (and person_entered collections)")
    elif fmt not in ("", "json"):
        raise SettingError(f"format {json.dumps(fmt)} must be json, yaml or csv")


def check_option_kind(o: Dict[str, Any]) -> None:
    """Registry.CheckOption: the kind's constraints, each delivery's render,
    the default and the group_values as values of o."""
    _kind_check(o)
    deliveries = o.get("delivery") if isinstance(o.get("delivery"), list) else []
    if o.get("type") == "size" and o.get("allow_unlimited") and not deliveries:
        raise SettingError("allow_unlimited needs deliveries that say how unlimited is rendered (render.unlimited)")
    for d in deliveries:
        try:
            _check_render(o, render_of(d) if isinstance(d, dict) else {})
        except SettingError as e:
            raise SettingError(f"{delivery_name(d)}: render: {e}") from None
    if _has(o, "default"):
        try:
            setting_value(o, o["default"])
        except SettingError as e:
            raise SettingError(f"default {_gofmt(o['default'])}: {e}") from None
    gv = o.get("group_values") if isinstance(o.get("group_values"), dict) else {}
    for g in sorted(gv, key=str):
        try:
            setting_value(o, gv[g])
        except SettingError as e:
            raise SettingError(f"group_values[{g}] {_gofmt(gv[g])}: {e}") from None


# ── compose interpolation (settings.go referenced / interpolations) ──

def _interpolations(s: str, rx: Any) -> List[Any]:
    """rx's matches compose interpolates: one preceded by an odd run of $ is escaped."""
    out = []
    for m in rx.finditer(s):
        run, i = 0, m.start() - 1
        while i >= 0 and s[i] == "$":
            run += 1
            i -= 1
        if run % 2 == 0:
            out.append(m)
    return out


def compose_references(s: str, name: str) -> bool:
    """Whether compose interpolates ${name} in s."""
    return bool(_interpolations(s, re.compile(r"\$\{" + re.escape(name) + r"(\}|:?[-?+])")))


def _string_values(x: Any, out: List[str]) -> None:
    """scalarValues: every decoded string value (mapping keys excluded)."""
    if isinstance(x, str):
        out.append(x)
    elif isinstance(x, dict):
        for val in x.values():
            _string_values(val, out)
    elif isinstance(x, list):
        for e in x:
            _string_values(e, out)


def compose_environment(services: Dict[str, Any]) -> Dict[str, Dict[str, Optional[str]]]:
    """composeEnvironment: service → name → value (None = passed through)."""
    out: Dict[str, Dict[str, Optional[str]]] = {}
    for svc, s in services.items():
        env: Dict[str, Optional[str]] = {}
        raw = s.get("environment") if isinstance(s, dict) else None
        if isinstance(raw, dict):
            for k, val in raw.items():
                env[str(k)] = None if val is None else scalar_text(val)
        elif isinstance(raw, list):
            for e in raw:
                k, eq, val = scalar_text(e).partition("=")
                env[k] = val if eq else None
        out[str(svc)] = env
    return out


def option_env_names(o: Dict[str, Any]) -> List[str]:
    """Option.EnvNames: every env variable o's env deliveries write (indexed
    NAME_{n} expanded to NAME_1 … NAME_<max_items>); an instance option
    without deliveries writes UPPER(key) (a path none)."""
    out: List[str] = []

    def add(n: str) -> None:
        if n.endswith(INDEX_SUFFIX):
            mi = o.get("max_items")
            if isinstance(mi, int) and not isinstance(mi, bool):
                out.extend(f"{n[:-len(INDEX_SUFFIX)]}_{i}" for i in range(1, min(mi, MAX_INDEXED) + 1))
            return
        out.append(n)
    deliveries = o.get("delivery")
    if scope_of(o) == "instance" and not deliveries:
        if o.get("type") != "path" and isinstance(o.get("key"), str):
            add(o["key"].upper())
        return out
    for d in deliveries if isinstance(deliveries, list) else []:
        if isinstance(d, dict) and _str(d, "env"):
            add(_str(d, "env"))
    return out


def setting_options(m: Dict[str, Any]) -> List[Dict[str, Any]]:
    s = m.get("settings")
    opts = s.get("options") if isinstance(s, dict) else None
    return [o for o in opts if isinstance(o, dict)] if isinstance(opts, list) else []


def settings_env_names(m: Dict[str, Any]) -> List[str]:
    return [n for o in setting_options(m) for n in option_env_names(o)]


def reserved_var(k: str) -> bool:
    """templates.ReservedVar: the instance variables the Hub sets."""
    return k in INSTANCE_VARS or k.startswith(INSTANCE_VAR_PREFIXES)


def reserved_use(o: Dict[str, Any]) -> Tuple[str, str]:
    """reservedUse: what of o is reserved (projects 2 / 3), and for which feature."""
    t = o.get("type")
    if t == "folder":
        return "type folder", FEATURE_FOLDERS
    if t in ("person_secret", "person_id"):
        return f"type {t}", FEATURE_SHARING
    for f, feat, on in (("folder", FEATURE_FOLDERS, _has(o, "folder")), ("checks", FEATURE_FOLDERS, _has(o, "checks")),
                        ("hash", FEATURE_SHARING, _str(o, "hash") != ""),
                        ("length", FEATURE_SHARING, o.get("length") not in (None, 0)),
                        ("revoke_on_leave", FEATURE_SHARING, _has(o, "revoke_on_leave")),
                        ("on_restore", FEATURE_SHARING, _str(o, "on_restore") != ""),
                        ("pool", FEATURE_SHARING, _str(o, "pool") != ""),
                        ("username", FEATURE_SHARING, _has(o, "username")),
                        ("mount", FEATURE_SHARING, _has(o, "mount"))):
        if on:
            return f, feat
    if isinstance(o.get("delivery"), str):
        return "delivery: " + o["delivery"], FEATURE_SHARING
    return "", ""


def applies_of(o: Dict[str, Any]) -> str:
    """The effective applies (§13.9 defaults: claims next_sign_in, headers next_request, else restart)."""
    if _str(o, "applies"):
        return _str(o, "applies")
    for d in o.get("delivery") if isinstance(o.get("delivery"), list) else []:
        if isinstance(d, dict) and isinstance(d.get("claim"), dict):
            return "next_sign_in"
        if isinstance(d, dict) and isinstance(d.get("header"), dict):
            return "next_request"
    return "restart"


def check_id_shape(app_id: str) -> Optional[str]:
    """templates.CheckIDShape: no portcullis segment, its own Normalize form."""
    for seg in re.split(r"[^a-zA-Z0-9]+", app_id):
        if seg.lower() == "portcullis":
            return (f"id {json.dumps(app_id)}: portcullis may not be a segment of an id (Traefik's automatic names "
                    f"<service>-portcullis-<id> of two instances could collide)")
    if not ID_NORMAL_RE.fullmatch(app_id):
        return (f"id {json.dumps(app_id)}: write it as letters and digits joined by single - (Traefik turns _, -- and a "
                f"trailing - into the same automatic name as another id)")
    return None


def traefik_enable(labels: Dict[str, str]) -> Tuple[bool, Optional[str]]:
    """templates.TraefikEnable: exactly true or false, set once (folded keys)."""
    key, on = None, False
    for k in sorted(labels):
        if fold_key(k) != "traefik.enable":
            continue
        if key is not None:
            a, b = sorted((key, k))
            return False, f"traefik.enable is set twice ({json.dumps(a)} and {json.dumps(b)})"
        key = k
        val = labels[k]
        if val == "true":
            on = True
        elif val != "false":
            return False, (f"traefik.enable is {json.dumps(val)}: write true or false (Traefik also reads 1, t, TRUE, … as "
                           "on; the Hub accepts only these two)")
    return on, None


_ROUTER_SVC_NAME_RE = re.compile(r"^traefik\.(?:http|tcp|udp)\.(?:routers|services)\.([^.]+)\.")
_HTTP_SERVICE_RE = re.compile(r"^traefik\.http\.services\.([^.]+)\.")
_HTTP_ROUTER_NAME_RE = re.compile(r"^traefik\.http\.routers\.([a-z0-9][a-z0-9_-]*)\.(.+)$")


def auto_name_key(svc: str) -> str:
    """autoNameKey: Traefik's provider.Normalize part of <svc>_<project>."""
    return re.sub(r"[^a-zA-Z0-9]+", "-", svc).strip("-").lower()


def check_traefik_routes(t: Template, services: Dict[str, Any], r: Report) -> None:
    """ParseRoutes' refusals beyond the rule form (routes.go): automatic-name
    look-alikes, Traefik services or HTTP routers on two compose services,
    automatic names that normalise alike, traefik.enable exactly true/false."""
    tsvc_owner: Dict[str, str] = {}
    router_owner: Dict[str, str] = {}
    auto_owner: Dict[str, str] = {}
    for sname in sorted(services, key=str):
        svc = services[sname]
        if not isinstance(svc, dict):
            continue
        where = f"{t.c_where}: services.{sname}"
        labels = labels_of(svc)
        for k in sorted(labels):
            m = _ROUTER_SVC_NAME_RE.match(fold_key(k))
            if m and ("-portcullis-" in m.group(1) or m.group(1).endswith("-portcullis")):
                r.error(where, f"Traefik name {m.group(1)} looks like an automatic service name (<compose service>-portcullis-<id>, "
                               "which Traefik gives a container's routers without a service label) and would merge with it: "
                               "names may not contain -portcullis- or end with -portcullis", HUB_HINT)
        for name in sorted({m.group(1) for k in labels for m in [_HTTP_SERVICE_RE.match(k)] if m}):
            if name in tsvc_owner:
                r.error(t.c_where, f"Traefik service {name} is defined on services {tsvc_owner[name]} and {sname} (Traefik would "
                                   "merge them into one load balancer): give each its own name", HUB_HINT)
            else:
                tsvc_owner[name] = str(sname)
        enabled, why = traefik_enable(labels)
        if why:
            r.error(where, why, HUB_HINT)
        if enabled:
            key = auto_name_key(str(sname))
            if key in auto_owner:
                r.error(t.c_where, f"services {auto_owner[key]} and {sname} would get the same automatic Traefik service name "
                                   f"(Traefik turns every run of characters other than letters and digits into -, "
                                   f"{key}-portcullis-<id>) and be merged into one load balancer: rename one of them", HUB_HINT)
            else:
                auto_owner[key] = str(sname)
            if not any(_HTTP_ROUTER_NAME_RE.match(k) for k in labels) and \
                    not any(k.startswith(("traefik.tcp.", "traefik.udp.")) for k in labels):
                r.error(where, "traefik.enable=true without an HTTP router rule (Traefik would apply its default rule)", HUB_HINT)
        for name in sorted({m.group(1) for k in labels for m in [_HTTP_ROUTER_NAME_RE.match(k)] if m}):
            if fold_key(name) in router_owner:
                r.error(t.c_where, f"router {name} is defined on services {router_owner[fold_key(name)]} and {sname}: give each its own name", HUB_HINT)
            else:
                router_owner[fold_key(name)] = str(sname)


class _Refuse(Exception):
    pass


class _SpecCheck:
    """ValidateSettingsSpec over one template (contract §13)."""

    def __init__(self, t: Template, services: Dict[str, Any], routers: Dict[str, Dict[str, str]], r: Report) -> None:
        self.t, self.r = t, r
        self.m: Dict[str, Any] = t.manifest or {}
        self.auth: Dict[str, Any] = self.m.get("auth") if isinstance(self.m.get("auth"), dict) else {}
        self.services = {str(k): (s if isinstance(s, dict) else {}) for k, s in services.items()}
        self.routers = routers
        self.env = compose_environment(self.services)
        self.scalars: List[str] = []
        _string_values(t.compose or {}, self.scalars)
        self.files: Dict[str, Dict[str, Any]] = {}
        self.hooks: Dict[str, Dict[str, Any]] = {}
        self.opts: Dict[str, Dict[str, Any]] = {}
        self.claims: Dict[Tuple[str, str], str] = {}
        self.headers: Dict[str, str] = {}
        self.fields: Dict[Tuple[str, str, str], str] = {}
        # routes (templates.Routes): Traefik services per compose service,
        # network_mode, Traefik-labelled services.
        self.traefik_services: Dict[str, List[str]] = {}
        self.network_mode: Dict[str, str] = {}
        self.labelled: Set[str] = set()
        for name, s in self.services.items():
            labels = labels_of(s)
            self.traefik_services[name] = sorted({m.group(1) for k in labels for m in [_HTTP_SERVICE_RE.match(k)] if m})
            nm = s.get("network_mode")
            self.network_mode[name] = nm if isinstance(nm, str) else ""
            if any(fold_key(k).startswith("traefik.") for k in labels):
                self.labelled.add(name)

    def err(self, msg: str, hint: str = SETTINGS_HINT) -> None:
        self.r.error(self.t.m_where, msg, hint)

    def run(self) -> None:
        self.check_files()
        self.check_hooks()
        self.check_reload()
        spec = self.m.get("settings")
        if not isinstance(spec, dict):
            return
        sections = spec.get("sections") or []
        seen: Set[str] = set()
        for s in sections:
            s = scalar_text(s)
            if not SECTION_RE.fullmatch(s):
                self.err(f"settings.sections: {json.dumps(s)} must match ^{SECTION_RE.pattern}$")
            elif s in seen:
                self.err(f"settings.sections: {json.dumps(s)} listed twice")
            seen.add(s)
        self.sections = seen
        bad: Set[int] = set()
        options = setting_options(self.m)
        for i, o in enumerate(options):
            key = _str(o, "key")
            if not OPTION_KEY_RE.fullmatch(key):
                self.err(f"setting {key}: key must match ^{OPTION_KEY_RE.pattern}$ (an identifier, not an env name)")
                bad.add(i)
                continue
            if key in self.opts:
                self.err(f"setting {key}: declared twice")
                bad.add(i)
                continue
            why = self.type_problem(o)
            if why:
                self.err(f"setting {key}: {why}")
                bad.add(i)
            self.opts[key] = o
        self.check_env_names(options, bad)
        for i, o in enumerate(options):
            if i in bad:
                continue
            try:
                self.option(o)
                check_option_kind(o)
            except (_Refuse, SettingError) as e:
                self.err(f"setting {_str(o, 'key')}: {e}")
                continue
            self.warnings(o)

    # files / hooks / reload

    def has_trigger(self, tr: str) -> bool:
        return any(tr in (h.get("when") or []) for h in self.m.get("hooks") or [] if isinstance(h, dict))

    def check_files(self) -> None:
        files = [f for f in self.m.get("files") or [] if isinstance(f, dict)]
        for i, f in enumerate(files):
            name, svc, mount = _str(f, "name"), _str(f, "service"), _str(f, "mount")
            w = f"files[{name}]"
            omc = _str(f, "on_membership_change")
            problems = []
            if not FILE_HOOK_NAME_RE.fullmatch(name):
                problems.append(f"name must match ^{FILE_HOOK_NAME_RE.pattern}$")
            elif name in self.files:
                problems.append("declared twice")
            if svc not in self.services:
                problems.append(f"service {svc} is not in compose.yml")
            if not valid_mount(mount):
                problems.append(f"mount {json.dumps(mount)} must be an absolute, clean container directory (no ':')")
            if omc in ("", "none", "restart"):
                pass
            elif omc == "reload":
                if self.m.get("reload") is None:
                    problems.append("on_membership_change: reload needs the template's reload action")
            elif omc == "hook":
                if not self.has_trigger("membership_change"):
                    problems.append("on_membership_change: hook needs a hook with when: [membership_change]")
            else:
                problems.append(f"on_membership_change {json.dumps(omc)} must be restart, reload, hook or none")
            for g in files[:i]:
                if _str(g, "service") == svc and _nested(_str(g, "mount"), mount):
                    problems.append(f"mount {mount} collides with files[{_str(g, 'name')}] ({_str(g, 'mount')}) on service {svc}")
            for o in setting_options(self.m):
                tg = o.get("target") if isinstance(o.get("target"), dict) else None
                if o.get("type") == "path" and tg and _str(tg, "service") == svc and _nested(_str(tg, "mount"), mount):
                    problems.append(f"mount {mount} collides with setting {_str(o, 'key')}'s target {_str(tg, 'mount')} on service {svc}")
            for p in problems:
                self.err(f"{w}: {p}")
            self.files.setdefault(name, f)

    def check_hooks(self) -> None:
        for h in [h for h in self.m.get("hooks") or [] if isinstance(h, dict)]:
            name, svc = _str(h, "name"), _str(h, "service")
            w = f"hooks[{name}]"
            problems = []
            if not FILE_HOOK_NAME_RE.fullmatch(name):
                problems.append(f"name must match ^{FILE_HOOK_NAME_RE.pattern}$")
            elif name in self.hooks:
                problems.append("declared twice")
            if svc not in self.services:
                problems.append(f"service {svc} is not in compose.yml")
            cmd = h.get("command") or []
            if not cmd:
                problems.append("command must be a non-empty argv list (run directly, no sh -c)")
            elif any(scalar_text(a) == "" or has_control(scalar_text(a)) for a in cmd):
                problems.append("command arguments must be non-empty, without control characters")
            if has_control(_str(h, "user")):
                problems.append("user contains control characters")
            when = h.get("when") or []
            if not when:
                problems.append("when must list at least one trigger (start, settings_change, membership_change)")
            for tr in when:
                if tr not in HOOK_TRIGGERS:
                    problems.append(f"when {json.dumps(scalar_text(tr))} must be start, settings_change or membership_change")
            if _has(h, "timeout"):
                try:
                    ns = go_parse_duration(scalar_text(h["timeout"]))
                    if ns < 0 or ns > HOOK_MAX_TIMEOUT:
                        problems.append(f"timeout {scalar_text(h['timeout'])} must be between 0 (default 30s) and 10m0s")
                except ValueError as e:
                    problems.append(f"duration {json.dumps(scalar_text(h['timeout']))}: time: {e}")
            for p in problems:
                self.err(f"{w}: {p}")
            self.hooks.setdefault(name, h)

    def check_reload(self) -> None:
        rl = self.m.get("reload")
        if not isinstance(rl, dict):
            return
        hook, svc, sig = _str(rl, "hook"), _str(rl, "service"), _str(rl, "signal")
        if hook and (svc or sig):
            self.err("reload: either {service, signal} or {hook}, not both")
        elif hook:
            if hook not in self.hooks:
                self.err(f"reload: hook {hook} is not declared in hooks")
        else:
            if svc not in self.services:
                self.err(f"reload: service {json.dumps(svc)} is not in compose.yml")
            if sig not in RELOAD_SIGNALS:
                self.err(f"reload: signal {json.dumps(sig)} must be HUP, USR1 or USR2")

    # options

    def type_problem(self, o: Dict[str, Any]) -> str:
        t = _str(o, "type")
        if t in OLD_TYPES:
            return f"type {t} is template contract v2: {OLD_TYPES[t]}"
        what, feat = reserved_use(o)
        if feat:
            return f"{what} needs {feat}, which this Hub doesn't implement"
        if t not in BUILTIN_TYPES:
            return f"unknown type {json.dumps(t)}"
        return ""

    def check_env_names(self, options: List[Dict[str, Any]], bad: Set[int]) -> None:
        m = self.m
        owner: Dict[str, str] = {}
        for e in m.get("env") or []:
            if isinstance(e, dict) and _str(e, "key"):
                owner[_str(e, "key")] = "env[] " + _str(e, "key")
        for p in m.get("ports") or []:
            if isinstance(p, dict) and _str(p, "key"):
                owner[_str(p, "key")] = "ports[] " + _str(p, "key")
                owner[_str(p, "key") + "_BIND"] = "ports[] " + _str(p, "key") + " (bind)"
        for c in m.get("keycloak_clients") or []:
            if isinstance(c, dict) and _str(c, "secret_env"):
                owner[_str(c, "secret_env")] = f"keycloak client {_str(c, 'client_id')} secret_env"
        for i, o in enumerate(options):
            if i in bad:
                continue
            key = _str(o, "key")
            try:
                for d in o.get("delivery") if isinstance(o.get("delivery"), list) else []:
                    n = _str(d, "env") if isinstance(d, dict) else ""
                    if not n:
                        continue
                    if n.endswith(INDEX_SUFFIX):
                        self.indexed(o, n[:-len(INDEX_SUFFIX)])
                    elif "{" in n:
                        raise _Refuse(f"env name {json.dumps(n)}: the only indexed form is NAME_{{n}}")
                for n in option_env_names(o):
                    if not ENV_KEY_RE.fullmatch(n):
                        raise _Refuse(f"env name {json.dumps(n)} must match ^{ENV_KEY_RE.pattern}$")
                    if reserved_var(n) or n.startswith("PORTCULLIS_"):
                        raise _Refuse(f"env name {n} is reserved (PORTCULLIS_*: core and the Hub set them)")
                    if n in owner:
                        raise _Refuse(f"env name {n} is already used by {owner[n]}")
                    owner[n] = "setting " + key
                    for svc in sorted(self.env):
                        val = self.env[svc].get(n, "\0absent")
                        if val is not None and val != "\0absent" and not compose_references(val, n):
                            raise _Refuse(f"compose.yml hard-codes {n} in service {svc}'s environment (use ${{{n}}})")
                    if not any(compose_references(s, n) for s in self.scalars):
                        raise _Refuse(f"env name {n} is not referenced as ${{{n}}} in compose.yml")
            except _Refuse as e:
                self.err(f"setting {key}: {e}")
                bad.add(i)

    def indexed(self, o: Dict[str, Any], prefix: str) -> None:
        if o.get("type") != "list" or scope_of(o) != "instance":
            raise _Refuse(f"indexed env {prefix}{INDEX_SUFFIX} is for instance list options only")
        mi = o.get("max_items")
        if not isinstance(mi, int) or isinstance(mi, bool) or not 1 <= mi <= MAX_INDEXED:
            raise _Refuse(f"indexed env {prefix}{INDEX_SUFFIX} needs max_items (1-{MAX_INDEXED})")
        rx = re.compile(r"\$\{" + re.escape(prefix) + r"_([0-9]+)(\}|:?[-?+])")
        for sc in self.scalars:
            for mm in _interpolations(sc, rx):
                n = int(mm.group(1)) if len(mm.group(1)) <= 18 else 0
                if n < 1 or n > mi:
                    raise _Refuse(f"compose.yml references {prefix}_{mm.group(1)}, beyond max_items {mi}")

    def identityless(self) -> bool:
        a = self.auth
        nl = a.get("native_login") if isinstance(a.get("native_login"), dict) else {}
        return a.get("method") in ("public", "custom") or bool(nl.get("allow_without_gateway"))

    def option(self, o: Dict[str, Any]) -> None:
        label, desc = _str(o, "label"), _str(o, "description")
        if label == "" or blen(label) > 64 or has_control(label):
            raise _Refuse("label must be a single non-empty line of at most 64 characters")
        if blen(desc) > 500 or any(c != "\n" and is_control_rune(c) for c in desc):
            raise _Refuse("description must be at most 500 characters, without control characters")
        sec = _str(o, "section")
        if sec and sec not in self.sections:
            raise _Refuse(f"section {json.dumps(sec)} is not listed in settings.sections")
        scope = scope_of(o)
        if scope not in SCOPES:
            raise _Refuse(f"scope {json.dumps(_str(o, 'scope'))} must be instance, person, group or person_entered")
        applies = _str(o, "applies")
        if applies and applies not in APPLIES:
            raise _Refuse(f"applies {json.dumps(applies)} must be live, reload, next_request, next_sign_in, restart or account_creation")
        if scope == "person_entered":
            self.person_entered(o)
        t = o.get("type")
        sv = o.get("self_visible")
        if o.get("privileged") and scope != "person":
            raise _Refuse("privileged needs scope: person")
        if sv is not None and scope != "person" and not (scope == "person_entered" and sv):
            raise _Refuse("self_visible needs scope: person")
        if (_str(o, "resolve") or o.get("resolve_choices")) and scope != "person":
            raise _Refuse("resolve and resolve_choices need scope: person")
        if _has(o, "group_values") and scope != "person":
            raise _Refuse("group_values need scope: person")
        if o.get("admin_override") and scope != "person_entered":
            raise _Refuse("admin_override needs scope: person_entered")
        if scope == "person" and not _has(o, "default"):
            raise _Refuse("scope person needs a default (the value for everyone else with access)")
        if scope == "group" and _has(o, "default"):
            raise _Refuse("scope group takes no default (the group records are the values)")
        if o.get("unique") and t != "list" and not (scope == "person_entered" and t in ("string", "int")):
            raise _Refuse("unique is for list options and person_entered string / int options")
        if _has(o, "generate") and t != "secret":
            raise _Refuse("generate is for secret options")
        if _has(o, "writes_as") and t != "path":
            raise _Refuse("writes_as is for path options")
        if t == "path" and scope != "instance":
            raise _Refuse("a path option must have scope instance")
        if applies == "reload" and self.m.get("reload") is None:
            raise _Refuse("applies: reload needs the template's reload action")
        self.resolve(o)
        self.group_values(o)
        self.privileged(o)
        self.requires(o)
        self.path_and_secret(o)
        self.deliveries(o)

    def person_entered(self, o: Dict[str, Any]) -> None:
        t = o.get("type")
        if t not in PERSON_ENTERED_TYPES:
            if t == "secret":
                raise _Refuse("scope person_entered can't be a secret: a per-person credential is person_secret (project 3)")
            raise _Refuse(f"scope person_entered is for string, int, bool or enum options, not {t}")
        for field, on in (("default", _has(o, "default")), ("required", bool(o.get("required"))),
                          ("resolve", _str(o, "resolve") != ""), ("resolve_choices", bool(o.get("resolve_choices"))),
                          ("group_values", _has(o, "group_values")), ("privileged", bool(o.get("privileged"))),
                          ("requires", bool(o.get("requires"))),
                          ("self_visible: false (people always see their own value)", o.get("self_visible") is False),
                          ("applies: account_creation", _str(o, "applies") == "account_creation")):
            if on:
                raise _Refuse(f"scope person_entered takes no {field}")
        if o.get("unique") and t not in ("string", "int"):
            raise _Refuse("unique is for person_entered string / int options")
        if t == "string":
            if not _has(o, "max_len") and not _str(o, "pattern") and not _str(o, "format"):
                raise _Refuse(f"a person_entered string needs max_len (at most {PERSON_ENTERED_MAX_LEN}), a pattern or a format")
            if _has(o, "max_len") and o["max_len"] > PERSON_ENTERED_MAX_LEN:
                raise _Refuse(f"a person_entered string's max_len is at most {PERSON_ENTERED_MAX_LEN}")
        if self.identityless() and not _str(self.auth, "access_group"):
            raise _Refuse("scope person_entered on a template whose routes can run without Portcullis identity (method public / "
                          "custom, or the app's own login only) needs auth.access_group (who may enter a value)")
        applies = applies_of(o)
        for d in o.get("delivery") if isinstance(o.get("delivery"), list) else []:
            if not isinstance(d, dict):
                continue
            if _str(d, "env"):
                rd = d.get("render") if isinstance(d.get("render"), dict) else None
                if rd is None or (not _has(rd, "join") and _str(rd, "format") != "json"):
                    raise _Refuse("a person_entered env delivery is the list of values: it needs render.join or render.format: json")
                if applies != "restart":
                    raise _Refuse("a person_entered env delivery needs applies: restart")
            elif isinstance(d.get("file"), dict):
                f = self.files.get(_str(d["file"], "name"))
                if f is None:
                    continue
                omc = _str(f, "on_membership_change")
                want = {"restart": "restart", "reload": "reload", "hook": "live"}.get(omc, "")
                if not want:
                    raise _Refuse(f"file {_str(f, 'name')} has no on_membership_change: person-entered values reach it only "
                                  "through the membership path")
                if applies != want:
                    raise _Refuse(f"applies {applies} doesn't match file {_str(f, 'name')}'s on_membership_change {omc} "
                                  f"(want applies: {want})")
            elif _str(d, "hook"):
                h = self.hooks.get(_str(d, "hook"))
                if h is None:
                    continue
                if applies != "live":
                    raise _Refuse("a person_entered hook delivery needs applies: live")
                if "membership_change" not in (h.get("when") or []):
                    raise _Refuse(f"hook {_str(h, 'name')} needs membership_change in its when to deliver person-entered values")
            elif isinstance(d.get("claim"), dict):
                if applies != "next_sign_in":
                    raise _Refuse(f"a claim delivery applies at next_sign_in, not {applies}")
            elif isinstance(d.get("header"), dict):
                if applies != "next_request":
                    raise _Refuse(f"a header delivery applies at next_request, not {applies}")

    def resolve(self, o: Dict[str, Any]) -> None:
        def fits(rule: str) -> None:
            if rule not in RESOLVE_TYPES:
                raise _Refuse(f"resolve {rule} must be max, min, priority, union, intersection, any or all")
            types = RESOLVE_TYPES[rule]
            if types is not None and o.get("type") not in types:
                raise _Refuse(f"resolve {rule} doesn't fit type {o.get('type')}")
        if _str(o, "resolve"):
            fits(_str(o, "resolve"))
        for rule in o.get("resolve_choices") or []:
            try:
                fits(scalar_text(rule))
            except _Refuse as e:
                raise _Refuse(f"resolve_choices: {scalar_text(rule)}: {e}") from None

    def group_values(self, o: Dict[str, Any]) -> None:
        gv = o.get("group_values") if isinstance(o.get("group_values"), dict) else {}
        for k in gv:
            if k == PLACEHOLDER_ACCESS:
                if not _str(self.auth, "access_group"):
                    raise _Refuse(f"group_values: {k} needs auth.access_group")
                if o.get("privileged"):
                    raise _Refuse(f"group_values: {k} on a privileged option would give everyone with access a privileged "
                                  f"value: use {PLACEHOLDER_ADMIN}")
            elif k == PLACEHOLDER_ADMIN:
                if not _str(self.auth, "admin_group"):
                    raise _Refuse(f"group_values: {k} needs auth.admin_group")
            else:
                raise _Refuse(f"group_values: {json.dumps(scalar_text(k))}: only the placeholders {PLACEHOLDER_ACCESS} and "
                              f"{PLACEHOLDER_ADMIN} (the admin picks other groups)")

    def privileged(self, o: Dict[str, Any]) -> None:
        if not o.get("privileged"):
            return
        t = o.get("type")
        if t == "enum":
            cs = o.get("options") or []
            if not cs:
                raise _Refuse("an enum needs options")
            low = _str(cs[0], "value")
            if not isinstance(o.get("default"), str) or o["default"] != low:
                raise _Refuse(f"a privileged option's default must be its lowest-ranked value {json.dumps(low)}")
        elif t == "bool":
            if o.get("default") is not False:
                raise _Refuse("a privileged option's default must be its lowest-ranked value false")
        else:
            raise _Refuse("privileged is for enum and bool options (a role, an admin flag)")

    def requires(self, o: Dict[str, Any]) -> None:
        reqs = [scalar_text(k) for k in o.get("requires") or []]
        if reqs and scope_of(o) != "instance":
            raise _Refuse("requires is for instance options")
        for k in reqs:
            ro = self.opts.get(k)
            if k == _str(o, "key"):
                raise _Refuse("requires names itself")
            if ro is None:
                raise _Refuse(f"requires {k}: no such option")
            if scope_of(ro) != "instance":
                raise _Refuse(f"requires {k}: not an instance option")

    def path_and_secret(self, o: Dict[str, Any]) -> None:
        if o.get("type") == "path":
            tg = o.get("target") if isinstance(o.get("target"), dict) else None
            if tg is None:
                raise _Refuse("a path option needs a target {service, mount}")
            if _str(tg, "service") not in self.services:
                raise _Refuse(f"target service {json.dumps(_str(tg, 'service'))} is not in compose.yml")
            if not valid_mount(_str(tg, "mount")):
                raise _Refuse(f"target mount {json.dumps(_str(tg, 'mount'))} must be an absolute, clean container path (no ':')")
            if o.get("delivery"):
                raise _Refuse("a path option is delivered as its target mount: no delivery")
        wa = o.get("writes_as")
        if isinstance(wa, dict):
            for what in ("uid", "gid"):
                ref = wa.get(what)
                if isinstance(ref, int) and not isinstance(ref, bool):
                    if ref < 0:
                        raise _Refuse(f"writes_as.{what} must be non-negative")
                elif isinstance(ref, str) and ref != "":
                    ro = self.opts.get(ref)
                    if ro is None or scope_of(ro) != "instance" or ro.get("type") not in ("int", "string"):
                        raise _Refuse(f"writes_as.{what}: {ref} is not an instance int or string option")
                else:
                    raise _Refuse(f"writes_as.{what}: a number or an option key")
        g = o.get("generate")
        if isinstance(g, dict):
            length = g.get("length") if isinstance(g.get("length"), int) else 0
            if not 8 <= length <= 128:
                raise _Refuse(f"generate.length {length} must be 8-128")
            if _str(g, "charset") not in GENERATE_CHARSETS:
                raise _Refuse(f"generate.charset {json.dumps(_str(g, 'charset'))} must be hex, alphanumeric or ascii_printable")

    def deliveries(self, o: Dict[str, Any]) -> None:
        scope = scope_of(o)
        ds = [d if isinstance(d, dict) else {} for d in (o.get("delivery") if isinstance(o.get("delivery"), list) else [])]
        if not ds:
            if scope == "person":
                raise _Refuse("scope person needs a per-person delivery (claim, header, file or hook)")
            if scope in ("group", "person_entered"):
                raise _Refuse(f"scope {scope} needs a delivery")
        per_person = hook = False
        for d in ds:
            kinds = [bool(_str(d, "env")), isinstance(d.get("claim"), dict), isinstance(d.get("header"), dict),
                     isinstance(d.get("file"), dict), bool(_str(d, "hook"))]
            if sum(kinds) != 1:
                raise _Refuse("each delivery is exactly one of env, claim, header, file or hook")
            if _has(d, "render") and not _str(d, "env") and not _str(d, "hook"):
                raise _Refuse("render goes inside a claim, header or file delivery")
            if _str(d, "env"):
                if scope == "person":
                    raise _Refuse("per-person env is not allowed (one env for every person): deliver through a claim, header, file or hook")
                if scope == "group":
                    rd = d.get("render") if isinstance(d.get("render"), dict) else {}
                    if _str(rd, "format") != "json":
                        raise _Refuse("a scope group env delivery is the map of records: it needs render.format: json")
            elif isinstance(d.get("claim"), dict):
                per_person = True
                self.claim(o, d["claim"])
            elif isinstance(d.get("header"), dict):
                per_person = True
                self.header(o, d["header"])
            elif isinstance(d.get("file"), dict):
                per_person = True
                self.file(o, d["file"])
                hook = hook or _str(self.files[_str(d["file"], "name")], "on_membership_change") == "hook"
            elif _str(d, "hook"):
                per_person = hook = True
                if _str(d, "hook") not in self.hooks:
                    raise _Refuse(f"hook {_str(d, 'hook')} is not declared in hooks")
        if scope == "person" and not per_person:
            raise _Refuse("scope person needs a per-person delivery (claim, header, file or hook)")
        if _str(o, "applies") == "live" and not hook:
            raise _Refuse("applies: live means a hook applies it: add a hook delivery (or a file with on_membership_change: hook)")

    def claim(self, o: Dict[str, Any], c: Dict[str, Any]) -> None:
        if scope_of(o) not in ("person", "person_entered"):
            raise _Refuse("a claim delivery is for scope person or person_entered")
        method = _str(self.auth, "method")
        if method != "native-oidc":
            raise _Refuse(f"a claim delivery needs auth.method native-oidc (not {method})")
        client, name, jt = _str(c, "client"), _str(c, "name"), _str(c, "json_type")
        if client not in {_str(k, "client_id") for k in self.m.get("keycloak_clients") or [] if isinstance(k, dict)}:
            raise _Refuse(f"claim: client {client} is not a keycloak_clients[] client_id")
        if not CLAIM_NAME_RE.fullmatch(name):
            raise _Refuse(f"claim {json.dumps(name)}: name must match ^{CLAIM_NAME_RE.pattern}$")
        if name in RESERVED_CLAIMS or name.startswith(("attr_", "portcullis_")):
            raise _Refuse(f"claim {name} is reserved (standard, Keycloak, attr_* and portcullis_* claims)")
        if jt and jt not in CLAIM_JSON_TYPES:
            raise _Refuse(f"claim {name}: json_type {json.dumps(jt)} must be int, string, bool or json")
        why = claim_type_problem(o, c)
        if why:
            raise _Refuse(f"claim {name}: {why}")
        if (client, name) in self.claims:
            raise _Refuse(f"claim {name} on client {client} is already delivered by setting {self.claims[(client, name)]}")
        self.claims[(client, name)] = _str(o, "key")

    def net_ns(self, svc: str) -> Optional[str]:
        """Routes.NetNS: network_mode service:X followed; "host"; None = a cycle or unknown target."""
        seen: Set[str] = set()
        while True:
            if svc in seen:
                return None
            seen.add(svc)
            nm = self.network_mode.get(svc, "")
            if nm == "host":
                return "host"
            if not nm.startswith("service:"):
                return svc
            nxt = nm[len("service:"):]
            if nxt not in self.network_mode:
                return None
            svc = nxt

    def router_target(self, ri: Dict[str, str]) -> Optional[str]:
        ts = ri.get("service", "").strip()
        if ts == "":
            return ri.get("_service")
        base, _, prov = ts.partition("@")
        if prov and fold_key(prov) != "docker":
            return None
        for svc in sorted(self.traefik_services):
            if any(fold_key(n) == fold_key(base) for n in self.traefik_services[svc]):
                return svc
        return None

    def header(self, o: Dict[str, Any], h: Dict[str, Any]) -> None:
        if scope_of(o) not in ("person", "person_entered"):
            raise _Refuse("a header delivery is for scope person or person_entered")
        name = _str(h, "name")
        if not HEADER_NAME_RE.fullmatch(name):
            raise _Refuse(f"header {json.dumps(name)} must be X-Forwarded-Attr-<Name>")
        a = self.auth
        nl = a.get("native_login") if isinstance(a.get("native_login"), dict) else None
        if a.get("method") == "public" or (a.get("method") == "custom" and not (nl and nl.get("supported") is True)):
            raise _Refuse(f"header {name}: method {a.get('method')} routes carry no Portcullis identity (no per-person values, "
                          "and clients could forge the header)")
        if nl and nl.get("allow_without_gateway"):
            raise _Refuse(f"header {name}: the app may run with its own login only (no Portcullis in front): clients could forge the header")
        for svc in sorted(self.network_mode):
            ns = self.net_ns(svc)
            if ns is None:
                raise _Refuse(f"header {name}: service {svc}'s network_mode doesn't resolve to a service of the template (a cycle?): "
                              "the Hub can't tell which backend its routers reach")
            if ns == "host" and svc in self.labelled:
                raise _Refuse(f"header {name}: service {svc} has Traefik labels and runs in the host's network namespace "
                              "(network_mode host): it can reach any port on the host, the delivering backend's included")
        gated: Set[str] = set()
        target: Dict[str, str] = {}
        routers = {n: ri for n, ri in self.routers.items() if "rule" in ri}
        for rn in sorted(routers):
            ri = routers[rn]
            tg = self.router_target(ri)
            if tg is None:
                raise _Refuse(f"header {name}: router {rn}'s service {ri.get('service', '').strip()} isn't one of the template's "
                              "own services: the Hub can't tell which backend it reaches")
            ns = self.net_ns(tg)
            if ns is None:
                raise _Refuse(f"header {name}: router {rn}'s backend has a network_mode the Hub can't resolve")
            target[rn] = ns
            if "portcullis-groups@docker" in split_middlewares(ri.get("middlewares", "")):
                gated.add(ns)
        if not gated:
            raise _Refuse(f"header {name} needs routers with portcullis-groups@docker (group-gate returns the header)")
        for rn in sorted(routers):
            mws = split_middlewares(routers[rn].get("middlewares", ""))
            if target[rn] in gated and not any(m in FORWARD_AUTH_MWS for m in mws):
                raise _Refuse(f"header {name}: router {rn} reaches service {target[rn]} (its network namespace) without Portcullis "
                              "forward-auth: clients could forge the header there")
        k = name.lower()
        if k in self.headers:
            raise _Refuse(f"header {name} is already delivered by setting {self.headers[k]}")
        self.headers[k] = _str(o, "key")

    def file(self, o: Dict[str, Any], fd: Dict[str, Any]) -> None:
        fname = _str(fd, "name")
        if fname not in self.files:
            raise _Refuse(f"file {fname} is not declared in files")
        scope = scope_of(o)
        if scope in ("instance", "group"):
            if _str(fd, "field"):
                raise _Refuse(f"file {fname}: field is for person and person_entered options (this option is the file's "
                              f"{json.dumps(_str(o, 'key'))} entry)")
            return
        section = "people" if scope == "person" else "entries"
        field = _str(fd, "field") or _str(o, "key")
        if not FIELD_RE.fullmatch(field):
            raise _Refuse(f"file {fname}: field {json.dumps(field)} must match ^{FIELD_RE.pattern}$")
        k = (fname, section, field)
        if k in self.fields:
            raise _Refuse(f"file {fname}: field {field} is already written by setting {self.fields[k]}")
        self.fields[k] = _str(o, "key")

    def warnings(self, o: Dict[str, Any]) -> None:
        """Advice the Hub gives at run time rather than at discover."""
        key = _str(o, "key")
        ds = [d for d in o.get("delivery") or [] if isinstance(d, dict)] if isinstance(o.get("delivery"), list) else []
        if scope_of(o) == "instance" and _str(o, "applies") in ("live", "reload") and any(_str(d, "env") for d in ds):
            self.r.warn(self.t.m_where, f"setting {key}: applies {_str(o, 'applies')} with an env delivery: a change still "
                                        "restarts the app (the env is read at start)",
                        "deliver it only through the hook / reload path, or declare applies: restart")
        values = ([o["default"]] if _has(o, "default") else []) + \
            (list(o["group_values"].values()) if isinstance(o.get("group_values"), dict) else [])
        for d in ds:
            rd = render_of(d)
            unit = _str(rd, "unit")
            units = SIZE_RENDER_UNITS if o.get("type") == "size" else DURATION_RENDER_UNITS if o.get("type") == "duration" else {}
            if not rd.get("integer") or not unit or unit not in units:
                continue
            for raw in values:
                val = setting_value(o, raw)
                if isinstance(val, int) and val % units[unit]:
                    shown = show_size(val) if o.get("type") == "size" else show_duration(val)
                    self.r.warn(self.t.m_where, f"setting {key}: {delivery_name(d)}: {shown} is not a whole number of {unit}: "
                                                "the Hub refuses this value at save", "pick a default on the delivery's unit")
        for d in ds:
            f = self.files.get(_str(d["file"], "name")) if isinstance(d.get("file"), dict) else None
            if o.get("type") != "secret" or f is None:
                continue
            user = scalar_text(self.services.get(_str(f, "service"), {}).get("user")).split(":", 1)[0]
            if user and user not in ("0", "root", "10001"):
                self.r.warn(self.t.m_where, f"setting {key}: service {_str(f, 'service')} runs as {user} but "
                                            f"{_str(f, 'name')}.secrets.json is 0600 (root or uid 10001 only)",
                            "run the reading service as root or user: \"10001\" (contract §13.7)")


def claim_type_problem(o: Dict[str, Any], c: Dict[str, Any]) -> str:
    """templates.claimTypeFits: a json_type the claim's render can't produce."""
    rd = c.get("render") if isinstance(c.get("render"), dict) else {}
    jt, t = _str(c, "json_type"), o.get("type")

    def numeric(int32: bool) -> str:
        if t in ("int", "duration"):
            pass
        elif t == "size":
            if int32 and _str(rd, "unit") in ("", "B"):
                return (f"json_type {jt}: a size in bytes overflows the 32-bit integer Keycloak converts to: render it in a "
                        "unit (render.unit: MiB, GiB, …)")
        else:
            return f"json_type {jt} needs a number: type {t} doesn't render as one"
        if o.get("allow_unlimited"):
            if not _has(rd, "unlimited"):
                return f"json_type {jt}: render.unlimited must be set"
            u = _str(rd, "unlimited")
            if int32:
                if not re.fullmatch(r"[+-]?[0-9]+", u) or not -(1 << 31) <= int(u) < (1 << 31):
                    return f"json_type {jt}: render.unlimited {json.dumps(u)} must be a 32-bit integer"
            else:
                try:
                    json.loads(u, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
                except ValueError:
                    return f"json_type {jt}: render.unlimited {json.dumps(u)} must be JSON (a number or null)"
        return ""

    def boolean() -> str:
        if t != "bool":
            return f"json_type {jt} needs type bool (not {t})"
        if (_has(rd, "true") and _str(rd, "true") != "true") or (_has(rd, "false") and _str(rd, "false") != "false"):
            return f"json_type {jt}: render.true / render.false must be exactly true / false"
        return ""
    if jt == "int":
        return numeric(True)
    if jt == "bool":
        return boolean()
    if jt == "json":
        if _str(rd, "format") == "json" or (t == "table" and _str(rd, "format") == ""):
            return ""
        if t in ("int", "size", "duration"):
            return numeric(False)
        if t == "bool":
            return boolean()
        return f"json_type {jt}: type {t} renders plain text: add render.format: json"
    return ""


def check_settings(t: Template, services: Dict[str, Any], routers: Dict[str, Dict[str, str]], r: Report) -> None:
    """Template contract v3 settings, files, hooks and reload (contracts §13),
    as the Hub's ValidateSettingsSpec and settings.Registry check them."""
    m = t.manifest or {}
    if isinstance(m.get("settings"), list):
        r.error(t.m_where, "settings: a list of settings is template contract v2; contract v3 declares settings: "
                           "{sections, options} (integration contracts §13)", SETTINGS_HINT)
        return
    if t.schema_errors & set(SETTINGS_SHAPE_KEYS):
        return   # the schema errors above say what to fix first
    _SpecCheck(t, services, routers, r).run()


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
