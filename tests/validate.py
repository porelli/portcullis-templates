#!/usr/bin/env python3
"""Static validation for Portcullis app templates.

Checks every <app-id>/manifest.yaml against schema/manifest.schema.json and
enforces the repository rules a JSON Schema cannot express (they need the
compose file, the filesystem, or more than one template at once). No Docker
needed.

    pip install -r tests/requirements.txt
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
import textwrap
import unicodedata
from urllib.parse import urlsplit
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
try:
    import re2  # google-re2: setting patterns are RE2, as in the Hub (Go regexp)
except ImportError:  # pragma: no cover
    sys.exit("validate.py needs google-re2: pip install -r tests/requirements.txt")

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
    # Kubernetes (§2): the CIDR of the only peers that may send identity
    # headers (Traefik's /32 on Docker/Podman, the pod CIDR on Kubernetes),
    # read only in exactly this default form (SOURCE_VARS).
    "PORTCULLIS_TRAEFIK_SOURCE": "172.31.250.2/32",
    # AI support (§2): mcp-gate's range (its /32, or the pod CIDR).
    # Referencing it is allowed; declaring it is not (ai_reserved_var).
    "PORTCULLIS_MCP_GATE_SOURCE": "172.31.250.3/32",
}
VAR_TRAEFIK_SOURCE = "PORTCULLIS_TRAEFIK_SOURCE"
TRAEFIK_SOURCE_REF = "${PORTCULLIS_TRAEFIK_SOURCE:-172.31.250.2/32}"
# A CIDR default that differs would widen or move the trust: exactly the
# default form, nothing else (no other operator, no bare $NAME).
SOURCE_VARS = {"PORTCULLIS_TRAEFIK_SOURCE", "PORTCULLIS_MCP_GATE_SOURCE"}
# Core settings that are not template variables (§2): the Hub doesn't copy
# them into instances; refused anywhere in a template's files, any form.
REMOVED_VARS = {"PORTCULLIS_TRAEFIK_IP": "PORTCULLIS_TRAEFIK_SOURCE", "PORTCULLIS_MCP_GATE_IP": "PORTCULLIS_MCP_GATE_SOURCE"}
REMOVED_VARS_RE = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(sorted(REMOVED_VARS)) + r")(?![A-Za-z0-9_])")
SOURCE_HINT = (f"see {DOCS_URL}/integration-contracts/ (§2, PORTCULLIS_TRAEFIK_SOURCE): an IPv4 CIDR; "
               "a setting that can't take a CIDR gets the nginx gate (esphome/gate.sh) in front")

# Subdomains owned by core (group-gate-map.conf); templates must not route them.
CORE_SUBDOMAINS = {"auth", "traefik", "hub", "directory", "enroll", "metrics", "people", "mcp"}  # contracts §4, §5.1

# Contract v2 (contracts §3.1): instance-scoped variables the Hub writes into
# every instance's .env. Templates use them in the default form with the
# default instance's value and never declare them in the manifest.
# PORTCULLIS_LOCAL_NETWORKS (file sharing, F36): read only as exactly
# ${PORTCULLIS_LOCAL_NETWORKS} (check_reserved_var_refs), never in the
# default form the other instance variables take.
VAR_LOCAL_NETWORKS = "PORTCULLIS_LOCAL_NETWORKS"
# AI support (§3.1, §2): every PORTCULLIS_AI_* name is the Hub's (ENABLED,
# READONLY_<COMPANION>, PROVIDER_<NAME>_<FIELD>); PORTCULLIS_MCP_GATE_SOURCE
# (and the removed PORTCULLIS_MCP_GATE_IP) are core's. A manifest never declares them (check_manifest_rules); compose
# reads only ${PORTCULLIS_AI_ENABLED:-false} and its own companions'
# ${PORTCULLIS_AI_READONLY_<C>:-true} (check_ai).
VAR_AI_PREFIX = "PORTCULLIS_AI_"
VAR_AI_ENABLED = "PORTCULLIS_AI_ENABLED"
VAR_AI_READONLY = "PORTCULLIS_AI_READONLY_"
VAR_AI_PROVIDER = "PORTCULLIS_AI_PROVIDER_"
VAR_MCP_GATE_SOURCE = "PORTCULLIS_MCP_GATE_SOURCE"
VAR_MCP_GATE_IP = "PORTCULLIS_MCP_GATE_IP"
AI_HINT = f"see {DOCS_URL}/integration-contracts/#32-ai-support-the-ai-block-new-ai-support and CONTRIBUTING.md, \"AI support\""
VPN_HINT = f"see {DOCS_URL}/integration-contracts/ (§3.3, the vpn: block) and CONTRIBUTING.md, \"VPN providers\""
VAR_VPN_PREFIX = "PORTCULLIS_VPN_"
INSTANCE_VARS = {"PORTCULLIS_INSTANCE", "PORTCULLIS_OIDC_CLIENT_ID", "PORTCULLIS_ACCESS_GROUP", "PORTCULLIS_ADMIN_GROUP",
                 VAR_LOCAL_NETWORKS}
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
     r"^\+\$\{PORTCULLIS_TRAEFIK_SOURCE:-172\.31\.250\.2/32\}(,\+127\.0\.0\.1)?(,\+\[::1\])?$",
     "Pi-hole without a password must set FTLCONF_webserver_acl to +${PORTCULLIS_TRAEFIK_SOURCE:-172.31.250.2/32} "
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
    ("OPENID_SESSION_SECRET", r".", "ALLOW_EMAIL_LOGIN", r"(?i)^false$",
     "LibreChat with OpenID must set ALLOW_EMAIL_LOGIN: \"false\" (password login next to SSO)"),
    ("OPENID_SESSION_SECRET", r".", "ALLOW_REGISTRATION", r"(?i)^false$",
     "LibreChat with OpenID must set ALLOW_REGISTRATION: \"false\" (local sign-up; the first local account becomes "
     "LibreChat's administrator)"),
    ("OPENID_SESSION_SECRET", r".", "ALLOW_SHARED_LINKS_PUBLIC", r"(?i)^false$",
     "LibreChat must set ALLOW_SHARED_LINKS_PUBLIC: \"false\" (public shared links show a conversation, and what "
     "the person's apps returned in it, to anyone with the link)"),
    ("OPENID_SESSION_SECRET", r".", "OPENID_REQUIRED_ROLE", r"^\$\{PORTCULLIS_ACCESS_GROUP:-[^}]+\}$",
     "LibreChat must set OPENID_REQUIRED_ROLE: ${PORTCULLIS_ACCESS_GROUP:-users_<app>} (with "
     "OPENID_REQUIRED_ROLE_PARAMETER_PATH: groups): otherwise every realm user signs in"),
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
    ("ghcr.io/librechat-ai/librechat:", "config",
     "LibreChat's librechat.yaml (the MCP server, the model endpoints, no secret values) is rendered by the "
     "config one-shot from the Hub's ai-providers.json; keep it"),
    ("ghcr.io/porelli/firefox-sync:", "firefox-sync-init",
     "Firefox Sync's tokenserver takes any Mozilla account; only the firefox-sync-init allowlist trigger keeps other accounts off"),
]

# image prefix -> (one-shot the image's Traefik-routed services must wait for, message)
REQUIRED_BEFORE_ROUTED = [
    ("ghcr.io/librechat-ai/librechat:", "config",
     "LibreChat must start only after config rendered librechat.yaml (depends_on: config: condition: "
     "service_completed_successfully); without it LibreChat starts on its defaults"),
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


_BOOL_TAG = "tag:yaml.org,2002:bool"


def _construct_key(loader: yaml.SafeLoader, key_node: yaml.Node, deep: bool) -> Any:
    """A mapping key; a plain `true` / `false` key keeps its text, as the
    Hub's yaml.v3 matches struct fields by it (`render: {true: "on"}` is the
    field "true"; `TRUE:` matches no field and stays a boolean)."""
    if isinstance(key_node, yaml.ScalarNode) and key_node.tag == _BOOL_TAG and key_node.value in ("true", "false"):
        return key_node.value
    return loader.construct_object(key_node, deep=deep)


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> Dict[Any, Any]:
    seen: Set[Any] = set()
    for key_node, _ in node.value:
        key = _construct_key(loader, key_node, deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    loader.flatten_mapping(node)   # merge keys (<<), as SafeLoader.construct_mapping
    mapping: Dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = _construct_key(loader, key_node, deep)
        try:
            hash(key)
        except TypeError:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark, "found unhashable key", key_node.start_mark) from None
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _refuse_binary(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    """CheckTags: !!binary decodes to text no check sees (compose reads
    [!!binary MDYwMDAx] as "060001", gid 60001)."""
    raise yaml.constructor.ConstructorError(
        None, None, "YAML tag !!binary is not allowed (a binary scalar decodes to text no check sees)", node.start_mark)


_UniqueKeyLoader.add_constructor("tag:yaml.org,2002:binary", _refuse_binary)
# Read plain scalars as the Hub's yaml.v3 does (YAML 1.2 core schema): only
# true / false are booleans (yes / no / on / off stay strings, so
# `traefik.enable: yes` and `default: yes` are refused as the Hub refuses
# them), timestamps and base-60 numbers (`1:30`) stay strings.
_DROPPED_TAGS = (_BOOL_TAG, "tag:yaml.org,2002:timestamp", "tag:yaml.org,2002:int", "tag:yaml.org,2002:float")
_UniqueKeyLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag not in _DROPPED_TAGS]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()}
_UniqueKeyLoader.add_implicit_resolver(
    _BOOL_TAG, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF"))
# SafeLoader's int and float resolvers without their base-60 forms.
_UniqueKeyLoader.add_implicit_resolver("tag:yaml.org,2002:int", re.compile(r"""^(?:[-+]?0b[0-1_]+
    |[-+]?0[0-7_]+
    |[-+]?(?:0|[1-9][0-9_]*)
    |[-+]?0x[0-9a-fA-F_]+)$""", re.X), list("-+0123456789"))
_UniqueKeyLoader.add_implicit_resolver("tag:yaml.org,2002:float", re.compile(r"""^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?
    |\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?
    |[-+]?\.(?:inf|Inf|INF)
    |\.(?:nan|NaN|NAN))$""", re.X), list("-+0123456789."))


def compose_bool(v: Any) -> Optional[bool]:
    """A boolean compose field as compose-go reads it (loader toBoolean):
    true / false, or (deprecated) y / yes / on and n / no / off, any case;
    None for anything else (compose refuses it)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        low = v.lower()
        if low in ("true", "y", "yes", "on"):
            return True
        if low in ("false", "n", "no", "off"):
            return False
    return None


def scalar_text(v: Any) -> str:
    """A decoded YAML scalar as the Hub reads it into a string (Go's
    fmt.Sprint: booleans lowercase)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    return "" if v is None else str(v)


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


def var_names_deep(text: str) -> Set[str]:
    """Every variable name text interpolates, nested defaults included
    (${A:-${B}} gives A and B); $$ is a literal dollar."""
    out: Set[str] = set()
    for name, _op, rest in iter_var_refs(text):
        out.add(name)
        out |= var_names_deep(rest)
    return out


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
        # compose user: / group_add per service (check_folders, compose_ids).
        self.compose_users: Dict[str, str] = {}
        self.compose_group_add: Dict[str, List[str]] = {}

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
    if e.validator == "required" and not e.absolute_path and "'ai'" in e.message:
        return e.message + " (AI support: ai.mcp companions or ai.unsupported with a one-line reason; see CONTRIBUTING.md, \"AI support\")"
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
        if ai_reserved_var(k):
            r.error(t.m_where, f"{section} key {k} is reserved (AI support: PORTCULLIS_AI_* are the Hub's, "
                               f"{VAR_MCP_GATE_SOURCE} is core's)", AI_HINT)
        if k.startswith(VAR_VPN_PREFIX):
            r.error(t.m_where, f"{section} key {k} is reserved (VPN-only access: PORTCULLIS_VPN_* are core's and the Hub's)",
                    VPN_HINT)
        if k == VAR_COMPOSE_PROFILES:
            r.error(t.m_where, f"{k} is an instance variable the Hub sets — a manifest may not declare it", SETUP_HINT)
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

    if auth.get("method") in ("forward-auth", "header-auth") and auth.get("group_access") is False:
        r.warn(t.m_where, f"auth.method {auth['method']} with group_access: false lets every Portcullis user in",
               "set group_access: true and access_group: users_<app> unless that is intended")


LINKS_HINT = "see CONTRIBUTING.md, \"Adding an app\" (links): the project's own homepage and its canonical upstream repository"
# links.source on a known code host must be the repository itself (no
# tree/blob/release pages, no .git, no trailing slash), by URL path.
SOURCE_HOSTS = {
    "github.com": r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    "codeberg.org": r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    "gitea.com": r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    "bitbucket.org": r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    "gitlab.com": r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+",
    "git.sr.ht": r"/~[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
}
# Registry and package pages are distribution channels, not the project.
LINK_FORBIDDEN_HOSTS = {"hub.docker.com", "registry.hub.docker.com", "docker.io", "ghcr.io", "quay.io",
                        "gcr.io", "lscr.io", "registry.gitlab.com", "artifacthub.io", "pypi.org", "www.npmjs.com"}
SELF_REPO = "https://github.com/porelli/portcullis-templates"
CRAFT_REPO_RE = re.compile(r"(?m)^\s*CRAFT_REPO:\s*['\"]?(storytold/[A-Za-z0-9_.-]+)['\"]?\s*$")


def check_links(t: Template, r: Report) -> None:
    """links: the app's official website and upstream source repository (schema: both required, https)."""
    links = (t.manifest or {}).get("links")
    if not isinstance(links, dict):
        return  # the schema reports it
    for field in ("website", "source"):
        url = links.get(field)
        if not isinstance(url, str):
            continue
        parts = urlsplit(url)
        host, path = (parts.hostname or "").lower(), parts.path
        if host in LINK_FORBIDDEN_HOSTS or (host == "github.com" and "/pkgs/" in path):
            r.error(t.m_where, f"links.{field} {url} is a registry or package page, not the project",
                    LINKS_HINT)
        if url.rstrip("/").lower().startswith(SELF_REPO.lower()):
            r.error(t.m_where, f"links.{field} {url} points at this templates repository", LINKS_HINT)
    source = links.get("source")
    if isinstance(source, str):
        parts = urlsplit(source)
        host, path = (parts.hostname or "").lower(), parts.path
        pat = SOURCE_HOSTS.get(host)
        if pat is None:
            r.warn(t.m_where, f"links.source {source} is not on a known code host ({', '.join(sorted(SOURCE_HOSTS))})",
                   "fine for a self-hosted forge, but make sure it is the canonical repository, not a mirror")
        elif not re.fullmatch(pat, path) or path.endswith(".git") or "/-/" in path + "/" \
                or parts.query or parts.fragment:
            r.error(t.m_where, f"links.source {source} is not a repository URL on {host}",
                    "use the repository's root, e.g. https://github.com/<owner>/<repo> (no /tree/..., /-/..., .git, "
                    "trailing slash, query or fragment); " + LINKS_HINT)
    # Craft templates download storytold/<app> releases: the source is that repo.
    try:
        with open(t.compose_path, encoding="utf-8") as f:
            craft = CRAFT_REPO_RE.findall(f.read())
    except OSError:
        craft = []
    for repo in set(craft):
        want = f"https://github.com/{repo}"
        if source != want:
            r.error(t.m_where, f"links.source must be {want} (compose downloads CRAFT_REPO {repo})", LINKS_HINT)


def check_removed_vars(t: Template, r: Report) -> None:
    """PORTCULLIS_TRAEFIK_IP / PORTCULLIS_MCP_GATE_IP (core settings, not
    template variables, §2) in any file of the template, in any form:
    ${...}, $NAME, $$NAME, an environment key, a script, a comment."""
    for root, dirs, files in os.walk(t.dir):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for fn in sorted(files):
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8") as f:
                    text = f.read()
            except (UnicodeDecodeError, OSError):
                continue
            for name in sorted(set(REMOVED_VARS_RE.findall(text))):
                r.error(f"{t.id}/{os.path.relpath(path, t.dir)}",
                        f"{name} is not a template variable (a core setting the Hub doesn't copy): "
                        f"use ${{{REMOVED_VARS[name]}:-{CORE_VARS[REMOVED_VARS[name]]}}}, an IPv4 CIDR", SOURCE_HINT)


# The reviewed IPv4 CIDR check (esphome/gate.sh): every file that defines
# cidr_ok() has exactly this definition (compose: dollars doubled).
CIDR_FN_RE = re.compile(r"(?ms)^( *)cidr_ok\(\) \{\n.*?^\1\}\n")


def cidr_function(text: str, compose: bool = False) -> Optional[str]:
    """The cidr_ok() definition in text (dedented; compose: $$ -> $), or None."""
    m = CIDR_FN_RE.search(text)
    if not m:
        return None
    fn = textwrap.dedent(m.group(0))
    return fn.replace("$$", "$") if compose else fn


def check_compose(t: Template, r: Report) -> None:
    check_removed_vars(t, r)
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
    trust_nets = trust_networks(t, services)
    for name, spec in top_nets.items():
        if name in trust_nets:
            continue  # check_ai's check_trust_network judges it
        if name == PROXY_NET:
            if not (isinstance(spec, dict) and spec.get("external") is True):
                r.error(t.c_where, f"networks.{PROXY_NET} must be declared 'external: true'",
                        "core creates portcullis-proxy (fixed subnet, Traefik's static IP); templates only attach to it")
        elif name != "default":
            r.error(t.c_where, f"networks.{name}: templates may only use 'default' and '{PROXY_NET}' (and an "
                    "identity_headers AI companion's trust network)")
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
        if is_instance_var(name) or name.startswith(FOLDER_VAR_PREFIX) or name.startswith(VAR_AI_PREFIX):
            continue  # check_instance_vars; check_settings (reserved variable forms, F36); check_ai
        if name in SOURCE_VARS:
            if (op, rest) != (":-", CORE_VARS[name]):
                r.error(t.c_where, f"${{{name}}} must be exactly the default form ${{{name}:-{CORE_VARS[name]}}}",
                        SOURCE_HINT)
            continue
        if name in REMOVED_VARS:
            continue  # check_removed_vars
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
                    f"trust identity / forwarded headers only from {TRAEFIK_SOURCE_REF}")

    if method == "header-auth":
        if TRAEFIK_SOURCE_REF not in t.compose_values:
            r.error(t.c_where, "header-auth app does not restrict identity headers to Traefik",
                    f"set the app's proxy allowlist (or a gate in front of it) to {TRAEFIK_SOURCE_REF}; see CONTRIBUTING.md")
        if "${PORTCULLIS_PROXY_SUBNET" in t.compose_values or "${PORTCULLIS_PROXY_IP_RANGE" in t.compose_values:
            r.error(t.c_where, "header-auth app references the portcullis-proxy subnet",
                    "trusting the subnet lets every app container forge X-Forwarded-User; trust PORTCULLIS_TRAEFIK_SOURCE only")

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
            nm = svc.get("network_mode")
            target = nm[len("service:"):] if isinstance(nm, str) and nm.startswith("service:") else None
            # templates.checkNetworkMode: exactly as written (Docker matches the
            # keywords exactly: " host" and "Host" are network names).
            if not (nm in ("none", "host") or (target and target != sname and target in services)):
                r.error(where, f"network_mode {nm!r}: only none, host or service:<another service of this template>, exactly, in lower case",
                        "any other value names a network (e.g. portcullis-proxy) the service would join unchecked")
        elif enabled:
            if PROXY_NET not in nets or ("default" not in nets and not trust_nets & set(nets)):
                r.error(where, f"Traefik-routed service must use networks: [default, {PROXY_NET}] "
                        "(or [portcullis-proxy, <its AI companion's trust network>])")
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

    # Only method custom may have no HTTP router (§3, F48): a gateway method
    # with none would protect nothing. A router-less custom template (the
    # file-sharing templates) may set group_access with an access group and
    # no native_login: the access group is only its population (§3, F1).
    if not routers and method != "custom":
        r.error(t.c_where, f"auth.method {method} needs at least one HTTP router (only custom templates may have none)", HUB_HINT)
    if not routers and method == "custom" and auth.get("group_access") is True \
            and not any(o.get("type") in PERSON_TYPES for o in setting_options(t.manifest)):
        r.warn(t.m_where, "a router-less template's group_access gates nothing without a person_secret or person_id option",
               "the access group of a template with no web page only decides who gets a per-person credential or id "
               "(contract §3); set group_access: false, or add the option")
    nl = auth.get("native_login")
    if method == "custom" and routers and auth.get("group_access") and not (isinstance(nl, dict) and nl.get("supported") is True):
        r.error(t.m_where, "auth.method custom with group_access: true needs auth.native_login.supported: true",
                "group-gate only runs when the Hub puts Portcullis sign-in in front of the app (native_login); a router-less "
                "custom template (no web page, §3) is the exception")

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
    check_ai(t, services, routers, r)
    check_vpn(t, services, r)
    check_setup(t, services, routers, r)


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
            if not is_instance_var(name) or name == VAR_LOCAL_NETWORKS:
                continue   # PORTCULLIS_LOCAL_NETWORKS: exactly ${PORTCULLIS_LOCAL_NETWORKS} (check_settings)
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
    (r"(?m)^\s*allow \$\{src\};$", "allow ${src}; (PORTCULLIS_TRAEFIK_SOURCE, Traefik's range, only)"),
    (r'(?m)^cidr_ok "\$src" \|\| ', "the CIDR check of PORTCULLIS_TRAEFIK_SOURCE (cidr_ok)"),
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
             f"running ./templates/<id>/gate.sh (copy it from esphome/) with PORTCULLIS_TRAEFIK_SOURCE: {TRAEFIK_SOURCE_REF}")


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
DNS_HINT = ("names ending in -internal (a gate's upstream) are declared as aliases on the default network "
            "(or an internal: true project network) only; "
            "a name on portcullis-proxy could catch another app's gated traffic")


def trust_networks(t: "Template", services: Dict[str, Any]) -> Set[str]:
    """The sole network of each identity_headers kind-companion service
    (contracts §3.2 trust network; _AICheck.check_trust_network validates it)."""
    out: Set[str] = set()
    ai = (t.manifest or {}).get("ai")
    for c in (ai.get("mcp") or []) if isinstance(ai, dict) and isinstance(ai.get("mcp"), list) else []:
        if not isinstance(c, dict) or c.get("kind") != "companion":
            continue
        ident = c.get("identity") if isinstance(c.get("identity"), dict) else {}
        svc = services.get(str(c.get("service"))) if isinstance(c.get("service"), str) else None
        if ident.get("mode") == "identity_headers" and isinstance(svc, dict):
            nets = networks_of(svc)
            if len(nets) == 1 and nets[0] not in ("default", PROXY_NET):
                out.add(nets[0])
    return out


def private_networks(compose: Optional[Dict[str, Any]]) -> Set[str]:
    """Service network keys that are the project's own network: 'default',
    unless the top level renames it or makes it external (then shared), and
    every network declared exactly {internal: true} (Hub
    checkInternalNames: e.g. an identity_headers companion's trust network)."""
    nets = (compose or {}).get("networks") or {}
    nets = nets if isinstance(nets, dict) else {}
    out: Set[str] = set()
    spec = nets.get("default")
    if not (isinstance(spec, dict) and (spec.get("name") is not None or spec.get("external") not in (None, False))):
        out.add("default")
    for k, spec in nets.items():
        if isinstance(spec, dict) and spec.get("internal") is True and len(spec) == 1:
            out.add(str(k))
    return out


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
        if env_of(svc).get(VAR_TRAEFIK_SOURCE) != TRAEFIK_SOURCE_REF:
            r.error(where, f"the gate needs {VAR_TRAEFIK_SOURCE}: {TRAEFIK_SOURCE_REF}", GATE_HINT)
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
        read_only = bool(compose_bool(vol.get("read_only")))
        if "read_only" in vol and compose_bool(vol.get("read_only")) is None:
            r.error(where, f"read_only {vol.get('read_only')!r} is not a boolean compose reads",
                    "write read_only: true (or false)")
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
    # Every cidr_ok() (gates, inline checks of PORTCULLIS_TRAEFIK_SOURCE) is
    # the reviewed one of esphome/gate.sh.
    ref_fn: Optional[str] = None
    ref_path = os.path.join(ROOT, "esphome", GATE_SH)
    if os.path.isfile(ref_path):
        with open(ref_path, encoding="utf-8") as f:
            ref_fn = cidr_function(f.read())
    for t in templates:
        for root, dirs, files in os.walk(t.dir):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            for fn in sorted(files):
                path = os.path.join(root, fn)
                try:
                    with open(path, encoding="utf-8") as f:
                        text = f.read()
                except (UnicodeDecodeError, OSError):
                    continue
                got = cidr_function(text, compose=fn == "compose.yml" and root == t.dir)
                if got is None and "cidr_ok()" not in text:
                    continue
                if got is None or got != ref_fn:
                    r.error(f"{t.id}/{os.path.relpath(path, t.dir)}", "cidr_ok() differs from esphome/gate.sh's",
                            "copy the reviewed IPv4 CIDR check (compose: with every $ doubled) unchanged")


# The file-sharing templates' converge script (contract §13.17): one
# reviewed copy, byte-identical in exactly these templates, every one of
# them in the repo and shipping it.
SYNC_TEMPLATES = {"samba", "timemachine"}
SYNC_SCRIPT = os.path.join("bin", "portcullis-sync")
SYNC_HINT = ("portcullis-sync is shared by the file-sharing templates (contract §13.17): copy the reviewed one, "
             "byte for byte, and change both together")


def check_sync_copies(templates: List[Template], r: Report) -> None:
    """Every template that ships bin/portcullis-sync has the same bytes, and
    those templates are exactly SYNC_TEMPLATES (each one in the repo)."""
    ref: Optional[Tuple[str, bytes]] = None
    present = {t.id for t in templates}
    for missing in sorted(SYNC_TEMPLATES - present):
        r.error(f"{missing}/", f"the file-sharing template {missing} is not in the repo (it ships {SYNC_SCRIPT})", SYNC_HINT)
    for t in sorted(templates, key=lambda x: x.id):
        path = os.path.join(t.dir, SYNC_SCRIPT)
        where = f"{t.id}/{SYNC_SCRIPT}"
        if not os.path.isfile(path):
            if t.id in SYNC_TEMPLATES:
                r.error(f"{t.id}/", f"missing {SYNC_SCRIPT} (every file-sharing template ships the shared script)", SYNC_HINT)
            continue
        if t.id not in SYNC_TEMPLATES:
            r.error(where, f"only the file-sharing templates ({', '.join(sorted(SYNC_TEMPLATES))}) ship {SYNC_SCRIPT}", SYNC_HINT)
            continue
        with open(path, "rb") as f:
            data = f.read()
        if ref is None:
            ref = (t.id, data)
        elif data != ref[1]:
            # Under both templates: either one's errors show the drift.
            r.error(f"{ref[0]}/{SYNC_SCRIPT}", f"{ref[0]}/{SYNC_SCRIPT} differs from {where}", SYNC_HINT)
            r.error(where, f"{where} differs from {ref[0]}/{SYNC_SCRIPT}", SYNC_HINT)


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
                 "alertmanager", "blackbox", "textfile-exporter", "grafana", "mcp-gate", "sessions", "dns-tool",
                 "wg"}
CORE_VOLUMES = {"postgres_data", "vault_data", "lldap_data", "hub_data", "traefik_acme", "domains_data",
                "prometheus_data", "alertmanager_data", "grafana_data", "hub_secrets", "mcp_gate_data",
                "group_gate_data", "wg_data", "vpn_doc"}
# Core's network aliases that aren't service names (wg's metrics address
# on portcullis-metrics-wg): reserved DNS names too (Hub coreAliases).
CORE_ALIASES = {"wg-metrics"}
# The Hub override's top-level key for its secrets volume (F15,
# templates.SecretsVolumeKey): no template names it (folded, embedded).
SECRETS_VOLUME_KEY = "portcullis-hub-secrets"
CORE_NETWORKS = {"portcullis", "portcullis-auth", "portcullis-certs", "portcullis-domains", "domains-egress",
                 "socket-proxy-traefik", "socket-proxy-hub", "monitoring", "alerting", "portcullis-mcp",
                 "portcullis-sessions", "portcullis-vpn", "portcullis-vpn-edge", "portcullis-metrics-wg", "wg-egress"}
# MCP_NAME_PREFIX (AI support, §3.2): the Hub's companion aliases and
# routers portcullis-mcp-<instance-id>--<companion>, refused anywhere in
# compose.yml (any key or value, folded, also split by an interpolation).
MCP_NAME_PREFIX = "portcullis-mcp-"
# VPN_NAME_PREFIX (VPN-only access, §3/§3.3): the Hub's portcullis-vpn
# network, portcullis-vpnallow-<id> allowlist middleware and
# portcullis-vpnonly-<id> router, refused anywhere in compose.yml like
# MCP_NAME_PREFIX, no exception (the forwarder image is
# ghcr.io/porelli/portcullis-forwarder).
VPN_NAME_PREFIX = "portcullis-vpn"
RESERVED_REFS = ("forward-auth-ext", "portcullis-auth-ext", "portcullis-oauth2-", MCP_NAME_PREFIX, VPN_NAME_PREFIX)
CORE_CONTAINER_RE = re.compile(r"^portcullis[-_](.+)[-_][0-9]+$")
HUB_TOP_KEYS = {"services", "volumes", "networks", "name"}
HUB_SERVICE_KEYS = {
    "image", "volumes", "restart", "environment", "networks", "security_opt", "cap_drop", "cap_add",
    "pids_limit", "mem_limit", "mem_reservation", "memswap_limit", "cpus", "cpu_shares", "labels", "command", "read_only",
    "depends_on", "tmpfs", "entrypoint", "user", "group_add", "healthcheck", "shm_size", "network_mode", "working_dir",
    "hostname", "devices", "container_name", "ports", "expose", "ulimits", "stop_grace_period", "stop_signal", "init",
    "privileged", "sysctls", "logging", "tty", "stdin_open", "dns", "dns_search", "extra_hosts", "platform", "pull_policy",
    "pid", "ipc", "volumes_from", "domainname", "mac_address", "oom_score_adj", "storage_opt", "userns_mode",
    "device_cgroup_rules", "gpus", "runtime", "isolation", "blkio_config", "cgroup", "cgroup_parent", "cpuset",
    "profiles"}  # profiles only as check_setup allows (contracts §13.18)
CORE_TRAEFIK_NAMES = {
    "routers": {"dashboard", "enroll", "enroll-invite", "enroll-self", "grafana-metrics", "hub", "keycloak",
                "keycloak-admin", "keycloak-resources", "lldap", "oauth2-callback", "people", "portal", "mcp", "hub-mcp",
                "people-mcp", "people-vpn-enrol",
                # VPN-only access (core vpn1): the -vpn twins of the routers
                # through group-gate and the /vpn-required routers.
                "core-vpn-required", "dashboard-vpn", "grafana-metrics-vpn", "hub-vpn", "keycloak-admin-vpn",
                "keycloak-admin-vpn-required", "people-vpn", "people-vpn-enrol-vpn", "portal-vpn"},
    "middlewares": {"vpn-required-path", "portcullis-groups-vpn", "portcullis-public-guard-vpn", "portal-vpn-path",
                    "directory-redirect", "hub-proxy-secret", "portal-path", "portcullis-auth", "portcullis-auth-console",
                    "portcullis-auth-ext", "portcullis-groups", "portcullis-public-guard", "portcullis-self"},
    "services": {"enroll", "forward-auth", "forward-auth-ext", "grafana-metrics", "group-gate", "hub", "hub-people",
                 "keycloak", "lldap", "mcp-gate"},
}
APP_MIDDLEWARES = {"portcullis-auth", "portcullis-groups"}
# Exactly core's traefik/dynamic/middlewares.yml (Hub fileMiddlewares;
# TestCoreNamesComplete compares with a core checkout). strip-client-forwarded
# (core vpn1) already runs first on every websecure / vpnsecure router at the
# entrypoint, so naming it again is harmless.
FILE_MIDDLEWARES = {"client-headers", "client-cert-pem", "rate-limit", "rate-limit-auth", "security-headers",
                    "strip-client-forwarded"}
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
        if c in CORE_SERVICES or c in CORE_ALIASES:
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
                if ref == MCP_NAME_PREFIX:
                    r.error(where, f"references {MCP_NAME_PREFIX!r}: names starting {MCP_NAME_PREFIX} (routers, services, middlewares, "
                                   "aliases, container names, hostnames, any key or value) are the Hub's AI companion routes and aliases",
                            AI_HINT)
                elif ref == VPN_NAME_PREFIX:
                    r.error(where, f"references \"{VPN_NAME_PREFIX}\": names starting {VPN_NAME_PREFIX} (the VPN network, "
                                   "middlewares and routers) are rendered by the Hub only (contract §3.3)", VPN_HINT)
                else:
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
        if names_secrets_volume_key(str(k)):
            r.error(where, f"volume {k} is reserved: {SECRETS_VOLUME_KEY} is the Hub's secrets volume", HUB_HINT)
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
        for vol in as_list(svc.get("volumes")):
            src = ""
            if isinstance(vol, str):
                src = vol if vol.strip().startswith("${") else vol.split(":", 1)[0]   # a ${X:-…} source may hold colons
            elif isinstance(vol, dict):
                src = scalar_text(vol.get("source")) if vol.get("source") is not None else ""
            if names_secrets_volume_key(src):
                r.error(sw, f"volume {src} names the Hub's secrets volume ({SECRETS_VOLUME_KEY}): only the Hub mounts it", HUB_HINT)
        for x in as_list(svc.get("volumes_from")):
            if names_secrets_volume_key(scalar_text(x)):
                r.error(sw, f"volumes_from {x} names the Hub's secrets volume", HUB_HINT)
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
                 "secret", "group", "groups", "user", "users", "person_secret", "person_id"}
PERSON_TYPES = ("person_secret", "person_id")   # file sharing (§13.2): one value per person, set by the Hub
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
HOOK_TRIGGERS = ("start", "settings_change", "membership_change", "credential_change", "ai", "vpn")   # ai: AI support, vpn: VPN providers (§13.8)
RELOAD_SIGNALS = {"HUP", "USR1", "USR2"}
GENERATE_CHARSETS = {"hex", "alphanumeric", "ascii_printable"}
CLAIM_JSON_TYPES = {"int", "string", "bool", "json"}
PLACEHOLDER_ACCESS, PLACEHOLDER_ADMIN = "{{ACCESS_GROUP}}", "{{ADMIN_GROUP}}"
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
_RE2_OPTIONS = re2.Options()
_RE2_OPTIONS.log_errors = False
# \C (any byte) is the one C++ RE2 escape Go's regexp refuses.
_BYTE_ESCAPE_RE = re.compile(r"(?<!\\)(?:\\\\)*\\C")


def _compile_pattern(p: str) -> Any:
    """compilePattern: anchored ^…$, ≤ 500, RE2 syntax (google-re2: the
    library Go's regexp ports, linear time), applied to the whole value as
    ^(?:…)$."""
    if p in _PATTERN_CACHE:
        return _PATTERN_CACHE[p]
    if blen(p) > 500:
        raise SettingError("pattern is longer than 500 characters")
    if not (p.startswith("^") and p.endswith("$")):
        raise SettingError(f"pattern {json.dumps(p)} must be anchored: ^…$")
    if _BYTE_ESCAPE_RE.search(p):
        raise SettingError(f"pattern {json.dumps(p)}: error parsing regexp: invalid escape sequence: `\\C`")
    try:
        rx = re2.compile("^(?:" + p + ")$", _RE2_OPTIONS)
    except re2.error as e:
        msg = e.args[0].decode() if e.args and isinstance(e.args[0], bytes) else str(e)
        raise SettingError(f"pattern {json.dumps(p)}: error parsing regexp: {msg}") from None
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
        ("mode", _str(o, "mode") != ""), ("needs", _str(o, "needs") != ""), ("folder", _has(o, "folder")),
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
        if label == "" or len(label) > 64 or has_control(label):
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
            if label == "" or len(label) > 64 or has_control(label):
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
        _only_fields(o, "target", "mode", "needs", "folder")
        if _has(o, "folder") and (_str(o, "mode") or _str(o, "needs") or _has(o, "writes_as")):
            raise SettingError("folder together with mode, needs or writes_as: folder.access and folder.runs_as replace them")
        mode, needs = _str(o, "mode"), _str(o, "needs")
        if mode not in ("", "ro", "rw"):
            raise SettingError(f"mode {json.dumps(mode)} must be ro or rw")
        if needs not in ("", "read", "write"):
            raise SettingError(f"needs {json.dumps(needs)} must be read or write")
        if mode == "ro" and needs == "write":
            raise SettingError("needs: write with mode: ro: the app could never write there")
    elif t in PERSON_TYPES:
        _only_fields(o)
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
            if not _compile_pattern(_str(o, "pattern")).search(raw):
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
            raise SettingError(f"{json.dumps(raw)}: a shared folder value is resolved by the Hub")
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
    """EffectiveScope: person for person_secret / person_id (their scope field is refused)."""
    if o.get("type") in PERSON_TYPES:
        return "person"
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


def _check_render(o: Dict[str, Any], d: Dict[str, Any], rd: Dict[str, Any]) -> None:
    t, unit = o.get("type"), _str(rd, "unit")
    kind = _delivery_kind(d)
    if kind == "env":
        for name in ("true", "false", "unlimited", "join"):
            if _has(rd, name) and any(c in _str(rd, name) for c in "'\\"):
                raise SettingError(f"{name} must not contain a single quote or a backslash (an env value is single-quoted)")
    if _str(rd, "format") in ("yaml", "csv") and kind in ("env", "header", "claim"):
        raise SettingError(f"format {_str(rd, 'format')} is multi-line: an env, header or claim delivery takes one line "
                           "(use format: json or join)")
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
    pe = scope_of(o) == "person_entered"
    collection = t in LIST_LIKE or pe
    if _has(rd, "join"):
        if not collection:
            raise SettingError("join is for list, multi_enum, groups and users options (and person_entered collections)")
        if _str(rd, "join") == "" or has_control(_str(rd, "join")):
            raise SettingError("join must be a non-empty separator without newlines or control characters")
        if _str(rd, "format"):
            raise SettingError("join and format exclude each other")
    if rd.get("expand_members") is True:
        if t not in ("group", "groups") or scope_of(o) != "instance":
            raise SettingError("expand_members is for group and groups options of scope instance")
        if kind != "file":
            raise SettingError("expand_members is for file deliveries (a data file holds the members)")
        if _has(rd, "join") or _str(rd, "format"):
            raise SettingError("expand_members renders the member list: no join or format")
    fmt = _str(rd, "format")
    if fmt in ("yaml", "csv"):
        # Only env carries a person_entered collection; elsewhere it is the person's own (scalar) value.
        if t not in LIST_LIKE and t != "table":
            if pe:
                raise SettingError(f"format {fmt} is for list and table values: outside env a person_entered {t} is the person's own value")
            raise SettingError(f"format {fmt} is for list, multi_enum, groups, users and table options (and person_entered collections)")
    elif fmt not in ("", "json"):
        raise SettingError(f"format {json.dumps(fmt)} must be json, yaml or csv")


def check_option_kind(o: Dict[str, Any]) -> None:
    """Registry.CheckOption: the kind's constraints, each delivery's render,
    the default and the group_values as values of o."""
    _kind_check(o)
    check_checks(o)
    deliveries = o.get("delivery") if isinstance(o.get("delivery"), list) else []
    if o.get("type") == "size" and o.get("allow_unlimited") and not deliveries:
        raise SettingError("allow_unlimited needs deliveries that say how unlimited is rendered (render.unlimited)")
    for d in deliveries:
        try:
            _check_render(o, d if isinstance(d, dict) else {}, render_of(d) if isinstance(d, dict) else {})
        except SettingError as e:
            raise SettingError(f"{delivery_name(d)}: render: {e}") from None
    check_unlimited_reachable(o)
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
    check_option_values(o)


# ── rendering values through the deliveries (settings.Render / RenderDelivery) ──

MAX_HEADER_VALUE, MAX_CLAIM_VALUE = 1024, 4096
INDEX_SUFFIX_RE = "_{n}"


def _json_text(v: Any) -> str:
    """encoding/json with SetEscapeHTML(false), compact (the Hub trims Encode's newline)."""
    def conv(x: Any) -> Any:
        if x is UNLIMITED:
            return "unlimited"
        if isinstance(x, list):
            return [conv(i) for i in x]
        if isinstance(x, dict):
            return {str(k): conv(i) for k, i in x.items()}
        return x
    return json.dumps(conv(v), ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _item_text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _divide(n: int, div: int, unit: str, shown: str, integer: bool) -> Tuple[str, Any]:
    if n % div == 0:
        return str(n // div), n // div
    if integer:
        raise SettingError(f"{shown} is not a whole number of {unit}: the app takes whole {unit}")
    f = n / div
    return repr(f), f


class _Rendered:
    def __init__(self, text: str, js: Any, text_err: Optional[str] = None) -> None:
        self.text, self.json, self.text_err = text, js, text_err


def _multi_line(s: str) -> _Rendered:
    return _Rendered(s, s, "the rendered value contains a newline (use format: json for a single-line value)"
                     if has_control(s) else None)


def render_value(o: Dict[str, Any], v: Any, rd: Dict[str, Any]) -> _Rendered:
    """settings.Render: canonical v for one render rd."""
    t, fmt = o.get("type"), _str(rd, "format")
    if t in LIST_LIKE:
        texts = [_item_text(i) for i in v]
        if fmt == "json":
            return _Rendered(_json_text(v), v)
        if fmt in ("yaml", "csv"):
            # Multi-line except for one short item; files and hooks only (statically checked).
            return _multi_line("\n".join(texts) + ("\n" if fmt == "yaml" else ""))
        sep = _str(rd, "join") if _has(rd, "join") else ","
        clash = next((f"item {json.dumps(x)} contains the separator {json.dumps(sep)}" for x in texts if sep in x), None)
        joined = sep.join(texts)
        if _has(rd, "join"):
            if clash:
                raise SettingError(clash)
            return _Rendered(joined, joined)
        return _Rendered(joined, v, clash)
    if t == "table":
        kc = _str(o, "key_column")
        structured: Any = {_item_text(r.get(kc)): r for r in v} if kc else v
        if fmt in ("", "json"):
            return _Rendered(_json_text(structured), structured)
        return _multi_line("\n")
    if t == "size":
        if v is UNLIMITED:
            if not _has(rd, "unlimited"):
                raise SettingError("the delivery has no render.unlimited: it can't take unlimited")
            out = _Rendered(_str(rd, "unlimited"), _str(rd, "unlimited"))
        else:
            unit = _str(rd, "unit") or "B"
            out = _Rendered(*_divide(v, SIZE_RENDER_UNITS[unit], unit, show_size(v), bool(rd.get("integer"))))
    elif t == "duration":
        unit = _str(rd, "unit") or "s"
        out = _Rendered(*_divide(v, DURATION_RENDER_UNITS[unit], unit, show_duration(v), bool(rd.get("integer"))))
    elif t == "int":
        out = _Rendered(str(v), v)
    elif t == "bool":
        out = _Rendered(_item_text(v), v)
        if _has(rd, "true") or _has(rd, "false"):
            txt = _item_text(v)
            if v and _has(rd, "true"):
                txt = _str(rd, "true")
            elif not v and _has(rd, "false"):
                txt = _str(rd, "false")
            out = _Rendered(txt, txt)
    else:
        out = _Rendered(v, v)
    if fmt == "json":
        out.text = _json_text(out.json)
    elif fmt:
        raise SettingError(f"format {fmt} is for list and table options")
    if has_control(out.text):
        raise SettingError("the rendered value contains a newline or control characters")
    return out


def _delivery_kind(d: Dict[str, Any]) -> str:
    for k in ("claim", "header", "file"):
        if isinstance(d.get(k), dict):
            return k
    return "env" if _str(d, "env") else ("hook" if _str(d, "hook") else "")


def render_delivery(o: Dict[str, Any], v: Any, d: Dict[str, Any]) -> None:
    """RenderDelivery, then the env quote rule (envQuote) for env deliveries
    (indexed NAME_{n}: each item on its own, RenderIndexed)."""
    name, kind = delivery_name(d), _delivery_kind(d)
    indexed = kind == "env" and _str(d, "env").endswith(INDEX_SUFFIX_RE)
    try:
        if indexed:
            texts = []
            for i, it in enumerate(v if isinstance(v, list) else [], 1):
                s = _item_text(it)
                if has_control(s):
                    raise SettingError(f"item {i} contains a newline or control characters")
                texts.append(s)
        else:
            out = render_value(o, v, render_of(d))
            if kind in ("env", "header", "claim"):
                if out.text_err:
                    raise SettingError(out.text_err)
                n = blen(out.text)
                if kind == "header" and n > MAX_HEADER_VALUE:
                    raise SettingError(f"the rendered value is {n} bytes, over the {MAX_HEADER_VALUE}-byte header limit")
                if kind == "claim" and n > MAX_CLAIM_VALUE:
                    raise SettingError(f"the rendered value is {n} bytes, over the {MAX_CLAIM_VALUE}-byte claim attribute limit")
            texts = [out.text] if kind == "env" else []
        for i, s in enumerate(texts, 1):
            why = env_text_problem(s, kind == "env" and not indexed and env_json(o, d))
            if why:
                raise SettingError(f"item {i}: {why}" if indexed else why)
    except SettingError as e:
        raise SettingError(f"{name}: {e}") from None


def env_text_problem(text: str, from_json: bool) -> str:
    """CheckEnvText: text a single-quoted env value can't carry."""
    if not any(c in text for c in "'\\\n\r"):
        return ""
    if from_json and "\\" in text:
        return ("the JSON text contains a backslash (JSON escapes a double quote, a backslash and control characters "
                "inside strings as \\…), which an env value can't carry (use a file or hook delivery)")
    return "the value contains a single quote, a backslash or a line break, which an env value can't carry (use a file or hook delivery)"


def env_json(o: Dict[str, Any], d: Dict[str, Any]) -> bool:
    """EnvJSON: the env delivery carries JSON text (format json; a table's default rendering)."""
    fmt = _str(render_of(d), "format")
    return fmt == "json" or (o.get("type") == "table" and fmt == "")


def option_deliveries(o: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The option's deliveries, the implicit env UPPER(key) of an instance option without any."""
    ds = [d for d in (o.get("delivery") if isinstance(o.get("delivery"), list) else []) if isinstance(d, dict)]
    if not ds and scope_of(o) == "instance" and o.get("type") != "path" and isinstance(o.get("key"), str):
        ds = [{"env": o["key"].upper()}]
    return ds


def empty_default(v: Any) -> bool:
    """emptyDefault: a manifest default that holds no value (none, "", an empty list or map)."""
    return v is None or v == "" or v == [] or v == {}


def check_unlimited_reachable(o: Dict[str, Any]) -> None:
    """checkUnlimitedReach: allow_unlimited refused when a delivery's
    numeric render.unlimited is also what a size within the option's bounds
    renders as (the app would take it for unlimited; under resolve: min a
    restrictive row would win as the smallest)."""
    if o.get("type") != "size" or not o.get("allow_unlimited"):
        return
    try:
        lo, hi, _ = _read_bounds(o, parse_size)
    except SettingError:
        return  # the kind's own check reports it
    for d in o.get("delivery") if isinstance(o.get("delivery"), list) else []:
        rd = render_of(d) if isinstance(d, dict) else {}
        if not _has(rd, "unlimited"):
            continue
        u = _str(rd, "unlimited")
        if not re.fullmatch(r"[+-]?[0-9]+", u, re.ASCII) or not INT64_MIN <= int(u) <= INT64_MAX or int(u) < 0:
            continue  # not a number, or below any size
        div = SIZE_RENDER_UNITS.get(_str(rd, "unit"), 1) if _str(rd, "unit") else 1
        if int(u) > INT64_MAX // div:
            continue
        v = int(u) * div
        if (lo is None or v >= lo) and (hi is None or v <= hi):
            raise SettingError(f"allow_unlimited: {delivery_name(d)} renders unlimited as {u}, which the value {show_size(v)} "
                               "also renders as (set min above it, or render unlimited as a value no size reaches)")


def check_option_values(o: Dict[str, Any]) -> None:
    """The default and each group_values value through every delivery."""
    vals = []
    if _has(o, "default"):
        vals.append((f"default {_gofmt(o['default'])}", o["default"]))
    gv = o.get("group_values") if isinstance(o.get("group_values"), dict) else {}
    for g in sorted(gv, key=str):
        vals.append((f"group_values[{g}] {_gofmt(gv[g])}", gv[g]))
    for what, raw in vals:
        v = setting_value(o, raw)
        for d in option_deliveries(o):
            try:
                render_delivery(o, v, d)
            except SettingError as e:
                raise SettingError(f"{what}: {e}") from None


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
    if o.get("type") in PERSON_TYPES:
        return out   # no env (F5): their own checks refuse an env delivery

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
    return k in INSTANCE_VARS or k.startswith(INSTANCE_VAR_PREFIXES) or k.startswith("PORTCULLIS_FOLDER_") or ai_reserved_var(k) \
        or k == VAR_COMPOSE_PROFILES


def ai_reserved_var(k: str) -> bool:
    """The AI support variables (§3.1, §2): PORTCULLIS_AI_* (the Hub's) and
    core's PORTCULLIS_MCP_GATE_SOURCE (and the removed PORTCULLIS_MCP_GATE_IP);
    never declared by a template."""
    return k.startswith(VAR_AI_PREFIX) or k in (VAR_MCP_GATE_SOURCE, VAR_MCP_GATE_IP)


def _set(o: Dict[str, Any], k: str) -> bool:
    """A Go slice / map / pointer field that is set: present and not null
    (an empty list counts, like a non-nil empty slice)."""
    return k in o and o[k] is not None


def file_sharing_fields(o: Dict[str, Any]) -> str:
    """fileSharingFields: the two types' own fields on any other type."""
    t = o.get("type")
    if t != "person_secret":
        for f, on in (("hash", _str(o, "hash") != ""), ("length", o.get("length") not in (None, 0)),
                      ("revoke_on_leave", _has(o, "revoke_on_leave")), ("on_restore", _str(o, "on_restore") != ""),
                      ("username", _has(o, "username")), ("mount", _has(o, "mount")), ("info", _set(o, "info"))):
            if on:
                return f"{f} is for person_secret options"
        if isinstance(o.get("delivery"), str) and t != "person_id":
            return (f"delivery: {o['delivery']} is for person_secret options (as delivery: file); other options take a list "
                    "of deliveries")
    if t != "person_id" and _str(o, "pool") != "":
        return "pool is for person_id options"
    return ""


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


# ── Shared folders (contract §13.15) ────────────────────────────────
# A mirror of the Hub's portcullis-hub internal/templates/folders.go: the
# path option's folder block, option-level doctor checks, the folder gid
# range 60000-60999 and the strict uid / gid source forms of compose user:
# and group_add, with the Hub's messages. compose.yml's user: / group_add
# are read from the YAML node graph and resolved as yaml.v3 resolves plain
# scalars (v3_plain_resolve), so 0165141 is octal 60001 as Docker gets it.
# Where PyYAML can't see what yaml.v3 sees, the mirror refuses more, never
# less (CONTRIBUTING.md "Shared folders and checks").

FOLDERS_HINT = f"see {DOCS_URL}/integration-contracts/#1315-shared-folders-checks-and-lan-only-ports"
FOLDER_TYPE_REFUSAL = "type folder is reserved: a shared folder is a type: path option with a folder block (§13.15)"
FOLDER_READ, FOLDER_WRITE = "read", "write"
JOIN_GROUP_ADD, JOIN_GID_ENV, JOIN_TEMPLATE = "group_add", "gid_env", "template"
CHECK_LAN_ONLY = "lan_only"   # the port flag and the doctor's finding kind, never an option check
CHECK_KINDS = ("exclusive", "filesystem", "free_space", "requires_group_value")
CHECK_PARAMS = {"filesystem": ("needs", "not"), "free_space": ("min",)}
FS_NEEDS, FS_NOT = ("xattr", "acl"), ("nfs", "cifs", "fuse")
CHECK_REASON_MAX = 200
FOLDER_GID_MIN, FOLDER_GID_MAX = 60000, 60999
MAX_RUNS_AS_ID = (1 << 31) - 1
GID_RANGE_TEXT = f"{FOLDER_GID_MIN}-{FOLDER_GID_MAX} (shared folder groups)"
FOLDER_VAR_PREFIX = "PORTCULLIS_FOLDER_"

# The Hub's regexps (Go's $ is the end of the text: fullmatch / match here).
USER_NUM_RE = re.compile(r"[0-9]{1,10}")
SINGLE_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)([0-9]{1,10}))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")
BRACE_REF_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:[:?+-]{1,2}[0-9]*)?\}")
# groupNameRe: a plain group (group_add) or user (uid part) name; not
# GROUP_NAME_RE, the group options' lldap.ValidGroupName.
ID_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
GID_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+?])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")
DECIMAL_RE = re.compile(r"-?[0-9]{1,18}")
_V3_FLOAT_RE = re.compile(r"[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?")
_V3_MAP = {"true": "bool", "True": "bool", "TRUE": "bool", "false": "bool", "False": "bool", "FALSE": "bool",
           "": "null", "~": "null", "null": "null", "Null": "null", "NULL": "null",
           ".nan": "float", ".NaN": "float", ".NAN": "float", ".inf": "float", ".Inf": "float", ".INF": "float",
           "+.inf": "float", "+.Inf": "float", "+.INF": "float", "-.inf": "float", "-.Inf": "float", "-.INF": "float",
           "<<": "merge"}


def _q(s: str) -> str:
    """Go's %q for the messages (printable non-ASCII kept)."""
    return json.dumps(s, ensure_ascii=False)


def in_folder_gid_range(n: int) -> bool:
    return FOLDER_GID_MIN <= n <= FOLDER_GID_MAX


def _go_parse_int(s: str, base: int, signed: bool) -> Optional[int]:
    """strconv.ParseInt / ParseUint (s, base, 64): None when it fails."""
    neg = False
    if signed and s[:1] in ("+", "-"):
        neg, s = s[0] == "-", s[1:]
    if base == 0:
        low = s[:2].lower()
        if low == "0x":
            base, s = 16, s[2:]
        elif low == "0o":
            base, s = 8, s[2:]
        elif low == "0b":
            base, s = 2, s[2:]
        elif s[:1] == "0" and len(s) > 1:
            base, s = 8, s[1:]
        else:
            base = 10
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"[:base]
    if not s or any(c not in digits for c in s.lower()):
        return None
    n = -int(s, base) if neg else int(s, base)
    if signed and not INT64_MIN <= n <= INT64_MAX:
        return None
    if not signed and n > (1 << 64) - 1:
        return None
    return n


def v3_plain_resolve(v: str) -> Tuple[str, Optional[int]]:
    """yaml.v3 resolve("", v): the tag of a plain scalar (str, int, float,
    bool, null, timestamp, merge) and, for an int, its value."""
    if v in _V3_MAP:
        return _V3_MAP[v], None
    hint = v[:1]
    if hint == ".":
        try:
            float(v)
            return "float", None
        except ValueError:
            return "str", None
    if hint and (hint.isdigit() and hint.isascii() or hint in "+-"):
        # parseTimestamp needs four digits and '-': such a value is never a
        # number, a name or a reference, so calling it a timestamp only
        # changes which refusal is shown.
        if re.match(r"[0-9]{4}-", v):
            return "timestamp", None
        plain = v.replace("_", "")
        for signed in (True, False):
            n = _go_parse_int(plain, 0, signed)
            if n is not None:
                return "int", n
        if _V3_FLOAT_RE.fullmatch(plain):
            return "float", None
        for pre, base, neg in (("0b", 2, False), ("-0b", 2, True), ("0o", 8, False), ("-0o", 8, True)):
            if plain.startswith(pre):
                n = _go_parse_int(plain[len(pre):], base, True)
                if n is not None:
                    return "int", -n if neg else n
        return "str", None
    return "str", None


class _IDNodeLoader(_UniqueKeyLoader):
    """Composes nodes and records which scalar carried an explicit tag
    (yaml.v3 keeps it as the node's Tag; a plain one is resolved)."""

    def compose_scalar_node(self, anchor: Any) -> yaml.ScalarNode:
        event = self.peek_event()
        node = super().compose_scalar_node(anchor)
        node.v3_explicit = event.tag not in (None, "!")  # type: ignore[attr-defined]
        return node


def v3_tag(node: yaml.Node) -> str:
    """The node's tag as yaml.v3's parser sets it (!!str, !!int, …)."""
    if isinstance(node, yaml.ScalarNode):
        if getattr(node, "v3_explicit", False):
            t = node.tag
            return "!!" + t[len("tag:yaml.org,2002:"):] if t.startswith("tag:yaml.org,2002:") else t
        if node.style:
            return "!!str"
        return "!!" + v3_plain_resolve(node.value)[0]
    return "!!seq" if isinstance(node, yaml.SequenceNode) else "!!map"


def _is_null(node: Optional[yaml.Node]) -> bool:
    return node is None or (isinstance(node, yaml.ScalarNode) and v3_tag(node) == "!!null")


def id_scalar(node: Optional[yaml.Node]) -> Tuple[Optional[str], str]:
    """idScalar: a user: / group_add value as compose reads it (None = not
    set; aliases are the anchored node itself in PyYAML's graph): only
    !!str, !!int and !!null, an !!int written in decimal as YAML decodes it."""
    if _is_null(node):
        return None, ""
    if not isinstance(node, yaml.ScalarNode):
        return None, "want a scalar"
    tag = v3_tag(node)
    if tag not in ("!!str", "!!int"):
        return None, f"want a string or a whole number, not {tag}"
    if tag == "!!int":
        rt, n = v3_plain_resolve(node.value)
        if rt != "int" or n is None or not INT64_MIN <= n <= INT64_MAX:
            return None, f"cannot decode {node.value!r} as a whole number"
        return str(n), ""
    return node.value, ""


def _node_map(node: yaml.Node, depth: int = 0) -> Dict[str, yaml.Node]:
    """A mapping node's keys as yaml.v3 decodes a struct: explicit keys
    win, then the (last) << merge, a sequence of maps first map first."""
    if not isinstance(node, yaml.MappingNode) or depth > 32:
        raise ValueError("map merge requires map or sequence of maps as the value")
    out: Dict[str, yaml.Node] = {}
    merge = None
    for k, val in node.value:
        if isinstance(k, yaml.ScalarNode) and v3_tag(k) == "!!merge":
            merge = val
            continue
        if isinstance(k, yaml.ScalarNode):
            out.setdefault(k.value, val)
    if merge is not None:
        for m in (merge.value if isinstance(merge, yaml.SequenceNode) else [merge]):
            for k, val in _node_map(m, depth + 1).items():
                out.setdefault(k, val)
    return out


def compose_ids(text: str) -> Tuple[Dict[str, str], Dict[str, List[str]], str]:
    """composeIDs: every service's user: ("" = set empty) and group_add
    entries, or the reason compose.yml can't be read that way."""
    users: Dict[str, str] = {}
    group_add: Dict[str, List[str]] = {}
    try:
        root = yaml.compose(text, Loader=_IDNodeLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as e:
        return users, group_add, f"compose.yml: {e}"
    if _is_null(root):
        return users, group_add, ""
    if not isinstance(root, yaml.MappingNode):
        return users, group_add, "compose.yml: the top level must be a mapping"
    try:
        services = _node_map(root).get("services")
        if _is_null(services):
            return users, group_add, ""
        svcs = _node_map(services)
    except ValueError as e:
        return users, group_add, f"compose.yml: {e}"
    for svc, node in svcs.items():
        if _is_null(node):
            continue
        try:
            s = _node_map(node)
        except ValueError:
            return {}, {}, f"compose.yml: service {svc} is not a mapping"
        u, err = id_scalar(s.get("user"))
        if err:
            return {}, {}, f"service {svc}: user: {err}"
        if u is not None:
            users[svc] = u
        g = s.get("group_add")
        if _is_null(g):
            continue
        if not isinstance(g, yaml.SequenceNode):
            return {}, {}, f"service {svc}: group_add must be a list"
        for e in g.value:
            val, err = id_scalar(e)
            if err or val is None:
                return {}, {}, f"service {svc}: group_add entries must be numbers or names"
            group_add.setdefault(svc, []).append(val)
    return users, group_add, ""


def split_user(u: str) -> Tuple[str, str, bool]:
    """splitUser: compose user: split at the first ':' outside ${…}."""
    depth, i = 0, 0
    while i < len(u):
        if u[i] == "$" and i + 1 < len(u) and u[i + 1] == "{":
            depth += 1
            i += 1
        elif u[i] == "}" and depth > 0:
            depth -= 1
        elif u[i] == ":" and depth == 0:
            return u[:i], u[i + 1:], True
        i += 1
    return u, "", False


def user_part(s: str) -> Tuple[Optional[int], str, bool]:
    """parseUserPart: (a literal number, the ${NAME…} / $NAME it names, other)."""
    if USER_NUM_RE.fullmatch(s):
        return int(s), "", False
    m = SINGLE_REF_RE.fullmatch(s)
    if m:
        return None, m.group(1) or m.group(4), False
    return None, "", True


def default_int(d: Any) -> Optional[int]:
    """defaultInt: a manifest default as an integer (a YAML int, a whole
    float, a decimal string), None when it can't be read so. yaml.v3 reads
    an int beyond int64 as a uint64 above 1<<62 or a float above 2^53:
    both unreadable."""
    if isinstance(d, bool):
        return None
    if isinstance(d, int):
        return d if INT64_MIN <= d <= INT64_MAX else None
    if isinstance(d, float):
        return int(d) if d == int(d) and abs(d) <= 1 << 53 else None
    if isinstance(d, str) and DECIMAL_RE.fullmatch(d):
        return int(d)
    return None


def id_default(ro: Dict[str, Any]) -> Tuple[int, bool, bool]:
    """idDefault: (the default, unreadable, in the folder gid range)."""
    if not _has(ro, "default"):
        return 0, False, False
    d = default_int(ro["default"])
    if d is None:
        return 0, True, False
    return d, False, in_folder_gid_range(d)


def quote_default(d: Any) -> str:
    return _q(d) if isinstance(d, str) else _gofmt(d)


def runs_as_of(o: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    f = o.get("folder")
    ra = f.get("runs_as") if isinstance(f, dict) else None
    return ra if isinstance(ra, dict) else None


def runs_as_norm(ra: Dict[str, Any]) -> Tuple[Any, ...]:
    """A runs_as as the Hub's RunsAs struct compares (reflect.DeepEqual)."""
    return (ra.get("uid"), ra.get("gid"), _str(ra, "uid_env"), _str(ra, "gid_env"),
            _str(ra, "uid_from"), _str(ra, "gid_from"))


def runs_as_number_problem(o: Dict[str, Any]) -> str:
    """RunsAs.UnmarshalYAML: a uid / gid that isn't a whole number."""
    ra = runs_as_of(o)
    if ra is None:
        return ""
    for what in ("uid", "gid"):
        n = ra.get(what)
        if n is None:
            continue
        if isinstance(n, bool) or not isinstance(n, int) or not INT64_MIN <= n <= INT64_MAX:
            shown = "" if isinstance(n, (dict, list)) else scalar_text(n)
            return f"folder.runs_as.{what}: want a whole number, not {_q(shown)} (a variable goes in {what}_env)"
    return ""


def folder_join(o: Dict[str, Any]) -> str:
    """FolderSpec.Join: joins_group, default group_add."""
    f = o.get("folder") if isinstance(o.get("folder"), dict) else {}
    return _str(f, "joins_group") or JOIN_GROUP_ADD


class FolderCheck:
    """The folder parts of the Hub's specCheck over one template: its
    options (dicts), every service's compose user: and group_add entries.
    Each method answers the Hub's refusal, or None."""

    def __init__(self, options: List[Dict[str, Any]], users: Dict[str, str], group_add: Dict[str, List[str]]) -> None:
        self.options, self.users, self.group_add = options, users, group_add

    def any_env_option(self, name: str) -> Optional[Dict[str, Any]]:
        """anyEnvOption: the instance option (any type) delivering env name."""
        for ro in self.options:
            if scope_of(ro) == "instance" and name in option_env_names(ro):
                return ro
        return None

    def env_option(self, name: str) -> Optional[Dict[str, Any]]:
        """envOption: the instance int option delivering env name."""
        ro = self.any_env_option(name)
        return ro if ro is not None and ro.get("type") == "int" else None

    def services(self) -> List[str]:
        return sorted(set(self.users) | set(self.group_add))

    # compose-level (composeGIDs), on every service, before the options

    def compose_gids(self) -> List[str]:
        out = []
        for s in self.services():
            msg = self.service_gids(s)
            if msg:
                out.append(msg)
        return out

    def service_gids(self, s: str) -> Optional[str]:
        u = self.users.get(s, "")
        msg = user_fallbacks(s, u)
        if msg:
            return msg
        uid, g, has_gid = split_user(u)
        if u != "" and not (USER_NUM_RE.fullmatch(uid) or ID_NAME_RE.fullmatch(uid) or SINGLE_REF_RE.fullmatch(uid)):
            return (f"service {s}: compose user: uid {_q(uid)} must be a whole number, a user name or exactly one "
                    "${NAME} / $NAME (no mixed forms)")
        msg = self.int_ref(s, "compose user: uid", uid)
        if msg:
            return msg
        if has_gid:
            msg = self.gid_source(s, "compose user: gid", "compose user: gid", g, False)
            if msg:
                return msg
        for e in self.group_add.get(s, []):
            msg = self.gid_source(s, "group_add gid", "group_add", e, True)
            if msg:
                return msg
        return None

    def int_ref(self, svc: str, what: str, val: str) -> Optional[str]:
        m = SINGLE_REF_RE.fullmatch(val)
        if not m:
            return None
        name = m.group(1) or m.group(4)
        if self.env_option(name) is None:
            return (f"service {svc}: {what} ${{{name}}} must name an instance int option of this template "
                    "(not a string option, an undeclared variable or PORTCULLIS_*)")
        return None

    def gid_source(self, svc: str, lit: str, ref: str, val: str, names: bool) -> Optional[str]:
        if USER_NUM_RE.fullmatch(val):
            if in_folder_gid_range(int(val)):
                return f"service {svc}: {lit} {int(val)} is in {GID_RANGE_TEXT}"
            return None
        if names and ID_NAME_RE.fullmatch(val):
            return None
        if not SINGLE_REF_RE.fullmatch(val):
            if names:
                return (f"service {svc}: group_add entry {_q(val)} must be a whole number, a group name or exactly one "
                        "${NAME} / $NAME (no mixed forms)")
            return f"service {svc}: compose user: gid {_q(val)} must be a whole number or exactly one ${{NAME}} / $NAME (no mixed forms)"
        msg = self.int_ref(svc, ref, val)
        if msg:
            return msg
        for m in _interpolations(val, GID_REF_RE):
            name, op, value = m.group(1) or m.group(4), m.group(2) or "", m.group(3) or ""
            if op and op not in ("?", ":?") and USER_NUM_RE.fullmatch(value) and in_folder_gid_range(int(value)):
                return f"service {svc}: {lit} {int(value)} (the default of ${{{name}}}) is in {GID_RANGE_TEXT}"
            ro = self.env_option(name)
            if ro is not None:
                d, _, inr = id_default(ro)
                if inr:
                    return f"service {svc}: {ref} ${{{name}}} is setting {_str(ro, 'key')}, whose default {d} is in {GID_RANGE_TEXT}"
        return None

    # the folder block of one option (folderOption)

    def folder_option(self, o: Dict[str, Any]) -> Optional[str]:
        f = o.get("folder")
        if not isinstance(f, dict):
            return None
        bad = runs_as_number_problem(o)
        if bad:
            return bad
        if o.get("type") != "path" or scope_of(o) != "instance":
            return f"folder is for path options with scope instance (not type {_str(o, 'type')}, scope {scope_of(o)})"
        for name, on in (("mode", _str(o, "mode") != ""), ("needs", _str(o, "needs") != ""), ("writes_as", _has(o, "writes_as"))):
            if on:
                return f"{name} together with folder: folder.access and folder.runs_as replace them"
        access = _str(f, "access")
        if access == "":
            return "folder.access is required (read or write)"
        if access not in (FOLDER_READ, FOLDER_WRITE):
            return f"folder.access {_q(access)} must be read or write"
        ra = runs_as_of(o)
        if ra is None:
            return "folder.runs_as is required (the uid and gid the app uses on the mount)"
        join = _str(f, "joins_group")
        for what in ("uid", "gid"):
            num, env, frm = ra.get(what), _str(ra, what + "_env"), _str(ra, what + "_from")
            n = (num is not None) + (env != "") + (frm != "")
            # Each person's files: the template applies the folder gid itself.
            if what == "gid" and n == 0 and _str(ra, "uid_from") and join == JOIN_TEMPLATE:
                continue
            if n != 1:
                return (f"folder.runs_as.{what}: exactly one of {what}, {what}_env, {what}_from (a number, the env name of an "
                        "instance int option, or a person_id option)")
            if frm:
                if what == "gid" and not _str(ra, "uid_from"):
                    return "folder.runs_as.gid_from needs uid_from (a per-person tree: each person's private group is their uid)"
                if what == "gid" and join != JOIN_TEMPLATE:
                    return "folder.runs_as.gid_from needs joins_group: template"
                ro = next((x for x in self.options if _str(x, "key") == frm), None)
                if ro is None or ro.get("type") != "person_id":
                    return f"folder.runs_as.{what}_from {frm} is not a person_id option of this template"
                continue
            if num is not None:
                if not 0 <= num <= MAX_RUNS_AS_ID:
                    return f"folder.runs_as.{what} {num} is not a valid id (0-{MAX_RUNS_AS_ID})"
                if what == "gid" and in_folder_gid_range(num):
                    return f"folder.runs_as.gid {num} is in {GID_RANGE_TEXT}"
                continue
            if reserved_var(env) or env.startswith("PORTCULLIS_"):
                return f"folder.runs_as.{what}_env {env} is reserved (PORTCULLIS_*: core and the Hub set them)"
            ro = self.env_option(env)
            if ro is None:
                return f"folder.runs_as.{what}_env {env} is not the env name of an instance int option of this template"
            d, bad, inr = id_default(ro)
            if bad:
                return (f"folder.runs_as.{what}_env {env} names setting {_str(ro, 'key')}, whose default "
                        f"{quote_default(ro['default'])} is not a whole number")
            if inr and what == "gid":
                return f"folder.runs_as.{what}_env {env} names setting {_str(ro, 'key')}, whose default {d} is in {GID_RANGE_TEXT}"
        if join == JOIN_GID_ENV:
            if _str(ra, "gid_env") == "":
                return "folder.joins_group: gid_env needs runs_as.gid_env (the variable the folder gid is written to)"
        elif join not in ("", JOIN_GROUP_ADD, JOIN_TEMPLATE):
            return f"folder.joins_group {_q(join)} must be group_add, gid_env or template"
        if f.get("must_own") is True and access != FOLDER_WRITE:
            return "folder.must_own needs access: write (the Hub makes the app the owner of what it writes)"
        tg = o.get("target")
        if not isinstance(tg, dict):
            return None   # path_and_secret refuses it
        svc = _str(tg, "service")
        msg = self.compose_user_matches(svc, ra) or self.group_add_resolves(svc)
        if msg:
            return msg
        if join == JOIN_GID_ENV:
            leak = self.gid_env_leaks().get(_str(ra, "gid_env"))
            if leak:
                return leak
        return self.same_env_same_runs_as(o)

    def compose_user_matches(self, svc: str, ra: Dict[str, Any]) -> Optional[str]:
        u = self.users.get(svc, "")
        if u == "":
            return None
        if _str(ra, "uid_from"):
            return (f"folder.runs_as.uid_from: service {svc}'s compose user: {_q(u)} runs every process as one uid: each "
                    "person's own uid needs the service to start as root (no user:)")
        us, gs, has_gid = split_user(u)
        ids = [("uid", us, ra.get("uid"), _str(ra, "uid_env"))]
        if has_gid:
            ids.append(("gid", gs, ra.get("gid"), _str(ra, "gid_env")))
        for what, part, num, env in ids:
            pnum, penv, other = user_part(part)
            if other:
                return (f"service {svc}'s compose user: {_q(u)} is not numeric next to a folder block: give numbers "
                        "in compose `user:` (uid:gid, or ${PUID:-1000}:${PGID:-1000})")
            if pnum is not None and num is not None:
                if num != pnum:
                    return f"folder.runs_as.{what} {num} doesn't match service {svc}'s compose user: {_q(u)}"
            elif pnum is not None:
                return f"folder.runs_as.{what}_env {env} doesn't match service {svc}'s compose user: {_q(u)} (use {what}: {pnum})"
            elif num is not None:
                return (f"folder.runs_as.{what}: service {svc}'s compose user: takes it from ${{{penv}}}: use {what}_env: "
                        f"{penv}")
            elif env != penv:
                return (f"folder.runs_as.{what}_env {env} doesn't match service {svc}'s compose user: {_q(u)} "
                        f"(use {what}_env: {penv})")
        return None

    def group_add_resolves(self, svc: str) -> Optional[str]:
        for e in self.group_add.get(svc, []):
            if USER_NUM_RE.fullmatch(e):
                continue
            _, env, _ = user_part(e)
            if env and self.env_option(env) is not None:
                continue
            return (f"service {svc}'s group_add entry {_q(e)} next to a folder block must be a number or ${{NAME}} "
                    "of an instance int option")
        return None

    def gid_env_leaks(self) -> Dict[str, str]:
        """gidEnvLeaks: per gid_env join variable, the first other service
        (sorted) whose compose user: gid or group_add reads it."""
        targets: Dict[str, Set[str]] = {}
        for o in self.options:
            f, ra, tg = o.get("folder"), runs_as_of(o), o.get("target")
            if not isinstance(f, dict) or _str(f, "joins_group") != JOIN_GID_ENV or ra is None or not _str(ra, "gid_env") \
                    or not isinstance(tg, dict):
                continue
            targets.setdefault(_str(ra, "gid_env"), set()).add(_str(tg, "service"))
        out: Dict[str, str] = {}
        for env, on in targets.items():
            for s in self.services():
                if s in on:
                    continue
                _, g, ok = split_user(self.users.get(s, ""))
                reads = []
                if ok and user_part(g)[1] == env:
                    reads.append("compose user: gid")
                if any(user_part(e)[1] == env for e in self.group_add.get(s, [])):
                    reads.append("group_add")
                for what in reads:
                    out.setdefault(env, f"folder.joins_group: gid_env writes the folder gid to {env}, which service {s}'s "
                                        f"{what} also reads: only the services the folder options target may use a gid_env variable")
        return out

    def same_env_same_runs_as(self, o: Dict[str, Any]) -> Optional[str]:
        ra = runs_as_of(o) or {}
        svc = _str(o.get("target") or {}, "service")
        for p in self.options:
            if p is o or _str(p, "key") == _str(o, "key"):
                break
            pr, ptg = runs_as_of(p), p.get("target")
            if not isinstance(p.get("folder"), dict) or pr is None or not isinstance(ptg, dict) or _str(ptg, "service") != svc:
                continue
            for j in (p, o):
                if folder_join(j) == JOIN_GID_ENV and _str(ra, "gid_env") != _str(pr, "gid_env"):
                    other = p if j is o else o
                    g = _str(runs_as_of(j) or {}, "gid_env")
                    return (f"service {svc} joins a folder group through gid_env {g}: every folder option on it must use "
                            f"runs_as.gid_env {g} (setting {_str(other, 'key')} doesn't)")
            if _str(ra, "gid_env") and _str(ra, "gid_env") == _str(pr, "gid_env"):
                shared = "gid_env " + _str(ra, "gid_env")
            elif _str(ra, "uid_env") and _str(ra, "uid_env") == _str(pr, "uid_env"):
                shared = "uid_env " + _str(ra, "uid_env")
            else:
                continue
            if runs_as_norm(ra) != runs_as_norm(pr) or folder_join(o) != folder_join(p):
                return (f"folder names {shared} like setting {_str(p, 'key')} on service {svc}, with another runs_as or "
                        "joins_group (one primary gid per process: use identical blocks)")
        return None

    # option-level doctor checks (checks)

    def checks(self, o: Dict[str, Any]) -> Optional[str]:
        seen: Set[str] = set()
        for i, c in enumerate(o.get("checks") or []):
            c = c if isinstance(c, dict) else {}
            kind = _str(c, "kind")
            if kind == CHECK_LAN_ONLY:
                return f"checks[{i}]: kind lan_only is not an option check: set lan_only: true on the port"
            if kind not in CHECK_KINDS:
                return f"checks[{i}]: unknown kind {_q(kind)} (the catalog: {', '.join(CHECK_KINDS)})"
            w = f"checks[{i}] ({kind})"
            if kind in seen:
                return f"{w}: listed twice"
            seen.add(kind)
            reason = _str(c, "reason")
            if reason.strip() == "" or len(reason) > CHECK_REASON_MAX or has_control(reason):
                return f"{w}: reason must be one line of 1-{CHECK_REASON_MAX} characters, without control characters"
            path, folder = o.get("type") == "path", isinstance(o.get("folder"), dict)
            if kind == "filesystem" and not (path and folder):
                return f"{w}: needs a path option with a folder block"
            if kind == "exclusive" and not (path and folder and _str(o["folder"], "access") == FOLDER_WRITE):
                return f"{w}: needs a path option with folder.access: write"
            if kind == "free_space" and not path:
                return f"{w}: needs a path option"
            if kind == "requires_group_value" and scope_of(o) != "person":
                return f"{w}: needs scope: person"
            for p, on in (("needs", _has(c, "needs")), ("not", _has(c, "not")), ("min", _str(c, "min") != "")):
                if on and p not in CHECK_PARAMS.get(kind, ()):
                    return f"{w}: {kind} takes no {p}"
            if kind == "filesystem":
                needs, nots = c.get("needs") or [], c.get("not") or []
                if not needs and not nots:
                    return f"{w}: filesystem needs needs or not (what to check)"
                for field, items, allowed, want in (("needs", needs, FS_NEEDS, "xattr or acl"), ("not", nots, FS_NOT, "nfs, cifs or fuse")):
                    got: Set[str] = set()
                    for x in items:
                        x = scalar_text(x)
                        if x not in allowed:
                            return f"{w}: {field} {_q(x)} must be {want}"
                        if x in got:
                            return f"{w}: {field} {_q(x)} listed twice"
                        got.add(x)
            if kind == "free_space" and _str(c, "min") == "":
                return f"{w}: free_space needs min (a size such as 500GiB)"
        return None


def check_checks(o: Dict[str, Any]) -> None:
    """settings.checkChecks: free_space.min is a size in binary units, > 0."""
    for i, c in enumerate(o.get("checks") or []):
        if not isinstance(c, dict) or _str(c, "kind") != "free_space" or _str(c, "min") == "":
            continue
        m = _str(c, "min")
        try:
            n = parse_size(m)
        except SettingError as e:
            raise SettingError(f"checks[{i}] (free_space): min {_q(m)}: {e}") from None
        if n <= 0:
            raise SettingError(f"checks[{i}] (free_space): min must be more than 0")


def check_folders(t: Template, services: Dict[str, Any], r: Report) -> None:
    """The compose-level shared-folder rules (Hub composeIDs + composeGIDs,
    on every service of every template, settings or not): reads compose
    user: / group_add for the option checks (t.compose_users /
    t.compose_group_add) and refuses gids in 60000-60999 and any uid / gid
    source that isn't a number, a name or exactly one ${NAME} of an
    instance int option."""
    users, group_add, err = compose_ids(t.compose_text)
    t.compose_users, t.compose_group_add = users, group_add
    if err:
        r.error(t.c_where, err, FOLDERS_HINT)
        return
    fc = FolderCheck(setting_options(t.manifest or {}), users, group_add)
    for msg in fc.compose_gids():
        r.error(t.c_where, msg, FOLDERS_HINT)


def user_fallbacks(svc: str, u: str) -> Optional[str]:
    """userFallbacks: every ${…} fallback in compose user: is only digits."""
    i = 0
    while i < len(u):
        if u[i] != "$" or i + 1 >= len(u):
            i += 1
            continue
        if u[i + 1] == "$":
            i += 2
            continue
        if u[i + 1] == "{" and not BRACE_REF_RE.match(u, i):
            return (f"service {svc}: compose user: {_q(u)}: a ${{…}} fallback may only be a whole "
                    "number (no ':', '$' or nesting)")
        i += 1
    return None


class _Refuse(Exception):
    pass


# ── file sharing (contract §3 router-less, §13.2 person_secret / person_id;
# Hub internal/templates/filesharing.go and reservedvars.go) ──

USERNAME_REASON_MAX, USERNAME_PATTERN_MAX, RESERVED_NAME_MAX = 200, 500, 64
INFO_LABEL_MAX, INFO_VALUE_MAX = 64, 500
PERSON_SECRET_MIN_LENGTH = 24
PERSON_ID_POOLS = {"posix_uid": (20000, 59999)}
USERNAME_PATTERN_VAR = "PORTCULLIS_USERNAME_PATTERN"
USERNAME_RESERVED_VAR = "PORTCULLIS_USERNAME_RESERVED"
PATTERN_SPECIAL = "\\.[]{}()|*+?^$"
PATTERN_CLASSES = {"alnum", "alpha", "digit", "lower", "upper", "xdigit"}
PORT_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
INFO_VALUE_TYPES = {"string", "int", "enum", "bool"}
SHARING_HINT = f"see {DOCS_URL}/integration-contracts/#1316-per-person-credentials-and-ids-new-file-sharing"


def _pattern_class(s: bytes) -> Tuple[int, str]:
    """patternClass: the length of the bracket class at the start of s, or a problem."""
    i, items = 1, 0
    if i < len(s) and s[i:i + 1] == b"^":
        i += 1
    while i < len(s):
        c = s[i:i + 1]
        if c == b"]":
            if items == 0:
                return 0, "an empty bracket class"
            return i + 1, ""
        if s.startswith(b"[:", i):
            end = s.find(b":]", i + 2)
            if end < 0 or s[i + 2:end].decode() not in PATTERN_CLASSES:
                return 0, "a bracket class names only [:alnum:], [:alpha:], [:digit:], [:lower:], [:upper:] or [:xdigit:]"
            i = end + 2
        elif c in (b"[", b"\\"):
            return 0, f"'{c.decode()}' inside a bracket class (no collating elements [. .] or equivalence classes [= =])"
        else:
            i += 1
        items += 1
    return 0, "an unclosed bracket class"


def _pattern_count(s: bytes) -> Optional[int]:
    if not s or len(s) > 4 or s.strip(b"0123456789"):
        return None
    n = int(s)
    return n if n <= 1000 else None


def _pattern_interval(s: bytes) -> Tuple[int, str]:
    """patternInterval: the length of the {m} / {m,n} at the start of s, or a problem."""
    bad = "an interval is {m} or {m,n} with m <= n <= 1000"
    end = s.find(b"}")
    if end < 0:
        return 0, bad
    ms, two, ns = s[1:end].partition(b",")
    if not two:
        ns = ms
    m, n = _pattern_count(ms), _pattern_count(ns)
    if m is None or n is None or m > n:
        return 0, bad
    return end + 1, ""


def username_pattern_problem(p: str) -> str:
    """usernamePattern (F37, Task 3 fix round 1): only the patterns Go's RE2
    and busybox ERE read alike:

        pattern  = "^" atom* "$"
        atom     = (literal | class) [interval]
        literal  = a byte 0x21-0x7E other than \\ . [ ] { } ( ) | * + ? ^ $
        class    = "[" ["^"] item+ "]"
        item     = "[:" name ":]" | a byte 0x21-0x7E other than \\ [ ]
        name     = alnum | alpha | digit | lower | upper | xdigit
        interval = "{" m "}" | "{" m "," n "}"   (decimal, m <= n <= 1000)

    then RE2 must compile it. "" = accepted."""
    b = p.encode("utf-8", "surrogatepass")
    if len(b) > USERNAME_PATTERN_MAX:
        return f"at most {USERNAME_PATTERN_MAX} characters"
    if len(b) < 2 or b[:1] != b"^" or b[-1:] != b"$":
        return "must be anchored (^…$)"
    if any(c < 0x21 or c > 0x7E for c in b):
        return "only printable ASCII without spaces"
    body = b[1:-1]
    i = 0
    while i < len(body):
        c = body[i:i + 1]
        if c == b"[":
            n, why = _pattern_class(body[i:])
        elif c.decode() not in PATTERN_SPECIAL:
            n, why = 1, ""
        else:
            n, why = 0, (f"'{c.decode()}' at {i + 1} is not a literal, a bracket class or an interval after one (only what "
                         "RE2 and busybox ERE read alike)")
        if why:
            return why
        i += n
        if i < len(body) and body[i:i + 1] == b"{":
            n, why = _pattern_interval(body[i:])
            if why:
                return why
            i += n
    try:
        re2.compile(p, _RE2_OPTIONS)
    except re2.error as e:
        msg = e.args[0].decode() if e.args and isinstance(e.args[0], bytes) else str(e)
        return f"error parsing regexp: {msg}"
    return ""


def go_var_refs(s: str) -> List[Tuple[str, bool]]:
    """varRefs: the interpolations of compose value s ($$ is a literal $):
    (name, exactly ${NAME})."""
    out: List[Tuple[str, bool]] = []
    i = 0
    while i < len(s):
        if s[i] != "$":
            i += 1
            continue
        if i + 1 < len(s) and s[i + 1] == "$":
            i += 2
            continue
        j = i + 1
        braced = j < len(s) and s[j] == "{"
        if braced:
            j += 1
        k = j
        while k < len(s) and (s[k] == "_" or "A" <= s[k] <= "Z" or "a" <= s[k] <= "z" or "0" <= s[k] <= "9"):
            k += 1
        if k > j:
            out.append((s[j:k], braced and k < len(s) and s[k] == "}"))
        i += 1
    return out


def folder_gid_var(key: str) -> str:
    """FolderGIDVar: the variable the Hub writes a folder option's gid to."""
    return FOLDER_VAR_PREFIX + "GID_" + key.upper()


def names_secrets_volume_key(s: Any) -> bool:
    """NamesSecretsVolumeKey: s (folded) names or embeds the Hub's secrets volume key."""
    return isinstance(s, str) and SECRETS_VOLUME_KEY in fold_key(s.strip())


class _SpecCheck:
    """ValidateSettingsSpec over one template (contract §13)."""

    def __init__(self, t: Template, services: Dict[str, Any], routers: Dict[str, Dict[str, str]], r: Report) -> None:
        self.t, self.r = t, r
        self.m: Dict[str, Any] = t.manifest or {}
        self.auth: Dict[str, Any] = self.m.get("auth") if isinstance(self.m.get("auth"), dict) else {}
        self.services = {str(k): (s if isinstance(s, dict) else {}) for k, s in services.items()}
        self.routers = routers
        self.env = compose_environment(self.services)
        self.folders = FolderCheck(setting_options(self.m), t.compose_users, t.compose_group_add)
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

    def cerr(self, msg: str, hint: str = SETTINGS_HINT) -> None:
        self.r.error(self.t.c_where, msg, hint)

    @property
    def routerless(self) -> bool:
        """routerlessOf: method custom and no HTTP router (§3)."""
        return _str(self.auth, "method") == "custom" and not self.routers

    def run(self) -> None:
        self.check_reserved_var_refs()
        self.check_files()
        self.check_hooks()
        self.check_reload()
        self.check_secret_mounters()
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
        self.check_username_pattern_env()
        self.check_username_reserved_env()

    # file sharing: compose-level rules

    def check_reserved_var_refs(self) -> None:
        """reservedVarRefs (F36): ${PORTCULLIS_LOCAL_NETWORKS} only exactly so;
        ${PORTCULLIS_FOLDER_GID_<KEY>} only as a whole environment: value of
        the service <KEY>'s folder block targets; no other PORTCULLIS_FOLDER_*.
        PORTCULLIS_UNPRIVILEGED_PORT_START not available to templates (P15)."""
        # VPN-only access (§2, §3): PORTCULLIS_VPN_* are core.env's and the
        # Hub's, never compose interpolation; a gateway's shell reads the
        # PORTCULLIS_VPN_EDGE the Hub sets as $$PORTCULLIS_VPN_EDGE.
        for sc in self.scalars:
            for name, _ in go_var_refs(sc):
                if name.startswith(VAR_VPN_PREFIX):
                    self.cerr(f"${{{name}}} is reserved: PORTCULLIS_VPN_* are core's and the Hub's (the Hub sets "
                              "PORTCULLIS_VPN_EDGE in the ingress container's environment: read it in a container shell as "
                              "$$PORTCULLIS_VPN_EDGE)", VPN_HINT)
                    return
        # P15: PORTCULLIS_UNPRIVILEGED_PORT_START is core.env-only, never available to templates
        for sc in self.scalars:
            if "PORTCULLIS_UNPRIVILEGED_PORT_START" in sc:
                self.cerr("PORTCULLIS_UNPRIVILEGED_PORT_START is not available to templates (core.env-only)",
                          "templates use fixed port numbers, host-networking-only ports in manifest ports[], or "
                          "the Hub's compatibility check against the host's setting")
                return

        allowed: Dict[str, List[str]] = {}
        for o in setting_options(self.m):
            tg = o.get("target")
            if o.get("type") == "path" and isinstance(o.get("folder"), dict) and isinstance(tg, dict) and _str(tg, "service"):
                allowed.setdefault(folder_gid_var(_str(o, "key")), []).append(_str(tg, "service"))
        ok_count: Dict[str, int] = {}
        for svc in sorted(self.env):
            for val in self.env[svc].values():
                if val is None:
                    continue
                for name, svcs in allowed.items():
                    if val == "${" + name + "}" and svc in svcs:
                        ok_count[name] = ok_count.get(name, 0) + 1

        def folder_refusal(name: str) -> None:
            self.cerr(f"{name} is set by the Hub: only ${{PORTCULLIS_FOLDER_GID_<KEY>}} may be read, exactly so, as a whole "
                      "environment: value of the service that <KEY>'s folder block targets",
                      "PORTCULLIS_FOLDER_GID_<KEY> is for a template that applies a path option's folder gid itself "
                      "(folder.joins_group: template); " + FOLDERS_HINT)
        seen: Dict[str, int] = {}
        for sc in self.scalars:
            for name, exact in go_var_refs(sc):
                if name == VAR_LOCAL_NETWORKS:
                    if not exact:
                        self.cerr(f"{VAR_LOCAL_NETWORKS} may appear only as exactly ${{{VAR_LOCAL_NETWORKS}}} (no default or "
                                  f"alternate form, no bare ${VAR_LOCAL_NETWORKS})",
                                  "the Hub always writes it (an empty value means loopback only): a default would widen what "
                                  "the app allows; " + FOLDERS_HINT)
                        return
                elif name.startswith(FOLDER_VAR_PREFIX):
                    ref = "${" + name + "}"
                    whole = sc == ref or (sc.endswith("=" + ref) and bool(ENV_KEY_RE.fullmatch(sc[:-len("=" + ref)])))
                    if not exact or not whole or not allowed.get(name):
                        folder_refusal(name)
                        return
                    seen[name] = seen.get(name, 0) + 1
        for name in sorted(seen):
            if seen[name] > ok_count.get(name, 0):
                folder_refusal(name)
                return

    def secret_mounters(self) -> Set[str]:
        return {_str(o["mount"], "service") for o in setting_options(self.m)
                if o.get("type") == "person_secret" and isinstance(o.get("mount"), dict)}

    def check_secret_mounters(self) -> None:
        """The Hub's pre-up check (secretsmount.go, Task 6 fix round 1b): with
        a person_secret mount, every service's pid / ipc stays private (no
        host, container:* or service:*, in either direction) and no service
        takes a mounter's volumes; and (contract §13.17, this repo's rule)
        every published port is lan_only."""
        mounters = self.secret_mounters()
        if not mounters:
            return
        hint = ("a shared pid or ipc namespace reaches the hash files of the service mounting a person_secret "
                "(/proc/<pid>/root) or its memory; " + SHARING_HINT)
        for n in sorted(self.services):
            svc = self.services[n]
            for field in ("pid", "ipc"):
                val = svc.get(field)
                lv = scalar_text(val).strip().lower() if val is not None else ""
                if lv in ("", "private") or (field == "ipc" and lv in ("shareable", "none")):
                    continue
                self.cerr(f"service {n} shares the {field} namespace {scalar_text(val)}: the Hub refuses to start a "
                          "template with a person_secret mount whose services share a pid or ipc namespace", hint)
            for vf in as_list(svc.get("volumes_from")):
                vf = scalar_text(vf)
                src = vf[len("service:"):] if vf.startswith("service:") else vf
                src = src.split(":", 1)[0]
                if vf.startswith("container:") or src in mounters:
                    self.cerr(f"service {n} takes the volumes of {vf} (volumes_from): it would read the person_secret "
                              "hash files", hint)
        for p in self.m.get("ports") or []:
            if isinstance(p, dict) and p.get("lan_only") is not True:
                self.err(f"port {_str(p, 'key')}: a template with a person_secret option publishes only lan_only ports: "
                         "set lan_only: true", "file-sharing ports are for the local networks only (contract §13.17); "
                         "the doctor judges their binding (§14.7)")

    def check_username_pattern_env(self) -> None:
        """usernamePatternEnv: a compose PORTCULLIS_USERNAME_PATTERN is a
        person_secret's username.pattern with every $ written $$ (§13.2)."""
        patterns = set()
        for o in setting_options(self.m):
            u = o.get("username")
            if o.get("type") == "person_secret" and isinstance(u, dict) and _str(u, "pattern"):
                patterns.add(_str(u, "pattern"))
        for svc in sorted(self.env):
            if USERNAME_PATTERN_VAR not in self.env[svc]:
                continue
            val = self.env[svc][USERNAME_PATTERN_VAR]
            if val is None or "$" in val.replace("$$", "") or val.replace("$$", "$") not in patterns:
                self.cerr(f"service {svc}: {USERNAME_PATTERN_VAR} must be a person_secret option's username.pattern with "
                          "every $ written as $$", "the script and the Hub apply one username rule; " + SHARING_HINT)

    def check_username_reserved_env(self) -> None:
        """A compose PORTCULLIS_USERNAME_RESERVED is a person_secret's
        username.reserved joined by single spaces, in order (portcullis-sync
        refuses the same names as the Hub, F37)."""
        lists = set()
        for o in setting_options(self.m):
            u = o.get("username")
            if o.get("type") == "person_secret" and isinstance(u, dict) and isinstance(u.get("reserved"), list):
                lists.add(" ".join(str(x) for x in u["reserved"]))
        for svc in sorted(self.env):
            if USERNAME_RESERVED_VAR not in self.env[svc]:
                continue
            if self.env[svc][USERNAME_RESERVED_VAR] not in lists:
                self.cerr(f"service {svc}: {USERNAME_RESERVED_VAR} must be a person_secret option's username.reserved "
                          "joined by single spaces, in order", "the script and the Hub refuse the same names; " + SHARING_HINT)

    # file sharing: the two types (filesharing.go)

    def file_sharing_template(self, o: Dict[str, Any]) -> None:
        """F1: a router-less custom template whose access group is the population."""
        if not self.routerless or self.auth.get("group_access") is not True or not _str(self.auth, "access_group"):
            raise _Refuse(f"{o.get('type')} needs a router-less template: auth.method custom with no HTTP router, "
                          "group_access: true and an auth.access_group (who gets one)")

    @staticmethod
    def person_fields_refused(o: Dict[str, Any], *extra: Tuple[str, bool]) -> None:
        fs = [("scope", _str(o, "scope") != ""), ("default", _has(o, "default")), ("required", o.get("required") is True),
              ("resolve", _str(o, "resolve") != ""), ("resolve_choices", _set(o, "resolve_choices")),
              ("group_values", _set(o, "group_values")), ("privileged", o.get("privileged") is True),
              ("requires", _set(o, "requires")), ("requires_any", _set(o, "requires_any")),
              ("admin_override", o.get("admin_override") is True), ("unique", o.get("unique") is True),
              ("generate", _has(o, "generate")), ("writes_as", _has(o, "writes_as"))]
        for f, on in fs + list(extra):
            if on:
                raise _Refuse(f"{o.get('type')} takes no {f} (the Hub sets one value per person)")

    def person_secret(self, o: Dict[str, Any]) -> None:
        self.file_sharing_template(o)
        self.person_fields_refused(o, ("self_visible", _has(o, "self_visible")), ("checks", _set(o, "checks")))
        if _str(o, "hash") != "nt":
            raise _Refuse("hash must be nt (the NT hash)")
        length = o.get("length") if isinstance(o.get("length"), int) and not isinstance(o.get("length"), bool) else 0
        if length < PERSON_SECRET_MIN_LENGTH:
            raise _Refuse(f"length {length} must be at least {PERSON_SECRET_MIN_LENGTH}")
        if length % 4:
            raise _Refuse(f"length {length} must be a multiple of 4 (the password is shown in groups of 4)")
        if o.get("delivery") != "file":
            raise _Refuse("a person_secret takes exactly delivery: file (its hash files are mounted at mount); env, claim, "
                          "header, hook and data-file deliveries are refused")
        applies = _str(o, "applies")
        if applies not in ("", "live"):
            raise _Refuse(f"applies {applies}: a person_secret applies live (its credential_change hook)")
        mt = self.secret_mount(o)
        if o.get("revoke_on_leave") is not True:
            raise _Refuse("revoke_on_leave must be true (a person who leaves loses the password)")
        if _str(o, "on_restore") != "void":
            raise _Refuse("on_restore must be void (a restore voids every password)")
        self.username_rule(o.get("username"))
        for i, line in enumerate(o.get("info") or []):
            try:
                self.info_line(line if isinstance(line, dict) else {})
            except _Refuse as e:
                raise _Refuse(f"info[{i}]: {e}") from None
        svc = _str(mt, "service")
        for h in self.m.get("hooks") or []:
            if isinstance(h, dict) and _str(h, "service") == svc and "credential_change" in (h.get("when") or []):
                return
        raise _Refuse(f"a person_secret needs a hook on service {svc} (its mount.service) whose when lists credential_change: "
                      "it applies revocations live")

    def secret_mount(self, o: Dict[str, Any]) -> Dict[str, Any]:
        mt = o.get("mount")
        if not isinstance(mt, dict):
            raise _Refuse("a person_secret needs mount {service, path}: where its hash files are mounted read-only")
        svc, path = _str(mt, "service"), _str(mt, "path")
        if svc not in self.services:
            raise _Refuse(f"mount.service {svc} is not in compose.yml")
        if not valid_mount(path):
            raise _Refuse(f"mount.path {_q(path)} must be an absolute, clean container directory (no ':')")
        for f in self.m.get("files") or []:
            if isinstance(f, dict) and _str(f, "service") == svc and _nested(_str(f, "mount"), path):
                raise _Refuse(f"mount.path {path} collides with files[{_str(f, 'name')}] ({_str(f, 'mount')}) on service {svc}")
        options = setting_options(self.m)
        mine = next((i for i, x in enumerate(options) if x is o), len(options))
        for i, p in enumerate(options):
            if p is o or _str(p, "key") == _str(o, "key"):
                continue
            tg, pm = p.get("target"), p.get("mount")
            if p.get("type") == "path" and isinstance(tg, dict) and _str(tg, "service") == svc and _nested(_str(tg, "mount"), path):
                raise _Refuse(f"mount.path {path} collides with setting {_str(p, 'key')}'s target {_str(tg, 'mount')} on service {svc}")
            if p.get("type") == "person_secret" and isinstance(pm, dict) and _str(pm, "service") == svc \
                    and _nested(_str(pm, "path"), path) and i < mine:
                raise _Refuse(f"mount.path {path} collides with setting {_str(p, 'key')}'s mount {_str(pm, 'path')} on service {svc}")
        return mt

    @staticmethod
    def username_rule(u: Any) -> None:
        """checkUsernameRule (None = no rule)."""
        if not isinstance(u, dict):
            return
        pat = _str(u, "pattern")
        if pat:
            why = username_pattern_problem(pat)
            if why:
                raise _Refuse(f"username.pattern {_q(pat)}: {why}")
        for r in u.get("reserved") or []:
            r = scalar_text(r)
            if r == "" or blen(r) > RESERVED_NAME_MAX or r != r.lower() or has_control(r) or " " in r or "\t" in r:
                raise _Refuse(f"username.reserved {_q(r)}: want lowercase names (at most {RESERVED_NAME_MAX} characters, no spaces)")
        reason = _str(u, "reason")
        if reason.strip() == "" or len(reason) > USERNAME_REASON_MAX or has_control(reason):
            raise _Refuse(f"username.reason must be one line of 1-{USERNAME_REASON_MAX} characters (shown to a person whose "
                          "name the app can't serve)")

    def info_line(self, line: Dict[str, Any]) -> None:
        label, value = _str(line, "label"), _str(line, "value")
        if label.strip() == "" or len(label) > INFO_LABEL_MAX or has_control(label):
            raise _Refuse(f"label must be one line of 1-{INFO_LABEL_MAX} characters")
        if value == "" or len(value) > INFO_VALUE_MAX or has_control(value):
            raise _Refuse(f"value must be one line of 1-{INFO_VALUE_MAX} characters")
        i = 0
        while i < len(value):
            c = value[i]
            if c == "}":
                raise _Refuse(f"value {_q(value)}: a }} outside a placeholder")
            if c == "{":
                j = value.find("}", i)
                if j < 0:
                    raise _Refuse(f"value {_q(value)}: an unclosed {{")
                why = self.placeholder(value[i + 1:j])
                if why:
                    raise _Refuse(f"value {_q(value)}: {why}")
                i = j
            i += 1

    def placeholder(self, p: str) -> str:
        """One {…} of an info value (without the braces): the problem, or ""."""
        def port(k: str) -> str:
            if not PORT_KEY_RE.fullmatch(k):
                return f"{{{p}}}: {_q(k)} is not a port key"
            if any(isinstance(pt, dict) and _str(pt, "key") == k for pt in self.m.get("ports") or []):
                return ""
            return f"{{{p}}}: no declared port {k} (ports[].key)"
        if p == "user":
            return ""
        if p.startswith("value:"):
            k = p[len("value:"):]
            o = self.opts.get(k)
            if o is None:
                return f"{{{p}}}: no such option"
            if scope_of(o) != "instance" or o.get("type") not in INFO_VALUE_TYPES:
                return f"{{{p}}}: only an instance string, int, enum or bool option may be shown"
            if o.get("self_visible") is not True:
                return f"{{{p}}}: setting {k} must set self_visible: true to be shown"
            return ""
        if p.startswith("port:"):
            return port(p[len("port:"):])
        if p.startswith("port_suffix:"):
            k, colon, d = p[len("port_suffix:"):].partition(":")
            if not colon:
                return f"{{{p}}}: want {{port_suffix:<KEY>:<default port>}}"
            if not re.fullmatch(r"[1-9][0-9]{0,4}", d, re.ASCII) or int(d) > 65535:
                return f"{{{p}}}: default {_q(d)} must be a port number (1-65535)"
            return port(k)
        return f"{{{p}}} is not a placeholder ({{user}}, {{value:<key>}}, {{port:<KEY>}}, {{port_suffix:<KEY>:<default>}})"

    def person_id(self, o: Dict[str, Any]) -> None:
        self.file_sharing_template(o)
        self.person_fields_refused(o)
        if _str(o, "pool") not in PERSON_ID_POOLS:
            raise _Refuse("pool must be posix_uid (the Hub-wide uid pool)")
        if o.get("self_visible") is not False:
            raise _Refuse("a person_id needs self_visible: false (never shown on My apps)")
        why = self.folders.checks(o)
        if why:
            raise _Refuse(why)
        raw = o.get("delivery")
        ds = [raw] if isinstance(raw, str) else (raw if isinstance(raw, list) else [])
        if not ds:
            raise _Refuse("a person_id needs a file delivery ({file: {name, field}}: the people section of a data file)")
        for d in ds:
            if not isinstance(d, dict) or not isinstance(d.get("file"), dict) or any(_has(d, k) for k in ("env", "claim", "header", "hook", "render")):
                raise _Refuse("a person_id takes only file deliveries ({file: {name, field}})")
            self.file(o, d["file"])
            fname = _str(d["file"], "name")
            if _str(o, "applies") == "live" and _str(self.files[fname], "on_membership_change") != "hook":
                raise _Refuse(f"applies: live means a hook applies it: file {fname} needs on_membership_change: hook")

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
            if _str(f, "format") not in ("", "json", "tsv"):
                problems.append(f"format {json.dumps(_str(f, 'format'))} must be json or tsv")
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
                problems.append("when must list at least one trigger (start, settings_change, membership_change, credential_change, ai, vpn)")
            for tr in when:
                if tr not in HOOK_TRIGGERS:
                    problems.append(f"when {json.dumps(scalar_text(tr))} must be start, settings_change, membership_change, "
                                    "credential_change, ai or vpn")
            if "ai" in when and len(when) != 1:
                problems.append("when: ai can't be combined with another trigger (an ai hook is run only by the AI machinery): "
                                "write exactly when: [ai]")
            elif "vpn" in when and len(when) != 1:
                problems.append("vpn can't be combined with other triggers")
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
            elif is_ai_hook(self.hooks[hook]):
                self.err(f"reload: hook {hook} is an ai hook (when: [ai]): the settings engine never runs it")
            elif is_vpn_hook(self.hooks[hook]):
                self.err(f"reload: hook {hook} is a vpn hook (when: [vpn]): the settings engine never runs it")
        else:
            if svc not in self.services:
                self.err(f"reload: service {json.dumps(svc)} is not in compose.yml")
            if sig not in RELOAD_SIGNALS:
                self.err(f"reload: signal {json.dumps(sig)} must be HUP, USR1 or USR2")

    # options

    def type_problem(self, o: Dict[str, Any]) -> str:
        t = _str(o, "type")
        bad = runs_as_number_problem(o)   # the Hub's strict decode, before everything
        if bad:
            return bad
        if t in OLD_TYPES:
            return f"type {t} is template contract v2: {OLD_TYPES[t]}"
        if t == "folder":
            return FOLDER_TYPE_REFUSAL
        why = file_sharing_fields(o)
        if why:
            return why
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
            if i in bad or o.get("type") in PERSON_TYPES:
                continue   # person_secret / person_id: no env (their own checks refuse an env delivery)
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
        if label == "" or len(label) > 64 or has_control(label):
            raise _Refuse("label must be a single non-empty line of at most 64 characters")
        if blen(desc) > 500 or any(c != "\n" and is_control_rune(c) for c in desc):
            raise _Refuse("description must be at most 500 characters, without control characters")
        sec = _str(o, "section")
        if sec and sec not in self.sections:
            raise _Refuse(f"section {json.dumps(sec)} is not listed in settings.sections")
        applies = _str(o, "applies")
        if applies and applies not in APPLIES:
            raise _Refuse(f"applies {json.dumps(applies)} must be live, reload, next_request, next_sign_in, restart or account_creation")
        if o.get("type") == "person_secret":
            return self.person_secret(o)
        if o.get("type") == "person_id":
            return self.person_id(o)
        scope = scope_of(o)
        if scope not in SCOPES:
            raise _Refuse(f"scope {json.dumps(_str(o, 'scope'))} must be instance, person, group or person_entered")
        why = self.folders.folder_option(o) or self.folders.checks(o)
        if why:
            raise _Refuse(why)
        if scope == "person_entered":
            self.person_entered(o)
        t = o.get("type")
        sv = o.get("self_visible")
        if o.get("privileged") and scope != "person":
            raise _Refuse("privileged needs scope: person")
        # An instance option may set self_visible: true (never false) for a
        # person_secret info line's {value:<key>} (§13.1).
        if sv is not None and scope != "person" and not (scope in ("person_entered", "instance") and sv is True):
            raise _Refuse("self_visible needs scope: person (an instance option may only set self_visible: true)")
        if (_str(o, "resolve") or o.get("resolve_choices")) and scope != "person":
            raise _Refuse("resolve and resolve_choices need scope: person")
        if _has(o, "group_values") and scope != "person":
            raise _Refuse("group_values need scope: person")
        if o.get("admin_override") and scope != "person_entered":
            raise _Refuse("admin_override needs scope: person_entered")
        if t == "secret" and scope != "instance":
            raise _Refuse("a secret option needs scope instance (a secret is write-only, stored apart from the settings)")
        if scope == "person" and not _has(o, "default"):
            raise _Refuse("scope person needs a default (the value for everyone else with access)")
        if o.get("required") and scope == "group":
            raise _Refuse("required is not for scope group (its records are optional, and it has no default)")
        if o.get("required") and scope == "person" and empty_default(o.get("default")):
            raise _Refuse("required on scope person needs a non-empty default (the value for everyone without a row)")
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
        if scope == "person" and not _str(o, "resolve"):
            raise _Refuse("scope person needs resolve (how a person's rows combine: max, min, priority, union, intersection, any or all)")

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
        """requires and requires_any (§13.9): instance options naming other instance options."""
        for field in ("requires", "requires_any"):
            reqs = [scalar_text(k) for k in o.get(field) or []]
            if reqs and scope_of(o) != "instance":
                raise _Refuse(f"{field} is for instance options")
            for k in reqs:
                ro = self.opts.get(k)
                if k == _str(o, "key"):
                    raise _Refuse(f"{field} names itself")
                if ro is None:
                    raise _Refuse(f"{field} {k}: no such option")
                if scope_of(ro) != "instance":
                    raise _Refuse(f"{field} {k}: not an instance option")

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
                    if what == "gid" and in_folder_gid_range(ref):
                        raise _Refuse(f"writes_as.gid {ref} is in {GID_RANGE_TEXT}")
                elif isinstance(ref, str) and ref != "":
                    ro = self.opts.get(ref)
                    if ro is None or scope_of(ro) != "instance" or ro.get("type") not in ("int", "string"):
                        raise _Refuse(f"writes_as.{what}: {ref} is not an instance int or string option")
                    d, bad, inr = id_default(ro)
                    if bad:
                        raise _Refuse(f"writes_as.{what}: setting {ref}'s default {quote_default(ro['default'])} is not a whole number")
                    if inr and what == "gid":
                        raise _Refuse(f"writes_as.{what}: setting {ref}'s default {d} is in {GID_RANGE_TEXT}")
                else:
                    raise _Refuse(f"writes_as.{what}: a number or an option key")
        g = o.get("generate")
        if isinstance(g, dict):
            length = g.get("length") if isinstance(g.get("length"), int) else 0
            if not 8 <= length <= 128:
                raise _Refuse(f"generate.length {length} must be 8-128")
            if _str(g, "charset") not in GENERATE_CHARSETS:
                raise _Refuse(f"generate.charset {json.dumps(_str(g, 'charset'))} must be hex, alphanumeric or ascii_printable")
            if _has(o, "min_len") and length < o["min_len"]:
                raise _Refuse(f"generate.length {length} is below min_len {o['min_len']}")
            if _has(o, "max_len") and length > o["max_len"]:
                raise _Refuse(f"generate.length {length} is above max_len {o['max_len']}")

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
                if is_ai_hook(self.hooks[_str(d, "hook")]):
                    raise _Refuse(f"hook {_str(d, 'hook')} is an ai hook (when: [ai]): no option delivers to it")
                if is_vpn_hook(self.hooks[_str(d, "hook")]):
                    raise _Refuse(f"hook {_str(d, 'hook')} is a vpn hook (when: [vpn]): no option delivers to it")
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
        if _str(self.files[fname], "format") == "tsv":
            if o.get("type") == "table":
                raise _Refuse(f"file {fname} is tsv, which has no table rows: deliver a table to a JSON file")
            if o.get("type") == "secret":
                raise _Refuse(f"file {fname} is tsv: a secret goes only to a JSON file's {fname}.secrets.json")
            # Hub H10: a tsv value is the default scalar / list text; json,
            # yaml or csv would be multi-line or structured text tsv can't hold.
            tf = _str(fd.get("render") if isinstance(fd.get("render"), dict) else {}, "format")
            if tf:
                raise _Refuse(f"file {fname} is tsv: render.format {tf} can't be written to a tsv file (drop the format; "
                              "lists are written as their comma-joined text)")
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
    check_folders(t, services, r)
    m = t.manifest or {}
    if isinstance(m.get("settings"), list):
        r.error(t.m_where, "settings: a list of settings is template contract v2; contract v3 declares settings: "
                           "{sections, options} (integration contracts §13)", SETTINGS_HINT)
        return
    if t.schema_errors & set(SETTINGS_SHAPE_KEYS):
        return   # the schema errors above say what to fix first
    _SpecCheck(t, services, routers, r).run()


# ── AI support: the ai: block (contracts §3.2) ─────────────────────
# Mirrors portcullis-hub internal/templates/ai.go (ValidateAI) rule for
# rule: every refusal the Hub makes at discover is an error here naming the
# field. Keep the two in sync (and with mcp-gate's forbidden headers).

AI_CLIENT_PREFIX = "portcullis-ai-"
AI_PROVIDERS_FILE = "ai-providers"
DEFAULT_MCP_PATH = "/mcp"
MAX_ALIAS_LEN = 63
MCP_PROTOCOLS = ("2025-06-18", "2025-11-25", "2026-07-28")
PROVIDER_KINDS = ("litellm", "openai_compatible", "anthropic", "openai", "google", "bedrock", "azure_openai")
COMPANION_NAME_RE = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
COMPANION_NAME_MAX = 31
COMPANION_LABEL_MAX = 64
UNSUPPORTED_MAX = 200
ALT_NAME_MAX = 64
ALT_NOTE_MAX = 200
TOOL_PATTERNS_MAX = 256
SCOPE_MAX = 128
TOKEN_FORMAT_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,31} \{credential\}")
SECRET_FORMAT_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,31} \{secret\}")
AI_HEADER_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
TOOL_PATTERN_RE = re.compile(r"[A-Za-z0-9_.*-]{1,128}(:[A-Za-z0-9_.*-]{1,128})?")
MCP_PATH_RE = re.compile(r"/([A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*)?")
# A superset of core mcp-gate's forbiddenHeader: a name the gate refuses
# would make it refuse the whole mcp-gate.json.
AI_FORBIDDEN_HEADERS = {"host", "cookie", "content-type", "accept", "proxy-authorization", "mcp-protocol-version", "mcp-session-id",
                        "content-length", "transfer-encoding", "connection", "te", "upgrade", "keep-alive", "trailer", "proxy-connection"}
AI_FORBIDDEN_HEADER_PREFIXES = ("mcp-", "x-forwarded-", "x-auth-request-", "remote-", "x-portcullis-")
_AI_HEADER_TEXT = ("Host, Cookie, Content-Type, Accept, Content-Length, Transfer-Encoding, Connection, TE, Upgrade, Keep-Alive, "
                   "Trailer, Proxy-Connection, Proxy-Authorization, Mcp-*, MCP-Protocol-Version, Mcp-Session-Id, X-Forwarded-*, "
                   "X-Auth-Request-*, Remote-* or X-Portcullis-*")


def is_ai_hook(h: Any) -> bool:
    """Hook.IsAI: when lists ai (only ever alone: check_hooks)."""
    return isinstance(h, dict) and "ai" in as_list(h.get("when"))


def is_vpn_hook(h: Any) -> bool:
    """Hook.IsVPN: when lists vpn (only ever alone: vpn_errors)."""
    return isinstance(h, dict) and "vpn" in as_list(h.get("when"))


def single_line(s: Any, limit: int) -> bool:
    """singleLine: a string of 1-limit runes, not blank, no control characters."""
    return isinstance(s, str) and s.strip() != "" and len(s) <= limit and not has_control(s)


# HTTPS_URL_RE: never looser than the Hub's httpsURL (Go url.Parse + https
# + host + no userinfo): a host of letters, digits, '.' and '-' or a
# bracketed IPv6 address, an optional all-digit port, then a path / query
# / fragment whose every '%' starts a two-hex-digit escape, no whitespace,
# backslashes or control characters.
HTTPS_URL_RE = re.compile(r"https://(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]+)?"
                          r"(?:[/?#](?:[^\s%\\]|%[0-9A-Fa-f]{2})*)?")


def https_url(s: Any) -> bool:
    """httpsURL: an absolute https URL with a host and no userinfo."""
    return isinstance(s, str) and not has_control(s) and bool(HTTPS_URL_RE.fullmatch(s))


def valid_mcp_path(p: Any) -> bool:
    """validMCPPath: absolute, clean, URL-safe segments, no ? or #."""
    return isinstance(p, str) and bool(MCP_PATH_RE.fullmatch(p)) and go_clean(p) == p


def ai_header_problem(h: str) -> bool:
    low = h.lower()
    return not AI_HEADER_RE.fullmatch(h) or low in AI_FORBIDDEN_HEADERS or low.startswith(AI_FORBIDDEN_HEADER_PREFIXES)


def readonly_var(companion: str) -> str:
    """ReadOnlyVar: PORTCULLIS_AI_READONLY_<COMPANION>."""
    return VAR_AI_READONLY + companion.upper().replace("-", "_")


def raw_var_refs(s: str) -> List[Tuple[str, str]]:
    """rawVarRefs: (name, full text) of each interpolation ($$ is a literal
    $): ${...} up to its first closing brace, or $NAME."""
    out: List[Tuple[str, str]] = []
    i, n = 0, len(s)
    while i < n:
        if s[i] != "$":
            i += 1
            continue
        if i + 1 < n and s[i + 1] == "$":
            i += 2
            continue
        j = i + 1
        braced = j < n and s[j] == "{"
        if braced:
            j += 1
        k = j
        while k < n and (s[k] == "_" or s[k].isascii() and s[k].isalnum()):
            k += 1
        if k == j:
            i += 1
            continue
        end = k
        if braced:
            c = s.find("}", k)
            end = c + 1 if c >= 0 else n
        out.append((s[j:k], s[i:end]))
        i += 1
    return out


class _AICheck:
    """ValidateAI over one template."""

    def __init__(self, t: Template, services: Dict[str, Any], routers: Dict[str, Dict[str, str]], r: Report) -> None:
        self.t, self.r = t, r
        self.m: Dict[str, Any] = t.manifest or {}
        self.services = {str(k): (v if isinstance(v, dict) else {}) for k, v in services.items()}
        self.routers = routers
        self.hooks = {_str(h, "name"): h for h in self.m.get("hooks") or [] if isinstance(h, dict)}
        self.named: Set[str] = set()   # hooks an ai: field names

    def err(self, msg: str) -> None:
        self.r.error(self.t.m_where, msg, AI_HINT)

    def cerr(self, msg: str) -> None:
        self.r.error(self.t.c_where, msg, AI_HINT)

    def run(self) -> None:
        m = self.m
        for c in m.get("keycloak_clients") or []:
            cid = _str(c, "client_id") if isinstance(c, dict) else ""
            if cid.lower().startswith(AI_CLIENT_PREFIX):
                self.err(f"keycloak_clients: client_id {cid}: the prefix {AI_CLIENT_PREFIX} is the Hub's AI clients' (contract §8)")
        for f in m.get("files") or []:
            if isinstance(f, dict) and _str(f, "name") == AI_PROVIDERS_FILE:
                self.err(f"files[{AI_PROVIDERS_FILE}]: the data file name {AI_PROVIDERS_FILE} is reserved for the AI page (contract §3.2)")
        # A core subdomain (mcp included) as a default subdomain:
        # check_rule_forms ("subdomain ... belongs to core").
        a = m.get("ai")
        if "ai" not in m or not isinstance(a, dict):
            # Missing: the schema error says so; the compose side is
            # checked as if the template had no companions.
            self.check_var_refs([])
            self.check_ai_hooks()
            return
        if "ai" in self.t.schema_errors:
            # Misshapen: the schema errors say what to fix. The companions
            # and hooks are read from the raw block, so a shape error
            # doesn't turn into "only AI variables …" / "no ai: field
            # names it" errors.
            raw = [c for c in as_list(a.get("mcp")) if isinstance(c, dict) and isinstance(c.get("name"), str)]
            for c in raw:
                ident = c.get("identity") if isinstance(c.get("identity"), dict) else {}
                self.named.update(n for n in (ident.get("mint"), ident.get("revoke")) if isinstance(n, str))
            if isinstance(a.get("on_change"), str):
                self.named.add(a["on_change"])
            self.check_var_refs(raw)
            self.check_ai_hooks()
            return
        has_mcp, has_unsup = "mcp" in a, "unsupported" in a
        if has_mcp and has_unsup:
            self.err("ai: either ai.mcp or ai.unsupported, not both")
        elif not has_mcp and not has_unsup:
            self.err("ai: required (ai.mcp or ai.unsupported)")
        companions = [c for c in a.get("mcp") or [] if isinstance(c, dict)] if has_mcp else []
        if has_unsup:
            if not single_line(a.get("unsupported"), UNSUPPORTED_MAX):
                self.err(f"ai.unsupported must be one line of 1–{UNSUPPORTED_MAX} characters")
            if _str(a, "on_change"):
                self.err("ai.on_change is only allowed with ai.mcp")
            alt = a.get("alternative")
            if isinstance(alt, dict):
                if not single_line(alt.get("name"), ALT_NAME_MAX):
                    self.err(f"ai.alternative.name must be one line of 1–{ALT_NAME_MAX} characters")
                elif not https_url(alt.get("source")):
                    self.err("ai.alternative.source must be an https:// URL")
                elif not single_line(alt.get("note"), ALT_NOTE_MAX):
                    self.err(f"ai.alternative.note must be one line of 1–{ALT_NOTE_MAX} characters")
        elif has_mcp:
            if not companions:
                self.err("ai.mcp: list at least one companion (or use ai.unsupported)")
            if _has(a, "alternative"):
                self.err("ai.alternative is only allowed with ai.unsupported")
            if _has(a, "chat"):
                self.err("ai.chat is only allowed with ai.unsupported (an AI page is no app the AI drives)")
        self.check_ai_clients(a.get("chat") if isinstance(a.get("chat"), dict) else None)
        if has_mcp and not has_unsup and companions:
            self.check_companions(companions)
            if _str(a, "on_change"):
                self.ai_hook("ai.on_change", _str(a, "on_change"))
        self.check_var_refs(companions if has_mcp and not has_unsup else [])
        self.check_ai_hooks()
        if has_mcp and not has_unsup and companions:
            self.check_ai_hook_services(companions)

    def check_ai_hook_services(self, companions: List[Dict[str, Any]]) -> None:
        """An ai hook never runs on a kind: companion service (at scale 0
        while its companion is off: the owed revoke_all / on_change could
        never run). Hub ValidateAI."""
        svcs = {_str(c, "service") for c in companions if isinstance(c, dict) and _str(c, "kind") == "companion"}
        for name, h in self.hooks.items():
            if name in self.named and isinstance(h, dict) and _str(h, "service") in svcs:
                self.err(f"hooks[{name}]: an ai hook may not run on service {_str(h, 'service')}: it backs a kind: "
                         "companion companion, at scale 0 while AI support is off (run it on the app's own service)")

    def check_ai_hooks(self) -> None:
        for name, h in self.hooks.items():
            if is_ai_hook(h) and name not in self.named:
                self.err(f"hooks[{name}]: when: [ai] but no ai: field names it (only ai.mcp[].identity.mint / revoke and "
                         "ai.on_change run ai hooks)")

    def ai_hook(self, where: str, name: str) -> None:
        """aiHook: the hook exists and is exactly when: [ai]."""
        self.named.add(name)
        h = self.hooks.get(name)
        if h is None:
            self.err(f"{where}: hook {name} is not declared in hooks")
        elif as_list(h.get("when")) != ["ai"]:
            self.err(f"{where}: hook {name} must have exactly when: [ai] (contract §13.8)")

    def check_ai_clients(self, chat: Optional[Dict[str, Any]]) -> None:
        clients = [c for c in self.m.get("keycloak_clients") or [] if isinstance(c, dict) and c.get("ai_client") is True]
        if chat is None:
            if clients:
                self.err(f"keycloak_clients: client {_str(clients[0], 'client_id')} has ai_client: true, which is only allowed with ai.chat")
            return
        if len(clients) != 1:
            self.err(f"ai.chat: exactly one keycloak_clients entry has ai_client: true (found {len(clients)})")
        elif not _str(clients[0], "secret_env"):
            self.err(f"keycloak_clients: ai_client {_str(clients[0], 'client_id')} needs a secret_env (a confidential client)")
        kinds = chat.get("provider_kinds")
        kinds = kinds if isinstance(kinds, dict) else {}
        if not kinds:
            self.err(f"ai.chat.provider_kinds: list at least one model provider kind ({', '.join(PROVIDER_KINDS)})")
        for k, n in kinds.items():
            if k not in PROVIDER_KINDS:
                self.err(f"ai.chat.provider_kinds: {json.dumps(str(k))} must be one of {', '.join(PROVIDER_KINDS)}")
            elif n not in ("one", "many"):
                self.err(f"ai.chat.provider_kinds: {k}: {json.dumps(scalar_text(n))} must be one or many")
        f = chat.get("file") if isinstance(chat.get("file"), dict) else {}
        fsvc, mount = _str(f, "service"), _str(f, "mount")
        if fsvc not in self.services:
            self.err(f"ai.chat.file: service {json.dumps(fsvc)} is not in compose.yml")
        elif not valid_mount(mount):
            self.err(f"ai.chat.file: mount {json.dumps(mount)} must be an absolute, clean container directory (no ':')")
        else:
            for df in self.m.get("files") or []:
                if isinstance(df, dict) and _str(df, "service") == fsvc and _nested(_str(df, "mount"), mount):
                    self.err(f"ai.chat.file: mount {mount} collides with files[{_str(df, 'name')}]'s mount {_str(df, 'mount')}")
                    break
        esvc = _str(chat.get("env") if isinstance(chat.get("env"), dict) else {}, "service")
        if not esvc or esvc not in self.services:
            self.err(f"ai.chat.env: service {json.dumps(esvc)} must be a service of compose.yml (it receives the providers' variables)")

    def check_var_refs(self, companions: List[Dict[str, Any]]) -> None:
        """checkAIVarRefs over every compose string value."""
        own = {readonly_var(_str(c, "name")) for c in companions}
        scalars: List[str] = []
        _string_values(self.t.compose or {}, scalars)
        seen: Set[str] = set()
        for sc in scalars:
            for name, text in raw_var_refs(sc):
                # A default or alternate text naming an AI variable
                # (${X:-PORTCULLIS_AI_...}, any case) could build one.
                if text.startswith("${") and VAR_AI_PREFIX in text[2 + len(name):].upper():
                    msg = f"{text}: a default or alternate value naming {VAR_AI_PREFIX}* is refused (the AI variables are the Hub's)"
                    if msg not in seen:
                        seen.add(msg)
                        self.cerr(msg)
                    continue
                if not name.startswith(VAR_AI_PREFIX):
                    continue
                if name.startswith(VAR_AI_PROVIDER):
                    msg = (f"references {name}: PORTCULLIS_AI_PROVIDER_* variables are never referenced by a template "
                           "(the Hub adds them to ai.chat.env's service)")
                elif name == VAR_AI_ENABLED:
                    if companions and text == "${" + VAR_AI_ENABLED + ":-false}":
                        continue
                    msg = f"{VAR_AI_ENABLED} may appear only as exactly ${{{VAR_AI_ENABLED}:-false}}, in a template with ai.mcp"
                elif name in own:
                    if text == "${" + name + ":-true}":
                        continue
                    msg = f"{name} may appear only as exactly ${{{name}:-true}}"
                else:
                    msg = (f"references {name}: the only AI variables are {VAR_AI_ENABLED} and PORTCULLIS_AI_READONLY_<COMPANION> "
                           "of the template's own companions")
                if msg not in seen:
                    seen.add(msg)
                    self.cerr(msg)
        # Nor may a service set one (an environment map key, or a list item
        # NAME / NAME=...; case-insensitive): it would take the Hub's provider
        # secret's place (G31; the Hub's checkAIVarRefs).
        services = (self.t.compose or {}).get("services") if isinstance(self.t.compose, dict) else None
        for svc in sorted(services) if isinstance(services, dict) else []:
            for k in _environment_keys(services[svc]):
                if "$" in k:
                    self.cerr(f"service {svc}: the environment variable name {json.dumps(k)} is built by interpolation: names are written out")
                elif k.upper().startswith(VAR_AI_PROVIDER):
                    self.cerr(f"service {svc} sets {k}: PORTCULLIS_AI_PROVIDER_* variables are set only by the Hub (on ai.chat.env's service)")

    def check_trust_network(self, w: str, svc: str, router: str) -> None:
        """Hub checkTrustNetwork: an identity_headers companion joins exactly
        one network, an internal: true project network whose members are
        exactly the companion and the service(s) of its router."""
        nets = sorted(networks_of(self.services[svc]))
        if len(nets) != 1 or nets[0] in ("default", PROXY_NET):
            self.err(f"{w}: identity_headers companion service {svc} must join exactly one network, its trust network "
                     f"(an internal: true project network shared only with the app that trusts the headers), not {nets}")
            return
        trust = nets[0]
        top = (self.t.compose or {}).get("networks") or {}
        spec = top.get(trust) if isinstance(top, dict) else None
        # Exactly {internal: true}: an address plan or driver option could
        # make the subnet the app trusts cover other addresses.
        if not (isinstance(spec, dict) and spec.get("internal") is True and len(spec) == 1):
            self.err(f"{w}: the trust network {trust} must be declared at the top level as exactly {{internal: true}} "
                     "(no ipam, driver, driver_opts, enable_ipv6, attachable, labels, name or external)")
            return
        want = {svc} | {_str(rt, "_service") for n, rt in self.routers.items() if n == router}
        if len(want) < 2:
            self.err(f"{w}: no compose service carries router {router} (the app that trusts the identity headers)")
            return
        for name in sorted(self.services):
            s = self.services[name]
            inside = trust in networks_of(s)
            if inside and name not in want:
                self.err(f"{w}: service {name} joins the trust network {trust}: only the companion {svc} and the service(s) "
                         f"of router {router} may (any other member could send identity headers the app trusts)")
            elif not inside and name in want:
                self.err(f"{w}: service {name} (router {router}) must join the trust network {trust}")
            mode = s.get("network_mode")
            if isinstance(mode, str) and mode.startswith("service:") and mode[len("service:"):] in want:
                self.err(f"{w}: service {name} uses network_mode {mode}: it would share an address on the trust network {trust}")
            pid = s.get("pid")
            if isinstance(pid, str) and pid.startswith("service:") and pid[len("service:"):] in want:
                self.err(f"{w}: service {name} uses pid {pid}: it would share the process namespace of a trust network member ({trust})")

    def check_companions(self, companions: List[Dict[str, Any]]) -> None:
        auth = self.m.get("auth") if isinstance(self.m.get("auth"), dict) else {}
        method = _str(auth, "method")
        stop = False
        if auth.get("admin_paths"):
            self.err("ai.mcp: not allowed with auth.admin_paths (the gate can't apply path groups; use ai.unsupported)")
            stop = True
        if method in ("public", "mtls"):
            self.err(f"ai.mcp: not allowed with auth.method {method} (no Portcullis identity, or LoA 3)")
            stop = True
        if not self.routers:
            self.err("ai.mcp: not allowed on a router-less template (a companion's endpoint is on one of its hosts)")
            stop = True
        if stop:
            return
        host_routers = set()
        for name, rt in self.routers.items():
            p = parse_rule(rt.get("rule", ""))
            if p is not None and p[3] is None:
                host_routers.add(name)
        random_env = {_str(e, "key") for e in self.m.get("env") or [] if isinstance(e, dict) and e.get("generate") == "random"}
        public_prefixes: List[str] = []
        pa = auth.get("public_access")
        for pp in (pa.get("paths") or []) if isinstance(pa, dict) else []:
            pre = _str(pp, "prefix").split(PUBLIC_TOKEN, 1)[0].rstrip("/") if isinstance(pp, dict) else ""
            public_prefixes.append(pre or "/")
        kinds = {_str(c, "name"): _str(c, "kind") for c in companions}
        names: Set[str] = set()
        service_use: Dict[str, str] = {}
        endpoints: Dict[str, List[Tuple[str, str]]] = {}
        for i, c in enumerate(companions):
            name = _str(c, "name")
            if not COMPANION_NAME_RE.fullmatch(name) or len(name) > COMPANION_NAME_MAX:
                self.err(f"ai.mcp[{i}]: name {json.dumps(name)} must match ^{COMPANION_NAME_RE.pattern}$ and be at most "
                         f"{COMPANION_NAME_MAX} characters")
                continue
            w = f"ai.mcp[{name}]"
            if name in names:
                self.err(f"{w}: name declared twice")
                continue
            names.add(name)
            self.check_companion(w, c, host_routers, random_env, public_prefixes, kinds, service_use, endpoints)

    def check_companion(self, w: str, c: Dict[str, Any], host_routers: Set[str], random_env: Set[str], public_prefixes: List[str],
                        kinds: Dict[str, str], service_use: Dict[str, str], endpoints: Dict[str, List[Tuple[str, str]]]) -> None:
        name, kind, svc = _str(c, "name"), _str(c, "kind"), _str(c, "service")
        ident = c.get("identity") if isinstance(c.get("identity"), dict) else {}
        mode = _str(ident, "mode")
        alias = MCP_NAME_PREFIX + self.t.id + "--" + name
        if len(alias) > MAX_ALIAS_LEN:
            self.err(f"{w}: the alias {alias} is longer than {MAX_ALIAS_LEN} characters (one DNS label: 15 + len(id) + 2 + "
                     f"len(companion) ≤ {MAX_ALIAS_LEN})")
        if not single_line(c.get("label"), COMPANION_LABEL_MAX):
            self.err(f"{w}: label must be one line of 1–{COMPANION_LABEL_MAX} characters")
        if kind not in ("companion", "builtin"):
            self.err(f"{w}: kind {json.dumps(kind)} must be companion or builtin")
        if svc not in self.services:
            self.err(f"{w}: service {svc} is not in compose.yml")
        elif not ID_NORMAL_RE.fullmatch(svc):
            self.err(f"{w}: service {svc} must match ^{ID_NORMAL_RE.pattern}$ (no _, no --, no trailing -)")
        if mode not in ("app_token", "identity_headers", "app_oauth"):
            self.err(f"{w}: identity.mode {json.dumps(mode)} must be app_token, identity_headers or app_oauth")
        if mode == "app_oauth" and kind != "builtin":
            self.err(f"{w}: app_oauth needs kind builtin (the app is its own MCP authorization server)")
        other = service_use.get(svc)
        if other is not None and (kind == "companion" or kinds.get(other) == "companion"):
            self.err(f"{w}: companion service {svc} already backs companion {other}")
        if kind == "companion" and svc in self.services:
            s = self.services[svc]
            if any(fold_key(k).startswith("traefik.") for k in labels_of(s)):
                self.err(f"{w}: companion service {svc} may have no traefik.* label (the Hub routes it)")
            if PROXY_NET in networks_of(s):
                self.err(f"{w}: companion service {svc} may not join {PROXY_NET} itself (the Hub's override attaches it while AI support is on)")
            if "network_mode" in s:
                self.err(f"{w}: companion service {svc} may not set network_mode")
            named = [f for f in ("container_name", "hostname") if f in s]
            if named:
                self.err(f"{w}: companion service {svc} may not set {' or '.join(named)}")
            if "ports" in s:
                self.err(f"{w}: companion service {svc} may not publish ports (the gate is the only way in)")
            for oname in sorted(self.services):
                if self.services[oname].get("network_mode") == f"service:{svc}":
                    self.err(f"{w}: service {oname} uses network_mode service:{svc}, the companion service's network namespace "
                             "(it would reach the companion past the gate)")
        if kind == "companion" and mode == "identity_headers" and svc in self.services:
            self.check_trust_network(w, svc, _str(c, "router"))
        if mode == "identity_headers":
            # A host-network service sends from the host's addresses, the
            # trust network's gateway side included.
            for oname in sorted(self.services):
                if self.services[oname].get("network_mode") == "host":
                    self.err(f"{w}: service {oname} uses network_mode host: not allowed next to an identity_headers companion "
                             "(it reaches the app from the host's addresses)")
                if self.services[oname].get("pid") == "host":
                    self.err(f"{w}: service {oname} uses pid host: not allowed next to an identity_headers companion "
                             "(it sees every process of the host, the companion's included)")
            cs = ident.get("caller_secret") if isinstance(ident.get("caller_secret"), dict) else {}
            secret = _str(cs, "env")
            for oname in sorted(self.services):
                if secret and oname != svc and any(secret in var_names_deep(v) for v in _scalars(self.services[oname])):
                    self.err(f"{w}: service {oname} reads the caller secret {secret}: only the companion service {svc} may")
        service_use[svc] = name
        port = c.get("port", 0)
        port = port if isinstance(port, int) and not isinstance(port, bool) else -1
        if (mode != "app_oauth" and port < 1) or port < 0 or port > 65535:
            self.err(f"{w}: port {scalar_text(c.get('port', 0))} must be 1–65535")
        path = c.get("path")
        if _has(c, "path") and path != "" and not valid_mcp_path(path):
            self.err(f"{w}: path {json.dumps(scalar_text(path))} must be absolute and clean, without ? or #")
        router = _str(c, "router")
        if router not in host_routers:
            self.err(f"{w}: router {json.dumps(router)} is not a host router of the template (a router whose rule is Host() alone)")
        if mode == "app_oauth" and _str(c, "public_path"):
            self.err(f"{w}: public_path is refused on an app_oauth companion (its endpoint is the app's own route https://<host><path>)")
        if mode == "app_oauth":
            pp = _str(c, "path") or DEFAULT_MCP_PATH
        else:
            pp = _str(c, "public_path") or DEFAULT_MCP_PATH
            self.check_public_path(w, pp, public_prefixes)
        for opath, oname in endpoints.get(router, []):
            if _nested(pp, opath):
                self.err(f"{w}: endpoint path (public_path, or path for app_oauth) {pp} on router {router} overlaps companion "
                         f"{oname}'s {opath}")
                break
        endpoints.setdefault(router, []).append((pp, name))
        self.check_modes(w, c, mode)
        self.check_identity(w, c, ident, mode, random_env)
        tools = c.get("tools") if isinstance(c.get("tools"), dict) else {}
        for cls in ("writes", "confirm", "never"):
            pats = as_list(tools.get(cls))
            if len(pats) > TOOL_PATTERNS_MAX:
                self.err(f"{w}: tools.{cls} lists more than {TOOL_PATTERNS_MAX} patterns")
            for pat in pats:
                if not isinstance(pat, str) or not TOOL_PATTERN_RE.fullmatch(pat):
                    self.err(f"{w}: tools.{cls} pattern {json.dumps(scalar_text(pat))} must match ^{TOOL_PATTERN_RE.pattern}$")
        if mode == "app_oauth" and c.get("aggregate") is True:
            self.err(f"{w}: aggregate: true is refused on an app_oauth companion (never in \"all my apps\")")
        up = _str(c, "upstream")
        if up == "community" and kind == "builtin":
            self.err(f"{w}: upstream community with kind builtin (the app's own server is official)")
        elif up not in ("official", "community"):
            self.err(f"{w}: upstream {json.dumps(up)} must be official or community")
        if not https_url(c.get("source")):
            self.err(f"{w}: source must be an https:// URL (the companion project's home)")
        protos = as_list(c.get("protocol"))
        if not protos:
            self.err(f"{w}: protocol must list at least one of {', '.join(MCP_PROTOCOLS)}")
        seen: Set[str] = set()
        for p in protos:
            if p not in MCP_PROTOCOLS or p in seen:
                self.err(f"{w}: protocol {json.dumps(scalar_text(p))} must be one of {', '.join(MCP_PROTOCOLS)}, each once")
                break
            seen.add(p)

    def check_public_path(self, w: str, pp: str, public_prefixes: List[str]) -> None:
        if not valid_mcp_path(pp) or pp == "/":
            self.err(f"{w}: public_path {json.dumps(pp)} must be absolute and clean, and not /")
            return
        for root in ("/.well-known", "/oauth2"):
            if pp == root or pp.startswith(root + "/"):
                self.err(f"{w}: public_path {pp} may not be at or under {root}/ (metadata and sign-in routes)")
                return
        for p in public_prefixes:
            if p == "/" or _nested(pp, p):
                self.err(f"{w}: public_path {pp} overlaps the auth.public_access path {p}")
                return

    def check_modes(self, w: str, c: Dict[str, Any], mode: str) -> None:
        modes = as_list(c.get("modes"))
        dm = _str(c, "default_mode")
        if not modes:
            self.err(f"{w}: modes must list read_only and/or read_write")
            return
        if any(md not in ("read_only", "read_write") for md in modes) or len(set(map(str, modes))) != len(modes):
            self.err(f"{w}: modes must be a subset of read_only, read_write without repeats (got {modes})")
            return
        if mode == "app_oauth" and modes != ["read_write"]:
            self.err(f"{w}: an app_oauth companion's modes are exactly [read_write]")
        elif dm and dm not in modes:
            self.err(f"{w}: default_mode {json.dumps(dm)} is not one of modes {modes}")
        elif len(modes) == 2 and not dm:
            self.err(f"{w}: default_mode is required when modes has two entries")

    def check_identity(self, w: str, c: Dict[str, Any], ident: Dict[str, Any], mode: str, random_env: Set[str]) -> None:
        def extra(*fields: str) -> bool:
            for f in fields:
                v = ident.get(f)
                if f in ident and v is not None and v != "":
                    self.err(f"{w}: identity.{f} is not a parameter of mode {mode}")
                    return True
            return False
        if mode == "app_token":
            if extra("caller_secret"):
                return
            header = _str(ident, "header")
            if header and ai_header_problem(header):
                self.err(f"{w}: identity.header {json.dumps(header)} must match ^{AI_HEADER_RE.pattern}$ and not be {_AI_HEADER_TEXT}")
            fmt, basic = _str(ident, "format"), ident.get("basic")
            if fmt and basic is not None:
                self.err(f"{w}: identity: exactly one of format and basic, not both")
            elif fmt:
                if not TOKEN_FORMAT_RE.fullmatch(fmt):
                    self.err(f"{w}: identity.format {json.dumps(fmt)} must match ^{TOKEN_FORMAT_RE.pattern}$ (e.g. \"token {{credential}}\")")
            elif isinstance(basic, dict):
                u = basic.get("user")
                if u != "{username}" and (not single_line(u, 128) or any(ch in str(u) for ch in ":{}")):
                    self.err(f"{w}: identity.basic.user must be exactly {{username}} or a one-line literal without :, {{ or }}")
                if basic.get("password") != "{credential}":
                    self.err(f"{w}: identity.basic.password must be exactly {{credential}}")
            else:
                self.err(f"{w}: identity: app_token needs format or basic")
            if not _str(ident, "mint"):
                self.err(f"{w}: identity.mint (a hook) is required for app_token")
            if not _str(ident, "revoke"):
                self.err(f"{w}: identity.revoke (a hook) is required for app_token")
            scopes = ident.get("scopes") if isinstance(ident.get("scopes"), dict) else {}
            modes = as_list(c.get("modes"))
            for k, lst in scopes.items():
                if k not in modes:
                    self.err(f"{w}: identity.scopes key {json.dumps(str(k))} is not one of modes {modes}")
                    continue
                if any(not single_line(sc, SCOPE_MAX) for sc in as_list(lst)):
                    self.err(f"{w}: identity.scopes.{k} entries must be one line of 1–{SCOPE_MAX} characters")
        elif mode == "identity_headers":
            if extra("header", "format", "basic", "mint", "revoke", "scopes"):
                return
            cs = ident.get("caller_secret")
            if not isinstance(cs, dict):
                self.err(f"{w}: identity_headers needs identity.caller_secret {{env, header, format}}")
                return
            env = _str(cs, "env")
            if env not in random_env:
                self.err(f"{w}: identity.caller_secret.env {json.dumps(env)} must be an env entry with generate: random")
            header = _str(cs, "header")
            if header and ai_header_problem(header):
                self.err(f"{w}: identity.caller_secret.header {json.dumps(header)} must match ^{AI_HEADER_RE.pattern}$ and not be "
                         f"{_AI_HEADER_TEXT}")
            f = _str(cs, "format")
            if f and f != "{secret}" and not SECRET_FORMAT_RE.fullmatch(f):
                self.err(f"{w}: identity.caller_secret.format {json.dumps(f)} must contain {{secret}} once: exactly {{secret}} or "
                         f"match ^{SECRET_FORMAT_RE.pattern}$")
        elif mode == "app_oauth":
            if extra("header", "format", "basic", "mint", "scopes", "caller_secret"):
                return
            if not _str(ident, "revoke"):
                self.err(f"{w}: identity.revoke (a hook) is required for app_oauth")
        for field in ("mint", "revoke"):
            n = _str(ident, field)
            if n:
                self.ai_hook(f"{w}: identity.{field}", n)


def _environment_keys(svc: Any) -> List[str]:
    """The variable names a compose service's environment sets: its map
    keys, or each list item's name (before the first =)."""
    env = svc.get("environment") if isinstance(svc, dict) else None
    if isinstance(env, dict):
        return sorted(str(k) for k in env)
    if isinstance(env, list):
        return [it.split("=", 1)[0].strip() for it in env if isinstance(it, str)]
    return []


def check_ai(t: Template, services: Dict[str, Any], routers: Dict[str, Dict[str, str]], r: Report) -> None:
    """The ai: block (contracts §3.2), as the Hub's ValidateAI checks it."""
    _AICheck(t, services, routers, r).run()


# ── VPN providers: the vpn: block (contracts §3.3) ─────────────────
# Mirrors portcullis-hub internal/templates/vpn.go (ValidateVPN) with the
# same texts; tests/vpn_vectors.json is a byte copy of the Hub's
# internal/templates/testdata/vpn_vectors.json (lint: "VPN vectors match
# the Hub").

VPN_LABEL_MAX = 64
VPN_MAX_RANGES = 8
VPN_MIN_BITS, VPN_MAX_BITS = 8, 30
VPN_REFRESH_MIN, VPN_REFRESH_MAX = 15 * 10 ** 9, 10 * 60 * 10 ** 9   # ns
VPN_OWNERS = ("oidc_sub", "username")
_VPN_SETTING_RE = re.compile(r"\{\{setting:(.*)\}\}", re.S)   # the Hub's prefix/suffix test
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
_VPN_PREFIX_RE = re.compile(rf"({_OCTET}(?:\.{_OCTET}){{3}})/(0|[1-9][0-9]?)")
_HTTP_ROUTER_RE = re.compile(r"^traefik\.http\.routers\.([^.]+)\.(.+)$")
# A host router (contract §3.1): the rule is a Host() alone.
_HOST_ONLY_RULE_RE = re.compile(r"Host\(`[^`]*`\)")
# Core's forwarder image, pinned by digest (V1): the only service besides
# the ingress allowed in its network namespace.
FORWARDER_IMAGE_RE = re.compile(r"ghcr\.io/porelli/portcullis-forwarder(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}")


def vpn_prefix(s: Any) -> Optional[ipaddress.IPv4Network]:
    """A canonical IPv4 prefix /8-/30 (netip.ParsePrefix, Is4, Masked() ==
    itself), else None."""
    m = _VPN_PREFIX_RE.fullmatch(s) if isinstance(s, str) else None
    if not m or not VPN_MIN_BITS <= int(m.group(2)) <= VPN_MAX_BITS:
        return None
    net = ipaddress.IPv4Network(s, strict=False)
    return net if str(net) == s else None


def vpn_errors(m: Any, compose: Any) -> List[str]:
    """ValidateVPN: the vpn: block and the vpn hooks of manifest m against
    compose file compose, every refusal in the Hub's order (the first is
    the one the Hub reports)."""
    m = m if isinstance(m, dict) else {}
    services = (compose or {}).get("services") if isinstance(compose, dict) else None
    services = {str(k): (sv if isinstance(sv, dict) else {}) for k, sv in (services or {}).items()} \
        if isinstance(services, dict) else {}
    hooks = {_str(h, "name"): h for h in m.get("hooks") or [] if isinstance(h, dict)}
    out: List[str] = []
    named: Set[str] = set()

    def vpn_hook(where: str, name: str) -> None:
        named.add(name)
        h = hooks.get(name)
        if h is None or as_list(h.get("when")) != ["vpn"]:
            out.append(f"{where}: {name} is not a hook with exactly when: [vpn]")

    b = m.get("vpn")
    if isinstance(b, dict):
        if not single_line(b.get("label"), VPN_LABEL_MAX):
            out.append(f"vpn.label: a single line of 1–{VPN_LABEL_MAX} characters")
        ranges = b.get("ranges") if isinstance(b.get("ranges"), list) else []
        if not 1 <= len(ranges) <= VPN_MAX_RANGES:
            out.append(f"vpn.ranges: 1–{VPN_MAX_RANGES} IPv4 prefixes")
        nets: List[Tuple[str, ipaddress.IPv4Network]] = []
        for i, rg in enumerate(ranges):
            text = scalar_text(rg)
            sm = _VPN_SETTING_RE.fullmatch(text)
            if sm:
                o = next((o for o in setting_options(m) if _str(o, "key") == sm.group(1)), None)
                if o is None or o.get("type") != "string" or _str(o, "format") != "cidr" or scope_of(o) != "instance":
                    out.append(f"vpn.ranges[{i}]: {text} must name a cidr setting")
                continue
            net = vpn_prefix(rg)
            if net is None:
                out.append(f"vpn.ranges[{i}]: {text} is not an IPv4 prefix between /{VPN_MIN_BITS} and /{VPN_MAX_BITS}")
                continue
            nets.append((text, net))
        for i, (a, na) in enumerate(nets):
            for bt, nb in nets[i + 1:]:
                if na.overlaps(nb):
                    out.append(f"vpn.ranges: {a} overlaps {bt}")

        ing = b.get("ingress") if isinstance(b.get("ingress"), dict) else {}
        out.extend(vpn_ingress_errors(m, services, _str(ing, "service"), _str(ing, "proxy_protocol")))

        ident = b.get("identity") if isinstance(b.get("identity"), dict) else {}
        source = _str(ident, "source")
        if source == "hook":
            vpn_hook("vpn.identity.hook", _str(ident, "hook"))
            if _str(ident, "owner") not in VPN_OWNERS:
                out.append("vpn.identity.owner: oidc_sub or username")
        elif source == "static":
            if "hook" in ident or "owner" in ident:   # present at all (contract: no hook and no owner)
                out.append("vpn.identity: source static takes no hook or owner")
        else:
            out.append("vpn.identity.source: hook or static")
        if _has(ident, "refresh"):
            try:
                ns = go_parse_duration(scalar_text(ident["refresh"]))
            except ValueError:
                ns = -1
            if not VPN_REFRESH_MIN <= ns <= VPN_REFRESH_MAX:
                out.append("vpn.identity.refresh: between 15s and 10m")

        dns = b.get("dns") if isinstance(b.get("dns"), dict) else {}
        dhook, manual = _str(dns, "hook"), dns.get("manual") is True
        if bool(dhook) == manual:
            out.append("vpn.dns: exactly one of hook and manual: true")
        elif dhook:
            vpn_hook("vpn.dns.hook", dhook)

        routers: Dict[str, Dict[str, str]] = {}
        for sv in services.values():
            for k, val in labels_of(sv).items():
                mm = _HTTP_ROUTER_RE.match(k)
                if mm:
                    routers.setdefault(mm.group(1), {})[mm.group(2)] = val
        for rt in as_list(b.get("control_routers")):
            rt = scalar_text(rt)
            if rt not in routers or not _HOST_ONLY_RULE_RE.fullmatch(routers[rt].get("rule", "").strip()):
                out.append(f"vpn.control_routers: {rt} is not a host router of the template")
            elif vpn_serves_admin_ui(m, routers[rt].get("rule", "")):
                out.append(f"vpn.control_routers: {rt} serves an admin UI")

    # (when: [vpn, <other>] is check_hooks' refusal, the Hub's settings
    # check, which runs first.)
    for name, h in hooks.items():
        if is_vpn_hook(h) and name not in named:
            out.append(f"hooks[{name}]: when: [vpn] needs a vpn: block that names it")
    return out


def vpn_net_ns(services: Dict[str, Dict[str, Any]], svc: str) -> Optional[str]:
    """Routes.NetNS: the service whose network namespace svc runs in
    (network_mode service:X followed), "host", or None for a cycle or an
    unknown target (fail closed)."""
    seen: Set[str] = set()
    while True:
        if svc in seen:
            return None
        seen.add(svc)
        nm = services.get(svc, {}).get("network_mode")
        nm = nm if isinstance(nm, str) else ""
        if nm == "host":
            return "host"
        if not nm.startswith("service:"):
            return svc
        nxt = nm[len("service:"):]
        if nxt not in services:
            return None
        svc = nxt


def vpn_ingress_errors(m: Dict[str, Any], services: Dict[str, Dict[str, Any]], s: str, proxy: str) -> List[str]:
    """checkVPNIngress: the ingress exists and can join a network; no
    service uses the host's pid namespace, and neither the ingress, the
    services sharing its network namespace nor a routed service use host
    networking; every
    service in the ingress's network namespace (chains followed) is no
    job, no AI companion, has no Traefik label and publishes no ports, and
    besides the ingress only the pinned forwarder may join it;
    proxy_protocol v2. The Hub stops at the first."""
    if s not in services:
        return [f"vpn.ingress.service: {s} is not a service of compose.yml"]
    if "network_mode" in services[s]:
        return [f"vpn.ingress.service: {s} has network_mode"]
    names = sorted(services)
    members = [s] + [n for n in names if n != s and vpn_net_ns(services, n) == s]
    # Host namespaces: pid: host on no service (it exposes the host's
    # processes, the ingress's included); network_mode: host never for the
    # ingress, a service sharing its namespace or a routed
    # (traefik-labelled) service, other services keep the template rules
    # (NetBird's relay keeps host networking).
    for n in names:
        routed = any(fold_key(k).startswith("traefik.") for k in labels_of(services[n]))
        # (n in members never holds for host networking: the ingress has no
        # network_mode and members carry service:; kept as the rule reads.)
        if services[n].get("network_mode") == "host" and (n in members or routed):
            return [f"vpn: service {n} uses network_mode: host"]
        if services[n].get("pid") == "host":
            return [f"vpn: service {n} uses pid: host"]
    jobs = job_services(m, services)
    ai = m.get("ai") if isinstance(m.get("ai"), dict) else {}
    companions = {_str(c, "service") for c in as_list(ai.get("mcp")) if isinstance(c, dict) and _str(c, "kind") == "companion"}
    for n in members:
        sv = services[n]
        image = sv.get("image") if isinstance(sv.get("image"), str) else ""
        if n != s and not FORWARDER_IMAGE_RE.fullmatch(image):
            return [f"vpn.ingress.service: {n} shares {s}'s network namespace: only the pinned "
                    "ghcr.io/porelli/portcullis-forwarder image may"]
        if n in jobs:
            return [f"vpn.ingress.service: {n} is a job"]
        if n in companions:
            return [f"vpn.ingress.service: {n} is an AI companion"]
        if any(fold_key(k).startswith("traefik.") for k in labels_of(sv)):
            return [f"vpn.ingress.service: {n} has a Traefik router"]
        if "ports" in sv:
            return [f"vpn.ingress.service: {n} publishes ports"]
    if proxy != "v2":
        return ["vpn.ingress.proxy_protocol: only v2"]
    return []


def vpn_serves_admin_ui(m: Dict[str, Any], rule: str) -> bool:
    """servesAdminUI: group_admin, or an admin_paths path the router can
    serve (no path matcher, or one no path reasoning applies to, serves
    every path: fail closed)."""
    auth = m.get("auth") if isinstance(m.get("auth"), dict) else {}
    if auth.get("group_admin") is True:
        return True
    admin_paths = [scalar_text(p) for p in as_list(auth.get("admin_paths"))]
    if not admin_paths:
        return False
    paths = re.findall(r"(Path|PathPrefix)\(`([^`]*)`\)", rule)
    if not paths or re.search(r"\b(?!Path\(|PathPrefix\()Path[A-Za-z]*\(", rule):
        return True
    for kind, v in paths:
        for ap in admin_paths:
            if kind == "Path" and (v == ap or v.startswith(ap + "/")):
                return True
            if kind == "PathPrefix" and ((ap + "/").startswith(v) or v.startswith(ap + "/")):
                return True
    return False


def check_vpn(t: Template, services: Dict[str, Any], r: Report) -> None:
    """The vpn: block (contracts §3.3), as the Hub's ValidateVPN checks it.
    A misshapen block is left to the schema errors (its hooks are still
    checked against the raw block)."""
    m = t.manifest or {}
    if "vpn" in t.schema_errors and isinstance(m.get("vpn"), dict):
        errs = [e for e in vpn_errors(m, {"services": services}) if e.startswith("hooks[")]
    else:
        errs = vpn_errors(m, {"services": services})
    for e in errs:
        r.error(t.m_where, e, VPN_HINT)


# ── One-off jobs and setup options (contracts §3, §13.18) ──────────
# Mirrors portcullis-hub internal/templates/setup.go (validateSetup) with
# the same messages.

VAR_COMPOSE_PROFILES = "COMPOSE_PROFILES"
PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
SETUP_HINT = f"see {DOCS_URL}/integration-contracts/#1318-setup-options-and-compose-profiles-new-apps"
JOBS_HINT = f"see {DOCS_URL}/manifest-reference/#jobs"


def service_profiles(t: Template, services: Dict[str, Any], r: Report) -> Dict[str, List[str]]:
    """templates.ServiceProfiles: each service's profiles: (literal names)."""
    out: Dict[str, List[str]] = {}
    for name, svc in services.items():
        if not isinstance(svc, dict) or "profiles" not in svc:
            continue
        raw = svc.get("profiles")
        if not isinstance(raw, list) or not raw or any(not isinstance(p, str) or not PROFILE_RE.fullmatch(p) for p in raw):
            r.error(t.c_where, f"service {name}: profiles must be a list of literal profile names", SETUP_HINT)
            continue
        out[str(name)] = list(raw)
    return out


def job_services(m: Dict[str, Any], services: Dict[str, Any]) -> Set[str]:
    """templates.JobServices: the manifest's jobs plus every service another
    one depends on with condition: service_completed_successfully."""
    out = {scalar_text(j) for j in as_list(m.get("jobs"))}
    for svc in services.values():
        deps = svc.get("depends_on") if isinstance(svc, dict) else None
        if isinstance(deps, dict):
            for dep, c in deps.items():
                if isinstance(c, dict) and c.get("condition") == "service_completed_successfully":
                    out.add(str(dep))
    return out


def unprofiled_dependents(t: Template, services: Dict[str, Any], profiled: Dict[str, List[str]], r: Report) -> None:
    """unprofiledDependents: a service without profiles may not name a profiled
    one in depends_on, network_mode: service:<x> or volumes_from (compose
    can't start it for a setup choice that leaves that service off)."""
    for name in sorted(str(n) for n in services):
        svc = services.get(name)
        if name in profiled or not isinstance(svc, dict) or "profiles" in svc:
            continue
        refs: Dict[str, str] = {}
        deps = svc.get("depends_on")
        if isinstance(deps, list):
            for d in deps:
                if isinstance(d, str):
                    refs[d] = "depends_on"
        elif isinstance(deps, dict):
            for d in deps:
                refs[str(d)] = "depends_on"
        nm = svc.get("network_mode")
        if isinstance(nm, str) and nm.startswith("service:"):
            refs[nm[len("service:"):]] = "network_mode"
        for vf in as_list(svc.get("volumes_from")):
            src = vf.split(":", 1)[0] if isinstance(vf, str) else ""
            if src and src != "container":
                refs[src] = "volumes_from"
        for ref in sorted(refs):
            if ref in profiled:
                r.error(t.c_where, f"service {name}: {refs[ref]} names profiled service {ref}: give {name} the same profiles, or "
                                   f"compose can't start it when a setup choice leaves {ref} off", SETUP_HINT)
                break


def setup_option_problem(o: Dict[str, Any], known: Set[str], started: Set[str]) -> str:
    """setupOption: setup, fixed_after_start and profiles of one option."""
    instance = scope_of(o) == "instance"
    setup = o.get("setup") is True
    if setup and (not instance or o.get("type") == "secret"):
        return "setup needs scope instance and a type other than secret"
    if o.get("fixed_after_start") is True and not setup:
        return "fixed_after_start needs setup: true"
    if "profiles" not in o:
        return ""
    profiles = o.get("profiles")
    if not setup or o.get("type") != "enum" or not instance:
        return "profiles is for setup enum options of scope instance"
    if o.get("default") is None:
        return "profiles needs a default"
    profiles = profiles if isinstance(profiles, dict) else {}
    values = [scalar_text(c.get("value")) for c in as_list(o.get("options")) if isinstance(c, dict)]
    keys = sorted(scalar_text(k) for k in profiles)
    for k in keys:
        if k not in values:
            return f"profiles: {k} is not one of the option's values"
    for v in values:
        if v not in keys:
            return f"profiles: value {v} has no entry (write {v}: [] when it starts no profile)"
    for k in keys:
        lst = next(val for kk, val in profiles.items() if scalar_text(kk) == k)
        for p in as_list(lst):
            p = scalar_text(p)
            if not PROFILE_RE.fullmatch(p) or p not in known:
                return f"profiles.{k}: profile {p} is on no compose service"
            started.add(p)
    return ""


def check_setup(t: Template, services: Dict[str, Any], routers: Dict[str, Dict[str, str]], r: Report) -> None:
    """jobs (§3 "One-off jobs") and setup options with compose profiles
    (§13.18), as the Hub's validateSetup checks them."""
    m = t.manifest or {}
    routed = {rt.get("_service") for rt in routers.values()}
    listed: Set[str] = set()
    for j in as_list(m.get("jobs")):
        j = scalar_text(j)
        if j not in services:
            r.error(t.m_where, f"jobs: {j} is not a compose service", JOBS_HINT)
        elif j in listed:
            r.error(t.m_where, f"jobs: {j} is listed twice", JOBS_HINT)
        listed.add(j)
    # Every job, listed or found through depends_on, serves nothing.
    for j in sorted(job_services(m, services)):
        if j in routed:
            r.error(t.m_where, f"jobs: {j} has a Traefik router: a one-off job serves nothing", JOBS_HINT)
    profiled = service_profiles(t, services, r)
    unprofiled_dependents(t, services, profiled, r)
    known = {p for ps in profiled.values() for p in ps}
    started: Set[str] = set()
    for o in setting_options(m):
        why = setup_option_problem(o, known, started)
        if why:
            r.error(t.m_where, f"setting {_str(o, 'key')}: {why}", SETUP_HINT)
    for name in sorted(profiled):
        if not any(p in started for p in profiled[name]):
            r.error(t.c_where, f"service {name}: no setup option's profiles start it (its profiles {', '.join(profiled[name])})",
                    "give a setup enum option a profiles mapping that starts it, or drop profiles: (the Hub never starts it)")


# ── Runtime compatibility: rootless Podman ─────────────────────────

ROOTLESS_MAX_ID = 65535
_ROOTLESS_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?])([^}]*))?\}")
_ROOTLESS_DEVICE_RE = re.compile(r"/dev/[A-Za-z0-9._/-]+")
_GO_INT_RE = re.compile(r"[+-]?[0-9]+")


def _rootless_resolve(s: str, env: Dict[str, str]) -> str:
    """Interpolate s compose-style, as the Hub's resolve: ${V}, ${V:-d}
    (empty or unset -> d), ${V-d} (unset -> d), ${V:?...} / ${V?...} (the
    value); $$ is a literal dollar."""
    esc = "\x00"
    s = s.replace("$$", esc)

    def sub(m: "re.Match[str]") -> str:
        name, op, default = m.group(1), m.group(2) or "", m.group(3) or ""
        val = env.get(name)
        if op == ":-" and not val:
            return default
        if op == "-" and val is None:
            return default
        return val or ""

    return _ROOTLESS_VAR_RE.sub(sub, s).replace(esc, "$")


def _rootless_split(s: str) -> List[str]:
    """Split s at ':' outside ${...} (the Hub's splitOutsideVars)."""
    parts: List[str] = []
    depth = start = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c == "$" and i + 1 < len(s) and s[i + 1] == "{":
            depth += 1
            i += 1
        elif c == "}" and depth > 0:
            depth -= 1
        elif c == ":" and depth == 0:
            parts.append(s[start:i])
            start = i + 1
        i += 1
    parts.append(s[start:])
    return parts


def _go_scalar(v: Any) -> str:
    """A YAML scalar as the Hub sees its text."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        return str(int(v))
    return str(v)


def _rootless_scalars(v: Any) -> Tuple[List[str], bool]:
    """v's scalar items (v a list), else v itself as one; ok False for any
    non-scalar item or a non-list collection (the Hub's scalars)."""
    if v is None:
        return [], True
    if isinstance(v, (dict, list)):
        if isinstance(v, dict):
            return [], False
        out = [_go_scalar(x) for x in v if not isinstance(x, (dict, list))]
        return out, len(out) == len(v)
    return [_go_scalar(v)], True


def _go_atoi(s: str) -> Optional[int]:
    if not _GO_INT_RE.fullmatch(s):
        return None
    n = int(s)
    return n if -(1 << 63) <= n < (1 << 63) else None


def _rootless_host_port(p: Dict[str, Any], env: Dict[str, str]) -> int:
    """A manifest port's effective host port (a range's start): env's value
    for its key when set, else the default (the Hub's hostPort)."""
    key = p.get("key")
    v = (env.get(key) or "").strip() if isinstance(key, str) else ""
    rng = p.get("range")
    if isinstance(rng, str) and rng:
        r = v or rng
        n = _go_atoi(r.split("-", 1)[0].strip())
        return n if n is not None else 0
    if v:
        n = _go_atoi(v)
        if n is not None:
            return n
    d = p.get("default")
    return d if isinstance(d, int) and not isinstance(d, bool) else 0


def _compat_services(t: Template) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[str, List[str]]]]:
    """The template's compose services in order, or the refused verdict of
    an unreadable compose file (the Hub's orderedServices)."""
    compose = t.compose
    if compose is None:
        try:
            with open(t.compose_path, encoding="utf-8") as f:
                compose = yaml.load(f.read(), Loader=_UniqueKeyLoader)  # noqa: S506
        except Exception as e:  # noqa: BLE001 - any read / parse failure refuses
            return None, ("refused", [f"compose.yml can't be read: {e}"])
    services: Dict[str, Any] = {}
    if compose is not None:
        if not isinstance(compose, dict):
            return None, ("refused", ["compose.yml can't be read: not a mapping"])
        if "services" in compose:
            services = compose["services"]
            if not isinstance(services, dict):
                return None, ("refused", ["compose.yml can't be read: services is not a mapping"])
    for name, svc in services.items():
        if svc is not None and not isinstance(svc, dict):
            return None, ("refused", [f"compose.yml can't be read: service {name}: not a mapping"])
    return services, None


class _Reasons:
    """Refused and degraded reasons, each once (the Hub's compatReasons)."""

    def __init__(self) -> None:
        self.refused: List[str] = []
        self.degraded: List[str] = []

    def refuse(self, s: str) -> None:
        if s not in self.refused:
            self.refused.append(s)

    def degrade(self, s: str) -> None:
        if s not in self.degraded:
            self.degraded.append(s)

    def verdict(self) -> Tuple[str, List[str]]:
        if self.refused:
            return ("refused", self.refused)
        if self.degraded:
            return ("degraded", self.degraded)
        return ("ok", [])


RUNTIMES = ("docker", "podman", "kubernetes")


def runtime_compat(t: Template, rt: str, env: Optional[Dict[str, str]] = None, port_start: int = 80) -> Tuple[str, List[str]]:
    """Classify a template for runtime rt as the Hub's RuntimeCompat
    (portcullis-hub internal/templates/runtimecompat.go, kubecompat.go;
    shared vectors in tests/runtime_vectors.json): docker is always ok,
    podman the rootless rules, kubernetes the Kubernetes table (contracts
    §3.4, §11.10). env is the instance's effective values (None = the
    defaults; port keys carry the instance's host ports)."""
    if rt == "podman":
        return _podman_compat(t, env, port_start)
    if rt == "kubernetes":
        return _kube_compat(t, env)
    if rt == "docker":
        return ("ok", [])
    raise ValueError(f"unknown runtime {rt!r}")


def _podman_compat(t: Template, env: Optional[Dict[str, str]], port_start: int) -> Tuple[str, List[str]]:
    """Classify a template under rootless Podman, as the Hub's rootlessCompat
    (portcullis-hub internal/templates/runtimecompat.go).

    Rules, per service in compose order: devices (a source other than
    /dev/null and /dev/net/tun refused, /dev/null and /dev/net/tun
    degraded), cap_add (SYS_RAWIO / SYS_ADMIN / ALL refused, NET_ADMIN
    degraded), user / group_add ids above 65535 refused, network_mode host (resolved)
    degraded; then each manifest port (below port_start refused, UDP
    degraded); then folder runs_as ids outside 0-65535 refused. Each reason
    once. Any refused reason gives ("refused", refused reasons); else any
    degraded one ("degraded", degraded reasons); else ("ok", []). An
    unreadable compose file is refused.

    env is the instance's effective values (None = the defaults; port keys
    carry the instance's host ports).
    """
    env = env or {}
    refused: List[str] = []
    degraded: List[str] = []

    def refuse(s: str) -> None:
        if s not in refused:
            refused.append(s)

    def degrade(s: str) -> None:
        if s not in degraded:
            degraded.append(s)

    services, bad = _compat_services(t)
    if bad is not None or services is None:
        return bad or ("refused", [])

    def check_id(service: str, v: str) -> None:
        v = v.strip()
        if v and re.fullmatch(r"[0-9]+", v) and int(v) > ROOTLESS_MAX_ID:
            refuse(f"service {service} runs as id {v.lstrip('0')}, outside the rootless id range (0–65535)")

    for name, svc in services.items():
        svc = svc or {}
        tun = f"service {name} uses TUN/NET_ADMIN inside the rootless network namespace (prefer a userspace mode)"
        devs, ok = _rootless_scalars(svc.get("devices"))
        if not ok:
            refuse(f"service {name} passes the host device a non-device source: device access needs host root")
        for d in devs:
            src = _rootless_resolve(_rootless_split(d)[0], env)
            if src == "":
                continue  # an unset source: compose itself refuses the file
            if src == "/dev/null":
                degrade(f"service {name} has device slots: host devices can't be passed under rootless Podman")
            elif src == "/dev/net/tun":
                degrade(tun)
            else:
                shown = src if _ROOTLESS_DEVICE_RE.fullmatch(src) else "a non-device source"
                refuse(f"service {name} passes the host device {shown}: device access needs host root")
        caps, _ = _rootless_scalars(svc.get("cap_add"))
        for cp in caps:
            c = _rootless_resolve(cp, env).strip().upper()
            if c.startswith("CAP_"):
                c = c[len("CAP_"):]
            if c in ("SYS_RAWIO", "SYS_ADMIN", "ALL"):
                refuse(f"service {name} needs {'SYS_ADMIN' if c == 'ALL' else c} (raw device access needs host root)")
            elif c == "NET_ADMIN":
                degrade(tun)
        user = svc.get("user")
        if "user" in svc and not isinstance(user, (dict, list)):
            for part in _rootless_resolve(_go_scalar(user), env).split(":"):
                check_id(name, part)
        groups, _ = _rootless_scalars(svc.get("group_add"))
        for g in groups:
            check_id(name, _rootless_resolve(g, env))
        nm = svc.get("network_mode")
        if "network_mode" in svc and not isinstance(nm, (dict, list)) and _rootless_resolve(_go_scalar(nm), env) == "host":
            degrade(f"host networking: published ports must stay at or above {port_start}")

    manifest = t.manifest if isinstance(t.manifest, dict) else {}
    ports = manifest.get("ports")
    for p in ports if isinstance(ports, list) else []:
        if not isinstance(p, dict):
            continue
        n = _rootless_host_port(p, env)
        if n <= 0:
            continue
        proto = p.get("protocol") or "tcp"
        if n < port_start:
            refuse(f"host port {n}/{proto} is below net.ipv4.ip_unprivileged_port_start ({port_start}): "
                   f"lower it to {n} on the host to allow it (any local user can then bind ports from {n})")
        if proto == "udp":
            degrade(f"UDP clients on port {n} appear with a rewritten source address")

    for o in setting_options(manifest):
        folder = o.get("folder")
        runs_as = folder.get("runs_as") if isinstance(folder, dict) else None
        if not isinstance(runs_as, dict):
            continue
        target = o.get("target")
        svc_name = target.get("service") if isinstance(target, dict) else None
        if not (isinstance(svc_name, str) and svc_name):
            svc_name = _str(o, "key")
        for k in ("uid", "gid"):
            i = runs_as.get(k)
            if isinstance(i, int) and not isinstance(i, bool) and (i < 0 or i > ROOTLESS_MAX_ID):
                refuse(f"service {svc_name} runs as id {i}, outside the rootless id range (0–65535)")

    if refused:
        return ("refused", refused)
    if degraded:
        return ("degraded", degraded)
    return ("ok", [])



# ── Kubernetes compatibility (contracts §3.4, §11.10) ───────────────

# The Pod Security baseline's capabilities (the Hub's KubeBaselineCaps).
KUBE_BASELINE_CAPS = {"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE",
                      "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}
# The shared-folder roots without the Hub's own (HUB_OVERRIDE_BIND_ROOTS'
# default), and the env key under which the Hub passes its roots.
KUBE_DEFAULT_BIND_ROOTS = ["/srv", "/mnt", "/media"]
KUBE_ENV_BIND_ROOTS = "\x00bind_roots"
KUBE_DEFAULT_VPN_PORT = 51820
AVAHI_SERVICES_DIR_KEY = "avahi_services_dir"
_KUBE_SHOWN_USER_RE = re.compile(r"[A-Za-z0-9._-]{1,32}(:[A-Za-z0-9._-]{1,32})?")
_KUBE_SHOWN_PATH_RE = re.compile(r"/[A-Za-z0-9._/@+-]{0,200}")


def kube_core_ports(env: Dict[str, str]) -> List[int]:
    """The ports no app may publish on Kubernetes (the admission policy's
    corePorts): 80, 443, the VPN port (PORTCULLIS_VPN_PORT, default 51820),
    8000, 8081, 8443 and 8444."""
    vpn = KUBE_DEFAULT_VPN_PORT
    n = _go_atoi((env.get("PORTCULLIS_VPN_PORT") or "").strip())
    if n is not None:
        vpn = n
    return [80, 443, vpn, 8000, 8081, 8443, 8444]


def _kube_scalar(svc: Dict[str, Any], key: str, env: Dict[str, str]) -> str:
    """A service field's scalar value, resolved and trimmed ('' for a
    missing, null or non-scalar field: the Hub's scalarValue)."""
    v = svc.get(key)
    if v is None or isinstance(v, (dict, list)):
        return ""
    return _rootless_resolve(_go_scalar(v), env).strip()


def _kube_numeric(s: str) -> bool:
    return s != "" and s.strip("0123456789") == ""


def _kube_under_roots(p: str, roots: List[str]) -> bool:
    p = go_clean(p)
    for r in roots:
        r = go_clean(r.strip()) if r.strip() else ""
        if r in ("", ".") or not r.startswith("/"):
            continue
        if p == r or p.startswith(r.rstrip("/") + "/"):
            return True
    return False


def _kube_bind_sources(vols: Any, env: Dict[str, str]) -> List[str]:
    """A service's bind sources, resolved (short syntax with a path
    source, long syntax type: bind); named and anonymous volumes aren't."""
    out: List[str] = []
    if not isinstance(vols, list):
        return out
    for v in vols:
        if isinstance(v, dict):
            if _kube_scalar(v, "type", env) != "bind":
                continue
            src = _kube_scalar(v, "source", env)
            if src:
                out.append(src)
        elif not isinstance(v, list) and v is not None:
            parts = _rootless_split(_go_scalar(v))
            if len(parts) < 2:
                continue
            src = _rootless_resolve(parts[0], env).strip()
            if src.startswith(("/", ".", "~")):
                out.append(src)
    return out


def _kube_compat(t: Template, env: Optional[Dict[str, str]]) -> Tuple[str, List[str]]:
    """The Hub's kubeCompat: per service in compose order its devices,
    cap_add, user, network_mode, privileged, pid / ipc, binds, scale and
    extra_hosts; then each manifest port (a core port); then the Avahi
    option. Each reason once; refused, else degraded, else ok."""
    env = env or {}
    services, bad = _compat_services(t)
    if bad is not None or services is None:
        return bad or ("refused", [])
    c = _Reasons()
    roots = env[KUBE_ENV_BIND_ROOTS].split(":") if KUBE_ENV_BIND_ROOTS in env else KUBE_DEFAULT_BIND_ROOTS
    for name, svc in services.items():
        svc = svc or {}
        tun = f"service {name} uses TUN/NET_ADMIN (not on Kubernetes; prefer a userspace mode)"
        devs, ok = _rootless_scalars(svc.get("devices"))
        if not ok:
            c.refuse(f"service {name} passes host devices (not on Kubernetes)")
        for d in devs:
            src = _rootless_resolve(_rootless_split(d)[0], env)
            if src == "":
                continue
            if src == "/dev/null":
                c.degrade(f"service {name} has device slots: host devices can't be passed on Kubernetes")
            elif src == "/dev/net/tun":
                c.refuse(tun)
            else:
                c.refuse(f"service {name} passes host devices (not on Kubernetes)")
        caps, _ = _rootless_scalars(svc.get("cap_add"))
        for cp in caps:
            v = _rootless_resolve(cp, env).strip().upper()
            if v.startswith("CAP_"):
                v = v[len("CAP_"):]
            if v == "":
                continue
            if v == "NET_ADMIN":
                c.refuse(tun)
            elif v not in KUBE_BASELINE_CAPS:
                if v.strip("ABCDEFGHIJKLMNOPQRSTUVWXYZ_") != "" or len(v) > 32:
                    v = "a capability"
                c.refuse(f"service {name} adds {v}, outside the Kubernetes baseline")
        u = _kube_scalar(svc, "user", env)
        if u:
            uid, _, gid = u.partition(":")
            if not _kube_numeric(uid) or (gid != "" and not _kube_numeric(gid)):
                shown = u if _KUBE_SHOWN_USER_RE.fullmatch(u) else "a non-numeric value"
                c.refuse(f"service {name} runs as user {shown}: Kubernetes needs a numeric uid")
        if _kube_scalar(svc, "network_mode", env) == "host":
            c.refuse(f"service {name} uses network_mode: host (not on Kubernetes)")
        if _kube_scalar(svc, "privileged", env) in ("true", "True", "yes"):
            c.refuse(f"service {name} is privileged (not on Kubernetes)")
        for ns in ("pid", "ipc"):
            if _kube_scalar(svc, ns, env) == "host":
                c.refuse(f"service {name} shares the host's {ns} namespace (not on Kubernetes)")
        for src in _kube_bind_sources(svc.get("volumes"), env):
            if not src.startswith("/") or _kube_under_roots(src, roots):
                continue
            shown = src if _KUBE_SHOWN_PATH_RE.fullmatch(src) else "a host path"
            c.refuse(f"service {name} binds {shown}, outside the shared-folder roots (not on Kubernetes)")
        scale = _kube_scalar(svc, "scale", env)
        if scale:
            k = _go_atoi(scale)
            if k is None or k > 1:
                c.refuse(f"service {name} sets replicas above 1 (not on Kubernetes)")
        eh = svc.get("extra_hosts")
        if (isinstance(eh, (dict, list)) and len(eh) > 0) or (eh is not None and not isinstance(eh, (dict, list))
                                                            and _go_scalar(eh) != ""):
            c.refuse(f"service {name} sets extra_hosts (not on Kubernetes)")

    manifest = t.manifest if isinstance(t.manifest, dict) else {}
    first = next(iter(services), "")
    core = kube_core_ports(env)
    ports = manifest.get("ports")
    for p in ports if isinstance(ports, list) else []:
        if not isinstance(p, dict):
            continue
        n = _rootless_host_port(p, env)
        if n > 0 and n in core:
            svc_name = p.get("service") if isinstance(p.get("service"), str) and p.get("service") else first
            c.refuse(f"service {svc_name} publishes port {n}, a core port")
    for o in setting_options(manifest):
        if o.get("key") == AVAHI_SERVICES_DIR_KEY and (env.get(AVAHI_SERVICES_DIR_KEY) or "").strip():
            c.degrade("the Avahi services directory binds a host path outside the shared-folder roots: "
                      "leave it empty and connect by address")
    return c.verdict()


# ── Main ────────────────────────────────────────────────────────────

def runtime_classification(apps: Optional[List[str]] = None) -> str:
    """tests/runtime.txt: one line per template and runtime,
    <id>\t<runtime>\t<status>\t<reasons joined "; ">, kubernetes and podman
    (port start 80), with the defaults (no instance env), sorted (the Hub's
    TestRealTemplatesRuntimeClassification)."""
    lines = []
    for app_id in apps or discover():
        t = Template(app_id)
        if not os.path.isfile(t.manifest_path):
            continue
        try:
            with open(t.manifest_path, encoding="utf-8") as f:
                t.manifest = yaml.load(f.read(), Loader=_UniqueKeyLoader)  # noqa: S506
        except (OSError, yaml.YAMLError):
            t.manifest = None
        for rt in ("kubernetes", "podman"):
            status, reasons = runtime_compat(t, rt, env=None, port_start=80)
            lines.append(f"{app_id}\t{rt}\t{status}\t{'; '.join(reasons)}")
    return "".join(line + "\n" for line in sorted(lines))


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
    ap.add_argument("--runtime", action="store_true",
                    help="output the runtime compatibility classification (tests/runtime.txt)")
    args = ap.parse_args(argv)

    if args.runtime:
        print(runtime_classification(args.apps), end="")
        return 0

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
                check_links(t, sub)
                check_compose(t, sub)
        if i in ids:
            r.errors += sub.errors
            r.warnings += sub.warnings
    check_core_ref(r)
    check_dependabot(all_ids, r)
    cross = Report()
    check_cross(list(templates.values()), cross)
    check_sync_copies(list(templates.values()), cross)
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
