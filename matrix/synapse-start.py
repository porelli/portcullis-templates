#!/usr/bin/env python3
"""Portcullis start wrapper for Synapse (runs as uid 991 in the Synapse image).

Renders homeserver.yaml from the environment into the container's tmpfs
(never the data volume), then execs the image's /start.py. Fails closed: any
missing or malformed value stops the container before Synapse listens.

- Login: OIDC only (Keycloak), keyed on the OIDC sub; the Matrix localpart is
  the LLDAP username (preferred_username), never the email. Only members of
  the access group (groups claim) may sign in or get an account. No password
  login, no open registration, no linking to existing accounts.
- Federation: off unless MATRIX_FEDERATION_DOMAINS lists peer servers.
- Signing key: created once in /data (persistent); server_name is pinned in
  /data on first start and a different hostname is refused (Matrix user ids
  and rooms are bound to it forever).

Secrets come from the environment and are written only to the 0600 config
file in the tmpfs; nothing here prints them.
"""

import json
import os
import re
import secrets
import sys

DATA = "/data"
CONF_DIR = "/tmp/portcullis-synapse"
CONF = os.path.join(CONF_DIR, "homeserver.yaml")
SIGNING_KEY = os.path.join(DATA, "signing.key")
SERVER_NAME_PIN = os.path.join(DATA, "portcullis-server-name")

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SECRET_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{16,256}$")
# LLDAP group names / Keycloak client ids: printable, no whitespace or quotes.
NAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")


def die(msg: str) -> None:
    print(f"synapse-start: {msg}; refusing to start", file=sys.stderr, flush=True)
    sys.exit(1)


def env(name: str, rx: "re.Pattern[str]", what: str) -> str:
    val = os.environ.get(name, "")
    if not rx.fullmatch(val):
        # Never echo the value: it may be a secret.
        die(f"{name} is empty or not a valid {what}")
    return val


def write_private(path: str, text: str) -> None:
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def main() -> None:
    server_name = env("MATRIX_HOST", HOST_RE, "hostname")
    element_host = env("ELEMENT_HOST", HOST_RE, "hostname")
    issuer = os.environ.get("MATRIX_OIDC_ISSUER", "")
    m = re.fullmatch(r"https://([^/]+)/realms/portcullis", issuer)
    if not m or not HOST_RE.fullmatch(m.group(1)):
        die("MATRIX_OIDC_ISSUER is not https://auth.<domain>/realms/portcullis")
    client_id = env("MATRIX_OIDC_CLIENT_ID", NAME_RE, "Keycloak client id")
    access_group = env("MATRIX_ACCESS_GROUP", NAME_RE, "group name")
    client_secret = env("MATRIX_OIDC_SECRET", SECRET_RE, "secret")
    db_password = env("MATRIX_DB_PASSWORD", SECRET_RE, "secret")
    registration_secret = env("SYNAPSE_REGISTRATION_SECRET", SECRET_RE, "secret")
    macaroon_secret = env("SYNAPSE_MACAROON_SECRET", SECRET_RE, "secret")
    form_secret = env("SYNAPSE_FORM_SECRET", SECRET_RE, "secret")

    federation = [d for d in re.split(r"[\s,]+", os.environ.get("MATRIX_FEDERATION_DOMAINS", "")) if d]
    for d in federation:
        if not HOST_RE.fullmatch(d):
            die("MATRIX_FEDERATION_DOMAINS must be a comma-separated list of server names (hostnames)")

    if not os.path.isdir(DATA) or not os.access(DATA, os.W_OK):
        die(f"{DATA} is not writable (synapse-init must run first)")

    # server_name can never change: user ids, room ids and signatures embed it.
    if os.path.exists(SERVER_NAME_PIN):
        with open(SERVER_NAME_PIN, encoding="utf-8") as f:
            pinned = f.read().strip()
        if pinned != server_name:
            die(f"this homeserver was created as {pinned!r}; Matrix cannot change server_name "
                f"(instance hostname is now {server_name!r}). Restore the hostname or start a new instance")
    else:
        write_private(SERVER_NAME_PIN, server_name + "\n")

    if not os.path.exists(SIGNING_KEY):
        from signedjson.key import generate_signing_key, write_signing_keys
        key = generate_signing_key("a_" + secrets.token_hex(2))
        tmp = SIGNING_KEY + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            write_signing_keys(f, [key])
        os.replace(tmp, SIGNING_KEY)
        print("synapse-start: generated the server signing key", flush=True)

    resources = ["client", "federation"] if federation else ["client"]
    config = {
        "server_name": server_name,
        "public_baseurl": f"https://{server_name}/",
        "pid_file": os.path.join(CONF_DIR, "homeserver.pid"),
        "listeners": [{
            "port": 8008,
            "type": "http",
            "tls": False,
            "bind_addresses": ["0.0.0.0"],
            # Traefik terminates TLS; X-Forwarded-For is used for client IPs.
            "x_forwarded": True,
            "resources": [{"names": resources, "compress": False}],
        }],
        "database": {
            "name": "psycopg2",
            "args": {"user": "synapse", "password": db_password, "dbname": "synapse",
                     "host": "matrix-db", "port": 5432, "cp_min": 5, "cp_max": 10},
        },
        "media_store_path": os.path.join(DATA, "media_store"),
        "signing_key_path": SIGNING_KEY,
        "report_stats": False,
        "enable_metrics": False,
        "url_preview_enabled": False,
        # Federation: [] = denied with every server (upstream's recommended
        # off switch); no federation resource on the listener either.
        "federation_domain_whitelist": federation,
        "serve_server_wellknown": bool(federation),
        "trusted_key_servers": [],
        "suppress_key_server_warning": True,
        "allow_public_rooms_over_federation": False,
        "allow_public_rooms_without_auth": False,
        "require_auth_for_profile_requests": True,
        "limit_profile_requests_to_users_who_share_rooms": True,
        # Accounts only through the group-restricted OIDC login.
        "enable_registration": False,
        "password_config": {"enabled": False},
        # Group membership is only checked at the OIDC login, and access
        # tokens never expire by default: every device must sign in again
        # (through the group-checked SSO login) after 7 days, so a user
        # removed from the access group loses access within that time.
        "session_lifetime": "7d",
        "enable_3pid_changes": False,
        "enable_3pid_lookup": False,
        # Break-glass: shared-secret registration (Admin API, behind the
        # admin_paths gate at Traefik and this HMAC secret).
        "registration_shared_secret": registration_secret,
        "macaroon_secret_key": macaroon_secret,
        "form_secret": form_secret,
        "oidc_providers": [{
            # Never change idp_id: existing users are linked to it (oidc-portcullis).
            "idp_id": "portcullis",
            "idp_name": "Portcullis",
            "issuer": issuer,
            "client_id": client_id,
            "client_secret": client_secret,
            "client_auth_method": "client_secret_basic",
            "pkce_method": "always",
            "scopes": ["openid", "profile"],
            # Accounts are keyed on the OIDC sub (default subject_template);
            # never matched to an existing account (e.g. by localpart).
            "allow_existing_users": False,
            "enable_registration": True,
            "user_mapping_provider": {"config": {
                "localpart_template": "{{ user.preferred_username }}",
                "display_name_template": "{{ user.name }}",
                "confirm_localpart": False,
                # No email_template: the (user-editable) email is not imported.
            }},
            "attribute_requirements": [{"attribute": "groups", "value": access_group}],
            # Keycloak sign-outs (the Hub signs users out when they leave a
            # group) end the Synapse sessions too (manifest backchannel_logout_url).
            "backchannel_logout_enabled": True,
        }],
        "sso": {
            # Element on its own host skips Synapse's "continue to your
            # account" page; trailing slash so no other host prefix matches.
            "client_whitelist": [f"https://{element_host}/"],
        },
    }

    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    # JSON is valid YAML: no quoting pitfalls with any value.
    write_private(CONF, json.dumps(config, indent=2) + "\n")
    print(f"synapse-start: config written for {server_name} "
          f"(federation {'with ' + ', '.join(federation) if federation else 'off'})", flush=True)

    os.execv("/start.py", ["/start.py", "run", "--config-path", CONF])


if __name__ == "__main__":
    main()
