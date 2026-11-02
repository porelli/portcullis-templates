# Changelog

Notable changes to the default templates, newest first. Templates are not
versioned individually; entries are dated by the commit that lands on `main`.

## Unreleased (app instances and extra domains)

### New templates

- **Firefox Sync** (`firefox-sync`): Mozilla's syncstorage-rs 0.24.0 (the
  porelli/firefox-sync PostgreSQL build) for Mozilla accounts. The host is
  open (Firefox's Sync requests carry no cookie or client certificate), and
  only the Mozilla account ids in the "Allowed accounts" setting can sync
  (empty = nobody). The public server runs as a database role that can't
  touch the allowlist. Planned: each access-group member enters their own
  account id on their People page.
- **Vikunja** (`vikunja`): to-do lists and kanban boards, OIDC only (no
  password login, sign-up or invite links). Sign-in restricted to
  `users_vikunja` by the Hub's Keycloak access role. Link sharing is a
  setting, off by default.

### Upgrade notes

- **Nextcloud: admins must be in `users_nextcloud`.** The template now sets
  `auth.keycloak_access_role: true`: Keycloak lets only members of the access
  group (`users_nextcloud`, or `users_<instance-id>`) sign in. A member of
  `admin_nextcloud` who isn't also in `users_nextcloud` was let in before (by
  user_oidc's group whitelist) and is now denied. Before upgrading, add every
  existing Nextcloud admin to `users_nextcloud` (Hub → Users & Groups).
- Paperless-ngx, Vaultwarden and GitLab also set `keycloak_access_role: true`;
  their sign-in already required the access group (login-path gate), so
  nothing changes for their users.
- Vaultwarden runs with `SSO_ONLY`: the email + master password login is off;
  the master password only decrypts the vault after the SSO login.
- Jellyfin: the SSO plugin is pinned (version + sha256) and installed before
  Jellyfin starts; the local `admin` loses its password login (setup moves it
  to the plugin's provider).
- Guacamole: header logins as `guacadmin*` are refused (403); new databases
  name the built-in administrator `guacadmin-<generated suffix>`.
