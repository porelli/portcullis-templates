# Changelog

Notable changes to the default templates, newest first. Templates are not
versioned individually; entries are dated by the commit that lands on `main`.

## Unreleased (app instances and extra domains)

### New templates

- **Home Assistant** (`homeassistant`): native OIDC through the pinned
  auth_oidc integration, restricted to `users_homeassistant` in Keycloak
  (`keycloak_access_role: true`); the `homeassistant-init` job closes
  onboarding, installs auth_oidc and trusts only Traefik as proxy.
- **OxiCloud** (`oxicloud`): native OIDC only (`OXICLOUD_AUTH_METHODS=oidc`,
  no email account linking), login gated to `users_oxicloud`; the
  `oxicloud-init` job closes the first-run setup endpoint.
- **Mattermost** (`mattermost`, Team Edition): forward-auth gated to
  `users_mattermost` (Team Edition has no usable SSO); e-mail sign-up and
  plugin uploads off, plugin signatures required (pinned bundles signed per
  start by `mattermost-plugins`), bootstrap admin set by `mattermost-init`.

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
