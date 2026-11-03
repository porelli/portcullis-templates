# Changelog

Notable changes to the default templates, newest first. Templates are not
versioned individually; entries are dated by the commit that lands on `main`.

## Unreleased (app instances and extra domains)

### Template contract v3 settings (breaking)

Every template declares its settings in the contract v3 form (`settings:
{sections, options}`, typed options with lowercase keys, scopes, explicit
deliveries; contracts §13), validated by `tests/validate.py` as the Hub does.
No installs exist, so nothing is migrated: settings saved under v2 are not
carried over and have to be entered again.

- Typed options instead of free text: user pickers (guacamole, kanboard
  admin), lists (matrix federation peers, scrutiny disks, motionEye
  cameras), a multi-choice (paperless OCR languages), secrets (headscale API
  key, Plex claim token, Zigbee2MQTT MQTT password), time zones, IP
  addresses, device paths, and the Craft release version / SHA-256 pair.
- Plex runs as the "Plex user id / group id" settings (default 1000:1000);
  Jellyfin and Plex mount the library folders read-only.
- Pilots: Immich storage quota and role per group (token claims, at the
  next sign-in), trash days and machine learning; Grafana role per group
  (Viewer / Editor / Admin, header on every request: Admin is no longer a
  manual promotion, and a role changed in Grafana's UI is overwritten);
  Nextcloud default quota and trash retention applied live through occ;
  Firefox Sync's allowlist from the account ids people enter themselves.
- Firefox Sync: the "Allowed accounts" setting is gone. Members of
  `users_firefox-sync` (created on enable) enter their Mozilla account id
  on My apps; ids not tied to a person go in "Other allowed accounts".

### New templates

- **Firefox Sync** (`firefox-sync`): Mozilla's syncstorage-rs 0.24.0 (the
  porelli/firefox-sync PostgreSQL build) for Mozilla accounts. The host is
  open (Firefox's Sync requests carry no cookie or client certificate), and
  only Mozilla account ids on its allowlist can sync (empty = nobody): the
  ids members of `users_firefox-sync` enter themselves on My apps, plus the
  instance's "Other allowed accounts". The public server runs as a database
  role that can't touch the allowlist.
- **Vikunja** (`vikunja`): to-do lists and kanban boards, OIDC only (no
  password login, sign-up or invite links). Sign-in restricted to
  `users_vikunja` by the Hub's Keycloak access role. Link sharing is a
  setting, off by default.
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

- **ESPHome** (`esphome`): ESPHome Device Builder (ESPHome 2026.10.1) behind
  forward-auth + group-gate and a Traefik-only gate; no dashboard password,
  bridge networking (no mDNS: give devices a fixed address), optional serial
  port setting for flashing from the server.
- **Zigbee2MQTT** (`zigbee2mqtt`): Zigbee2MQTT 2.14.3 and its frontend behind
  the same gate; USB coordinator (device setting) or network coordinator;
  onboarding wizard off; external JS off by default; bundled Mosquitto 2.1
  (no anonymous clients, generated `zigbee2mqtt` / `homeassistant` users,
  allowlist ACL for Home Assistant) with an optional host MQTT port (default
  127.0.0.1), or an existing broker.
- **motionEye** (`motioneye`): motionEye 0.44.0 behind the same gate; its own
  admin/user login stays as a second step with generated passwords (never
  the empty default); up to four local cameras, a storage-folder setting.

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
