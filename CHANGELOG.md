# Changelog

Notable changes to the default templates, newest first. Templates are not
versioned individually; entries are dated by the commit that lands on `main`.

## Unreleased (app instances and extra domains)

### Relative binds stay in the template's own files (ux2)

A template's relative bind sources are now only `./templates/<id>/…` and
`./certs/ca-bundle.crt` (contract §3; `tests/validate.py` and the Hub agree):
the core checkout holds every instance's data, so `./appfiles/…`, `./secrets`,
`..` and symlinked escapes are refused, and no volume entry may use `$`
interpolation in any form (no shipped template did). The data-file name
`mail-admin` is reserved. **docs** no longer serves core's `./docs` directory: it serves its
own placeholder page (`docs/docs/index.md`), pointing at the published
documentation.

### Marketplace fields: long descriptions, logos, minimum resources (ux3)

Every template gets a `long_description` (Markdown, the `auth.notes` rules; contract §3
"Catalog fields"), shown in the Hub's Marketplace drawer. `resources` is set only where the
project's own documentation states a minimum: immich (6 GB RAM), gitlab (8 GB, its
memory-constrained minimum), netbird (2 GB), mattermost (2 GB, its smallest single-server
size), wiki (1 GB), grafana (512 MB) and pihole (512 MB RAM, 2 GB disk). No template has
`screenshots` yet. `category` is now one of 16 fixed slugs.

`logo.svg` ships only where the project publishes an SVG logo in its own repository under a
licence that allows redistribution. Each file is the upstream file with editor metadata,
`version` / `xml:space` and hidden paths removed and `style` / CSS class properties written
as presentation attributes (`tests/svgsafe.py`, the logo lint); the drawing is unchanged.
The logos remain their projects' trademarks, used only to identify the apps. Sources:

- `ai-chat`: <https://github.com/danny-avila/LibreChat/blob/8f20fb28e549949b05e8b164d8a504bc14c0951a/client/public/assets/logo.svg> (MIT)
- `gitea`: <https://github.com/go-gitea/gitea/blob/f8a668ab0c098476a47b9d96fb061fa31fec78ef/assets/logo.svg> (MIT)
- `headscale`: <https://github.com/juanfont/headscale/blob/f00c412cde4a000cc091037f926519b99ceb7626/docs/assets/logo/headscale3-dots.svg> (BSD-3-Clause)
- `immich`: <https://github.com/immich-app/immich/blob/2de9a92fba52ee20795a4b03a9ffad5d129a5aa9/design/immich-logo.svg> (AGPL-3.0)
- `jellyfin`: <https://github.com/jellyfin/jellyfin-ux/blob/9e27258e873f64edaa9c5955e753978975ed5589/branding/SVG/icon-transparent.svg> (CC-BY-SA-4.0)
- `oxicloud`: <https://github.com/AtalayaLabs/OxiCloud/blob/54639d466af20334e1bab38d39133b3df14ab16e/frontend/static/logo/logo-plain.svg> (MIT)
- `paperless`: <https://github.com/paperless-ngx/paperless-ngx/blob/fbadc2e1b8c34f80b48be0766cae7168e0e8ec24/docs/assets/logo_leaf.svg> (GPL-3.0)
- `scrutiny`: <https://github.com/AnalogJ/scrutiny/blob/8482272d45aaf4a6a32a1585b03e07a3c79a0682/webapp/frontend/src/assets/images/logo/scrutiny-logo-dark.svg> (MIT)
- `vaultwarden`: <https://github.com/dani-garcia/vaultwarden/blob/d57b69952db6eb12987a9668fea6b72df79cfa41/resources/vaultwarden-icon.svg> (AGPL-3.0)
- `vikunja`: <https://github.com/go-vikunja/vikunja/blob/5b9d4fcc720fe65548ab6c3f7c974c12b28d13af/frontend/originalMedia/images/logo.svg> (AGPL-3.0)
- `zigbee2mqtt`: <https://github.com/Koenkk/zigbee2mqtt/blob/9c505fd75f503a91a61244d6f0efa0e37d81a7b0/images/logo_vector.svg> (GPL-3.0)

Not shipped: Nextcloud (its logo is `LicenseRef-NextcloudTrademarks`), Home Assistant
(CC BY-NC-SA), Actual Budget (white-only mark), DokuWiki and Kanboard (CSS a plain lint
can't keep), and projects whose logo terms are a trademark policy only.

### stalwart: the read-only mail admin view

The `stalwart` template gets the optional `mail.admin_view` (contracts
§3.5, §19.13): a new `admin-view` service (`mailctl admin-view`, the adapter
image) that the Hub routes `mail-admin.<main domain>` to, full
administrators only. The bootstrap job makes the read-only role
`portcullis-viewer` and its account and writes its password to the new
`viewer_key` volume (group 2011, mailview); Stalwart serves its web admin
(the bundle pinned in the mailctl image) at `/admin` on a TLS listener
answered only to `admin-view`. Every write is refused by Stalwart itself.
Needs a mailctl image with `admin-view` (the pin is bumped separately).

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
- Plex runs as the "Plex user id / group id" settings (default 1001:1001, the image's own plex user);
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
