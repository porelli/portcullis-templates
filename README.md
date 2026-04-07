# Portcullis Templates

Default app marketplace for [Portcullis](https://github.com/porelli/portcullis) — the self-hosted YubiKey authentication gateway.

## Apps

This repo contains 22 pre-configured app templates, each with:

- `manifest.yaml` — app metadata, auth config, settings, env vars
- `compose.yml` — Docker Compose definition with Traefik routing

The [Portcullis Hub](https://github.com/porelli/portcullis-hub) automatically clones this repo on first startup and presents the apps in its catalog UI.

## Adding as a Template Source

The Hub auto-loads this repo. To add it manually or re-add after removal:

1. Open the Hub UI → Template Sources tab
2. Add source:
   - **Name:** `portcullis`
   - **URL:** `https://github.com/porelli/portcullis-templates.git`

## Creating Your Own Templates

See the [Manifest Reference](https://porelli.github.io/portcullis-docs/guides/manifest-reference/) and [Adding an App](https://porelli.github.io/portcullis-docs/guides/adding-an-app/) guides.

## Auth Methods

| Method | Apps |
|--------|------|
| **Native OIDC** | Actual Budget, GitLab, Guacamole, Headscale, Immich, Jellyfin, LiteLLM, NetBird, Nextcloud, Vaultwarden |
| **Forward Auth** | AdGuard, CloudBeaver, DokuWiki, Pi-hole, Scrutiny, Wiki.js |
| **Header Auth** | Firefly III, Grafana, Kanboard |
| **Custom/Public** | Plex (plex.tv accounts), Docs (public), Vault UI (mTLS) |
