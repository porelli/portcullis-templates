# Portcullis Templates

Default app marketplace for [Portcullis](https://github.com/porelli/portcullis) — the self-hosted YubiKey authentication gateway.

**Documentation: <https://porelli.github.io/portcullis-docs/>** — every template has a page in the [App Catalog](https://porelli.github.io/portcullis-docs/apps/); to write one, start with [CONTRIBUTING.md](CONTRIBUTING.md) and [Adding an App](https://porelli.github.io/portcullis-docs/guides/adding-an-app/).

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

## Contributing

New templates and fixes are welcome, including from forks. Start with
[CONTRIBUTING.md](CONTRIBUTING.md): step-by-step guide, auth method choice,
security rules and what CI runs.

Quick local check (no Docker daemon needed):

```bash
pip install -r tests/requirements.txt
python3 tests/validate.py          # manifest schema + repo rules
bash tests/compose-config.sh       # docker compose config for every template
```

- Manifests follow [`schema/manifest.schema.json`](schema/manifest.schema.json)
  (JSON Schema 2020-12); see also the
  [Manifest Reference](https://porelli.github.io/portcullis-docs/guides/manifest-reference/)
  and [Adding an App](https://porelli.github.io/portcullis-docs/guides/adding-an-app/).
- Every image is pinned by version tag and `@sha256:` digest; Dependabot
  proposes updates weekly.
- CI tests the templates against the core version in [`.core-ref`](.core-ref).
  Pull requests from forks get both lint and the full integration tests.

## Auth Methods

| Method | Apps |
|--------|------|
| **Native OIDC** | Actual Budget, DokuWiki, GitLab\*, Headscale, Immich, Jellyfin, LiteLLM\*, NetBird, Nextcloud, Vaultwarden\*, Wiki.js |
| **Forward Auth** | AdGuard, Pi-hole, Scrutiny |
| **Header Auth** | CloudBeaver, Firefly III, Grafana, Guacamole, Kanboard |
| **Custom/Public** | Plex (plex.tv accounts), Docs (public), Vault UI (mTLS, placeholder) |

\* Native OIDC plus forward-auth + group-gate on specific paths: GitLab,
LiteLLM and Vaultwarden gate their login paths by group (`users_<app>`),
Vaultwarden's `/admin` requires `admin_vaultwarden` (`auth.admin_paths`).
