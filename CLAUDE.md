# Portcullis Templates — Claude Code Instructions

## Project Overview

Default app marketplace for Portcullis. Contains 22 app templates with manifest.yaml + compose.yml.

## Layout & tooling

- `schema/manifest.schema.json` — manifest JSON Schema (2020-12); keep in sync with the Hub's `validateManifest` and the docs manifest reference
- `tests/validate.py` — schema + repo rules (run `python3 tests/validate.py`; needs `tests/requirements.txt`). Add new rules here, with a contributor-facing hint
- `tests/compose-config.sh` — `docker compose config -q` per template with dummy generated env
- `.core-ref` — core ref CI tests against (contracts §1); `.github/dependabot.yml` must list every template dir
- CI: `lint.yml` (all PRs incl. forks, no secrets), `test-apps.yml` (integration; fork PRs skipped, maintainers dispatch with `pr=<n>`; only `fetch-core` sees `PORTCULLIS_PAT`; image caches are written only by `fetch-core` (infra) and `app-images` (per-app, push to main only, list from `tests/app-images.sh`); `test` runs template code with no secrets, saves no cache, strips names from loaded tarballs and binds every image by a pinned-digest pull), `docs-dispatch.yml` (push to main → `templates-updated` to portcullis-docs)
- Contributor docs: `CONTRIBUTING.md`, `.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/`

## Critical Rules

- Every template MUST have `manifest.yaml` with a full `auth` section
- Compose files use `portcullis-proxy` external network (NOT `portcullis`)
- Frontend services: `networks: [default, portcullis-proxy]`
- Internal services (DBs, Redis): default network only
- Header-auth apps must accept identity headers (X-Forwarded-User etc.) only from Traefik: use the app's proxy allowlist with `${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}` (core var, Traefik's static IP on portcullis-proxy). If the app has no allowlist, reject the header from other peers in the app's own web server (Firefly, Guacamole) or keep the app off portcullis-proxy behind a gate (CloudBeaver). Never trust `**` / `0.0.0.0/0`. Tests use `assert_traefik_only_trust` / `assert_spoofed_identity_rejected` (tests/lib.sh)
- Identity = LLDAP username, never email (core 427c0aa): LLDAP lets users edit their own email, Keycloak marks it unverified (`email_verified=false`), group-gate sends `X-Forwarded-User` = username and `X-Forwarded-Email` = email (display/notifications only). Header-auth apps key on X-Forwarded-User; OIDC apps key on `sub`/`preferred_username` and must never link accounts by email (Vaultwarden `SSO_SIGNUPS_MATCH_EMAIL: "false"`, GitLab `omniauth_auto_link_user = false`, LiteLLM email attribute → unsent claim, Immich `immich-lock-local-users`, Headscale `email_verified_required: true`). Apps that reject `email_verified=false` but accept it absent set `keycloak_clients[].email_verified_claim: false` (Hub attaches core's `email-unverified` scope instead of `email`) and must not request the `email` scope (Keycloak: `invalid_scope`; validate.py checks `*SCOPE*` env); only Vaultwarden needs it (checked upstream: Immich, GitLab, LiteLLM, Actual, Headscale, NetBird don't gate on the claim). Gates that reject foreign X-Forwarded-User must reject X-Forwarded-Email too. validate.py `IDENTITY_*` tables enforce this; add new apps' settings there
- Volume names MUST have explicit `name: portcullis_<vol-name>`
- Files shipped with a template are mounted as `./templates/<app-id>/<file>` — relative paths resolve against the core checkout on the host, and the Hub copies the template dir to `<core>/templates/<app-id>/` before every `compose up` (CI symlinks the same layout). Never `./<file>` directly.
- Do NOT reference `./scripts/`. From `./certs/`, only `./certs/ca-bundle.crt:<path>:ro` may be mounted (the Hub-provided CA bundle); nothing else under `./certs/`
- Every `${VAR:?...}` (required) var in a compose file must be either a core var (e.g. `PORTCULLIS_DOMAIN`) or listed in the manifest `env:` with `generate: random` — the Hub only writes those into the per-app .env (tests/lib.sh mirrors this in CI)
- Images: explicit version tag + `@sha256:` index digest, never floating tags; don't bump DB majors; keep multi-image apps in lockstep (netbird management/signal, immich server/ML, guacamole/guacd) and note upstream upgrade paths in `auth.notes`
- Native-OIDC host-wide routers never use forward-auth. If the app can't restrict OIDC logins by group (GitLab CE, LiteLLM, Vaultwarden), gate only its login paths with a higher-priority `PathPrefix` router using `portcullis-auth@docker,portcullis-groups@docker` and set `group_access: true` (validate.py `LOGIN_GATES` guards gitlab/litellm/vaultwarden; Vaultwarden also needs `INVITATIONS_ALLOWED`/`SIGNUPS_ALLOWED` false, since email invitations create placeholder accounts the first SSO user with that email claims). SSO users get the least-privileged role
- Public share links go in `auth.public_access` (paths with one `{token}` segment + anchored `token_pattern`, `supporting` assets, `default_mode`, `enabled_by_default`), never as an ungated router in compose.yml: the Hub generates the public router (no forward-auth, identity headers stripped, one TLS tier per host). Header-auth apps with it list `auth.identity_headers`. `supporting` paths serve static files only (exact routes need `exact` + `justification`); login headers/cookies/query params go in `credential_headers`/`credential_cookies`/`credential_query` (Authorization is always stripped). Researched lists: nextcloud, grafana (listed, on by default = nothing open until a share is listed), immich (all, off by default). Vaultwarden Send and Kanboard can't be scoped by path (see their notes)
- Admin panels on a path behind forward-auth go in `auth.admin_paths` (e.g. vaultwarden `/admin`) so group-gate requires `admin_group` there
- No `ports:` / `build:` / `container_name:` / `env_file:` in compose; host ports go in manifest `ports:`
- After changing manifests, regenerate docs: `python3 scripts/generate-app-docs.py --source /Volumes/workspace/portcullis/portcullis-templates` (from portcullis-docs repo)
