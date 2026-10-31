# Portcullis Templates — Claude Code Instructions

## Project Overview

Default app marketplace for Portcullis. Contains 22 app templates with manifest.yaml + compose.yml.

## Critical Rules

- Every template MUST have `manifest.yaml` with a full `auth` section
- Compose files use `portcullis-proxy` external network (NOT `portcullis`)
- Frontend services: `networks: [default, portcullis-proxy]`
- Internal services (DBs, Redis): default network only
- Header-auth apps must accept identity headers (X-Forwarded-User etc.) only from Traefik: use the app's proxy allowlist with `${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}` (core var, Traefik's static IP on portcullis-proxy). If the app has no allowlist, reject the header from other peers in the app's own web server (Firefly, Guacamole) or keep the app off portcullis-proxy behind a gate (CloudBeaver). Never trust `**` / `0.0.0.0/0`. Tests use `assert_traefik_only_trust` / `assert_spoofed_identity_rejected` (tests/lib.sh)
- Volume names MUST have explicit `name: portcullis_<vol-name>`
- Files shipped with a template are mounted as `./templates/<app-id>/<file>` — relative paths resolve against the core checkout on the host, and the Hub copies the template dir to `<core>/templates/<app-id>/` before every `compose up` (CI symlinks the same layout). Never `./<file>` directly.
- Do NOT reference `./scripts/`. From `./certs/`, only `./certs/ca-bundle.crt:<path>:ro` may be mounted (the Hub-provided CA bundle); nothing else under `./certs/`
- Every `${VAR:?...}` (required) var in a compose file must be either a core var (e.g. `PORTCULLIS_DOMAIN`) or listed in the manifest `env:` with `generate: random` — the Hub only writes those into the per-app .env (tests/lib.sh mirrors this in CI)
- After changing manifests, regenerate docs: `python3 scripts/generate-app-docs.py --source /Volumes/workspace/portcullis/portcullis-templates` (from portcullis-docs repo)
