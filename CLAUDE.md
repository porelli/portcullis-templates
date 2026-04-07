# Portcullis Templates — Claude Code Instructions

## Project Overview

Default app marketplace for Portcullis. Contains 22 app templates with manifest.yaml + compose.yml.

## Critical Rules

- Every template MUST have `manifest.yaml` with a full `auth` section
- Compose files use `portcullis-proxy` external network (NOT `portcullis`)
- Frontend services: `networks: [default, portcullis-proxy]`
- Internal services (DBs, Redis): default network only
- Volume names MUST have explicit `name: portcullis_<vol-name>`
- Do NOT reference `./certs/` or `./scripts/` — the Hub injects those via compose overrides
- After changing manifests, regenerate docs: `python3 scripts/generate-app-docs.py --source /Volumes/workspace/portcullis-templates` (from portcullis-docs repo)
