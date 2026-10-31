<!-- Thanks for contributing! See CONTRIBUTING.md for the rules behind each item. -->

## What

<!-- New template / fix / update. Which app(s), and why. -->

## Checklist

- [ ] `python3 tests/validate.py` passes
- [ ] `bash tests/compose-config.sh <app-id>` passes
- [ ] `shellcheck -S warning` is clean for changed scripts
- [ ] Images pinned to an explicit release tag **and** `@sha256:` digest; no database major bumps
- [ ] Auth method chosen per CONTRIBUTING.md; `auth.notes` explains how login, groups and admin work
- [ ] Forward-/header-auth routers use `portcullis-auth@docker,portcullis-groups@docker`; a native-OIDC host-wide router does not
- [ ] If any realm user could otherwise sign in: login paths gated by group, least-privileged default role
- [ ] Header-auth: identity headers accepted only from `${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}`; `assert_traefik_only_trust` / `assert_spoofed_identity_rejected` in the test
- [ ] No published HTTP ports; host ports declared under manifest `ports:`
- [ ] Secrets declared under `env:` with `generate: random`; no hard-coded or default passwords
- [ ] New template: added to `.github/dependabot.yml` and has `tests/apps/<app-id>.sh`

## Testing

<!-- What you ran. If you booted the stack yourself, how. Fork PRs: integration
tests run after a maintainer triggers them; lint runs right away. -->
