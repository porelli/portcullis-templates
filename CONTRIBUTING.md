# Contributing templates

Thanks for helping grow the Portcullis app catalog. A template is one
directory at the root of this repo:

```
<app-id>/
  manifest.yaml   # what the Hub shows and how auth is wired
  compose.yml     # how the app runs behind Traefik
  ...             # optional support files (config templates, setup scripts)
tests/apps/<app-id>.sh   # its CI test
```

The [Hub](https://github.com/porelli/portcullis-hub) clones this repo, lists
every template that passes validation and, when a user enables one, copies the
directory to `<core>/templates/<app-id>/` and runs `docker compose up`.

Reference docs:
[Manifest reference](https://porelli.github.io/portcullis-docs/guides/manifest-reference/),
[Adding an app](https://porelli.github.io/portcullis-docs/guides/adding-an-app/),
[Integration contracts](https://porelli.github.io/portcullis-docs/guides/integration-contracts/)
(the authoritative interface between this repo, the Hub and core).

## Adding a template, step by step

1. **Check for an existing request.** Search the issues, or open a
   "New app request" issue first if you want feedback on the approach.
2. **Pick an app id.** Lowercase, `^[a-z0-9][a-z0-9_-]{0,63}$`, e.g.
   `uptime-kuma`. It is the directory name, the compose project scope and part
   of URLs. Pick a subdomain no other template uses.
3. **Choose the auth method** (see [Choosing an auth method](#choosing-an-auth-method)).
4. **Write `manifest.yaml`.** Copy a template with the same auth method (for
   example `grafana/` for header-auth, `scrutiny/` for forward-auth,
   `vaultwarden/` for native OIDC) and adapt it. The schema is
   [`schema/manifest.schema.json`](schema/manifest.schema.json); for editor
   completion add this first line:
   ```yaml
   # yaml-language-server: $schema=../schema/manifest.schema.json
   ```
5. **Write `compose.yml`** following the [rules](#compose-rules) below.
6. **Pin the images** by version tag and digest (see [Images](#images)).
7. **Add the directory to `.github/dependabot.yml`** (docker-compose
   `directories:`), so image updates arrive as PRs.
8. **Add `tests/apps/<app-id>.sh`.** At minimum a static test (copy
   `tests/apps/scrutiny.sh`); boot the container with `compose_up` when the app
   starts reliably in CI. Header-auth apps must use
   `assert_traefik_only_trust` and `assert_spoofed_identity_rejected`
   from `tests/lib.sh`.
9. **Run the local checks** (next section) and open a pull request. Fill in
   the checklist in the PR template.

## Local checks

```bash
python3 -m venv .venv && .venv/bin/pip install -r tests/requirements.txt
.venv/bin/python tests/validate.py            # schema + repo rules, all templates
.venv/bin/python tests/validate.py my-app     # just yours (cross-template checks still run)
PATH=.venv/bin:$PATH bash tests/compose-config.sh my-app   # docker compose config -q (no daemon needed)
shellcheck -S warning tests/apps/*.sh ./*/*.sh
actionlint                                    # only if you touched .github/workflows
```

`tests/validate.py` prints one line per problem with a hint, for example:

```
ERROR my-app/compose.yml: services.web: image tag 'latest' is floating
      hint: pin the exact release, e.g. postgres:16.15-alpine instead of postgres:16-alpine; ...
```

The integration tests (`tests/apps/*.sh` against a real Keycloak/LLDAP/Traefik
stack) need the private core repo, so you normally cannot run them locally;
CI runs them for you once a maintainer approves (see below).

## What CI runs

| Workflow | When | Secrets | What |
|----------|------|---------|------|
| **Lint** (`lint.yml`) | every push and PR, including forks | none | `tests/validate.py`, `docker compose config` for every template, shellcheck, actionlint |
| **Test Apps** (`test-apps.yml`) | push to `main`, every PR **including forks**, manual runs | none | boots core at the ref in `.core-ref`, then runs `tests/apps/<app>.sh` for every changed template |
| **Notify docs** (`docs-dispatch.yml`) | push to `main` | `DOCS_DISPATCH_TOKEN` | asks the docs site to regenerate the app pages |

Core ([porelli/portcullis](https://github.com/porelli/portcullis)) is public
and cloned anonymously, so your fork PR gets the full integration tests
automatically. No job in Test Apps references a secret. Maintainers can
re-run a PR by hand with **Actions -> Test Apps -> Run workflow**, `pr = <number>`;
that run tests the exact head commit and aborts if the PR moved.

We deliberately do not use `pull_request_target`: it would run fork code with
a write token. Inside Test Apps, the trust boundary is per job:

- `gate` and `changes` decide what to test; they run no template code.
- `fetch-core` checks out nothing from the PR except `.core-ref`, read from a
  trusted commit (for PR runs, the PR's *base* commit, so a PR cannot point CI
  at another core ref). It clones core, packs it as an artifact, and is the
  only job besides `app-images` that writes an image cache.
- `app-images` runs only on pushes to `main` (never for PRs or manual runs).
  It reads each tested app's `compose.yml` (`tests/app-images.sh`), pulls its
  pinned images and writes that app's image cache. It starts no container.
- `test` runs your `tests/apps/<app>.sh` and compose file. It references no
  secret, writes no cache, downloads core by artifact id with digest
  verification, and treats every image cache as untrusted: after
  `docker load` it removes any name the tarball set, then binds every image
  (core's and the app's) with a `docker pull` of the digest pinned in the
  compose file. The pull checks the manifest against that digest and reuses
  a loaded image only if its ID (the hash of its config, which pins every
  layer) is the one that manifest names; otherwise it downloads it fresh.
- Every job has a read-only `contents: read` token.

`.core-ref` holds the core version the templates are tested against: a tag
such as `v1.4.0`, or `main` during development. Changing it re-tests every
template. (For PRs the base branch's `.core-ref` is used.)

## Choosing an auth method

| The app... | `auth.method` | Router middlewares |
|------------|---------------|--------------------|
| speaks OpenID Connect and can be pointed at Keycloak | `native-oidc` (+ `keycloak_clients`) | **no** `portcullis-auth`; the app logs users in itself |
| can create/log in users from a trusted header (`X-Forwarded-User`) | `header-auth` | `portcullis-auth@docker,portcullis-groups@docker` |
| has its own login (or none) and no SSO | `forward-auth` | `portcullis-auth@docker,portcullis-groups@docker` |
| is protected by client certificates only | `mtls` | `tls.options: protected@file`, no forward-auth |
| uses a vendor account system (e.g. plex.tv) | `custom` | none |
| is meant to be public | `public` | none |

Prefer `native-oidc` when the app supports it well: mobile apps, API tokens and
CLI clients keep working. Then check **who can log in**:

- If the app can restrict OIDC logins to a group, configure it with
  `access_group` (`users_<app-id>`) and set `group_access: true`.
- If it cannot, any Keycloak realm user could sign in. Put only the
  interactive login paths behind forward-auth + group-gate on a
  higher-priority `PathPrefix` router and keep the API on the host-wide router
  without forward-auth. See `gitlab/` (`/users`) and `litellm/` (`/ui`, `/sso`,
  `/login`, ...). A host-wide router of a native-OIDC app must never use
  `portcullis-auth@docker`.
- Give SSO-created users the **least-privileged role** the app has, and map
  `admin_group` to admin only where the app supports it.

Admin panels on a path (e.g. Vaultwarden's `/admin`): route the path through a
`PathPrefix` router with `portcullis-auth@docker,portcullis-groups@docker` and
list it in `auth.admin_paths`; group-gate then additionally requires
`admin_group` for it.

Public share links (e.g. Nextcloud `/s/<token>`): declare them in
`auth.public_access` — never as a router without forward-auth in
`compose.yml`. When an admin turns the exception on in the Hub, the Hub adds
the public router itself (no forward-auth, no group-gate, identity headers
stripped). Rules, all checked by `tests/validate.py`:

- Only for `forward-auth`, `header-auth` and `native-oidc` apps. Header-auth
  apps also list the headers they trust in `auth.identity_headers`.
- `paths[].prefix`: segment-boundary prefix of letters, digits and `. _ ~ -`;
  not `/`, no wildcards, `..`, `%`, `?`, `#`. At most 20, each with a
  `description`. Read the upstream routes at the pinned version and keep the
  list as narrow as the share page allows.
- Put the share token in the path as one `{token}` segment where the app
  allows it (`/s/{token}`) and give an anchored `token_pattern`: admins can
  then open single shares (`listed` mode). Static assets / l10n the page
  needs are `supporting: true`: they only serve static files (dot-free
  directories, a file with a static extension; add more with
  `static_extensions`, never script extensions). A single app route the
  page needs is `exact: true` with a `justification`. Other token-free paths
  open only in mode `all`.
- Logins must not ride the public router: list the app's other login
  headers in `credential_headers`, login cookies in `credential_cookies` and
  login query parameters in `credential_query`. Core's public guard
  (group-gate) refuses requests carrying any of them, or `Authorization` /
  `Proxy-Authorization`, with cookie / query names normalised the way PHP
  does. Check every authentication source of the app at the pinned version.
- Broad prefixes (`/api`, `/index.php`, bare `*.php`, `/ocs/v2.php`, ...) need
  `broad: true` and a `justification`; `/admin`, `/oauth2` and `/.well-known`
  are never public, and public paths may not overlap `admin_paths` or another
  router's `Path`/`PathPrefix` (login gates). Routers on the app's hosts may
  only use `Host`, `Path`, `PathPrefix`, `Method`, `Header`, `Query`,
  `ClientIP`, without negation.
- `enabled_by_default: true` only if nothing is opened until an admin acts
  (listed mode) or the exception can't weaken the host (see Immich: on, it
  drops the handshake mTLS requirement under an mTLS-only policy).

## Compose rules

`tests/validate.py` checks all of these.

- **Networks.** Services with `traefik.enable: "true"` use
  `networks: [default, portcullis-proxy]`; databases, caches and sidecars stay
  on `default` only. Declare `portcullis-proxy` as `external: true`. No other
  networks.
- **Routers.** `rule: Host(\`<sub>.${PORTCULLIS_DOMAIN:-portcullis.local}\`)`
  (the Hub derives policies from this exact form), `entrypoints: websecure`,
  `tls.options` one of `authaware@file`, `public@file`, `protected@file`, and
  `security-headers@file` in the middlewares. Core subdomains (`auth`,
  `traefik`, `hub`, `directory`, `enroll`) are off limits.
- **Volumes** declare `name: portcullis_<volume>`, unique across templates.
- **Files** shipped with the template are mounted as
  `./templates/<app-id>/<file>` (never `./<file>`) and must exist in the
  directory. From core, only `./certs/ca-bundle.crt:<path>:ro` may be mounted;
  never `./scripts/` or anything else under `./certs/`.
- **Variables.** Core variables (`PORTCULLIS_DOMAIN`, `PORTCULLIS_PROXY_SUBNET`,
  `PORTCULLIS_PROXY_IP_RANGE`, `PORTCULLIS_TRAEFIK_IP`) always use their
  default form, e.g. `${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}`. Every other
  variable must be declared in the manifest (`env`, `settings` or `ports`).
  Required ones (`${VAR:?...}`) must be `env` entries with `generate: random`,
  because that is all the Hub writes. Use `$$VAR` for variables the container
  shell should expand.
- **No** `ports:`, `build:`, `container_name:` or `env_file:`.

## Security rules

- **Identity headers only from Traefik.** A header-auth app must accept
  `X-Forwarded-User` (and similar) only from `${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}`,
  Traefik's static IP on `portcullis-proxy`. Use the app's proxy allowlist
  (Grafana `GF_AUTH_PROXY_WHITELIST`, Kanboard `TRUSTED_PROXY_NETWORKS`). If the
  app has no allowlist, reject the header from other peers in its own web
  server (Firefly III, Guacamole) or keep the app off `portcullis-proxy` behind
  a small gate (CloudBeaver). Never trust `**`, `0.0.0.0/0`, `::/0` or the
  proxy subnet: every other app container shares that network.
- **Identity is the LLDAP username, never the email.** LLDAP lets every user
  change their own email, so Keycloak marks it unverified and an email-keyed
  account could be taken over. Forward-auth passes `X-Forwarded-User` (the
  immutable LLDAP username) and `X-Forwarded-Email` (display and
  notifications only). Header-auth apps key accounts on `X-Forwarded-User`;
  OIDC apps key on `sub` or `preferred_username` and must not link or create
  accounts by email match (look for settings like "match/link by email",
  "auto link user"; if the app cannot turn it off, see `immich/`). A gate that
  rejects a foreign `X-Forwarded-User` must reject `X-Forwarded-Email` too.
  `tests/validate.py` flags known email-linking settings. An OIDC app that
  refuses `email_verified=false` but accepts the claim being absent sets
  `email_verified_claim: false` on its `keycloak_clients` entry (the client
  then gets the `email-unverified` scope instead of `email`) and must stop
  requesting the `email` scope, or Keycloak answers `invalid_scope`
  (see `vaultwarden/`).
- **No published HTTP ports.** HTTP(S) goes through Traefik only. Non-HTTP
  host ports (DNS, TURN, ...) are declared under `ports:` in the manifest; the
  Hub detects collisions and writes the bindings.
- **Secrets via `generate: random`.** Passwords, OIDC client secrets, app keys:
  declare them under `env:` with `generate: random` (the Hub generates 32 hex
  characters). Never hard-code a secret or ship a default password; replace
  well-known upstream defaults on first boot (see `guacamole/`).
- **Least privilege.** Internal services stay off `portcullis-proxy`;
  `privileged`, host networking and host paths only when the app cannot work
  otherwise, explained in `auth.notes`.

## Images

Every image is pinned to an explicit release **and** its multi-arch index
digest:

```yaml
image: grafana/grafana:13.3.0@sha256:488984b716c0862639f91a698adbe2862677a5a07bad42da5f03f3030883b205
```

Get the digest with `docker buildx imagetools inspect grafana/grafana:13.3.0`
(the top-level `Digest:`). Floating tags (`latest`, `stable`, `release`,
`main`, `16-alpine`, `2`, ...) are rejected. Dependabot proposes updates weekly
and keeps tag and digest in sync.

Upgrade constraints:

- Do not bump database majors (PostgreSQL, MySQL, Redis); that needs a data
  migration.
- Apps with several images (NetBird management + signal, Immich server + ML,
  Guacamole + guacd) move in lockstep; Dependabot groups them.
- Apps with upstream upgrade paths (GitLab, Nextcloud, Guacamole,
  Headscale/Headplane, NetBird, Immich) say so in `auth.notes`; bump them one
  supported step at a time.

## After your PR is merged

The docs site regenerates the app pages from the manifests automatically
(`docs-dispatch.yml`).
