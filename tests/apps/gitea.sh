#!/usr/bin/env bash
# Test: Gitea (native OIDC through an OAuth2 source written by gitea-auth)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="gitea"
section "Gitea"

APP_ID=gitea

COMPOSE=$(_find_compose "$APP_ID" || true)
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
AUTH_SH="$(dirname "$COMPOSE")/auth.sh"

# Static: native OIDC host-wide router without forward-auth (git over HTTPS
# and the API use personal access tokens).
if grep -qE 'routers\.gitea\.middlewares:.*portcullis-(auth|groups)@docker' "$COMPOSE"; then
  fail "forward-auth middleware on the host-wide Gitea router"
else
  pass "host-wide router has no forward-auth"
fi

# Static: no password, sign-up, passkey, OpenID or header login; nothing
# readable anonymously.
assert_compose_setting "$COMPOSE" GITEA__service__ENABLE_PASSWORD_SIGNIN_FORM false
assert_compose_setting "$COMPOSE" GITEA__service__ENABLE_BASIC_AUTHENTICATION false
assert_compose_setting "$COMPOSE" GITEA__service__ENABLE_PASSKEY_AUTHENTICATION false
assert_compose_setting "$COMPOSE" GITEA__service__DISABLE_REGISTRATION true
assert_compose_setting "$COMPOSE" GITEA__service__ALLOW_ONLY_EXTERNAL_REGISTRATION true
assert_compose_setting "$COMPOSE" GITEA__service__ENABLE_REVERSE_PROXY_AUTHENTICATION false
assert_compose_setting "$COMPOSE" GITEA__openid__ENABLE_OPENID_SIGNIN false
assert_compose_setting "$COMPOSE" GITEA__service__REQUIRE_SIGNIN_VIEW true
assert_compose_setting "$COMPOSE" GITEA__security__INSTALL_LOCK true

# Identity: username = preferred_username, never linked by name/email.
assert_compose_setting "$COMPOSE" GITEA__oauth2_client__USERNAME preferred_username
assert_compose_setting "$COMPOSE" GITEA__oauth2_client__ACCOUNT_LINKING disabled

# Group restriction and admin mapping from the instance's groups.
if grep -q "'RequiredClaimName', 'groups'" "$AUTH_SH" && grep -q "'RequiredClaimValue', :'access_group'" "$AUTH_SH" \
  && grep -q "'AdminGroup', :'admin_group'" "$AUTH_SH"; then
  pass "OAuth2 source requires the access group and maps the admin group"
else
  fail "auth.sh must set RequiredClaimName/Value (access group) and AdminGroup"
fi
if grep -q '^  group_access: true' "$MANIFEST" && grep -q '^  group_admin: true' "$MANIFEST"; then
  pass "manifest: group_access and group_admin true"
else
  fail "manifest must set group_access: true and group_admin: true"
fi

# Secret never on a command line.
if grep -hvE '^[[:space:]]*#' "$(dirname "$COMPOSE")/setup.sh" "$AUTH_SH" | grep -qE -- '--secret' \
  || ! grep -q '\\getenv oidc_secret GITEA_OIDC_SECRET' "$AUTH_SH"; then
  fail "the OIDC secret must reach Gitea through psql \\getenv, not the CLI"
else
  pass "OIDC secret read from the environment (psql \\getenv)"
fi


# ── AI support (contracts §3.2, §15.5): static ──────────────
HOOK_SH="$(dirname "$COMPOSE")/portcullis/mcp-token.sh"
MCP_IMAGE=$(sed -n 's/^    image: \(docker\.gitea\.com\/gitea-mcp-server:[^[:space:]]*\)$/\1/p' "$COMPOSE")
if [[ "$MCP_IMAGE" =~ ^docker\.gitea\.com/gitea-mcp-server:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]]; then
  pass "gitea-mcp pinned tag@digest ($MCP_IMAGE)"
else
  fail "gitea-mcp must be the official image pinned tag@sha256 (got '$MCP_IMAGE')"
fi
MCP_SVC=$(awk '/^  gitea-mcp:/{f=1; next} f && /^  [a-z]/{f=0} f' "$COMPOSE")
if grep -q 'GITEA_READONLY: \${PORTCULLIS_AI_READONLY_GITEA:-true}$' <<<"$MCP_SVC" \
  && ! grep -qE 'GITEA_ACCESS_TOKEN|"-T"|"--token"|"-token"|traefik\.|ports:|portcullis-proxy' <<<"$MCP_SVC"; then
  pass "gitea-mcp: read-only by default, no static token, no labels / ports / proxy network"
else
  fail "gitea-mcp: needs GITEA_READONLY from PORTCULLIS_AI_READONLY_GITEA and no static token, labels, ports or portcullis-proxy"
fi
if [ "$(grep -c '^    service: gitea$' <<<"$(awk '/^hooks:/{f=1; next} f && /^[a-z]/{f=0} f' "$MANIFEST")")" = 2 ] \
  && [ -x "$HOOK_SH" ] && grep -q 'mcp-token.sh:/portcullis/mcp-token.sh:ro' "$COMPOSE"; then
  pass "mint/revoke hooks run in the gitea service (script mounted read-only)"
else
  fail "mcp-mint / mcp-revoke must run in the gitea service with mcp-token.sh mounted read-only and executable"
fi
# The hook token reaches curl on stdin only; no credential on any argv.
if grep -q -- 'curl --config - ' "$HOOK_SH" && ! grep -vE '^[[:space:]]*#' "$HOOK_SH" | grep -qE -- '(-H|--header|-u|--user)[ =]'; then
  pass "mcp-token.sh: curl reads credentials from stdin (--config -)"
else
  fail "mcp-token.sh must pass credentials to curl via --config - only"
fi

compose_up "$APP_ID"

# The setup chain must finish before Gitea starts (fail closed).
for job in gitea-migrate gitea-auth; do
  if RC=$(timeout 300 docker wait "portcullis-${job}-1" 2>/dev/null) && [ "$RC" = "0" ]; then
    pass "$job exited 0"
  else
    fail "$job did not finish successfully (rc=${RC:-none})"
    docker logs "portcullis-${job}-1" 2>&1 | tail -10 || true
  fi
done

# The secret never appears in the setup logs.
SECRET="${GITEA_OIDC_SECRET:-}"
if [ -n "$SECRET" ] && docker logs portcullis-gitea-auth-1 2>&1 | grep -qF "$SECRET"; then
  fail "gitea-auth logged the OIDC client secret"
else
  pass "gitea-auth does not log the OIDC client secret"
fi

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:3000/api/healthz" 180 "$APP_ID"

# The login page redirects straight to the Portcullis source.
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://${IP}:3000/user/login" || true)
if echo "$LOC" | grep -q '/user/oauth2/Portcullis'; then
  pass "/user/login -> Portcullis OAuth2 source"
else
  fail "/user/login should redirect to /user/oauth2/Portcullis (got '$LOC')"
fi

# The OAuth2 source start redirects to Keycloak with the instance's client.
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://${IP}:3000/user/oauth2/Portcullis" || true)
if echo "$LOC" | grep -q "auth.${DOMAIN}/realms/portcullis/" && echo "$LOC" | grep -q "client_id=${PORTCULLIS_OIDC_CLIENT_ID:-gitea}"; then
  pass "OAuth2 start -> auth.${DOMAIN} (client ${PORTCULLIS_OIDC_CLIENT_ID:-gitea})"
else
  info "OAuth2 start redirected to '$LOC' (Keycloak discovery may be unreachable from this runner)"
fi

# Password sign-in is refused even when posted directly.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -d 'user_name=portcullis-breakglass&password=x' "http://${IP}:3000/user/login" || echo 000)
if [ "$CODE" = "403" ]; then
  pass "POST /user/login -> 403 (no password sign-in)"
else
  fail "POST /user/login expected 403, got $CODE"
fi

# Sign-up refused; nothing readable anonymously.
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:3000/explore/repos" || echo 000)
if [ "$CODE" = "303" ] || [ "$CODE" = "302" ]; then
  pass "/explore/repos anonymous -> $CODE (sign-in required)"
else
  fail "/explore/repos anonymous expected a redirect to sign-in, got $CODE"
fi
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:3000/api/v1/repos/search" || echo 000)
if [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
  pass "/api/v1/repos/search anonymous -> $CODE"
else
  fail "/api/v1/repos/search anonymous expected 401/403, got $CODE"
fi

# Basic auth with a password is ignored (tokens only): the request is as
# anonymous as one without credentials (REQUIRE_SIGNIN_VIEW: 403). With
# basic auth on, a wrong password would be checked and answered 401.
ANON=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:3000/api/v1/user" || echo 000)
BODY=$(curl -s -w ' %{http_code}' -u 'portcullis-breakglass:x' "http://${IP}:3000/api/v1/user" || echo 000)
CODE=${BODY##* }
if { [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; } && [ "$CODE" = "$ANON" ]; then
  pass "basic auth with a password treated as anonymous ($CODE, same as no credentials)"
else
  fail "basic auth with a password: got $CODE (anonymous: $ANON): ${BODY:0:200}"
fi


# ── AI support: hooks and the gitea-mcp companion ───────────
G=portcullis-gitea-1
TMP=$(mktemp -d)
gitea_cli() { docker exec -u git "$G" gitea admin "$@"; }
hook() { docker exec -i -u git "$G" /portcullis/mcp-token.sh "$1"; }
rand12() { openssl rand -hex 6; }
mint_in() { # user mode scopes-json
  printf '{"action":"mint","user":"%s","instance":"gitea","companion":"gitea","name":"portcullis-ai-%s","mode":"%s","scopes":%s}' "$1" "$(rand12)" "$2" "$3"
}
RO_SCOPES='["read:repository","read:issue","read:user","read:organization","read:notification"]'
RW_SCOPES='["write:repository","write:issue","read:user","read:organization","write:notification"]'
# api_as TOKEN METHOD PATH [JSON]: the HTTP code; the body in $TMP/body.
# The token goes to curl on stdin, never on its argv.
api_as() {
  local data=()
  if [ -n "${4:-}" ]; then printf '%s' "$4" > "$TMP/req"; data=(-H 'Content-Type: application/json' --data-binary "@$TMP/req"); fi
  printf 'header = "Authorization: token %s"\n' "$1" \
    | curl --config - -s -o "$TMP/body" -w '%{http_code}' -X "$2" ${data[@]+"${data[@]}"} "http://${IP}:3000/api/v1$3" || echo 000
}
db() { docker exec portcullis-gitea-db-1 psql -X -U gitea -d gitea -tAc "$1"; }

# Hook admin: an admin that may use tokens; the break-glass admin stays locked.
if [ "$(db "SELECT count(*) FROM \"user\" WHERE lower_name = 'portcullis-hooks' AND is_admin AND NOT prohibit_login AND is_active AND NOT must_change_password")" = 1 ] \
  && [ "$(db "SELECT count(*) FROM \"user\" WHERE lower_name = 'portcullis-breakglass' AND is_admin AND prohibit_login")" = 1 ]; then
  pass "hook admin portcullis-hooks ready; break-glass admin still sign-in prohibited"
else
  fail "gitea-migrate / gitea-auth must create portcullis-hooks (admin, active) and keep the break-glass admin locked"
fi

# Accounts as the Portcullis OAuth2 source would create them (no SSO in a
# shell test), each with a private repository.
for u in alice bob; do
  gitea_cli user create --username "$u" --email "$u@example.invalid" --random-password --must-change-password=false >/dev/null
  tok=$(gitea_cli user generate-access-token --username "$u" --token-name "$u-setup" --scopes write:repository,read:user --raw)
  printf '%s' "$tok" > "$TMP/$u-setup"
  CODE=$(api_as "$tok" POST /user/repos "{\"name\":\"$u-private\",\"private\":true}")
  [ "$CODE" = 201 ] || fail "creating $u's private repository: HTTP $CODE $(head -c 200 "$TMP/body")"
done

# mint: read-only credential as alice, only read scopes.
if OUT=$(mint_in alice read_only "$RO_SCOPES" | hook mint) && CRED=$(jq -er '.credential' <<<"$OUT") && RO_ID=$(jq -er '.id' <<<"$OUT") \
  && [ "$(jq -r 'keys | join(",")' <<<"$OUT")" = "credential,id" ]; then
  pass "mint (read_only) for alice -> {credential, id} (id $RO_ID)"
else
  fail "mint for alice failed"; CRED=x RO_ID=0
fi
CODE=$(api_as "$CRED" GET /user)
if [ "$CODE" = 200 ] && [ "$(jq -r .login "$TMP/body")" = alice ]; then
  pass "the credential authorizes as alice"
else
  fail "the minted credential: /api/v1/user -> $CODE $(head -c 200 "$TMP/body")"
fi
SCOPES=$(db "SELECT scope FROM access_token WHERE id = $RO_ID")
CODE=$(api_as "$CRED" POST /user/repos '{"name":"ai-write-attempt"}')
if [ "$CODE" = 403 ] && ! grep -q 'write:' <<<"$SCOPES"; then
  pass "read_only credential has read scopes only ($SCOPES); a write is refused (403)"
else
  fail "read_only credential: scopes '$SCOPES', write -> $CODE"
fi
set +e; mint_in nobody read_only "$RO_SCOPES" | hook mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" = 3 ] && pass "mint for a person without a Gitea account -> exit 3" || fail "mint for nobody: exit $RC, want 3"
set +e; mint_in alice read_only '["write:repository"]' | hook mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" != 0 ] && [ "$RC" != 3 ] && pass "mint with a write scope in read_only mode refused (exit $RC)" || fail "write scope in read_only: exit $RC"
set +e; printf '{"action":"mint","user":"alice"}' | hook mint >/dev/null 2>&1; RC=$?; set -e
[ "$RC" != 0 ] && [ "$RC" != 3 ] && pass "malformed mint input refused (exit $RC)" || fail "malformed mint input: exit $RC"

# The companion (started with the template: GITEA_READONLY defaults to true).
MCP_IP=$(app_container_ip "$APP_ID" gitea-mcp)
wait_for_url "http://${MCP_IP}:8080/healthz" 60 gitea-mcp
# mcp IP TOKEN BODY: the JSON-RPC answer (SSE or JSON); HTTP code in $TMP/mcpcode.
mcp() {
  printf '%s' "$3" > "$TMP/mcpreq"
  { [ -z "$2" ] || printf 'header = "Authorization: token %s"\n' "$2"; } \
    | curl --config - -s -o "$TMP/mcpout" -w '%{http_code}' -X POST "http://$1:8080/mcp" \
      -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
      -H 'MCP-Protocol-Version: 2025-11-25' --data-binary "@$TMP/mcpreq" > "$TMP/mcpcode" || echo 000 > "$TMP/mcpcode"
  if grep -q '^data: ' "$TMP/mcpout"; then sed -n 's/^data: //p' "$TMP/mcpout"; else cat "$TMP/mcpout"; fi
}
LIST='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
MYREPOS='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"repo_read","arguments":{"method":"list_my_repos"}}}'
R=$(mcp "$MCP_IP" "$CRED" "$MYREPOS")
TEXT=$(jq -r '[.result.content[]?.text] | join("\n")' <<<"$R" 2>/dev/null || true)
if grep -q 'alice-private' <<<"$TEXT" && ! grep -q 'bob-private' <<<"$TEXT"; then
  pass "gitea-mcp with alice's token lists alice's repositories only (bob's private one absent)"
else
  fail "gitea-mcp list_my_repos as alice: $(head -c 400 <<<"$R")"
fi
R=$(mcp "$MCP_IP" "" "$MYREPOS")
grep -q 'alice-private\|bob-private' <<<"$R" && fail "gitea-mcp without a token returned repositories" || pass "gitea-mcp without a token sees no repository"
mcp "$MCP_IP" 0000000000000000000000000000000000000000 "$MYREPOS" >/dev/null
[ "$(cat "$TMP/mcpcode")" = 401 ] && pass "gitea-mcp: a token Gitea rejects -> 401" || fail "gitea-mcp with a bad token: HTTP $(cat "$TMP/mcpcode")"

# Tool classes against the real tools: read-only (the template's default)
# and a read-write instance of the same image.
mcp "$MCP_IP" "$CRED" "$LIST" > "$TMP/tools-ro.json"
NET=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' portcullis-gitea-mcp-1 | tr ' ' '\n' | grep -m1 .)
docker run -d --rm --name portcullis-t-gitea-mcp-rw --network "$NET" --read-only --tmpfs /tmp \
  --security-opt no-new-privileges:true --cap-drop ALL -e GITEA_READONLY=false "$MCP_IMAGE" \
  /app/gitea-mcp -t http --port 8080 -H http://gitea-internal:3000 >/dev/null
RW_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' portcullis-t-gitea-mcp-rw)
wait_for_url "http://${RW_IP}:8080/healthz" 60 gitea-mcp-rw
mcp "$RW_IP" "$CRED" "$LIST" > "$TMP/tools-rw.json"
docker rm -f portcullis-t-gitea-mcp-rw >/dev/null 2>&1 || true
if python3 - "$MANIFEST" "$TMP/tools-ro.json" "$TMP/tools-rw.json" <<'PY'
import fnmatch, json, re, sys
manifest = open(sys.argv[1]).read()
pats = {k: json.loads(re.search(r"^\s+%s:\s*(\[.*\])\s*$" % k, manifest, re.M).group(1)) for k in ("writes", "confirm", "never")}
def tools(path):
    out = {}
    for t in json.load(open(path))["result"]["tools"]:
        enum = ((t.get("inputSchema") or {}).get("properties") or {}).get("method", {}).get("enum") or []
        out[t["name"].lower()] = {"methods": [m.lower() for m in enum], "ann": t.get("annotations") or {}}
    return out
ro, rw = tools(sys.argv[2]), tools(sys.argv[3])
def match(p, tool, method=None):
    pt, _, pm = p.lower().partition(":")
    if not fnmatch.fnmatchcase(tool, pt):
        return False
    return not pm or (method is not None and fnmatch.fnmatchcase(method, pm))
def hits(p):
    return any(match(p, t) if ":" not in p else any(match(p, t, m) for m in v["methods"]) for t, v in rw.items())
bad = []
print("  INFO %d tools (read-write), %d (read-only)" % (len(rw), len(ro)))
for t, v in sorted(rw.items()):
    print("  INFO   %s%s%s" % (t, " [destructiveHint]" if v["ann"].get("destructiveHint") else "", (" methods=" + ",".join(v["methods"])) if v["methods"] else ""))
for k in ("writes", "confirm", "never"):
    for p in pats[k]:
        if not hits(p):
            bad.append("%s pattern %r matches no real tool" % (k, p))
noc = lambda t: any(":" not in p and match(p, t) for p in pats["confirm"])
for t, v in rw.items():
    if "delete" in t and not noc(t):
        bad.append("tool %s is not in confirm" % t)
    for m in v["methods"]:
        if "delete" in m and not (noc(t) or any(match(p, t, m) for p in pats["confirm"])):
            bad.append("%s:%s is not in confirm" % (t, m))
w = lambda t: any(":" not in p and match(p, t) for p in pats["writes"])
hidden = set(rw) - set(ro)
if not hidden or not ro:
    bad.append("GITEA_READONLY=true hid nothing (or everything)")
for t in sorted(hidden):
    if not w(t):
        bad.append("write tool %s (hidden in read-only) is not in writes" % t)
for t in sorted(ro):
    if w(t):
        bad.append("read-only tool %s is matched by writes" % t)
    if not ro[t]["ann"].get("readOnlyHint"):
        bad.append("tool %s is listed in read-only mode without readOnlyHint" % t)
for b in bad:
    print("  FAIL " + b)
sys.exit(1 if bad else 0)
PY
then
  pass "tool classes match gitea-mcp's real tools (writes / confirm patterns, every delete confirmed, GITEA_READONLY hides exactly the writes)"
else
  fail "tool classes do not match gitea-mcp's tools (above)"
fi

# revoke: the token is refused afterwards.
if printf '{"action":"revoke","user":"alice","ids":["%s"]}' "$RO_ID" | hook revoke && [ "$(api_as "$CRED" GET /user)" = 401 ]; then
  pass "revoke -> alice's credential refused (401)"
else
  fail "revoke: the credential still works or the hook failed"
fi

# revoke_all: every portcullis-ai-* token of every person, nothing else.
OUT_A=$(mint_in alice read_write "$RW_SCOPES" | hook mint) && OUT_B=$(mint_in bob read_write "$RW_SCOPES" | hook mint) || fail "mint (read_write) failed"
set +e; printf '{"action":"revoke_all","prefix":"portcullis-"}' | hook revoke >/dev/null 2>&1; RC=$?; set -e
if [ "$RC" != 0 ] && [ "$(api_as "$(jq -r .credential <<<"$OUT_B")" GET /user)" = 200 ]; then
  pass "revoke_all with another prefix refused (exit $RC), nothing deleted"
else
  fail "revoke_all with prefix portcullis-: exit $RC"
fi
if printf '{"action":"revoke_all","prefix":"portcullis-ai-"}' | hook revoke; then
  pass "revoke_all exited 0"
else
  fail "revoke_all failed"
fi
LEFT=$(db "SELECT count(*) FROM access_token WHERE name LIKE 'portcullis-ai-%'")
HOOKLEFT=$(db "SELECT count(*) FROM access_token WHERE name LIKE 'portcullis-hook-%'")
CA=$(api_as "$(jq -r .credential <<<"$OUT_A")" GET /user); CB=$(api_as "$(jq -r .credential <<<"$OUT_B")" GET /user)
CS=$(api_as "$(cat "$TMP/bob-setup")" GET /user)
if [ "$LEFT" = 0 ] && [ "$CA" = 401 ] && [ "$CB" = 401 ] && [ "$CS" = 200 ]; then
  pass "revoke_all: no portcullis-ai-* token left (alice, bob refused); bob's own token kept"
else
  fail "revoke_all: $LEFT portcullis-ai-* tokens left, alice $CA, bob $CB, bob's own token $CS"
fi
[ "$HOOKLEFT" = 0 ] && pass "no hook-local admin token left after the runs" || fail "$HOOKLEFT hook-local admin token(s) left"
rm -rf "$TMP"

compose_down "$APP_ID"
