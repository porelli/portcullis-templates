#!/usr/bin/env bash
# Test: AI Chat (LibreChat, the AI page): librechat.yaml rendered from the
# Hub's ai-providers.json (secrets only as ${VAR} references, fail closed),
# native OIDC restricted to the access group, the MCP OAuth callback.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="ai-chat"
section "AI Chat"

APP_ID=ai-chat
COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
DIR="$(dirname "$COMPOSE")"
MANIFEST="$DIR/manifest.yaml"
FIXTURE="$(pwd)/tests/apps/fixtures/ai-providers.json"
IMAGE=$(yq -r '.services.api.image' "$COMPOSE")
WELCOME="No model provider configured; ask your administrator"
REFUSED_WELCOME="The AI page's model configuration was refused; ask your administrator"
WORK=$(mktemp -d)
chmod 0755 "$WORK"
# A marker stands in for every secret: it must never reach a rendered file
# or a log.
MARKER="portcullis-t28-marker-$(openssl rand -hex 8)"

# ── Static ────────────────────────────────────────────────────────────
assert_compose_setting "$COMPOSE" ALLOW_EMAIL_LOGIN false
assert_compose_setting "$COMPOSE" ALLOW_REGISTRATION false
assert_compose_setting "$COMPOSE" ALLOW_PASSWORD_RESET false
assert_compose_setting "$COMPOSE" OPENID_USERNAME_CLAIM preferred_username
assert_compose_setting "$COMPOSE" OPENID_REQUIRED_ROLE '\$\{PORTCULLIS_ACCESS_GROUP:-users_ai-chat\}'
assert_compose_setting "$COMPOSE" OPENID_REQUIRED_ROLE_PARAMETER_PATH groups
assert_compose_setting "$COMPOSE" CONFIG_PATH /portcullis/librechat/librechat.yaml
if grep -q 'PORTCULLIS_AI_PROVIDER_' "$COMPOSE"; then
  fail "compose.yml names a provider variable (only the Hub's override does)"
else
  pass "compose.yml names no provider variable"
fi
if [ "$(yq -r '.services.config.image' "$COMPOSE")" = "$IMAGE" ]; then
  pass "config runs the api image ($IMAGE)"
else
  fail "config and api run different images"
fi
if [ "$(yq -r '.services.api.depends_on.config.condition' "$COMPOSE")" = service_completed_successfully ]; then
  pass "api waits for config (service_completed_successfully)"
else
  fail "api must depend on config: service_completed_successfully"
fi
if yq -r '.services.api.volumes[]' "$COMPOSE" | grep -qx 'librechat-config:/portcullis/librechat:ro'; then
  pass "api mounts the rendered configuration read-only"
else
  fail "api must mount librechat-config read-only"
fi
# The renderer's kind table is the manifest's provider_kinds.
want=$(yq -o=json -I=0 '.ai.chat.provider_kinds | to_entries | map(.key + "=" + .value) | sort' "$MANIFEST")
got=$(docker run --rm --entrypoint node -w /app -v "$DIR/portcullis/render-config.mjs:/r.mjs:ro" "$IMAGE" \
  --input-type=module -e "const {KINDS} = await import('/r.mjs'); console.log(JSON.stringify(Object.entries(KINDS).map(([k, v]) => k + '=' + (v.many ? 'many' : 'one')).sort()))")
if [ "$want" = "$got" ]; then
  pass "render-config.mjs renders exactly the manifest's provider kinds ($got)"
else
  fail "provider kinds differ: manifest $want, render-config.mjs $got"
fi

# ── Rendering (no stack) ──────────────────────────────────────────────
# render <providers.json> <out dir>: run the config service's command in
# the LibreChat image (root without capabilities, the data file group
# 10001, read-only root) with every secret variable set to the marker.
render() {
  local in="$1" out="$2"
  mkdir -p "$out"; chmod 0777 "$out"; rm -f "$out/librechat.yaml"
  local envs=(-e PORTCULLIS_DOMAIN="$DOMAIN" -e PORTCULLIS_INSTANCE="${RENDER_INSTANCE:-ai-chat}" -e AI_CHAT_MCP_SECRET="$MARKER")
  for v in $(jq -r '[.providers[]?.env[]?] | unique | .[]' "$in" 2>/dev/null || true); do
    envs+=(-e "$v=$MARKER")
  done
  docker run --rm --user 0:0 --group-add 10001 --cap-drop ALL --read-only --tmpfs /tmp --network none -w /app \
    "${envs[@]}" \
    -v "$in:/portcullis/ai-providers/ai-providers.json:ro" \
    -v "$DIR/portcullis/render-config.mjs:/portcullis/render-config.mjs:ro" \
    -v "$DIR/portcullis/librechat.base.yaml:/portcullis/librechat.base.yaml:ro" \
    -v "$out:/portcullis/librechat" \
    --entrypoint node "$IMAGE" /portcullis/render-config.mjs \
    /portcullis/ai-providers/ai-providers.json /portcullis/librechat.base.yaml /portcullis/librechat/librechat.yaml
}

info "Pulling $IMAGE..."
docker pull -q "$IMAGE" >/dev/null

cp "$FIXTURE" "$WORK/full.json"; chmod 0644 "$WORK/full.json"
if render "$WORK/full.json" "$WORK/full" > "$WORK/full.log" 2>&1; then
  pass "fixture (one provider of every kind) rendered"
else
  fail "fixture not rendered: $(tail -3 "$WORK/full.log")"
fi
Y="$WORK/full/librechat.yaml"
if yq -e '.version' "$Y" >/dev/null 2>&1; then
  pass "librechat.yaml parses"
else
  fail "librechat.yaml does not parse"
fi
if grep -rq "$MARKER" "$WORK/full" "$WORK/full.log"; then
  fail "a secret value reached librechat.yaml or the log"
else
  pass "no secret value in librechat.yaml or the log"
fi
# Every secret-bearing value is a ${VAR} reference (or user_provided /
# the keyless placeholder), and each provider reference is its own.
bad=$(yq -r '(.endpoints.custom[]?.apiKey), (.endpoints.azureOpenAI.groups[]?.apiKey), .mcpServers.portcullis.oauth.client_secret' "$Y" \
  | grep -vE '^(\$\{PORTCULLIS_AI_PROVIDER_[A-Z0-9_]+\}|\$\{AI_CHAT_MCP_SECRET\}|user_provided|none)$' || true)
if [ -z "$bad" ]; then
  pass "secrets only as \${VAR} references"
else
  fail "secret values that are not references: $bad"
fi
# Whole file: the only ${...} references are the MCP server's and the
# providers' own variables, and no {{...}} placeholder at all.
refs=$(grep -o '\${[^}]*}' "$Y" | sort -u | grep -vxE '\$\{(PORTCULLIS_DOMAIN|PORTCULLIS_OIDC_CLIENT_ID_AI_CHAT_MCP|AI_CHAT_MCP_SECRET|PORTCULLIS_AI_PROVIDER_[A-Z0-9_]+)\}' || true)
if [ -z "$refs" ] && ! grep -q '{{' "$Y"; then
  pass "whole file: only the allowed \${VAR} references, no {{...}}"
else
  fail "whole file: unexpected references: $refs $(grep -o '{{[^}]*}}' "$Y" | sort -u | tr '\n' ' ')"
fi
want_refs=$(jq -r '[.providers[] | select(.credentials == "admin") | .env.key // empty] | sort | .[]' "$FIXTURE")
got_refs=$(yq -r '(.endpoints.custom[]?.apiKey), (.endpoints.azureOpenAI.groups[]?.apiKey)' "$Y" \
  | sed -n 's/^\${\(PORTCULLIS_AI_PROVIDER_[A-Z0-9_]*\)}$/\1/p' | sort)
if [ "$want_refs" = "$got_refs" ]; then
  pass "each admin key is its provider's variable ($(echo "$got_refs" | wc -l | tr -d ' '))"
else
  fail "key references: want [$want_refs] got [$got_refs]"
fi
n=$(yq -r '[.endpoints.custom[] | select(.baseURL == "http://gpu.lan:11434/v1" or .baseURL == "https://vllm.lab.example/v1")] | length' "$Y")
labels=$(yq -r '[.endpoints.custom[].name] | join("|")' "$Y")
if [ "$n" = 2 ] && echo "$labels" | grep -q 'Ollama on the office GPU' && echo "$labels" | grep -q 'vLLM in the lab'; then
  pass "two openai_compatible providers -> two custom endpoints with their labels"
else
  fail "openai_compatible endpoints: $n ($labels)"
fi
if [ "$(yq -r '.endpoints.custom[] | select(.name == "Anthropic API (US)") | .provider' "$Y")" = anthropic ]; then
  pass "anthropic -> custom endpoint with LibreChat's native Anthropic client"
else
  fail "anthropic endpoint missing or not provider: anthropic"
fi
if [ "$(yq -r '.endpoints.custom[] | select(.name == "Google Gemini") | .apiKey' "$Y")" = user_provided ]; then
  pass "per_person -> user_provided"
else
  fail "per_person provider is not user_provided"
fi
if [ "$(yq -r '.endpoints.azureOpenAI.groups[0].models["gpt-4o"].deploymentName' "$Y")" = gpt4o-prod ]; then
  pass "azure_openai -> endpoints.azureOpenAI.groups[] with its deployment"
else
  fail "azure group not rendered"
fi
if [ "$(yq -r '.endpoints.custom[] | select(.name == "OpenAI (gpt)") | .baseURL' "$Y")" = https://api.openai.com/v1 ]; then
  pass "a label equal to a built-in endpoint gets the provider name ('OpenAI (gpt)')"
else
  fail "label OpenAI not disambiguated: $labels"
fi
mcp=$(yq -o=json -I=0 '.mcpServers' "$Y")
if [ "$(yq -r '.mcpServers | keys | join(",")' "$Y")" = portcullis ] \
  && [ "$(yq -r '.mcpServers.portcullis.url' "$Y")" = 'https://mcp.${PORTCULLIS_DOMAIN}/mcp' ] \
  && [ "$(yq -r '.mcpServers.portcullis.type' "$Y")" = streamable-http ] \
  && [ "$(yq -r '.mcpServers.portcullis.oauth.scope' "$Y")" = 'mcp:all' ] \
  && [ "$(yq -r '.mcpServers.portcullis.oauth.client_id' "$Y")" = '${PORTCULLIS_OIDC_CLIENT_ID_AI_CHAT_MCP}' ] \
  && [ "$(yq -r '.mcpServers.portcullis.oauth.client_secret' "$Y")" = '${AI_CHAT_MCP_SECRET}' ]; then
  pass "one MCP server: portcullis (all my apps, mcp:all, the ai-chat-mcp client)"
else
  fail "MCP server: $mcp"
fi
if [ "$(yq -r '.interface.customWelcome // ""' "$Y")" = "" ]; then
  pass "no welcome text while a provider is configured"
else
  fail "welcome text with providers"
fi

echo '{"version":1,"instance":"ai-chat","providers":[]}' > "$WORK/empty.json"; chmod 0644 "$WORK/empty.json"
if render "$WORK/empty.json" "$WORK/empty" > "$WORK/empty.log" 2>&1 \
  && [ "$(yq -r '.interface.customWelcome' "$WORK/empty/librechat.yaml")" = "$WELCOME" ] \
  && [ "$(yq -r '.endpoints | keys | join(",")' "$WORK/empty/librechat.yaml")" = agents ]; then
  pass "no provider -> the welcome text, no model endpoint"
else
  fail "empty provider list: $(tail -3 "$WORK/empty.log")"
fi

# The locks, whatever the providers: no person-chosen URL is ever fetched
# by the server (api is on portcullis-proxy and its project network).
assert_locks() {
  local y="$1" what="$2" caps
  caps=$(yq -r '.endpoints.agents.capabilities | sort | join(",")' "$y")
  if [ "$caps" = "artifacts,ask_user_question,chain,context,deferred_tools,memory,skills,subagents,tools" ]; then
    pass "$what: agent capabilities without actions, web_search, execute_code, file_search, ocr"
  else
    fail "$what: agent capabilities: $caps"
  fi
  if [ "$(yq -r '.actions.allowedDomains | join(",")' "$y")" = actions.invalid ]; then
    pass "$what: actions closed (allowedDomains: actions.invalid)"
  else
    fail "$what: actions: $(yq -o=json -I=0 '.actions' "$y")"
  fi
  if [ "$(yq -r '.includedTools | join(",")' "$y")" = calculator ] && [ "$(yq -r '.filteredTools // "none"' "$y")" = none ]; then
    pass "$what: built-in tools: calculator only"
  else
    fail "$what: tools: $(yq -o=json -I=0 '{"i": .includedTools, "f": .filteredTools}' "$y")"
  fi
  if [ "$(yq -r '.interface.autoSubmitFromUrl' "$y")" = false ] \
    && [ "$(yq -o=json -I=0 '.interface.sharedLinks' "$y")" = '{"create":false,"share":false,"public":false}' ]; then
    pass "$what: no prompt submitted from a URL; shared links off (create, share, public)"
  else
    fail "$what: autoSubmitFromUrl / sharedLinks: $(yq -o=json -I=0 '{"a": .interface.autoSubmitFromUrl, "s": .interface.sharedLinks}' "$y")"
  fi
  if [ "$(yq -r '.interface.webSearch' "$y")" = false ] \
    && [ "$(yq -o=json -I=0 '.interface.mcpServers' "$y")" = '{"use":true,"create":false,"share":false,"public":false}' ] \
    && [ "$(yq -r '.mcpSettings.allowedDomains | join(",")' "$y")" = "mcp.$DOMAIN,auth.$DOMAIN" ] \
    && [ "$(yq -r '.mcpServers | keys | join(",")' "$y")" = portcullis ]; then
    pass "$what: web search off; no MCP server but portcullis, none added; MCP reaches mcp/auth only"
  else
    fail "$what: interface / MCP locks: $(yq -o=json -I=0 '{"i": .interface, "m": .mcpSettings}' "$y")"
  fi
}
assert_locks "$WORK/full/librechat.yaml" "with providers"
assert_locks "$WORK/empty/librechat.yaml" "no provider"

# Fail closed: each malformed file exits non-zero and leaves no file.
refused() {
  local label="$1" jqexpr="$2" want="$3"
  jq "$jqexpr" "$FIXTURE" > "$WORK/bad.json"; chmod 0644 "$WORK/bad.json"
  mkdir -p "$WORK/bad"; chmod 0777 "$WORK/bad"; rm -f "$WORK/bad/librechat.yaml"; echo stale > "$WORK/bad/librechat.yaml"
  if render "$WORK/bad.json" "$WORK/bad" > "$WORK/bad.log" 2>&1; then
    fail "$label: rendered (must be refused)"
  elif ! grep -q -- "$want" "$WORK/bad.log"; then
    fail "$label: refused without '$want': $(tail -2 "$WORK/bad.log")"
  elif ! is_fallback "$WORK/bad/librechat.yaml"; then
    fail "$label: refused, but librechat.yaml is not the locked fallback: $(head -c 300 "$WORK/bad/librechat.yaml" 2>/dev/null)"
  else
    pass "$label: refused (exit 1), only the locked provider-less fallback written"
  fi
}
# is_fallback <yaml>: what the renderer writes after a refusal: no model
# endpoint, the refusal's welcome text, every lock, no provider reference.
is_fallback() {
  [ -s "$1" ] \
    && [ "$(yq -r '.endpoints | keys | join(",")' "$1")" = agents ] \
    && [ "$(yq -r '.interface.customWelcome' "$1")" = "$REFUSED_WELCOME" ] \
    && ! grep -q 'PORTCULLIS_AI_PROVIDER_' "$1" \
    && [ "$(assert_locks "$1" fallback | grep -c FAIL)" = 0 ]
}
refused "unknown top-level field" '. + {extra: 1}' "unknown field"
refused "version 2" '.version = 2' "version 2"
refused "unknown entry field" '.providers[0].secret = "x"' "unknown field"
refused "missing entry field" 'del(.providers[1].models)' "missing field"
refused "foreign variable name" '.providers[1].env.key = "AI_CHAT_MCP_SECRET"' "must be PORTCULLIS_AI_PROVIDER_CLAUDE_KEY"
refused "bedrock (not rendered)" '.providers[1].kind = "bedrock"' "not one this template renders"
refused "two anthropic providers" '.providers[3].kind = "anthropic" | .providers[3].models.fetch = false' "at most one anthropic"
refused "placeholder in a base URL" '.providers[5].base_url = "http://gpu.lan/${AI_CHAT_MCP_SECRET}"' 'may not contain'
refused "per_person with a variable" '.providers[2].env = {key: "PORTCULLIS_AI_PROVIDER_GEMINI_KEY"}' "per_person"
refused "per_person Azure" '.providers[0].credentials = "per_person" | .providers[0].env = {}' "Azure"
refused "unsorted providers" '.providers |= reverse' "sorted by name"
refused "not an object" '"x"' "must be an object"
refused "\${ in a label" '.providers[5].label = "Ollama ${AI_CHAT_MCP_SECRET}"' 'may not contain'
refused "{{ in a label" '.providers[5].label = "Ollama {{LIBRECHAT_USER_EMAIL}}"' 'may not contain'
refused "\${ in a model name" '.providers[5].models.list[0] = "llama-${AI_CHAT_MCP_SECRET}"' 'may not contain'
refused "{{ in a model name" '.providers[5].models.list[0] = "llama-{{LIBRECHAT_USER_ID}}"' 'may not contain'
refused "{{ in an Azure model name" '.providers[0].deployments["gpt4o-prod"] = "gpt-{{LIBRECHAT_USER_ID}}"' 'may not contain'
RENDER_INSTANCE=ai-research refused "another instance's file" '.' "is for instance ai-chat, not ai-research"
rm -f "$WORK/missing.json"
mkdir -p "$WORK/miss"; chmod 0777 "$WORK/miss"; rm -f "$WORK/miss/librechat.yaml"; echo stale > "$WORK/miss/librechat.yaml"
if ! render "$WORK/missing.json" "$WORK/miss" > "$WORK/miss.log" 2>&1 && is_fallback "$WORK/miss/librechat.yaml"; then
  pass "missing ai-providers.json: refused, only the locked fallback written"
else
  fail "missing ai-providers.json not refused: $(tail -2 "$WORK/miss.log")"
fi
# A provider whose key isn't set yet is left out, the rest render.
jq 'del(.providers[1].env.key)' "$FIXTURE" > "$WORK/nokey.json"; chmod 0644 "$WORK/nokey.json"
if render "$WORK/nokey.json" "$WORK/nokey" > "$WORK/nokey.log" 2>&1 \
  && ! grep -q 'Anthropic' <<< "$(yq -r '.endpoints.custom[].name' "$WORK/nokey/librechat.yaml")" \
  && grep -q 'claude: left out until the administrator sets its key' "$WORK/nokey.log"; then
  pass "a provider without its key yet is left out (logged)"
else
  fail "provider without key: $(tail -2 "$WORK/nokey.log")"
fi

# ── Stack ─────────────────────────────────────────────────────────────
# The Hub's delivery: the fixture, and the providers' variables on api.
for v in $(jq -r '[.providers[].env[]] | unique | .[]' "$FIXTURE"); do export "$v=$MARKER"; done
export AI_CHAT_MCP_SECRET="${AI_CHAT_MCP_SECRET:-$(openssl rand -hex 16)}"
COMPOSE_OVERRIDE="$WORK/override.yml"
export COMPOSE_OVERRIDE
write_ai_providers_override "$APP_ID" "$(cat "$FIXTURE")" "$COMPOSE_OVERRIDE"
if ! compose_up "$APP_ID"; then
  fail "the stack did not start"
  for s in config mongodb meilisearch api; do docker logs --tail 15 "portcullis-$s-1" 2>&1 | sed "s/^/  $s: /"; done
  exit 1
fi
HOST="$PORTCULLIS_HOST_AI"

info "Waiting for config..."
if RC=$(timeout 300 docker wait portcullis-config-1 2>/dev/null) && [ "$RC" = 0 ]; then
  pass "config exited 0"
else
  fail "config did not finish successfully (rc=${RC:-none}): $(docker logs portcullis-config-1 2>&1 | tail -3)"
fi
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' portcullis-api-1 2>/dev/null)" = healthy ] && break
  sleep 5
done
if [ "$(docker inspect -f '{{.State.Health.Status}}' portcullis-api-1 2>/dev/null)" = healthy ]; then
  pass "api healthy"
else
  fail "api not healthy: $(docker logs portcullis-api-1 2>&1 | tail -20)"
fi
IP=$(app_container_ip "$APP_ID" api)

if docker exec portcullis-api-1 sh -c 'test "$PORTCULLIS_AI_PROVIDER_CLAUDE_KEY" = "$1"' _ "$MARKER"; then
  pass "the Hub's override puts the provider variables on api"
else
  fail "api lacks the provider variables"
fi
config_env=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' portcullis-config-1)
if [ -n "$config_env" ] && ! grep -q PORTCULLIS_AI_PROVIDER_ <<< "$config_env"; then
  pass "config never receives a provider variable"
else
  fail "config has provider variables"
fi
if docker exec portcullis-api-1 grep -q 'Anthropic API (US)' /portcullis/librechat/librechat.yaml \
  && ! docker exec portcullis-api-1 grep -q "$MARKER" /portcullis/librechat/librechat.yaml; then
  pass "api reads the rendered librechat.yaml (no secret value in it)"
else
  fail "api's librechat.yaml: missing or holds a secret"
fi
docker exec portcullis-api-1 cat /portcullis/librechat/librechat.yaml > "$WORK/live.yaml" 2>/dev/null || true
assert_locks "$WORK/live.yaml" "api's librechat.yaml"
if docker exec portcullis-api-1 sh -c 'touch /portcullis/librechat/x' 2>/dev/null; then
  fail "api can write its configuration"
else
  pass "api's configuration is read-only"
fi
docker logs portcullis-api-1 > "$WORK/api.log" 2>&1 || true
docker logs portcullis-config-1 > "$WORK/config.log" 2>&1 || true
if [ ! -s "$WORK/config.log" ] || grep -q "$MARKER" "$WORK/api.log" "$WORK/config.log"; then
  fail "a secret value is in the logs"
else
  pass "no secret value in the api / config logs"
fi

CFG=$(curl -sf "http://$IP:3080/api/config" 2>/dev/null || echo '{}')
if [ "$(echo "$CFG" | jq -r '.openidLoginEnabled')" = true ] && [ "$(echo "$CFG" | jq -r '.emailLoginEnabled')" = false ] \
  && [ "$(echo "$CFG" | jq -r '.registrationEnabled')" = false ] && [ "$(echo "$CFG" | jq -r '.openidAutoRedirect')" = true ]; then
  pass "/api/config: OpenID only (no email login, no registration), auto-redirect"
else
  fail "/api/config: $(echo "$CFG" | jq -c '{openidLoginEnabled, emailLoginEnabled, registrationEnabled, openidAutoRedirect}' 2>/dev/null)"
fi
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{"email":"e2e@example.com","password":"Password123!"}' "http://$IP:3080/api/auth/login" || echo 000)
if [ "$CODE" = 403 ]; then
  pass "POST /api/auth/login (password) -> 403"
else
  fail "POST /api/auth/login (password) -> $CODE (expected 403)"
fi
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{"name":"x","username":"x","email":"x@example.com","password":"Password123!","confirm_password":"Password123!"}' \
  "http://$IP:3080/api/auth/register" || echo 000)
if [ "$CODE" = 403 ] || [ "$CODE" = 404 ]; then
  pass "POST /api/auth/register -> $CODE"
else
  fail "registration answered $CODE"
fi

# The MCP OAuth callback LibreChat sends Keycloak back to.
LOC=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "http://$IP:3080/api/mcp/portcullis/oauth/callback" || echo 000)
if [ "${LOC%% *}" = 302 ] && echo "$LOC" | grep -q '/oauth/error?error=missing_code'; then
  pass "/api/mcp/portcullis/oauth/callback exists (no code -> $LOC)"
else
  fail "/api/mcp/portcullis/oauth/callback: $LOC"
fi
out=$(via_traefik "$HOST" /api/mcp/portcullis/oauth/callback)
if [ "${out%% *}" = 302 ]; then
  pass "callback reachable on https://$HOST via Traefik"
else
  fail "callback via Traefik: $out"
fi
out=$(via_traefik "$HOST" /oauth/openid)
if echo "${out#* }" | grep -q "//auth\.$DOMAIN/realms/portcullis/"; then
  pass "/oauth/openid redirects to Keycloak"
else
  fail "/oauth/openid: $out"
fi
# Keycloak and the gate resolve to Traefik inside api (no hairpin).
for h in "auth.$DOMAIN" "mcp.$DOMAIN"; do
  got=$(docker exec portcullis-api-1 getent hosts "$h" | awk '{print $1}' | head -1)
  if [ "$got" = "${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}" ]; then
    pass "api resolves $h to Traefik ($got)"
  else
    fail "api resolves $h to '$got'"
  fi
done
# From LibreChat's own runtime (node, NODE_EXTRA_CA_CERTS = the CA bundle).
reach() {
  docker exec portcullis-api-1 node -e \
    'fetch(process.argv[1]).then((r) => console.log(r.status)).catch((e) => console.log("error " + ((e.cause && e.cause.code) || e.message)))' \
    "$1" 2>&1 | tail -1 || true
}
code=$(reach "https://auth.$DOMAIN/realms/portcullis/.well-known/openid-configuration")
if [ "$code" = 200 ]; then
  pass "api reaches Keycloak over TLS (CA bundle)"
else
  fail "api -> auth.$DOMAIN: ${code:-no answer}"
fi
# The gate answers on mcp.<domain> (a 401/503 without a token is the gate's
# answer; only a network or TLS error fails).
code=$(reach "https://mcp.$DOMAIN/mcp")
# core's gate answers 401 (no token) or 503 (AI support off, this test's core).
case "$code" in
  401|503) pass "api reaches the MCP gate at https://mcp.$DOMAIN/mcp through Traefik over TLS (HTTP $code)" ;;
  *) fail "api -> https://mcp.$DOMAIN/mcp: ${code:-no answer} (expected the gate's 401 or 503)" ;;
esac

# Without its configuration file, api refuses to start (LibreChat would run
# on its defaults: no locks, no MCP server).
docker run --rm --user 0:0 --network none -v portcullis_librechat-config:/c --entrypoint rm "$IMAGE" -f /c/librechat.yaml
docker restart portcullis-api-1 >/dev/null 2>&1 || true
healthy=no
for _ in $(seq 1 12); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' portcullis-api-1 2>/dev/null)" = healthy ] && healthy=yes
  sleep 5
done
docker logs portcullis-api-1 > "$WORK/api-noconf.log" 2>&1 || true
if [ "$healthy" = no ] && grep -q 'missing or empty: not starting LibreChat' "$WORK/api-noconf.log"; then
  pass "no librechat.yaml: api refuses to start (never healthy in 60 s)"
else
  fail "no librechat.yaml: api healthy=$healthy, $(docker logs --tail 3 portcullis-api-1 2>&1)"
fi

# Fail closed at start: a malformed file stops api from starting.
compose_down "$APP_ID"
write_appfile "$APP_ID" ai-providers '{"version":1,"instance":"ai-chat","providers":[],"x":1}'
compose_up "$APP_ID" || true
RC=$(timeout 300 docker wait portcullis-config-1 2>/dev/null || echo none)
sleep 5
if [ "$RC" != 0 ] && [ "$(docker inspect -f '{{.State.Running}}' portcullis-api-1 2>/dev/null || echo false)" != true ]; then
  pass "malformed ai-providers.json: config exits $RC, api not started"
  docker run --rm --user 0:0 --network none -v portcullis_librechat-config:/c:ro --entrypoint cat "$IMAGE" /c/librechat.yaml > "$WORK/fb.yaml" 2>/dev/null || true
  if is_fallback "$WORK/fb.yaml"; then
    pass "malformed ai-providers.json: the volume holds the locked, provider-less fallback"
  else
    fail "malformed ai-providers.json: the volume's librechat.yaml is not the fallback"
  fi
else
  fail "malformed ai-providers.json: config rc=$RC, api running=$(docker inspect -f '{{.State.Running}}' portcullis-api-1 2>/dev/null)"
fi

# A provider change re-delivers the file and restarts: the new start
# re-renders (here: no provider any more -> the welcome text).
compose_down "$APP_ID"
write_appfile "$APP_ID" ai-providers '{"version":1,"instance":"ai-chat","providers":[]}'
compose_up "$APP_ID"
RC=$(timeout 300 docker wait portcullis-config-1 2>/dev/null || echo none)
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' portcullis-api-1 2>/dev/null)" = healthy ] && break
  sleep 5
done
if [ "$RC" = 0 ] && docker exec portcullis-api-1 grep -q "$WELCOME" /portcullis/librechat/librechat.yaml \
  && ! docker exec portcullis-api-1 grep -q 'Anthropic API (US)' /portcullis/librechat/librechat.yaml; then
  pass "restart re-renders: no provider -> the welcome text"
else
  fail "re-render after a provider change (config rc=$RC)"
fi
compose_down "$APP_ID"
