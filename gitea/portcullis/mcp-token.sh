#!/bin/bash
# mcp-token.sh: per-person Gitea access tokens for the gitea-mcp companion
# (Portcullis AI support, integration contracts §15.5). The hooks mcp-mint
# and mcp-revoke run it in the gitea service as git; it never sees tool
# traffic.
#
#   mint    stdin {"action":"mint","user","instance","companion","name","mode","scopes"}
#           -> stdout {"credential":"…","id":"…"}; exit 3: no Gitea account yet
#   revoke  stdin {"action":"revoke","user","ids":[…]}   (ids [] = all of the person's)
#           or    {"action":"revoke_all","prefix":"portcullis-ai-"}
#
# The person's token is minted with Gitea's own CLI (`gitea admin user
# generate-access-token`, straight into the database). Gitea's CLI can't
# list or delete tokens, so the token id lookup and every deletion go
# through Gitea's API on 127.0.0.1 as portcullis-hooks (an admin that can
# only ever use tokens, created by setup.sh) with a hook-local token this
# run mints and deletes again, from a trap if the run fails. That admin
# never runs a tool call: tools always run as the person.
#
# Input is parsed strictly against the §15.5 shapes (no JSON tool in the
# image): anything else is refused before Gitea is touched. No secret is
# ever on an argv: the hook token reaches curl on stdin (--config -), the
# person's token only travels through pipes and builtins.
set -euo pipefail
umask 077

readonly API=http://127.0.0.1:3000/api/v1
readonly PREFIX=portcullis-ai-
readonly HOOK_USER=portcullis-hooks
readonly HOOK_PREFIX=portcullis-hook-
readonly BREAKGLASS=portcullis-breakglass
readonly MAX_INPUT=65536
# Gitea usernames as the Portcullis OAuth2 source creates them (the
# lowercase LLDAP username, Gitea's 40-character limit).
readonly USER_RE='[a-z0-9][a-z0-9._-]{0,39}'
# Access token scopes a credential may get: never admin, never all.
readonly SCOPE_RE='(read|write):(activitypub|issue|misc|notification|organization|package|repository|user)'
readonly S='[[:space:]]*'

die() { echo "mcp-token: $*" >&2; exit 1; }

HOOK_NAME=""
HOOK_TOKEN=""

# api METHOD PATH: the answer body on stdout. Returns 0 on 2xx, 4 on 404,
# 1 otherwise. The hook token is sent as HTTP Basic (Gitea's token
# endpoints accept nothing else) through curl's config on stdin.
api() {
  local out code
  out=$(printf 'user = "%s:%s"\n' "$HOOK_USER" "$HOOK_TOKEN" \
    | curl --config - -sS --max-time 20 -X "$1" -w '\n%{http_code}' "$API$2") || return 1
  code=${out##*$'\n'}
  printf '%s' "${out%$'\n'*}"
  case $code in
    2??) return 0 ;;
    404) return 4 ;;
    *) echo "mcp-token: $1 $2: HTTP $code" >&2; return 1 ;;
  esac
}

# list_tokens USER NAME_PREFIX: "id name" of USER's tokens whose name
# starts with NAME_PREFIX. Fails on an answer it can't read in full.
list_tokens() {
  local page=1 body all pairs rc
  while :; do
    rc=0
    body=$(api GET "/users/$1/tokens?page=$page&limit=50") || rc=$?
    [ "$rc" = 0 ] || return "$rc"
    all=$(grep -oE '"id":[0-9]+' <<<"$body" | wc -l) || true
    pairs=$(grep -oE '"id":[0-9]+,"name":"[^"]*"' <<<"$body" | sed -E 's/^"id":([0-9]+),"name":"([^"]*)"$/\1 \2/') || true
    [ "$all" -eq "$(grep -c . <<<"$pairs" || true)" ] || { echo "mcp-token: unexpected token list answer for $1" >&2; return 1; }
    [ "$all" -gt 0 ] || return 0
    awk -v p="$2" 'index($2, p) == 1' <<<"$pairs"
    [ "$all" -ge 50 ] || return 0
    page=$((page + 1))
    [ "$page" -le 1000 ] || { echo "mcp-token: too many tokens for $1" >&2; return 1; }
  done
}

# delete_token USER ID: deleted or already gone.
delete_token() {
  local rc=0
  api DELETE "/users/$1/tokens/$2" >/dev/null || rc=$?
  [ "$rc" = 0 ] || [ "$rc" = 4 ]
}

# The hook-local admin token: minted for this run only (scope write:user:
# list and delete tokens), stale ones of earlier runs deleted with it.
hook_token_start() {
  local name rand stale id n
  rand=$(od -An -N6 -tx1 /dev/urandom) || die "no random bytes"
  rand=${rand//[[:space:]]/}
  name=$HOOK_PREFIX$rand
  [[ $name =~ ^${HOOK_PREFIX}[a-z0-9]{12}$ ]] || die "no random token name"
  HOOK_NAME=$name
  HOOK_TOKEN=$(gitea admin user generate-access-token --username "$HOOK_USER" \
    --token-name "$HOOK_NAME" --scopes write:user --raw) || die "minting the hook token failed (is $HOOK_USER missing? gitea-migrate creates it)"
  [[ $HOOK_TOKEN =~ ^[0-9a-f]{40}$ ]] || { HOOK_TOKEN=""; die "unexpected generate-access-token output"; }
  stale=$(list_tokens "$HOOK_USER" "$HOOK_PREFIX") || die "listing $HOOK_USER's tokens failed"
  while read -r id n; do
    [ -n "$id" ] && [ "$n" != "$HOOK_NAME" ] || continue
    delete_token "$HOOK_USER" "$id" || die "deleting the stale hook token $n failed"
  done <<<"$stale"
}

# hook_token_end: delete this run's token with itself.
hook_token_end() {
  [ -n "$HOOK_TOKEN" ] || return 0
  delete_token "$HOOK_USER" "$HOOK_NAME" || return 1
  HOOK_TOKEN=""
}

on_exit() {
  local rc=$?
  if [ -n "$HOOK_TOKEN" ]; then
    hook_token_end || { echo "mcp-token: deleting the hook token $HOOK_NAME failed (the next run deletes it)" >&2; [ "$rc" != 0 ] || rc=1; }
  fi
  exit "$rc"
}
trap on_exit EXIT

# account USER: "true"/"false" (IsActive) for an existing Gitea user, ""
# for none.
account() {
  local users
  users=$(gitea admin user list) || die "gitea admin user list failed"
  awk -v u="$1" 'NR > 1 && tolower($2) == u { print $4; exit }' <<<"$users"
}

reserved() { [ "$1" = "$BREAKGLASS" ] || [ "$1" = "$HOOK_USER" ]; }

# ── input ────────────────────────────────────────────────
[ "$#" = 1 ] || die "usage: mcp-token.sh mint|revoke < input"
input=$(head -c $((MAX_INPUT + 1)))
[ "${#input}" -le "$MAX_INPUT" ] || die "input too large"
# No string value may hold whitespace, so whitespace is normalised first.
input=${input//[$'\t\r\n']/ }

q() { printf '"%s"%s:%s' "$1" "$S" "$S"; }
re_mint="^${S}[{]${S}$(q action)\"mint\"${S},${S}$(q user)\"(${USER_RE})\"${S},${S}$(q instance)\"[a-z0-9-]{1,63}\"${S},${S}$(q companion)\"[a-z0-9-]{1,31}\"${S},${S}$(q name)\"(${PREFIX}[a-z0-9]{12})\"${S},${S}$(q mode)\"(read_only|read_write)\"${S},${S}$(q scopes)[[]([^]]*)[]]${S}[}]${S}$"
re_revoke="^${S}[{]${S}$(q action)\"revoke\"${S},${S}$(q user)\"(${USER_RE})\"${S},${S}$(q ids)[[]([^]]*)[]]${S}[}]${S}$"
re_revoke_all="^${S}[{]${S}$(q action)\"revoke_all\"${S},${S}$(q prefix)\"${PREFIX}\"${S}[}]${S}$"

# ── mint ─────────────────────────────────────────────────
mint() {
  [[ $input =~ $re_mint ]] || die "refused: not a mint request of contract §15.5"
  local user=${BASH_REMATCH[1]} name=${BASH_REMATCH[2]} mode=${BASH_REMATCH[3]} list=${BASH_REMATCH[4]}
  local scopes="" item state token ids id
  ! reserved "$user" || die "refused: $user is a Portcullis service account"
  [[ $list =~ ^${S}$ ]] && die "refused: no scopes"
  IFS=',' read -r -a items <<<"$list"
  for item in "${items[@]}"; do
    [[ $item =~ ^${S}\"(${SCOPE_RE})\"${S}$ ]] || die "refused: scope not allowed"
    [ "$mode" = read_write ] || [[ ${BASH_REMATCH[1]} == read:* ]] || die "refused: a write scope in read_only mode"
    scopes=${scopes:+$scopes,}${BASH_REMATCH[1]}
  done

  state=$(account "$user")
  if [ -z "$state" ]; then
    echo "mcp-token: $user has no Gitea account yet (signs in to Gitea once to create it)" >&2
    exit 3
  fi
  [ "$state" = true ] || die "$user's Gitea account is disabled"

  token=$(gitea admin user generate-access-token --username "$user" --token-name "$name" \
    --scopes "$scopes" --raw) || die "generate-access-token failed"
  [[ $token =~ ^[0-9a-f]{40}$ ]] || die "unexpected generate-access-token output (token $name of $user may exist: revoke_all removes it)"

  hook_token_start
  ids=$(list_tokens "$user" "$PREFIX") || { delete_token "$user" "$name" || true; die "looking up the id of $name failed"; }
  id=$(awk -v n="$name" '$2 == n { print $1 }' <<<"$ids")
  [[ $id =~ ^[0-9]+$ ]] || { delete_token "$user" "$name" || true; die "no unique id for $name"; }
  # The hook token goes before the credential is handed out: a failure
  # here leaves no token the Hub doesn't know about.
  hook_token_end || { delete_token "$user" "$id" || true; die "deleting the hook token failed"; }
  printf '{"credential":"%s","id":"%s"}\n' "$token" "$id"
}

# ── revoke / revoke_all ──────────────────────────────────
# parse_ids LIST: the ids of a revoke request into WANT (empty: all of
# the person's portcullis-ai-* tokens).
WANT=()
parse_ids() {
  local item
  [[ $1 =~ ^${S}$ ]] && return 0
  IFS=',' read -r -a items <<<"$1"
  for item in "${items[@]}"; do
    [[ $item =~ ^${S}\"([0-9]{1,19})\"${S}$ ]] || die "refused: ids must be Gitea token ids"
    WANT+=("${BASH_REMATCH[1]}")
  done
}

revoke() {
  local user=$1 tokens id n
  [ -n "$(account "$user")" ] || return 0 # no account, no tokens
  tokens=$(list_tokens "$user" "$PREFIX") || die "listing $user's tokens failed"
  if [ "${#WANT[@]}" = 0 ]; then
    while read -r id n; do
      [ -n "$id" ] || continue
      delete_token "$user" "$id" || die "deleting $user's token $n failed"
    done <<<"$tokens"
    return 0
  fi
  for id in "${WANT[@]}"; do
    # Only the person's portcullis-ai-* tokens are ever deleted; an id
    # that is gone already counts as revoked.
    if awk -v i="$id" '$1 == i { f = 1 } END { exit !f }' <<<"$tokens"; then
      delete_token "$user" "$id" || die "deleting $user's token $id failed"
    fi
  done
}

revoke_all() {
  local users u
  users=$(gitea admin user list) || die "gitea admin user list failed"
  while read -r u; do
    [ -n "$u" ] || continue
    [[ $u =~ ^[A-Za-z0-9._-]{1,40}$ ]] || die "unexpected user name in gitea admin user list"
    tokens=$(list_tokens "$u" "$PREFIX") || die "listing $u's tokens failed"
    while read -r id n; do
      [ -n "$id" ] || continue
      delete_token "$u" "$id" || die "deleting $u's token $n failed"
    done <<<"$tokens"
  done < <(awk 'NR > 1 { print $2 }' <<<"$users")
}

case $1 in
  mint) mint ;;
  revoke)
    if [[ $input =~ $re_revoke ]]; then
      user=${BASH_REMATCH[1]}
      parse_ids "${BASH_REMATCH[2]}"
      ! reserved "$user" || die "refused: $user is a Portcullis service account"
      hook_token_start
      revoke "$user"
    elif [[ $input =~ $re_revoke_all ]]; then
      hook_token_start
      revoke_all
    else
      die "refused: not a revoke or revoke_all request of contract §15.5"
    fi
    hook_token_end || die "deleting the hook token failed (the next run deletes it)"
    ;;
  *) die "usage: mcp-token.sh mint|revoke < input" ;;
esac
