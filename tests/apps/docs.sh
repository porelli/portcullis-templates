#!/usr/bin/env bash
# Test: Docs (public, no auth)
# Static config check only — docs app needs mounted content files.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="docs"
section "Docs"

# Find compose file in several possible locations
COMPOSE=""
for candidate in \
  "docs/compose.yml" \
  "${TEMPLATES_DIR:-}/docs/compose.yml" \
  "${PROJECT_DIR:-}/templates/docs/compose.yml"; do
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    COMPOSE="$candidate"
    break
  fi
done

if [ -n "$COMPOSE" ]; then
  pass "compose.yml found: $COMPOSE"
else
  fail "compose.yml not found for docs (searched: docs/, TEMPLATES_DIR=${TEMPLATES_DIR:-unset}, PROJECT_DIR=${PROJECT_DIR:-unset})"
fi

if [ -n "$COMPOSE" ]; then
  if grep -q 'traefik.enable.*true' "$COMPOSE"; then
    pass "Traefik routing enabled"
  else
    fail "Traefik routing not configured"
  fi

  if grep -q 'portcullis-auth@docker' "$COMPOSE"; then
    fail "Docs should NOT have forward-auth middleware (it's public)"
  else
    pass "No forward-auth middleware (correct for public app)"
  fi
fi
