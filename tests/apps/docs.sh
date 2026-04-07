#!/usr/bin/env bash
# Test: Docs (public, no auth)
# The docs compose mounts content files not available in CI.
# This test verifies compose config only (no container).
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="docs"
section "Docs"

# Find compose file
COMPOSE=""
for p in "docs/compose.yml" "$TEMPLATES_DIR/docs/compose.yml"; do
  [ -f "$p" ] && COMPOSE="$p" && break
done

if [ -n "$COMPOSE" ]; then
  pass "compose.yml found: $COMPOSE"
else
  fail "compose.yml not found for docs"
fi

# Verify Traefik labels (public, no auth middleware)
if grep -q 'traefik.enable.*true' "$COMPOSE" 2>/dev/null; then
  pass "Traefik routing enabled"
else
  fail "Traefik routing not configured"
fi

if grep -q 'portcullis-auth@docker' "$COMPOSE" 2>/dev/null; then
  fail "Docs should NOT have forward-auth middleware (it's public)"
else
  pass "No forward-auth middleware (correct for public app)"
fi
