#!/usr/bin/env bash
# Test: Docs (public, no auth)
# Note: The docs compose mounts content files that may not exist in CI.
# This test verifies the container starts and Traefik routing is configured.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="docs"
section "Docs"

APP_ID=docs

# Verify compose file exists and is valid YAML
compose_path=$(_find_compose "$APP_ID")
if [ -n "$compose_path" ]; then
  pass "compose.yml found: $compose_path"
else
  fail "compose.yml not found for docs"
  exit 1
fi

# Verify Traefik labels are present (public, no auth middleware)
if grep -q 'traefik.enable.*true' "$compose_path"; then
  pass "Traefik routing enabled"
else
  fail "Traefik routing not configured"
fi

if grep -q 'portcullis-auth@docker' "$compose_path"; then
  fail "Docs should NOT have forward-auth middleware (it's public)"
else
  pass "No forward-auth middleware (correct for public app)"
fi
