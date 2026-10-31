#!/usr/bin/env bash
# Print the images CI needs for one app's integration test, one per line,
# sorted: every services.*.image of <app>/compose.yml, or nothing if
# tests/apps/<app>.sh never boots the template (static tests pull nothing).
# test-apps.yml keys the per-app image cache on a hash of this output.
#
# Reads files only (no compose interpolation, no daemon); needs yq v4.
#
#   bash tests/app-images.sh grafana
set -euo pipefail
cd "$(dirname "$0")/.."

app="${1:?usage: tests/app-images.sh <app>}"
[[ "$app" =~ ^[a-z0-9][a-z0-9_-]*$ ]] && [ -f "$app/compose.yml" ] || { echo "unknown app '$app'" >&2; exit 1; }

if [ -f "tests/apps/$app.sh" ] && grep -q '^[^#]*compose_up' "tests/apps/$app.sh"; then
  yq -r '.services[].image // ""' "$app/compose.yml" | sed '/^$/d' | LC_ALL=C sort -u
fi
