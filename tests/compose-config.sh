#!/usr/bin/env bash
# Run `docker compose config -q` on every template (or the ones given as
# arguments), the way the Hub would render it: core variables from their
# defaults and a dummy value for every manifest env entry with
# generate: random. Needs the docker CLI with the compose plugin (no daemon)
# and python3 + PyYAML.
#
#   bash tests/compose-config.sh            # all templates
#   bash tests/compose-config.sh grafana    # one template
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$#" -gt 0 ]; then
  apps=("$@")
else
  apps=()
  for f in */compose.yml; do apps+=("${f%/compose.yml}"); done
fi

failed=0
for app in "${apps[@]}"; do
  if [ ! -f "$app/compose.yml" ]; then
    echo "FAIL $app: no compose.yml"; failed=1; continue
  fi
  # KEY=value lines for the per-app .env the Hub would write.
  envs=()
  while IFS= read -r line; do
    [ -n "$line" ] && envs+=("$line")
  done < <(python3 - "$app/manifest.yaml" <<'PY'
import sys, yaml
try:
    m = yaml.safe_load(open(sys.argv[1])) or {}
except FileNotFoundError:
    m = {}
for e in m.get("env") or []:
    if isinstance(e, dict) and e.get("generate") == "random":
        print(f"{e['key']}=ci-dummy-{e['key'].lower()}")
PY
)
  # Clean environment: only what the Hub would provide.
  if out=$(env -i PATH="$PATH" HOME="$HOME" ${DOCKER_CONFIG:+DOCKER_CONFIG="$DOCKER_CONFIG"} "${envs[@]+"${envs[@]}"}" \
      docker compose -p portcullis -f "$app/compose.yml" --project-directory . config -q 2>&1); then
    echo "ok   $app"
  else
    echo "FAIL $app"; echo "$out" | sed 's/^/     /'; failed=1
  fi
done
exit "$failed"
