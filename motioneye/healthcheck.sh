#!/bin/sh
# motionEye healthcheck: both local accounts have a password (motioneye-init)
# and the web UI answers.
set -eu
f=/etc/motioneye/motion.conf
grep -Eq '^# @admin_password [^[:space:]]' "$f"
grep -Eq '^# @normal_password [^[:space:]]' "$f"
curl -fsS -o /dev/null --max-time 5 http://127.0.0.1:8765/
