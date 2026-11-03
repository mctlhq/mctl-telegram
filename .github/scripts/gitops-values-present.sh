#!/usr/bin/env bash
# Reports whether a values file exists on mctl-gitops main.
#
# Usage: gitops-values-present.sh platform-gitops/services/<team>/<svc>/values.yaml
# Env:   GH_TOKEN        token with contents:read on mctl-gitops (required)
#        GITHUB_API_URL  API base, defaults to https://api.github.com
#
# Exit codes:
#   0  HTTP 200, the file is present
#   3  HTTP 404, the file is absent (the only absence signal)
#   1  anything else: other status, transport failure, empty status,
#      unset token, invalid path. A read that could not be observed is
#      never treated as "absent".
set -uo pipefail

path="${1:-}"
case "$path" in
  platform-gitops/services/*) ;;
  *) echo "invalid values path: '$path'" >&2; exit 1 ;;
esac
case "$path" in
  *..*|*" "*) echo "invalid values path: '$path'" >&2; exit 1 ;;
esac
if [ -z "${GH_TOKEN:-}" ]; then
  echo "GH_TOKEN is not set" >&2
  exit 1
fi

api="${GITHUB_API_URL:-https://api.github.com}"
crc=0
code="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${GH_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${api}/repos/mctlhq/mctl-gitops/contents/${path}?ref=main")" || crc=$?
if [ "$crc" -ne 0 ]; then
  echo "curl failed with exit code $crc" >&2
  exit 1
fi
case "$code" in
  200) exit 0 ;;
  404) exit 3 ;;
  *) echo "unexpected HTTP status '$code'" >&2; exit 1 ;;
esac
