#!/usr/bin/env bash
# Resolve one immutable set of stable CLI releases for a deployment.
#
# stdout is deliberately machine-only: "<claude> <codex> <grok>".  Human
# diagnostics go to stderr so deploy.sh can consume this with `read` without
# eval'ing registry-controlled text.
set -euo pipefail

fetch_npm_version() {
  local package_url="$1" package_name="$2" payload version
  payload="$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
    --location --retry 3 --retry-all-errors --connect-timeout 10 \
    --max-time 90 "$package_url")"
  version="$(python3 -c '
import json, sys
data = json.load(sys.stdin)
value = data.get("version", "")
print(value if isinstance(value, str) else "")
' <<<"$payload")"
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z._-]*)?$ ]]; then
    printf '[cli-resolver] invalid %s version from registry: %q\n' \
      "$package_name" "$version" >&2
    return 1
  fi
  printf '%s' "$version"
}

claude_version="$(fetch_npm_version \
  'https://registry.npmjs.org/@anthropic-ai%2fclaude-code/latest' \
  'Claude Code')"
codex_version="$(fetch_npm_version \
  'https://registry.npmjs.org/@openai%2fcodex/latest' \
  'Codex CLI')"
grok_version="$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
  --location --retry 3 --retry-all-errors --connect-timeout 10 --max-time 90 \
  'https://x.ai/cli/stable' \
  | tr -d '\r[:space:]')"

if [[ ! "$grok_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z._-]*)?$ ]]; then
  printf '[cli-resolver] invalid Grok Build version from stable channel: %q\n' \
    "$grok_version" >&2
  exit 1
fi

printf '%s %s %s\n' "$claude_version" "$codex_version" "$grok_version"
