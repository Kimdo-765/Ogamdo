#!/usr/bin/env bash
# Install the exact CLI releases resolved once per deployment on the HOST
# (start.sh:339-349, via scripts/resolve-agent-cli-versions.sh).  This script
# runs in both api and worker image builds and refuses to run without exact
# pins, so no floating tag survives into the image.
set -euo pipefail

# The three versions arrive as build args and they are MANDATORY.
# api/Dockerfile:13-15 and worker/Dockerfile:78-80 declare them as
# `ARG ..._CLI_VERSION=latest`, and docker-compose.yml:157-159 (the
# x-worker-service anchor, i.e. worker-1..12) and :246-248 (api) substitute
# `${..._CLI_VERSION:-latest}` — so every build path that does not export a
# resolved pin hands this script the literal string `latest`.  It used to
# quietly turn that into an `npm view` / `x.ai/cli/stable` lookup INSIDE the
# build, which defeated the build arg twice over:
#
#   * `./restart.sh --build` never calls the resolver, so api and worker-1..12
#     each resolved independently mid-build.  A channel that advanced between
#     the api layer and the twelfth worker layer left the 13 images on
#     DIFFERENT agent CLI versions.  Each image does record its OWN answer in
#     /usr/local/share/ogamdo/agent-cli-versions (written at the bottom of this
#     script), but nothing compares those thirteen files, so the divergence is
#     invisible until an adapter behaves differently on one worker.
#   * `latest` is a constant, so the RUN layer's cache key never moved.  A
#     restart.sh-only host kept whatever version its first build happened to
#     catch (silent CLI rot), while alternating start.sh (exact, e.g. 2.1.160)
#     with restart.sh --build (`latest`) flipped that key back and forth.  That
#     layer is worker/Dockerfile:82-88 — above the Docker CLI (:91),
#     requirements.txt (:102), angr (:123), .NET/ilspycmd (:167), ghidra,
#     pwndbg (:306) and foundry (:464) — so every flip rebuilt essentially all
#     of hextech_ctf_tool-worker, measured at 8.64 GB by `docker image ls`.
#
# So refuse rather than resolve.  Resolution belongs on the host, once, where a
# single answer can be handed to all 13 builds.  `latest` is still defaulted in
# here only so that a variable that is unset entirely lands in the message
# below instead of dying on `set -u`'s bare "unbound variable".
: "${CLAUDE_CLI_VERSION:=latest}"
: "${CODEX_CLI_VERSION:=latest}"
: "${GROK_CLI_VERSION:=latest}"

for name in CLAUDE_CLI_VERSION CODEX_CLI_VERSION GROK_CLI_VERSION; do
  version="${!name}"
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z._-]*)?$ ]]; then
    printf 'refusing unpinned/invalid %s: %q\n' "$name" "$version" >&2
    cat >&2 <<'MSG'
This image is built from exact versions only.  Resolve them once on the host
and give api and EVERY worker the same answer:

  read -r CLAUDE_CLI_VERSION CODEX_CLI_VERSION GROK_CLI_VERSION \
    < <(scripts/resolve-agent-cli-versions.sh)
  export CLAUDE_CLI_VERSION CODEX_CLI_VERSION GROK_CLI_VERSION
  docker compose build api worker-1 ...

./start.sh already does this before it builds.
MSG
    exit 2
  fi
done

# PREFLIGHT: does this base image's Node satisfy what we are about to pin?
#
# engine-strict below turns a mismatch into a failed BUILD, which is right —
# but npm reports it as EBADENGINE thirty lines into an apt transcript, and
# the reader has to work out that the BASE IMAGE is the thing to change, not
# the version that was resolved. Say it here, in one line, before npm does.
#
# This fires for real: the resolver moving claude-code 2.1.158 -> 2.1.258
# crossed its engines.node ">=22.0.0" while both Dockerfiles still installed
# Node 20, and every one of the 13 image builds died on it at once.
_node_major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
for spec in "@anthropic-ai/claude-code@${CLAUDE_CLI_VERSION}" \
            "@openai/codex@${CODEX_CLI_VERSION}"; do
  want="$(npm view "$spec" engines.node 2>/dev/null | tr -d '\r')"
  case "$want" in
    '>='*)
      need="${want#>=}"; need="${need%%.*}"
      if [ -n "$need" ] && [ "$_node_major" -lt "$need" ] 2>/dev/null; then
        printf 'node %s is too old for %s (needs node >=%s).\n' \
          "$_node_major" "$spec" "$need" >&2
        printf 'FIX THE BASE IMAGE, not the pin: bump the nodesource setup_NN.x\n' >&2
        printf 'line in api/Dockerfile and worker/Dockerfile to >= %s.\n' "$need" >&2
        exit 3
      fi ;;
  esac
done

npm_config_engine_strict=true npm install --global --no-audit --no-fund \
  "@anthropic-ai/claude-code@${CLAUDE_CLI_VERSION}" \
  "@openai/codex@${CODEX_CLI_VERSION}"

# Grok's official installer normally puts the executable under ~/.grok.  That
# directory is a runtime auth/session bind mount in Ogamdo, so image contents
# there would be hidden.  Keep the immutable download at /opt and expose the
# binary through /usr/local/bin; the mounted ~/.grok remains credentials only.
installer="$(mktemp)"
trap 'rm -f "$installer"' EXIT
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 3 --retry-all-errors --connect-timeout 10 --max-time 90 \
  https://x.ai/cli/install.sh >"$installer"
HOME=/opt/ogamdo-grok GROK_CHANNEL=stable GROK_BIN_DIR=/usr/local/bin \
  bash "$installer" "$GROK_CLI_VERSION"
rm -f /usr/local/bin/agent

claude_actual="$(claude --version 2>&1 | head -1)"
codex_actual="$(codex --version 2>&1 | head -1)"
grok_actual="$(grok --version 2>&1 | head -1)"

banner_version() {
  local banner="$1"
  if [[ "$banner" =~ ([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z._-]*)?) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  fi
}

[[ "$(banner_version "$claude_actual")" == "$CLAUDE_CLI_VERSION" ]]
[[ "$(banner_version "$codex_actual")" == "$CODEX_CLI_VERSION" ]]
[[ "$(banner_version "$grok_actual")" == "$GROK_CLI_VERSION" ]]

# Pin the command surfaces used by the adapters, not just three version
# banners.  A latest major that removes one of these contracts must fail the
# candidate image before any live container is recreated.
claude --help 2>&1 | grep -q -- '--output-format'
codex exec --help 2>&1 | grep -q -- '--json'
grok agent --help 2>&1 | grep -q -- 'stdio'

printf 'Claude Code = %s\nCodex CLI = %s\nGrok Build = %s\n' \
  "$claude_actual" "$codex_actual" "$grok_actual"
install -d /usr/local/share/ogamdo
printf 'CLAUDE_CLI_VERSION=%s\nCODEX_CLI_VERSION=%s\nGROK_CLI_VERSION=%s\n' \
  "$CLAUDE_CLI_VERSION" "$CODEX_CLI_VERSION" "$GROK_CLI_VERSION" \
  > /usr/local/share/ogamdo/agent-cli-versions
rm -rf /root/.npm
