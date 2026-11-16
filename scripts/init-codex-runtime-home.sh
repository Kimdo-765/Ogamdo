#!/usr/bin/env bash
# Initialise HexTech's private Codex runtime home from the operator's login.
#
# The containers run Codex as uid 0.  Mounting the operator's ~/.codex rw lets
# those processes replace config.toml and session files with root-owned 0600
# files, which breaks an already-running host TUI.  HexTech therefore gets a
# separate writable home and imports only the OAuth credential on first use.
set -euo pipefail

SOURCE_HOME="${1:?source Codex home is required}"
RUNTIME_HOME="${2:?HexTech Codex runtime home is required}"

source_real="$(realpath -m -- "$SOURCE_HOME")"
runtime_real="$(realpath -m -- "$RUNTIME_HOME")"
if [ "$source_real" = "$runtime_real" ]; then
  printf 'refusing to bootstrap Codex into the operator home: %s\n' "$source_real" >&2
  exit 2
fi

umask 077
mkdir -p -- "$RUNTIME_HOME"
chmod 700 -- "$RUNTIME_HOME" 2>/dev/null || true

# Never copy config.toml, sessions, locks, skills, or package state.  The
# HexTech adapter supplies its runtime configuration via CLI flags and needs
# only file-backed ChatGPT OAuth.  Copying the rest would recreate the TUI
# ownership collision this helper exists to prevent.
# BOOTSTRAP *AND* REFRESH.  This used to copy only when the runtime auth.json
# was missing or empty, which made it first-use-only: after `codex login` the
# operator's ~/.codex/auth.json was fresh and the containers kept the old
# token, so `start.sh` could not fix it. Observed 2026-09-07 — job
# 97591b1cf8a2 died on "Failed to refresh token: 401 Unauthorized" against a
# runtime credential nine days older than the login.
#
# NEWER-WINS, NOT SOURCE-WINS. The runtime home is mounted rw and Codex
# rotates its own token there, so the runtime copy is legitimately newer much
# of the time. Overwriting unconditionally would roll a live session back to a
# stale credential. `-nt` copies only when the login really is the newer one.
if [ -s "$SOURCE_HOME/auth.json" ] \
   && { [ ! -s "$RUNTIME_HOME/auth.json" ] \
        || [ "$SOURCE_HOME/auth.json" -nt "$RUNTIME_HOME/auth.json" ]; }; then
  verb=refreshed
  [ -s "$RUNTIME_HOME/auth.json" ] || verb=initialized
  # Keep one generation. A rolled-back token is recoverable; a lost one means
  # another `codex login`.
  if [ -s "$RUNTIME_HOME/auth.json" ]; then
    cp -p -- "$RUNTIME_HOME/auth.json" "$RUNTIME_HOME/auth.json.prev" 2>/dev/null || true
  fi
  auth_tmp="$RUNTIME_HOME/.auth.json.bootstrap.$$"
  cp -- "$SOURCE_HOME/auth.json" "$auth_tmp"
  chmod 600 -- "$auth_tmp"
  mv -f -- "$auth_tmp" "$RUNTIME_HOME/auth.json"
  printf '%s isolated HexTech Codex OAuth at %s\n' "$verb" "$RUNTIME_HOME"
fi
