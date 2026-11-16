#!/usr/bin/env bash
# Control only the Security RAG HTTP server on this Ogamdo host.
set -euo pipefail

SERVICE=security-rag.service

usage() {
  printf 'Usage: %s {start|stop|status}\n' "${0##*/}" >&2
  exit 2
}

case "${1:-}" in
  start|stop|status) ;;
  *) usage ;;
esac

if ! command -v systemctl >/dev/null 2>&1 || ! systemctl --user cat "$SERVICE" >/dev/null 2>&1; then
  printf 'RAG user service is unavailable: %s\n' "$SERVICE" >&2
  exit 1
fi

case "$1" in
  start)
    systemctl --user start "$SERVICE"
    if ! systemctl --user is-active --quiet "$SERVICE"; then
      printf 'RAG server failed to start. Check: journalctl --user -u %s -n 50\n' "$SERVICE" >&2
      exit 1
    fi
    printf 'RAG server running: http://127.0.0.1:8765\n'
    ;;
  stop)
    systemctl --user stop "$SERVICE"
    printf 'RAG server stopped.\n'
    ;;
  status)
    if systemctl --user is-active --quiet "$SERVICE"; then
      printf 'RAG server running: http://127.0.0.1:8765\n'
    else
      printf 'RAG server stopped.\n'
    fi
    ;;
esac
