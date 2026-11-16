#!/usr/bin/env bash
# =============================================================================
# tunnel-autostart.sh — bring up the cloudflared OOB tunnel (tunnel.sh) DETACHED
#   and wait until it has auto-published its public URL into Settings
#   (Callback URL). Called by start.sh / restart.sh so the callback URL in
#   /data/settings.json is set automatically whenever the stack comes up.
#
#   Set AUTO_TUNNEL=0 (env or .env) to skip — e.g. if you run your own tunnel.
#   No-ops gracefully (exit 0) when cloudflared isn't installed, so it never
#   blocks a bring-up.
#
# Env in:  PROJECT_DIR  WEB_PORT (8000)  API_BASE  TUNNEL_LOG  TUNNEL_PIDFILE
# =============================================================================
set -uo pipefail

if [ "${AUTO_TUNNEL:-1}" = "0" ]; then
  echo "[tunnel] AUTO_TUNNEL=0 -> skipping tunnel auto-start"
  exit 0
fi

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PORT="${WEB_PORT:-8000}"
API_BASE="${API_BASE:-http://localhost:$PORT}"
TUNNEL_LOG="${TUNNEL_LOG:-/tmp/hextech-ctf-tunnel.log}"
TUNNEL_PIDFILE="${TUNNEL_PIDFILE:-/tmp/hextech-ctf-tunnel.pid}"
TS="$PROJECT_DIR/tunnel.sh"

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "[tunnel] cloudflared not installed -> skipping auto-start."
  echo "[tunnel]   install it, then run ./tunnel.sh (or re-run this) to enable OOB callbacks."
  exit 0
fi
[ -r "$TS" ] || { echo "[tunnel] $TS not found -> skipping auto-start"; exit 0; }

# Stop any tunnel we previously started so we don't stack cloudflared instances.
TUNNEL_PIDFILE="$TUNNEL_PIDFILE" bash "$TS" stop >/dev/null 2>&1 || true

echo "[tunnel] starting cloudflared tunnel (detached); log: $TUNNEL_LOG"
# setsid: own session so the tunnel outlives this helper (and the caller).
# Baseline the Callback URL *after* the stop above and *before* the launch: the
# stop path's TERM trap deliberately RESTORES the previous URL rather than
# blanking it (tunnel.sh cleanup(): "that URL is itself dead now (it was a
# previous tunnel), but restoring is least-surprise vs. silently blanking an
# operator-set VPS URL"). So a *.trycloudflare.com value is routinely sitting in
# settings at loop entry, and only a CHANGE from this baseline proves the tunnel
# we just launched published anything.
prior_url="$(jq -r '.callback_url // empty' \
  "$PROJECT_DIR/data/settings.json" 2>/dev/null || true)"
TUNNEL_PIDFILE="$TUNNEL_PIDFILE" PROJECT_DIR="$PROJECT_DIR" WEB_PORT="$PORT" API_BASE="$API_BASE" \
  setsid bash "$TS" >"$TUNNEL_LOG" 2>&1 </dev/null &
disown 2>/dev/null || true

# Wait for tunnel.sh to publish a *.trycloudflare.com URL into settings
# (cloudflared edge warm-up is a few seconds).
url=""
for _ in $(seq 1 40); do
  # Read the host-owned settings file, NOT GET /api/settings. tunnel.sh writes
  # the URL through the authenticated API (it loads .auth_token and sends a
  # Bearer header), but this supervisor only needs to OBSERVE completion and has
  # no business copying the operator token to do it. An unauthenticated GET here
  # is not merely unauthorised, it is silently wrong: with auth enabled the API
  # answers 401 {"detail":"auth required"} (measured on this host), jq yields the
  # empty string, and the loop burns all 40s and reports "no URL within 40s
  # (rate-limit?)" about a tunnel that published fine -- then tells the operator
  # to `$TS stop && $TS`, destroying a healthy tunnel and spending a real quick-
  # tunnel slot against the limit the message blamed. data/ is a directory bind
  # mount, so update_settings' atomic write-and-rename inside the container is
  # visible here; the callback URL is non-secret.
  url="$(jq -r '.callback_url // empty' \
    "$PROJECT_DIR/data/settings.json" 2>/dev/null || true)"
  case "$url" in
    *trycloudflare.com*) [ "$url" != "$prior_url" ] && break; url="" ;;
    *) url="" ;;
  esac
  sleep 1
done

if [ -n "$url" ]; then
  # One reachability check through the EXISTING tunnel: a single GET, NOT a new
  # tunnel, so this does not touch Cloudflare's quick-tunnel rate limit. Poll
  # briefly for edge warm-up so the operator gets an honest reachable/not signal.
  reach=0
  for _ in $(seq 1 15); do
    [ "$(curl -s --max-time 6 "$url/api/collector/_autostartprobe/_p?c=PING" 2>/dev/null || true)" = "ok" ] \
      && { reach=1; break; }
    sleep 2
  done
  if [ "$reach" = 1 ]; then
    echo "[tunnel] Callback URL auto-set -> $url  (reachable -- beacons will land)"
  else
    echo "[tunnel] Callback URL auto-set -> $url  (NOT reachable yet)"
    echo "[tunnel]   the quick-tunnel may still be warming up or be rate-limited;"
    echo "[tunnel]   if beacons don't land, re-roll a fresh URL:  $TS stop && $TS"
  fi
  echo "[tunnel]   stop:  $TS stop      logs:  tail -f $TUNNEL_LOG"
else
  echo "[tunnel] tunnel launched but no *.trycloudflare.com URL within 40s (rate-limit?)."
  echo "[tunnel]   check:  tail -n 30 $TUNNEL_LOG    re-roll:  $TS stop && $TS"
fi
exit 0
