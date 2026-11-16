#!/usr/bin/env bash
# =============================================================================
# deploy.sh — apply freshly-patched code to the RUNNING stack, no rebuild.
#
# WHY THIS IS ENOUGH (no image build, no daemon bounce, no sudo):
#   The source trees are bind-mounted read-only into the containers
#   (docker-compose.yml: ./modules ./api ./web-ui -> api, ./modules ./worker
#   -> worker). So the FILES are always current the instant you edit them; a
#   container RESTART just makes the long-lived Python process re-import them.
#   The UI is served by api StaticFiles straight from ./web-ui with
#   `Cache-Control: no-cache` (api/main.py) — so the UI is ALWAYS fresh on the
#   next browser refresh; it needs NO restart, only Ctrl-Shift-R if your
#   browser is being stubborn.
#
#   => "apply latest" = restart the backend containers whose code changed.
#      api    : api/  modules/  web-ui/   (routes + shared modules + UI host)
#      worker : modules/  worker/         (the agent/runner process)
#      modules/ touches BOTH.
#
# USAGE
#   ./deploy.sh              # restart api + every IDLE worker slot
#   ./deploy.sh --api        # api only            (safe anytime — jobs run in worker)
#   ./deploy.sh --worker     # worker slots only
#   ./deploy.sh --force      # restart ALL slots even if jobs are running (KILLS them)
#   ./deploy.sh --changed    # restart only the services whose mounted paths changed
#                            #   since the last deploy (uses git HEAD vs .last_deploy)
#   ./deploy.sh -h|--help
#
# SAFETY
#   * A slot restart KILLS the job on that slot. The worker is now one
#     container per SLOT, so deploy.sh restarts only the slots that are
#     provably idle and defers the rest with a warning (re-run with --worker
#     when they finish, or --force to override).
#     It FAILS CLOSED: if any job is queued, or is running but has not yet
#     recorded which slot serves it, EVERY slot is deferred — an unplaced job
#     can land on any of them.
#   * If Docker Desktop's WSL integration is shadowing the snap docker CLI
#     (docker can't see the hextech containers although :8000 serves), the
#     light restart can't reach the daemon — deploy.sh detects this and prints
#     the one-time fix instead of silently failing.
#
# EXIT: 0 ok · 2 bad args · 3 cli-shadowed · 4 stack down · 5 restart failed
#       6 restarted API did not become healthy
# =============================================================================
set -uo pipefail

# WHERE THIS ACTS.  Derived from the script's OWN location, not a baked path.
#
# It used to default to /home/yadohyun/HexTech_CTF_TOOL, which stopped being
# true the moment the tree was cloned elsewhere: the running stack's compose
# label `com.docker.compose.project.working_dir` reads /home/yadohyun/ogamdo
# and every bind mount (modules, worker, api, web-ui, data) resolves there.
# A `./restart.sh` launched from the live tree would therefore have torn that
# stack down and brought it back up against the OTHER checkout — silently
# swapping the mounted code and the job data underneath a running deployment.
# Deriving from $BASH_SOURCE makes "restart this checkout" mean what it says,
# and the env override still wins for anyone who needs to point it elsewhere.
PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
PROJECT="hextech_ctf_tool"
JOBS_DIR="$PROJECT_DIR/data/jobs"
LAST_DEPLOY_FILE="$PROJECT_DIR/.last_deploy"
API_URL="http://localhost:8000"

if [ -t 1 ]; then
  C=$'\033[1;36m'; Y=$'\033[1;33m'; R=$'\033[1;31m'; G=$'\033[1;32m'; N=$'\033[0m'
else C=''; Y=''; R=''; G=''; N=''; fi
log()  { printf '%s[deploy]%s %s\n' "$C" "$N" "$*"; }
warn() { printf '%s[deploy] WARN:%s %s\n' "$Y" "$N" "$*"; }
err()  { printf '%s[deploy] ERR:%s %s\n'  "$R" "$N" "$*"; }
ok()   { printf '%s[deploy] OK:%s %s\n'   "$G" "$N" "$*"; }

MODE="both"; FORCE=0; CHANGED=0
for a in "$@"; do
  case "$a" in
    --api) MODE="api" ;;
    --worker) MODE="worker" ;;
    --both) MODE="both" ;;
    --force) FORCE=1 ;;
    --changed) CHANGED=1 ;;
    -h|--help) sed -n '2,43p' "$0"; exit 0 ;;
    *) err "unknown arg: $a (use --api|--worker|--both|--force|--changed)"; exit 2 ;;
  esac
done

cd "$PROJECT_DIR" 2>/dev/null || { err "project dir not found: $PROJECT_DIR"; exit 1; }

# --- pick the docker CLI that actually drives THIS project's daemon ----------
# In WSL, /usr/bin/docker can flip to the Docker-Desktop CLI (which sees a
# different, empty daemon) while the stack runs under snap dockerd. We don't
# care WHICH binary, only that `compose ps` sees our containers.
DC() { docker compose -p "$PROJECT" "$@"; }

cli_sees_stack() {
  docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${PROJECT}-"
}
# The health probe must hit an endpoint that is PUBLIC BY DESIGN.
#
# This used to probe "$API_URL/" and demand exactly 200.  Once login was
# added, `/` began answering 307 -> /login for an unauthenticated caller, so
# the check could never pass again: every deploy ended in
#   "restarted api is not 200 - .last_deploy NOT advanced"
# with a perfectly healthy api behind it (uvicorn logging "Application
# startup complete" and serving /api/health 200).  Observed live on
# 2026-09-02.  Two things broke with it: `--changed` reads .last_deploy, so
# it never advanced either; and the shadowed-CLI diagnostic below calls
# api_up() to tell "CLI cannot see the stack" apart from "stack is down",
# so it reported the wrong one.
#
# /api/health is listed in api/auth.py's public-path allowlist and answers
# {"status":"ok"} without a session, which is exactly what a liveness probe
# needs.  Redirects are deliberately NOT followed: following them would make
# the login page itself count as a healthy api.
api_up() { [ "$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/api/health" 2>/dev/null)" = "200" ]; }

# --- stale KVM override guard (must run before ANY compose command) ---------
# start.sh generates docker-compose.override.yml to pass /dev/kvm through, and
# that file names SERVICES. The worker split renamed them (worker ->
# worker-1/worker-2), so an override written before the split declares a
# service that no longer exists AND has no image or build context. Compose
# rejects the whole project:
#     service "worker" has neither an image nor a build context specified:
#     invalid compose project
# — which breaks every compose command, including the ones that would fix it.
#
# The file self-identifies with start.sh's marker, so when it is ours we may
# drop it. The move-test is what makes this safe: the override is only removed
# when removing it DEMONSTRABLY repairs the project, never merely because some
# unrelated compose error occurred.
_heal_stale_override() {
  local ovr=docker-compose.override.yml bak
  [ -f "$ovr" ] || return 0
  head -1 "$ovr" 2>/dev/null \
    | grep -qxF "# AUTO-GENERATED by start.sh: KVM device passthrough" || return 0
  DC config --services >/dev/null 2>&1 && return 0
  bak="${ovr}.stale.$$"
  mv "$ovr" "$bak" 2>/dev/null || return 0
  if DC config --services >/dev/null 2>&1; then
    warn "removed a STALE generated $ovr — it named a worker service that no"
    warn "longer exists and broke every docker compose command. Re-run ./start.sh"
    warn "to regenerate it with the current slot names (KVM stays off until then)."
    rm -f "$bak"
  else
    mv "$bak" "$ovr" 2>/dev/null || true
  fi
}
_heal_stale_override

# --- if the CLI on PATH is blind, look for one that isn't --------------------
# The comment above says we don't care WHICH binary, only that it sees our
# containers — but nothing acted on that, so a shadowed PATH `docker` ended the
# run even when a working CLI sat one directory away. In WSL that is the normal
# state, not an edge case: Docker Desktop's integration puts a wrapper ahead of
# snap's docker on PATH, the wrapper talks to a different (empty) daemon, and
# every deploy stopped with a manual "pick one of these two fixes".
#
# Try the known alternates before giving up. Each candidate has to prove itself
# with the same cli_sees_stack test the PATH one just failed, so this can only
# ever select a CLI that actually drives THIS project's daemon.
if ! cli_sees_stack; then
  _path_docker="$(command -v docker || true)"
  for _cand in /snap/bin/docker /usr/bin/docker /usr/local/bin/docker; do
    [ -x "$_cand" ] || continue
    [ "$_cand" = "$_path_docker" ] && continue        # that's the one that failed
    # eval so the chosen path is baked in AT DEFINITION. A plain
    # `docker() { command "$_cand" "$@"; }` would re-read $_cand at CALL time,
    # and the loop reassigns it — the function would follow the loop variable
    # instead of the binary it was validated with.
    eval "docker() { command $_cand \"\$@\"; }"
    if cli_sees_stack; then
      warn "PATH docker cannot see ${PROJECT}; using ${_cand} for this run."
      warn "To make it permanent: Docker Desktop -> Settings -> Resources ->"
      warn "WSL Integration -> toggle this distro OFF."
      break
    fi
    unset -f docker
  done
fi

# --- diagnose the environment BEFORE touching anything -----------------------
if ! cli_sees_stack; then
  if api_up; then
    err "docker CLI is SHADOWED — it cannot see the ${PROJECT} containers, yet"
    err ":8000 is serving (the stack runs under a daemon your CLI can't reach,"
    err "typically snap dockerd hidden by Docker Desktop's WSL integration)."
    echo
    warn "One-time fix (pick ONE), then re-run ./deploy.sh:"
    warn "  A) Docker Desktop -> Settings -> Resources -> WSL Integration ->"
    warn "     toggle this distro OFF  (restores docker -> snap; no sudo after)"
    warn "  B) sudo snap restart docker   (bounces the snap daemon; containers"
    warn "     return via 'restart: unless-stopped' with the new bind-mounted code)"
    exit 3
  fi
  err "stack appears DOWN (no ${PROJECT} containers, :8000 not 200)."
  err "bring it up first:  ./start.sh        (or ./restart.sh if orphaned)"
  exit 4
fi

# --- which services need a restart -------------------------------------------
declare -A WANT=()
# Set only when we have DIRECT evidence that an image this deploy depends on is
# still stale — see the IMAGE-REBUILD GUARD below. Like DEFERRED it gates the
# `.last_deploy` stamp at the tail, so it has to exist in EVERY mode: that stamp
# site also runs for --api/--worker/--both, and under `set -u` (line 45) an
# unset variable there would kill the deploy at its last line instead of
# stamping it.
REBUILD_PENDING=0
if [ "$CHANGED" = 1 ]; then
  base="$(cat "$LAST_DEPLOY_FILE" 2>/dev/null || true)"
  head="$(git rev-parse HEAD 2>/dev/null || true)"

  # A baseline git cannot resolve is NOT "nothing changed".
  #
  # $base is whatever bytes happen to sit in .last_deploy, and it used to go
  # straight to `git diff` unchecked. Verified in this repo:
  #     git diff --name-only deadbeef HEAD 2>/dev/null   -> rc 128, stdout EMPTY
  # with "fatal: bad object" thrown away on the discarded stderr. An empty
  # changed_paths makes both greps below fail, WANT stays empty, and the run
  # printed a GREEN "changed paths touch no mounted backend code" and stamped
  # HEAD — a git error reported to the operator as a clean, up-to-date deploy,
  # with every commit between the bad baseline and HEAD skipped for good. A
  # rebase, a `git gc` after a branch was dropped, a half-written file or a
  # stray trailing line all produce exactly that input.
  #
  # Validate it up front and, when it does not name a commit, fall into the
  # existing "no baseline" branch instead of inventing a new failure mode:
  # restarting both services is already the right answer when we cannot tell
  # what changed.
  if [ -n "$base" ] && ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
    warn "--changed: .last_deploy does not name a commit in this checkout"
    warn "  ($(printf '%s' "$base" | tr '\r\n' '  ' | cut -c1-60)) — treating it as NO baseline."
    base=""
  fi

  if [ -z "$base" ] || [ -z "$head" ]; then
    warn "--changed: no git baseline; falling back to restart both"
    WANT[api]=1; WANT[worker]=1
  elif [ "$base" = "$head" ]; then
    ok "nothing new since last deploy ($head) — UI already fresh, no restart needed."
    exit 0
  elif ! changed_paths="$(git diff --name-only "$base" "$head" 2>/dev/null)"; then
    # The baseline resolved a moment ago, so getting here means git itself
    # failed (a corrupt object, an unreadable index). Same rule as above: a
    # failed diff must never be read as "no files changed". stderr stays
    # discarded on purpose — git also writes NOTES there on success (rename
    # detection, for one), and those would flow into the path greps below.
    warn "--changed: git diff $base..$head FAILED — cannot tell what changed;"
    warn "falling back to restart both, the same as having no baseline at all."
    WANT[api]=1; WANT[worker]=1
  else
    # changed_paths is already set: the elif above ran the diff and only fell
    # through to here because it SUCCEEDED.

    # --- IMAGE-REBUILD GUARD --------------------------------------------------
    # deploy.sh only RESTARTS bind-mounted code (api/, modules/, web-ui/,
    # worker/). Anything BAKED INTO AN IMAGE — runner/, forensic/, misc/,
    # decompiler/, any Dockerfile, any requirements*.txt — needs a real BUILD,
    # which this script never performs. Worse, a change confined to those paths
    # matches NEITHER restart pattern below, so it fell into the "changed paths
    # touch no mounted backend code" early-exit: the fix silently did nothing AND
    # the deploy baseline advanced, hiding it from the next --changed run too.
    # That is how a runner/Dockerfile fix can look deployed while the live image
    # is still stale, so warn LOUDLY and, for the runner, probe the LIVE image
    # instead of trusting the file (memory: deploy_after_merge_habit).
    img_changed="$(echo "$changed_paths" | grep -E '(^|/)Dockerfile$|^(runner|forensic|misc|decompiler)/|requirements[^/]*\.txt$' || true)"
    if [ -n "$img_changed" ]; then
      warn "IMAGE REBUILD REQUIRED — these changed paths are BAKED INTO IMAGES:"
      echo "$img_changed" | sed 's/^/    /' >&2
      warn "deploy.sh restarts bind-mounted code only; it will NOT rebuild them."
      warn "run:  ./start.sh --rebuild     (or: docker compose -p $PROJECT --profile tools build <svc>)"
      # Cheap liveness probe (~0.3s) so the operator sees LIVE-vs-STALE rather
      # than a Dockerfile diff. Best-effort: any docker hiccup degrades to a note.
      #
      # The probe is also the ONLY thing in this block allowed to gate the
      # `.last_deploy` stamp, and that restraint is the point. A gate needs a
      # CLEARING transition or it pins the baseline forever and destroys the
      # self-correction the stamp comment at the tail depends on. The probe has
      # one: it is a direct observation of the LIVE image, so `./start.sh
      # --rebuild` flips it from FAILED to OK and the very next `--changed` run
      # stamps by itself, with no file to hand-edit. Gating on the mere presence
      # of a changed image path would have no such transition — nothing this
      # script can observe ever says "that Dockerfile is baked in now" — so
      # forensic/, misc/, decompiler/ and the api/worker Dockerfiles keep the
      # loud warning above and deliberately do NOT touch the stamp.
      if echo "$img_changed" | grep -q '^runner/'; then
        if probe_out="$(docker run --rm --network none "${PROJECT}-runner" \
              sh -c 'printf "int main(void){return 0;}" > /tmp/_p.c && gcc /tmp/_p.c -o /tmp/_p' 2>&1)"; then
          ok  "live runner image: toolchain OK (already rebuilt)"
        else
          REBUILD_PENDING=1
          warn "live runner image is STALE — a compile probe FAILED in it:"
          echo "$probe_out" | head -3 | sed 's/^/    /' >&2
        fi
      fi
    fi

    echo "$changed_paths" | grep -qE '^(api/|modules/|web-ui/)' && WANT[api]=1
    echo "$changed_paths" | grep -qE '^(worker/|modules/)'      && WANT[worker]=1
    if [ ${#WANT[@]} -eq 0 ]; then
      # Nothing to RESTART — but if the probe above just caught the runner
      # image out, stamping here is what turned that discovery into a one-shot:
      # the next `--changed` would take the `base = head` exit at the top of
      # this block, never re-run the probe, and the image would stay stale with
      # no signal left anywhere. Hold the baseline instead so the next run
      # rediscovers it. Exit stays 0, matching the deferred-slot path at the
      # tail — the loud block above is the report, not the status code.
      if [ "$REBUILD_PENDING" = 1 ]; then
        warn "nothing to restart, and .last_deploy is NOT advanced: the live"
        warn "runner image failed its compile probe. Rebuild it, then re-run"
        warn "'./deploy.sh --changed' — it re-probes and stamps on its own."
        exit 0
      fi
      ok "changed paths touch no mounted backend code — nothing to restart."
      echo "$head" > "$LAST_DEPLOY_FILE" 2>/dev/null || true
      exit 0
    fi
  fi
else
  case "$MODE" in
    api)    WANT[api]=1 ;;
    worker) WANT[worker]=1 ;;
    both)   WANT[api]=1; WANT[worker]=1 ;;
  esac
fi

# --- worker slot discovery ----------------------------------------------------
# The worker is now N containers, one per SLOT (`worker-1`, `worker-2`, ...),
# each running exactly one RQ process. A pre-split compose file has a single
# `worker`; both shapes are matched so this script keeps working either way.
# Worker services DEFINED in the compose file.
worker_services() {
  DC config --services 2>/dev/null | grep -xE 'worker(-[0-9]+)?' | sort
}

# Worker services that actually HAVE a container right now. This — not the
# compose file — is what may be restarted.
#
# `docker compose restart <service-with-no-container>` EXITS 0 AND DOES
# NOTHING. Verified on docker compose v2. Between merging the slot split and
# running the migration recreate, the compose file says worker-1/worker-2
# while the running container is still the old `worker` service, so restarting
# by DEFINED name would print "restarting: worker-1 worker-2", exit clean,
# leave the live worker on stale code — and advance .last_deploy so the next
# --changed run skips it too. That is the same silent-staleness failure the
# image-rebuild guard above exists for.
worker_services_live() {
  DC ps --format '{{.Service}}' 2>/dev/null | grep -xE 'worker(-[0-9]+)?' | sort -u
}

# True when a pre-split `worker` container is still up while the compose file
# has already moved to worker-N.
#
# This state cannot be resolved by `up`: worker-1 pins container_name
# hextech_ctf_tool-worker-1, which is the name the OLD container already holds.
# Verified — `up -d --force-recreate` then half-migrates: worker-2 is Created
# but never started, worker-1 dies on
#   Conflict. The container name "/..." is already in use
# and the old container keeps running. So detect it and say what to run;
# never walk into it.
migration_pending() {
  docker ps -aq \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=worker" 2>/dev/null | grep -q . \
    && worker_services | grep -qxE 'worker-[0-9]+'
}

print_migration_steps() {
  warn "the compose file defines worker slots but a pre-split 'worker' container"
  warn "is still running. deploy.sh will restart the LIVE container so this"
  warn "deploy is real, but the slot split is NOT in effect until you run:"
  warn "    rm -f docker-compose.override.yml"
  warn "    docker rm -f ${PROJECT}-worker-1        # frees the pinned name"
  warn "    docker compose -p $PROJECT up -d worker-1 worker-2"
  warn "    ./start.sh                              # regenerates the KVM override"
}

# Which slots are serving a job right now.
#
# Prints exactly one of:
#   IDLE                 no running/queued job at all
#   BUSY <n> <n> ...     these slot numbers are serving a job
#   ALL <detail>         a job is active but its slot cannot be determined
#
# FAIL CLOSED is the whole design. Two cases produce an active job with no
# resolvable slot, and treating either as "idle" kills a job:
#   * a QUEUED job has no worker yet and can be dispatched to any slot at any
#     moment, including the instant between this scan and the restart;
#   * a job in the pre-agent window has not written rq_worker_name to meta.json
#     yet — the same window that made the UI's stale-running check misfire.
# "No slot" therefore means "could be any slot", never "no slot is busy".
slot_scan() {
  python3 - "$JOBS_DIR" <<'PY'
import glob, json, os, re, sys

active = []
for m in glob.glob(os.path.join(sys.argv[1], "*", "meta.json")):
    try:
        with open(m) as fh:
            d = json.load(fh)
    except Exception:
        # An unreadable meta.json for a job that might be running is exactly
        # the ambiguity this scan must not resolve optimistically.
        active.append((os.path.basename(os.path.dirname(m)), "", "?", True))
        continue
    if d.get("status") in ("running", "queued"):
        # `worker_slot` is stamped into meta.json by modules/_common.py's
        # write_meta, from the WORKER_SLOT env of the slot serving the job.
        # `rq_worker_name` is a fallback only: GET /api/jobs computes it live
        # from RQ and never persists it, so it is absent from every meta.json
        # on disk.
        slot = str(d.get("worker_slot") or "").strip()
        if not slot:
            m2 = re.match(r"^htct-s(\d+)-w\d+$", str(d.get("rq_worker_name") or ""))
            slot = m2.group(1) if m2 else ""
        active.append((os.path.basename(os.path.dirname(m)), slot,
                       d.get("status"), False))

if not active:
    print("IDLE")
    raise SystemExit

slots, unknown = set(), []
for jid, slot, status, unreadable in active:
    # A QUEUED job is unplaced by definition — it can be dispatched to any
    # slot between this scan and the restart — so it always defers everything.
    if slot and status == "running" and not unreadable:
        slots.add(slot)
    else:
        why = ("unreadable meta" if unreadable
               else "queued, not yet dispatched" if status == "queued"
               else "no worker_slot recorded (job predates the slot split?)")
        unknown.append("%s(%s)" % (jid[:12], why))
if unknown:
    print("ALL " + ", ".join(unknown))
else:
    print("BUSY " + " ".join(sorted(slots, key=int)))
PY
}

# --- active-job guard: restart only the slots with no job on them -------------
declare -a RESTART_SVCS=()
# Set when any worker slot was wanted but NOT restarted. It gates the
# `.last_deploy` stamp at the tail — see the comment there; leaving it unset
# after a deferral makes the deferred slot permanently stale.
DEFERRED=0
[ -n "${WANT[api]:-}" ] && RESTART_SVCS+=(api)

if [ -n "${WANT[worker]:-}" ]; then
  migration_pending && print_migration_steps
  # LIVE services, never the defined ones — a defined service with no container
  # restarts to a silent exit 0 (see worker_services_live).
  mapfile -t WSVCS < <(worker_services_live)
  # Anything defined but not live is a slot that was never created. Say so:
  # otherwise "restarting: worker-1" reads as if worker-2 were fine.
  missing="$(comm -23 <(worker_services) <(worker_services_live) | tr '\n' ' ')"
  [ -n "${missing// /}" ] && warn "defined but NOT running (never created): ${missing% }"

  if [ ${#WSVCS[@]} -eq 0 ]; then
    DEFERRED=1
    warn "no worker container is running — nothing to restart. Bring the stack"
    warn "up first:  docker compose -p $PROJECT up -d"
  elif [ "$FORCE" = 1 ]; then
    warn "--force: restarting ALL worker slots, killing any in-flight job"
    RESTART_SVCS+=("${WSVCS[@]}")
  else
    scan="$(slot_scan 2>/dev/null || echo 'ALL slot scan failed')"
    case "$scan" in
      IDLE)
        RESTART_SVCS+=("${WSVCS[@]}")
        ;;
      BUSY*)
        busy=" ${scan#BUSY} "
        deferred=()
        for s in "${WSVCS[@]}"; do
          n="${s#worker-}"
          # A bare `worker` (pre-split) has no slot number, so it can never be
          # proven idle here — only the IDLE branch above restarts it.
          if [ "$n" = "$s" ] || [[ "$busy" == *" $n "* ]]; then
            deferred+=("$s")
          else
            RESTART_SVCS+=("$s")
          fi
        done
        if [ ${#deferred[@]} -gt 0 ]; then
          DEFERRED=1
          warn "slots busy with a job — DEFERRING: ${deferred[*]}"
          warn "re-run './deploy.sh --worker' when they finish, or '--force' to kill them."
        fi
        ;;
      *)
        DEFERRED=1
        warn "a job is running/queued but its slot could not be determined:"
        warn "  ${scan#ALL }"
        warn "DEFERRING every worker slot — a queued or just-started job can land"
        warn "on any of them. Re-run './deploy.sh --worker' when idle, or '--force'."
        ;;
    esac
  fi
fi

[ ${#RESTART_SVCS[@]} -eq 0 ] && { ok "nothing to restart."; exit 0; }

svcs="${RESTART_SVCS[*]}"
log "restarting: $svcs (bind-mounted code — no rebuild)"
# shellcheck disable=SC2086
if ! DC restart $svcs 2>&1 | sed 's/^/  /'; then
  err "container restart failed — .last_deploy NOT advanced."
  exit 5
fi

# --- verify ------------------------------------------------------------------
for i in $(seq 1 25); do api_up && break; sleep 1; done
if api_up; then
  ok "api $API_URL/api/health -> 200"
elif [ -n "${WANT[api]:-}" ]; then
  err "restarted api /api/health is not 200 — .last_deploy NOT advanced."
  err "check 'docker compose -p $PROJECT logs api'"
  exit 6
else
  warn "api not 200 — worker restart succeeded, but check 'docker compose -p $PROJECT logs api'"
fi

# --- stamp the deploy so --changed can no-op next time -----------------------
# ONLY when every slot that needed the new code actually got it.
#
# This gate is what stops a deferral from becoming PERMANENT. `modules/` is
# bind-mounted and imported once per worker process, so a slot keeps the code
# it had at ITS last restart. Under the slot split deploy.sh restarts slot 2
# and defers busy slot 1 — and if the stamp advanced anyway, the next
# `--changed` would print "nothing new since last deploy" and exit 0. Slot 1
# would then serve the OLD prompts and modules indefinitely, with no signal
# that anything was wrong: half the jobs on new code, half on old, and nothing
# in meta.json recording which.
#
# Not advancing the stamp makes the next `--changed` retry the deferred slot on
# its own. That is self-correcting, where merely recording the skew would only
# have made it auditable after the fact.
# REBUILD_PENDING earns a place in the same gate for the same reason. This is
# the stamp site that actually fired in practice: no commit in the last 300
# touched runner/ ALONE, they all also touched worker/ or api/, so the run took
# the normal path — WANT non-empty, DEFERRED 0 — restarted the containers,
# stamped HEAD, and the loud "live runner image is STALE" block never appeared
# again because the next `--changed` no-ops on `base = head`. The restart was
# real; the image behind it was not. Same self-correcting shape as above: the
# probe is a live observation, so a rebuild clears it without anyone editing
# .last_deploy.
if [ "$DEFERRED" = 1 ] || [ "$REBUILD_PENDING" = 1 ]; then
  if [ "$DEFERRED" = 1 ]; then
    warn ".last_deploy NOT advanced — a worker slot still runs the OLD code."
    warn "the next './deploy.sh --changed' will retry it automatically; or run"
    warn "'./deploy.sh --worker' once the job finishes."
  fi
  if [ "$REBUILD_PENDING" = 1 ]; then
    warn ".last_deploy NOT advanced — the restart applied the new mounted code,"
    warn "but the live runner image FAILED its compile probe and is still stale."
    warn "run './start.sh --rebuild', then './deploy.sh --changed': the probe"
    warn "passes and the stamp advances on its own. Until then every '--changed'"
    warn "re-diffs from the same baseline and will restart these services again —"
    warn "harmless (an api restart is safe anytime, see USAGE) but not a no-op."
  fi
else
  git rev-parse HEAD > "$LAST_DEPLOY_FILE" 2>/dev/null || true
fi

# stamp web-ui/version.json so the UI version badge shows the deployed commit
[ -x "$PROJECT_DIR/stamp-version.sh" ] && "$PROJECT_DIR/stamp-version.sh" || true

ok "deployed. UI is served no-cache from the ./web-ui mount — just refresh the"
ok "browser (Ctrl-Shift-R) to see UI changes; backend now runs the latest code."
