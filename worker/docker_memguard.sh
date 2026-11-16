#!/usr/bin/env bash
# docker-memguard — a `docker` shim that injects a memory cap into `docker run`
# / `docker create` when the caller did not set one.
#
# WHY THIS EXISTS
# Each worker slot container is capped by a cgroup (WORKER_SLOT_MEM), but every
# container the AGENT starts is a SIBLING — a separate cgroup no slot's cap
# bounds. Nothing taught the agent to pass --memory, so challenge
# containers ran unlimited.
#
# 2026-08-01, job 0ddd62708d39: the chal image ran a socat fork-per-connection
# launcher, so every connection forked a fresh copy of the challenge binary,
# and each one grew ~1-2 GiB
# per minute with no ceiling (measured: 2780 -> 2837 -> 2921 -> 3071 MiB over
# ~80 s on one process). The exploit reconnected repeatedly. WSL2 died at 22:21:50 with the VM out of memory and
# — the tell — NO container recorded OOMKilled, because an uncapped container
# has no cgroup limit to hit: the kernel ran out globally instead.
#
# A prompt line asking for --memory would not fix this; prompt adherence is not
# a guarantee, and the guarantee is the point. This is the enforcement point.
#
# SCOPE — deliberately narrow:
#   * `run` and `create` only. Every other subcommand is exec'd untouched.
#   * If the caller already passed --memory / -m in any form, nothing changes.
#   * The orchestrator's own sibling containers (runner / decompiler x2 /
#     forensic / misc / misc_recarve / web terminal) go through the docker-py
#     SDK, not this CLI, so this file does not bound them — each sets its own
#     mem_limit, memswap_limit and nano_cpus at the call site, and
#     scripts/test_worker_cpu_limit.py enumerates those sites by AST so a new
#     one cannot be added uncapped. The callers that DO reach this shim are the
#     agent's Bash and worker/chal_libc_fix.py.
#
# CPU LEAKS THE SAME WAY, and it went unbounded for as long as memory did.
# 2026-08-25, job 0a22d7fa7919: an agent fanned its own search into 36
# processes and took 2467% CPU on a 32-core host (load average 45.8) while
# eight other slots crawled. Nothing misbehaved — there was simply no ceiling.
# Worker slots and the runner are now capped at 8 CPUs each; a container the
# AGENT starts is a sibling of both and is bounded here, or nowhere.
#
# --cpus is injected the same way --memory is, and for the same reason: a later
# occurrence of the flag wins, so a caller's own --cpus (which necessarily
# comes after ours) overrides it for free. VERIFIED, not assumed — docker
# 29.6.1, `--cpus 1 --cpus 4` yields cpu.max 400000/100000 and `--cpus 8
# --cpus 2` yields 200000/100000.
#
# TUNING: CHAL_CONTAINER_MEM (default 2g) and CHAL_CONTAINER_CPUS (default 8).
# Disable a cap with `0`. NOT by setting it empty: compose passes these through
# `${VAR:-default}`, which substitutes the default for an EMPTY value as well as
# an unset one, so an empty .env entry arrives here AS THE DEFAULT. `0` is the
# only spelling that reaches this file as a disable.
# NOTE also that CHAL_CONTAINER_MEM=0 alone no longer makes the shim fully
# transparent, because the CPU cap is a separate guarantee. Set BOTH to 0 for
# the old pass-through-everything behaviour.

set -o pipefail
# Overridable ONLY so the guard can be tested by pointing it at a recorder that
# prints its argv instead of starting a container. Production never sets it;
# an unset variable keeps the previous hard-coded path exactly.
REAL="${DOCKER_MEMGUARD_REAL:-/usr/bin/docker}"
LIMIT="${CHAL_CONTAINER_MEM-2g}"
CPUS="${CHAL_CONTAINER_CPUS-8}"

_off() { [ -z "$1" ] || [ "$1" = "0" ]; }

# Both caps disabled, or the real docker is missing → behave exactly like
# plain docker.
if { _off "$LIMIT" && _off "$CPUS"; } || [ ! -x "$REAL" ]; then
    exec "$REAL" "$@"
fi

# THE SUBCOMMAND SCAN, AND WHY IT IS NOT JUST "FIRST NON-DASH ARGUMENT".
# A handful of docker's GLOBAL flags carry their value in a SEPARATE argument,
# and that value does not begin with `-`. A naive first-non-dash scan therefore
# reads the VALUE as the subcommand. Reproduced with an argv recorder in front
# of the real binary:
#   docker -H unix:///var/run/docker.sock run --rm alpine
#   docker -c default run --rm alpine
#   docker --log-level debug run --rm alpine
#   docker --config /tmp/cfg run --rm alpine
# every one of those resolved the subcommand to the flag's value, matched
# neither `run` nor `create`, and exec'd the real docker untouched: no
# --memory, no --cpus, AND no job label. For this file that is not a benign
# "does nothing" — an uncapped sibling container is exactly what took the WSL2
# VM out of memory on 2026-08-01 (job 0ddd62708d39, above), and an unlabelled
# one is invisible to `_hard_stop_job` and to the end-of-job sweep in
# modules/_common.reap_job_siblings, so the leak could not even be cleaned up
# afterwards.
#
# The set below is the closed one, not a guess: `docker --help` on 29.6.1 (the
# snap daemon this host runs) lists exactly seven `string`-typed entries under
# Global Options — --config, -c/--context, -H/--host, -l/--log-level,
# --tlscacert, --tlscert, --tlskey. The remaining globals (-D/--debug, --tls,
# --tlsverify, -v/--version) are booleans and consume nothing, so skipping
# their successor would be the same bug pointed the other way.
#
# The `--flag=value` and attached-shorthand `-Hvalue` spellings need no entry:
# each stays a SINGLE token that still begins with `-`, so it is already
# consumed whole — `-H=unix:///x run`, `--log-level=debug run` and
# `-Hunix:///x run` all injected correctly even before this change, while their
# space-separated twins did not. Anything unrecognised keeps the old
# pass-through contract: an unknown flag is skipped without eating the next
# argument, so at worst the shim declines to act rather than mangling
# somebody's command line.
_takes_value() {
    case "$1" in
        -H|--host|-c|--context|-l|--log-level|--config|\
        --tlscacert|--tlscert|--tlskey) return 0 ;;
        *) return 1 ;;
    esac
}

args=("$@")

# Index of the first non-flag argument at or after $1, or -1 if there is none.
# Deliberately does NOT consult _takes_value: global flags only appear BEFORE
# the subcommand, and past that point the same spellings mean something else
# entirely (`docker run -c 512 img` is --cpu-shares, not --context), so
# skipping their argument there would be a new bug of the same family.
_positional_after() {
    local j="$1"
    while [ "$j" -lt "${#args[@]}" ]; do
        case "${args[$j]}" in
            -*) ;;
            *) echo "$j"; return 0 ;;
        esac
        j=$((j+1))
    done
    echo -1
}

sub=""; sub_idx=-1
i=0
while [ "$i" -lt "${#args[@]}" ]; do
    case "${args[$i]}" in
        -*) if _takes_value "${args[$i]}"; then i=$((i+2)); else i=$((i+1)); fi ;;
        *) sub="${args[$i]}"; sub_idx=$i; break ;;
    esac
done
[ "$sub_idx" -ge 0 ] || exec "$REAL" "$@"

# `docker network create` leaks the same way containers do, and worse in one
# respect: docker's default address pool is finite, so accumulated
# `chal_<id>_net` bridges eventually fail new job setups outright with "could
# not find an available, non-overlapping IPv4 address pool". Three orphaned
# networks with zero attached containers were found 2026-08-02. Labelling them
# lets the end-of-job sweep in modules/_common.reap_job_siblings take them
# back. No --memory here — a network has no cgroup.
if [ "$sub" = "network" ] && [ -n "${JOB_ID:-}" ]; then
    nidx=$(_positional_after $((sub_idx + 1)))
    if [ "$nidx" -ge 0 ] && [ "${args[$nidx]}" = "create" ]; then
        out=("${args[@]:0:$((nidx + 1))}" \
             --label "hextech_ctf_tool_job_id=$JOB_ID" \
             "${args[@]:$((nidx + 1))}")
        echo "[docker-memguard] tagged network with hextech_ctf_tool_job_id=$JOB_ID" >&2
        exec "$REAL" "${out[@]}"
    fi
fi

# `docker container run` is the same operation as `docker run` and used to walk
# straight past this guard: the first non-flag argument is `container`, which
# matched neither arm, so the shim exec'd the real docker untouched. An agent
# does not have to know that to hit it -- it is the spelling docker's own
# reference pages use. Resolve the pair and inject after the real subcommand.
inject_idx=$sub_idx
if [ "$sub" = "container" ]; then
    cidx=$(_positional_after $((sub_idx + 1)))
    csub=""; [ "$cidx" -ge 0 ] && csub="${args[$cidx]}"
    case "$csub" in
        run|create) inject_idx=$cidx ;;
        *) exec "$REAL" "$@" ;;
    esac
else
    case "$sub" in
        run|create) ;;
        *) exec "$REAL" "$@" ;;
    esac
fi

# Inject unconditionally, immediately after the subcommand — do NOT try to
# detect an existing --memory first. Verified against docker 28: when the flag
# appears twice the LAST occurrence wins, so a caller's own --memory / -m,
# which necessarily comes later on the line, overrides this default for free.
#
# Scanning was the first implementation and it was WRONG: the args include the
# CONTAINER's own command line, so `docker run img cmd --memory ignored` looked
# pre-capped and the container launched unlimited — the exact case the guard
# exists for. A test caught it. No scan, no gap.
#
# The splice is by INDEX, not by matching the subcommand's string value. The
# string form injected after the FIRST argument that merely READ like the
# subcommand, so `docker -c run run --rm alpine` — a context literally named
# `run` — emitted `[--context] [--memory] [2g] ... [run] [--rm] [alpine]`,
# handing our own flag to --context as its value and malforming the command
# line. sub_idx / inject_idx are the positions the scan actually settled on, so
# there is nothing left to re-match and nothing to get wrong.
#
# Only --memory is injected, never --memory-swap: a caller passing --memory 8g
# would otherwise be paired with our 2g swap and docker rejects memory-swap <
# memory. RAM is what we are bounding; swap defaults still apply.
#
# The job label rides along for two reasons, and the second one is the bigger
# win. It makes the container ATTRIBUTABLE in the Containers tab — without it
# an agent-started container carries no trace of which job made it, and once
# that job's directory is deleted the link is gone for good (measured
# 2026-08-02: of 12 orphaned challenge containers, only the 3 whose names
# happened to embed a job id could be attributed at all). And it makes the
# container REAPABLE: api/routes/jobs.py `_hard_stop_job` already force-removes
# every sibling labelled `hextech_ctf_tool_job_id=<id>`, so labelling closes
# the leak itself rather than only reporting it.
#
# JOB_ID is exported into the agent's environment by the orchestrator and this
# shim runs as a descendant of the agent's Bash, so it is inherited (verified
# live on job 926773a15d8b). Omitted entirely when unset — an unlabelled
# container is the status quo, whereas a label reading `=` would be a lie that
# `_hard_stop_job` could match against the wrong thing.
inj=(); applied=""
if ! _off "$LIMIT"; then
    inj+=(--memory "$LIMIT"); applied="$applied --memory $LIMIT"
fi
if ! _off "$CPUS"; then
    inj+=(--cpus "$CPUS"); applied="$applied --cpus $CPUS"
fi
if [ -n "${JOB_ID:-}" ]; then
    inj+=(--label "hextech_ctf_tool_job_id=$JOB_ID")
fi
out=("${args[@]:0:$((inject_idx + 1))}" \
     ${inj[@]+"${inj[@]}"} \
     "${args[@]:$((inject_idx + 1))}")

echo "[docker-memguard] defaults applied:${applied:- none}" \
     "${JOB_ID:+plus label hextech_ctf_tool_job_id=$JOB_ID }" \
     "(pass the flag yourself to override, or set" \
     "CHAL_CONTAINER_MEM=0 / CHAL_CONTAINER_CPUS=0)" >&2
exec "$REAL" "${out[@]}"
