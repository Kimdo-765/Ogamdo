#!/usr/bin/env bash
# chal-engine — a `qemu-system-*` shim that relocates the call into the
# CHALLENGE'S OWN container, so the emulator the agent tests on is the one the
# target runs.
#
# WHY THIS EXISTS
# A kernel challenge ships its own engine inside its Dockerfile, and its
# launcher invokes that engine BY NAME:
#
#   chal/Dockerfile   FROM ubuntu:24.04 ; apt install qemu-system-x86 -> 8.2.2
#   chal/run.sh       exec qemu-system-x86_64 ...
#   this worker       Debian 13                                       -> 10.0.11
#
# So PATH decides which binary runs, and an agent that copies the challenge's
# launcher perfectly still tests on a build two major versions away. The
# divergence is observable, not theoretical — the iPXE option-ROM base printed
# at boot differs, and the challenge container's value matches the REMOTE's.
#
# One kernel-pwn lineage lost five jobs to this. One job ran its entire
# parameter search on the wrong qemu; another refuted its whole hypothesis
# on the wrong qemu and only then noticed the gap, with no way to act on it.
#
# WHY A PROMPT DID NOT FIX IT
# The guidance WAS fixed first (modules/pwn/prompts.py now says the accelerator
# is part of the machine, and that the emulator itself is a version). Job
# 2a4ecbec367b then ran 12 of its 19 boots on the worker's qemu anyway. The
# actor doing the booting was a `debugger` subagent, and modules/codex_cli.py's
# own comment records why it never saw that guidance:
#
#     "Child agents do not automatically receive the main agent's developer
#      prompt."
#
# Only the output-language policy is copied into role overlays. So the advice
# reached main and main delegated the booting. Same lesson as
# worker/docker_memguard.sh, whose header states it plainly: prompt adherence
# is not a guarantee, and the guarantee is the point. This is the enforcement
# point.
#
# FAILURE MODE IS "DO NOTHING", NEVER "BREAK"
# Every precondition below exits into the real binary. A worker without the
# image, without a job, without a docker socket, or without HOST_DATA_DIR
# behaves exactly as it did before this file existed.

set -u

REAL="${CHAL_ENGINE_REAL:-/usr/bin/$(basename "$0")}"
[ -x "$REAL" ] || REAL="/usr/bin/qemu-system-x86_64"

# The name we were invoked as IS the entrypoint we ask the container for, so
# one shim serves every qemu-system-* symlink pointed at it.
ENGINE="$(basename "$0")"

# WHY THIS SHIM LOGS AT ALL
#
# It shipped silent, and job 1da7e690ddcd then booted 20 times: 14 on the
# worker's qemu, 6 relocated, split cleanly by time. Four hypotheses for the
# bypass were eliminated by test — the symlink is installed, the exec bit is
# set, a login shell still resolves to it, and both eras used relative paths.
# The fifth needs the invocation, and the invocation is not recorded: BOTH
# agent models delegate the booting, and delegated tool calls never reach
# gpt-events.jsonl (13 `wait` events, zero subagent Bash rows).
#
# So the shim is the only witness to its own decisions. Without this it can
# fail on half a job's boots and leave nothing to read.
#
# Written to a FILE, not stderr: the agent parses qemu's output, and a line
# injected there is a line it may try to interpret. The one exception is the
# case where no job can be identified — there is no job-scoped place to write,
# and that is precisely the case most worth seeing, so it goes to stderr with
# a prefix the way worker/docker_memguard.sh already does.
_log_shim() {
    _reason="$1"
    shift
    if [ -n "${JOB:-}" ] && [ -d "/data/jobs/${JOB}/work" ]; then
        _dir="/data/jobs/${JOB}/work/.chalbox"
        mkdir -p "$_dir" 2>/dev/null || return 0
        {
            printf '%s engine=%s %s\n' \
                "$(date -u +%H:%M:%S 2>/dev/null || echo '??:??:??')" \
                "$ENGINE" "$_reason"
            printf '    cwd=%s\n    argv=%s\n' "$PWD" "$*"
        } >> "$_dir/shim.log" 2>/dev/null
    else
        printf '[chal-engine] %s (no job identified; cwd=%s)\n' \
            "$_reason" "$PWD" >&2
    fi
}

# Every precondition exits through here, and each names ITSELF — a log that
# only says "passed through" answers the question one step too late.
_passthrough() {
    _why="$1"
    shift
    _log_shim "PASS-THROUGH: $_why" "$@"
    exec "$REAL" "$@"
}

# ---------------------------------------------------------------- preconditions

# 1. Which job? JOB_ID is set in the agent's session env
#    (modules/_common.py), but a subagent or a detached shell may not carry it,
#    and the booting actor here is USUALLY a subagent. So fall back to the cwd,
#    which is /data/jobs/<id>/... for every agent shell.
JOB="${JOB_ID:-}"
if [ -z "$JOB" ]; then
    case "$PWD" in
        /data/jobs/*)
            JOB="${PWD#/data/jobs/}"
            JOB="${JOB%%/*}"
            ;;
    esac
fi
[ -n "$JOB" ] || _passthrough "no JOB_ID and cwd is not under /data/jobs" "$@"

# 2. HOST_DATA_DIR is needed because the bind source is a HOST path — the
#    docker daemon resolves it, not this container.
#
#    NON-EMPTY IS NOT THE SAME AS CORRECT, and the difference was silent and
#    total. .env.example ships the line as a placeholder,
#
#        HOST_DATA_DIR=/home/youruser/HexTech_CTF_TOOL/data
#
#    start.sh only WARNS that it must be edited, and nothing checks it. On
#    this deployment it was never edited, so every relocation bind-mounted
#    that path — which does not exist, so the daemon CREATED it, root-owned
#    and empty. The challenge container then booted against a directory with
#    no ./chal, no bzImage and no exploit: /home/youruser/... was found on
#    disk holding nothing but empty work/ dirs for three job ids. The boots
#    that "passed through" at least ran on real files; the ones that
#    relocated ran on nothing, and shim.log called them RELOCATED either way.
#
#    So do not trust the variable. The daemon can be asked what this
#    container's /data ACTUALLY resolves to, and that answer is authoritative
#    by construction — it is the same mount the job tree is read through.
#    Fall back to the env var only when the query fails, and say so either
#    way: a corrected value is exactly the kind of thing that must not be
#    silent twice.
_true_data_src="$(docker inspect "$(hostname)" \
    --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' \
    2>/dev/null | head -1)"
if [ -n "$_true_data_src" ] && [ "$_true_data_src" != "${HOST_DATA_DIR:-}" ]; then
    _log_shim "HOST_DATA_DIR CORRECTED: env said '${HOST_DATA_DIR:-<unset>}', the /data mount really is '$_true_data_src'" "$@"
    HOST_DATA_DIR="$_true_data_src"
fi
[ -n "${HOST_DATA_DIR:-}" ] || _passthrough "HOST_DATA_DIR unset — the bind source is a HOST path" "$@"

# 3. The image must already exist. modules/_chalbox.py builds it at job start,
#    off the critical path, precisely so this check passes before the agent's
#    first boot. Building HERE would be worse than not relocating: an agent's
#    boot is routinely wrapped in `timeout 30`, and a cold build is minutes —
#    it would eat the very call it exists to fix.
IMAGE="chal_${JOB}"
docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || _passthrough "no image $IMAGE (chalbox did not build, or docker is unreachable)" "$@"

# 4. Every path the caller named must be REACHABLE after relocation. The
#    container mounts /data/jobs/<id> and nothing else, so an absolute path
#    outside it — /tmp/payload, /opt/something — exists on the worker and not
#    in the container.
#
#    Found by running this shim, not by reading it: the first end-to-end test
#    passed `-hda /tmp/dummy_payload` and the guest simply never booted. That
#    is a BREAK, not a no-op, and the whole design rule here is that a
#    precondition failure must leave the caller exactly as it was. The agent's
#    own TMPDIR is /data/jobs/<id>/work/tmp (modules/_common.py sets it), so
#    scratch files are inside the mount in normal use and this rarely fires.
#
#    Relative paths resolve by construction — but only because -w "$PWD"
#    reproduces the cwd on the far side, which is a guarantee only while the
#    cwd is itself inside the mount. The loop below judges them against $PWD
#    for exactly that reason.
for _arg in "$@"; do
    # The spelling the caller used, kept because $_arg is narrowed below and
    # the NEXT argument's -append test has to see the option, not the token.
    _whole="$_arg"

    # WHICH STRING IS "A PATH THE CALLER NAMED"? Not always the argument.
    # qemu's canonical way of naming a file is INSIDE an option value:
    #
    #   -drive file=/tmp/x,format=raw       -chardev socket,path=/tmp/mon
    #   -drive if=pflash,file=/tmp/OVMF.fd  -fsdev local,path=/tmp/share
    #   -serial file:/tmp/log               -qmp unix:/tmp/q.sock,server
    #
    # None of those STRINGS begins with '/', so the rule below, reading only
    # "$_arg", walked past every one of them. Measured with a recorder in
    # place of docker: `-hda /tmp/exists.img` passed through correctly, while
    # the SAME file spelled `-drive file=/tmp/exists.img,format=raw`
    # relocated into a container where /tmp/exists.img does not exist. That is
    # the `-hda /tmp/dummy_payload` break above, in the spelling agents
    # actually write.
    #
    # So pick the token the rule should judge before running it: the argument
    # as spelled when the argument IS a path this worker has, otherwise the
    # most damning fragment inside it.
    #
    # COMMA IS THE ONLY SEPARATOR SPLIT ON, and the split is quoted parameter
    # expansion. Splitting on ':' and '=' as well, unquoted, was tried and is
    # wrong twice over: the shell then word-splits on spaces too, so
    # `-append "console=ttyS0 init=/bin/sh quiet"` yields the fragment
    # /bin/sh — which exists on every worker — and the shim would give up on
    # precisely the kernel boots it exists for; and an argument containing '*'
    # would be pathname-expanded before the -e test ever saw it.
    _cand=""
    _rel=""
    _rest="$_arg"
    case "$_arg" in
        # Judge a real path as the caller spelled it, so that a filename which
        # merely CONTAINS a comma is never shredded into fragments.
        /*) [ -e "$_arg" ] && _rest="" ;;
    esac
    # -append is the GUEST's kernel command line. Its key=value tokens name
    # guest devices and guest binaries (root=/dev/vda1, init=/bin/sh), never
    # files this worker opens, so it stays judged whole exactly as before and
    # is never taken apart. Both dash spellings, for the reason the
    # accelerator block below records.
    case "${_prev:-}" in
        -append|--append) _rest="" ;;
    esac
    while [ -n "$_rest" ]; do
        _frag="${_rest%%,*}"
        case "$_rest" in
            *,*) _rest="${_rest#*,}" ;;
            *)   _rest="" ;;
        esac
        # `file=/tmp/x` -> `/tmp/x`, then `unix:/tmp/q.sock` -> `/tmp/q.sock`:
        # one leading key= and one leading scheme:, each dropped only when the
        # half being dropped is a bare word. A half that already contains '/'
        # is part of the path, not a label for it.
        case "$_frag" in
            *=*) case "${_frag%%=*}" in */*) ;; *) _frag="${_frag#*=}" ;; esac ;;
        esac
        case "$_frag" in
            *:*) case "${_frag%%:*}" in */*|"") ;; *) _frag="${_frag#*:}" ;; esac ;;
        esac
        case "$_frag" in
            /data/jobs/"$JOB"/*) [ -n "$_cand" ] || _cand="$_frag" ;;
            # An outside fragment that EXISTS is the one the rule will act on,
            # so it wins outright. One that does not exist is remembered only
            # in case nothing better turns up: a fragment this worker does not
            # have must not shadow a later one it does, or
            # `-fw_cfg name=/opt/x,file=/tmp/real` would hide /tmp/real.
            /*) if [ -e "$_frag" ]; then _cand="$_frag"; break; fi
                [ -n "$_cand" ] || _cand="$_frag" ;;
            ""|-*) ;;
            *) [ -n "$_rel" ] || _rel="$_frag" ;;
        esac
    done
    if [ -n "$_cand" ]; then
        _arg="$_cand"
    elif [ -n "$_rel" ]; then
        # THE CWD IS PART OF THE PRECONDITION, NOT A GIVEN. A relative name
        # survives relocation only because -w "$PWD" recreates the cwd inside
        # the container, and that holds only while the cwd is itself inside
        # the one directory this run mounts. $PWD is consulted in precondition
        # 1 solely as a FALLBACK for a missing JOB_ID, so on the normal path
        # — JOB_ID set, which is what modules/_common.py puts in the session
        # env — nothing ever compared it with the mount: a boot from /tmp
        # with `-kernel ./bzImage` relocated into a workdir docker CREATES
        # EMPTY, and the kernel simply was not there.
        #
        # Resolving the name against $PWD hands that boot to the rule below
        # instead. Deliberately narrow, for the same reason the -e test exists
        # at all: an existing file is evidence, a bare string is not. A call
        # whose paths are all absolute and inside the mount therefore keeps
        # relocating even from an outside cwd — there the unmounted -w harms
        # nothing, and refusing would send a boot that works today to the
        # worker's qemu. What stays uncovered is a relative name for a file
        # that does not exist YET, an output the container would write into
        # the empty workdir and lose.
        case "$PWD" in
            /data/jobs/"$JOB"|/data/jobs/"$JOB"/*) ;;
            *) _arg="${PWD%/}/$_rel" ;;
        esac
    fi

    case "$_arg" in
        /data/jobs/"$JOB"/*) ;;
        # Standard device nodes are not job files. Every image carries them
        # with identical semantics, so relocation cannot make them
        # unreachable, and the check below must not read them as evidence
        # that it should give up.
        #
        # This exemption is load-bearing, not tidiness. The CHALLENGE'S OWN
        # launcher passes `-monitor /dev/null` (chal/run.sh in one kernel-pwn
        # lineage), so an agent that copies the canonical invocation — the
        # exact behaviour this shim exists to reward — trips the
        # reachability rule and pass-throughs to the worker's qemu. Job
        # 24225668a27d booted twice and shim.log records both as
        # "PASS-THROUGH: argument /dev/null is outside the job mount",
        # i.e. the faithful invocation was the one guaranteed to run on the
        # wrong build. The header's "this rarely fires" was measured against
        # scratch paths and missed the launcher's own fixed arguments.
        #
        # The list is deliberately CLOSED, and short. Two categories stay
        # out of it because they are exactly the unreachability this rule
        # is for:
        #   · block devices — /dev/sda names a different disk inside;
        #   · per-process fds — /dev/fd/63 from a `<(...)` process
        #     substitution exists on the worker and names something else,
        #     or nothing, in the container. /dev/tty is the same shape:
        #     the relocation runs `docker run -i` with deliberately no -t
        #     (see below), so a controlling terminal the worker has is one
        #     the container does not.
        # The five below are character devices every image carries with
        # identical semantics; the three std streams are forwarded by -i.
        /dev/null|/dev/zero|/dev/full|/dev/random|/dev/urandom) ;;
        /dev/stdin|/dev/stdout|/dev/stderr) ;;
        /*)
            # A bare flag like -nographic never matches /*; a value that looks
            # like an outside path does. Only treat it as a path when it
            # actually exists on the worker — otherwise a string that merely
            # starts with / (a -append value, say) would disable the shim.
            if [ -e "$_arg" ]; then
                _passthrough "argument $_arg is outside the job mount and exists on this worker" "$@"
            fi
            ;;
    esac
    _prev="$_whole"
done

# ------------------------------------------------------------------- accelerator

# The accelerator is part of the machine, not a speed knob, so it is NOT
# stripped or added — whatever the caller asked for is what runs. But KVM needs
# the device, and a container does not get it by default. Pass it through only
# when the caller actually asked, and only when the host really has it: a
# --device for a missing node fails the run, which would violate the
# do-nothing-on-doubt rule above.
KVM_ARGS=""
# Both dash spellings, because qemu takes both.  `qemu-system-x86_64
# --enable-kvm` is accepted (verified against the shipped 6.2.0), and the
# single-dash-only patterns below could never match it: in " --enable-kvm "
# the character before `-enable-kvm` is another dash, not the space the
# pattern requires.  An agent that writes the GNU-style form therefore got
# relocated WITHOUT the device, qemu failed to initialise KVM inside the
# container, and shim.log still recorded "RELOCATED" — a boot that died for a
# reason the log denied.  Matching wide is the safe direction here: a spurious
# --device on a host that has the node is harmless, a missing one is fatal.
case " $* " in
    *" -enable-kvm "*|*" --enable-kvm "*|\
    *" -accel kvm"*|*" --accel kvm"*|*"accel=kvm"*)
        if [ -c /dev/kvm ]; then
            KVM_ARGS="--device /dev/kvm"
        fi
        ;;
esac

# --------------------------------------------------------------------- relocate

# -w "$PWD" with a bind at the SAME absolute path is what makes the caller's
# arguments work untouched — relative paths like ./chal/bzImage and absolute
# ones like /data/jobs/<id>/work/chal/flag both resolve. modules/_runner.py
# uses the same trick and its comment records why.
#
# -i keeps stdin attached (a -nographic guest reads it); deliberately no -t,
# which would break piped input.
#
# --label is what reap_chal_containers cleans by, and matters here because a
# `timeout` that kills this client can leave the container behind.
#
# `docker` resolves to worker/docker_memguard.sh, which injects --memory and
# --cpus. That is wanted: a challenge VM started this way is a sibling cgroup
# that nothing else bounds.
# Log the relocation too, so the file is a COMPLETE record rather than a list
# of failures. "Six boots relocated and fourteen did not" is only readable if
# both halves are written; a log of pass-throughs alone cannot distinguish a
# shim that fired twenty times from one that never ran at all.
# PRESENT TENSE, DELIBERATELY. This line is written BEFORE the exec, so it
# records an INTENT, not an outcome — the process is replaced on the next
# line and can never come back to amend it. Written as "RELOCATED" it read as
# proof the boot ran, and that is exactly how a total failure hid: with
# HOST_DATA_DIR pointing at a placeholder path, nineteen boots mounted an
# empty daemon-created directory and every one of them was logged
# "RELOCATED into chal_<id>". A log that cannot be wrong about the outcome
# must not claim one.
_log_shim "RELOCATING into ${IMAGE}${KVM_ARGS:+ (+kvm device)} (intent; the exec below replaces this process, so no result line follows)" "$@"

exec docker run --rm -i \
    --label "hextech_job=${JOB}" \
    ${KVM_ARGS} \
    -v "${HOST_DATA_DIR}/jobs/${JOB}:/data/jobs/${JOB}" \
    -w "$PWD" \
    --entrypoint "$ENGINE" \
    "$IMAGE" "$@"
