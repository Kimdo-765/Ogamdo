"""Per-slot memory: always-on usage sampling, optional dynamic caps.

TWO HALVES, DELIBERATELY UNEQUAL.

  * The SAMPLER runs unconditionally. It is read-only — one
    `/sys/fs/cgroup/memory.current` read measured at 0.007 ms — and it is the
    only thing that will ever produce a defensible base cap. Gate it behind the
    feature flag and the day the flag is switched ON there is nothing to size
    from, which is the blind-tuning state a three-round review existed to avoid.

  * The GOVERNOR (changing a cap) runs only when `dynamic_worker_mem` is ON.
    Default OFF means the stack behaves exactly as it does today: the
    `worker_slot_mem` setting is the sole authority and no cgroup moves.

WHY A SLOT-WIDE LOCK AND NOT A JOB-SCOPED ONE.
The contended resource is the VM's memory budget, which every slot shares. A
lock in the job's own directory cannot serialise two slots — they are separate
containers, separate processes, and their `work_dir`s never collide. This repo
already paid for that lesson: `codex_turn_guard` locks `work_dir`, so two
retries of the same lineage never met on the guard and collided inside Codex
instead (job 7cf810bfe449, 2026-08-23). The lock here lives on the shared
`/data` mount, which both slots see.

WHY THE READ AND THE WRITE ARE IN THE SAME CRITICAL SECTION.
The budget check is `sum(other slots' caps) + want <= 70% of the VM`. Computing
that outside the lock is worthless: two slots can both read "the other one is
at 2g", both conclude 8g fits, and both write — 16 GiB of ceiling inside a
15.6 GiB VM, which is the unbounded condition that froze WSL on 2026-07-29 and
2026-08-01. Re-read every cap INSIDE the lock, decide, write, verify.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

CGROUP = Path("/sys/fs/cgroup")
LOCK_PATH = Path("/data/.worker-memory.lock")
SAMPLE_INTERVAL_S = 5.0

# What makes a container a slot, for the budget sum in `_worker_containers`.
SLOT_NAME_MATCH = "worker-"


def _slot_name_match() -> str:
    """The slot-name fragment, read from the environment AT CALL TIME.

    Not a module constant a test can monkeypatch, and the difference is not
    stylistic. `run_one_worker` is launched with
    `multiprocessing.get_context("spawn")` (worker/runner.py), so the child
    re-imports this module from source and any attribute a parent had patched
    is gone. A simulation that patched the constant would therefore fall back
    to "worker-" inside the very process that dispatches jobs — and would then
    point the governor at the PRODUCTION slots while reporting that it had
    isolated itself. That is worse than an untested feature.

    An env var survives spawn, and reading it per call means nothing caches a
    stale answer. Production never sets it; the default is the shipped value.
    """
    return os.environ.get("WORKER_SLOT_NAME_MATCH") or SLOT_NAME_MATCH

# The share of the VM that worker slot caps may claim in total. Same number and
# same reason as api/routes/settings.py: the remainder is kernel, dockerd, the
# api and redis containers, and the challenge containers an agent starts as
# siblings of its slot.
#
# 0.70 -> 0.85 (operator, 2026-09-04). The old value was chosen for a 15.6 GB
# WSL host, where 30% was 4.7 GB and the margin was genuinely thin. This host
# is 84.3 GB, so 30% left 25 GB idle while the gate refused real work: the sum
# here counts every slot's CAP, and 11 idle slots hold 47.2 GB of reservations
# they cannot use (12 slots exist, worker_concurrency is 3). Job 23250acbdeeb
# climbed 4.29 -> 6.44 -> 9.66 GB, then asked for 14.5 GB after an OOM and was
# refused at 47.2 + 14.5 > 59.0 — while the host had 79.3 GB free. It OOM-killed
# twice. At 0.85 the same slot may take 24.4 GB and the ladder runs to its
# ceiling; 12.6 GB still stands aside for the OS and the sibling containers.
TOTAL_BUDGET_FRACTION = 0.85

# A cap must clear the slot's unreclaimable footprint by this much. A cap set AT
# the live footprint passes a naive `want > usage` test and then OOM-kills on
# the very next allocation while reporting success.
SHRINK_HEADROOM = 1.5

# Modules whose work is a solver rather than a driver. Provisional: the sampler
# exists precisely so this list and the factor below can be replaced by measured
# distributions instead of intuition. The 88-job census put real worker-side OOM
# at rev 2, web 1, pwn 0, crypto 0 — pwn is absent because every pwn OOM in that
# census was the QEMU guest or the target binary, neither of which lives in the
# slot's cgroup, so raising the slot cap would have changed nothing.
#
# web was here on that evidence (1 OOM) and the operator removed it on
# 2026-08-25, narrowing the start-time expansion to rev and crypto.
#
# Be precise about what web loses, because "one OOM buys it back" is NOT true.
# From a 2g base the ladder is 2 -> 3 -> 4.5 GiB, so ONE escalation reaches
# 3 GiB — still under the 4 GiB the sampled web jobs actually ran at. web needs
# BOTH escalations to clear that, and it pays for each with a killed process.
# That is the operator's tradeoff to make, not a cost to paper over: if web
# starts OOMing at 2g, the fix is a larger base, not a comment claiming it is
# covered.
EXPANSION_MODULES = frozenset({"rev", "crypto"})

# What an expansion module starts at: a MULTIPLE of the operator's base, not a
# fixed size. The previous `max(base, 8 GiB)` floor ignored the base entirely
# below 8 GiB — setting the base to 2g moved rev/crypto not at all, which is
# not what a per-slot setting should mean. Scaling keeps the operator's number
# authoritative: base 2g gives rev 4g, base 4g gives 8g.
#
# Deliberately NOT clamped to the total budget here. `desired_cap_bytes` says
# what this slot WANTS; `apply_cap` is the single place that decides what is
# allowed, under the flock, against every other slot's current cap. Bounding it
# twice would put the same policy in two places and let them disagree.
EXPANSION_FACTOR = 2

# Escalation on a real OOM, and the ceiling it may not pass. 1.5x is the
# operator's number; the cap on the number of escalations is not — an unbounded
# ladder would walk a single slot into the whole budget.
# THE HIGH-WATER MARK — expand BEFORE the kill, not after it.
#
# `OomEscalator` below is reactive by design and says so plainly: it cannot
# help the process that already died. That was a fair trade while a round was
# one child. It stopped being one when rounds went concurrent: job
# cc38cfa29161 measured ~0.61 GB per delegate child against a 4.29 GB slot
# (0.66 GB idle, 2.48 GB at three children, 448 cgroup samples), so a round of
# eight projects to ~5.5 GB and the first symptom would be a dead job.
#
# Operator decision, 2026-09-03: expand when OBSERVED usage crosses this
# fraction of the CURRENT cap. Lowered 0.80 -> 0.70 by operator decision on
# 2026-09-08, because the race below stopped being theoretical. The sampler
# caught three expansions at 81%, then 90%, then 100% of the cap — the last on
# job d94336686a22 with 76 KB of headroom left, and that slot climbed
# 4.3 -> 5.7 GB in the six seconds after. A lower trigger does not close the
# race; it starts the expansion further from the wall.
#
# THIS IS A RACE AND THAT IS UNDERSTOOD. The sampler wakes every
# SAMPLE_INTERVAL_S (5 s); several children booting QEMU can cross 80% and
# then the cap inside one window, and this fires too late. It is a strict
# improvement on waiting for the kill — not a guarantee against one. The
# guarantee would have to be computed BEFORE the children are launched, from
# a count the orchestrator already knows; that is a different change and this
# is not it.
HIGH_WATER_FRACTION = 0.70

# The same 1.5x step the OOM ladder uses, and for the same reason: it clears
# a full extra child (0.61 GB) at every cap this deployment runs at, without
# claiming a doubling the shared budget may not have to give.
HIGH_WATER_FACTOR = 1.5

# A proactive trigger fires far more often than an OOM does, so the ladder is
# bounded the same way.
#
# Was 2, on the reasoning that two steps from 4.29 GB reach 9.7 GB and that is
# past anything the measured per-child cost projects for a full round. Job
# 4aa002418ca0 falsified the PREMISE, not the arithmetic: a forensic run
# reconstructing an 11.25 GB multipart archive is not a round of delegate
# children, it is one process whose working set the per-child model says
# nothing about. It climbed 4 -> 6 -> 9 GiB, logged "already expanded 2 times
# — not raising further" at 02:52:50, and was OOM-killed at 02:57:45. The
# escalator then raised the cap to 13.5 GiB — twenty seconds after the summary
# agent had already returned is_error=true.
#
# Operator decision, 2026-09-08: a third step, which reaches that same 13.5 GiB
# BEFORE the kill instead of after it.
#
# Only NON-expansion modules gain anything. rev and crypto start at
# base x EXPANSION_FACTOR, so MAX_CAP_FACTOR already clamps their second step
# and a third changes nothing for them. From a 4 GiB base the new ladder is
# 4 -> 6 -> 9 -> 13.5 GiB against a 16 GiB ceiling, so no step is clamped, and
# one slot at 13.5 GiB beside eleven at base is 57.5 GiB against the ~71 GiB
# TOTAL_BUDGET_FRACTION allows on this host — grantable, not merely wanted.
#
# MAX_ESCALATIONS is a separate ladder and is deliberately left at 2.
MAX_HIGH_WATER_STEPS = 3

OOM_ESCALATION_FACTOR = 1.5
MAX_ESCALATIONS = 2

# The absolute ceiling any one slot may reach, as a multiple of the base.
#
# MAX_ESCALATIONS alone does NOT bound this, because the ladder starts from the
# slot's CURRENT cap and an expansion module already starts at base x
# EXPANSION_FACTOR. With base 2g that ladder runs 4 -> 6 -> 9 GiB, i.e. base x
# 4.5, and the step count is the only thing that stopped it — raise
# MAX_ESCALATIONS or EXPANSION_FACTOR and the reachable maximum moves with it,
# silently. A ceiling expressed against the base is the bound that stays true
# when those two change.
#
# It binds where the step count does not: rev at base 2g wants 4 -> 6 -> 9, and
# the second step is clamped to 8. A non-expansion module (2 -> 3 -> 4.5) never
# reaches it, so this costs nothing in the common case.
MAX_CAP_FACTOR = 4


# --------------------------------------------------------------------------
# cgroup reads (in-container, read-only)
# --------------------------------------------------------------------------

def _read_int(name: str) -> Optional[int]:
    try:
        return int((CGROUP / name).read_text().strip())
    except Exception:
        return None


def _read_events() -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        for line in (CGROUP / "memory.events").read_text().splitlines():
            parts = line.split()
            if len(parts) == 2:
                try:
                    out[parts[0]] = int(parts[1])
                except ValueError:
                    pass
    except Exception:
        pass
    return out


def sample() -> dict[str, Any]:
    """One reading of this slot's own cgroup. Never raises."""
    ev = _read_events()
    return {
        "ts": time.time(),
        "current": _read_int("memory.current"),
        "max": _read_int("memory.max"),
        "peak": _read_int("memory.peak"),
        "oom_kill": ev.get("oom_kill"),
        "oom": ev.get("oom"),
    }


def _unreclaimable() -> Optional[int]:
    """anon + slab: the part of the footprint that shrinking cannot reclaim.

    This is the floor a new cap has to clear. `memory.current` includes page
    cache, which the kernel will drop under pressure, so using it as the floor
    refuses caps that would in fact have been fine.
    """
    try:
        stat = {}
        for line in (CGROUP / "memory.stat").read_text().splitlines():
            k, _, v = line.partition(" ")
            try:
                stat[k] = int(v)
            except ValueError:
                pass
        anon = stat.get("anon", 0)
        slab = stat.get("slab", 0)
        return anon + slab or None
    except Exception:
        return None


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------

def own_container_name() -> Optional[str]:
    """This worker's own container, as docker knows it.

    The hostname is the short container id unless someone overrides it, so ask
    docker to resolve it rather than reconstructing `<project>-worker-<slot>`
    from env — that string is a compose detail and has already been renamed
    once.
    """
    try:
        import docker  # type: ignore

        client = docker.from_env()
        c = client.containers.get(socket.gethostname())
        return getattr(c, "name", None)
    except Exception:
        return None


def parse_mem(value: str | int | None) -> Optional[int]:
    """`4g` / `4096m` / plain bytes -> bytes. None on anything unparseable."""
    if value is None:
        return None
    if isinstance(value, int):
        return value or None
    v = str(value).strip().lower()
    if not v:
        return None
    mult = 1
    if v[-1] in "kmg":
        mult = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[v[-1]]
        v = v[:-1]
    try:
        n = int(float(v) * mult)
    except ValueError:
        return None
    return n or None


def host_mem_total() -> Optional[int]:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
# the governor — the only thing that changes a cap
# --------------------------------------------------------------------------

class CapRefused(RuntimeError):
    pass


def _worker_containers(client) -> list:
    """Every worker slot container docker can see, running or not.

    The name fragment is a module constant so a simulation can point the whole
    governor at disposable containers instead. That is not a convenience: the
    budget gate sums every container this returns, so a harness that reuses the
    production fragment either (a) leaks a container that then counts against
    every future real job, or (b) computes `others` as the two REAL slots — 8
    GiB against a 10.93 GiB budget — and can therefore only ever observe a
    REFUSAL, never an allowed expansion. Half the behaviour would be untestable
    and the harness would still report success.
    """
    out = []
    for c in client.containers.list(all=True):
        name = getattr(c, "name", "") or ""
        if _slot_name_match() in name:
            env = (c.attrs.get("Config", {}) or {}).get("Env") or []
            if any(str(e).startswith("WORKER_SLOT=") for e in env):
                out.append(c)
    return out


def apply_cap(want_bytes: int, *, log: Optional[Callable[[str], None]] = None) -> dict:
    """Set THIS slot's cap to `want_bytes`, under the slot-wide lock.

    Returns a result dict; never raises for a refusal — a refused expansion is
    a normal outcome that the caller carries on from, not an error.
    """
    def _say(msg: str) -> None:
        if log:
            try:
                log(msg)
            except Exception:
                pass

    me = own_container_name()
    if not me:
        return {"applied": False, "reason": "cannot resolve own container"}

    try:
        import docker  # type: ignore
    except Exception as e:
        return {"applied": False, "reason": f"docker sdk unavailable: {e}"}

    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK_PATH, "a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            client = docker.from_env()
            slots = _worker_containers(client)
            if not slots:
                return {"applied": False, "reason": "no worker slot containers visible"}

            # Re-read EVERY cap inside the lock. A value read before taking it
            # is exactly the stale snapshot two slots can both act on.
            caps = {}
            for c in slots:
                caps[c.name] = int((c.attrs.get("HostConfig", {}) or {}).get("Memory") or 0)

            others = sum(v for k, v in caps.items() if k != me)
            host = host_mem_total()
            if host:
                budget = int(host * TOTAL_BUDGET_FRACTION)
                if others + want_bytes > budget:
                    return {
                        "applied": False,
                        "reason": (
                            "refused: %d B for %s + %d B held by other slots = %d B, "
                            "over the %d%% budget of this VM's %d B (%d B)"
                            % (want_bytes, me, others, others + want_bytes,
                               int(TOTAL_BUDGET_FRACTION * 100), host, budget)
                        ),
                        "want": want_bytes, "others": others, "budget": budget,
                    }

            # Shrinking below the live unreclaimable footprint OOM-kills this
            # slot's own job on its next allocation.
            floor = _unreclaimable()
            if floor and want_bytes < int(floor * SHRINK_HEADROOM):
                return {
                    "applied": False,
                    "reason": (
                        "refused: %d B leaves no headroom over this slot's "
                        "unreclaimable footprint (%d B); need at least %d B"
                        % (want_bytes, floor, int(floor * SHRINK_HEADROOM))
                    ),
                    "want": want_bytes, "floor": floor,
                }

            target = client.containers.get(me)
            # memswap == mem on purpose. With mem alone docker allows swap up
            # to 2x the cap, and slow swap thrash is the state that wedged the
            # VM twice.
            target.update(mem_limit=want_bytes, memswap_limit=want_bytes)

            target.reload()
            got = int((target.attrs.get("HostConfig", {}) or {}).get("Memory") or 0)
            ok = got == want_bytes
            _say("[worker-mem] %s cap -> %d B (%s)"
                 % (me, got, "ok" if ok else "MISMATCH, wanted %d" % want_bytes))
            return {"applied": ok, "container": me, "want": want_bytes, "got": got,
                    "reason": None if ok else "docker reported %d B" % got}
        except Exception as e:
            return {"applied": False, "reason": "%s: %s" % (type(e).__name__, e)}
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


# --------------------------------------------------------------------------
# policy
# --------------------------------------------------------------------------

def base_cap_bytes() -> Optional[int]:
    try:
        from modules.settings_io import get_setting

        return parse_mem(get_setting("worker_slot_mem"))
    except Exception:
        return None


def dynamic_enabled() -> bool:
    try:
        from modules.settings_io import get_setting

        return bool(get_setting("dynamic_worker_mem"))
    except Exception:
        return False


def desired_cap_bytes(module: str | None) -> Optional[int]:
    """What this slot's cap should be for a job of `module`.

    Flag OFF -> the base, always. Applying the base at job start is what heals
    a cap some earlier run left raised: the restore path can be skipped (a hard
    Stop SIGKILLs the work horse) but the next job's start cannot.

    That healing is best-effort, not a guarantee, and it got weaker when the
    expansion became a multiple. A want of `base * EXPANSION_FACTOR` can be
    REFUSED by the total-budget gate on a busy stack, where the old fixed floor
    could not exceed it as easily; a refused want leaves the cap where it was.
    apply_cap logs the refusal, and the following job tries again.

    Flag ON -> `base * EXPANSION_FACTOR` for an EXPANSION_MODULES job, the base
    for everything else. This is what the slot WANTS; `apply_cap` decides what
    it gets, and a want over the total budget is refused there and logged.
    """
    base = base_cap_bytes()
    if base is None or not dynamic_enabled():
        return base
    if (module or "").lower() in EXPANSION_MODULES:
        # A multiple of the base, so the operator's setting still governs.
        # `* EXPANSION_FACTOR` is always > base, so this can never LOWER a cap
        # the way a fixed floor could once the base rose above it.
        return int(base * EXPANSION_FACTOR)
    return base


class HighWaterExpander:
    """Raise this slot's cap when usage crosses HIGH_WATER_FRACTION of it.

    Deliberately the same shape as `OomEscalator` — same ladder, same absolute
    ceiling, same `dynamic_enabled()` re-check on every call so that OFF means
    off — with the one difference that is the entire point: it fires on a
    SAMPLE, while the processes are still alive.

    Bounded three ways, because a watermark fires far more often than a kill:

      * `MAX_HIGH_WATER_STEPS` caps the ladder for this job. The cap is
        restored to base when the job ends (worker/runner.py), so the ladder
        does not carry into the next one.
      * `MAX_CAP_FACTOR` caps the absolute ceiling, shared with the escalator
        so the two ladders cannot stack past it.
      * A REFUSAL IS LOGGED ONCE. `apply_cap`'s budget gate legitimately
        refuses while other slots hold the VM's 70%, and a slot sitting above
        the watermark asks again every 5 s — that is 720 identical lines an
        hour, which is a log nobody reads and a real refusal nobody sees.
    """

    def __init__(self, log: Optional[Callable[[str], None]] = None) -> None:
        self.count = 0
        self.log = log
        self._lock = threading.Lock()
        self._refusal_said = False

    def _say(self, msg: str) -> None:
        if self.log:
            try:
                self.log(msg)
            except Exception:
                pass

    def __call__(self, current: int, cap: int) -> None:
        if not dynamic_enabled():
            return
        # `memory.max` is unlimited (`_read_int` -> None) on a slot with no
        # cgroup cap. There is no watermark on a limit that does not exist.
        if not current or not cap or cap <= 0:
            return
        if current < cap * HIGH_WATER_FRACTION:
            return
        with self._lock:
            if self.count >= MAX_HIGH_WATER_STEPS:
                if self.count == MAX_HIGH_WATER_STEPS:
                    self.count += 1          # log the ceiling exactly once
                    self._say("[worker-mem] high water again, but this slot has "
                              "already expanded %d times — not raising further"
                              % MAX_HIGH_WATER_STEPS)
                return

            want = int(cap * HIGH_WATER_FACTOR)
            base = base_cap_bytes()
            if base:
                ceiling = int(base * MAX_CAP_FACTOR)
                if cap >= ceiling:
                    # Never step DOWN off a watermark: the slot is near its
                    # cap, and shrinking it is the opposite of the intent.
                    self.count = MAX_HIGH_WATER_STEPS + 1     # stop the ladder
                    self._say("[worker-mem] high water but this slot is already "
                              "at the ceiling (%d B = base x %d); not raising "
                              "further" % (ceiling, MAX_CAP_FACTOR))
                    return
                if want > ceiling:
                    self._say("[worker-mem] high water expansion clamped %d B -> "
                              "%d B (ceiling = base x %d)"
                              % (want, ceiling, MAX_CAP_FACTOR))
                    want = ceiling

            res = apply_cap(want, log=self.log)
            if res.get("applied"):
                self.count += 1
                self._refusal_said = False
                self._say("[worker-mem] high water: %d B is %.0f%% of the %d B cap "
                          "— raised to %d B (step %d/%d)"
                          % (current, 100.0 * current / cap, cap, want,
                             self.count, MAX_HIGH_WATER_STEPS))
            elif not self._refusal_said:
                self._refusal_said = True
                self._say("[worker-mem] high water: %d B is %.0f%% of the %d B cap "
                          "but the expansion was REFUSED (%s) — this slot stays "
                          "at its cap; not repeating this line"
                          % (current, 100.0 * current / cap, cap,
                             res.get("reason") or "no reason given"))


class OomEscalator:
    """Raise this slot's cap after a REAL cgroup OOM kill, a bounded number of times.

    Wired to the sampler's `on_oom`, which fires on a rise in this slot's own
    `memory.events:oom_kill`. It is deliberately reactive and deliberately
    limited:

      * It cannot help the process that already died. Escalating buys the
        agent's NEXT attempt more room; it does not resurrect the first.
      * `dynamic_enabled()` is checked on every call, not captured at
        construction. With the flag OFF this must be a no-op — a feature that is
        "off" and still moves a cgroup is not off.
      * `MAX_ESCALATIONS` exists because an unbounded ladder walks one slot into
        the entire budget, one OOM at a time, and every step passes the total
        gate individually.

    Runs on the sampler thread, so the counter is taken under a lock; the
    cross-process race is already handled by the flock inside `apply_cap`.
    """

    def __init__(self, log: Optional[Callable[[str], None]] = None) -> None:
        self.count = 0
        self.log = log
        self._lock = threading.Lock()

    def _say(self, msg: str) -> None:
        if self.log:
            try:
                self.log(msg)
            except Exception:
                pass

    def __call__(self, delta: int) -> None:
        if not dynamic_enabled():
            return
        with self._lock:
            if self.count >= MAX_ESCALATIONS:
                if self.count == MAX_ESCALATIONS:
                    self.count += 1          # log the ceiling exactly once
                    self._say("[worker-mem] OOM again, but this slot has already "
                              "escalated %d times — not raising further"
                              % MAX_ESCALATIONS)
                return
            current = _read_int("memory.max")
            if not current:
                self._say("[worker-mem] OOM seen but this slot has no readable "
                          "cap; not escalating")
                return
            want = int(current * OOM_ESCALATION_FACTOR)

            # Clamp to the absolute ceiling. Without this the reachable maximum
            # is whatever MAX_ESCALATIONS x OOM_ESCALATION_FACTOR happens to
            # multiply out to from an already-expanded start, which is a number
            # nobody chose.
            base = base_cap_bytes()
            if base:
                ceiling = int(base * MAX_CAP_FACTOR)
                if current >= ceiling:
                    # Never step DOWN on an OOM. Shrinking the slot that just
                    # ran out of memory is the opposite of the intent, and the
                    # shrink-headroom gate would refuse it anyway — silently,
                    # since apply_cap only logs on success.
                    self.count = MAX_ESCALATIONS + 1        # stop the ladder
                    self._say("[worker-mem] OOM but this slot is already at the "
                              "ceiling (%d B = base x %d); not raising further"
                              % (ceiling, MAX_CAP_FACTOR))
                    return
                if want > ceiling:
                    self._say("[worker-mem] OOM escalation clamped %d B -> %d B "
                              "(ceiling = base x %d)"
                              % (want, ceiling, MAX_CAP_FACTOR))
                    want = ceiling

            res = apply_cap(want, log=self.log)
            if res.get("applied"):
                self.count += 1
                self._say("[worker-mem] OOM -> escalated %d B to %d B (%d/%d)"
                          % (current, want, self.count, MAX_ESCALATIONS))
            else:
                self._say("[worker-mem] OOM -> escalation to %d B refused: %s"
                          % (want, res.get("reason") or "no reason given"))


# --------------------------------------------------------------------------
# the sampler — always on
# --------------------------------------------------------------------------

class JobSampler:
    """Polls this slot's cgroup for the life of one job.

    Writes to its OWN append-only file, never to meta.json. `write_meta` is a
    read-modify-write with no lock and no atomic replace
    (modules/_common.py:1148), so a background thread calling it races the
    job's own status writes and silently drops one of them.

    `memory.peak` would be the natural source but cannot be reset per job from
    inside the container — /sys/fs/cgroup is mounted read-only — so the peak is
    accumulated from polled `memory.current` instead.
    """

    def __init__(self, job_id: str, sample_path: Path,
                 on_oom: Optional[Callable[[int], None]] = None,
                 on_high_water: Optional[Callable[[int, int], None]] = None,
                 interval_s: float = SAMPLE_INTERVAL_S) -> None:
        self.job_id = job_id
        self.path = sample_path
        self.on_oom = on_oom
        self.on_high_water = on_high_water
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.peak = 0
        self.baseline_oom: Optional[int] = None
        self.oom_delta = 0

    def _write(self, row: dict) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(json.dumps(row) + "\n")
        except Exception:
            pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            row = sample()
            cur = row.get("current") or 0
            if cur > self.peak:
                self.peak = cur
            # BEFORE the oom bookkeeping, on purpose: this is the hook whose
            # whole value is firing while the processes are still alive.
            # Guarded like on_oom is — a callback that raises must not stop
            # the sampler, because the sampler is also what records the peak
            # this job is judged on.
            if self.on_high_water:
                try:
                    self.on_high_water(cur, row.get("max") or 0)
                except Exception:
                    pass
            ok = row.get("oom_kill")
            if ok is not None:
                if self.baseline_oom is None:
                    self.baseline_oom = ok
                delta = ok - self.baseline_oom
                if delta > self.oom_delta:
                    self.oom_delta = delta
                    row["oom_kill_delta"] = delta
                    if self.on_oom:
                        try:
                            self.on_oom(delta)
                        except Exception:
                            pass
            self._write(row)
            self._stop.wait(self.interval_s)

    def start(self) -> "JobSampler":
        first = sample()
        self.baseline_oom = first.get("oom_kill")
        self.peak = first.get("current") or 0
        self._write(dict(first, event="start", job=self.job_id))
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="worker-mem-sampler")
        self._thread.start()
        return self

    def stop(self) -> dict:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval_s + 2)
        summary = {
            "peak_bytes": self.peak,
            "oom_kill_delta": self.oom_delta,
            "cap_bytes": _read_int("memory.max"),
        }
        self._write(dict(sample(), event="stop", job=self.job_id, **summary))
        return summary
