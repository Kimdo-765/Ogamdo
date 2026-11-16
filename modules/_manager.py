"""MANAGER — how likely is this job to end in a flag, and how far from one is it.

WHY THIS EXISTS

The dashboard could say what a job WAS doing (status, cost, the monitor's
narration) and never what it was WORTH. An operator with several jobs running
had no way to tell the one that is three steps from a working exploit from the
one that has been re-testing a refuted hypothesis for two hours -- and this
session produced both. Job 340e62bdcd32 spent its last two hours measuring
replica latency; job 44591f39ef9f spent 2.5 hours analysing a dead instance.
Neither was distinguishable from progress by looking at the row.

So a separate agent reads the job's own signals and answers two questions:
a probability, and a position on a fixed pipeline.

WHY THE PIPELINE IS FIXED HERE AND NOT ASKED FOR

The model returns a STAGE from `STAGES`; the code derives "3 of 7" from it.
Letting the model invent both numerator and denominator produces bars that
cannot be compared between two jobs, or even between two assessments of the
same job -- 3/11 then 4/9 reads as progress and is not. A fixed ladder makes
the bar mean one thing.

WHY ITS OWN ROLE

This is a judgement ABOUT the work, not part of doing it. Pointing it at the
main model would pay solving rates for a dashboard number, so `manager` is in
ROLE_OVERRIDABLE and CONFIGURABLE_ROLES and the operator picks its provider
and model in Settings like any other role.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from modules._sdk_buffer import AGENT_MAX_BUFFER_BYTES

# The ladder every job is placed on. Ordered, and the order is the whole point:
# a job cannot be at `remote-verified` without having had an exploit to verify.
# Keep in sync with the labels the dashboard prints.
STAGES: tuple[str, ...] = (
    "recon",             # reading the bundle / probing the target
    "surface-map",       # endpoints, protocol, or binary structure understood
    "vuln-identified",   # a specific, named weakness with evidence
    "exploit-drafted",   # a script exists that attempts it
    "local-verified",    # it works against a local or mocked instance
    "remote-verified",   # it reaches the real target and does something
    "flag-captured",     # the flag is in hand
)

MANAGER_MODEL = os.environ.get("MANAGER_MODEL", "claude-sonnet-4-6")
_ASSESS_TIMEOUT_S = int(os.environ.get("MANAGER_TIMEOUT_S", "90"))
# Signal lines handed to the model. Enough to see the arc of the last few
# attempts; not so many that a long job pays for its own history every cycle.
_SIGNAL_LINES = 40

_TASKS: dict[str, asyncio.Task] = {}


def manager_enabled() -> bool:
    """Both switches must say yes, matching the monitor's contract.

    The env var is "this deployment cannot run it at all"; the setting is the
    operator's live choice. Default OFF: this spends tokens on every running
    job, and a feature that bills by existing should be opted into.
    """
    if os.environ.get("MANAGER_ENABLED", "1") == "0":
        return False
    try:
        from modules.settings_io import get_setting

        return bool(get_setting("manager_agent"))
    except Exception:
        return False


def interval_s() -> int:
    try:
        from modules.settings_io import get_setting

        return max(30, int(get_setting("manager_interval_s") or 90))
    except Exception:
        return 90


def _job_dir(job_id: str) -> Path:
    return Path(os.environ.get("DATA_DIR", "/data")) / "jobs" / job_id


def assessment_path(job_id: str) -> Path:
    return _job_dir(job_id) / "manager.json"


def read_assessment(job_id: str) -> dict | None:
    """Latest assessment, or None. Safe to call from the api on every list."""
    try:
        return json.loads(assessment_path(job_id).read_text(encoding="utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# What the model is shown
# ---------------------------------------------------------------------------
# Kept deliberately narrow. run.log is ~96% `[main] TOOL`/`TOOL_RESULT` echo,
# and handing that to a model costs tokens to say nothing. These are the lines
# that carry a decision: the orchestrator's own bookkeeping, the judge's
# verdicts, what the runner did, and main's prose -- which is where a change of
# strategy is actually announced.
_SIGNAL_RE = re.compile(
    r"\[(orchestrator|judge|runner|report|chalbox)\]|\[main\] AGENT:"
)
# Positional, not substring: `TOOL_RESULT` bodies quote judge verdicts and
# agent prose back at you, and a filter that matched on content pulled the
# echo in with the signal. This has bitten in this repo before.
_NOISE_RE = re.compile(r"\[main\] (TOOL_RESULT|TOOL_ERROR|TOOL )")


def _all_signal_lines(job_id: str) -> list[str]:
    log = _job_dir(job_id) / "run.log"
    try:
        raw = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [l[:400] for l in raw
            if _SIGNAL_RE.search(l) and not _NOISE_RE.search(l)]


def _signal_lines(job_id: str, limit: int = _SIGNAL_LINES) -> list[str]:
    """The TAIL, for the model to read.

    Counts are taken from the whole log instead (see collect_signals): the
    first draft counted `auto-run turn` inside this window and reported 1 for a
    job that had run seventeen, because the earlier sixteen were off the end of
    it. A window is the right input for "what is happening now" and the wrong
    one for "how many times has this happened".
    """
    return _all_signal_lines(job_id)[-limit:]


def collect_signals(job_id: str) -> dict:
    """The facts an assessment is made from. No model call here.

    Structured state is read directly rather than left for the model to infer
    from prose: whether an artifact exists, how many attempts have run, what
    the last verdict was. A model asked to count attempts from a log will
    sometimes miscount, and the number is already on disk.
    """
    jd = _job_dir(job_id)
    out: dict = {"job_id": job_id}
    try:
        meta = json.loads((jd / "meta.json").read_text(encoding="utf-8"))
    except Exception:
        meta = {}
    out["module"] = meta.get("module")
    out["status"] = meta.get("status")
    out["has_target"] = bool(meta.get("target_url"))
    out["flags"] = len(meta.get("flags") or [])
    out["flag_candidates"] = len(meta.get("flag_candidates") or [])

    # An artifact is the difference between "has an idea" and "has a script".
    out["artifacts"] = sorted(
        p.name for p in (jd / "work").glob("*.py")
        if p.name in ("exploit.py", "solver.py")
    ) if (jd / "work").is_dir() else []

    every = _all_signal_lines(job_id)
    out["signal_lines"] = every[-_SIGNAL_LINES:]
    # Counted from the log rather than asked for: cheap, exact, and it anchors
    # the model when the prose is ambiguous about how many times this has run.
    # Over EVERY signal line, not the tail the model reads.
    joined = "\n".join(every)
    out["auto_run_turns"] = len(re.findall(r"auto-run turn \d+:", joined))
    verdicts = re.findall(r"postjudge verdict=([a-z_]+)", joined)
    out["verdicts"] = verdicts[-6:]
    out["last_verdict"] = verdicts[-1] if verdicts else None
    ev = re.findall(r"budget (-?\d+)/(\d+), (\d+) distinct states", joined)
    if ev:
        out["evidence_budget"] = f"{ev[-1][0]}/{ev[-1][1]}"
        out["distinct_states"] = int(ev[-1][2])
    try:
        out["elapsed_s"] = int(time.time() - (jd / "run.log").stat().st_ctime)
    except Exception:
        out["elapsed_s"] = None
    return out


def _sys_prompt() -> str:
    stages = "\n".join(f"  {i + 1}. {s}" for i, s in enumerate(STAGES))
    return (
        "You assess CTF solving jobs for an operator watching several at once. "
        "You are NOT solving the challenge; you are judging how this run is "
        "going, from its own log.\n\n"
        "Return ONE JSON object and nothing else:\n"
        '{"stage": "<one of the stage names>", "flag_probability": <0-100 '
        'integer>, "confidence": "low"|"medium"|"high", "next_step": "<one '
        'short line: the single most useful next move>", "blocker": "<one '
        'short line, or empty if none>", "rationale": "<one short line of '
        'evidence for the probability>"}\n\n'
        f"STAGES, in order:\n{stages}\n\n"
        "Rules that matter:\n"
        "- `stage` is the FURTHEST point this job has actually reached with "
        "evidence in the log, not the one it is trying to reach.\n"
        "- `flag_probability` is the chance THIS run ends with the real flag. "
        "Repeated verdicts of the same kind, a saturated evidence budget, or "
        "an unreachable target are strong evidence AGAINST, whatever the "
        "agent's own prose claims. An agent saying it is close is not "
        "evidence; a remote-verified exploit is.\n"
        "- Be willing to return a LOW number. A calibrated 15 is worth more to "
        "the operator than an encouraging 60, because the number exists to "
        "decide which job to look at.\n"
        "- Every string field must be at most 120 characters, in the same "
        "language as the log's own prose where there is one."
    )


# ---------------------------------------------------------------------------
# The model call
# ---------------------------------------------------------------------------
def _parse(text: str) -> dict | None:
    """First JSON object in the reply, or None.

    Models wrap JSON in prose and fences whatever the prompt says, so the
    object is extracted rather than the whole reply parsed.
    """
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


async def _ask_claude(prompt: str, model: str) -> dict | None:
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        import anyio
    except Exception:
        return None
    options = ClaudeAgentOptions(
        max_buffer_size=AGENT_MAX_BUFFER_BYTES,
        system_prompt=_sys_prompt(),
        model=model,
        allowed_tools=[],
        disallowed_tools=["Agent", "Task", "WebSearch", "WebFetch", "Bash",
                          "Read", "Write", "Edit", "Glob", "Grep"],
        permission_mode="bypassPermissions",
    )
    acc = ""
    try:
        with anyio.fail_after(_ASSESS_TIMEOUT_S):
            async for msg in query(prompt=prompt, options=options):
                cls = type(msg).__name__
                if cls == "AssistantMessage":
                    for block in getattr(msg, "content", []) or []:
                        if type(block).__name__ == "TextBlock":
                            acc += getattr(block, "text", "") or ""
                elif cls == "ResultMessage" and getattr(msg, "is_error", False):
                    return None
    except Exception:
        return None
    return _parse(acc)


async def _ask_gpt(prompt: str, model: str | None) -> dict | None:
    try:
        from modules.gpt_agent import query_gpt_once
        from modules.agent_provider import default_model_for
    except Exception:
        return None
    m = (model or "").strip()
    if not m or m.lower().startswith(("claude", "grok")):
        m = default_model_for("gpt")
    try:
        r = await query_gpt_once(
            prompt=prompt, cwd="/tmp", system_prompt=_sys_prompt(),
            model=m, effort="low", timeout_s=float(_ASSESS_TIMEOUT_S),
            enable_tools=False,
        )
    except Exception:
        return None
    return None if r.get("error") else _parse(r.get("text") or "")


async def _ask_grok(prompt: str, model: str | None) -> dict | None:
    try:
        from modules.grok_acp import query_grok_once, resolve_grok_bin
        from modules.agent_provider import default_model_for
        resolve_grok_bin()
    except Exception:
        return None
    m = (model or "").strip()
    if not m or m.lower().startswith("claude"):
        try:
            m = default_model_for("grok")
        except Exception:
            m = "grok-build"
    try:
        r = await query_grok_once(
            prompt=prompt, cwd="/tmp", system_prompt=_sys_prompt(),
            model=m, effort="low", timeout_s=float(_ASSESS_TIMEOUT_S),
        )
    except Exception:
        return None
    return None if r.get("error") else _parse(r.get("text") or "")


def _route(job_id: str) -> tuple[str, str]:
    """(provider, model) for this job's manager role."""
    provider, model = "claude", MANAGER_MODEL
    try:
        from modules.agent_provider import provider_for_role
        from modules.model_presets import resolve_role_model

        provider = provider_for_role(job_id, "manager") or "claude"
        model = resolve_role_model("manager", MANAGER_MODEL, provider) or MANAGER_MODEL
    except Exception:
        pass
    return provider, model


def _normalize(raw: dict, signals: dict) -> dict:
    """Model output -> the record the dashboard renders.

    `steps_done` is DERIVED from the stage name, never taken from the model:
    a bar whose denominator moves between assessments shows progress that did
    not happen. An unrecognised stage falls to the first rung rather than
    guessing -- being wrong and low is recoverable, being wrong and high is
    what the operator would act on.
    """
    stage = str(raw.get("stage") or "").strip().lower()
    idx = STAGES.index(stage) if stage in STAGES else 0
    # OUT OF RANGE IS UNPARSEABLE, NOT 100. Clamping 999 upward turns a model
    # that returned garbage into maximum confidence -- the one direction this
    # number must never fail in, because it is the direction an operator acts
    # on. A value outside 0-100 means the field was not answered.
    try:
        prob = int(round(float(raw.get("flag_probability", 0))))
        if not 0 <= prob <= 100:
            prob = 0
    except (TypeError, ValueError):
        prob = 0
    # A captured flag is not a probability question. The meta already knows.
    if signals.get("flags"):
        idx, prob = len(STAGES) - 1, 100
    conf = str(raw.get("confidence") or "low").strip().lower()
    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "stage": STAGES[idx],
        "steps_done": idx + 1,
        "steps_total": len(STAGES),
        "flag_probability": prob,
        "confidence": conf if conf in ("low", "medium", "high") else "low",
        "next_step": str(raw.get("next_step") or "")[:120],
        "blocker": str(raw.get("blocker") or "")[:120],
        "rationale": str(raw.get("rationale") or "")[:120],
        "evidence": {
            "auto_run_turns": signals.get("auto_run_turns"),
            "last_verdict": signals.get("last_verdict"),
            "evidence_budget": signals.get("evidence_budget"),
            "distinct_states": signals.get("distinct_states"),
            "artifacts": signals.get("artifacts"),
        },
    }


async def assess(job_id: str) -> dict | None:
    """One assessment. Writes `<job>/manager.json` and returns it."""
    signals = collect_signals(job_id)
    if not signals.get("signal_lines"):
        return None
    provider, model = _route(job_id)
    payload = {k: v for k, v in signals.items() if k != "signal_lines"}
    prompt = (
        "JOB STATE:\n" + json.dumps(payload, ensure_ascii=False, indent=1)
        + "\n\nRECENT SIGNAL LINES (oldest first):\n"
        + "\n".join(signals["signal_lines"])
    )
    if provider == "gpt":
        raw = await _ask_gpt(prompt, model)
    elif provider == "grok":
        raw = await _ask_grok(prompt, model)
    else:
        raw = await _ask_claude(prompt, model)
    if not raw:
        return None
    rec = _normalize(raw, signals)
    rec["provider"], rec["model"] = provider, model
    try:
        path = assessment_path(job_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
        # History, for a bar that should not be read as a single moment.
        with (path.parent / "manager.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return rec


# ---------------------------------------------------------------------------
# The always-on supervisor, mirroring modules/_monitor.py
# ---------------------------------------------------------------------------
# `hold` is terminal for the SESSION — nothing is running — but the job is
# resumable the moment a new target arrives, so it is not a failure.
_TERMINAL = {"finished", "stopped", "failed", "flag_ready", "no_flag",
             "hold"}


def _is_terminal(job_id: str) -> bool:
    try:
        meta = json.loads(
            (_job_dir(job_id) / "meta.json").read_text(encoding="utf-8"))
    except Exception:
        return False
    return meta.get("status") in _TERMINAL


async def run_manager(job_id: str) -> None:
    """Assess this job until it ends.

    Re-assesses only when the log has GROWN. A job that is thinking hard
    produces no new signal lines for minutes at a time, and paying for an
    identical assessment of an unchanged log is the failure mode a dashboard
    widget has to avoid -- the point of this agent is to be cheap enough that
    nobody turns it off.
    """
    last_len = -1
    while not _is_terminal(job_id):
        try:
            n = len(_all_signal_lines(job_id))
            if n != last_len:
                rec = await assess(job_id)
                if rec:
                    last_len = n
        except Exception:
            pass
        await asyncio.sleep(interval_s())
    # One final read after the run ends: the last assessment was made before
    # the outcome was known, and a row frozen at "45%" on a job that finished
    # with a flag is worse than no number.
    try:
        await assess(job_id)
    except Exception:
        pass


async def _guarded(job_id: str) -> None:
    try:
        await run_manager(job_id)
    except Exception:
        pass
    finally:
        _TASKS.pop(job_id, None)


def ensure_manager(job_id: str) -> None:
    """Start a manager task for job_id if none is alive. Idempotent."""
    if not manager_enabled() or not job_id or _is_terminal(job_id):
        return
    t = _TASKS.get(job_id)
    if t is not None and not t.done():
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _TASKS[job_id] = loop.create_task(_guarded(job_id))


def _scan_running() -> list[str]:
    out: list[str] = []
    root = Path(os.environ.get("DATA_DIR", "/data")) / "jobs"
    try:
        for d in root.iterdir():
            if not d.is_dir() or not (d / "run.log").exists():
                continue
            try:
                meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
            except Exception:
                continue
            if meta.get("status") and meta["status"] not in _TERMINAL:
                out.append(d.name)
    except OSError:
        pass
    return out


async def _supervisor() -> None:
    while True:
        try:
            if manager_enabled():
                for jid in _scan_running():
                    ensure_manager(jid)
        except Exception:
            pass
        # Slower than the monitor's 8s: this sweep only has to notice a NEW
        # job, and the per-job loop owns its own cadence from there.
        await asyncio.sleep(20)


def start_supervisor() -> None:
    """Launch the supervisor. Call once from api.main startup.

    Deliberately NOT gated on manager_enabled() at startup: the setting is a
    live toggle, and a supervisor that refused to start because the feature
    was off at boot would need an api restart to pick the operator's change
    up. The gate is inside the loop instead.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(_supervisor())
