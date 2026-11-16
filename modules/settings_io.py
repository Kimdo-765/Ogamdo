"""Settings persistence shared by api + worker.

Settings are stored in /data/settings.json (mounted on both containers).
Precedence: settings file > env var > default.

Sensitive values (api keys, auth tokens) are returned masked from
get_settings_view() — full values stay on disk.
"""

from __future__ import annotations

import json
import math
import os
import threading
from pathlib import Path
from typing import Any  # noqa: F401

SETTINGS_PATH = Path(os.environ.get("SETTINGS_PATH", "/data/settings.json"))

# Allowed values for agent_provider. Keep in sync with the Settings UI and
# modules/agent_provider.py.
AGENT_PROVIDERS = ("claude", "grok", "gpt")

# (key, env_fallback, type, default)
SCHEMA: list[tuple[str, str | None, type, Any]] = [
    # Which coding-agent backend runs CTF jobs. "claude" = Claude Agent SDK
    # (current default). "grok" = Grok Build via ACP / headless (in progress).
    ("agent_provider", "AGENT_PROVIDER", str, "claude"),
    # Ollama on this box, reachable as a ROLE target (never as a whole-job
    # backend — see agent_provider.LOCAL_CAPABLE_ROLES). Empty means "not
    # configured", which is how the UI tells "no local runtime" from "a local
    # runtime that is down": a blank field promises nothing, a filled one that
    # fails to answer is a fault worth showing.
    #
    # The default is the docker bridge gateway, not localhost: the monitor
    # runs inside the api container, and 127.0.0.1 there is the container.
    ("ollama_url", "OLLAMA_URL", str, ""),
    # The tag to run there, e.g. `gemma4-heretic:latest`. No constant default:
    # an Ollama tag is whatever the operator pulled, and guessing one would
    # request a model that is not installed.
    ("ollama_model", "OLLAMA_MODEL", str, ""),
    # Human-facing prose emitted by every role. "auto" preserves the model's
    # natural/default language; ko/en add a common system instruction. A job
    # snapshots the effective value at create time.
    ("agent_output_language", "AGENT_OUTPUT_LANGUAGE", str, "auto"),
    # OPTIONAL per-role backend override, e.g. {"judge": "claude"} while
    # agent_provider stays "gpt". Absent / empty means every role follows
    # agent_provider, which is byte-for-byte the pre-hybrid behaviour — the
    # scalar above is deliberately NOT replaced, because _monitor.py and the
    # retry chain read it as a plain string.
    ("agent_role_providers", None, dict, {}),
    ("anthropic_api_key", "ANTHROPIC_API_KEY", str, ""),
    ("claude_model", "CLAUDE_MODEL", str, "claude-opus-4-7"),
    # Global effort for Claude sessions (low/medium/high/xhigh/max). UI has
    # always exposed this; SCHEMA entry was missing so saves were dropped.
    ("claude_effort", "CLAUDE_EFFORT", str, ""),
    # xAI / Grok Build credentials + defaults (used when agent_provider=grok).
    ("xai_api_key", "XAI_API_KEY", str, ""),
    ("grok_model", "GROK_MODEL", str, "grok-build"),
    ("grok_effort", "GROK_EFFORT", str, ""),
    # GPT provider. Codex CLI + ChatGPT OAuth is the default; the direct
    # Responses API remains an explicit usage-billed fallback.
    ("gpt_runtime", "GPT_RUNTIME", str, "codex"),
    ("openai_api_key", "OPENAI_API_KEY", str, ""),
    ("gpt_model", "GPT_MODEL", str, "gpt-5.6-sol"),
    ("gpt_effort", "GPT_EFFORT", str, "medium"),
    ("auth_token", "AUTH_TOKEN", str, ""),
    ("job_ttl_days", "JOB_TTL_DAYS", int, 7),
    ("job_timeout_seconds", "JOB_TIMEOUT", int, 900),
    # Provider fallback for a Codex CLI turn whose caller does not pass an
    # explicit per-job budget (for example, auxiliary/standalone turns). Main
    # solver sessions derive their budget from job_timeout instead. Keep the
    # fallback visible so the next job picks up a change via apply_to_env().
    ("codex_turn_timeout_seconds", "CODEX_TURN_TIMEOUT_S", int, 3600),
    # Read-only in slot mode: concurrency is now the NUMBER OF worker-N
    # services in docker-compose.yml, and worker/runner.py forces 1 process per
    # slot container regardless of what is stored here. Kept in the schema so
    # an older single-container compose file still works.
    ("worker_concurrency", "WORKER_CONCURRENCY", int, 3),
    # Cgroup memory cap for EACH worker slot container, as a docker size string
    # ("4g", "4096m", or plain bytes). Restored 2026-07-29 after a real
    # `global_oom` (one python3 at 15.0 GB inside a 15.5 GB VM) froze the whole
    # WSL VM: the cap does not save a runaway job, it keeps the kill LOCAL to
    # the container instead of taking the host session down. Unlike every other
    # key here this one is NOT read at job start — it is a container-create
    # property — so PUT /api/settings applies it LIVE via the Docker API, and
    # docker-compose.yml reads WORKER_SLOT_MEM from .env as the boot default.
    #
    # RENAMED from worker_mem_limit / WORKER_MEM_LIMIT on the slot split, and
    # the rename is load-bearing, not cosmetic. That key meant "cap for the ONE
    # worker container" and both /data/settings.json and .env held 8g. Reusing
    # it would have silently reinterpreted 8g as PER SLOT, and the first
    # settings save would have pushed 8g onto every slot via `docker update` —
    # 16 GiB of cap inside a 15.99 GiB VM, i.e. exactly the unbounded condition
    # that froze WSL twice. A renamed key falls back to this safe default; a
    # reinterpreted one fails to 2x. The stale `worker_mem_limit` entry left in
    # /data/settings.json is inert: lookups iterate SCHEMA, so a key that is not
    # here is never read and never shown.
    ("worker_slot_mem", "WORKER_SLOT_MEM", str, "4g"),
    # Master switch for dynamic per-slot memory. Default OFF means the stack
    # behaves EXACTLY as it does today: `worker_slot_mem` above is the only
    # authority, and no code path changes a cgroup cap while a job runs.
    #
    # It is a separate key on purpose. Flipping this must NOT reinterpret
    # `worker_slot_mem` — that key keeps meaning "the base cap for every slot",
    # and the dynamic policy layers on top of it. The comment above records
    # what happens when a memory key changes meaning under an operator: the
    # worker_mem_limit -> worker_slot_mem rename existed because reusing the
    # old key would have pushed one container's 8g onto EVERY slot.
    #
    # Deliberately not gating the sampler. The sampler is read-only
    # (one /sys/fs/cgroup/memory.current read is ~0.007 ms) and it is what
    # produces the data needed to choose a base and an expansion size. Gate it
    # here and the day this flag is switched ON there is nothing to tune from.
    ("dynamic_worker_mem", "DYNAMIC_WORKER_MEM", bool, False),
    # Does a high-severity prejudge STOP the sandbox, or only report?
    #
    # `judge_mode` is one switch over two different things: prejudge (a
    # prediction, made before the script has ever run) and postjudge (a
    # reading of what a real execution actually did). Turning it to `shadow`
    # to stop the first also silenced the second, and job df05d2ce2710
    # measured what that costs: the sandbox finally ran — twice — and then the
    # retry loop had no verdict to iterate on and stopped after two attempts
    # (`stop_kind=reviewer_redirect_no_run`), 24.7 min into a 58 min budget.
    #
    # So the ship gate gets its own key. OFF means prejudge still runs, still
    # logs every issue it found, and still records — it just does not get to
    # decide that a script never executes. Default ON so no other deployment
    # changes behaviour by upgrading; this one runs it OFF (2026-09-03) after
    # job cc38cfa29161, where flag_likelihood=0.00 blocked the ship and the
    # sandbox never ran at all.
    ("prejudge_ship_gate", "PREJUDGE_SHIP_GATE", bool, True),
    # Does a judge STOP end the job, or become the work it implies?
    #
    # Measured over several runs on one hard challenge: every one ended on a
    # judge opinion and none because a budget ran out. Meanwhile
    # INVESTIGATION_BUDGET=0, COST_CAP_USD=0, AUTO_RETRY_MAX=-1 and
    # job_timeout_seconds=9999999: nothing was capping anything. The run had
    # unlimited road and stopped anyway.
    #
    # "No small fix exists" is the CORRECT verdict on a target that needs a
    # capability nobody has built yet — and it is the signal to start the
    # long work, not to end the run. Operator decision, 2026-09-03: OFF here. A CTF runs at
    # most 48 hours and the operator holds the Stop button, so an unproductive
    # loop is cheap to end by hand and a premature halt is not.
    #
    # Default ON so no other deployment changes behaviour by upgrading.
    ("judge_stop_halts", "JUDGE_STOP_HALTS", bool, True),
    # Advertise Codex's multi-agent v2 toolset to main, or not?
    #
    # `spawn_agent` is NOT registered in this deployment — proven outside the
    # platform on two models — but `wait` IS, and it returns
    # {"receiver_thread_ids": [], "agents_states": {}} every single time.
    # Across three measured jobs: 27 / 9 / 60 wait events, 9 / 3 / 20 of them
    # empty rosters, and every one of those is main sleeping on a roster that
    # cannot fill. Delegation here goes through .scratch/delegate.json, which
    # needs none of this.
    #
    # Measured on codex-cli 0.152.1 with the flag OFF, the model answers
    # NO_WAIT_TOOL instead of claiming it called one. The `agents.*` overlays
    # this block also registers exist only for Codex's own spawn_agent
    # children; our delegate children take their model from `--model`
    # directly (run_pre_recon -> resolve_role_model), so turning this off
    # costs the file channel nothing.
    #
    # Default ON so no other deployment changes behaviour by upgrading.
    ("codex_multi_agent_v2", "CODEX_MULTI_AGENT_V2", bool, True),
    # The Monitor agent — a narration layer that watched run.log and published
    # a per-job commentary feed. Superseded: GPT jobs already bypass it
    # (_monitor.py:_monitor_enabled_for_job returns False for provider=gpt,
    # because the Timeline replaces it), and GPT is what this deployment runs.
    # The operator's call, 2026-09-04: "monitor agent는 폐기에 가까운 agent라서
    # 기능은 삭제하지 말고 OFF 처리해줘."
    #
    # So the code stays whole and this key decides. Note the default is FALSE,
    # inverting the convention used by the three keys above: those default ON
    # because ON is the historical behaviour worth preserving. Here the
    # feature is being retired, so the safe state is the OFF one, and an
    # unreadable policy must not resurrect a deprecated agent.
    ("monitor_agent", "MONITOR_AGENT", bool, False),
    # Flag harvester — a model that re-reads agent output looking for flags the
    # regex missed. FLAG_RE carries a fixed alphabet of ~20 known prefixes, so
    # REVERSSEUM{...} (job 29f1d8f14268) and pokactf2024{...} (fed8eedff33d)
    # were both invisible to it; each was recovered only because the solver
    # happened to print the FLAG_CANDIDATE marker.
    #
    # Default ON: this is a feature the operator asked for, and it is advisory
    # only — it appends to <jobdir>/flag_grain.txt and can neither write
    # meta.flags nor end a job. The three gates above default ON to preserve
    # historical behaviour; this one defaults ON because OFF would ship a
    # requested feature that does nothing until someone finds the switch.
    ("flag_harvester", "FLAG_HARVESTER", bool, True),
    # --- Manager agent -----------------------------------------------------
    # Reads a running job's own signals and answers two questions the raw log
    # does not: how likely is this to end in a flag, and how far from a working
    # exploit is it. Its own role, so the operator can point it at a cheap
    # model independently of the stack the job runs on — this is a judgement
    # ABOUT the job, not part of solving it, and paying main-model rates for a
    # dashboard number would be the wrong trade.
    ("manager_agent", "MANAGER_AGENT", bool, False),
    # Seconds between assessments for one running job. The floor matters more
    # than the ceiling: a job's odds do not move meaningfully inside a minute,
    # and a per-job LLM call every few seconds is how a dashboard widget ends
    # up costing more than the work it describes.
    ("manager_interval_s", "MANAGER_INTERVAL_S", int, 90),
    # Remove the containers and networks a job created once it reaches a
    # terminal status. Default ON: agent-started containers have no other
    # owner, and containers from 2026-06 were still running in 2026-08, each
    # holding a 2 GiB cgroup ceiling. Turn OFF to keep a failed job's challenge
    # stack up for debugging — the Containers tab can then clear it by hand.
    ("reap_job_containers", "REAP_JOB_CONTAINERS", bool, True),
    ("callback_url", "CALLBACK_URL", str, ""),
    # Operator spend budget (USD) for the top-bar "used / budget" usage pill.
    # 0 = no budget set → the pill shows cumulative spend only (no bar / %).
    # This is an OPERATOR budget, NOT the Claude account limit — a true
    # remaining-quota number isn't retrievable in the OAuth/headless path
    # (see the usage-widget feasibility notes); the pill reads existing
    # aggregate cost against this ceiling.
    ("budget_usd", "BUDGET_USD", float, 0.0),
    # Quality-gate judge that wraps auto_run exploit/solver execution
    # (pre-flight script review → post-mortem verdict). Each stage is one
    # short no-tools Claude call against LATEST_JUDGE_MODEL. Disable to
    # skip all judge calls and run the script with the plain runner
    # (saves ~2 Claude turns per auto_run job at the cost of losing
    # parse-error detection).
    #
    # A stall-detection stage used to be listed here as a third one. It is
    # excluded from v1 enforce and gated behind `enable_supervise`
    # (default False), so hang detection is NOT among the things this
    # setting buys — the hard timeout still covers it.
    ("enable_judge", "ENABLE_JUDGE", bool, True),
    # Tri-state successor to `enable_judge`. Empty means "derive from the
    # boolean", so existing settings keep meaning exactly what they meant:
    # False -> off, True -> enforce. `shadow` is reachable only by setting
    # this explicitly — a mode that changes what the operator sees should
    # never be entered by inference.
    ("judge_mode", "JUDGE_MODE", str, ""),
    # S1-ENV remote-target gate.  Default OFF: a false positive kills a
    # healthy job, while a false negative preserves the pre-gate behaviour.
    # When enabled, only pwn/rev job-start probes may stop a job; the runner's
    # later pre-sandbox reachability note remains warn-only.
    ("enable_remote_target_gate", "ENABLE_REMOTE_TARGET_GATE", bool, False),
    # When True, every job's user_prompt is prepended with a short
    # paragraph listing same-module entries from the exploit library
    # (`/data/exploits/`, populated via POST /api/exploits/save) so
    # the agent can `cat /data/exploits/<id>/report.md` for insight on
    # similar chals (leak vector / FSOP variant / technique pick).
    # Default OFF — `heap_state_evolution_gap` memory warns against
    # broad prompt nudges from small libraries; only flip on after the
    # library has several curated entries the operator trusts.
    ("enable_exploit_library_hint", "ENABLE_EXPLOIT_LIBRARY_HINT", bool, False),
    # --- Venue VPN ---------------------------------------------------------
    # A CTF's problem servers live only on the contest LAN while Ogamdo runs at
    # home, so the laptop that goes to the venue is the only thing on both
    # networks. It dials in as a WireGuard peer and advertises the venue's
    # subnets; this box routes them to it. See modules/vpn.py for why the
    # tunnel terminates in the WSL VM and not in Windows (short version:
    # networkingMode=bridged makes the WSL VM its own LAN host with its own
    # default route, so a Windows profile carries Windows' traffic and none of
    # Ogamdo's).
    ("vpn_enabled", "VPN_ENABLED", bool, False),
    # `venue` routes only the advertised subnets and leaves everything else --
    # model APIs, package mirrors -- on the home line. `all` sends every
    # CONTAINER's egress through the venue via a policy rule per docker bridge,
    # while the WSL host keeps its LAN default route so the handshake and
    # Ogamdo's own control plane are never routed into the tunnel they need.
    # Default `venue`: a venue that firewalls outbound API calls kills every
    # job under `all`, and that is not a thing to discover mid-contest.
    ("vpn_scope", "VPN_SCOPE", str, "venue"),
    # UDP port WireGuard LISTENS on inside the WSL VM -- the INTERNAL side of
    # the router's port forward.
    ("vpn_listen_port", "VPN_LISTEN_PORT", int, 51820),
    # The EXTERNAL port the laptop dials, when the router maps it to a
    # different internal one. 0 means "same as the listen port".
    #
    # These are two numbers, not one, because a router that separates internal
    # from external port lets them differ -- and the failure is silent and
    # one-directional: the desktop listens correctly, the tunnel looks
    # configured, and only the laptop's `Endpoint` is wrong, so nothing
    # anywhere reports a problem except a handshake that never arrives.
    ("vpn_external_port", "VPN_EXTERNAL_PORT", int, 0),
    # Tunnel addresses. Defaults are in 10.99/16 to stay clear of the 10.0/24
    # and 172.x ranges a venue or docker is likely to be using already.
    ("vpn_address", "VPN_ADDRESS", str, "10.99.0.1/24"),
    ("vpn_peer_address", "VPN_PEER_ADDRESS", str, "10.99.0.2/32"),
    # The laptop's WireGuard public key. Empty means the tunnel cannot start;
    # vpn.start() refuses rather than bringing up an interface with no peer.
    ("vpn_peer_public_key", "VPN_PEER_PUBLIC_KEY", str, ""),
    # Comma-separated venue subnets the laptop can reach, e.g.
    # "10.20.0.0/16, 192.168.4.0/24". A /0 here is REFUSED — it would be
    # written into the main table and take this box's own egress with it; that
    # is what vpn_scope=all is for.
    ("vpn_venue_subnets", "VPN_VENUE_SUBNETS", str, ""),
    # Public address or DDNS name of this box, used only to render the config
    # the laptop pastes in. Ogamdo never dials out; the peer dials in.
    ("vpn_endpoint_host", "VPN_ENDPOINT_HOST", str, ""),
]
_MEM_SUFFIX = {"b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


def parse_mem_limit(value: Any) -> int:
    """Docker size string -> bytes. Accepts '12g', '8192m', '512K', or a plain
    byte count. Raises ValueError on anything else, so a typo in the UI is a
    400 rather than a silently-wrong cgroup limit."""
    s = str(value).strip().lower().replace("ib", "")
    if not s:
        raise ValueError("empty memory limit")
    mult = 1
    if s[-1] in _MEM_SUFFIX:
        mult = _MEM_SUFFIX[s[-1]]
        s = s[:-1].strip()
    try:
        n = float(s)
    except ValueError:
        raise ValueError(f"not a size: {value!r} (use e.g. '12g', '8192m')")
    # `float()` happily accepts 'inf' / 'nan'. `inf <= 0` is False, so an
    # infinity sailed past the positivity check and blew up in int() with
    # OverflowError — which the route catches as ValueError only, turning a
    # typo into an HTTP 500 instead of the promised 400.
    if not math.isfinite(n):
        raise ValueError(f"not a size: {value!r} (use e.g. '12g', '8192m')")
    if n <= 0:
        raise ValueError(f"memory limit must be positive: {value!r}")
    want = int(n * mult)
    # Upper bound. Without one, '1000g' on a 16 GB host was accepted, written
    # to the cgroup and reported as success — leaving the worker effectively
    # UNCAPPED, i.e. exactly the state the cap exists to prevent, while the UI
    # showed a reassuring number.
    total = _host_mem_total_bytes()
    if total and want > total:
        raise ValueError(
            f"{value!r} ({want:,} B) exceeds host RAM ({total:,} B) — that "
            f"leaves the container effectively uncapped"
        )
    return want


def _host_mem_total_bytes() -> int:
    """Host MemTotal in bytes, or 0 when unreadable (non-Linux, restricted)."""
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return 0


_SECRET_KEYS = {
    "anthropic_api_key",
    "xai_api_key",
    "openai_api_key",
    "auth_token",
}

_lock = threading.Lock()


def _coerce(value: Any, typ: type) -> Any:
    """Cast `value` to `typ`, with sane handling for bool.

    Plain `bool("false")` returns True (any non-empty string is truthy).
    For settings that come from env vars or HTTP form data we want
    "false"/"0"/"no"/"off" → False, "true"/"1"/"yes"/"on" → True.
    Everything else falls back to `typ(value)`.
    """
    if typ is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        s = str(value).strip().lower()
        if s in ("", "0", "false", "no", "off", "none", "null"):
            return False
        return True
    if typ is str:
        # Strip. A settings value arrives from an HTML form or a paste, and a
        # stray leading space is invisible in every UI that shows it — the
        # stored callback_url was ' https://…trycloudflare.com', which would
        # have broken `curl "$CALLBACK_URL"` the moment anything used it.
        # Coercing here fixes reads AND writes for every string setting at
        # once, rather than one accessor at a time.
        return str(value).strip()
    return typ(value)


def load_settings() -> dict[str, Any]:
    if not SETTINGS_PATH.exists():
        return {}
    try:
        return json.loads(SETTINGS_PATH.read_text())
    except Exception:
        return {}


def save_settings(d: dict[str, Any]) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = SETTINGS_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(d, indent=2))
        tmp.replace(SETTINGS_PATH)


def get_setting(key: str) -> Any:
    settings = load_settings()
    for k, env_key, typ, default in SCHEMA:
        if k != key:
            continue
        v = settings.get(k)
        if v not in (None, ""):
            try:
                return _coerce(v, typ)
            except (TypeError, ValueError):
                return v
        if env_key:
            ev = os.environ.get(env_key, "")
            if ev != "":
                try:
                    return _coerce(ev, typ)
                except (TypeError, ValueError):
                    return ev
        return default
    return None


def apply_to_env() -> None:
    """Push current settings into the process env so libraries that read
    `os.environ["ANTHROPIC_API_KEY"]` (etc.) see them.

    Called by orchestrators at the start of each job — that way the user
    can change the key via the UI and the next job picks it up without a
    container restart.

    For ANTHROPIC_API_KEY / XAI_API_KEY / OPENAI_API_KEY: a placeholder value (e.g.
    "sk-ant-..." or a value ending in "...") is treated as unset so the
    agent falls back to OAuth / browser credentials on disk.
    """
    for key, env_key, typ, _ in SCHEMA:
        if not env_key:
            continue
        v = get_setting(key)
        if v in (None, ""):
            continue
        if key in ("anthropic_api_key", "xai_api_key", "openai_api_key"):
            sv = str(v)
            if sv.startswith("sk-ant-...") or sv.endswith("..."):
                os.environ.pop(env_key, None)
                continue
        os.environ[env_key] = str(v)


def has_claude_oauth() -> bool:
    """True if the worker container has a Claude Code OAuth credentials file
    (mounted from the host's ~/.claude). Used to detect whether claude.ai
    subscription auth is available even when no API key is configured.
    """
    candidates = [
        Path("/root/.claude/.credentials.json"),
        Path("/root/.claude/credentials.json"),
        Path.home() / ".claude" / ".credentials.json",
        Path.home() / ".claude" / "credentials.json",
    ]
    for c in candidates:
        try:
            if c.is_file() and c.stat().st_size > 0:
                return True
        except Exception:
            pass
    return False


def has_anthropic_api_key() -> bool:
    """True if a real (non-placeholder) Anthropic API key is configured."""
    v = str(get_setting("anthropic_api_key") or "")
    if not v:
        return False
    if v.startswith("sk-ant-...") or v.endswith("..."):
        return False
    return True


def has_claude_auth() -> bool:
    return has_anthropic_api_key() or has_claude_oauth()


def has_xai_api_key() -> bool:
    """True if a real (non-placeholder) xAI API key is configured."""
    v = str(get_setting("xai_api_key") or "")
    if not v:
        return False
    if v.endswith("..."):
        return False
    return True


def has_grok_auth_file() -> bool:
    """True if Grok CLI browser/OAuth credentials exist on disk.

    The worker may mount the host ``~/.grok`` (or equivalent) so
    ``grok login`` credentials work without stuffing XAI_API_KEY into
    settings. Paths mirror the Claude OAuth check.
    """
    candidates = [
        Path("/root/.grok/auth.json"),
        Path.home() / ".grok" / "auth.json",
        Path(os.environ.get("GROK_HOME", "") or "/nonexistent") / "auth.json",
    ]
    for c in candidates:
        try:
            if c.is_file() and c.stat().st_size > 0:
                return True
        except Exception:
            pass
    return False


def has_grok_auth() -> bool:
    return has_xai_api_key() or has_grok_auth_file()


def has_openai_api_key() -> bool:
    """True if a real (non-placeholder) OpenAI API key is configured."""
    v = str(get_setting("openai_api_key") or "")
    return bool(v and not v.endswith("...") and v not in {"sk-...", "sk-proj-..."})


def codex_auth_method() -> str:
    """Return the non-secret auth mode from Codex's cache, if available.

    The token payload is never returned or logged. Containers use file-backed
    auth because a host OS keyring cannot be mounted into Docker.
    """
    candidates = [
        Path(os.environ.get("CODEX_HOME", "") or "/nonexistent") / "auth.json",
        Path("/root/.codex/auth.json"),
        Path.home() / ".codex" / "auth.json",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        try:
            if not candidate.is_file() or candidate.stat().st_size <= 0:
                continue
            data = json.loads(candidate.read_text())
            mode = (
                str(data.get("auth_mode") or data.get("authMode") or "unknown")
                .strip()
                .lower()
            )
            return mode or "unknown"
        except Exception:
            continue
    return ""


def has_codex_auth_file() -> bool:
    return bool(codex_auth_method())


def has_codex_oauth() -> bool:
    """Whether a file-backed ChatGPT login is mounted for Codex CLI."""
    mode = codex_auth_method()
    return mode in {"chatgpt", "oauth", "chatgpt_oauth"}


def get_gpt_runtime() -> str:
    value = str(get_setting("gpt_runtime") or "codex").strip().lower()
    return value if value in {"codex", "responses"} else "codex"


def get_agent_provider() -> str:
    """Return the active agent backend: ``claude``, ``grok`` or ``gpt``.

    Unknown / empty values fall back to ``claude`` so a typo in settings
    never silently disables the only fully-wired path.
    """
    v = str(get_setting("agent_provider") or "claude").strip().lower()
    return v if v in AGENT_PROVIDERS else "claude"


JUDGE_MODES = ("off", "shadow", "enforce")


def get_judge_mode() -> str:
    """`off` | `shadow` | `enforce`.

    `judge_mode` wins when explicitly set; otherwise it is derived from the
    legacy boolean so no existing deployment changes behaviour by upgrading.
    `shadow` is deliberately NOT derivable — it runs the judge without letting
    it gate anything, and entering that by inference would leave an operator
    believing a gate is live when it is not.
    """
    raw = str(get_setting("judge_mode") or "").strip().lower()
    if raw in JUDGE_MODES:
        return raw
    legacy = get_setting("enable_judge")
    return "enforce" if (legacy is None or bool(legacy)) else "off"


# Stage 8 scope — operator decision, 2026-08-09. `enforce` is NOT global.
#
# SCOPE HISTORY — the constant has held two operator decisions, both measured.
#
# Stage 7 (handoff turn 0069, 2026-08-09) scoped it to pwn and web. That table
# could only measure discriminating power where BOTH outcome classes exist: pwn
# was 8 capture / 8 negative and web 3 / 3, while rev (13 / 1) and crypto
# (6 / 0) had no meaningful negative class — a judge answering "success" every
# time scores full marks against those, which is a measurement not taken rather
# than a good result.
#
# 2026-08-29: the operator widened it to every module. Re-measured over the
# jobs whose sandbox actually ran, which is the only population a judge wraps:
#
#     rev       29 runs   17 capture / 12 negative   <- negative class now real
#     crypto     7 runs    1 capture /  6 negative   <- negative class now real
#     web       13 runs    2 capture / 11 negative
#     pwn        5 runs    1 capture /  4 negative
#     web3       2 runs    0 capture /  2 negative   <- no positive class, n<5
#     misc       0 runs                              <- enforce is inert here
#     forensic   0 runs                              <- enforce is inert here
#
# So the stage-7 objection to rev and crypto is answered by the corpus that has
# accumulated since. It is NOT answered for web3, and misc/forensic never reach
# a judge at all because they have no sandbox phase — gating them changes
# nothing rather than gating on nothing. Those three are in scope because the
# operator chose one rule for every module over a scope that has to be
# relitigated each time a module's corpus grows.
#
# Deliberately a constant rather than a settings key: STATE.md's rule is that a
# new requirement has to displace an existing one or be approved, and the
# operator approved a scope, not a control surface.
JUDGE_ENFORCE_MODULES: tuple[str, ...] = (
    "pwn", "web", "rev", "crypto", "web3", "misc", "forensic",
)


def codex_multi_agent_v2_enabled() -> bool:
    """Should the Codex adapter advertise multi-agent v2 to main?

    Read at call time. A missing key advertises it, which is the historical
    behaviour.
    """
    try:
        v = get_setting("codex_multi_agent_v2")
    except Exception:
        return True
    return True if v is None else bool(v)


def judge_stop_halts_enabled() -> bool:
    """Does a judge STOP end the auto-retry loop?

    Read at call time so an operator can change it without a restart. A
    missing key halts, which is the historical behaviour.
    """
    try:
        v = get_setting("judge_stop_halts")
    except Exception:
        return True          # unreadable policy keeps the halt
    return True if v is None else bool(v)


def flag_harvester_enabled() -> bool:
    """Should the flag harvester adjudicate candidates for running jobs?

    Read at call time so the toggle takes effect without an API restart. A
    missing key is ON, matching the declared default.
    """
    try:
        v = get_setting("flag_harvester")
    except Exception:
        # Unreadable policy leaves it ON: the harvester cannot change a job's
        # outcome, so failing open costs a model call, never a wrong verdict.
        return True
    return True if v is None else bool(v)


def monitor_agent_enabled() -> bool:
    """Should the (retired) Monitor narration agent run at all?

    Read at call time so the operator can flip it without restarting the API.
    A missing key is OFF: this agent is being retired, and the failure mode
    worth guarding is "it came back on its own", not "it stayed off".

    The MONITOR_ENABLED env kill switch still wins independently — see
    modules/_monitor.py:monitor_enabled().
    """
    try:
        v = get_setting("monitor_agent")
    except Exception:
        return False
    return False if v is None else bool(v)


def prejudge_ship_gate_enabled() -> bool:
    """May a high-severity prejudge stop the sandbox from ever running?

    Read at call time, never captured: an operator flipping this must not need
    a restart to stop a gate that is costing them runs. A missing key is ON,
    which keeps the historical behaviour for a deployment that never set it.
    """
    try:
        v = get_setting("prejudge_ship_gate")
    except Exception:
        # FAIL SAFE, AND FAIL SAFE HERE TOO. _runner.py's call site already
        # wraps this, but "the gate survives an unreadable policy" is a
        # property of the gate, not of one caller's carefulness — the next
        # caller will not know to wrap it.
        return True
    return True if v is None else bool(v)


def effective_judge_mode(mode: str, module: str) -> str:
    """The mode a job of `module` actually runs under.

    Every known module is in scope as of 2026-08-29. The mechanism is kept
    rather than removed: a module can be taken back out by editing one tuple,
    and the shadow fallback below is still what an out-of-scope module gets —
    it keeps recording what the judge would have said instead of going dark.

    Unknown or empty module never reaches enforce, and that is NOT part of the
    scope decision — it is the defence against not knowing. "We could not tell
    which module this is" must not resolve to "gate it": a caller that cannot
    name the module cannot tell an unrecognised one apart from a typo, and a
    gate is the wrong thing to resolve an unknown into.
    """
    m = str(mode or "").strip().lower()
    if m not in JUDGE_MODES:
        return "off"
    if m != "enforce":
        return m
    return "enforce" if str(module or "").strip().lower() in JUDGE_ENFORCE_MODULES else "shadow"


def get_agent_role_providers() -> dict[str, str]:
    """Per-role backend overrides from Settings, sanitized.

    Returns ``{role: provider}`` keeping only entries whose provider is a
    known ROUTING TARGET. A malformed value yields ``{}`` — an unreadable
    override must degrade to "every role follows agent_provider", never to a
    half-applied map. Role names are NOT validated here; the resolver owns
    that, so a future role does not need a settings_io release to be routable.

    The target set is NOT ``AGENT_PROVIDERS``. Those are the JOB BACKENDS, and
    `local` is deliberately absent from them — it can drive a role and cannot
    drive a job. Checking a ROUTE against the backend list silently discarded
    every `local` route the operator saved: Settings stored it, the UI showed
    it back (the view reads the raw value), and this function dropped it on
    the way to the resolver, so a job created afterwards carried no monitor
    route at all and followed its Claude backend instead.

    Imported lazily rather than mirrored. A second hand-copied provider list
    is precisely how the first one drifted.
    """
    raw = get_setting("agent_role_providers")
    if not isinstance(raw, dict):
        return {}
    try:
        from modules.agent_provider import ROLE_TARGET_PROVIDERS as _targets
    except Exception:  # pragma: no cover — partially-initialised import
        _targets = AGENT_PROVIDERS
    out: dict[str, str] = {}
    for role, provider in raw.items():
        r = str(role or "").strip().lower()
        p = str(provider or "").strip().lower()
        if r and p in _targets:
            out[r] = p
    return out


def has_active_agent_auth() -> bool:
    """Auth available for whichever provider Settings currently selects."""
    provider = get_agent_provider()
    if provider == "grok":
        return has_grok_auth()
    if provider == "gpt":
        return (
            has_codex_oauth() if get_gpt_runtime() == "codex" else has_openai_api_key()
        )
    return has_claude_auth()


def mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def get_settings_view() -> dict[str, Any]:
    """Public view safe to send to the UI. Secrets are masked."""
    settings = load_settings()
    out: dict[str, Any] = {
        "claude_oauth_detected": has_claude_oauth(),
        "grok_auth_detected": has_grok_auth_file(),
        "codex_auth_detected": has_codex_auth_file(),
        "codex_oauth_detected": has_codex_oauth(),
        "codex_auth_method": codex_auth_method(),
        "agent_providers": list(AGENT_PROVIDERS),
    }
    for key, env_key, typ, default in SCHEMA:
        raw = settings.get(key)
        env_v = os.environ.get(env_key, "") if env_key else ""
        effective_raw = raw if raw not in (None, "") else env_v if env_v else default
        try:
            effective = (
                _coerce(effective_raw, typ)
                if effective_raw not in (None, "")
                else default
            )
        except (TypeError, ValueError):
            effective = effective_raw
        if key == "agent_provider":
            # Always expose a normalized value so the UI never has to
            # re-validate typos stored on disk.
            effective = str(effective or "claude").strip().lower()
            if effective not in AGENT_PROVIDERS:
                effective = "claude"
        if key == "gpt_runtime":
            effective = str(effective or "codex").strip().lower()
            if effective not in {"codex", "responses"}:
                effective = "codex"
        if key == "agent_output_language":
            from modules.output_language import normalize_output_language

            effective = normalize_output_language(effective)
        if key in _SECRET_KEYS:
            out[f"{key}_set"] = bool(raw)
            out[f"{key}_env_set"] = bool(env_v)
            out[f"{key}_masked"] = mask(str(raw or ""))
        else:
            out[key] = effective
            out[f"{key}_source"] = (
                "settings" if raw not in (None, "") else "env" if env_v else "default"
            )
    return out


def update_settings(patch: dict[str, Any]) -> dict[str, Any]:
    """Apply a patch. For each key in patch:
      - value is None or "" : clear the override (revert to env/default)
      - any other value     : set
    Keys not present in the patch dict are left untouched.
    """
    cur = load_settings()
    valid = {k for k, *_ in SCHEMA}
    for key, val in patch.items():
        if key not in valid:
            continue
        if val is None or (isinstance(val, str) and val == ""):
            cur.pop(key, None)
            continue
        if key == "agent_output_language":
            from modules.output_language import OUTPUT_LANGUAGES

            v = str(val).strip().lower()
            if v not in OUTPUT_LANGUAGES:
                raise ValueError(
                    "agent_output_language must be one of "
                    f"{OUTPUT_LANGUAGES}, got {val!r}"
                )
            cur[key] = v
            continue
        if key == "agent_provider":
            v = str(val).strip().lower()
            if v not in AGENT_PROVIDERS:
                raise ValueError(
                    f"agent_provider must be one of {AGENT_PROVIDERS}, got {val!r}"
                )
            cur[key] = v
            continue
        if key == "codex_turn_timeout_seconds":
            if isinstance(val, bool) or (
                isinstance(val, float) and not val.is_integer()
            ):
                raise ValueError("codex_turn_timeout_seconds must be a positive integer")
            try:
                v = int(val)
            except (TypeError, ValueError):
                raise ValueError("codex_turn_timeout_seconds must be a positive integer")
            if v <= 0:
                raise ValueError("codex_turn_timeout_seconds must be greater than zero")
            cur[key] = v
            continue
        if key == "gpt_runtime":
            v = str(val).strip().lower()
            if v not in {"codex", "responses"}:
                raise ValueError(
                    f"gpt_runtime must be one of ('codex', 'responses'), got {val!r}"
                )
            cur[key] = v
            continue
        for k, _, typ, _ in SCHEMA:
            if k == key:
                try:
                    cur[key] = _coerce(val, typ)
                except (TypeError, ValueError):
                    cur[key] = val
                break
    save_settings(cur)
    return get_settings_view()
