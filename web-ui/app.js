const API = "/api";

// Statuses at which a job stops changing, so the detail poller must stop too.
// NEAR modules/_monitor.py:_TERMINAL but deliberately NOT equal to it, and
// the two must not be "reconciled". They answer different questions:
// _TERMINAL is when the NARRATOR stops talking, this is when the UI stops
// polling. `hold` is in the Python set and must stay OUT of this one --
// a held job is waiting for the operator, and the way out of a hold is the
// Continue button with a New target, which only renders while the panel is
// still refreshing. Adding `hold` here silently removes the only exit.
// (test_target_hold asserts exactly that.) `error` is UI-only the other way.
// `stopped` was MISSING here while
// being the most common status in this deployment (12 of 32 jobs) — an
// operator-stopped job kept re-fetching 256 KB and re-colourising ~3,350 lines
// every 2s for as long as its panel stayed open. `error` was missing too.
// A rendered row's signature, kept OUT of the DOM. Storing markup in a
// data-sig attribute means writing a multi-kilobyte attribute per row and
// then trusting the browser to hand back the exact same string — quotes and
// newlines included — on every read. When it does not, the comparison fails
// on every poll, the row is rewritten on every poll, and the flicker has no
// visible cause. A WeakMap keyed by the element cannot disagree with itself,
// and it is released with the node.
const _ROW_SIG = new WeakMap();

// --- churn meter ----------------------------------------------------------
// Four separate causes of the same reported flicker were found and fixed by
// reading the code, and a fifth was reported anyway. Reading harder is not
// working; this counts what the DOM actually does. Cost is one observer and
// an integer per bucket — it stays on so the next report starts with an
// answer instead of a theory.
//
// Read it from the console:  __uiChurn()
window.__uiChurnCounts = Object.create(null);
(() => {
  const bucket = (node) => {
    let el = node && node.nodeType === 1 ? node : (node && node.parentElement);
    for (; el; el = el.parentElement) {
      if (el.classList && el.classList.length) {
        const known = ["live-fire-agent", "live-fire-agents-grid", "live-fire-vuln",
                       "live-fire-progress-list", "run-log", "gpt-timeline-feed",
                       "monitor-feed", "vuln-panel", "job-meta",
                       "run-log-footer"];
        const hit = known.find((k) => el.classList.contains(k));
        if (hit) return hit;
      }
      if (el.id === "jobs-list") return "jobs-list";
      if (el.id === "job-detail") return "job-detail(whole)";
    }
    // NAME THE UNKNOWN. "other" was the largest bucket in the second reading
    // and told nobody anything; a meter that cannot say WHERE is only half an
    // instrument. This walks up to four levels and describes what it found.
    let el2 = node && node.nodeType === 1 ? node : (node && node.parentElement);
    const path = [];
    for (let n = 0; el2 && n < 4; el2 = el2.parentElement, n++) {
      const cls = el2.classList && el2.classList.length
        ? "." + Array.from(el2.classList).slice(0, 2).join(".") : "";
      path.unshift((el2.id ? "#" + el2.id : el2.tagName.toLowerCase()) + cls);
    }
    return "other: " + path.join(" > ");
  };
  try {
    new MutationObserver((records) => {
      for (const r of records) {
        const k = bucket(r.target);
        window.__uiChurnCounts[k] = (window.__uiChurnCounts[k] || 0) + 1;
      }
    }).observe(document.body, {childList: true, subtree: true,
                               characterData: true, attributes: true});
  } catch (_) { /* an instrument must never break the page */ }
})();
window.__htmlDiff = function () { return window.__lastHtmlDiffs || []; };
window.__uiChurn = function (reset, keep) {
  const rows = Object.entries(window.__uiChurnCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, keep || 14);
  if (reset) window.__uiChurnCounts = Object.create(null);
  return Object.fromEntries(rows);
};
const JOB_TERMINAL = ["finished", "failed", "stopped", "error", "no_flag", "flag_ready"];


// Catalog of Claude models offered in every Analyze form. Add new
// snapshot/alias names here to expose them. Empty value = "use the
// global Settings model".
const CLAUDE_MODELS = [
  // Aliases (Anthropic recommends pinning to dated snapshots in
  // production). Sorted by family (Opus → Sonnet → Haiku) then by
  // version (newest first). 1M-context variants follow their
  // alias immediately so the dropdown groups the same model's
  // 200K / 1M choices together.
  //
  // The SDK accepts the `[1m]` suffix; claude-code auto-enables
  // the long-context beta. Verified 2026-05-24 under the worker's
  // current authenticated plan: Opus 4.7[1m] and Opus 4.1[1m] both
  // work. Opus 4.8[1m] added 2026-05-29 — confirmed available on
  // the current plan (the Claude Code session driving this tool runs
  // on claude-opus-4-8[1m]).
  // Sonnet/Haiku [1m] respond with "Usage credits are required for
  // long context requests" — billing-tier limited and intentionally
  // not listed here.
  //
  // Claude 5 family — newest. Fable 5 base + [1m] verified 2026-07-02
  // (FABLE_OK / FABLE1M_OK); Sonnet 5 base + [1m] verified 2026-07-19
  // (SONNET5_OK / SONNET51M_OK) — both trivial-prompt round-trips on the
  // worker's authenticated plan. Unlike Sonnet 4.x, whose [1m] is credit-
  // gated ("Usage credits are required for long context requests"), Sonnet
  // 5[1m] and Fable 5[1m] are NOT credit-gated here.
  // Opus 5 base + [1m] added 2026-07-24, same way — verified by trivial
  // round-trip IN THE WORKER (OPUS5_OK / OPUS51M_OK) on the authenticated
  // plan, so it is the new flagship Opus and leads the list. (Still no
  // Haiku 5.) NOTE: this only ADDS choices — the global default stays
  // whatever Settings says; nothing here changes a running job's model.
  "claude-opus-5",
  "claude-opus-5[1m]",
  // Fable 5.1 added 2026-09-05 — verified the same way as the rest: a
  // trivial round-trip in the WORKER on the authenticated plan
  // (claude-fable-5-1 and its [1m] both returned PROBE_OK). It was the only
  // model in the assistant's own known-current set missing from this list.
  "claude-fable-5-1",
  "claude-fable-5-1[1m]",
  "claude-fable-5",
  "claude-fable-5[1m]",
  "claude-sonnet-5",
  "claude-sonnet-5[1m]",
  "claude-opus-4-8",
  "claude-opus-4-8[1m]",
  "claude-opus-4-7",
  "claude-opus-4-7[1m]",
  "claude-opus-4-6",
  "claude-opus-4-6[1m]",
  "claude-opus-4-1",
  "claude-opus-4-1[1m]",
  "claude-opus-4",
  "claude-sonnet-4-6",
  "claude-sonnet-4-5",
  "claude-sonnet-4",
  "claude-haiku-4-5",
  "claude-haiku-4",
  // Dated snapshots (most stable for reproducible runs). Same sort
  // order — Opus / Sonnet / Haiku, newest first.
  "claude-opus-4-7-20251205",
  "claude-opus-4-1-20250805",
  "claude-sonnet-4-6-20251119",
  "claude-sonnet-4-5-20250929",
  "claude-sonnet-4-20250514",
  "claude-haiku-4-5-20251001",
  "claude-3-7-sonnet-latest",
  "claude-3-5-sonnet-20241022",
  "claude-3-5-haiku-20241022",
];

// Reasoning effort levels accepted by ClaudeAgentOptions(effort=...).
// SDK translates these to a `--effort <value>` CLI arg; empty = SDK
// default (model-dependent). Higher effort means longer per-turn
// thinking budget and (typically) higher per-call cost — pick "max"
// for high-stakes synthesis turns and "low" for cheap probes.
const CLAUDE_EFFORTS = ["low", "medium", "high", "xhigh", "max"];

// Grok Build / xAI model ids offered in Settings (and per-job dropdowns
// when agent_provider=grok). `grok-build` is the coding-agent default.
//
// Probed 2026-09-05 on grok 1.0.13: ALL SIX returned PROBE_OK. `grok-4` first
// read as a failure at a 40s timeout and passed at 150s — it is slow, not
// missing, which is worth knowing before anyone trims it from this list.
const GROK_MODELS = [
  "grok-4.6",
  "grok-4.5",
];

// Grok CLI effort ladder (union with Claude's so per-job dropdowns stay
// one list). Empty = CLI/model default.
const GROK_EFFORTS = ["none", "minimal", "low", "medium", "high", "xhigh", "max"];

// OpenAI Codex / Responses model ids. Keep the visible Codex catalog here so
// the same choices are available globally, per job, and in provider presets.
//
// Probed 2026-09-05 on codex-cli 0.153.1, `gpt_runtime=codex` (this
// deployment), one `codex exec` round-trip each. Three outcomes, and the
// difference between the last two matters:
//
//   OK           the model answered.
//   ACCOUNT      the model EXISTS — it just refuses this auth:
//                400 "not supported when using Codex with a ChatGPT account".
//                Kept and marked; an API-key deployment can use it.
//   UNKNOWN      codex printed "Model metadata for `X` not found. Defaulting
//                to fallback metadata" — the slug is not in its catalogue.
//
// HOW THE UNKNOWNS WERE CAUGHT, because a plain probe cannot: an unrecognised
// slug still ANSWERS. `gpt-6-zzz-fake` returned a correct reply, as did seven
// invented `gpt-6-*` names. Success proves nothing; only the metadata warning
// separates a real model from a fallback. Verify that way or not at all.
//
// gpt-6-astra added — the current Codex TUI model, verified with no metadata
// warning and a live answer. `gpt-6` itself is NOT a real slug.
const GPT_MODELS = [
  "gpt-6-astra",              // OK — newest, works on ChatGPT OAuth
  "gpt-6-astra-mini",         // ACCOUNT — real, needs an API key
  "gpt-6-astra-codex",        // ACCOUNT — real, needs an API key
  "gpt-5.6-sol",              // OK
  "gpt-5.6-terra",            // OK
  "gpt-5.6-luna",             // OK
  "gpt-daybreak-blue-latest", // OK
  "gpt-5.5",                  // OK
  "gpt-5.4-mini",             // OK
  "gpt-5.3-codex-spark",      // OK
  // Removed 2026-09-05: "gpt-5.6", "gpt-5.4", "gpt-6". All three are UNKNOWN
  // slugs — codex has no metadata for them and silently falls back, so
  // selecting one gave a worse model with no error. The old comment here
  // called gpt-5.6 "the Responses API flagship alias"; whatever it once was,
  // this CLI does not know it.
];
const GPT_EFFORTS = ["none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"];

// Active provider from last Settings load — drives per-job model lists.
let activeAgentProvider = "claude";
// Non-secret Settings snapshot used to keep auth readiness visible while the
// operator changes provider/runtime controls before saving.
let latestSettingsView = null;

function providerAuthSummary(provider, settings, gptRuntime) {
  const s = settings || {};
  if (provider === "gpt") {
    const runtime = gptRuntime === "responses" ? "responses" : "codex";
    if (runtime === "responses") {
      const ready = !!(s.openai_api_key_set || s.openai_api_key_env_set);
      return {
        ready,
        label: "OpenAI GPT Responses API",
        badge: ready ? "✓ API key ready" : "✗ API key missing",
        detail: ready
          ? "API-key billing is ready."
          : "configure OPENAI_API_KEY first.",
      };
    }
    const ready = !!s.codex_oauth_detected;
    return {
      ready,
      label: "OpenAI Codex",
      badge: ready ? "✓ ChatGPT OAuth ready" : "✗ OAuth missing",
      detail: ready
        ? "ChatGPT OAuth subscription is ready."
        : "run `codex login` on the host first.",
    };
  }
  if (provider === "grok") {
    const login = !!s.grok_auth_detected;
    const key = !!(s.xai_api_key_set || s.xai_api_key_env_set);
    const ready = login || key;
    return {
      ready,
      label: "Grok Build (ACP)",
      badge: login ? "✓ login auth ready" : (key ? "✓ API key ready" : "✗ auth missing"),
      detail: ready
        ? "ready for jobs."
        : "configure an xAI key or Grok login first.",
    };
  }
  const oauth = !!s.claude_oauth_detected;
  const key = !!(s.anthropic_api_key_set || s.anthropic_api_key_env_set);
  const ready = oauth || key;
  return {
    ready,
    label: "Claude Agent SDK",
    badge: oauth ? "✓ OAuth ready" : (key ? "✓ API key ready" : "✗ auth missing"),
    detail: ready ? "ready for jobs." : "set an API key or run `claude login` first.",
  };
}

function renderProviderAuthUI(provider, {unsaved = false} = {}) {
  if (!latestSettingsView) return;
  const runtime = document.querySelector("#settings-form [name=gpt_runtime]")?.value
    || latestSettingsView.gpt_runtime || "codex";
  for (const p of ["claude", "grok", "gpt"]) {
    const badge = document.getElementById(`${p}-provider-auth`);
    if (!badge) continue;
    const state = providerAuthSummary(p, latestSettingsView, runtime);
    badge.textContent = state.badge;
    badge.classList.toggle("auth-ready", state.ready);
    badge.classList.toggle("auth-missing", !state.ready);
  }
  const selected = ["claude", "grok", "gpt"].includes(provider)
    ? provider : "claude";
  const state = providerAuthSummary(selected, latestSettingsView, runtime);
  const status = document.getElementById("provider-status");
  if (!status) return;
  status.textContent = `${unsaved ? "Selected (unsaved)" : "Active"}: ${state.label} — ${state.detail}`
    + (unsaved ? " Click Save to apply to the next job." : "");
  status.style.color = state.ready ? "var(--green)" : "var(--red)";
}

function fillModelSelects(provider) {
  const p = provider || activeAgentProvider || "claude";
  const models = p === "grok" ? GROK_MODELS : (p === "gpt" ? GPT_MODELS : CLAUDE_MODELS);
  // Per-job selects: empty = "default from Settings"
  document.querySelectorAll('[data-role="model-select"]').forEach((sel) => {
    const prev = sel.value;
    sel.innerHTML = "";
    sel.appendChild(new Option("(default — Settings value)", ""));
    for (const m of models) sel.appendChild(new Option(m, m));
    if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
  });
  // Global Claude Settings select (always Claude catalog).
  document.querySelectorAll('[data-role="model-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use env / default)", ""));
    for (const m of CLAUDE_MODELS) sel.appendChild(new Option(m, m));
  });
  // Global Grok Settings select.
  document.querySelectorAll('[data-role="grok-model-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use env / default)", ""));
    for (const m of GROK_MODELS) sel.appendChild(new Option(m, m));
  });
  document.querySelectorAll('[data-role="gpt-model-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use env / default)", ""));
    for (const m of GPT_MODELS) sel.appendChild(new Option(m, m));
  });
}

function fillEffortSelects(provider) {
  const p = provider || activeAgentProvider || "claude";
  const efforts = p === "grok" ? GROK_EFFORTS : (p === "gpt" ? GPT_EFFORTS : CLAUDE_EFFORTS);
  // Per-job: empty = Settings value (falls through to SDK default if
  // Settings is also empty). Same UX as fillModelSelects.
  document.querySelectorAll('[data-role="effort-select"]').forEach((sel) => {
    const prev = sel.value;
    sel.innerHTML = "";
    sel.appendChild(new Option("(default — Settings value)", ""));
    for (const e of efforts) sel.appendChild(new Option(e, e));
    if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
  });
  document.querySelectorAll('[data-role="effort-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use SDK default)", ""));
    for (const e of CLAUDE_EFFORTS) sel.appendChild(new Option(e, e));
  });
  document.querySelectorAll('[data-role="grok-effort-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use CLI default)", ""));
    for (const e of GROK_EFFORTS) sel.appendChild(new Option(e, e));
  });
  document.querySelectorAll('[data-role="gpt-effort-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use model default)", ""));
    for (const e of GPT_EFFORTS) sel.appendChild(new Option(e, e));
  });
}

function setProviderUI(provider) {
  const p = ["claude", "grok", "gpt"].includes(provider) ? provider : "claude";
  activeAgentProvider = p;
  const radio = document.querySelector(
    `#settings-form input[name=agent_provider][value="${p}"]`
  );
  if (radio) radio.checked = true;
  const claudeBlock = document.getElementById("settings-claude-block");
  const grokBlock = document.getElementById("settings-grok-block");
  const gptBlock = document.getElementById("settings-gpt-block");
  if (claudeBlock) claudeBlock.classList.toggle("provider-active", p === "claude");
  if (grokBlock) grokBlock.classList.toggle("provider-active", p === "grok");
  if (gptBlock) gptBlock.classList.toggle("provider-active", p === "gpt");
  fillModelSelects(p);
  fillEffortSelects(p);
  if (document.getElementById("preset-active")) setPresetProvider(p);
}

// --- local runtime (Ollama) -------------------------------------------------
// Probed on demand rather than polled: it answers in milliseconds when it is
// up, and a Settings page that pings a possibly-absent host every few seconds
// would spend the operator's attention on a box they may not run at all.
async function _probeOllama() {
  const form = document.getElementById("settings-form");
  if (!form) return;
  const urlEl = form.querySelector("[name=ollama_url]");
  const sel = form.querySelector("[name=ollama_model_select]");
  const hid = form.querySelector("[name=ollama_model]");
  const status = form.querySelector(".ollama-probe-status");
  const say = (s) => { if (status) status.textContent = s; };
  const url = (urlEl && urlEl.value || "").trim();
  say("확인 중…");
  try {
    // The typed value is probed, not the saved one: the field has to be
    // testable BEFORE Save, or the only way to check an address is to commit
    // to it first.
    const q = url ? `?url=${encodeURIComponent(url)}` : "";
    const res = await fetch(`${API}/settings/ollama${q}`);
    const d = await res.json().catch(() => ({}));
    if (!d.configured) { say("엔드포인트가 비어 있습니다 — 로컬 타깃이 꺼진 상태입니다"); return; }
    if (!d.reachable) { say(`✗ 연결 실패 — ${d.detail || "no answer"}`); return; }
    const models = d.models || [];
    const loaded = (d.loaded || []).map((m) => m.name);
    if (sel) {
      const keep = (hid && hid.value) || "";
      sel.innerHTML = `<option value="">(선택 안 함)</option>`
        + models.map((m) => {
            const on = loaded.includes(m.name) ? " · 상주" : "";
            const meta = [m.params, m.quant, m.size_gb ? m.size_gb + "GB" : ""]
              .filter(Boolean).join(" ");
            return `<option value="${escapeHtml(m.name)}"${m.name === keep ? " selected" : ""}>`
                 + `${escapeHtml(m.name)}${meta ? ` — ${escapeHtml(meta)}` : ""}${on}</option>`;
          }).join("");
    }
    say(`✓ ${models.length}개 모델${loaded.length ? ` · 상주: ${loaded.join(", ")}` : ""}`);
  } catch (e) {
    say(`✗ ${e}`);
  }
}

// Discovery answers "where is it", the probe answers "what has it got". Kept
// apart because they fail differently: nothing answering on any address is a
// host problem, and an address that answers with no models is a pull problem.
//
// It FILLS the field and stops there. Writing the setting itself would be a
// change the operator never saw and cannot undo by walking away, so Save stays
// their click — the value is just no longer theirs to type.
async function _discoverOllama() {
  const form = document.getElementById("settings-form");
  if (!form) return false;
  const urlEl = form.querySelector("[name=ollama_url]");
  const status = form.querySelector(".ollama-probe-status");
  const say = (s) => { if (status) status.textContent = s; };
  say("주소 탐지 중…");
  try {
    const res = await fetch(`${API}/settings/ollama/discover`);
    const d = await res.json().catch(() => ({}));
    if (!d.discovered) {
      const tried = (d.tried || []).map((t) => t.url).join(", ");
      say(`✗ 응답 없음 — 시도: ${tried || "(후보 없음)"}. `
        + `WSL에서 ollama serve 가 OLLAMA_HOST=0.0.0.0 로 떠 있는지 확인하세요.`);
      return false;
    }
    if (urlEl) {
      urlEl.value = d.url || "";
      // Marks the form dirty on purpose: a filled field that Save would not
      // persist is the worst of both worlds.
      urlEl.dispatchEvent(new Event("change", { bubbles: true }));
    }
    await _probeOllama();
    const now = (status && status.textContent) || "";
    say(`${d.url} 발견 · ${now}`.trim());
    return true;
  } catch (e) {
    say(`✗ ${e}`);
    return false;
  }
}

document.addEventListener("click", (e) => {
  if (e.target.closest('[data-action="ollama-probe"]')) _probeOllama();
  if (e.target.closest('[data-action="ollama-discover"]')) _discoverOllama();
});
document.addEventListener("change", (e) => {
  const sel = e.target.closest('[data-action="ollama-model-select"]');
  if (!sel) return;
  const hid = document.querySelector("#settings-form [name=ollama_model]");
  if (hid) hid.value = sel.value || "";
});

let selectedJob = null;
let pollTimer = null;

// Per-job token snapshots used to render Δ in the tokens pill so the
// run-log footer shows live "↓X k tokens" deltas the way Claude
// Code's status line does. Keyed by job id; reset whenever the job
// changes or its turn count regresses (= retry/resume forked it).
const _prevTokens = {};

// In-flight reviewer/retry streams, keyed by the job the retry was
// launched FROM. streamRetry() runs a POST fetch + ReadableStream with NO
// AbortController, so navigating to another job (which rebuilds
// #job-detail.innerHTML and destroys the ephemeral retry-panel) does NOT
// kill the stream — it keeps running server-side. Without a place to hold
// the "reviewer in progress" state OUTSIDE the DOM, re-entering the job
// rebuilds the detail from server data alone and the panel is gone. This
// map holds each stream's state so renderReviewerPanel() can repaint it
// after any detail re-render. Entry shape:
//   { flow, flowEmoji, flowVerb, isManual, stageText, text, firstToken,
//     status: "running"|"done"|"error", kind, newJobId }
// Known limit: in-page only — a full page reload (F5) loses it, and the
// POST stream can't be re-attached after reload anyway. The reported bug
// is SPA navigation (leave the job window, come back), which this covers.
const activeReviewers = new Map();

// Live SSE stream state. We keep the 2-second poller as a fallback so
// the panel still works when the server-side stream is unavailable
// (older worker image, redis hiccup, browser without EventSource).
// When a live stream connects, the poller's interval is widened so the
// stream is the primary signal and the poller is only there to refresh
// derived fields the stream doesn't carry (file links, full result_data).
let liveStream = null;
let liveStreamJobId = null;
let liveStreamConnected = false;
let _metaRefreshTimer = null;

// ── Flag alarm: bottom-right toast + beep on a NEW [FLAG?] candidate or
// a NEW promoted 🚩 flag, for ANY job (works even with no detail panel
// open, via the global poller added at startup). _flagSeen tracks the
// VALUES already alarmed per job; the FIRST poll seeds the baseline
// silently so we never alarm for jobs already flagged when the page loads.
//
// Values, not counts. The count version alarmed on `nCands > prev.cands`,
// which produced BOTH of the symptoms the operator reported:
//   * DUPLICATES — refreshJobs() has no in-flight guard and is driven by two
//     timers plus ~10 call sites, so two fetches can land out of order. The
//     older response lowers the stored count, and the next poll re-detects
//     the same transition and re-toasts the SAME flag. A set only ever grows,
//     so a stale response is now a subset that adds nothing.
//   * MISSED — the old code toasted `fc[fc.length - 1]` once per pass and
//     used `else if`, so if a poll brought two candidates only the last one
//     alarmed, and if it brought a flag AND a candidate the candidate was
//     swallowed. Both were then recorded as seen, so they never fired later.
//     Now every fresh value alarms, and flags and candidates are independent.
// (The comment on _showFlagToast already claimed "per-candidate dedup in
// _detectFlagTransitions" — this is that dedup finally existing.)
const _flagSeen = {};            // jobId -> { flags: Set<string>, cands: Set<string> }
let _flagAlarmReady = false;     // becomes true after the baseline pass
let _flagAudioCtx = null;        // lazy WebAudio context for the beep

function _scheduleMetaRefresh(id) {
  if (_metaRefreshTimer) return;
  _metaRefreshTimer = setTimeout(() => {
    _metaRefreshTimer = null;
    if (selectedJob === id) renderJob(id);
  }, 350);
}

// User preference: hide/show the live SDK panel. Persisted so the
// choice survives page reloads. Defaults to "show".
let _sdkLiveHidden = (() => {
  try { return localStorage.getItem("sdk_live_hidden") === "1"; }
  catch (_) { return false; }
})();

// Log-tail style live feed: one row per SDK event, single fixed-height
// pane, no card chrome, no animations. The earlier card-based design
// caused reflow + typing animation that read as visual chaos.
const _SDK_MAX_LINES = 60;
const _SDK_BODY_PREVIEW_CHARS = 240;

function _renderSdkEvent(id, payload) {
  const panel = document.querySelector(
    `.sdk-live[data-job-id="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`,
  );
  if (!panel) return;
  panel.hidden = false;
  if (_sdkLiveHidden) panel.classList.add("collapsed");
  const feed = panel.querySelector(".sdk-live-feed");
  if (!feed) return;

  const line = document.createElement("div");
  _fillSdkRow(line, payload);

  const wasAtBottom =
    feed.scrollTop + feed.clientHeight >= feed.scrollHeight - 8;
  feed.appendChild(line);
  while (feed.children.length > _SDK_MAX_LINES) {
    feed.removeChild(feed.firstChild);
  }
  if (wasAtBottom) feed.scrollTop = feed.scrollHeight;
}

// The row, as markup. Pure: no lookup, no measurement, no insertion — so the
// backfill can build sixty of them without touching the document once.
function _sdkRowHtml(payload) {
  const kind = payload.kind || "";
  const tag = payload.tag || "main";

  let label, body, kindClass;
  if (kind === "text") {
    label = "AGENT"; kindClass = "sdk-text"; body = payload.text || "";
  } else if (kind === "thinking") {
    label = "THINK"; kindClass = "sdk-think"; body = payload.thinking || "";
  } else if (kind === "tool_use") {
    label = `TOOL ${payload.name || "?"}`;
    kindClass = "sdk-tool";
    try {
      body = typeof payload.input === "string"
        ? payload.input
        : JSON.stringify(payload.input);
    } catch (_) { body = String(payload.input || ""); }
  } else if (kind === "tool_result") {
    label = payload.is_error ? "RESULT(err)" : "RESULT";
    kindClass = payload.is_error ? "sdk-error" : "sdk-result";
    body = payload.preview || "";
  } else {
    label = kind.toUpperCase(); kindClass = "sdk-misc";
    try { body = JSON.stringify(payload); } catch (_) { body = String(payload); }
  }

  // Collapse whitespace + truncate so each event is exactly one row.
  // The full body still lands in the run-log below; this pane is for
  // an at-a-glance live view, not the full transcript.
  const preview = (body || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, _SDK_BODY_PREVIEW_CHARS);

  return {
    cls: `sdk-line ${kindClass}`,
    html: `<span class="sdk-line-tag">[${escapeHtml(tag)}]</span> `
      + `<span class="sdk-line-label">${escapeHtml(label)}</span>: `
      + `<span class="sdk-line-body">${escapeHtml(preview)}</span>`,
  };
}

function _fillSdkRow(el, payload) {
  const r = _sdkRowHtml(payload);
  el.className = r.cls;
  el.innerHTML = r.html;
}

// THE BACKFILL, IN ONE PASS.
//
// Opening a job replays up to 400 sdk events, and each one used to go through
// _renderSdkEvent: a document-wide querySelector, then THREE geometry reads
// (scrollTop, clientHeight, scrollHeight) before the append and one more after.
// A geometry read invalidates layout for the WHOLE document, not the subtree,
// so the cost scales with everything else on the page — which is why it hid
// from every measurement taken against the panel alone.
//
// Measured in real Chrome 148 with the real stylesheet and the real 400
// payloads from job 19cf9578a0fc:
//
//     panel only        (1,182 elements)      39 ms
//     with the page     (2,316 elements)   1,370 ms      <-- 35x
//
// The operator saw about three seconds, and reported the two symptoms this
// predicts: "LIVE AGENT ACTIVITY가 안뜨고 3초후에 렉이 풀리면서 뜸" — the panel
// is what the loop is building — and the directory browser stuck on "loading…"
// for the same window, because its fetch callback could not run while the main
// thread was doing 1,600 forced layouts.
//
// Only the last _SDK_MAX_LINES survive the trim anyway, so the other 340 rows
// were built, laid out and destroyed for nothing.
function _renderSdkBatch(id, payloads) {
  if (!payloads || !payloads.length) return;
  const panel = document.querySelector(
    `.sdk-live[data-job-id="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`,
  );
  if (!panel) return;
  panel.hidden = false;
  if (_sdkLiveHidden) panel.classList.add("collapsed");
  const feed = panel.querySelector(".sdk-live-feed");
  if (!feed) return;

  // Keep whatever is already there (a live event can land mid-backfill), then
  // trim once at the end rather than per row.
  const keep = payloads.slice(-_SDK_MAX_LINES);
  const frag = document.createDocumentFragment();
  for (const p of keep) {
    const el = document.createElement("div");
    _fillSdkRow(el, p);
    frag.appendChild(el);
  }
  feed.appendChild(frag);
  while (feed.children.length > _SDK_MAX_LINES) {
    feed.removeChild(feed.firstChild);
  }
  feed.scrollTop = feed.scrollHeight;
}

function _appendLiveLogLine(id, payload) {
  // Backfill events are redundant — renderJob's /log fetch already
  // populated the pre. Streaming starts strictly after backfill_done.
  if (payload.backfill) return;
  // A filter is active: the <pre> shows only matching lines, so don't append
  // unfiltered live lines. The 2s poll re-fetches + re-applies the filter.
  if ((_logSearch[id] || "").trim()) return;
  const pre = document.querySelector(
    `pre.run-log[data-job-id="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`,
  );
  if (!pre) return;
  const wasAtBottom =
    pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 12;
  const tsPrefix = payload.ts ? `[${payload.ts}] ` : "";
  const raw = tsPrefix + (payload.line || "") + "\n";
  // Use colorizeRunLog so the appended line picks up the same styling
  // as polled renders (agent tags get colored, paths underlined, etc.).
  let colored = raw;
  try {
    colored = colorizeRunLog(raw, null);
  } catch (_) {
    colored = escapeHtml(raw);
  }
  pre.insertAdjacentHTML("beforeend", colored);
  // Cap to last ~600KB so an unbounded live tail doesn't slow the DOM.
  if (pre.textContent.length > 700_000) {
    // Slice from the textContent baseline, then re-colorize once.
    const tail = pre.textContent.slice(-500_000);
    try {
      pre.innerHTML = colorizeRunLog(tail, null);
    } catch (_) {
      pre.textContent = tail;
    }
  }
  if (wasAtBottom) pre.scrollTop = pre.scrollHeight;
}

function _openLiveStream(id) {
  _closeLiveStream();
  if (typeof EventSource === "undefined") return;
  let es;
  try {
    // backfill=sdk: renderJob has ALREADY fetched /log and /monitor, so the
    // stream's line-by-line replay of the same content was parsed and then
    // thrown away by _appendLiveLogLine / _appendMonitorEntry. On 19cf9578a0fc
    // that was 2,807 SSE frames and 423 KB per entry, and because the sdk
    // replay comes after it, the "live agent activity" panel could not appear
    // until it finished — the three seconds the operator was seeing.
    es = new EventSource(`${API}/jobs/${id}/stream?backfill=sdk`);
  } catch (_) {
    return;
  }
  liveStream = es;
  liveStreamJobId = id;
  liveStreamConnected = false;

  es.addEventListener("log", (e) => {
    if (liveStreamJobId !== id) return;
    try {
      _appendLiveLogLine(id, JSON.parse(e.data));
    } catch (_) {}
  });
  es.addEventListener("meta", (e) => {
    if (liveStreamJobId !== id) return;
    // Only structural changes (status / flag / lifecycle) need a full
    // detail.innerHTML rebuild. Token / turn / compaction deltas would
    // otherwise re-render every ~350ms during an active agent turn and
    // visibly drift the user's scroll position. The slow poller still
    // refreshes the tokens-pill every 8s, which is good enough.
    try {
      const payload = JSON.parse(e.data);
      // A status change OR a freshly-spotted flag candidate ([FLAG?])
      // warrants a detail rebuild so the operator sees it at once.
      if (payload && (payload.status_update || payload.flag_candidates)) {
        _scheduleMetaRefresh(id);
      }
    } catch (_) {}
  });
  // Backfilled events are buffered and drawn once, on backfill_done. A bare
  // `if (payload.backfill) return;` — the guard the log and monitor handlers
  // use — would NOT do here: _renderSdkEvent is the only thing that ever
  // un-hides this panel or puts a row in it, so dropping the backfill would
  // leave the operator with a permanently empty box on any finished job.
  const sdkBuf = [];
  es.addEventListener("sdk", (e) => {
    if (liveStreamJobId !== id) return;
    try {
      const payload = JSON.parse(e.data);
      if (payload && payload.backfill) sdkBuf.push(payload);
      else _renderSdkEvent(id, payload);
    } catch (_) {}
  });
  es.addEventListener("monitor", (e) => {
    if (liveStreamJobId !== id) return;
    try {
      _appendMonitorEntry(id, JSON.parse(e.data));
    } catch (_) {}
  });
  es.addEventListener("backfill_done", () => {
    // One pass, one layout — instead of 400 events x 4 geometry reads.
    try { _renderSdkBatch(id, sdkBuf.splice(0)); } catch (_) {}
    liveStreamConnected = true;
    // Now that the live stream is providing events, widen the poll
    // interval so we don't fight the stream with full re-renders.
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = setInterval(async () => {
        const job = await renderJob(id);
        if (job && JOB_TERMINAL.includes(job.status)) {
          clearInterval(pollTimer);
          pollTimer = null;
          await refreshJobs();
          await refreshStats();
        }
      }, 8000);
    }
  });
  es.addEventListener("done", () => {
    _closeLiveStream();
    // Final structural refresh so result-block file links + cost
    // pill update one last time.
    renderJob(id, { force: true });
    refreshJobs();
    refreshStats();
  });
  es.onerror = () => {
    // EventSource auto-reconnects unless we explicitly close. If the
    // browser flags the stream as permanently closed, surrender and
    // let the (still-running) 2s poller carry the panel forward.
    if (!liveStream) return;
    if (liveStream.readyState === EventSource.CLOSED) {
      liveStream = null;
      liveStreamJobId = null;
      liveStreamConnected = false;
    }
  };
}

function _closeLiveStream() {
  if (liveStream) {
    try { liveStream.close(); } catch (_) {}
  }
  liveStream = null;
  liveStreamJobId = null;
  liveStreamConnected = false;
  if (_metaRefreshTimer) {
    clearTimeout(_metaRefreshTimer);
    _metaRefreshTimer = null;
  }
}

// Run-log timestamp display mode. Logs are written in UTC by the
// orchestrator (`[HH:MM:SS]`). Default is UTC so behavior is
// unchanged for users who haven't opted in. The toggle button in
// the run-log titlebar flips this and triggers a re-render.
let runlogTz = (() => {
  try { return localStorage.getItem("runlog_tz") || "utc"; }
  catch (_) { return "utc"; }
})();
function _setRunlogTz(tz) {
  if (tz !== "utc" && tz !== "local") tz = "utc";
  runlogTz = tz;
  try { localStorage.setItem("runlog_tz", tz); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}
function _localTzName() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "local"; }
  catch (_) { return "local"; }
}

// --- MONITOR view: curated, LLM-narrated signal feed over run.log --------
// A per-job monitor task (api-side) filters run.log to meaningful signals and
// narrates each batch in every configured language; entries stream over the
// SSE `monitor` channel and back-fill from /api/jobs/<id>/monitor. The run-log
// window has a Run-log|Monitor view toggle + a language <select>. Both prefs
// persist like runlogTz.
let monitorView = (() => {
  try { return localStorage.getItem("monitor_view") === "1"; }
  catch (_) { return false; }
})();
let monitorLang = (() => {
  try { return localStorage.getItem("monitor_lang") || "ko"; }
  catch (_) { return "ko"; }
})();
function _setMonitorView(on) {
  monitorView = !!on;
  try { localStorage.setItem("monitor_view", monitorView ? "1" : "0"); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}
function _setMonitorLang(lang) {
  monitorLang = lang || "ko";
  try { localStorage.setItem("monitor_lang", monitorLang); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}

// Claude and grok now have a structured timeline too, normalised from
// sdk.jsonl into the same events the GPT one emits. It is the DEFAULT: the raw
// log is a wall of `[main] TOOL Bash: {"command": ...` that the operator had to
// parse by eye, and the data to render it properly was already on disk.
// Seeded from the old Monitor boolean once, so a saved Monitor preference
// survives the change instead of being silently reset to a new default.
let claudeLogView = (() => {
  try {
    const saved = localStorage.getItem("claude_log_view");
    if (saved && ["timeline", "monitor", "log"].includes(saved)) return saved;
    return localStorage.getItem("monitor_view") === "1" ? "monitor" : "timeline";
  } catch (_) { return "timeline"; }
})();
function _setClaudeLogView(view) {
  claudeLogView = ["timeline", "monitor", "vuln", "log"].includes(view) ? view : "timeline";
  try { localStorage.setItem("claude_log_view", claudeLogView); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}

// GPT gets an additive structured timeline.  Keep this preference separate
// from the historical Run-log|Monitor boolean so Claude/Grok retain their
// exact default and saved behavior.
let gptLogView = (() => {
  try {
    const value = localStorage.getItem("gpt_log_view") || "timeline";
    return ["timeline", "log"].includes(value) ? value : "timeline";
  } catch (_) { return "timeline"; }
})();
// Tri-state: "1", "0", or unset. Unset resolves per provider, because the
// default that is right for one is wrong for the other. GPT hides tool cards
// by default for a measured reason — 3,899 of them on 48fadce3dde7, 43.6% of
// the cards. A claude job has six, and hiding those leaves the timeline with
// the agent's prose and no record of what it actually DID, which is the half
// worth reading.
let gptTimelineToolsPref = (() => {
  try {
    const v = localStorage.getItem("gpt_timeline_tools");
    return v === "1" ? true : v === "0" ? false : null;
  } catch (_) { return null; }
})();
function timelineToolsFor(isGpt) {
  return gptTimelineToolsPref === null ? !isGpt : gptTimelineToolsPref;
}
let gptTimelineTools = false;   // effective value, set per render
function _setGptLogView(view) {
  gptLogView = ["timeline", "log"].includes(view) ? view : "timeline";
  try { localStorage.setItem("gpt_log_view", gptLogView); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}
function _toggleGptTimelineTools() {
  // Toggling makes the preference EXPLICIT, so it stops resolving per
  // provider — the operator has now said which they want.
  gptTimelineToolsPref = !gptTimelineTools;
  gptTimelineTools = gptTimelineToolsPref;
  try { localStorage.setItem("gpt_timeline_tools", gptTimelineTools ? "1" : "0"); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}

// A filed runner stop, remembered per job. The controls row is NOT in the
// preserved set, so it is rebuilt by the 2-second poll — and stopping the RUN
// leaves the JOB running, so the button stays on screen and its "requested"
// label reverted almost immediately. An operator who cannot see that the
// click registered clicks again, which is how one stop becomes three.
const _runnerStopAt = Object.create(null);

const _MON_SEV_ICON = { good: "🟢", info: "●", warn: "▲", err: "■" };

function _fmtMonTime(iso) {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    if (runlogTz === "local") return d.toLocaleTimeString([], { hour12: false });
    return d.toISOString().slice(11, 19);  // UTC HH:MM:SS
  } catch (_) { return ""; }
}

function _monText(entry, lang) {
  const t = entry && entry.text;
  if (!t) return "";
  if (typeof t === "string") return t;
  return t[lang] || t.en || t.ko
    || Object.values(t).find((v) => typeof v === "string" && v) || "";
}

function _monRowHtml(entry, lang) {
  const sev = entry.sev || "info";
  const kind = entry.kind || "";
  const time = _fmtMonTime(entry.ts);
  const text = _monText(entry, lang);
  const raw = Array.isArray(entry.raw) ? entry.raw.join("\n") : "";
  return `<div class="mon-row mon-${escapeHtml(sev)}" title="${escapeHtml(raw)}">`
    + `<span class="mon-ico">${_MON_SEV_ICON[sev] || "●"}</span>`
    + `<span class="mon-time">${escapeHtml(time)}</span>`
    + `<span class="mon-kind mon-kind-${escapeHtml(kind)}">${escapeHtml(kind)}</span>`
    + `<span class="mon-text">${escapeHtml(text)}</span>`
    + `</div>`;
}

// The findings the monitor pulled out of its own narration batches. Same
// entries, same feed, filtered — no second channel to keep in sync, which is
// how `blocked.json` ended up written by three modules and read by none.
//
// Clicking one steers MAIN at it. That is the only affordance here on
// purpose: the panel reports, the agent investigates, and the operator
// decides which finding is worth a turn.
function _vulnRowHtml(entry, lang, jobId, running) {
  const v = entry.vuln || {};
  const grade = String(v.severity || "medium").toLowerCase();
  const where = v.where || "";
  const why = v.why || "";
  // percent-encoded, NOT escapeHtml'd: this repo's escapeHtml covers & < >
  // and deliberately not quotes, so JSON in an attribute would end the
  // attribute at its first `"` — and this text comes from a model reading
  // challenge source. Same rule the job tag is pinned to elsewhere.
  const payload = encodeURIComponent(JSON.stringify({
    title: v.title || "", where, why, severity: grade,
  }));
  // Click SELECTS; it does not steer. One finding is often not an exploit —
  // the chain is — so the operator picks the set first and sends once. It
  // also means clicking a row to read it can no longer fire an instruction
  // at the agent, which the single-click version did.
  const key = _vulnKeyOf(v);
  const picked = running && _vulnPicked(jobId, key);
  return `<li class="vuln-row vuln-${escapeHtml(grade)}${picked ? " vuln-picked" : ""}"${running
      ? ` data-action="vuln-pick" data-vuln="${payload}" data-key="${escapeHtml(key)}"`
        + ` role="checkbox" aria-checked="${picked}" tabindex="0"` : ""}>`
    + (running ? `<span class="vuln-check">${picked ? "☑" : "☐"}</span>` : "")
    + `<span class="vuln-grade">${escapeHtml(grade)}</span>`
    + `<span class="vuln-title">${escapeHtml(v.title || "")}</span>`
    + (where ? `<span class="vuln-where">${escapeHtml(where)}</span>` : "")
    + `<span class="vuln-time">${escapeHtml(_fmtMonTime(entry.ts))}</span>`
    + (why ? `<div class="vuln-why">${escapeHtml(why)}</div>` : "")
    + `</li>`;
}


// Which findings the operator has picked, per job. Outside the DOM because
// the panel repaints whenever a new finding lands, and a selection that
// vanished mid-pick would be worse than no selection at all.
const _vulnPicks = Object.create(null);

// The entries the panel was last drawn from, per job. Toggling a selection
// repaints the panel, and the repaint needs the same list the fetch produced
// — re-fetching on every click would make selection feel like latency.
const _lastMonitorEntries = Object.create(null);

function _vulnKeyOf(v) {
  return `${String(v.title || "").trim().toLowerCase()}|`
       + `${String(v.where || "").trim().toLowerCase()}`;
}

function _vulnPicked(id, key) {
  return !!(_vulnPicks[id] && _vulnPicks[id][key]);
}

function renderVulnPanel(entries, lang, running, view, jobId) {
  // ITS OWN TAB. The findings started life beside the monitor feed they are
  // lifted from, which put a growing list in the way of the commentary and
  // made "what has this job found" a thing you scrolled to rather than a
  // thing you opened. One tab, one question.
  if (view && view !== "vuln") return "";
  const all = entries || [];
  // Nothing at all means the monitor is not producing — off, or not started.
  // Promising a findings panel there would be a claim the platform cannot
  // keep. One entry is proof the narrator is alive, and from that point the
  // panel stays visible EVEN WHEN EMPTY: "no findings yet" and "this feature
  // is broken" looked identical while it rendered nothing, which is how the
  // first version of this shipped inert without anyone being able to tell.
  if (!all.length) return "";
  const vulns = all.filter(
    (e) => e && e.kind === "vuln" && e.vuln && e.vuln.title);
  const head = `<div class="vuln-head">발견된 취약점 <b>${vulns.length}</b>`
    + `<small>모니터가 실시간으로 추려낸 것 · 확정된 판정이 아닙니다</small></div>`;
  if (!vulns.length) {
    return head + `<div class="vuln-none">아직 없음 — 에이전트가 취약점을 `
      + `단언하는 순간 여기에 쌓입니다. 진행·도구·계획 보고는 제외됩니다.</div>`;
  }
  // One finding is frequently not an exploit; the chain is. So the panel
  // sends a SET, and the instruction it composes differs: one asks for a
  // verdict, several ask for a chain — including the answer "these do not
  // combine, and here is why", which is worth a turn of its own.
  const picks = running ? _vulnPickedList(jobId, vulns) : [];
  const bar = running
    ? `<div class="vuln-bar">`
      + `<span class="vuln-count">${picks.length}개 선택됨</span>`
      + `<button class="vuln-send" data-action="vuln-send"${picks.length ? "" : " disabled"}>`
      + (picks.length > 1 ? "🕸 엮어서 체인 탐색 지시" : "🔎 심층 탐색 지시") + `</button>`
      + `<button class="vuln-clear" data-action="vuln-clear"${picks.length ? "" : " disabled"}>선택 해제</button>`
      + `<span class="vuln-bar-status" aria-live="polite"></span></div>`
    : "";
  return head + bar + `<ul class="vuln-list">`
    + vulns.map((e) => _vulnRowHtml(e, lang, jobId, running)).join("")
    + `</ul>`;
}


function _vulnPickedList(jobId, vulns) {
  // Resolved against what is ON the panel, so a pick whose finding scrolled
  // out of the 400-line window does not travel as a ghost.
  const sel = _vulnPicks[jobId] || {};
  return (vulns || [])
    .map((e) => e.vuln)
    .filter((v) => v && sel[_vulnKeyOf(v)]);
}

function renderMonitorEntries(entries, lang) {
  if (!entries || !entries.length) {
    return `<div class="mon-empty">아직 모니터 해설이 없습니다 · no monitor commentary yet</div>`;
  }
  return entries.map((e) => _monRowHtml(e, lang)).join("");
}

function _appendMonitorEntry(id, payload) {
  // Backfilled entries already arrived via renderJob's /monitor fetch.
  if (payload && payload.backfill) return;
  const feed = document.querySelector(
    `.monitor-feed[data-job-id="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`,
  );
  if (!feed) return;
  const empty = feed.querySelector(".mon-empty");
  if (empty) empty.remove();
  const wasAtBottom =
    feed.scrollTop + feed.clientHeight >= feed.scrollHeight - 12;
  feed.insertAdjacentHTML("beforeend", _monRowHtml(payload, monitorLang));
  while (feed.children.length > 800) feed.removeChild(feed.firstChild);
  if (wasAtBottom) feed.scrollTop = feed.scrollHeight;
  _appendVulnRow(id, payload);
}

// A finding must appear the moment it is found, not on the next 2s repaint —
// the whole point of pulling it out of the narration was that the operator
// can act on it while the run is still in the turn that produced it.
function _appendVulnRow(id, payload) {
  if (!payload || payload.kind !== "vuln" || !payload.vuln) return;
  // Keep the repaint source in step, or a selection toggle would redraw the
  // panel from a list that predates this finding and drop it off screen.
  (_lastMonitorEntries[id] = _lastMonitorEntries[id] || []).push(payload);
  const sel = (window.CSS && CSS.escape) ? CSS.escape(id) : id;
  const panel = document.querySelector(`.vuln-panel[data-job-id="${sel}"]`);
  if (!panel) return;
  let list = panel.querySelector(".vuln-list");
  if (!list) {
    // First finding: the panel is showing its empty state, so rebuild it.
    // The view MUST be passed — without it the gate reads `undefined` and a
    // finding arriving while the operator sits on another tab would paint the
    // panel into a view that is supposed to be free of it.
    panel.innerHTML = renderVulnPanel([payload], monitorLang, true, claudeLogView, id);
    return;
  }
  list.insertAdjacentHTML("beforeend",
    _vulnRowHtml(payload, monitorLang, id, true));
  const count = panel.querySelector(".vuln-head b");
  if (count) count.textContent = String(list.children.length);
}

const _GPT_EVENT_ICON = {
  agent_started: "▶", agent_completed: "✓", turn_started: "↻",
  turn_completed: "✓", turn_failed: "■", message: "●", artifact: "✎",
  wait: "◷", tool: "⌘", delegation: "↳", warning: "▲", error: "■",
};
const _GPT_STATUS_KO = {
  running: "실행 중", waiting: "응답 대기", completed: "완료", failed: "실패", configured: "대기",
  observed: "결과 미기록", warning: "주의", info: "업데이트",
};
function _fmtDuration(ms) {
  // null/undefined FIRST: Number(null) is 0, so an unmeasured duration came
  // out as a confident "0ms" on every tool row of a job that simply had no
  // timestamps to subtract.
  if (ms === null || ms === undefined || ms === "") return "";
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return "";
  if (n < 1000) return `${Math.round(n)}ms`;
  const sec = Math.round(n / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}
/** One row. `jobId` is only needed so a tool that touched a file can link to
 *  it; the file endpoint resolves a basename against <job>/ and <job>/work/,
 *  which is why only the basename travels. */
function _gptTimelineEventHtml(event, jobId) {
  const kind = event.kind || "event";
  const status = event.status || "info";
  const role = event.role || "system";
  const time = _fmtMonTime(event.ts);
  let durationValue = event.duration_ms;
  if (durationValue == null && kind === "wait" && ["running", "observed"].includes(status)) {
    const began = new Date(event.ts).getTime();
    if (Number.isFinite(began)) durationValue = Math.max(0, Date.now() - began);
  }
  const duration = _fmtDuration(durationValue);
  const title = event.title || event.tool || kind;
  const fullSummary = String(event.summary || "");
  const summary = fullSummary.length > 700 ? fullSummary.slice(0, 700) + "…" : fullSummary;
  // Reuses the existing delegated `a.file-preview-link` handler, so the row
  // opens the same preview modal the file browser does — no second viewer.
  const _fileUrl = (event.file && jobId)
    ? `${API}/jobs/${encodeURIComponent(jobId)}/file/${encodeURIComponent(event.file)}` : "";
  const fileHtml = _fileUrl
    ? `<a class="file-preview-link tl-file" data-name="${escapeHtml(event.file)}"
          data-url="${_fileUrl}" href="${_fileUrl}">${escapeHtml(event.file)}</a>` : "";
  const detailParts = [];
  if (event.input) {
    const value = typeof event.input === "string"
      ? event.input : JSON.stringify(event.input, null, 2);
    if (value) detailParts.push(`INPUT\n${value}`);
  }
  if (event.detail) detailParts.push(`OUTPUT\n${event.detail}`);
  const detail = detailParts.join("\n\n");
  const stats = [];
  if (duration) stats.push(duration);
  if (event.output_lines != null) stats.push(`${event.output_lines} lines`);
  if (event.output_bytes != null) stats.push(`${Number(event.output_bytes).toLocaleString()} B`);
  if (event.exit_code != null) stats.push(`exit ${event.exit_code}`);
  const toolClass = kind === "tool" ? " gpt-tool-event" : "";
  return `<article class="gpt-event gpt-event-${escapeHtml(kind)} gpt-status-${escapeHtml(status)}${toolClass}">
    <div class="gpt-event-rail"><span>${_GPT_EVENT_ICON[kind] || "·"}</span></div>
    <div class="gpt-event-main">
      <div class="gpt-event-head">
        <span class="gpt-event-time">${escapeHtml(time)}</span>
        <span class="gpt-role gpt-role-${escapeHtml(role)}">${escapeHtml(role)}</span>
        <strong>${escapeHtml(title)}</strong>
        <span class="gpt-event-status">${escapeHtml(_GPT_STATUS_KO[status] || status)}</span>
        ${stats.length ? `<span class="gpt-event-stats">${escapeHtml(stats.join(" · "))}</span>` : ""}
      </div>
      ${summary || fileHtml ? `<div class="gpt-event-summary">${escapeHtml(summary)}${
        fileHtml ? ` <span class="tl-file-sep">·</span> ${fileHtml}` : ""}</div>` : ""}
      ${detail ? `<details class="gpt-event-detail"><summary>원본 입력/출력 보기</summary><pre>${escapeHtml(detail)}</pre></details>` : ""}
    </div>
  </article>`;
}
// How many agents are working right now.
//
// Three separately-sourced facts, deliberately not merged into one invented
// number. `running` counts ROLE CARDS, and summarize_agents folds every child
// of a role into one card — so three concurrent recon children read as one
// running role. `delegations` is the honest count of children actually
// spawned, and is the number that distinguishes serial delegation from
// parallel. They disagree on purpose; the tooltip says so rather than letting
// a reader assume the smaller one is the truth.
//
// `main 대기 중` is surfaced because it is the expensive state: job
// 24225668a27d spent 491s of 950s (52%) with main blocked in `wait`, and that
// was invisible until someone summed the event list by hand.
function _gptActivityHtml(activity) {
  if (!activity) return "";
  const running = Number(activity.running || 0);
  const delegations = Number(activity.delegations || 0);
  const waiting = !!activity.main_waiting;
  const roles = Array.isArray(activity.running_roles) ? activity.running_roles : [];
  // "0건" would be a lie on Codex: measured on job 7b8bd665f130, the CLI emits
  // no spawn item at all, so the count is UNAVAILABLE rather than zero — while
  // main's own messages that run reported delegating to recon, debugger and
  // judge, and every `wait` returned real findings. Say which of the two it is.
  const observable = activity.spawns_observable !== false;
  // A roster the run actually reported beats every inference: `list_agents`
  // names the children and their states, which nothing else on this timeline
  // can. See modules/gpt_run_events._parse_agent_roster.
  const kids = Array.isArray(activity.children) ? activity.children : [];
  const kidsActive = Number(activity.children_active || 0);
  const tip = [
    roles.length ? `실행 중 역할: ${roles.join(", ")}` : "실행 중인 역할 없음",
    kids.length
      ? "자식 에이전트 " + kids.length + "개 (활성 " + kidsActive + "): "
        + kids.map((c) => c.name + "=" + c.status).join(", ")
      : (observable
          ? `위임된 자식 에이전트: ${delegations}건`
          : "자식 명단 미확인: Codex CLI는 spawn 이벤트를 내보내지 않습니다."
            + " main이 `list_agents`를 호출하면 여기에 명단이 표시됩니다."),
    "역할 카드는 같은 역할의 자식을 한 장으로 합치므로, 위임 건수가 실행 중 역할 수보다 클 수 있습니다.",
    waiting ? "main이 자식 응답을 기다리는 중입니다 (그동안 main은 일하지 않습니다)." : "",
  ].filter(Boolean).join("\n");
  const cls = waiting ? "gpt-activity waiting" : (running ? "gpt-activity live" : "gpt-activity");
  return `<span class="${cls}" title="${escapeHtml(tip)}">`
    + `에이전트 ${running}개 실행 중`
    + (kids.length ? ` · 자식 ${kidsActive}/${kids.length}`
       : (observable && delegations ? ` · 위임 ${delegations}건` : ""))
    + (waiting ? " · main 대기 중" : "")
    + `</span>`;
}

/** Where the clock and the context actually went, under the flow that spent
 *  them. Every figure is computed server-side by the SAME build_trace the
 *  궤적 view uses, so the two cannot disagree — and anything it could not
 *  measure is omitted rather than shown as a zero. */
function _timelineStatsHtml(st) {
  if (!st) return "";
  const bits = [];
  const n = (v) => (v >= 1_000_000 ? (v / 1_000_000).toFixed(2) + "M"
    : v >= 1000 ? (v / 1000).toFixed(1) + "k" : String(v));
  const pair = [];
  if (st.turns != null) pair.push(`${st.turns} turns`);
  if (st.steps != null) pair.push(`${st.steps} steps`);
  if (pair.length) bits.push(pair.join(" · "));
  const times = [];
  if (st.agent_s != null) times.push(`agent ${_traceDur(st.agent_s)}`);
  if (st.run_s != null) times.push(`tool ${_traceDur(st.run_s)}`);
  if (st.adjudicate_s != null) times.push(`judge ${_traceDur(st.adjudicate_s)}`);
  if (times.length) bits.push(times.join(" · "));
  // null means "no context was read", which has no hit RATE. 0% would read as
  // a cache that is failing.
  if (st.cache_hit_pct != null) bits.push(`cache hit ${st.cache_hit_pct}%`);
  const tok = [];
  if (st.input_tokens) tok.push(`in ${n(st.input_tokens)}`);
  if (st.output_tokens) tok.push(`out ${n(st.output_tokens)}`);
  if (tok.length) bits.push(tok.join(" · "));
  if (!bits.length) return "";
  return `<div class="tl-stats">${bits.map((b) =>
    `<span>${escapeHtml(b)}</span>`).join('<i class="tl-sep">|</i>')}</div>`;
}

function renderGptTimeline(payload, jobId) {
  if (!payload || !payload.enabled) {
    return `<div class="gpt-timeline-empty">GPT Timeline을 사용할 수 없습니다.</div>`;
  }
  const agents = Array.isArray(payload.agents) ? payload.agents : [];
  let events = Array.isArray(payload.events) ? payload.events : [];
  // Tool cards were BUILT and then hidden by CSS
  // (.run-log-window[data-show-tools="0"] .gpt-tool-event { display:none }).
  // They are 43.6% of the cards on 48fadce3dde7 — 3,899 elements parsed for a
  // view nobody is looking at, since gptTimelineTools defaults to false. The
  // rail is drawn per card, so not building them renders pixel-identically to
  // hiding them; the toggle calls renderJob({force:true}) and gets them back.
  let toolsHidden = 0;
  if (!gptTimelineTools) {
    const kept = events.filter((e) => (e && e.kind) !== "tool");
    toolsHidden = events.length - kept.length;
    events = kept;
  }
  let cardsClipped = 0;
  if (jobId && !_renderUncapped.has(jobId) && events.length > _RENDER_MAX_CARDS) {
    cardsClipped = events.length - _RENDER_MAX_CARDS;
    events = events.slice(-_RENDER_MAX_CARDS);   // newest, like the log tail
  }
  const agentHtml = agents.map((agent) => {
    const status = agent.status || "configured";
    const current = String(agent.current || "");
    return `<div class="gpt-agent-card gpt-agent-${escapeHtml(status)}">
      <div class="gpt-agent-card-head">
        <strong>${escapeHtml(agent.role || "agent")}</strong>
        <span>${escapeHtml(_GPT_STATUS_KO[status] || status)}</span>
      </div>
      <code>${escapeHtml(agent.model || "model 미확인")}</code>
      ${agent.provider && agent.provider !== "gpt"
        ? `<span class="gpt-agent-routed" title="이 역할은 다른 백엔드로 라우팅되어 GPT 이벤트를 남기지 않습니다">↗ ${escapeHtml(agent.provider)}</span>`
        : ""}
      ${current ? `<div>${escapeHtml(current.slice(0, 130))}${current.length > 130 ? "…" : ""}</div>` : ""}
    </div>`;
  }).join("");
  const eventHtml = events.length
    ? _moreBanner(jobId, cardsClipped, "건") + events.map((e) => _gptTimelineEventHtml(e, jobId)).join("")
    : `<div class="gpt-timeline-empty">${toolsHidden
        ? `tool 이벤트 ${toolsHidden}건은 "도구 보기"로 확인하세요.`
        : "아직 기록된 GPT 이벤트가 없습니다."}</div>`;
  const fallback = payload.source === "run.log fallback"
    ? `<span class="gpt-timeline-source fallback" title="이 job은 구조화 이벤트 도입 전에 시작되어 기존 run.log를 읽기 전용으로 정리했습니다.">legacy log projection</span>`
    : `<span class="gpt-timeline-source">structured events</span>`;
  return `${_timelineStatsHtml(payload.stats)}
    <div class="gpt-timeline-meta">
      ${fallback}
      ${_gptActivityHtml(payload.activity)}
      ${payload.preset ? `<span>preset · ${escapeHtml(payload.preset)}</span>` : ""}
    </div>
    <div class="gpt-agent-grid">${agentHtml}</div>
    <div class="gpt-event-list">${eventHtml}</div>`;
}
// Lightweight 1-second tick that updates ONLY the timing pill's
// textContent on running jobs. Independent of pollTimer (which
// re-renders the whole detail panel and is paused on selection /
// open forms), so the elapsed counter stays smooth.
let livePillTimer = null;
// Age of the agent's last SDK event, in the same visual family as the elapsed
// pill. Seconds are kept visible past the minute mark on purpose: the whole
// point of this readout is watching it reset, and "8m" alone hides the reset
// for up to a minute.
function _fmtAgentAge(sec) {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

// The three blocks that grow while a job runs, written into containers the
// hashed html leaves empty. Each is set ONLY when it differs, and the scroll
// position is kept, because a <pre> that jumps to the top every two seconds is
// unreadable — which is what a full rebuild did to it.
function _paintVolatile(id, parts) {
  const esc = (v) => (window.CSS && CSS.escape) ? CSS.escape(v) : v;
  const put = (sel, html) => {
    if (html === null || html === undefined) return;
    const el = document.querySelector(`${sel}[data-job-id="${esc(id)}"]`);
    if (!el || el.dataset.painted === String(html.length) + ":" + _cheapHash(html)) return;
    const wasAtBottom =
      el.scrollTop + el.clientHeight >= el.scrollHeight - 12;
    el.innerHTML = html;
    el.dataset.painted = String(html.length) + ":" + _cheapHash(html);
    if (wasAtBottom) el.scrollTop = el.scrollHeight;
  };
  const ap = document.querySelector(`[data-live-agent="${esc(id)}"]`);
  if (ap && parts.agentAt) {
    if (ap.dataset.agentAt !== parts.agentAt) ap.dataset.agentAt = parts.agentAt;
    if (ap.title !== parts.agentTitle) ap.title = parts.agentTitle;
    if (!ap.textContent) ap.textContent = "⚡";
  }
  const cost = document.querySelector(`[data-live-cost="${esc(id)}"]`);
  if (cost && parts.cost != null && cost.textContent !== parts.cost) {
    cost.textContent = parts.cost;
  }
  put("div.run-log-footer", parts.tokens);
  put("pre.run-log", parts.log);
  put("div.gpt-timeline-feed", parts.gpt);
  put("div.tr-feed", parts.trace);
  put("div.monitor-feed", parts.monitor);
  put("div.vuln-panel", parts.vuln);
}

function _tickLivePill() {
  // Same 1s tick drives the agent-event age. It is a separate element from the
  // elapsed pill because they answer different questions — how long the job has
  // run, versus how long since the agent last said anything — and because the
  // elapsed pill must keep ticking on a job whose agent has not started yet.
  document.querySelectorAll(".agent-pill[data-agent-at]").forEach((pill) => {
    const iso = pill.dataset.agentAt;
    if (!iso) return;
    const sec = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    pill.textContent = `⚡ ${_fmtAgentAge(sec)}`;
  });
  document.querySelectorAll(".timing-pill.live").forEach((pill) => {
    const startedIso = pill.dataset.startedAt;
    if (!startedIso) return;
    const sec = Math.max(0, Math.round((Date.now() - new Date(startedIso).getTime()) / 1000));
    // Same formatter as every other elapsed/age readout. This was an inline
    // copy of the identical ternary; with the dashboard rendering these pills
    // too there are now three call sites, and three copies of one format is
    // three chances for them to drift apart on screen at the same time.
    const fmt = _fmtAgentAge(sec);
    // Only replace the text node holding the time; keep the inner
    // "running" tag span untouched.
    const tagEl = pill.querySelector(".timing-tag");
    if (!tagEl) return;
    pill.firstChild && (pill.firstChild.nodeValue = `⏱ ${fmt} `);
  });
  // Stop only when NEITHER live readout is on screen. Keying this on the
  // elapsed pill alone would be right today (a running job always has
  // started_at, so it is a superset) but silently wrong the moment that stops
  // holding — and the failure is invisible: a frozen counter reads exactly like
  // a wedged agent, which is the one thing this readout must never fake.
  if (!document.querySelector(".timing-pill.live, .agent-pill[data-agent-at]")) {
    clearInterval(livePillTimer);
    livePillTimer = null;
  }
}
function _ensureLivePillTimer() {
  if (livePillTimer) return;
  livePillTimer = setInterval(_tickLivePill, 1000);
}

document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    if (t.disabled) return;
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    document.getElementById(`panel-${t.dataset.tab}`).classList.add("active");
  });
});

// Directive folded into the description when "Capture remote flag" is ticked.
// Leads with the literal phrase so it's grep-able, then spells out the bar the
// operator wants. NOTE this is a USER-TURN hint (description → build_user_prompt
// → client.query), so it COUNTERS but does not override the system-prompt line
// (CTF_PREAMBLE: "...or producing a working exploit is the explicit goal") that
// otherwise lets a locally-validated / banner-only exploit read as goal-complete.
// It's a strong operator directive, NOT a hard success gate — the orchestrator's
// flag-scan + success decision (_common.py scan_job_for_flags / auto-run gate)
// is separate and unchanged by this checkbox.
const CAPTURE_REMOTE_FLAG_DIRECTIVE =
  "capture remote flag — this job is ONLY successful if your exploit/solver " +
  "captures the REAL flag from the remote target and prints it on its own line " +
  "as `FLAG_CANDIDATE: <flag>`. Local-only validation, a planted test flag, or a " +
  "banner-only smoke check do NOT count as success; keep iterating (reconnect/retry) " +
  "until the genuine remote flag is captured.";

async function submitJob(form, endpoint) {
  const fd = new FormData(form);
  // Multi-target rows (the +/× list) → join non-empty values with newlines into
  // the canonical field (target_url for web, target for pwn/crypto) so the
  // backend's parse_targets() splits them. The row inputs are intentionally
  // unnamed, so they never reach FormData on their own.
  const tlist = form.querySelector(".target-list");
  if (tlist && tlist.dataset.field) {
    const vals = Array.from(tlist.querySelectorAll(".target-input"))
      .map((i) => i.value.trim())
      .filter(Boolean);
    fd.set(tlist.dataset.field, vals.join("\n"));
  }
  for (const cb of form.querySelectorAll('input[type="checkbox"]')) {
    // Nameless checkboxes (e.g. the capture-remote-flag toggle) are UI-only and
    // must not leak into FormData as a blank-named field — they're handled below.
    if (!cb.name) continue;
    fd.set(cb.name, cb.checked ? "true" : "false");
  }
  // "Capture remote flag" toggle → fold the directive into the description so the
  // agent prompt (which otherwise accepts a "working exploit" as goal-complete)
  // gets an explicit remote-capture success bar. The checkbox itself carries no
  // `name`, so it never reaches the backend as a form field.
  //
  // GATE on an actual target: only fold the "capture from the REMOTE target"
  // mandate in when the job HAS a remote target. `tlist.dataset.field` is the
  // canonical target field (target_url for web, target for pwn/crypto/rev),
  // already populated from the row inputs above, so `fd.get()` is authoritative
  // here. An empty value means a genuinely offline job (e.g. a rev crackme with
  // only a binary) where "capture the REAL flag from the remote target" is
  // unsatisfiable by construction — folding it in there just makes the agent
  // chase a nonexistent remote (this misdirected offline rev job 0d0c3de3fbfb).
  // Any filled target row makes this non-empty, so TARGETED jobs are unchanged.
  const crf = form.querySelector(".capture-remote-flag-cb");
  const tfield = tlist && tlist.dataset.field;
  const hasTarget = tfield ? (fd.get(tfield) || "").trim() !== "" : false;
  if (crf && crf.checked && hasTarget) {
    const cur = (fd.get("description") || "").trim();
    if (!cur.toLowerCase().includes("capture remote flag")) {
      fd.set("description", cur
        ? `${cur}\n\n${CAPTURE_REMOTE_FLAG_DIRECTIVE}`
        : CAPTURE_REMOTE_FLAG_DIRECTIVE);
    }
  } else if (crf && crf.checked && !hasTarget) {
    // Operator ticked the box but gave no target — surface it (dev console)
    // rather than silently folding an unsatisfiable remote mandate into an
    // offline job.
    console.warn(
      "🚩 Capture remote flag ticked but no remote target provided — " +
        "mandate not applied (offline job).",
    );
  }
  // "Flag format" → stored in meta for the scanner (authoritative matcher),
  // AND folded into the description so the agent emits FLAG_CANDIDATE in the
  // right format and uses LOCAL{...} for local-test flags.
  const ff = (fd.get("flag_format") || "").trim();
  if (ff) {
    const cur = (fd.get("description") || "").trim();
    const directive =
      `FLAG FORMAT — the real flag for this challenge has the form \`${ff}\`. ` +
      "Emit `FLAG_CANDIDATE: <flag>` ONLY for a flag of this exact format; for any " +
      "local/test flag you plant, use a different format like `LOCAL{...}` so it is " +
      "never mistaken for the real capture.";
    if (!cur.includes("FLAG FORMAT")) {
      fd.set("description", cur ? `${cur}\n\n${directive}` : directive);
    }
  }
  // Drop empty optional fields so backend uses its default.
  const to = fd.get("job_timeout");
  if (to === "" || to == null) fd.delete("job_timeout");
  const model = fd.get("model");
  if (model === "" || model == null) fd.delete("model");
  const effort = fd.get("effort");
  if (effort === "" || effort == null) fd.delete("effort");
  if (ff === "") fd.delete("flag_format");

  const res = await fetch(`${API}${endpoint}`, { method: "POST", body: fd });
  if (!res.ok) {
    alert(`error: ${res.status} ${await res.text()}`);
    return;
  }
  const data = await res.json();
  await refreshJobs();
  selectJob(data.job_id);
}

// ---- Multi-target rows (+ / × buttons) -----------------------------------
// Web/Pwn/Crypto target fields are a dynamic list. "+ add target" appends a
// row; "×" removes one (always keeping ≥1). submitJob() joins the row values
// into the canonical field. Listeners are delegated so dynamically-added rows
// work without re-binding.
function makeTargetRow(placeholder) {
  const row = document.createElement("div");
  row.className = "target-row";
  const inp = document.createElement("input");
  inp.type = "text";
  inp.className = "target-input";
  inp.placeholder = placeholder || "";
  const rm = document.createElement("button");
  rm.type = "button";
  rm.className = "target-remove";
  rm.tabIndex = -1;
  rm.title = "Remove this target";
  rm.textContent = "×";
  row.append(inp, rm);
  return row;
}

// Delegated, not bound per render: these buttons sit inside .tr-feed, which
// _paintVolatile replaces with innerHTML on every poll — a directly-attached
// listener would survive exactly until the first repaint.
document.addEventListener("click", (e) => {
  const scaleBtn = e.target.closest(".tr-scale[data-action^=\"trace-scale-\"]");
  if (scaleBtn) {
    _setTraceScale(scaleBtn.dataset.action === "trace-scale-job" ? "job" : "lane");
  }
  const shapeBtn = e.target.closest(".tr-shape[data-action^=\"trace-shape-\"]");
  if (shapeBtn) {
    _setTraceShape(shapeBtn.dataset.action === "trace-shape-graph" ? "graph" : "lanes");
  }
});

document.addEventListener("click", (e) => {
  const addBtn = e.target.closest(".target-add");
  if (addBtn) {
    const list = addBtn.closest(".target-list");
    const rows = list.querySelector(".target-rows");
    const row = makeTargetRow(list.dataset.placeholder || "");
    rows.appendChild(row);
    row.querySelector(".target-input").focus();
    return;
  }
  const rmBtn = e.target.closest(".target-remove");
  if (rmBtn) {
    const rows = rmBtn.closest(".target-rows");
    if (rows.querySelectorAll(".target-row").length > 1) {
      rmBtn.closest(".target-row").remove();
    } else {
      // Last remaining row: clear instead of removing so one input always stays.
      const inp = rmBtn.closest(".target-row").querySelector(".target-input");
      if (inp) inp.value = "";
    }
  }
});

// The native "Reset" button clears values but leaves added rows behind — prune
// each target list back to a single empty row after the reset runs.
document.addEventListener("reset", (e) => {
  const lists = e.target.querySelectorAll
    ? e.target.querySelectorAll(".target-list") : [];
  if (!lists.length) return;
  setTimeout(() => {
    lists.forEach((list) => {
      const rows = list.querySelector(".target-rows");
      rows.querySelectorAll(".target-row").forEach((r, i) => { if (i > 0) r.remove(); });
      const first = rows.querySelector(".target-input");
      if (first) first.value = "";
    });
  }, 0);
});

// Build a multi-target row list for the retry / continue / resume forms — same
// markup + classes as the main submit forms, so the global +/× delegated
// listeners and CSS apply automatically. `prefill` (optional, newline/comma
// separated) seeds rows; blank → one empty row.
function targetListHtml(placeholder, prefill) {
  const vals = (prefill || "").split(/[\r\n,]+/).map((s) => s.trim()).filter(Boolean);
  if (!vals.length) vals.push("");
  const ph = escapeHtml(placeholder || "");
  const rows = vals.map((v) => `
        <div class="target-row">
          <input type="text" class="target-input" placeholder="${ph}" value="${escapeHtml(v)}" />
          <button type="button" class="target-remove" tabindex="-1" title="Remove this target">×</button>
        </div>`).join("");
  return `<div class="target-list" data-placeholder="${ph}">
        <div class="target-rows">${rows}</div>
        <button type="button" class="target-add" title="Add another target">+ add target</button>
      </div>`;
}

// Collect a form's non-empty target rows into a newline-joined string. The
// backend (_read_retry_body → _resolve_targets → parse_targets) splits it:
// "" = keep prior target, "(none)" = clear, several lines = multi-target.
function gatherTargets(formEl) {
  const list = formEl.querySelector(".target-list");
  if (!list) return "";
  return Array.from(list.querySelectorAll(".target-input"))
    .map((i) => i.value.trim())
    .filter(Boolean)
    .join("\n");
}

function challengeSecretHtml() {
  return `
    <label class="retry-manual-label" style="margin-top:0.4rem">Challenge credential (optional · stored job-scoped, never in the hint/log)</label>
    <input type="password" class="challenge-secret-value" autocomplete="new-password" placeholder="CTFD_ACCESS_TOKEN value" />
  `;
}

function appendChallengeSecret(formEl, body) {
  const value = formEl.querySelector(".challenge-secret-value")?.value.trim() || "";
  if (value) {
    body.challenge_secret_key = "CTFD_ACCESS_TOKEN";
    body.challenge_secret_value = value;
  }
  return value;
}

// Reviewer-mode retry/resume with an optional MULTI-target override (was a
// single-line window.prompt). No manual hint — the auto-reviewer generates it;
// this just lets the operator point the retry/resume at one or more new targets
// via the +/× list. opts: {formKey, submitLabel, streamOpts}.
function openReviewerRetryForm(jobId, anchorBtn, opts) {
  opts = opts || {};
  const key = opts.formKey || "retry";
  const existing = document.getElementById(`reviewer-${key}-form-` + jobId);
  if (existing) { existing.querySelector(".target-input")?.focus(); return; }
  const form = document.createElement("div");
  form.className = "retry-manual-form";
  form.id = `reviewer-${key}-form-` + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Target (override; blank = keep prior, "(none)" = clear · <b>+ add target</b> for several)</label>
    ${targetListHtml("e.g. http://newhost:8080  ·  ctf.example.com:31337")}
    ${challengeSecretHtml()}
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit">${opts.submitLabel || "↻ Retry (reviewer)"}</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Auto-reviewer writes the hint · optional new target(s)</small>
    </div>
  `;
  anchorBtn.parentElement.insertAdjacentElement("afterend", form);
  const submit = form.querySelector(".retry-manual-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  form.querySelector(".target-input")?.focus();
  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", () => {
    const freshCb = document.getElementById(`fresh-ctx-${jobId}`);
    const target = gatherTargets(form);
    const secretValue = form.querySelector(".challenge-secret-value")?.value.trim() || "";
    form.remove();
    streamRetry(jobId, anchorBtn, null, {
      ...(opts.streamOpts || {}),
      target,
      fresh: !!(freshCb && freshCb.checked),
      secretValue,
    });
  });
}

// One form for every jeopardy challenge. The module is not asked for and not
// sent: modules/_operator.py decides it in the worker from the same bundle the
// operator just uploaded. The seven /modules/<m>/analyze endpoints are still
// mounted for the AI Player, which classifies its own challenges.
document.getElementById("jeopardy-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/jeopardy/analyze");
});
document.getElementById("live-fire-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/live-fire/analyze");
});


function _setModelField(f, name, customName, catalog, value) {
  const modelSel = f.querySelector(`[name=${name}]`);
  const modelCustom = f.querySelector(`[name=${customName}]`);
  if (!modelSel) return;
  const cur = value || "";
  if (catalog.includes(cur)) {
    modelSel.value = cur;
    if (modelCustom) modelCustom.value = "";
  } else {
    modelSel.value = "";
    if (modelCustom) modelCustom.value = cur;
  }
}

// Mirrors modules/agent_provider.py: ROLE_OVERRIDABLE and ROLE_TARGET_PROVIDERS.
// Grok is deliberately absent from the targets — it stays a whole-job backend,
// and the server drops a role pointed at it rather than half-switching.
// Mirrors agent_provider.ROLE_OVERRIDABLE. A role missing HERE has its
// <select> silently ignored on save — the markup renders, the operator picks a
// provider, and nothing is stored.
const ROLE_OVERRIDABLE = ["operator", "judge", "reviewer", "report", "monitor", "harvester", "manager"];
// The targets available to EVERY role. This is ROLE_TARGET_PROVIDERS minus the
// role-gated ones — `local` is added per role by roleTargets() below, so this
// list is deliberately not equal to the Python set and must not be "corrected"
// to match it. Note this is NOT ROLE_FAILOVER_PROVIDERS either: automatic
// failover stays claude <-> gpt, because routing is the operator's explicit
// choice and failover is not.
const ROLE_TARGETS = ["claude", "gpt", "grok"];
// Mirrors agent_provider.LOCAL_CAPABLE_ROLES. `local` is a routing target for
// THESE roles only — it has an adapter for monitor narration and nothing else,
// and the server refuses a pin anywhere else (_target_ok). A FLAT target list
// here would validate judge->local on save: the server would still refuse it,
// but the operator would have been shown a choice that silently does nothing.
const LOCAL_CAPABLE_ROLES = ["monitor"];
function roleTargets(role) {
  const r = String(role || "").toLowerCase();
  return LOCAL_CAPABLE_ROLES.includes(r) ? ROLE_TARGETS.concat("local") : ROLE_TARGETS;
}

// Named topologies. Each is exactly "job provider + role routes"; the models
// are NOT part of this — those come from each provider's own preset, and a
// role routed to Claude already resolves through the Claude preset.
//
// These fill the form. They are deliberately not a stored setting: routing
// would then have two sources of truth (the topology and the four selects),
// and the whole class of defect this project keeps hitting is one rule living
// in two places. Settings stays authoritative; this is a shortcut to filling it.
const TOPOLOGIES = {
  codex:  { provider: "gpt",    routes: {} },
  claude: { provider: "claude", routes: {} },
  hybrid: { provider: "gpt",    routes: { judge: "claude", reviewer: "claude" } },
};

function currentTopology(form) {
  const base = form.querySelector("[name=agent_provider]:checked")?.value || "";
  const routes = {};
  for (const role of ROLE_OVERRIDABLE) {
    const v = String(form.querySelector(`[name=role_provider_${role}]`)?.value || "");
    if (v) routes[role] = v;
  }
  for (const [name, t] of Object.entries(TOPOLOGIES)) {
    if (t.provider !== base) continue;
    const want = Object.keys(t.routes).sort().join(",") +
      "|" + Object.values(t.routes).join(",");
    const have = Object.keys(routes).sort().join(",") +
      "|" + Object.keys(routes).sort().map((k) => routes[k]).join(",");
    if (want === have) return name;
  }
  return "custom";
}

function applyTopology(form, name) {
  const t = TOPOLOGIES[name];
  if (!t) return;
  const radio = form.querySelector(`[name=agent_provider][value="${t.provider}"]`);
  if (radio) radio.checked = true;
  for (const role of ROLE_OVERRIDABLE) {
    const sel = form.querySelector(`[name=role_provider_${role}]`);
    if (sel) sel.value = t.routes[role] || "";
  }
  setProviderUI(t.provider);
  renderProviderAuthUI(t.provider, { unsaved: true });
  renderRoleProviderStatus(form);
}

function renderRoleProviderStatus(form) {
  const el = document.getElementById("role-provider-status");
  if (!el) return;
  const base = form.querySelector("[name=agent_provider]:checked")?.value || "claude";
  const routed = ROLE_OVERRIDABLE
    .map((r) => [r, String(form.querySelector(`[name=role_provider_${r}]`)?.value || "")])
    .filter(([, v]) => v && v !== base);
  const topoSel = form.querySelector("[name=topology_preset]");
  if (topoSel) topoSel.value = currentTopology(form);
  el.textContent = routed.length
    ? `${routed.map(([r, v]) => `${r} → ${v}`).join(" · ")}  (job runs on ${base})`
    : `every role follows the job provider (${base}) — no hybrid routing`;
}

async function loadSettings() {
  const res = await fetch(`${API}/settings`);
  if (!res.ok) return;
  const s = await res.json();
  const f = document.getElementById("settings-form");

  // Provider first so model/effort catalogs match the selection.
  const provider = ["claude", "grok", "gpt"].includes(s.agent_provider)
    ? s.agent_provider : "claude";
  latestSettingsView = s;
  setProviderUI(provider);

  _setModelField(f, "claude_model", "claude_model_custom", CLAUDE_MODELS, s.claude_model);
  _setModelField(f, "grok_model", "grok_model_custom", GROK_MODELS, s.grok_model);
  _setModelField(f, "gpt_model", "gpt_model_custom", GPT_MODELS, s.gpt_model);
  const gptRuntime = s.gpt_runtime === "responses" ? "responses" : "codex";
  const gptRuntimeSel = f.querySelector("[name=gpt_runtime]");
  if (gptRuntimeSel) gptRuntimeSel.value = gptRuntime;
  const outputLanguageSel = f.querySelector("[name=agent_output_language]");
  if (outputLanguageSel) {
    const language = String(s.agent_output_language || "auto").toLowerCase();
    outputLanguageSel.value = ["auto", "ko", "en"].includes(language)
      ? language : "auto";
  }

  // Claude effort (mirrors model: empty = SDK default; otherwise one
  // of low/medium/high/xhigh/max). Stored under `claude_effort` in the
  // settings blob; per-job submissions inherit it when their own
  // effort dropdown is left blank.
  const effortSel = f.querySelector("[name=claude_effort]");
  if (effortSel) {
    const curEffort = s.claude_effort || "";
    effortSel.value = CLAUDE_EFFORTS.includes(curEffort) ? curEffort : "";
  }
  const grokEffortSel = f.querySelector("[name=grok_effort]");
  if (grokEffortSel) {
    const curG = s.grok_effort || "";
    grokEffortSel.value = GROK_EFFORTS.includes(curG) ? curG : "";
  }
  const gptEffortSel = f.querySelector("[name=gpt_effort]");
  if (gptEffortSel) {
    const curGpt = s.gpt_effort || "";
    gptEffortSel.value = GPT_EFFORTS.includes(curGpt) ? curGpt : "";
  }

  f.querySelector("[name=job_ttl_days]").value =
    s.job_ttl_days != null ? s.job_ttl_days : "";
  f.querySelector("[name=job_timeout_seconds]").value =
    s.job_timeout_seconds != null ? s.job_timeout_seconds : "";
  f.querySelector("[name=codex_turn_timeout_seconds]").value =
    s.codex_turn_timeout_seconds != null ? s.codex_turn_timeout_seconds : "";
  // Show the LIVE slot count, not the stored `worker_concurrency`. That
  // setting is inert under the slot split (runner.py forces 1 process per slot
  // container) and /data/settings.json still holds its pre-split value, so
  // rendering it would tell the operator "3 parallel jobs" while two slots are
  // running. Fall back to the stored value only when the live count is
  // unavailable — i.e. a pre-split deployment, where it is still the truth.
  const liveSlots = s.worker_mem_live && s.worker_mem_live.available
    ? s.worker_mem_live.slot_count : null;
  f.querySelector("[name=worker_concurrency]").value =
    liveSlots != null ? liveSlots
      : (s.worker_concurrency != null ? s.worker_concurrency : "");
  const memInput = f.querySelector("[name=worker_slot_mem]");
  if (memInput) memInput.value = s.worker_slot_mem != null ? s.worker_slot_mem : "";
  renderWorkerMemLive(s.worker_mem_live);
  const budgetInput = f.querySelector("[name=budget_usd]");
  if (budgetInput) budgetInput.value = s.budget_usd ? s.budget_usd : "";
  f.querySelector("[name=callback_url]").value = s.callback_url || "";
  // judge_mode is the tri-state. `shadow` is deliberately NOT derivable from
  // the legacy boolean — entering it by inference would leave the operator
  // believing a gate is live when it gates nothing — so fall back to the
  // boolean only for off/enforce, exactly as get_judge_mode() does server-side.
  // Per-role provider overrides. Absent key means "no routing", which is not
  // the same as an empty map — both render as "follow job provider", but only
  // the map is ever written back, so a job created while this was empty keeps
  // byte-identical meta.
  const roleRoutes = (s.agent_role_providers && typeof s.agent_role_providers === "object")
    ? s.agent_role_providers : {};
  for (const role of ROLE_OVERRIDABLE) {
    const sel = f.querySelector(`[name=role_provider_${role}]`);
    if (!sel) continue;
    const want = String(roleRoutes[role] || "").toLowerCase();
    sel.value = roleTargets(role).includes(want) ? want : "";
  }
  renderRoleProviderStatus(f);

  const modeSel = f.querySelector("[name=judge_mode]");
  if (modeSel) {
    const stored = String(s.judge_mode || "").toLowerCase();
    modeSel.value = ["off", "shadow", "enforce"].includes(stored)
      ? stored
      : (s.enable_judge === false ? "off" : "enforce");
  }
  // enable_exploit_library_hint default-False
  f.querySelector("[name=enable_exploit_library_hint]").checked = !!s.enable_exploit_library_hint;
  // dynamic_worker_mem default-False
  f.querySelector("[name=dynamic_worker_mem]").checked = !!s.dynamic_worker_mem;
  // monitor_agent default-FALSE: a missing key renders as OFF, which is the
  // retired state. `!!undefined` is already false, so no ternary here — and
  // that asymmetry with prejudge_ship_gate below is the point, not an
  // oversight: the two keys have opposite defaults on purpose.
  f.querySelector("[name=monitor_agent]").checked = !!s.monitor_agent;
  // flag_harvester default-TRUE: a missing key must render as ON, or the form
  // would offer to turn off something the server still has on.
  const _mgrBox = f.querySelector("[name=manager_agent]");
  if (_mgrBox) _mgrBox.checked = !!s.manager_agent;
  const _mgrInt = f.querySelector("[name=manager_interval_s]");
  if (_mgrInt && s.manager_interval_s != null) _mgrInt.value = s.manager_interval_s;
  const _vpnBox = f.querySelector("[name=vpn_enabled]");
  if (_vpnBox) _vpnBox.checked = !!s.vpn_enabled;
  const _ollamaUrl = f.querySelector("[name=ollama_url]");
  if (_ollamaUrl) _ollamaUrl.value = s.ollama_url || "";
  const _ollamaModel = f.querySelector("[name=ollama_model]");
  const _ollamaSel = f.querySelector("[name=ollama_model_select]");
  if (_ollamaModel) _ollamaModel.value = s.ollama_model || "";
  if (_ollamaSel && s.ollama_model) {
    // Show the saved tag before any probe: the picker's options arrive only
    // when the endpoint answers, and a blank box next to a configured model
    // reads as "nothing is set".
    _ollamaSel.innerHTML =
      `<option value="${escapeHtml(s.ollama_model)}" selected>`
      + `${escapeHtml(s.ollama_model)} (저장됨)</option>`;
  }
  for (const k of ["vpn_scope", "vpn_venue_subnets", "vpn_peer_public_key",
                   "vpn_endpoint_host", "vpn_listen_port", "vpn_external_port",
                   "vpn_address", "vpn_peer_address"]) {
    const el = f.querySelector(`[name=${k}]`);
    if (el && s[k] !== undefined && s[k] !== null) el.value = s[k];
  }
  f.querySelector("[name=flag_harvester]").checked =
    s.flag_harvester === undefined ? true : !!s.flag_harvester;
  // prejudge_ship_gate default-TRUE: a missing key must render as ON, or the
  // form would offer to turn off a gate the server still has on.
  f.querySelector("[name=prejudge_ship_gate]").checked =
    s.prejudge_ship_gate === undefined ? true : !!s.prejudge_ship_gate;

  document.getElementById("key-status").textContent = s.anthropic_api_key_set
    ? `set (${s.anthropic_api_key_masked}) — leave blank to keep, type new to replace`
    : (s.anthropic_api_key_env_set ? "using ANTHROPIC_API_KEY from env" : "not set");
  document.getElementById("oauth-status").textContent = s.claude_oauth_detected
    ? "✓ Claude Code OAuth detected — works without API key"
    : "✗ no OAuth credentials — run `claude login` on the host";
  document.getElementById("oauth-status").classList.toggle("oauth-ok", !!s.claude_oauth_detected);

  const xaiStatus = document.getElementById("xai-key-status");
  if (xaiStatus) {
    xaiStatus.textContent = s.xai_api_key_set
      ? `set (${s.xai_api_key_masked}) — leave blank to keep, type new to replace`
      : (s.xai_api_key_env_set ? "using XAI_API_KEY from env" : "not set");
  }
  const grokAuth = document.getElementById("grok-auth-status");
  if (grokAuth) {
    grokAuth.textContent = s.grok_auth_detected
      ? "✓ Grok auth.json detected — works without API key"
      : "✗ no Grok auth file — run `grok login` on the host (mount ~/.grok) or set XAI_API_KEY";
    grokAuth.style.color = s.grok_auth_detected ? "var(--green)" : "var(--fg-muted)";
  }
  const openaiStatus = document.getElementById("openai-key-status");
  if (openaiStatus) {
    openaiStatus.textContent = s.openai_api_key_set
      ? `set (${s.openai_api_key_masked}) — leave blank to keep, type new to replace`
      : (s.openai_api_key_env_set ? "using OPENAI_API_KEY from env" : "not set");
  }
  const codexOauthStatus = document.getElementById("codex-oauth-status");
  if (codexOauthStatus) {
    const method = s.codex_auth_method || "none";
    codexOauthStatus.textContent = s.codex_oauth_detected
      ? "✓ Codex ChatGPT OAuth detected — API key is not used"
      : (s.codex_auth_detected
        ? `✗ Codex auth exists but is '${method}', not ChatGPT OAuth`
        : "✗ no Codex OAuth file — run `codex login` on the host and rebuild/recreate containers");
    codexOauthStatus.style.color = s.codex_oauth_detected ? "var(--green)" : "var(--red)";
  }

  renderProviderAuthUI(provider);

  document.getElementById("auth-status").textContent = s.auth_token_set
    ? `set (${s.auth_token_masked})`
    : (s.auth_token_env_set ? "using AUTH_TOKEN from env" : "not set (auth disabled)");
  _settingsDirtyClear();

  // "endpoint도 자동으로 가져오게": an EMPTY endpoint on open is the one case
  // where there is nothing to overrule and a manual round-trip to avoid. A
  // filled one is left alone — re-discovering over an address the operator
  // typed would be the tool quietly disagreeing with them.
  const _ourl = f.querySelector("[name=ollama_url]");
  if (_ourl && !String(_ourl.value || "").trim()) _discoverOllama();
}

// Live-toggle provider cards without saving (save still required).
document.getElementById("settings-form")?.addEventListener("change", (e) => {
  const t = e.target;
  if (t && t.name === "agent_provider") {
    setProviderUI(t.value);
    renderProviderAuthUI(t.value, {unsaved: true});
    // The status line reads "judge → claude (job runs on gpt)", so it has to
    // be recomputed when either side of that sentence changes.
    renderRoleProviderStatus(e.currentTarget);
  }
  if (t && t.name && t.name.startsWith("role_provider_")) {
    renderRoleProviderStatus(e.currentTarget);
  }
  if (t && t.name === "topology_preset" && t.value !== "custom") {
    applyTopology(e.currentTarget, t.value);
  }
  if (t && t.name === "gpt_runtime") {
    const selected = document.querySelector(
      '#settings-form input[name="agent_provider"]:checked'
    )?.value || activeAgentProvider;
    renderProviderAuthUI(selected, {unsaved: selected === "gpt"});
  }
});

document.getElementById("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  // The form carries `novalidate`, so this handler always runs. Without it, a
  // constraint-invalid control sitting in a HIDDEN section aborts submission
  // before any listener fires and the browser cannot focus it to say why —
  // Save becomes a silent no-op. Validate here, reveal the offender's section,
  // then point at it. (form.elements includes <fieldset>, whose willValidate is
  // false, which is why this filters on willValidate rather than `:invalid`.)
  const bad = Array.from(e.target.elements).find((el) => el.willValidate && !el.checkValidity());
  if (bad) {
    const pane = bad.closest("[data-settings-pane]");
    if (pane) showSettingsPane(pane.dataset.settingsPane);
    // If a browser ever refuses to paint the bubble on a control revealed in
    // this same task, wrap these two lines in requestAnimationFrame(...): the
    // reveal is a synchronous class toggle, the bubble is painted.
    bad.focus();
    if (bad.reportValidity) bad.reportValidity();
    return;
  }
  const fd = new FormData(e.target);
  // Custom-text overrides the corresponding provider model dropdown.
  const custom = (fd.get("claude_model_custom") || "").toString().trim();
  if (custom) fd.set("claude_model", custom);
  fd.delete("claude_model_custom");
  const grokCustom = (fd.get("grok_model_custom") || "").toString().trim();
  if (grokCustom) fd.set("grok_model", grokCustom);
  fd.delete("grok_model_custom");
  const gptCustom = (fd.get("gpt_model_custom") || "").toString().trim();
  if (gptCustom) fd.set("gpt_model", gptCustom);
  fd.delete("gpt_model_custom");
  // The tag picker is populated from a live probe, so it only exists once the
  // endpoint answers. The stored key is `ollama_model`; the select is the
  // affordance, not the setting.
  const localTag = (fd.get("ollama_model_select") || "").toString().trim();
  if (localTag) fd.set("ollama_model", localTag);
  fd.delete("ollama_model_select");

  const payload = {};
  for (const [k, v] of fd.entries()) {
    if (v === "" && (k === "anthropic_api_key" || k === "xai_api_key" || k === "openai_api_key" || k === "auth_token")) {
      // Empty secret field: skip — keep current value
      continue;
    }
    if (k === "enable_exploit_library_hint") continue;  // handled explicitly below
    if (k === "dynamic_worker_mem") continue;  // handled explicitly below
    if (k === "prejudge_ship_gate") continue;  // ditto — checkboxes never post when unchecked
    if (k === "monitor_agent") continue;  // ditto
    if (k === "flag_harvester") continue;  // ditto
    if (k === "manager_agent") continue;  // ditto
    if (k === "vpn_enabled") continue;  // ditto
    if (k.startsWith("role_provider_")) continue;  // assembled into one map below
    if (k === "topology_preset") continue;  // a form shortcut, never a setting
    if (v === "") {
      payload[k] = null;  // null = clear the override
      continue;
    }
    if (k === "worker_slot_mem") {
      payload[k] = String(v).trim();
    } else if (k === "job_ttl_days" || k === "job_timeout_seconds" || k === "codex_turn_timeout_seconds" || k === "worker_concurrency" || k === "budget_usd" || k === "vpn_listen_port" || k === "vpn_external_port" || k === "manager_interval_s") {
      payload[k] = Number(v);
    } else {
      payload[k] = v;
    }
  }
  // Checkboxes are absent from FormData when unchecked — read directly
  // so the OFF state is sent as `false`, not "clear the override".
  //
  // The legacy boolean is written alongside the mode, and only ever to the
  // value the mode implies. Nothing but get_judge_mode()'s fallback reads it,
  // but a settings file saying enable_judge=true next to judge_mode=off is a
  // contradiction the next person to read it has to resolve.
  const _mode = String(payload.judge_mode || "enforce").toLowerCase();
  payload.enable_judge = _mode === "enforce";

  // The four selects are ONE setting. Sent as a whole map every time, so
  // clearing a role is a real clear rather than a key the server keeps from a
  // previous save. "follow job provider" is expressed by omitting the role.
  const routes = {};
  for (const role of ROLE_OVERRIDABLE) {
    const v = String(e.target.querySelector(`[name=role_provider_${role}]`)?.value || "").toLowerCase();
    if (roleTargets(role).includes(v)) routes[role] = v;
  }
  payload.agent_role_providers = routes;
  payload.enable_exploit_library_hint = !!e.target.querySelector("[name=enable_exploit_library_hint]").checked;
  payload.dynamic_worker_mem = !!e.target.querySelector("[name=dynamic_worker_mem]").checked;
  payload.prejudge_ship_gate =
    !!e.target.querySelector("[name=prejudge_ship_gate]").checked;
  payload.monitor_agent =
    !!e.target.querySelector("[name=monitor_agent]").checked;
  payload.flag_harvester =
    !!e.target.querySelector("[name=flag_harvester]").checked;
  payload.manager_agent =
    !!e.target.querySelector("[name=manager_agent]").checked;
  // Sending this ALWAYS, not only when it changed, is deliberate: the server
  // treats the key's presence as "act on the tunnel now" (start or stop), and
  // a Save that persisted vpn_scope while leaving the running tunnel on the
  // old scope is exactly the silent no-op the rest of this handler avoids.
  payload.vpn_enabled =
    !!e.target.querySelector("[name=vpn_enabled]").checked;
  // Radio always present; default claude if somehow missing.
  if (!payload.agent_provider) {
    payload.agent_provider = e.target.querySelector("[name=agent_provider]:checked")?.value || "claude";
  }
  const res = await fetch(`${API}/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    alert(`save failed: ${res.status} ${await res.text()}`);
    return;
  }
  // Clear secret fields after save
  e.target.querySelector("[name=anthropic_api_key]").value = "";
  const xaiIn = e.target.querySelector("[name=xai_api_key]");
  if (xaiIn) xaiIn.value = "";
  const openaiIn = e.target.querySelector("[name=openai_api_key]");
  if (openaiIn) openaiIn.value = "";
  e.target.querySelector("[name=auth_token]").value = "";
  let applied = null;
  try { applied = (await res.clone().json()).worker_mem_applied; } catch (_) {}
  let savedView = null;
  try { savedView = await res.clone().json(); } catch (_) {}
  await loadSettings();
  const savedProvider = (savedView && savedView.agent_provider) || payload.agent_provider || "claude";
  const savedGptRuntime = (savedView && savedView.gpt_runtime) || payload.gpt_runtime || "codex";
  const providerLine = savedProvider === "gpt"
    ? (savedGptRuntime === "codex"
      ? "Agent provider: OpenAI Codex — next job uses ChatGPT OAuth."
      : "Agent provider: OpenAI GPT Responses API — next job uses API-key billing.")
    : (savedProvider === "grok"
      ? "Agent provider: Grok Build (ACP) — next job uses Grok."
      : "Agent provider: Claude (Agent SDK) — next job uses Claude.");
  if (applied && applied.applied === false) {
    alert("Saved, but the per-slot memory limit was NOT applied to the running slots:\n\n" +
          applied.reason + "\n\nIt will take effect on the next `docker compose up -d worker-1 worker-2`.\n\n" +
          providerLine);
  } else if (applied && applied.applied) {
    alert("Saved. Per-slot memory limit applied to all " + (applied.slot_count || "") +
          " running slot(s) immediately.\n\n" + providerLine);
  } else {
    alert("Saved. Changes apply to the next job.\n\n" + providerLine);
  }
});

// The worker memory cap is a container-CREATE property, so the saved setting
// and the container's actual cgroup can diverge (a recreate resets it to the
// compose/.env default). Show what the container REALLY has, never just what
// was typed.
function fmtBytes(n) {
  if (!n || n <= 0) return "unlimited";
  const g = n / 1073741824;
  return g >= 1 ? g.toFixed(g < 10 ? 1 : 0) + " GiB" : Math.round(n / 1048576) + " MiB";
}
function renderWorkerMemLive(live) {
  const el = document.getElementById("worker-mem-live");
  if (!el) return;
  if (!live || !live.available) {
    el.innerHTML = '<br><b style="color:var(--yellow)">live value unavailable</b> (docker socket not reachable from the api container)';
    return;
  }
  // The cap is PER SLOT and there are N slots, so the number that matters for
  // "does this fit the VM" is the product. Showing only the per-slot value is
  // how an 8g-per-container setting quietly became 16 GiB of cap.
  const n = live.slot_count || (live.slots ? live.slots.length : 1);
  const lim = fmtBytes(live.limit_bytes);
  const use = live.usage_bytes ? fmtBytes(live.usage_bytes) : "?";
  const total = fmtBytes(live.total_limit_bytes || live.limit_bytes);
  let html = '<br>right now: <b>' + n + ' slot' + (n === 1 ? "" : "s") +
             ' &times; ' + lim + '</b> = ' + total + ' total cap, ' + use + ' in use';

  if (live.host_mem_total_bytes) {
    html += ' &middot; VM has ' + fmtBytes(live.host_mem_total_bytes);
  }
  if (!live.limit_bytes || live.limit_bytes <= 0) {
    html += ' <b style="color:var(--yellow)">— uncapped: one runaway job can freeze the host</b>';
  }
  if (live.limits_uniform === false) {
    html += ' <b style="color:var(--yellow)">— slots disagree on their cap' +
            ' (showing the smallest, which OOMs first); recreate to normalise</b>';
  }
  if (live.slots && live.slots.length > 1) {
    html += '<br>' + live.slots.map(function (s) {
      const u = s.usage_bytes ? fmtBytes(s.usage_bytes) : "?";
      return '&nbsp;&nbsp;slot ' + (s.slot || "?") + ': ' + fmtBytes(s.limit_bytes) +
             ' cap, ' + u + ' in use';
    }).join('<br>');
  }
  el.innerHTML = html;
}

// --- Settings sections (click-into list) -----------------------------------
// The one long Settings form is presented as click-into sections. Panes are
// hidden by CLASS ONLY: every named control stays in #settings-form, in the DOM,
// enabled, and is filled by the single loadSettings() pass. That is what keeps
// one Save covering all sections — a hidden field is still in FormData, so a
// section the operator never opened is not saved as `null` by the
// `v === ""` -> clear-the-override branch of the save loop.
const SETTINGS_PANE_KEY = "htct.settingsPane";

function _settingsPanes() {
  return Array.from(document.querySelectorAll("#panel-settings [data-settings-pane]"));
}

function showSettingsPane(name) {
  const panes = _settingsPanes();
  if (!panes.length) return;
  const known = new Set(panes.map((p) => p.dataset.settingsPane));
  // A stored/typo'd name must not blank the page: fall back to the first section.
  const want = known.has(name) ? name : panes[0].dataset.settingsPane;
  panes.forEach((p) => p.classList.toggle("settings-pane--on", p.dataset.settingsPane === want));
  document.querySelectorAll("#settings-nav [data-settings-target]").forEach((b) => {
    const on = b.dataset.settingsTarget === want;
    b.classList.toggle("active", on);
    b.setAttribute("aria-selected", on ? "true" : "false");
    b.tabIndex = on ? 0 : -1;
  });
  // Save writes /api/settings, i.e. the FORM. The presets pane has no form
  // fields and its own Save writes model_presets.json, so a form Save floating
  // over it would read as "presets saved" and save nothing of the kind.
  const footer = document.getElementById("settings-footer");
  const form = document.getElementById("settings-form");
  if (footer && form) footer.hidden = !form.querySelector('[data-settings-pane="' + want + '"]');
  try { localStorage.setItem(SETTINGS_PANE_KEY, want); } catch (_) {}
  // Two live readouts stop being live once their pane can be off-screen.
  if (want === "access") { loadTunnelStatus(); loadVpnStatus(); }
  if (want === "ops") refreshWorkerMemLive();
}

// The ONLY partial refresh. It must never touch a field: loadSettings()
// overwrites every control from the server, so calling it on navigation would
// silently discard unsaved edits made in the other sections.
async function refreshWorkerMemLive() {
  try {
    const res = await fetch(`${API}/settings`);
    if (!res.ok) return;
    const s = await res.json();
    renderWorkerMemLive(s.worker_mem_live);
  } catch (_) { /* readout only */ }
}

function _syncSettingsDirtyDots() {
  document.querySelectorAll("#settings-nav [data-settings-target]").forEach((b) => {
    const pane = document.querySelector(
      '#settings-form [data-settings-pane="' + b.dataset.settingsTarget + '"]');
    b.classList.toggle("settings-nav--dirty", !!(pane && pane.dataset.dirty));
  });
}
function _settingsDirtyClear() {
  document.querySelectorAll("#settings-form [data-settings-pane]")
    .forEach((p) => { delete p.dataset.dirty; });
  _syncSettingsDirtyDots();
}
function _markSettingsDirty(e) {
  const pane = e.target && e.target.closest && e.target.closest("[data-settings-pane]");
  if (!pane) return;
  pane.dataset.dirty = "1";
  _syncSettingsDirtyDots();
}
document.getElementById("settings-form")?.addEventListener("input", _markSettingsDirty);
document.getElementById("settings-form")?.addEventListener("change", _markSettingsDirty);

document.getElementById("settings-nav")?.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-settings-target]");
  if (!btn) return;
  showSettingsPane(btn.dataset.settingsTarget);
  document.getElementById(btn.getAttribute("aria-controls"))?.focus();
});
document.getElementById("settings-nav")?.addEventListener("keydown", (e) => {
  const items = Array.from(e.currentTarget.querySelectorAll("[data-settings-target]"));
  const i = items.indexOf(document.activeElement);
  if (i < 0) return;
  let j = null;
  if (e.key === "ArrowDown") j = (i + 1) % items.length;
  else if (e.key === "ArrowUp") j = (i - 1 + items.length) % items.length;
  else if (e.key === "Home") j = 0;
  else if (e.key === "End") j = items.length - 1;
  if (j === null) return;
  e.preventDefault();
  items[j].focus();
  showSettingsPane(items[j].dataset.settingsTarget);
});

// loadSettings() refetches EVERY section, not just the visible one, so both
// entry points into it can discard edits the operator cannot see. That was
// survivable while the whole form was on screen; with sections it is not.
function reloadSettingsGuarded() {
  if (document.querySelector("#settings-form [data-settings-pane][data-dirty]")
      && !confirm("Reload discards unsaved edits in EVERY section, not just this one. Continue?")) return;
  loadSettings();
}
document.getElementById("settings-reload").addEventListener("click", reloadSettingsGuarded);

// Load settings whenever the user clicks the Settings tab
document.querySelector('.tab[data-tab="settings"]').addEventListener("click", () => {
  reloadSettingsGuarded();
  loadModelPresets();
  loadTunnelStatus();
  loadVpnStatus();
});

// --- Cloudflared tunnel ----------------------------------------------------
// Activate/stop a cloudflared OOB quick-tunnel and show live connection state.
// Backed by /api/tunnel (start/stop/status) which runs cloudflared as a sibling
// container. Status reflects reality (container + edge probe), never a flag.
let _tunnelPoll = null;
let _tunnelPollTicks = 0;

function _stopTunnelPoll() {
  if (_tunnelPoll) { clearInterval(_tunnelPoll); _tunnelPoll = null; }
  _tunnelPollTicks = 0;
}

function _setTunnelChip(state, label) {
  const chip = document.getElementById("tunnel-chip");
  if (!chip) return;
  chip.className = "rl-chip " + (
    state === "connected" ? "rl-chip--ok" :
    state === "connecting" ? "rl-chip--warn" : "rl-chip--rejected"
  );
  chip.textContent = label;
}

function renderTunnel(s) {
  const warn = document.getElementById("tunnel-warning");
  if (warn) warn.hidden = !s.exposure_warning;
  const urlEl = document.getElementById("tunnel-url");
  if (urlEl) {
    if (s.running && s.url) { urlEl.hidden = false; urlEl.textContent = s.url; urlEl.href = s.url; }
    else { urlEl.hidden = true; urlEl.textContent = ""; urlEl.removeAttribute("href"); }
  }
  if (!s.running) {
    _setTunnelChip("down", s.error ? "error" : "down");
  } else if (!s.url) {
    _setTunnelChip("connecting", "connecting…");
  } else if (s._dud) {
    _setTunnelChip("down", "up but unreachable — re-roll");
  } else if (s.reachable === false) {
    _setTunnelChip("connecting", "edge warming up…");
  } else {
    _setTunnelChip("connected", s.url_published ? "connected" : "connected (unpublished)");
  }
  const txt = document.getElementById("tunnel-status-text");
  if (txt) txt.textContent = s.error ? s.error : (s.note || "");
}

async function loadTunnelStatus(probe = false) {
  try {
    const res = await fetch(`${API}/tunnel/status${probe ? "?probe=1" : ""}`);
    if (!res.ok) { _setTunnelChip("down", "status error"); _stopTunnelPoll(); return null; }
    const s = await res.json();
    // Cap the "edge warming up" window: after ~12 gated ticks (~60s) of
    // running-but-unreachable, call it a dud (a dead quick-tunnel that came up
    // but never routes) so the chip goes terminal-red and the poller stops,
    // instead of spinning yellow forever.
    if (s.running && s.url && s.reachable === false && _tunnelPollTicks >= 12) s._dud = true;
    renderTunnel(s);
    const connecting = s.running && (!s.url || s.reachable === false) && !s._dud;
    // The tunnel UI is one SECTION now, not the whole panel: keep the 5s poll
    // (and its 12-tick dud budget) tied to the section actually being on screen.
    const onSettings = !!document.getElementById("panel-settings")?.classList.contains("active")
      && !!document.getElementById("tunnel-block")?.classList.contains("settings-pane--on");
    if (connecting && onSettings) {
      _tunnelPollTicks++;
      if (!_tunnelPoll) _tunnelPoll = setInterval(() => loadTunnelStatus(true), 5000);
    } else {
      _stopTunnelPoll();
    }
    return s;
  } catch (_) {
    _setTunnelChip("down", "unreachable"); _stopTunnelPoll(); return null;
  }
}

document.getElementById("tunnel-activate").addEventListener("click", async (e) => {
  const btn = e.target; btn.disabled = true;
  _stopTunnelPoll();
  _setTunnelChip("connecting", "starting…");
  const txt = document.getElementById("tunnel-status-text");
  if (txt) txt.textContent = "spawning cloudflared + waiting for public URL (up to ~30s)…";
  try {
    const res = await fetch(`${API}/tunnel/start`, { method: "POST" });
    const s = await res.json();
    renderTunnel(s);
    if (s.ok) {
      loadTunnelStatus(true);   // re-check reachability (does NOT clobber an error)
    } else if (txt) {
      txt.textContent = s.error || s.detail || "start failed";  // keep it visible
    }
  } catch (err) {
    if (txt) txt.textContent = `start failed: ${err}`;
    _setTunnelChip("down", "error");
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("tunnel-stop").addEventListener("click", async (e) => {
  const btn = e.target; btn.disabled = true;
  _stopTunnelPoll();
  const txt = document.getElementById("tunnel-status-text");
  if (txt) txt.textContent = "stopping…";
  try {
    const res = await fetch(`${API}/tunnel/stop`, { method: "POST" });
    const s = await res.json();
    renderTunnel(s);
    if (txt) txt.textContent = s.error || s.note || "stopped";
  } catch (err) {
    if (txt) txt.textContent = `stop failed: ${err}`;
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("tunnel-refresh").addEventListener("click", () => loadTunnelStatus(true));

// ---------------------------------------------------------------------------
// Venue VPN status.
//
// Container, interface and peer are rendered SEPARATELY on purpose: they come
// apart, and the way they come apart is what an operator at a venue needs to
// read. "sidecar exited" with its log is a different problem from "up, but the
// laptop has never handshaked", and one chip that collapsed both into "down"
// would send them to debug the wrong end of the tunnel.
// ---------------------------------------------------------------------------
function _setVpnChip(state, label) {
  const chip = document.getElementById("vpn-chip");
  if (!chip) return;
  chip.className = "rl-chip " + (
    state === "ok" ? "rl-chip--ok" :
    state === "warn" ? "rl-chip--warn" : "rl-chip--rejected"
  );
  chip.textContent = label;
}

function _agoText(unixSeconds) {
  if (!unixSeconds) return "never";
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds);
  if (secs < 90) return `${secs}s ago`;
  if (secs < 5400) return `${Math.round(secs / 60)}m ago`;
  return `${Math.round(secs / 3600)}h ago`;
}

async function loadVpnStatus() {
  const text = document.getElementById("vpn-status-text");
  if (!document.getElementById("vpn-chip")) return;
  let s;
  try {
    const res = await fetch(`${API}/vpn/status`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    s = await res.json();
  } catch (e) {
    _setVpnChip("down", "unreachable");
    if (text) text.textContent = String(e.message || e);
    return;
  }
  const peer = (s.peers || [])[0];
  if (s.container !== "running") {
    _setVpnChip(s.container === "absent" ? "down" : "warn", s.container);
    // The sidecar's own last lines say WHY it exited — a missing config, a
    // port already bound. Far more use than the word "exited".
    if (text) text.textContent = (s.error || "").split("\n").slice(-2).join(" ") || "not running";
    return;
  }
  if (!s.interface_up) {
    _setVpnChip("warn", "container up, wg0 down");
    if (text) text.textContent = s.error || "";
    return;
  }
  if (!peer) {
    _setVpnChip("warn", "no peer configured");
    if (text) text.textContent = "set the laptop's public key and save";
    return;
  }
  const hs = peer.last_handshake || 0;
  // WireGuard is silent by design: no handshake yet is the NORMAL state right
  // up until the laptop first dials in, so it is a warning and never an error.
  const fresh = hs && (Date.now() / 1000 - hs) < 180;
  _setVpnChip(fresh ? "ok" : "warn", fresh ? "connected" : "waiting for laptop");
  if (text) {
    const routes = (s.routes || []).length;
    text.textContent =
      `handshake ${_agoText(hs)} · ${peer.endpoint || "no endpoint yet"} · ` +
      `${routes} route${routes === 1 ? "" : "s"} via wg0`;
  }
}

document.getElementById("vpn-refresh")?.addEventListener("click", loadVpnStatus);

document.getElementById("vpn-peer-config")?.addEventListener("click", async () => {
  const out = document.getElementById("vpn-peer-out");
  const note = document.getElementById("vpn-peer-note");
  if (!out) return;
  out.style.display = "block";
  out.textContent = "loading…";
  try {
    const res = await fetch(`${API}/vpn/peer-config`);
    const body = await res.json();
    if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
    out.textContent = body.config;
    if (note) note.hidden = false;
    // The config below carries the private half of the keypair stored on the
    // server. A DIFFERENT public key pinned in settings means the two ends can
    // never handshake — and WireGuard reports nothing, so the symptom is
    // identical to a blocked port and sends you to debug the router.
    if (body.key_mismatch) {
      out.textContent =
        "# WARNING: the 'Laptop public key' saved in settings does NOT match\n" +
        "# this config's private key, so the two ends can never handshake —\n" +
        "# and WireGuard will say nothing about it.\n" +
        "#\n" +
        "# Either clear that field (Ogamdo then uses its own keypair, below),\n" +
        "# or paste this key into it:\n" +
        `#   ${body.peer_public_key}\n\n` +
        body.config;
    }
    // Rendered without an Endpoint line, the config cannot dial anywhere. Say
    // so here rather than let it be discovered at the venue.
    if (!body.endpoint_set) {
      out.textContent =
        "# WARNING: \"This box's public address\" is empty, so this config has no\n" +
        "# Endpoint line and the laptop has nothing to dial. Set it and Save first.\n\n" +
        body.config;
    }
  } catch (e) {
    out.textContent = `error: ${e.message || e}`;
  }
});

// --- Provider model presets ------------------------------------------------
// Each provider owns an independent named-preset collection and active
// selection. The complete v2 store is edited in memory and PUT as one blob.
const PRESET_PROVIDERS = ["claude", "grok", "gpt", "local"];
const PRESET_PROVIDER_LABELS = {
  claude: "Claude", grok: "Grok", gpt: "GPT", local: "Local",
};
// Roles a given preset provider may be pinned for. Everything except `local`
// takes the full list; `local` takes only what has an adapter behind it, and
// that set lives in agent_provider.LOCAL_CAPABLE_ROLES. Offering a slot the
// backend ignores is the defect this repo keeps finding — a setting that
// looks like a choice and changes nothing.
const LOCAL_PRESET_ROLES = LOCAL_CAPABLE_ROLES;
const DEFAULT_PRESET_ROLES = ["operator", "main", "judge", "reviewer", "recon", "debugger", "triage", "report", "monitor", "harvester", "manager"];

function emptyPresetProviders() {
  return Object.fromEntries(PRESET_PROVIDERS.map((provider) => [
    provider, { active: "", presets: {} },
  ]));
}

let PRESET_STORE = {
  version: 2,
  providers: emptyPresetProviders(),
  configurable_roles: DEFAULT_PRESET_ROLES,
};
let PRESET_PROVIDER = "claude";
// A live-mounted UI can update before the long-running API process restarts.
// Never send a v2 body to a v1 server: it would interpret it as an empty flat
// store and erase the old preset file.
let PRESET_API_VERSION = 0;

// Human-readable default a blank role falls back to (shown in the "(inherit)" option).
const PRESET_ROLE_DEFAULTS = {
  main: "per-job pick / global Settings model",
  judge: "follows main model",
  reviewer: "follows judge slot / main",
  recon: "follows main — cache-aligned",
  debugger: "follows main — cache-aligned",
  triage: "follows main — cache-aligned",
  report: "follows main model",
  monitor: "provider monitor default",
  harvester: "cheap model — sonnet / provider default",
};

async function loadModelPresets() {
  PRESET_API_VERSION = 0;
  try {
    const res = await fetch(`${API}/model-presets`);
    if (!res.ok) return;
    const s = await res.json();
    if (s && typeof s === "object") {
      const providers = emptyPresetProviders();
      if (s.providers && typeof s.providers === "object") {
        PRESET_API_VERSION = 2;
        for (const provider of PRESET_PROVIDERS) {
          const bucket = s.providers[provider];
          if (!bucket || typeof bucket !== "object") continue;
          providers[provider] = {
            active: bucket.active || "",
            presets: bucket.presets || {},
          };
        }
      } else {
        PRESET_API_VERSION = 1;
        // Tolerate a stale/v1 API during rolling container restarts. Its flat
        // store belonged to whichever provider Settings selected.
        providers[activeAgentProvider] = {
          active: s.active || "",
          presets: s.presets || {},
        };
      }
      PRESET_STORE = {
        version: 2,
        providers,
        configurable_roles: (s.configurable_roles && s.configurable_roles.length)
          ? s.configurable_roles : DEFAULT_PRESET_ROLES,
      };
    }
  } catch (_) { return; }
  renderPresetControls();
}

function currentPresetBucket() {
  if (!PRESET_STORE.providers || typeof PRESET_STORE.providers !== "object") {
    PRESET_STORE.providers = emptyPresetProviders();
  }
  if (!PRESET_STORE.providers[PRESET_PROVIDER]) {
    PRESET_STORE.providers[PRESET_PROVIDER] = { active: "", presets: {} };
  }
  return PRESET_STORE.providers[PRESET_PROVIDER];
}

function presetCatalog(provider = PRESET_PROVIDER) {
  if (provider === "grok") return { models: GROK_MODELS, efforts: GROK_EFFORTS };
  if (provider === "gpt") return { models: GPT_MODELS, efforts: GPT_EFFORTS };
  return { models: CLAUDE_MODELS, efforts: CLAUDE_EFFORTS };
}

function renderPresetCatalogNote(provider = PRESET_PROVIDER) {
  const note = document.getElementById("preset-catalog-note");
  if (!note) return;
  const isGpt = provider === "gpt";
  note.hidden = !isGpt;
  note.textContent = isGpt
    ? `Current GPT catalog: ${GPT_MODELS.join(" · ")}. `
      + "Daybreak requires separate OpenAI approval; Codex Spark is Codex CLI-only."
    : "";
}

function presetRoles(provider = PRESET_PROVIDER) {
  const roles = Array.isArray(PRESET_STORE.configurable_roles)
    ? PRESET_STORE.configurable_roles : DEFAULT_PRESET_ROLES;
  // Every role, every HOSTED provider. `monitor` used to be filtered out of
  // GPT presets because the Timeline was treated as its replacement — which
  // made the role unpickable exactly where the backend had a complete GPT
  // narrator waiting. A role the backend can run must be selectable here, or
  // the setting is a promise the UI quietly withholds.
  //
  // `local` is the mirror image of that rule, not an exception to it: it gets
  // ONLY the roles with an adapter behind it. Backend-side the pin is ignored
  // for the rest (agent_provider._target_ok), so offering them would be the
  // same withheld promise pointing the other way.
  if (provider === "local") {
    return roles.filter((r) => LOCAL_PRESET_ROLES.includes(r));
  }
  return roles;
}

function setPresetProvider(provider) {
  PRESET_PROVIDER = PRESET_PROVIDERS.includes(provider) ? provider : "claude";
  renderPresetControls();
}

function renderPresetControls() {
  const sel = document.getElementById("preset-active");
  if (!sel) return;
  const bucket = currentPresetBucket();
  const names = Object.keys(bucket.presets || {}).sort();
  const active = bucket.active || "";
  document.querySelectorAll("[data-preset-provider]").forEach((button) => {
    const selected = button.dataset.presetProvider === PRESET_PROVIDER;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-pressed", selected ? "true" : "false");
  });
  const providerLabel = document.getElementById("preset-provider-label");
  if (providerLabel) providerLabel.textContent = PRESET_PROVIDER_LABELS[PRESET_PROVIDER];
  renderPresetCatalogNote();
  const saveButton = document.getElementById("preset-save");
  if (saveButton) {
    saveButton.disabled = PRESET_API_VERSION < 2;
    saveButton.title = PRESET_API_VERSION === 1
      ? "Restart the API to enable provider-scoped preset saves"
      : "";
  }
  sel.innerHTML = "";
  sel.appendChild(new Option(`(none — ${PRESET_PROVIDER_LABELS[PRESET_PROVIDER]} agents inherit defaults)`, ""));
  for (const n of names) sel.appendChild(new Option(n, n));
  sel.value = names.includes(active) ? active : "";
  renderPresetRoles();
  updatePresetStatus();
}

function renderPresetRoles() {
  const wrap = document.getElementById("preset-roles");
  if (!wrap) return;
  const active = document.getElementById("preset-active").value;
  const bucket = currentPresetBucket();
  wrap.innerHTML = "";
  if (!active) {
    const p = document.createElement("p");
    p.className = "preset-empty";
    p.textContent =
      `No ${PRESET_PROVIDER_LABELS[PRESET_PROVIDER]} preset active — main uses the per-job pick / global Settings model & `
      + (PRESET_PROVIDER === "gpt"
        ? "effort; judge/report follow main; activity uses the token-free Timeline. Click “+ New” to "
        : "effort; judge/report follow main; monitor runs cheap. Click “+ New” to ")
      + "create one.";
    wrap.appendChild(p);
    return;
  }
  const preset = bucket.presets[active] || {};
  const {models: providerModels, efforts: providerEfforts} = presetCatalog();
  for (const role of presetRoles()) {
    const cur = preset[role] || "";
    const lbl = document.createElement("label");
    lbl.className = "preset-role";
    const inheritTxt = PRESET_ROLE_DEFAULTS[role] || "inherit";
    lbl.innerHTML =
      `<span class="preset-role-name">${role}</span>` +
      `<select data-preset-role="${role}"></select>`;
    const s = lbl.querySelector("select");
    s.appendChild(new Option(`(inherit — ${inheritTxt})`, ""));
    for (const m of providerModels) s.appendChild(new Option(m, m));
    // A saved custom model that isn't in the catalog: surface it so it's editable.
    if (cur && !providerModels.includes(cur)) s.appendChild(new Option(`${cur} (custom)`, cur));
    s.value = cur;
    s.addEventListener("change", () => {
      if (!bucket.presets[active]) bucket.presets[active] = {};
      bucket.presets[active][role] = s.value;
      updatePresetStatus();
    });
    wrap.appendChild(lbl);
  }
  // effort row — reasoning effort for the MAIN session (mirrors the global
  // "Effort" Setting); not a model, so it's a separate control.
  const elbl = document.createElement("label");
  elbl.className = "preset-role";
  elbl.innerHTML =
    `<span class="preset-role-name">effort</span>` +
    `<select data-preset-effort></select>`;
  const es = elbl.querySelector("select");
  es.appendChild(new Option("(inherit — per-job / global Settings effort)", ""));
  for (const ef of providerEfforts) es.appendChild(new Option(ef, ef));
  es.value = preset.effort || "";
  es.addEventListener("change", () => {
    if (!bucket.presets[active]) bucket.presets[active] = {};
    bucket.presets[active].effort = es.value;
    updatePresetStatus();
  });
  wrap.appendChild(elbl);
}

function updatePresetStatus() {
  const el = document.getElementById("preset-status");
  if (!el) return;
  const bucket = currentPresetBucket();
  const active = bucket.active || "";
  const providerName = PRESET_PROVIDER_LABELS[PRESET_PROVIDER];
  if (PRESET_API_VERSION === 1) {
    el.textContent = "API restart required — the running API still uses the legacy single-preset format.";
    return;
  }
  if (PRESET_API_VERSION === 0) {
    el.textContent = "preset API unavailable — reload Settings and try again.";
    return;
  }
  if (!active || !bucket.presets[active]) {
    el.textContent = `${providerName}: no preset active — defaults in effect. Save to apply.`;
    return;
  }
  const p = bucket.presets[active];
  const parts = presetRoles().map(
    (r) => `${r}=${p[r] ? p[r] : "inherit"}`
  );
  parts.push(`effort=${p.effort ? p.effort : "inherit"}`);
  el.textContent = `${providerName} active: ${active} · ${parts.join(" · ")} · Save to apply`;
}

document.getElementById("preset-active").addEventListener("change", (e) => {
  currentPresetBucket().active = e.target.value;
  renderPresetRoles();
  updatePresetStatus();
});

document.querySelectorAll("[data-preset-provider]").forEach((button) => {
  button.addEventListener("click", () => setPresetProvider(button.dataset.presetProvider));
});

document.getElementById("preset-new").addEventListener("click", () => {
  const bucket = currentPresetBucket();
  const name = (prompt(`New ${PRESET_PROVIDER_LABELS[PRESET_PROVIDER]} preset name:`) || "").trim();
  if (!name) return;
  if (bucket.presets[name]) { alert(`preset "${name}" already exists for ${PRESET_PROVIDER_LABELS[PRESET_PROVIDER]}`); return; }
  bucket.presets[name] = Object.fromEntries([
    ...presetRoles().map((role) => [role, ""]),
    ["effort", ""],
  ]);
  bucket.active = name;
  renderPresetControls();
});

document.getElementById("preset-rename").addEventListener("click", () => {
  const bucket = currentPresetBucket();
  const cur = document.getElementById("preset-active").value;
  if (!cur) { alert("select a preset to rename first"); return; }
  const nn = (prompt("New name:", cur) || "").trim();
  if (!nn || nn === cur) return;
  if (bucket.presets[nn]) { alert(`preset "${nn}" already exists`); return; }
  bucket.presets[nn] = bucket.presets[cur];
  delete bucket.presets[cur];
  if (bucket.active === cur) bucket.active = nn;
  renderPresetControls();
});

document.getElementById("preset-delete").addEventListener("click", () => {
  const bucket = currentPresetBucket();
  const cur = document.getElementById("preset-active").value;
  if (!cur) { alert("select a preset to delete first"); return; }
  if (!confirm(`Delete preset "${cur}"?`)) return;
  delete bucket.presets[cur];
  if (bucket.active === cur) bucket.active = "";
  renderPresetControls();
});

document.getElementById("preset-save").addEventListener("click", async (e) => {
  if (PRESET_API_VERSION < 2) {
    alert("Restart the API, then reload Settings before saving provider presets.");
    return;
  }
  const btn = e.target;
  btn.disabled = true;
  try {
    const res = await fetch(`${API}/model-presets`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: 2, providers: PRESET_STORE.providers }),
    });
    if (!res.ok) { alert(`save failed: ${res.status} ${await res.text()}`); return; }
    const saved = await res.json();
    const providers = emptyPresetProviders();
    for (const provider of PRESET_PROVIDERS) {
      const bucket = saved.providers && saved.providers[provider];
      if (bucket) providers[provider] = {
        active: bucket.active || "",
        presets: bucket.presets || {},
      };
    }
    PRESET_STORE = {
      version: 2,
      providers,
      configurable_roles: (saved.configurable_roles && saved.configurable_roles.length)
        ? saved.configurable_roles : PRESET_STORE.configurable_roles,
    };
    renderPresetControls();
    const el = document.getElementById("preset-status");
    if (el) el.textContent = `all provider presets saved ✓ — ${PRESET_PROVIDER_LABELS[PRESET_PROVIDER]} selection applies to the next job`;
  } finally {
    btn.disabled = false;
  }
});

// --- Exploit Library -------------------------------------------------------
// Operator-curated library of past report.md + exploit.py pairs. Future
// jobs consult /data/exploits/<id>/ via plain Bash when the Settings
// toggle `enable_exploit_library_hint` is ON.

async function loadExploits() {
  const status = document.getElementById("exp-status");
  const list = document.getElementById("exp-list");
  if (!list) return;
  const module = document.getElementById("exp-filter-module").value;
  const search = document.getElementById("exp-filter-search").value.trim();
  const params = new URLSearchParams();
  if (module) params.set("module", module);
  if (search) params.set("search", search);
  status.textContent = "loading…";
  list.innerHTML = "";
  let data;
  try {
    const res = await fetch(`${API}/exploits?${params.toString()}`);
    if (!res.ok) {
      status.textContent = `error ${res.status}: ${await res.text()}`;
      return;
    }
    data = await res.json();
  } catch (e) {
    status.textContent = "fetch failed: " + e;
    return;
  }
  status.textContent = `${data.count} entr${data.count === 1 ? "y" : "ies"}`;
  if (!data.items.length) {
    list.innerHTML = `<li class="exp-empty">no saved exploits yet — save one via the 💾 button on any finished job's detail panel</li>`;
    return;
  }
  list.innerHTML = data.items.map((m) => {
    const id = m.id;
    const tagsHtml = (m.tags || []).map(t => `<span class="exp-tag">${escapeHtml(t)}</span>`).join("");
    const flagsHtml = (m.flags || []).map(f => `<code class="exp-flag">${escapeHtml(f)}</code>`).join(" ");
    const bug = (m.bug_classes || []).join(",") || "";
    const mit = m.mitigations ? Object.entries(m.mitigations).map(([k,v])=>`${k}=${v}`).join(" ") : "";
    return `<li class="exp-card" data-id="${id}">
      <div class="exp-card-head">
        <span class="exp-id">${escapeHtml(id)}</span>
        <span class="exp-module ${escapeHtml(m.module || "")}">${escapeHtml(m.module || "?")}</span>
        <span class="exp-saved" title="${escapeHtml(m.saved_at || "")}">${escapeHtml((m.saved_at || "").slice(0,19).replace("T"," "))}</span>
      </div>
      <div class="exp-card-meta">
        <div><b>chal:</b> ${escapeHtml(m.chal_filename || m.chal_name || "?")}${m.target_url ? ` <small>· target: ${escapeHtml(m.target_url)}</small>` : ""}</div>
        ${m.technique_name ? `<div><b>technique:</b> <code>${escapeHtml(m.technique_name)}</code></div>` : ""}
        ${(bug || m.arch || m.glibc_version) ? `<div><small>${[bug && `bug=${bug}`, m.arch && `arch=${m.arch}`, m.glibc_version && `glibc=${m.glibc_version}`].filter(Boolean).join(" · ")}</small></div>` : ""}
        ${mit ? `<div><small>mit: ${escapeHtml(mit)}</small></div>` : ""}
        ${flagsHtml ? `<div><small>🚩 ${flagsHtml}</small></div>` : ""}
        ${m.notes ? `<div class="exp-notes">${escapeHtml(m.notes)}</div>` : ""}
        ${tagsHtml ? `<div>${tagsHtml}</div>` : ""}
      </div>
      <div class="exp-card-actions">
        <a class="file-preview-link" data-name="${escapeHtml(id)}/report.md" data-url="${API}/exploits/${id}/file/report.md" href="${API}/exploits/${id}/file/report.md">📄 report.md</a>
        ${m.script_filename ? `<a class="file-preview-link" data-name="${escapeHtml(id)}/${escapeHtml(m.script_filename)}" data-url="${API}/exploits/${id}/file/${escapeHtml(m.script_filename)}" href="${API}/exploits/${id}/file/${escapeHtml(m.script_filename)}">🐍 ${escapeHtml(m.script_filename)}</a>` : ""}
        ${m.source_job_id ? `<a href="#" class="exp-jump-job" data-job-id="${escapeHtml(m.source_job_id)}">↗ source job</a>` : ""}
        <button class="exp-del-btn" data-id="${id}">🗑 delete</button>
      </div>
    </li>`;
  }).join("");

  for (const btn of list.querySelectorAll(".exp-del-btn")) {
    btn.addEventListener("click", async () => {
      const eid = btn.dataset.id;
      if (!confirm(`Delete exploit ${eid}? This cannot be undone.`)) return;
      btn.disabled = true;
      const res = await fetch(`${API}/exploits/${eid}`, { method: "DELETE" });
      if (!res.ok) {
        alert(`delete failed: ${res.status} ${await res.text()}`);
        btn.disabled = false;
        return;
      }
      loadExploits();
    });
  }
  for (const a of list.querySelectorAll(".exp-jump-job")) {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      const jid = a.dataset.jobId;
      // selectJob() opens the modal + scrolls. Works even when the
      // row isn't currently rendered (e.g. filtered out / TTL'd).
      try { selectJob(jid); }
      catch (_) { alert(`Source job ${jid} is no longer available.`); }
    });
  }
}

document.getElementById("exp-refresh").addEventListener("click", loadExploits);
document.getElementById("exp-filter-module").addEventListener("change", loadExploits);
{
  let _expSearchTimer = null;
  document.getElementById("exp-filter-search").addEventListener("input", () => {
    clearTimeout(_expSearchTimer);
    _expSearchTimer = setTimeout(loadExploits, 250);
  });
}
document.getElementById("exp-import-file").addEventListener("change", async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const mode = document.getElementById("exp-import-mode").value || "skip";
  const fd = new FormData();
  fd.set("file", file);
  fd.set("mode", mode);
  const status = document.getElementById("exp-status");
  status.textContent = `importing ${file.name}…`;
  const res = await fetch(`${API}/exploits/import`, { method: "POST", body: fd });
  e.target.value = "";  // reset so re-selecting same file fires change
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    alert(`import failed: ${res.status} — ${data.detail || ""}`);
    status.textContent = `import failed (${res.status})`;
    return;
  }
  const c = data.counts || {};
  status.textContent = `imported=${c.imported||0} · skipped=${c.skipped||0} · rejected=${c.rejected||0}`;
  loadExploits();
});

// Load the library on first click of the Exploits tab + on every
// click (cheap; the GET endpoint is just a directory walk).
document.querySelector('.tab[data-tab="exploits"]').addEventListener("click", loadExploits);

document.getElementById("refresh-jobs").addEventListener("click", () => {
  refreshJobs(); refreshStats();
});

document.getElementById("bulk-delete").addEventListener("click", async () => {
  const filter = document.getElementById("bulk-filter").value;
  let url = `${API}/jobs`;
  let label;
  if (filter === "__all__") {
    if (!confirm("Delete ALL jobs (including queued/running)?\nRunning jobs will be cancelled.")) return;
    url += "?all=true";
    label = "ALL jobs";
  } else if (filter === "") {
    if (!confirm("Delete all finished + failed jobs?")) return;
    label = "finished + failed jobs";
  } else {
    if (!confirm(`Delete all jobs with status="${filter}"?`)) return;
    url += `?status=${encodeURIComponent(filter)}`;
    label = `jobs with status=${filter}`;
  }
  const res = await fetch(url, { method: "DELETE" });
  if (!res.ok) {
    alert(`bulk delete failed: ${res.status} ${await res.text()}`);
    return;
  }
  const r = await res.json();
  alert(`Deleted ${r.deleted} ${label}${r.skipped ? ` (skipped ${r.skipped})` : ""}.`);
  if (selectedJob && r.ids && r.ids.includes(selectedJob)) {
    _closeJobModal();
  }
  await refreshJobs();
  await refreshStats();
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await fetch("/logout", { method: "POST" });
  location.href = "/login";
});

// ── Rate-limit chip rendering, shared by Claude, Grok and Codex ────────────
// What an operator wants off a weekly pool is how much is LEFT, so every chip
// leads with that. `remaining_pct` is served for Grok/Codex; for Claude only
// `utilization` (a used fraction) comes back, and the API docs it as
// "frequently absent for OAuth accounts" — hence the status-word fallback
// rather than rendering a confident 0%.
function _rlRemainingLabel(rl) {
  if (typeof rl.remaining_pct === "number") return `${Math.round(rl.remaining_pct)}% left`;
  if (typeof rl.utilization === "number") {
    // utilization can exceed 1 on an overage; clamp so we never say "-40% left".
    return `${Math.round(Math.max(0, 1 - rl.utilization) * 100)}% left`;
  }
  if (rl.status === "rejected") return "limit hit";
  if (rl.status === "allowed_warning") return "near limit";
  return "usage ok";
}

function _rlResetSuffix(rl) {
  if (!rl.resets_at) return "";
  const secs = rl.resets_at - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  // Days matter: both windows are `seven_day`, and the Claude chip used to
  // render a 3-day reset as "87h30m".
  if (d > 0) return ` · resets ${d}d${h}h`;
  if (h > 0) return ` · resets ${h}h${m}m`;
  return ` · resets ${m}m`;
}

function _rlStaleSuffix(rl) {
  if (!rl || !rl.stale) return "";
  let secs = Number(rl.stale_age_seconds);
  if (!Number.isFinite(secs) && rl.updated_at) {
    const observed = Date.parse(rl.updated_at);
    if (Number.isFinite(observed)) secs = (Date.now() - observed) / 1000;
  }
  if (!Number.isFinite(secs) || secs < 0) return " · stale";
  if (secs < 60) return " · stale <1m";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return ` · stale ${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return ` · stale ${hours}h`;
  return ` · stale ${Math.floor(hours / 24)}d`;
}

async function refreshStats() {
  try {
    const [statsRes, queueRes, usageRes] = await Promise.all([
      fetch(`${API}/jobs/stats`),
      fetch(`${API}/jobs/queue`),
      fetch(`${API}/jobs/usage`),
    ]);
    if (statsRes.ok) {
      const s = await statsRes.json();
      const el = document.getElementById("cost-total");
      el.textContent = `$${(s.total_cost_usd || 0).toFixed(3)} · ${s.count} jobs`;
      el.title = "by module: " + Object.entries(s.by_module || {})
        .map(([m, v]) => `${m}=${v.count} ($${v.cost_usd.toFixed(3)})`).join(", ");
    }
    if (queueRes.ok) {
      const q = await queueRes.json();
      const qe = document.getElementById("queue-info");
      qe.textContent = `${q.workers_busy}/${q.workers_total} workers · ${q.queued} queued`;
      qe.title = (q.workers || []).map(w =>
        `${w.name}: ${w.state}${w.job_id ? " (" + w.job_id + ")" : ""}`
      ).join("\n") || "no workers";
    }
    if (usageRes.ok) renderUsage(await usageRes.json());
  } catch (_) {}
}

// Render the operator budget pill + account rate-limit chips from
// GET /api/jobs/usage. Each hides gracefully when there's nothing to show
// (no budget set / no rate-limit event seen yet).
function renderUsage(u) {
  // --- budget pill: "used / budget" with a color by fraction consumed ---
  const pill = document.getElementById("usage-pill");
  if (pill) {
    const inflight0 = (u && u.in_flight_estimate_usd) || 0;
    const spendIncomplete = !!(u && u.spent_usd_complete === false);
    if (u && spendIncomplete) {
      // A reported-dollar subtotal is a lower bound, not a budget position.
      // Showing "$5.96 / $40" here falsely tells the operator the run is
      // bounded when an OAuth-backed main turn has no dollar price at all.
      const known = u.spent_usd || 0;
      const terminalEstimate = u.terminal_unpriced_estimate_usd || 0;
      pill.hidden = false;
      pill.classList.remove("usage-pill--warn", "usage-pill--over");
      pill.textContent = "spend unmeasurable";
      pill.title = `Total dollar spend is unmeasurable: at least one call has no `
        + `authoritative dollar price. Known reported subtotal $${known.toFixed(4)}`
        + (terminalEstimate > 0
            ? `; separate terminal token estimate ~${terminalEstimate.toFixed(4)} USD`
            : "")
        + (inflight0 > 0
            ? `; separate running token estimate ~${inflight0.toFixed(4)} USD`
            : "")
        + ". No remaining-budget or percentage claim is available.";
    } else if (u && u.budget_usd <= 0 && (u.spent_usd > 0 || inflight0 > 0)) {
      // No budget configured. The pill used to hide entirely here, which meant
      // the in-flight estimate shipped invisible on this deployment (no budget
      // is set by default). Show spend without the budget framing.
      pill.hidden = false;
      pill.classList.remove("usage-pill--warn", "usage-pill--over");
      pill.textContent = `$${(u.spent_usd || 0).toFixed(2)} spent`
        + (inflight0 > 0 ? ` +~$${inflight0.toFixed(2)}` : "");
      pill.title = `cumulative spend across all jobs — no operator budget set `
        + `(set one in Settings to get a used/budget bar).`
        + (inflight0 > 0
            ? `\n+~$${inflight0.toFixed(2)} estimated for job(s) still running `
              + `(token-based, runs high).`
            : "");
    } else if (u && u.budget_usd > 0) {
      const spent = u.spent_usd || 0, budget = u.budget_usd;
      const pct = u.pct_used != null ? u.pct_used : (spent / budget * 100);
      pill.hidden = false;
      // A RUNNING job contributes $0 to spent_usd until its ResultMessage
      // lands, so a long job is invisible here for hours. Show its token
      // estimate as a separate "+~$X" suffix — never folded into spent,
      // because the estimate runs high and the budget must stay honest.
      const inflight = u.in_flight_estimate_usd || 0;
      pill.textContent = `$${spent.toFixed(2)} / $${budget.toFixed(0)} (${pct.toFixed(0)}%)`
        + (inflight > 0 ? ` +~$${inflight.toFixed(2)}` : "");
      pill.classList.remove("usage-pill--warn", "usage-pill--over");
      if (pct >= 100) pill.classList.add("usage-pill--over");
      else if (pct >= 80) pill.classList.add("usage-pill--warn");
      const rem = u.remaining_usd != null ? u.remaining_usd : (budget - spent);
      pill.title = `operator budget — spent $${spent.toFixed(4)} of $${budget.toFixed(2)}; `
        + `$${rem.toFixed(2)} left. NOT the Claude account limit.`
        + (inflight > 0
            ? `\n+~$${inflight.toFixed(2)} estimated for job(s) still running `
              + `(token-based, runs high; excluded from the budget maths).`
            : "");
    } else {
      pill.hidden = true;  // no budget configured
    }
  }
  // --- Claude rate-limit status chip: green/amber/red + "resets in HH:MM" ---
  // All provider chips render through the two helpers above so they cannot
  // drift apart again: the Claude chip used to APPEND `utilization` as a used
  // percentage while the Grok chip showed remaining, so the same 0.37 read as
  // "37%" on one and "63% left" on the other — opposite meanings, same number,
  // side by side in the same bar.
  const chip = document.getElementById("ratelimit-chip");
  if (chip) {
    const rl = u && u.rate_limit;
    if (rl && rl.status && rl.status !== "unknown") {
      chip.hidden = false;
      chip.classList.remove("rl-chip--ok", "rl-chip--warn", "rl-chip--rejected");
      if (rl.status === "rejected") chip.classList.add("rl-chip--rejected");
      else if (rl.stale || rl.status === "allowed_warning") chip.classList.add("rl-chip--warn");
      else chip.classList.add("rl-chip--ok");
      const claudeUsageIcon = rl.stale ? "⚠" : "⏳";
      chip.textContent = `${claudeUsageIcon} Claude ${_rlRemainingLabel(rl)}`
        + `${_rlResetSuffix(rl)}${_rlStaleSuffix(rl)}`;
      const windows = (rl.windows || []).map((w) => {
        const label = w.label || w.rate_limit_type || w.kind || "Claude";
        const reset = w.resets_at
          ? `, resets ${new Date(w.resets_at * 1000).toLocaleString()}` : "";
        return `${label}: ${Math.round(w.remaining_pct)}% left${reset}`;
      }).join("\n");
      chip.title = `Claude rate-limit: ${rl.status}`
        + (rl.rate_limit_type ? ` (${rl.rate_limit_type})` : "")
        + (rl.subscription_type ? ` · ${rl.subscription_type}` : "")
        + (typeof rl.used_pct === "number"
            ? `\nused ${rl.used_pct}%` : "")
        + (typeof rl.remaining_pct === "number"
            ? ` · ${rl.remaining_pct}% remaining` : "")
        + (windows ? `\n${windows}` : "")
        + (rl.resets_at ? `\nresets at ${new Date(rl.resets_at * 1000).toLocaleString()}` : "")
        + (rl.updated_at ? `\nlast poll ${new Date(rl.updated_at).toLocaleString()}` : "")
        // WHY it is cached, when the module says why. "refresh unavailable"
        // sent the last investigation looking at the network; the actual
        // cause was a container mount pointing at an empty directory.
        + (rl.stale
            ? "\nshowing cached data — "
              + (rl.stale_reason || "refresh unavailable")
            : "");
    } else {
      chip.hidden = true;  // no rate-limit event seen yet
    }
  }

  // --- Grok SuperGrok weekly pool chip (remaining %) ---
  // Source: GET /api/jobs/usage → grok_rate_limit (cli-chat-proxy billing
  // poll, needs grok login OAuth). Hides when no auth / no data yet.
  const gchip = document.getElementById("grok-ratelimit-chip");
  if (gchip) {
    const gr = u && u.grok_rate_limit;
    if (gr && gr.status && gr.status !== "unknown") {
      gchip.hidden = false;
      gchip.classList.remove("rl-chip--ok", "rl-chip--warn", "rl-chip--rejected");
      if (gr.status === "rejected") gchip.classList.add("rl-chip--rejected");
      else if (gr.stale || gr.status === "allowed_warning") gchip.classList.add("rl-chip--warn");
      else gchip.classList.add("rl-chip--ok");
      const grokUsageIcon = gr.stale ? "⚠" : "⏳";
      gchip.textContent = `${grokUsageIcon} Grok ${_rlRemainingLabel(gr)}`
        + `${_rlResetSuffix(gr)}${_rlStaleSuffix(gr)}`;
      const prod = (gr.product_usage || [])
        .map((p) => `${p.product || "?"}: ${Math.round(p.usage_percent || 0)}%`)
        .join(", ");
      gchip.title = `Grok weekly pool: ${gr.status}`
        + (gr.rate_limit_type ? ` (${gr.rate_limit_type})` : "")
        + (typeof gr.used_pct === "number" ? `\nused ${gr.used_pct}%` : "")
        + (typeof gr.remaining_pct === "number" ? ` · ${gr.remaining_pct}% remaining` : "")
        + (prod ? `\nby product: ${prod}` : "")
        + (gr.resets_at ? `\nresets at ${new Date(gr.resets_at * 1000).toLocaleString()}` : "")
        + (gr.updated_at ? `\nlast poll ${new Date(gr.updated_at).toLocaleString()}` : "")
        + (gr.stale ? "\nshowing cached data (refresh unavailable)" : "");
    } else {
      gchip.hidden = true;
    }
  }

  // --- OpenAI Codex ChatGPT OAuth usage chip (remaining %) ---
  // Source: Codex CLI app-server account/rateLimits/read. The API caches the
  // sanitized response for 15 seconds; no OAuth token reaches this payload.
  const cchip = document.getElementById("codex-ratelimit-chip");
  if (cchip) {
    const cr = u && u.codex_rate_limit;
    if (cr && cr.status && cr.status !== "unknown") {
      cchip.hidden = false;
      cchip.classList.remove("rl-chip--ok", "rl-chip--warn", "rl-chip--rejected");
      if (cr.status === "rejected") cchip.classList.add("rl-chip--rejected");
      else if (cr.stale || cr.status === "allowed_warning") cchip.classList.add("rl-chip--warn");
      else cchip.classList.add("rl-chip--ok");
      const codexUsageIcon = cr.stale ? "⚠" : "⏳";
      cchip.textContent = `${codexUsageIcon} Codex ${_rlRemainingLabel(cr)}`
        + `${_rlResetSuffix(cr)}${_rlStaleSuffix(cr)}`;
      const windows = (cr.windows || []).map((w) => {
        const label = w.limit_name || w.limit_id || "Codex";
        const reset = w.resets_at
          ? `, resets ${new Date(w.resets_at * 1000).toLocaleString()}` : "";
        return `${label} ${w.window || "window"}: ${Math.round(w.remaining_pct)}% left${reset}`;
      }).join("\n");
      cchip.title = `Codex ChatGPT OAuth: ${cr.status}`
        + (cr.plan_type ? ` (${cr.plan_type})` : "")
        + (typeof cr.used_pct === "number" ? `\nused ${cr.used_pct}%` : "")
        + (typeof cr.remaining_pct === "number" ? ` · ${cr.remaining_pct}% remaining` : "")
        + (windows ? `\n${windows}` : "")
        + (cr.updated_at ? `\nlast poll ${new Date(cr.updated_at).toLocaleString()}` : "")
        + (cr.stale ? "\nshowing cached data (refresh unavailable)" : "");
    } else {
      cchip.hidden = true;
    }
  }
}

async function deleteJob(id, ev) {
  ev.stopPropagation();
  if (!confirm(`Delete job ${id}?`)) return;
  await fetch(`${API}/jobs/${id}`, { method: "DELETE" });
  if (selectedJob === id) {
    _closeJobModal();
  }
  refreshJobs();
  refreshStats();
}

// Pure stop — halt a running/queued job but KEEP it (record + ./work/). Unlike
// deleteJob (removes the job) and stop-&-resume (forks a fresh job), this just
// flips status to 'stopped'. Re-renders the detail so the operator sees the
// stopped pill and can then retry / run / delete at their leisure.
async function stopJob(id, btn) {
  if (!confirm(`Stop job ${id}?\nHalts the run but KEEPS the job and ./work/ artifacts (not deleted, not resumed).`)) return;
  const orig = btn ? btn.textContent : null;
  if (btn) { btn.disabled = true; btn.textContent = "■ stopping…"; }
  try {
    const res = await fetch(`${API}/jobs/${id}/stop`, { method: "POST" });
    if (!res.ok) {
      alert(`stop failed: ${res.status} ${await res.text()}`);
      if (btn) { btn.disabled = false; btn.textContent = orig; }
      return;
    }
    await refreshJobs();
    await selectJob(id);
    refreshStats();
  } catch (e) {
    alert(`stop error: ${e}`);
    if (btn) { btn.disabled = false; btn.textContent = orig; }
  }
}


// (Re)paint the "reviewer in progress" panel for `jobId` from its
// activeReviewers entry. Idempotent: creates the panel if absent, updates
// it in place otherwise (cheap on every streamed token). No-ops when this
// job's detail isn't the one on screen — the state persists in the map and
// is restored the next time renderJob() rebuilds the detail (selectJob →
// this is called just before renderJob returns). This is what makes the
// panel survive navigating away and back.
function renderReviewerPanel(jobId) {
  const detail = document.getElementById("job-detail");
  if (!detail) return;
  if (selectedJob !== jobId) return;
  const st = activeReviewers.get(jobId);
  let panel = document.getElementById("retry-panel-" + jobId);
  if (!st) { if (panel) panel.remove(); return; }

  if (!panel) {
    panel = document.createElement("div");
    panel.className = "retry-panel";
    panel.id = "retry-panel-" + jobId;
    panel.innerHTML =
      "<h4></h4>"
      + '<div class="stage"><span class="dot"></span><span class="stage-text"></span></div>'
      + '<pre class="hint-stream"></pre>';
    // Same insertion point streamRetry used: above the flag banner /
    // file-links / first heading in the detail.
    const refNode = detail.querySelector(".flag-banner")
      || detail.querySelector(".file-links")
      || detail.querySelector("h4");
    if (refNode && refNode.parentNode) refNode.parentNode.insertBefore(panel, refNode);
    else detail.appendChild(panel);
  }

  const label = st.flow === "resume" ? "Resume" : "Retry";
  const headerEl = panel.querySelector("h4");
  const stageEl = panel.querySelector(".stage-text");
  const streamEl = panel.querySelector(".hint-stream");
  const dot = panel.querySelector(".dot");

  panel.classList.toggle("retry-panel-error", st.status === "error");
  dot.classList.toggle("dot--error", st.status === "error");
  dot.classList.toggle("dot--done", st.status === "done");
  if (st.status === "error") {
    headerEl.textContent = `${st.flowEmoji} ${label} — error (no new job created)`;
  } else if (st.status === "done") {
    headerEl.textContent = `${st.flowEmoji} ${label} — ${st.isManual ? "your hint" : "reviewer"} submitted`;
  } else {
    headerEl.textContent = st.isManual
      ? `${st.flowEmoji} ${label} — your hint`
      : `${st.flowEmoji} ${label} — reviewer in progress`;
  }
  stageEl.textContent = st.stageText || "";

  const atBottom = streamEl.scrollTop + streamEl.clientHeight >= streamEl.scrollHeight - 8;
  const newText = (st.text != null && st.text !== "")
    ? st.text
    : (st.isManual ? "" : "(awaiting reviewer output…)");
  if (streamEl.textContent !== newText) streamEl.textContent = newText;
  if (atBottom) streamEl.scrollTop = streamEl.scrollHeight;

  // While the stream is live, keep every retry path disabled so a second
  // submit can't race it. A fresh renderJob() rebuilds the buttons enabled;
  // this re-disables them in the same tick. Terminal/absent entry leaves
  // them enabled.
  const running = st.status === "running";
  detail.querySelectorAll(
    ".retry-btn, .retry-manual-submit, .stop-resume-submit",
  ).forEach((b) => { b.disabled = running; });
}

async function streamRetry(jobId, btn, manualHint = null, opts = {}) {
  // Endpoint can be /retry/stream (default) or /resume/stream — same SSE
  // protocol either way, only the stage labels differ.
  const endpoint = opts.endpoint || `${API}/jobs/${jobId}/retry/stream`;
  const flow = opts.flow || "retry";   // "retry" | "resume"
  const flowVerb = flow === "resume" ? "resume" : "retry";
  const flowEmoji = flow === "resume" ? "✋" : "↻";
  const isManual = typeof manualHint === "string" && manualHint.length > 0;

  // Stop the regular polling so it doesn't fight our progress panel
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }

  // Tear down any in-flight inline form so it doesn't linger.
  const manualForm = document.getElementById("retry-manual-form-" + jobId);
  if (manualForm) manualForm.remove();
  const resumeForm = document.getElementById("stop-resume-form-" + jobId);
  if (resumeForm) resumeForm.remove();

  // Seed the PERSISTENT state + paint. From here the panel is rebuilt from
  // activeReviewers by renderReviewerPanel(), so navigating away and back
  // restores it instead of losing the "reviewer in progress" UI.
  activeReviewers.set(jobId, {
    flow, flowEmoji, flowVerb, isManual,
    stageText: isManual ? "submitting…" : "starting…",
    text: isManual ? manualHint : "",
    firstToken: !isManual,
    status: "running",
  });
  const origText = btn.textContent;
  btn.textContent = `⏳ ${flowVerb}…`;
  renderReviewerPanel(jobId);

  const setError = (kind, message) => {
    const st = activeReviewers.get(jobId);
    if (!st) return;
    st.status = "error";
    st.kind = kind;
    const kindLabel = ({
      api_error: "API error",
      auth: "auth error",
      rate_limit: "rate limit",
      policy_refusal: "usage-policy refusal",
      timeout: "timeout",
      empty: "empty response",
      no_context: "no prior context",
      gather: "context gather failed",
      halt: "stop failed",
      submit: "submit rejected",
      stream_closed: "stream closed",
      unknown: "unknown error",
    })[kind] || kind;
    st.stageText = `${kindLabel} — ${flowVerb} aborted`;
    const em = (message || "unknown error").trim();
    // Keep any partial reviewer text as forensic context above the error.
    st.text = st.firstToken ? em : `${st.text}\n\n--- ${kindLabel} ---\n${em}`;
    st.firstToken = false;
    renderReviewerPanel(jobId);
  };

  // EventSource only supports GET. Use fetch + ReadableStream to POST + stream.
  // Body fields are all optional from the server's POV: hint (manual mode
  // only) and target (always optional, blank = keep prior target).
  const targetOverride = (typeof opts.target === "string" && opts.target.trim())
    ? opts.target.trim() : null;
  const body = {};
  if (isManual) body.hint = manualHint;
  if (targetOverride) body.target = targetOverride;
  // fresh = start the retry WITHOUT forking the prior SDK conversation
  // (carried files + hint only). Defends against retry-fork-chain context
  // overflow ("Prompt is too long") on deep chains. Operator-selected.
  if (opts.fresh) body.fresh = true;
  if (opts.secretValue) {
    body.challenge_secret_key = "CTFD_ACCESS_TOKEN";
    body.challenge_secret_value = opts.secretValue;
  }
  const fetchOpts = { method: "POST" };
  if (Object.keys(body).length) {
    fetchOpts.headers = { "Content-Type": "application/json" };
    fetchOpts.body = JSON.stringify(body);
  }

  let resp;
  try {
    resp = await fetch(endpoint, fetchOpts);
  } catch (e) {
    setError("error", String(e));
    btn.textContent = origText;
    return;
  }
  if (!resp.ok) {
    const errBody = await resp.text().catch(() => "");
    setError("error", `${resp.status}: ${errBody}`);
    btn.textContent = origText;
    return;
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buf = "";

  function handleEvent(name, dataStr) {
    let data = {};
    try { data = JSON.parse(dataStr); } catch (_) {}
    const st = activeReviewers.get(jobId);
    if (!st) return;  // entry cleared (e.g. a newer retry replaced it)
    if (name === "stage") {
      const s = data.name;
      // The backend sends the resolved reviewer model (resolve_reviewer_model:
      // per-job meta.model → global claude_model → opus-4-7) so this shows the
      // ACTUAL model, not a hardcoded label.
      const reviewerModel = data.model || "reviewer";
      st.stageText = ({
        halting: "halting current job…",
        gathering: "gathering prior job context…",
        asking: `asking reviewer (${reviewerModel})…`,
        submitting: isManual
          ? (flow === "resume"
              ? "enqueueing fresh job (carrying ./work/) with your hint…"
              : "enqueueing new job with your hint…")
          : (flow === "resume"
              ? "enqueueing fresh job (carrying ./work/)…"
              : "enqueueing new job…"),
      })[s] || s;
      renderReviewerPanel(jobId);
    } else if (name === "token") {
      if (st.firstToken) { st.text = ""; st.firstToken = false; }
      st.text += data.delta || "";
      renderReviewerPanel(jobId);
    } else if (name === "done") {
      st.status = "done";
      st.newJobId = data.new_job_id;
      st.stageText = `submitted new job ${data.new_job_id}`;
      btn.textContent = origText;
      renderReviewerPanel(jobId);
      const newId = data.new_job_id;
      // Switch to the new job after a beat so user can read the hint — but
      // only if they're still on the job they launched the retry from; don't
      // yank them out of a different job they navigated to meanwhile.
      setTimeout(async () => {
        activeReviewers.delete(jobId);
        await refreshJobs();
        if (selectedJob === jobId && newId) await selectJob(newId);
        else renderReviewerPanel(jobId);  // clears the now-deleted panel
      }, 800);
    } else if (name === "error") {
      setError(data.kind || "error", data.message);
      btn.textContent = origText;
    }
  }

  // Converge EVERY loop-exit path to a terminal state. A stream that dies
  // WITHOUT delivering a done/error frame (api redeploy mid-stream, dropped
  // connection — the 73d78c failure) would otherwise leave a "running"
  // entry that the map now PERSISTS as a perpetual spinner on every
  // re-entry — strictly worse than the original disappearing-panel bug.
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      // SSE frames are separated by blank lines
      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        let evName = "message";
        let dataLines = [];
        for (const line of frame.split("\n")) {
          if (line.startsWith("event: ")) evName = line.slice(7).trim();
          else if (line.startsWith("data: ")) dataLines.push(line.slice(6));
        }
        if (dataLines.length) handleEvent(evName, dataLines.join("\n"));
      }
    }
  } catch (_) {
    // network / stream error — fall through to the terminal-state check.
  }
  // Stream closed with no done/error event → mark it terminal so it can't
  // re-render as an eternal spinner.
  const tail = activeReviewers.get(jobId);
  if (tail && tail.status === "running") {
    setError("stream_closed", "stream ended without completion");
    btn.textContent = origText;
  }
}

function openStopResumeForm(jobId, anchorBtn) {
  // If a form is already open for this job, just refocus it.
  const existing = document.getElementById("stop-resume-form-" + jobId);
  if (existing) {
    existing.querySelector("textarea")?.focus();
    return;
  }
  const form = document.createElement("div");
  form.className = "retry-manual-form stop-resume-form";
  form.id = "stop-resume-form-" + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Extra hint to add before resuming</label>
    <textarea rows="5" placeholder="What should the next attempt do differently? e.g. 'the leaked endpoint is /api/v2/profile, not /profile' — appended to the new job's description as [retry-hint]"></textarea>
    <label class="retry-manual-label" style="margin-top:0.4rem">Target (override; blank = keep prior, "(none)" = clear · <b>+ add target</b> for several)</label>
    ${targetListHtml("e.g. http://newhost:8080  ·  ctf.example.com:31337")}
    ${challengeSecretHtml()}
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit stop-resume-submit">✋ Stop &amp; resume</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Halts this job, then enqueues a fresh one with the same files + hint appended</small>
    </div>
  `;
  const buttonRow = anchorBtn.parentElement;
  buttonRow.insertAdjacentElement("afterend", form);

  const ta = form.querySelector("textarea");
  const submit = form.querySelector(".stop-resume-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  ta.focus();

  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", async () => {
    const hint = ta.value.trim();
    const secretValue = form.querySelector(".challenge-secret-value")?.value.trim() || "";
    if (!hint && !secretValue) {
      ta.focus();
      ta.classList.add("invalid");
      setTimeout(() => ta.classList.remove("invalid"), 600);
      return;
    }
    submit.disabled = true;
    cancel.disabled = true;
    const orig = submit.textContent;
    submit.textContent = "⏳ stopping & resuming…";
    // Stop polling so it doesn't fight the upcoming selectJob call.
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    try {
      const reqBody = { hint: hint || "Challenge credential supplied through the dedicated secret ingress." };
      appendChallengeSecret(form, reqBody);
      const t = gatherTargets(form);
      if (t) reqBody.target = t;
      const freshCb = document.getElementById(`fresh-ctx-${jobId}`);
      if (freshCb && freshCb.checked) reqBody.fresh = true;
      const res = await fetch(`${API}/jobs/${jobId}/resume`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqBody),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail || body);
        alert(`stop-and-resume failed: ${res.status} ${detail}`);
        submit.disabled = false; cancel.disabled = false;
        submit.textContent = orig;
        return;
      }
      form.remove();
      await refreshJobs();
      await selectJob(body.new_job_id);
    } catch (e) {
      alert(`stop-and-resume error: ${e}`);
      submit.disabled = false; cancel.disabled = false;
      submit.textContent = orig;
    }
  });
  for (const el of [ta]) {
    el.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        submit.click();
      } else if (e.key === "Escape") {
        e.preventDefault();
        form.remove();
      }
    });
  }
}

function openManualHintForm(jobId, anchorBtn) {
  // If a form is already open for this job, just refocus it.
  const existing = document.getElementById("retry-manual-form-" + jobId);
  if (existing) {
    existing.querySelector("textarea")?.focus();
    return;
  }
  const form = document.createElement("div");
  form.className = "retry-manual-form";
  form.id = "retry-manual-form-" + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Your hint for the next agent</label>
    <textarea rows="5" placeholder="e.g. The bot visits /report?id= and the cookie is on .site.com — exfiltrate via document.cookie to \$COLLECTOR_URL. Or: the heap leak comes from the formatted error on /api/echo, not /api/profile."></textarea>
    <label class="retry-manual-label" style="margin-top:0.4rem">Target (override; blank = keep prior, "(none)" = clear · <b>+ add target</b> for several)</label>
    ${targetListHtml("e.g. http://newhost:8080  ·  ctf.example.com:31337")}
    ${challengeSecretHtml()}
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit">Submit hint &amp; retry</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Skips reviewer · appended to new job's description as <code>[retry-hint]</code></small>
    </div>
  `;
  // Place the form right after the button row.
  const buttonRow = anchorBtn.parentElement;
  buttonRow.insertAdjacentElement("afterend", form);

  const ta = form.querySelector("textarea");
  const submit = form.querySelector(".retry-manual-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  ta.focus();

  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", () => {
    const hint = ta.value.trim();
    const secretValue = form.querySelector(".challenge-secret-value")?.value.trim() || "";
    if (!hint && !secretValue) {
      ta.focus();
      ta.classList.add("invalid");
      setTimeout(() => ta.classList.remove("invalid"), 600);
      return;
    }
    const freshCb = document.getElementById(`fresh-ctx-${jobId}`);
    streamRetry(
      jobId,
      submit,
      hint || "Challenge credential supplied through the dedicated secret ingress.",
      {
      target: gatherTargets(form),
      fresh: !!(freshCb && freshCb.checked),
      secretValue,
      },
    );
  });
  // Ctrl/Cmd+Enter shortcut
  for (const el of [ta]) {
    el.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        submit.click();
      } else if (e.key === "Escape") {
        e.preventDefault();
        form.remove();
      }
    });
  }
}

// Continue-in-place form: an operator note (folded into the SAME job's
// session as priority guidance) + optional new target (a restarted DreamHack
// instance often comes back on a new port). NOT a retry — same job/cwd/session.
function openContinueForm(jobId, anchorBtn) {
  const existing = document.getElementById("continue-form-" + jobId);
  if (existing) { existing.querySelector("textarea")?.focus(); return; }
  const form = document.createElement("div");
  form.className = "retry-manual-form continue-form";
  form.id = "continue-form-" + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Operator note (the agent CONTINUES the same session — no re-investigation)</label>
    <textarea rows="4" placeholder="e.g. I restarted the instance — the one-shot resource you were waiting on is available again. Run your existing exploit in one shot; don't probe."></textarea>
    <label class="retry-manual-label" style="margin-top:0.4rem">New target (blank = keep prior; a restarted instance usually has a new port · <b>+ add target</b> for several)</label>
    ${targetListHtml("e.g. http://host8.dreamhack.games:NEWPORT")}
    ${challengeSecretHtml()}
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit continue-submit">💬 Continue with note</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Same job · resumes the session · note added as <code>[retry-hint]</code></small>
    </div>
  `;
  anchorBtn.parentElement.insertAdjacentElement("afterend", form);
  const ta = form.querySelector("textarea");
  const submit = form.querySelector(".continue-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  ta.focus();
  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", async () => {
    const comment = ta.value.trim();
    const secretValue = form.querySelector(".challenge-secret-value")?.value.trim() || "";
    if (!comment && !secretValue) {
      ta.focus(); ta.classList.add("invalid");
      setTimeout(() => ta.classList.remove("invalid"), 600);
      return;
    }
    submit.disabled = true;
    submit.textContent = "Continuing…";
    try {
      const body = { comment };
      appendChallengeSecret(form, body);
      const _tg = gatherTargets(form);
      if (_tg) body.target = _tg;
      const res = await fetch(`${API}/jobs/${jobId}/continue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) { alert(`continue error: ${res.status} ${await res.text()}`); submit.disabled = false; submit.textContent = "💬 Continue with note"; return; }
      form.remove();
      await refreshJobs();
      selectJob(jobId);
    } catch (e) {
      alert(`continue failed: ${e}`);
      submit.disabled = false; submit.textContent = "💬 Continue with note";
    }
  });
  for (const el of [ta]) {
    el.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); submit.click(); }
      else if (e.key === "Escape") { e.preventDefault(); form.remove(); }
    });
  }
}


// One click out of a hold. It posts the SAME /continue the dialog posts --
// "continue in place, keep the work tree and the SDK session, inject a note"
// is already exactly the semantics a hold needs, and that route is the tested
// one. What this removes is the typing, not a step.
async function resumeHeldJob(jobId, btn) {
  const where = decodeURIComponent(btn.dataset.target || "");
  // The note is what the agent actually wakes up to, so it says what changed
  // and what NOT to do: a held run still has its findings, and re-deriving
  // them is the expensive failure mode here.
  const note = "[operator] The remote target is answering again"
    + (where ? ` at ${where}` : "")
    + ". This run was HELD because the previous instance stopped responding."
    + " Your work tree and your session are intact — do NOT re-investigate from"
    + " scratch. Re-point at this address and continue from where you were held.";
  const was = btn.textContent;
  btn.disabled = true;
  btn.textContent = "재개 중…";
  try {
    const res = await fetch(`${API}/jobs/${jobId}/continue`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // No `target` key on purpose. Omitting it keeps meta.target_url, which
      // is what Change target already wrote; sending the value this panel
      // happens to be showing would let a stale tab overwrite a newer address.
      body: JSON.stringify({ comment: note }),
    });
    if (!res.ok) {
      alert(`resume error: ${res.status} ${await res.text()}`);
      btn.disabled = false;
      btn.textContent = was;
      return;
    }
    await refreshJobs();
    selectJob(jobId);
  } catch (e) {
    alert(`resume failed: ${e}`);
    btn.disabled = false;
    btn.textContent = was;
  }
}

// Short two-note chirp via WebAudio (no asset). Autoplay policy may
// suspend the context until the first user gesture — the visual toast
// always shows regardless; the beep just catches up once the page has
// been interacted with.
let _flagBeepAt = 0;             // last beep, for the burst throttle below

function _flagBeep() {
  // One pass can now legitimately raise several toasts (that is the fix —
  // every fresh value alarms, not just the last). Without this guard those
  // would start N overlapping oscillators in the same audio frame and stack
  // into one loud blast. The toasts are all still shown; only the sound is
  // coalesced.
  const now = Date.now();
  if (now - _flagBeepAt < 1200) return;
  _flagBeepAt = now;
  try {
    _flagAudioCtx = _flagAudioCtx ||
      new (window.AudioContext || window.webkitAudioContext)();
    const ctx = _flagAudioCtx;
    if (ctx.state === "suspended") ctx.resume();
    const t = ctx.currentTime;
    [0, 0.18].forEach((dt, i) => {
      const o = ctx.createOscillator();
      const g = ctx.createGain();
      o.type = "sine";
      o.frequency.value = i === 0 ? 880 : 1320;
      g.gain.setValueAtTime(0.0001, t + dt);
      g.gain.exponentialRampToValueAtTime(0.25, t + dt + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t + dt + 0.15);
      o.connect(g);
      g.connect(ctx.destination);
      o.start(t + dt);
      o.stop(t + dt + 0.16);
    });
  } catch (_) { /* no WebAudio / autoplay-blocked — visual toast still shows */ }
}

function _flagToastContainer() {
  let c = document.getElementById("flag-toast-container");
  if (!c) {
    c = document.createElement("div");
    c.id = "flag-toast-container";
    document.body.appendChild(c);
  }
  return c;
}

// kind: "flag" (promoted 🚩) | "cand" ([FLAG?] candidate)
function _showFlagToast(kind, job, text) {
  const c = _flagToastContainer();
  const el = document.createElement("div");
  el.className = "flag-toast " + kind;
  const isFlag = kind === "flag";
  const icon = isFlag ? "🚩" : "🏁";
  const title = isFlag ? "FLAG FOUND" : "[FLAG?] candidate";
  const mod = escapeHtml(job.module || "job");
  const sid = escapeHtml(String(job.id || "").slice(0, 12));
  el.innerHTML =
    `<button class="flag-toast-x" title="dismiss">×</button>` +
    `<div class="flag-toast-h">${icon} <strong>${title}</strong></div>` +
    `<div class="flag-toast-sub">${mod} · <span class="flag-toast-id">${sid}</span></div>` +
    (text ? `<div class="flag-toast-body"><code>${escapeHtml(text)}</code></div>` : "");
  el.addEventListener("click", (e) => {
    if (e.target.closest(".flag-toast-x")) return;
    selectJob(job.id);
    el.remove();
  });
  el.querySelector(".flag-toast-x").addEventListener("click", (e) => {
    e.stopPropagation();
    el.remove();
  });
  c.appendChild(el);
  // STICKY: both FLAG FOUND and [FLAG?] candidate toasts persist until the
  // operator acknowledges them — clicking the toast (opens the job) or the ×
  // removes it. No auto-fade: a flag / candidate must never silently vanish
  // before it has been seen (operator request 2026-06-17). Pile-up is bounded
  // by per-candidate dedup in _detectFlagTransitions + the container's
  // max-height scroll (style.css).
  _flagBeep();
  // OS-level notification too — but only if already granted; never auto-prompt.
  // Clicking it focuses the tab AND opens the job, same as the in-page toast.
  try {
    if (window.Notification && Notification.permission === "granted") {
      const n = new Notification(`${icon} ${title} — ${mod}`,
        // requireInteraction keeps the OS notification on screen until the
        // operator dismisses/clicks it (supported browsers) — mirrors the
        // sticky in-page toast so a flag isn't lost to an auto-timeout.
        { body: text || sid, tag: "flag-" + job.id, requireInteraction: true });
      n.onclick = () => {
        try { window.focus(); } catch (_) {}
        selectJob(job.id);
        n.close();
      };
    }
  } catch (_) {}
}

// A patch version is news the way a flag is, but it is not the same KIND of
// news. A flag is the end of a job and must never scroll past unseen, so its
// toast is sticky. A patch version is one of several a live-fire job will
// publish on a short tick — the operator wants to know a new bundle is
// downloadable, not to dismiss a pile of dialogs mid-contest. So this one
// fades, and the version history panel is the durable record.
function _showPatchToast(job, versions, cleared) {
  const c = _flagToastContainer();
  const el = document.createElement("div");
  el.className = "flag-toast patch";
  const mod = escapeHtml(job.module || "job");
  const sid = escapeHtml(String(job.id || "").slice(0, 12));
  const tag = escapeHtml(String(job.tag || "").slice(0, 40));
  const clearText = Number.isFinite(cleared) && cleared > 0
    ? `${cleared} vuln clear` : "new bundle";
  el.innerHTML =
    `<button class="flag-toast-x" title="dismiss">×</button>` +
    `<div class="flag-toast-h">📦 <strong>패치 V${versions}</strong></div>` +
    `<div class="flag-toast-sub">${mod} · <span class="flag-toast-id">${
      tag || sid}</span></div>` +
    `<div class="flag-toast-body"><code>${escapeHtml(clearText)}</code></div>`;
  el.addEventListener("click", (e) => {
    if (e.target.closest(".flag-toast-x")) return;
    selectJob(job.id);
    el.remove();
  });
  el.querySelector(".flag-toast-x").addEventListener("click", (e) => {
    e.stopPropagation();
    el.remove();
  });
  c.appendChild(el);
  _flagBeep();
  setTimeout(() => {
    el.classList.add("leaving");
    setTimeout(() => el.remove(), 400);
  }, 12000);
  try {
    if (window.Notification && Notification.permission === "granted") {
      const n = new Notification(`📦 패치 V${versions} — ${mod}`,
        // Deliberately left off — unlike a flag, another version is coming.
        { body: `${clearText} · ${tag || sid}`, tag: "lfpatch-" + job.id });
      n.onclick = () => {
        try { window.focus(); } catch (_) {}
        selectJob(job.id);
        n.close();
      };
    }
  } catch (_) { /* notifications are a bonus, never a dependency */ }
}

const _patchSeen = Object.create(null);
let _patchAlarmReady = false;

// Same shape as the flag detector and driven from the same poll: compare
// against what was already seen, and seed the baseline on the first pass so
// opening the page does not alarm for every version a finished job has.
function _detectPatchTransitions(jobs) {
  for (const job of jobs || []) {
    if (!job || !job.id) continue;
    const versions = Number(job.live_fire_versions) || 0;
    if (!versions) continue;
    const seen = _patchSeen[job.id] || 0;
    if (versions > seen && _patchAlarmReady) {
      _showPatchToast(job, versions, Number(job.live_fire_integrated));
    }
    if (versions > seen) _patchSeen[job.id] = versions;
  }
  _patchAlarmReady = true;
}

function _detectFlagTransitions(jobs) {
  for (const job of jobs || []) {
    if (!job || !job.id) continue;
    let seen = _flagSeen[job.id];
    if (!seen) {
      seen = { flags: new Set(), cands: new Set() };
      _flagSeen[job.id] = seen;
    }
    const flags = job.flags || [];
    // Candidates already promoted to real flags are not candidates any more —
    // same rule the [FLAG?] box uses, so the alarm and the box agree.
    const cands = (job.flag_candidates || []).filter((x) => !flags.includes(x));
    // Tracked per KIND, so a value that was alarmed as a candidate alarms once
    // more when it is promoted to a flag. Promotion is news; a re-poll is not.
    const freshFlags = flags.filter((v) => v && !seen.flags.has(v));
    const freshCands = cands.filter((v) => v && !seen.cands.has(v));
    if (_flagAlarmReady) {
      for (const v of freshFlags) _showFlagToast("flag", job, v);
      for (const v of freshCands) _showFlagToast("cand", job, v);
    }
    for (const v of freshFlags) seen.flags.add(v);
    for (const v of freshCands) seen.cands.add(v);
  }
  _flagAlarmReady = true;   // baseline seeded after the first pass
}

async function refreshJobs() {
  const res = await fetch(`${API}/jobs`);
  const data = await res.json();
  _detectFlagTransitions(data.jobs);
  _detectPatchTransitions(data.jobs);
  const ul = document.getElementById("jobs-list");
  // RECONCILED, NOT REBUILT. `ul.innerHTML = ""` here blinked the entire job
  // list every seven seconds, from the global heartbeat, whether or not a
  // detail panel was open — and a row's own content changes while its job
  // runs, so it was visibly redrawn each time. The detail panels were taught
  // to patch themselves row by row; this list, which is on screen the whole
  // time, never was.
  const alive = new Set();
  let _slot = 0;
  for (const job of data.jobs) {
    alive.add(job.id);
    let li = ul.querySelector(
      `li[data-id="${(window.CSS && CSS.escape) ? CSS.escape(job.id) : job.id}"]`);
    const fresh = !li;
    if (fresh) li = document.createElement("li");
    li.dataset.id = job.id;
    // OUT OF THE SIGNATURE. A running job's cost moves on every poll, so
    // leaving it in the row's markup rewrote that row — and every node in it —
    // every seven seconds. It is a text node of its own now.
    const costText = job.cost_usd ? `· $${Number(job.cost_usd).toFixed(3)}` : "";
    const cost = `<span class="row-cost"></span>`;
    // HOW the flag was obtained, not just that there is one. `marker` means the
    // solver printed `FLAG_CANDIDATE: <flag>` — it declared that exact string as
    // its capture. `runner_regex` means only that a flag-SHAPED string appeared
    // somewhere in the runner's output; nobody declared anything. Job
    // 0c04e636633c shipped its solver's own diagnostic banner that way, and this
    // pill was indistinguishable from a real capture. Promotes and drops
    // nothing — curation stays MANUAL; it just stops the two looking alike.
    // `flag_sweep_suppressed` OVERRIDES the tier note and must be checked
    // first. When the runner printed a flag-shaped string and the same output
    // then declared failure, the scanner drops it and the NARRATIVE tier can
    // re-find the string in report.md — leaving provenance honestly
    // "narrative", whose note claims the runner's output does not contain it.
    // It does. Two different facts; show the one that is not misleading.
    const provNote = job.flag_sweep_suppressed
      ? "\n\n⚑ The runner's own output DID contain this string — and the same output declares it found nothing. Dropped from the trusted tier; whatever promoted this flag was something else."
      : ({
          runner_regex: "\n\n⚑ SWEPT, not declared — the solver printed no `FLAG_CANDIDATE:` marker, so nothing asserts this IS the flag; only that it is flag-shaped.",
          narrative: "\n\n⚑ From the agent's report.md / findings.json only — the runner's own stdout/stderr does not contain it.",
        }[job.flag_provenance] || "");
    const flagPill = (job.flags && job.flags.length)
      ? `<span class="flag-pill" title="${escapeHtml(job.flags.join('\n') + provNote)}">🚩 ${job.flags.length}${provNote ? "⚑" : ""}</span>` : "";
    // Unreproduced candidate badge. A job can end no_flag while the REAL flag is
    // already in flag_candidates: only a TRUSTED source (runner stdout / OOB
    // collector) promotes a flag, so a sandbox run that died for an ENVIRONMENT
    // reason leaves a genuine capture stranded (job e1b933afc137 — confirmed-
    // correct flag, status no_flag). Shown ONLY when flags is empty: `finished`
    // jobs routinely carry decoy candidates too (DH{**fake_flag**},
    // DH{32alphanumeric}), so badging them would be pure noise. This promotes
    // nothing — curation stays MANUAL — it just makes the candidate visible.
    const candPill = (!(job.flags && job.flags.length) && job.flag_candidates && job.flag_candidates.length)
      ? `<span class="flag-pill" style="background:var(--yellow-solid);color:var(--yellow-soft)"
           title="${escapeHtml(job.flag_candidates.join('\n'))}\n\nUNVERIFIED — the sandbox never reproduced these. Confirm against the challenge, then pin in the UI.">⚑ ${job.flag_candidates.length}</span>`
      : "";
    // Live readouts on the row itself, so the dashboard answers "is this one
    // moving?" without opening it. Both tick on the shared 1s timer via
    // _tickLivePill — the same elements the detail panel uses, so there is one
    // implementation of the age format and one place it can be wrong.
    let rowPills = "";
    if (job.status === "running" && job.started_at) {
      const sec = Math.max(0, Math.round((Date.now() - new Date(job.started_at).getTime()) / 1000));
      rowPills += `<span class="timing-pill live" data-started-at="${escapeHtml(job.started_at)}"
        title="started ${escapeHtml(job.started_at)}">⏱ ${_fmtAgentAge(sec)} <span class="timing-tag">running</span></span>`;
      // Same rule as the detail panel: NO fallback when the agent has not
      // emitted yet, because started_at in its place just measures the job's
      // own age and would read as liveness on a job that has produced nothing.
      if (job.last_agent_event_at) {
        const asec = Math.max(0, Math.round(
          (Date.now() - new Date(job.last_agent_event_at).getTime()) / 1000));
        rowPills += `<span class="agent-pill" data-agent-at="${escapeHtml(job.last_agent_event_at)}"
          title="${escapeHtml("last event: " + (job.last_event_actor || "main") + " · "
            + (job.last_event_kind || "?") + "\n\nWatch it RESET — a climbing number is normal; "
            + "a healthy run is silent for minutes while the model thinks.")}"
          >⚡ ${_fmtAgentAge(asec)}</span>`;
      }
    }
    // Operator tag, first on the row. It leads because it is the ONE field the
    // operator wrote themselves — module and filename are the same handful of
    // strings across every job ("pwn · chal.zip" eight times over), so the tag
    // is what actually distinguishes two rows at a glance. Display only; it is
    // never sent to the agent (see api/storage.py sanitize_job_tag).
    //
    // escapeHtml() here escapes & < > but NOT quotes, which is correct for a
    // TEXT context and would NOT be for an attribute — so the tag goes in the
    // element body and gets no title=, unlike the chips below.
    const tagPill = job.tag ? `<span class="tag-pill">${escapeHtml(job.tag)}</span> ` : "";
    const _rowHtml = `${tagPill}<strong>${job.module}</strong> · ${escapeHtml(job.filename || "")}
      <span class="status ${job.status}">${job.status}</span>${flagPill}${candPill}${rowPills}
      <button class="delete-btn">×</button>
      <div style="font-size:0.75rem;color:var(--fg-muted);"><span class="jobid-text">${job.id}</span><button class="copy-jobid-btn" data-jobid="${job.id}" title="Copy job ID">⧉</button> ${cost}</div>
        <div class="row-manager" hidden>
          <div class="mgr-head"><span class="mgr-prob"></span><span class="mgr-stage"></span></div>
          <div class="mgr-bar"><i class="mgr-fill"></i></div>
        </div>
        <div class="row-blocked" hidden><span class="blk-text"></span></div>`;
    // TWO DIFFERENT LIFETIMES, and conflating them stacks handlers. The row
    // click lives on the <li>, which innerHTML does not touch, so it is bound
    // exactly once when the element is created; the buttons live INSIDE and
    // are new nodes every time the content changes, so they are bound then.
    if (fresh) li.addEventListener("click", () => selectJob(job.id));
    if (_ROW_SIG.get(li) !== _rowHtml) {
      li.innerHTML = _rowHtml;
      _ROW_SIG.set(li, _rowHtml);
      li.querySelector(".delete-btn").addEventListener("click", (e) => deleteJob(job.id, e));
      li.querySelector(".copy-jobid-btn").addEventListener("click", (e) => copyJobId(job.id, e));
    }
    const costEl = li.querySelector(".row-cost");
    if (costEl && costEl.textContent !== costText) costEl.textContent = costText;
    // Same reason as cost and the manager bar: this moves while the job runs,
    // so it updates in place rather than through the row signature.
    //
    // It is a SIGNAL, never a stop — the operator is the only brake here. What
    // it buys is when: 340e62bdcd32 reached this state at attempt 3 and ran to
    // attempt 17 before a human noticed, which cost 3.9 hours and $35.
    const blkEl = li.querySelector(".row-blocked");
    if (blkEl) {
      const b = job.blocked_signal;
      blkEl.hidden = !b || !b.signalling;
      if (!blkEl.hidden) {
        const t = blkEl.querySelector(".blk-text");
        const reason = b.agent_reason_state === "accepted" && b.agent_reason
          ? " — " + b.agent_reason : "";
        const txt = `같은 벽 ${b.run}회 (${b.verdict})${reason}`;
        if (t.textContent !== txt) t.textContent = txt;
        t.title = `${b.verdict} 판정이 연속 ${b.run}회 반복됐습니다.\n`
          + `임계 ${b.threshold}회. 정지가 아니라 신호입니다 — 판단은 운영자 몫입니다.`
          + (b.agent_reason
             ? `\n\n에이전트 진술 (${b.agent_reason_state}): ${b.agent_reason}` : "");
      }
    }
    // OUT OF THE SIGNATURE, for the same reason cost is. The manager's
    // probability and stage move while a job runs, so putting them in _rowHtml
    // would rewrite the whole row — and every node in it — on each poll. The
    // SHAPE is in the markup and static; only text and one width change here.
    const mgrEl = li.querySelector(".row-manager");
    if (mgrEl) {
      const m = job.manager;
      // Hidden until an assessment exists. An empty bar beside "—%" claims the
      // job was assessed and scored nothing, which is a different statement
      // from "not assessed yet".
      mgrEl.hidden = !m || typeof m.flag_probability !== "number";
      if (!mgrEl.hidden) {
        const pct = Math.max(0, Math.min(100, m.flag_probability));
        const probEl = mgrEl.querySelector(".mgr-prob");
        const stageEl = mgrEl.querySelector(".mgr-stage");
        const fillEl = mgrEl.querySelector(".mgr-fill");
        const band = pct >= 60 ? "p-hi" : pct >= 25 ? "p-mid" : "p-lo";
        const probText = `${pct}%`;
        if (probEl.textContent !== probText) probEl.textContent = probText;
        if (probEl.className !== `mgr-prob ${band}`) probEl.className = `mgr-prob ${band}`;
        // The BAR is the pipeline position, not the probability — two different
        // questions, and one of them is a fact about what the job has already
        // done. Showing the probability twice would leave "how far along is it"
        // unanswered, which is half of what was asked for.
        const done = m.steps_done || 0, total = m.steps_total || 7;
        const stageText = `${m.stage || "?"} ${done}/${total}`;
        if (stageEl.textContent !== stageText) stageEl.textContent = stageText;
        const w = `${Math.round((done / Math.max(1, total)) * 100)}%`;
        if (fillEl.style.width !== w) fillEl.style.width = w;
        // Everything the assessment said, on hover: the row has space for two
        // numbers and the reasoning is what makes them actionable.
        const tip = [
          m.rationale && `왜: ${m.rationale}`,
          m.next_step && `다음: ${m.next_step}`,
          m.blocker && `막힌 것: ${m.blocker}`,
          m.confidence && `확신도: ${m.confidence}`,
          m.model && `${m.provider || ""} ${m.model}`.trim(),
          m.ts && `평가 시각: ${m.ts}`,
        ].filter(Boolean).join("\n");
        if (mgrEl.title !== tip) mgrEl.title = tip;
      }
    }
    li.classList.toggle("selected", job.id === selectedJob);
    // ONLY WHEN IT IS OUT OF PLACE. `appendChild` on an element already in
    // the document MOVES it — remove plus insert — so calling it for every
    // row on every poll re-ordered the entire list into itself, seven seconds
    // at a time. Measured: 1765 DOM mutations in ten seconds, more than every
    // other panel on the page put together, and the flicker the operator kept
    // reporting after four other causes had been found and fixed.
    if (ul.children[_slot] !== li) ul.insertBefore(li, ul.children[_slot] || null);
    _slot += 1;
  }
  for (const li of Array.from(ul.children)) {
    if (!alive.has(li.dataset.id)) li.remove();
  }
  // The rows above are re-created on every poll, so the pills they carry are
  // brand-new nodes with a stale-by-up-to-2s value baked in. Without this the
  // 1s tick only runs while a job DETAIL panel happens to be open, and the
  // dashboard's own counters would sit frozen between polls — the exact
  // "frozen counter reads like a wedged agent" failure the tick exists to
  // avoid. _ensureLivePillTimer is a no-op when the timer is already running.
  if (data.jobs.some((j) => j.status === "running")) _ensureLivePillTimer();
}

async function selectJob(id) {
  selectedJob = id;
  document.querySelectorAll("#jobs-list li").forEach((li) => {
    li.classList.toggle("selected", li.dataset.id === id);
  });
  _openJobModal(id);
  await renderJob(id, { force: true });
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const job = await renderJob(id);
    if (job && JOB_TERMINAL.includes(job.status)) {
      clearInterval(pollTimer);
      pollTimer = null;
      await refreshJobs();
      await refreshStats();
    }
  }, 2000);
  // Live SSE feed on top of the poller. backfill_done widens the
  // poller's interval; onerror lets it fall back to fast-polling.
  _openLiveStream(id);
}

function _openJobModal(id) {
  const m = document.getElementById("job-modal");
  if (!m) return;
  const title = m.querySelector(".job-modal-title");
  if (title) title.textContent = `Job ${id}`;
  m.hidden = false;
  // Lock background scroll while the modal is open.
  document.body.classList.add("modal-open");
}

function _closeJobModal() {
  const m = document.getElementById("job-modal");
  if (m) m.hidden = true;
  document.body.classList.remove("modal-open");
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  _closeLiveStream();
  selectedJob = null;
  document.querySelectorAll("#jobs-list li").forEach((li) =>
    li.classList.remove("selected"),
  );
  // Wipe the detail body so a stale render doesn't flash on the next open.
  const detail = document.getElementById("job-detail");
  if (detail) detail.innerHTML = "";
}

// ENTRY TIMING. Four rounds of "still laggy" were spent on things that were
// not the cause — the poll, the memo, the render caps, the SSE backfill —
// because every measurement available here (server handlers 4-61 ms, real HTTP
// round trips 1-9 ms, jsdom build+insert ~35 ms) added up to a fortieth of the
// three seconds the operator was actually seeing. jsdom cannot measure style,
// layout or paint, so the gap was invisible from this side. This makes the
// browser report which phase owns it.
//
// One console line per entry, and window.__entry keeps the last one.
const _T = (typeof performance !== "undefined" && performance.now)
  ? () => performance.now() : () => Date.now();

function _mark(marks, name) {
  marks.push([name, _T()]);
}

function _reportEntry(marks) {
  if (marks.length < 2) return;
  const t0 = marks[0][1];
  const parts = [];
  for (let i = 1; i < marks.length; i++) {
    parts.push(`${marks[i][0]}=${(marks[i][1] - marks[i - 1][1]).toFixed(0)}`);
  }
  const total = (marks[marks.length - 1][1] - t0).toFixed(0);
  const line = `[entry ${total}ms] ${parts.join(" ")}`;
  try { window.__entry = line; } catch (_) {}
  try { console.log(line); } catch (_) {}
}

// ---------------------------------------------------------------------------
// Execution trace — what shape the job ACTUALLY took.
//
// Not a workflow diagram. Ogamdo has no authored graph to draw: the shape
// emerges from a loop, one attempt at a time. What a node-and-edge picture
// would show — four nodes, N passes — is true of every job and distinguishes
// none of them. What distinguishes them is where the clock went, and across
// the whole job corpus that answer was startling enough to be worth a view of
// its own: execution never exceeded 2.3% of a job's wall clock, and the agent
// segment between runs held 82-100%.
//
// So: one row per attempt, time along the row. No chart library, for the
// reason already written in style.css — a CDN chart script would become the
// largest dependency in the app to draw bars that are three divs.
let traceView = (() => {
  try { return localStorage.getItem("trace_view") === "1"; }
  catch (_) { return false; }
})();
// Deliberately orthogonal to monitorView/gptLogView rather than folded into
// them: the trace applies to every provider, and keeping it separate means
// switching back lands on whatever view the operator already had, instead of
// resetting them to a default.
function _setTraceView(on) {
  traceView = !!on;
  try { localStorage.setItem("trace_view", traceView ? "1" : "0"); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}
/** Leave the trace WITHOUT rendering, so the sibling setter that follows
 *  renders once. Selecting another view has to clear this flag: activityView
 *  short-circuits on it, so while the trace is on, Run log / Monitor /
 *  Timeline would change their own preference and leave the screen where it
 *  was. The guarded handlers hid it completely -- `if (monitorView)
 *  _setMonitorView(false)` is a no-op when monitorView is already false, so
 *  the Run log button did nothing at all and the operator had no way back. */
function _leaveTraceView() {
  if (!traceView) return;
  traceView = false;
  try { localStorage.setItem("trace_view", "0"); } catch (_) {}
}
// Row widths: "lane" makes every attempt the same width (compare the INTERNAL
// split), "job" makes width proportional to duration (compare attempts to each
// other). Neither is the right default for both questions, so both ship.
let traceScale = (() => {
  try {
    const v = localStorage.getItem("trace_scale") || "lane";
    return ["lane", "job"].includes(v) ? v : "lane";
  } catch (_) { return "lane"; }
})();
function _setTraceScale(v) {
  traceScale = ["lane", "job"].includes(v) ? v : "lane";
  try { localStorage.setItem("trace_scale", traceScale); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}

/** Durations read by humans. Seconds stay seconds below a minute — rounding
 *  a 2-second exploit run to "0m" would erase the finding. */
function _traceDur(s) {
  if (!Number.isFinite(s)) return "—";
  if (s < 1) return s.toFixed(1) + "s";
  if (s < 60) return Math.round(s) + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + Math.round(s % 60) + "s";
  return Math.floor(s / 3600) + "h " + Math.round((s % 3600) / 60) + "m";
}

/** Classifies the run segment by how the process ended. */
function _traceRunCls(run) {
  if (!run) return "";
  if (run.spawn_failed) return " bad";
  if (run.timeout || run.killed_by_supervise) return " bad";
  if (run.exit_code === 0) return " ok";
  if (run.exit_code === null || run.exit_code === undefined) return "";
  return " warn";
}

/** Classifies the adjudicate segment by verdict. Unknown verdicts get no
 *  class rather than a guessed one, so a new verdict shows up as uncoloured
 *  instead of silently borrowing another verdict's meaning. */
function _traceVerdictCls(v) {
  if (v === "success") return " ok";
  if (v === "partial") return " warn";
  if (v === "network_error" || v === "setup_error") return " muted";
  if (v === "failure") return " bad";
  return "";
}

/** One coloured segment. `min-width` in CSS keeps a present-but-tiny segment
 *  visible: run is under 2% of most jobs, and at 900px across 28 lanes a
 *  purely proportional width would render the very thing being reported as
 *  sub-pixel. A segment that is absent is omitted entirely — different from
 *  one that is present and short. */
function _traceSeg(kind, cls, seconds, total, title) {
  if (seconds === null || seconds === undefined) return "";
  const pct = total > 0 ? (seconds / total) * 100 : 0;
  return `<span class="tr-seg tr-${kind}${cls}" style="flex-grow:${pct.toFixed(4)}"
    title="${escapeHtml(title)}"></span>`;
}

function _traceLaneRow(lane, jobTotal, maxLane) {
  const a = lane.agent ? lane.agent.s : null;
  const r = lane.run && lane.run.s !== null && lane.run.s !== undefined ? lane.run.s : null;
  const j = lane.adjudicate && lane.adjudicate.s !== null && lane.adjudicate.s !== undefined
    ? lane.adjudicate.s : null;
  const laneTotal = (a || 0) + (r || 0) + (j || 0);

  const preT = lane.prejudge
    ? `prejudge: ${lane.prejudge.would_block ? "would_block, " : ""}`
      + `severity=${lane.prejudge.severity || "?"}, issues=${lane.prejudge.issues ?? "?"}`
      + `, target=${lane.prejudge.target_liveness || "?"}`
    : "prejudge: (no result event)";
  const runT = lane.run
    ? `run ${_traceDur(r)} — ${lane.run.script || "?"}`
      + (lane.run.spawn_failed ? " — SPAWN FAILED" : "")
      + `, exit=${lane.run.exit_code ?? "?"}`
      + (lane.run.timeout ? ", TIMEOUT" : "")
      + (lane.run.killed_by_supervise ? ", killed by supervise" : "")
      // A run the JOB outlived: no exit event, so its duration is measured to
      // the job's own end and `exit=?` is not a gap in the record but the
      // whole story. Said out loud, because a long bar with an unknown exit
      // code otherwise reads as a broken trace.
      + (lane.run.unterminated ? ", NO EXIT — job ended first" : "")
      + `, stdout=${lane.run.stdout_bytes ?? "?"}B`
    : "실행되지 않음";
  const adjT = lane.adjudicate
    ? `adjudicate ${_traceDur(j)} — verdict=${lane.adjudicate.verdict}`
      + `, next=${lane.adjudicate.next_action ?? "?"}`
      + (lane.adjudicate.failure_code ? `, code=${lane.adjudicate.failure_code}` : "")
    : "판정 없음";

  // Width of the row itself. In "job" mode the longest lane fills the track
  // and the rest are proportional to it, so a 2-second attempt next to a
  // 20-minute one reads as the outlier it is.
  const rowPct = traceScale === "job" && maxLane > 0
    ? Math.max(2, (laneTotal / maxLane) * 100)
    : 100;

  const callChips = Object.keys(lane.calls || {}).sort().map((k) =>
    `${k}×${lane.calls[k]}`).join("  ");
  const cost = lane.cost_usd === null || lane.cost_usd === undefined
    ? "—"
    : (lane.cost_complete ? "$" : "≥$") + lane.cost_usd.toFixed(2);

  const verdict = lane.verdict || (lane.unreached ? "미도달" : (lane.open ? "진행 중" : "—"));
  const flags = lane.flag_gate && lane.flag_gate.flags_count
    ? ` <span class="tr-flag">flag×${lane.flag_gate.flags_count}</span>` : "";

  return `<div class="tr-lane${lane.open ? " open" : ""}">
    <span class="tr-n">${lane.unreached ? "·" : "#" + lane.n}</span>
    <span class="tr-track" style="width:${rowPct.toFixed(2)}%">
      ${_traceSeg("agent", "", a, laneTotal, `agent ${_traceDur(a)} — 초안 작성 + prejudge\n${preT}`)}
      ${_traceSeg("run", _traceRunCls(lane.run), r, laneTotal, runT)}
      ${_traceSeg("adj", _traceVerdictCls(lane.verdict), j, laneTotal, adjT)}
    </span>
    <span class="tr-dur">${_traceDur(laneTotal)}</span>
    <span class="tr-verdict${_traceVerdictCls(lane.verdict)}">${escapeHtml(verdict)}${flags}</span>
    <span class="tr-cost" title="${escapeHtml(callChips || "모델 호출 없음")}">${cost}</span>
  </div>`;
}

// --- graph view -------------------------------------------------------------
// The lanes answer "where did the clock go". This answers "what is wired to
// what", which is the question the n8n screenshot was really asking, and it is
// a different question -- not a prettier version of the same one. Neither view
// subsumes the other, so both ship and the operator picks.
//
// What a graph can show that lanes cannot: an edge that exists in the design
// and does nothing in practice. On 340e62bdcd32 prejudge raised would_block
// five times and all seventeen executions went ahead anyway; on 5efafb6ee9ab
// it was twenty-five blocks against twenty-seven runs. That edge is drawn
// dashed, ending in a stop, because that is what the data says it does.
let traceShape = (() => {
  try {
    const v = localStorage.getItem("trace_shape") || "lanes";
    return ["lanes", "graph"].includes(v) ? v : "lanes";
  } catch (_) { return "lanes"; }
})();
function _setTraceShape(v) {
  traceShape = ["lanes", "graph"].includes(v) ? v : "lanes";
  try { localStorage.setItem("trace_shape", traceShape); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}

/** Counts every node and edge in the graph, straight off the lanes. Nothing
 *  here is assumed: a node's number is how many lanes actually reached it. */
function _traceGraphData(t) {
  const lanes = t.lanes || [];
  const calls = (t.totals && t.totals.calls) || {};
  const tt = t.totals || {};
  const tally = (pick) => {
    const out = {};
    lanes.forEach((l) => { const v = pick(l); if (v !== null && v !== undefined) out[v] = (out[v] || 0) + 1; });
    return out;
  };
  const RANK = { success: 3, partial: 2 };
  const top = (obj, n) => Object.entries(obj)
    .sort((a, b) => (b[1] - a[1]) || ((RANK[b[0]] || 0) - (RANK[a[0]] || 0)))
    .slice(0, n).map(([k, v]) => `${k} ${v}`).join(", ");
  const all = (obj) => Object.entries(obj)
    .sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} × ${v}`).join("\n");
  const verdicts = tally((l) => l.verdict);
  const exits = tally((l) => (l.run ? l.run.exit_code : null));
  const sum = (tt.agent_s || 0) + (tt.run_s || 0) + (tt.adjudicate_s || 0);
  const pct = (v) => (sum > 0 ? (v / sum * 100).toFixed(1) + "%" : "—");
  return {
    lanes: lanes.length,
    prejudged: lanes.filter((l) => l.prejudge).length,
    blocked: lanes.filter((l) => l.prejudge && l.prejudge.would_block).length,
    ran: lanes.filter((l) => l.run).length,
    adjudicated: lanes.filter((l) => l.adjudicate).length,
    gated: lanes.filter((l) => l.flag_gate).length,
    flags: lanes.reduce((n, l) => n + ((l.flag_gate && l.flag_gate.flags_count) || 0), 0),
    // The loop closed once per lane after the first. Derived from the lane
    // count rather than guessed from verdicts, so it cannot disagree with the
    // other view.
    retries: Math.max(0, lanes.length - 1),
    calls, verdicts, exits, top, all, pct, tt,
  };
}

function _gNode(x, y, w, h, title, lines, cls, tip) {
  const body = lines.filter(Boolean).map((s, i) =>
    `<text class="g-sub" x="${x + w / 2}" y="${y + 42 + i * 15}" text-anchor="middle">${escapeHtml(s)}</text>`).join("");
  return `<g class="g-node ${cls}"><title>${escapeHtml(tip || title)}</title>
    <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="7"/>
    <rect class="g-accent" x="${x}" y="${y}" width="${w}" height="3" rx="1.5"/>
    <text class="g-title" x="${x + w / 2}" y="${y + 23}" text-anchor="middle">${escapeHtml(title)}</text>
    ${body}</g>`;
}

function _gArrow(x1, y, x2, label) {
  const mid = (x1 + x2) / 2;
  return `<g class="g-edge">
    <line x1="${x1}" y1="${y}" x2="${x2 - 7}" y2="${y}" marker-end="url(#trArrow)"/>
    <text class="g-elabel" x="${mid}" y="${y - 7}" text-anchor="middle">${escapeHtml(label)}</text>
  </g>`;
}

function _traceGraph(t) {
  const d = _traceGraphData(t);
  const sa = t.subagents || {roles: {}, main_tools: 0, available: [], never_invoked: [], source: null};
  const subRoles = Object.keys(sa.roles || {}).sort();
  // Turns the ORCHESTRATOR pushed into main -- the opposite direction from a
  // subagent, which main itself spawns. Same row, its own colour, because
  // "main asked for this" and "this was forced on main" are different facts.
  const inj = (t.totals && t.totals.injections) || {};
  const injRungs = Object.entries(inj).sort((a, b) => b[1] - a[1]);
  const injTotal = injRungs.reduce((n, [, v]) => n + v, 0);
  const satellites = subRoles.length + (injTotal ? 1 : 0);
  // The chain drops to make room only when there is something to put there.
  const SUBH = 68, SUBY = 6;
  const W = 940, NW = 158, NH = 92, Y = (satellites ? SUBY + SUBH + 40 : 34), M = 15, GAP = 30;
  const xs = [0, 1, 2, 3, 4].map((i) => M + i * (NW + GAP));
  const cy = Y + NH / 2;
  const nodes = [
    _gNode(xs[0], Y, NW, NH, "main 에이전트",
      [d.pct(d.tt.agent_s) + " · " + _traceDur(d.tt.agent_s),
       sa.source ? "도구 " + sa.main_tools + "회" : "사용량 보고 " + (d.calls["main/main"] || 0) + "회"],
      "g-agent",
      `초안 작성 + prejudge 대기\n${_traceDur(d.tt.agent_s)} (${d.pct(d.tt.agent_s)})\n`
      + (sa.source ? `도구 호출 ${sa.main_tools}회\n` : "")
      + "비용은 귀속 불가 — codex는 세션당 1회만 보고합니다"),
    _gNode(xs[1], Y, NW, NH, "prejudge",
      [(d.calls["judge/prejudge"] || 0) + " 호출", d.prejudged + " 시도에서 판정"],
      "g-prejudge" + (d.prejudged ? "" : " g-idle"),
      `모델 호출 ${d.calls["judge/prejudge"] || 0}회, 시도 ${d.prejudged}건\n`
      + "호출 수와 시도 수가 다른 이유는 이 데이터로 판별되지 않습니다"),
    _gNode(xs[2], Y, NW, NH, "runner",
      [d.ran + " 실행 · " + _traceDur(d.tt.run_s), "exit " + (d.top(d.exits, 2) || "—")],
      "g-run" + (d.ran ? "" : " g-idle"),
      `실행 ${d.ran}회, ${_traceDur(d.tt.run_s)} (${d.pct(d.tt.run_s)})\n\nexit code:\n${d.all(d.exits) || "—"}`),
    _gNode(xs[3], Y, NW, NH, "postjudge",
      [(d.calls["judge/postjudge"] || 0) + " 호출 · " + _traceDur(d.tt.adjudicate_s),
       d.top(d.verdicts, 2) || "—"],
      "g-adj" + (d.adjudicated ? "" : " g-idle"),
      `판정 ${d.adjudicated}건, ${_traceDur(d.tt.adjudicate_s)} (${d.pct(d.tt.adjudicate_s)})\n\nverdict:\n${d.all(d.verdicts) || "—"}`),
    _gNode(xs[4], Y, NW, NH, "flag gate",
      [d.gated + " 통과", "flag " + d.flags],
      d.flags ? "g-gate-hit" : ("g-gate" + (d.gated ? "" : " g-idle")),
      `게이트 통과 ${d.gated}회, 회수한 flag ${d.flags}개`),
  ].join("");

  const edges = [
    _gArrow(xs[0] + NW, cy, xs[1], String(d.prejudged)),
    _gArrow(xs[1] + NW, cy, xs[2], String(d.ran)),
    _gArrow(xs[2] + NW, cy, xs[3], String(d.adjudicated)),
    _gArrow(xs[3] + NW, cy, xs[4], String(d.gated)),
  ].join("");

  // The edge that is not wired. Drawn only when prejudge actually raised a
  // block, and drawn dead-ending, because every one of those runs went ahead.
  const blockStub = d.blocked ? `<g class="g-dead">
      <title>${escapeHtml(
        `prejudge가 ${d.blocked}회 would_block을 냈고, 실행은 ${d.ran}회 모두 진행됐습니다.\n`
        + "이 간선은 배선돼 있지 않습니다.")}</title>
      <path d="M${xs[1] + NW / 2},${Y + NH} L${xs[1] + NW / 2},${Y + NH + 26}"/>
      <path class="g-x" d="M${xs[1] + NW / 2 - 6},${Y + NH + 26} l12,12 M${xs[1] + NW / 2 + 6},${Y + NH + 26} l-12,12"/>
      <text class="g-dead-label" x="${xs[1] + NW / 2 + 14}" y="${Y + NH + 44}"
        >would_block ${d.blocked}회 — 실행을 멈추지 않음</text>
    </g>` : "";

  // The loop. This is the whole shape of the thing: everything above happens
  // once per pass, and the passes are what the job is made of.
  const ly = Y + NH + 78;
  const loop = d.retries ? `<g class="g-loop">
      <title>${escapeHtml(`게이트를 통과한 뒤 에이전트로 ${d.retries}회 되돌아갔습니다`)}</title>
      <path d="M${xs[4] + NW / 2},${Y + NH} L${xs[4] + NW / 2},${ly}
               L${xs[0] + NW / 2},${ly} L${xs[0] + NW / 2},${Y + NH + 7}"
            marker-end="url(#trArrowLoop)"/>
      <text class="g-loop-label" x="${(xs[0] + xs[4] + NW) / 2}" y="${ly - 8}" text-anchor="middle"
        >재시도 × ${d.retries}</text>
    </g>` : "";

  // Spawned subagents. These appear in NO ledger and NO events.jsonl -- codex
  // bills the session once and the exploit loop does not track the agent's own
  // team -- so `gpt-events.jsonl` is the only record that they ran at all.
  // Every satellite drops to a shared bus and enters main from the top, so
  // the row can hold any number of them without an edge crossing a node.
  const mainCx = M + NW / 2, busY = Y - 18;
  const wire = (cx, cls, marker) =>
    `<path class="${cls}" d="M${cx},${SUBY + SUBH} L${cx},${busY} L${mainCx},${busY} L${mainCx},${Y - 7}"
       marker-end="url(#${marker})"/>`;
  const subs = subRoles.slice(0, 4).map((role, i) => {
    const r = sa.roles[role];
    const x = M + i * (NW + GAP);
    return _gNode(x, SUBY, NW, SUBH, role,
      [`spawn ${r.spawns} · 도구 ${r.tools}`], "g-subagent",
      `${role}: spawn ${r.spawns}회, 도구 호출 ${r.tools}회`
      + (r.models && r.models.length ? `\n${r.models.join(", ")}` : "")
      + "\n\n사용량 원장에도 events.jsonl에도 남지 않습니다 — "
      + "이 기록의 출처는 gpt-events.jsonl뿐입니다")
      + wire(x + NW / 2, "g-spawn", "trArrowSpawn");
  }).join("");
  const injX = M + Math.min(subRoles.length, 4) * (NW + GAP);
  const RUNG_KO = {
    final_draft: "FINAL DRAFT", operator_steer: "OPERATOR STEER",
    soft_eject: "soft-eject", empty_wait: "EMPTY WAIT",
    contrarian_reframe: "contrarian", postjudge_feedback: "postjudge 피드백",
  };
  const rungName = (k) => RUNG_KO[k] || k;
  const injNode = injTotal ? _gNode(injX, SUBY, NW, SUBH, "주입 턴",
    [`총 ${injTotal}회`,
     injRungs.length ? `${rungName(injRungs[0][0])} ${injRungs[0][1]}` : ""],
    "g-inject",
    `오케스트레이터가 턴 경계에서 밀어 넣은 턴 ${injTotal}회\n\n`
    + injRungs.map(([k, v]) => `${rungName(k)} × ${v}`).join("\n")
    + "\n\n사다리 순위: FINAL DRAFT > OPERATOR STEER > soft-eject > EMPTY WAIT")
    + wire(injX + NW / 2, "g-injwire", "trArrowInject") : "";
  // Available and never reached for. Stated, because "debugger is not on the
  // diagram" should not read as a gap in the diagram.
  const unused = sa.source && (sa.never_invoked || []).length
    ? `<text class="g-unused" x="${M}" y="${ly + 22}"
        >호출되지 않은 역할: ${escapeHtml(sa.never_invoked.join(", "))}</text>` : "";
  const noSrc = !sa.source
    ? `<text class="g-unused" x="${M}" y="${ly + 22}"
        >subagent 기록 없음 — 이 job에는 provider 이벤트 스트림이 없습니다 (0회가 아니라 미기록)</text>` : "";

  const H = ly + (unused || noSrc ? 34 : 26);
  return `<div class="tr-graph">
    <svg viewBox="0 0 ${W} ${H}" width="100%" role="img"
         aria-label="${escapeHtml(`실행 그래프: 에이전트 → prejudge → runner → postjudge → flag gate, ${d.retries}회 반복`)}">
      <defs>
        <marker id="trArrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
          <path class="g-head" d="M0,0 L8,4 L0,8 z"/>
        </marker>
        <marker id="trArrowLoop" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
          <path class="g-head-loop" d="M0,0 L8,4 L0,8 z"/>
        </marker>
        <marker id="trArrowSpawn" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
          <path class="g-head-spawn" d="M0,0 L8,4 L0,8 z"/>
        </marker>
        <marker id="trArrowInject" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
          <path class="g-head-inject" d="M0,0 L8,4 L0,8 z"/>
        </marker>
      </defs>
      ${edges}${blockStub}${loop}${subs}${injNode}${nodes}${unused}${noSrc}
    </svg>
  </div>`;
}

/** Manager assessments as a sparkline. Drawn only with two or more points —
 *  a single assessment is a number, not a trend, and a one-point line chart
 *  implies a history that was never recorded. */
function _traceManagerSpark(series, w = 320, h = 44) {
  const pts = series
    .map((m) => m.flag_probability)
    .map((v) => (typeof v === "number" && v >= 0 && v <= 100 ? v : null));
  const known = pts.filter((v) => v !== null);
  if (known.length < 2) return "";
  const step = w / (pts.length - 1);
  const xy = pts.map((v, i) => (v === null ? null : [i * step, h - (v / 100) * h]));
  const d = xy.filter(Boolean).map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const last = known[known.length - 1];
  return `<div class="tr-mgr">
    <svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img"
         aria-label="manager flag probability over ${pts.length} assessments, now ${last}%">
      <path class="tr-mgr-line" d="${d}" fill="none" stroke-width="2"/>
      ${xy.filter(Boolean).map((p) =>
        `<circle class="tr-mgr-dot" cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="2.5"/>`).join("")}
    </svg>
    <span class="tr-mgr-label">manager flag 가능성 · 최근 ${last}%</span>
  </div>`;
}

/** The job-level split, above the lanes. This is the headline: on every job
 *  in the corpus it was overwhelmingly one colour, and the point of putting it
 *  first is that the per-lane rows then read as confirmation rather than as a
 *  wall of bars to be interpreted. */
function _traceSummary(t) {
  const tt = t.totals || {};
  const sum = (tt.agent_s || 0) + (tt.run_s || 0) + (tt.adjudicate_s || 0);
  const pct = (v) => (sum > 0 ? (v / sum) * 100 : 0);
  const cell = (kind, cls, label, secs) => `
    <div class="tr-sum-cell">
      <span class="tr-sum-swatch tr-${kind}${cls}"></span>
      <span class="tr-sum-pct">${sum > 0 ? pct(secs).toFixed(1) : "—"}%</span>
      <span class="tr-sum-label">${escapeHtml(label)}</span>
      <span class="tr-sum-abs">${_traceDur(secs)}</span>
    </div>`;
  const drift = t.wall_s !== null && t.wall_s !== undefined ? t.wall_s - sum : null;
  return `<div class="tr-summary">
    <div class="tr-sum-bar">
      ${/* No status modifier here on purpose: the summary reports WHERE the
            clock went, not how it turned out. Colouring it green once put
            "run: ok" above seventeen rows that every one exited non-zero. */""}
      ${_traceSeg("agent", "", tt.agent_s, sum, `agent ${_traceDur(tt.agent_s)}`)}
      ${_traceSeg("run", "", tt.run_s, sum, `run ${_traceDur(tt.run_s)}`)}
      ${_traceSeg("adj", "", tt.adjudicate_s, sum, `adjudicate ${_traceDur(tt.adjudicate_s)}`)}
    </div>
    <div class="tr-sum-cells">
      ${cell("agent", "", "agent — 초안 작성 + prejudge", tt.agent_s)}
      ${cell("run", "", "run — exploit 실행", tt.run_s)}
      ${cell("adj", "", "adjudicate — 판정", tt.adjudicate_s)}
    </div>
    <div class="tr-sum-foot">
      <span>${tt.lanes || 0} lane · 실행 ${tt.runs || 0}회</span>
      <span>총 ${_traceDur(t.wall_s)}</span>
      <span>${tt.cost_usd === null || tt.cost_usd === undefined
        ? "비용 보고 없음"
        : (tt.cost_complete ? "$" : "≥$") + tt.cost_usd.toFixed(2)}</span>
      ${/* Shown, not hidden: if the lanes ever stop tiling the job exactly,
            the number that proves it is on screen instead of in a test. */""}
      <span class="tr-drift${drift !== null && Math.abs(drift) > 2 ? " bad" : ""}"
            title="lane 합과 job 전체 시간의 차이">Δ ${drift === null ? "—" : drift.toFixed(1) + "s"}</span>
    </div>
  </div>`;
}

function renderTrace(t) {
  if (!t) {
    return `<div class="tr-wrap"><div class="tr-empty">트레이스를 불러오지 못했습니다.</div></div>`;
  }
  const lanes = t.lanes || [];
  const maxLane = lanes.reduce((m, l) => {
    const s = (l.agent ? l.agent.s : 0)
      + (l.run && l.run.s ? l.run.s : 0)
      + (l.adjudicate && l.adjudicate.s ? l.adjudicate.s : 0);
    return Math.max(m, s);
  }, 0);

  const notes = (t.notes || []).map((n) =>
    `<li>${escapeHtml(n)}</li>`).join("");

  // Events the lane vocabulary does not place. They were being written and
  // read by nothing — the hold reason, the blocked escalation, the operator's
  // module decision — so the structured half of the record was invisible even
  // though the prose half reached run.log. Rendered generically on purpose:
  // a kind added later shows up here without another edit.
  const others = (t.other_events || []).map((e) => {
    const d = Object.entries(e.detail || {})
      .map(([k, v]) => `${escapeHtml(k)}=${escapeHtml(String(v)).slice(0, 160)}`)
      .join(" · ");
    return `<li><code>${escapeHtml(e.phase)}/${escapeHtml(e.kind)}</code>`
      + `<span class="tr-ev-ts">${escapeHtml(String(e.ts || "").slice(11, 19))}</span>`
      + (d ? `<div class="tr-ev-d">${d}</div>` : "") + `</li>`;
  }).join("");

  return `<div class="tr-wrap">
    ${_traceSummary(t)}
    ${_traceManagerSpark(t.manager || [])}
    ${/* Two shapes, two questions. Lanes answer "where did the clock go";
          the graph answers "what is wired to what". The second is the one the
          n8n picture was asking, and it is not a nicer rendering of the first
          -- the graph cannot show that one attempt took twenty minutes, and
          the lanes cannot show that the block edge never fires. */""}
    <div class="tr-controls">
      <button class="tr-shape ${traceShape === "lanes" ? "active" : ""}"
              data-action="trace-shape-lanes"
              title="시도별 시간 분해 — 어디에 시계가 갔는지">레인</button>
      <button class="tr-shape ${traceShape === "graph" ? "active" : ""}"
              data-action="trace-shape-graph"
              title="노드와 간선 — 무엇이 무엇에 연결돼 있는지">그래프</button>
      ${traceShape === "lanes" ? `
        <span class="tr-ctl-sep"></span>
        <span class="tr-scale-label">행 너비</span>
        <button class="tr-scale ${traceScale === "lane" ? "active" : ""}"
                data-action="trace-scale-lane"
                title="모든 시도를 같은 너비로 — 시도 내부 비율을 비교">균등</button>
        <button class="tr-scale ${traceScale === "job" ? "active" : ""}"
                data-action="trace-scale-job"
                title="시도 길이에 비례 — 어느 시도가 시계를 먹었는지 비교">시간 비례</button>
      ` : ""}
    </div>
    ${traceShape === "graph"
      ? _traceGraph(t)
      : `<div class="tr-lanes">${lanes.map((l) => _traceLaneRow(l, t.wall_s, maxLane)).join("")}</div>`}
    ${notes ? `<ul class="tr-notes">${notes}</ul>` : ""}
    ${others ? `<details class="tr-others"><summary>그 외 이벤트 (${(t.other_events || []).length})</summary>
      <ul class="tr-ev">${others}</ul></details>` : ""}
    <div class="tr-legend">
      이 화면은 미리 배선된 workflow가 아니라 <b>실제로 걸어간 궤적</b>입니다.
      subagent(recon / debugger / triage / judge) 호출은 provider 이벤트 스트림에서,
      <b>주입 턴</b>(FINAL DRAFT / OPERATOR STEER / soft-eject / EMPTY WAIT /
      contrarian / postjudge 피드백)은 <code>agent/injected_turn</code> 이벤트에서
      옵니다. 둘 다 <b>기록된 것만</b> 그리며 추측하지 않습니다 — 주입 계측은
      2026-09-19에 추가됐으므로 그 전 job에서는 비어 있는 것이 "없었음"을
      뜻하지 않습니다.
    </div>
  </div>`;
}

async function renderJob(id, opts = {}) {
  const _marks = [];
  _mark(_marks, "start");
  const detail = document.getElementById("job-detail");
  // If the user is actively typing in an inline form (manual retry hint
  // or stop-and-resume hint), the 2-second polling re-render would blow
  // it away mid-keystroke. Skip this poll cycle. selectJob() passes
  // {force:true} so explicit job switches still re-render.
  if (
    !opts.force
    && detail.querySelector(
      ".retry-manual-form, .stop-resume-form, .steer-form, .tl-composer-typing")
  ) {
    return null;
  }
  // While a reviewer/retry stream is live for THIS job, skip the 2s poll
  // re-render — it would tear down and rebuild the retry-panel every cycle
  // (flicker) and fight the live token updates written by streamRetry.
  // selectJob() passes {force:true}, so explicit (re-)entry still rebuilds
  // the detail and restores the panel via renderReviewerPanel() below.
  if (!opts.force && activeReviewers.get(id)?.status === "running") {
    return null;
  }
  // Same idea for an active selection inside the run log: the polling
  // re-render replaces the text nodes and collapses the user's
  // selection, which makes copying live logs miserable. Skip the
  // cycle whenever the user has any selection inside the run log.
  if (!opts.force) {
    try {
      const sel = window.getSelection();
      if (sel && !sel.isCollapsed) {
        const anchor = sel.anchorNode;
        const focus = sel.focusNode;
        const inRunLog = (n) =>
          !!n && !!(n.nodeType === 1 ? n : n.parentElement)?.closest?.(".run-log");
        if (inRunLog(anchor) || inRunLog(focus)) {
          return null;
        }
      }
      // Don't yank the run-log search box out from under the user mid-type.
      const ae = document.activeElement;
      if (ae && ae.classList && ae.classList.contains("run-log-search")) {
        return null;
      }
    } catch (_) {}
  }
  const res = await fetch(`${API}/jobs/${id}`);
  if (!res.ok) {
    detail.textContent = "job not found";
    return null;
  }
  const job = await res.json();
  _mark(_marks, "job");
  const isGptJob = job.agent_provider === "gpt";
  const activityView = traceView
    ? "trace"
    : (isGptJob ? gptLogView : claudeLogView);
  gptTimelineTools = timelineToolsFor(isGptJob);

  // Cap the polling fetch at 256 KB so verbose Claude output (after a
  // big Read or Bash dump) doesn't make every 2s poll re-ship megabytes.
  const logRes = await fetch(`${API}/jobs/${id}/log?tail=262144`);
  const log = await logRes.text();
  _mark(_marks, "log");

  // Every provider. This was the last place still deciding for the operator
  // that a GPT job gets no narrator — the backend gates went first and this
  // one kept the feed from even being fetched, so the role stayed invisible
  // where the model had already been selected for it.
  let monitorEntries = [];
  try {
    const mr = await fetch(`${API}/jobs/${id}/monitor?tail=400`);
    if (mr.ok) monitorEntries = (await mr.json()).entries || [];
  } catch (_) {}
  const monitorFeedHTML = renderMonitorEntries(monitorEntries, monitorLang);
  _lastMonitorEntries[id] = monitorEntries;
  const vulnPanelHTML = renderVulnPanel(
    monitorEntries, monitorLang, job.status === "running", activityView, id);
  // One endpoint for every provider: it delegates to the GPT path for GPT and
  // normalises sdk.jsonl for the rest, so this call site stops caring which.
  let gptTimelinePayload = null;
  if (activityView === "timeline") {
    try {
      const tr = await fetch(`${API}/jobs/${id}/timeline?tail=800`);
      if (tr.ok) gptTimelinePayload = await tr.json();
    } catch (_) {}
  }
  let tracePayload = null;
  if (activityView === "trace") {
    try {
      const xr = await fetch(`${API}/jobs/${id}/trace`);
      if (xr.ok) tracePayload = await xr.json();
    } catch (_) {}
  }
  const traceHTML = activityView === "trace" ? renderTrace(tracePayload) : "";
  // ONLY THE VIEW THE OPERATOR IS LOOKING AT GETS BUILT.
  //
  // renderJob used to emit the timeline feed AND the fully colourised
  // <pre class="run-log"> into the same markup, every time, and style.css
  // then hid one of them with display:none (.run-log-window[data-view=...]).
  // On 48fadce3dde7 the invisible half was 29,328 nodes; on the MEDIAN GPT job
  // it was 79% of the panel's parse time. Nobody was ever going to see it.
  //
  // This is justified by "nobody sees it", not by that ratio: jsdom measures
  // parse only, and in a real browser a display:none subtree skips layout, so
  // the ratio ranks parse cost and not total cost. Not building it is right
  // either way, and switching views already calls renderJob({force:true}),
  // which builds whichever view just became active.
  const showTimeline = activityView === "timeline";
  const showLog = activityView === "log";
  _mark(_marks, "tl-fetch");
  const gptTimelineHTML = showTimeline
    ? renderGptTimeline(gptTimelinePayload, id)
    : "";
  const prevMonFeed = detail.querySelector(".monitor-feed");
  const prevMonAtBottom = prevMonFeed
    ? (prevMonFeed.scrollTop + prevMonFeed.clientHeight >= prevMonFeed.scrollHeight - 12)
    : true;
  const prevMonScrollTop = prevMonFeed ? prevMonFeed.scrollTop : 0;
  // The scrolling element is the EVENT LIST, not the feed — the feed is a
  // fixed box now so the agent cards stay put. Capturing the wrong element
  // here would silently stop preserving position across the 2s poll.
  const prevTimeline = detail.querySelector(".gpt-timeline-feed .gpt-event-list");
  const prevTimelineAtBottom = prevTimeline
    ? (prevTimeline.scrollTop + prevTimeline.clientHeight >= prevTimeline.scrollHeight - 12)
    : true;
  const prevTimelineScrollTop = prevTimeline ? prevTimeline.scrollTop : 0;

  // Preserve log scroll position across re-renders. If the user was already
  // at (or near) the bottom, snap to bottom after re-render so new entries
  // are visible (tail behavior). Otherwise keep their scroll position.
  const prevPre = detail.querySelector("pre.run-log");
  const prevAtBottom = prevPre
    ? (prevPre.scrollTop + prevPre.clientHeight >= prevPre.scrollHeight - 12)
    : true;
  const prevScrollTop = prevPre ? prevPre.scrollTop : 0;
  const isSameJob = prevPre && prevPre.dataset.jobId === id;
  // Same idea for the OUTER modal-body scroll: detail.innerHTML = ... resets
  // scrollTop to 0, so anywhere the user scrolled to read the description /
  // retry-hint chip / result links gets snapped back to the top on every
  // 2-second poll. Capture it now and restore after the replace, but only
  // if we're still on the same job (a fresh job starts at the top).
  const prevModalScrollTop = detail.scrollTop;

  // Preserve the live SDK panel state too. Without this, every poll
  // re-render rebuilds .sdk-live with its `hidden` attribute set, and
  // the panel only re-appears on the next SDK event — i.e. it
  // "flickers in and out" every poll cycle.
  const prevSdkPanel = detail.querySelector(".sdk-live");
  const prevSdkFeedHTML = (prevSdkPanel && isSameJob)
    ? prevSdkPanel.querySelector(".sdk-live-feed")?.innerHTML || null
    : null;
  const prevSdkFeedScroll = (prevSdkPanel && isSameJob)
    ? (prevSdkPanel.querySelector(".sdk-live-feed")?.scrollTop ?? 0)
    : 0;
  const prevSdkFeedAtBottom = (() => {
    if (!prevSdkPanel || !isSameJob) return true;
    const f = prevSdkPanel.querySelector(".sdk-live-feed");
    if (!f) return true;
    return f.scrollTop + f.clientHeight >= f.scrollHeight - 8;
  })();
  const prevSdkVisible = !!(prevSdkPanel && isSameJob && !prevSdkPanel.hidden);
  const prevSdkCollapsed = !!(prevSdkPanel && prevSdkPanel.classList.contains("collapsed"));

  // File-link helper. Left-click opens the syntax-highlighting preview
  // modal; middle-click / Ctrl+click / right-click "Open in new tab" still
  // gets the raw response since the underlying href is the API URL.
  const fileLink = (label, url, name) =>
    `<a href="${url}" target="_blank" class="file-preview-link"
        data-url="${url}" data-name="${escapeHtml(name)}">${escapeHtml(label)}</a>`;

  function liveFireOutcomeHtml(job, jobId) {
    if (job.module !== "live-fire") return "";
    const tiers = Array.isArray(job.evidence_tiers)
      ? job.evidence_tiers.filter((tier) => tier === "A" || tier === "B") : [];
    let state = "PENDING";
    let stateClass = "pending";
    if (job.ready_to_deploy === true) {
      state = "READY";
      stateClass = "ready";
    } else if (job.ready_to_deploy === false) {
      state = "UNVERIFIED";
      stateClass = "unverified";
    }
    const tierText = tiers.length ? tiers.map((tier) => `tier ${tier}`).join(" · ") : "tier unavailable";
    // The organizer's count next to what was actually found. "2 / 3" is the
    // only number that says whether the round is finished, and it is the
    // question the operator asks first.
    const known = Number(job.live_fire_known_vulnerabilities) || 0;
    const found = Array.isArray(job.live_fire_vulnerabilities)
      ? job.live_fire_vulnerabilities.length : 0;
    const countText = known
      ? `<span class="live-fire-count${found >= known ? " is-met" : ""}"
              title="patched / announced by the organizer">${found} / ${known}</span>`
      : "";
    const downloads = job.status === "finished" ? `
      <div class="live-fire-downloads">
        <a href="${API}/jobs/${encodeURIComponent(jobId)}/file/patched.zip" download>⬇ patched.zip</a>
        <a href="${API}/jobs/${encodeURIComponent(jobId)}/file/report.md" download>⬇ report.md</a>
        <a href="${API}/jobs/${encodeURIComponent(jobId)}/file/verification.json" download>⬇ verification.json</a>
      </div>` : "";
    // Interim snapshots are deliberately OUTSIDE the `status === "finished"`
    // guard above. A defence contest submits on a tick, and a fix that exists
    // at minute three was undeliverable until the job ended, which is the
    // whole reason the loop now publishes per attempt. Hiding them until the
    // end would give that back.
    return `<div class="live-fire-outcome ${stateClass}">
      <div><strong>${state}</strong><span>${escapeHtml(tierText)}</span>${countText}</div>
      <small>${state === "READY"
        ? "Machine gates passed; review before manual upload."
        : state === "UNVERIFIED"
          ? "Diagnostic ZIP only — do not treat as deployable."
          : "Patch and machine verification are still running."}</small>
      ${downloads}
      <div class="live-fire-agents" data-job="${escapeHtml(jobId)}" hidden>
        <div class="live-fire-agents-head">
          🛰️ agent 현황 <small>— 지금 누가 무엇을 하고 있는지</small>
        </div>
        <div class="live-fire-agents-grid"></div>
      </div>
      <div class="live-fire-vulns" data-job="${escapeHtml(jobId)}" hidden>
        <div class="live-fire-vulns-head">
          🎯 식별된 취약점 <small>— plan agent가 찾는 즉시</small>
        </div>
        <div class="live-fire-vulns-list"></div>
      </div>
      <div class="live-fire-progress" data-job="${escapeHtml(jobId)}"
           data-source="${escapeHtml(job.filename || "")}" hidden>
        <div class="live-fire-progress-head">${
          // The two engines publish on different terms and the label has to
          // say which: v1 emits per attempt before any check, v2 only after
          // the integrated bundle passes the validator. One sentence for both
          // was wrong for whichever job you were looking at.
          Number(job.live_fire_version) === 2
            ? `⚡ 패치 통합본 <small>— 취약점이 통합될 때마다, validator 통과 후</small>
               <button type="button" class="live-fire-fix" data-job="${escapeHtml(jobId)}"
                       title="기록한 operator feedback과 SLA 결과를 근거로 같은 job에서 패치 사이클을 한 번 더 돌립니다">
                 🔧 FIX
               </button>`
            : `⚡ 패치 스냅샷 <small>— 시도마다 즉시, 검증 전</small>`}
        </div>
        <div class="live-fire-progress-list"></div>
      </div>
    </div>`;
  }

  let resultBlock = liveFireOutcomeHtml(job, id);
  if (["finished", "running", "no_flag", "flag_ready", "failed", "stopped",
       "hold"].includes(job.status)) {
    // The per-artifact link list is gone. It hard-coded one filename per
    // module (`exploit.py.stdout`, `solver.py.stdout`, …) while the runner
    // names artifacts after the script it actually ran — so a crypto Sage job
    // produced `solver.sage.stdout` and every stdout/stderr link 404'd on a
    // file that was sitting right there. Browsing the directory removes the
    // guess entirely: whatever the run wrote is what is listed.
    //
    // `failed` and `stopped` are here because they are the statuses where an
    // operator most needs to look. A failed job had its retry button gated on
    // the MODULE and its file browser gated on the STATUS, so a failed misc
    // job (fd5bb1470319, 2026-08-25) rendered a panel with neither: no way to
    // rerun it and no way to see what it had written before it died. Both
    // halves of that were wrong independently. A job that failed still has a
    // ./work/ tree, and it is the tree worth reading.
    resultBlock += `
      <div class="job-files" data-job="${escapeHtml(id)}">
        <div class="job-files-bar">
          <span class="job-files-crumbs"></span>
          <button type="button" class="btn btn-sm job-files-refresh">Refresh</button>
          <a href="/terminal?job_id=${encodeURIComponent(id)}" target="_blank"
             class="job-files-terminal">⌨ open terminal</a>
        </div>
        <div class="job-files-list"></div>
      </div>
      <div class="flag-grain" data-job="${escapeHtml(id)}" hidden>
        <div class="flag-grain-bar">
          <span class="flag-grain-title">flag_grain</span>
          <span class="flag-grain-count"></span>
        </div>
        <div class="flag-grain-list"></div>
      </div>`;
  }

  // Job facts as labelled chips rather than one `·`-joined sentence. Same
  // fields, same order; the difference is that a chip can be found by shape.
  // In a 1600px-wide modal the old line ran the full width and every value sat
  // at a different x on every job, so reading "which model was this?" meant
  // parsing the whole string left to right.
  const _metaChip = (k, v, title = "") =>
    `<span class="job-meta-chip"${title ? ` title="${escapeHtml(title)}"` : ""}
      ><b>${escapeHtml(k)}</b>${escapeHtml(String(v))}</span>`;

  // Elapsed (running) / duration (terminal). Now rendered as a
  // standalone badge next to the status pill so it doesn't get
  // buried at the end of the small meta line. The running variant
  // is also driven by a tiny per-second interval (see further down)
  // independent of the 2-second poll re-render.
  let timingPill = "";
  if (job.started_at) {
    const start = new Date(job.started_at).getTime();
    const end = job.finished_at ? new Date(job.finished_at).getTime() : Date.now();
    const sec = Math.max(0, Math.round((end - start) / 1000));
    const fmt = (s) => {
      if (s < 60) return `${s}s`;
      if (s < 3600) return `${Math.floor(s/60)}m ${s%60}s`;
      const h = Math.floor(s/3600); const m = Math.floor((s%3600)/60);
      return `${h}h ${m}m`;
    };
    if (job.finished_at) {
      timingPill = `<span class="timing-pill done" title="started ${escapeHtml(job.started_at)}\nfinished ${escapeHtml(job.finished_at)}">⏱ ${fmt(sec)}</span>`;
    } else if (job.status === "running") {
      // No number here: `_tickLivePill` writes it into this text node every
      // second. Baking it in too made the polled html differ on every tick
      // and rebuilt the whole modal to move one digit.
      timingPill = `<span class="timing-pill live" data-started-at="${escapeHtml(job.started_at)}" title="started ${escapeHtml(job.started_at)}">⏱ <span class="timing-tag">running</span></span>`;
    } else if (job.status === "queued") {
      timingPill = `<span class="timing-pill queued">⏱ queued</span>`;
    }
  }

  // A liveness chip used to live here (active / silent / warming / dead) and
  // was REMOVED, not moved. Measured on job e601cd358ad6 — 3303 agent events
  // over 5.7 h — the agent's emission gaps have a median of 0 s but a p99 of
  // 121 s and a max of 16 min, and eighteen silences over five minutes account
  // for 52% of the run. Time-weighted, a perfectly healthy job showed amber
  // "silent" 75.3% of the time and green "active" only 24.7%. A warning colour
  // that is the normal state for three quarters of a run is not a signal, and
  // no single threshold can separate "thinking" from "stuck" on a distribution
  // that skewed.
  //
  // The one genuinely actionable state, "dead", was also the least trustworthy:
  // it keyed on `rq:worker:<name>`, which answers "is the process called
  // htct-sN-w0 alive?" — a name permanently bound to a slot and reused by every
  // job that runs there — not "is THIS job alive?". After a work horse is
  // SIGKILLed without writing a terminal status, the slot's container returns
  // under the same name and heartbeats every 30 s, so the chip would show
  // silent/warming forever and never dead.
  //
  // Whether a job is still going is answered by the run log and the monitor
  // feed, both of which are already on screen.

  // What DOES belong here is the underlying fact, stated without a verdict.
  // The chip above failed because it CLASSIFIED — it painted a warning colour
  // on a distribution whose normal state is silence. Age alone classifies
  // nothing, and the operator reads liveness from the one event the chip could
  // never show: the counter RESETTING to 0s. A number that snaps back is proof
  // the stream is alive; a number that keeps climbing is the raw fact, not an
  // accusation. So: no colour, no threshold, no label — deliberately.
  //
  // Measured on THIS UI's own data, job 729c62380722 while healthy: an 8m05s
  // gap between agent events (09:33:26 → 09:41:31) with run.log silent the
  // whole time. Gaps that long are ordinary — heap/crypto synthesis runs 15-40
  // min silent (memory opus-long-think-not-wedged). The tooltip says so,
  // because a bare "8m" invites exactly the panic the old chip trained.
  //
  // NO FALLBACK when the field is absent. During the pre-agent `analyze` phase
  // nothing writes it, and every chain that substituted started_at / updated_at
  // ended up measuring "time since the job started" — which crosses any
  // threshold on literally every job. That is the bug that put Stop AND Retry
  // on screen at once (43d896f). Absent means render nothing.
  let agentPill = "";
  if (job.status === "running" && job.last_agent_event_at) {
    const agentSec = Math.max(0, Math.round(
      (Date.now() - new Date(job.last_agent_event_at).getTime()) / 1000));
    // NOT THE TIMESTAMP EITHER. `data-agent-at` carries
    // `last_agent_event_at`, which moves every five seconds, and it was
    // enough on its own to make this string differ on every poll — so the
    // WHOLE modal was rebuilt, 114ms at a time, to change an attribute
    // nobody can see. Measured with `__htmlDiff()`, after four visible
    // values had already been pulled out and it still rebuilt.
    // `_paintVolatile` writes the attribute and the title in place; the
    // per-second ticker reads it from there.
    agentPill = `<span class="agent-pill" data-live-agent="${id}"></span>`;   // no number: _tickLivePill writes it every second
  }

  // Agent-count pill — the same reading the Timeline meta bar carries, on the
  // job header where no view can hide it.
  //
  // The meta bar lives INSIDE renderGptTimeline, and which of the two GPT
  // views is showing comes from `gptLogView`, which is persisted in
  // localStorage. An operator whose last choice was "log" therefore never
  // sees it — reported as "agent 개수가 ui에 안보여" while the API was
  // returning the count correctly the whole time. "How many agents are
  // running" is a question about the JOB, so it belongs beside the elapsed
  // and liveness pills that are always on screen.
  let agentsPill = "";
  const _act = gptTimelinePayload && gptTimelinePayload.activity;
  if (_act && job.status === "running") {
    const _r = Number(_act.running || 0);
    const _d = Number(_act.delegations || 0);
    const _w = !!_act.main_waiting;
    const _roles = Array.isArray(_act.running_roles) ? _act.running_roles : [];
    const _kids = Array.isArray(_act.children) ? _act.children : [];
    const _ka = Number(_act.children_active || 0);
    agentsPill = `<span class="agent-count-pill${_w ? " waiting" : (_r ? " live" : "")}"
      title="${escapeHtml(
        (_roles.length ? "실행 중 역할: " + _roles.join(", ") : "실행 중인 역할 없음")
        + "\n" + (_kids.length
            ? "자식 에이전트 " + _kids.length + "개 (활성 " + _ka + "): "
              + _kids.map(function (c) { return c.name + "=" + c.status; }).join(", ")
            : (_act.spawns_observable === false
                ? "자식 명단 미확인: Codex CLI가 spawn 이벤트를 내보내지 않습니다."
                  + " main이 `list_agents`를 호출하면 여기에 표시됩니다."
                : "위임된 자식 에이전트: " + _d + "건"))
        + "\n\n역할 카드는 같은 역할의 자식을 한 장으로 합치므로, 위임 건수가 "
        + "실행 중 역할 수보다 클 수 있습니다."
        + (_w ? "\n\nmain이 자식 응답을 기다리는 중입니다 (그동안 main은 일하지 않습니다)." : ""))}"
      >🤖 ${_r}${_kids.length ? " · 자식 " + _ka + "/" + _kids.length
          : ((_act.spawns_observable !== false && _d) ? " · 위임 " + _d : "")}${_w ? " · 대기" : ""}</span>`;
  }

  // Live token meter — reflects meta.agent_tokens (Anthropic usage,
  // SUMMED across turns; cache_read is per-call too so we sum it as
  // well). Hidden until at least one token has been observed.
  let tokensPill = "";
  const tk = job.agent_tokens || {};
  const ti = +tk.input_tokens || 0;
  const to = +tk.output_tokens || 0;
  const tcc = +tk.cache_creation_input_tokens || 0;
  const tcr = +tk.cache_read_input_tokens || 0;
  const turns = +job.agent_turns || 0;
  const tTotal = ti + to + tcc + tcr;
  if (tTotal > 0) {
    const fmtN = (n) => {
      if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + "M";
      if (n >= 1_000)     return (n / 1_000).toFixed(1) + "k";
      return String(n);
    };
    const cost = typeof job.cost_usd === "number"
      ? ` · $${job.cost_usd.toFixed(4)}` : "";
    const turnTag = turns > 0 ? ` · ${turns}t` : "";
    const fullTitle =
      `summed across ${turns} turns:\n` +
      `  input (fresh):  ${ti.toLocaleString()}\n` +
      `  output:         ${to.toLocaleString()}\n` +
      `  cache create:   ${tcc.toLocaleString()}\n` +
      `  cache read:     ${tcr.toLocaleString()}` +
      (typeof job.cost_usd === "number" ? `\n  cost:           $${job.cost_usd.toFixed(6)}` : "");
    // Δ since previous poll — gives the run-log footer a live
    // "↓ X tokens" counter like Claude Code's status line. Cache
    // bumps usually dwarf output (per-turn input is mostly cached
    // prompt + tool results), so we surface both arrows separately.
    let deltaTag = "";
    if (job.status === "running") {
      const prev = _prevTokens[id];
      const turnsRegressed = prev && prev.turns != null && turns < prev.turns;
      if (prev && !turnsRegressed) {
        const dCache = tcr - (prev.cache_read || 0);
        const dOut = to - (prev.output || 0);
        const dIn = ti - (prev.input || 0);
        const upTotal = dCache + dIn;
        const parts = [];
        if (dOut > 0) parts.push(`↓${fmtN(dOut)}`);
        if (upTotal > 0) parts.push(`↑${fmtN(upTotal)}`);
        if (parts.length) deltaTag = ` <span class="tokens-delta">(${parts.join(" ")})</span>`;
        else                 deltaTag = ` <span class="tokens-delta idle">(idle)</span>`;
      }
      _prevTokens[id] = { cache_read: tcr, output: to, input: ti, turns };
    } else {
      delete _prevTokens[id];
    }
    // Always show cache_read — for prompt-cache-heavy runs it's
    // where almost all the input lives.
    tokensPill = `<span class="tokens-pill" title="${escapeHtml(fullTitle)}">📊 in ${fmtN(ti)} · out ${fmtN(to)} · cache ${fmtN(tcr)}${turnTag}${cost}${deltaTag}</span>`;
  }

  // The soft-timeout decision banner was removed with the watchdog that fed
  // it (2026-07-30): nothing sets meta.awaiting_decision any more, so this
  // block could never render. `timeoutBlock` stays as an empty string so
  // the template that interpolates it is untouched.
  const timeoutBlock = "";

  // Description block: render the original description and any appended
  // `[retry-hint]` segment in a separate, color-coded chip so the user can
  // see at a glance which run is a retry and what hint was used.
  let descBlock = "";
  const rawDesc = (job.description || "").trim();
  if (rawDesc) {
    const marker = "[retry-hint]";
    const idx = rawDesc.indexOf(marker);
    let baseHtml = "";
    let hintHtml = "";
    if (idx === -1) {
      baseHtml = `<pre class="description-text">${escapeHtml(rawDesc)}</pre>`;
    } else {
      const base = rawDesc.slice(0, idx).trim();
      const hint = rawDesc.slice(idx + marker.length).trim();
      if (base) baseHtml = `<pre class="description-text">${escapeHtml(base)}</pre>`;
      if (hint) hintHtml = `
        <div class="description-hint">
          <span class="description-hint-label">retry hint</span>
          <pre class="description-text">${escapeHtml(hint)}</pre>
        </div>`;
    }
    descBlock = `<details class="description-block" open>
      <summary>Description${idx !== -1 ? " <span class=\"description-retry-chip\">retry</span>" : ""}</summary>
      ${baseHtml}${hintHtml}
    </details>`;
  }

  // Run-now button: show whenever the job dir actually contains a runnable
  // script (exploit.py / solver.py / solver.sage). Don't gate on status —
  // even 'failed' jobs sometimes have a usable partial script.
  let runBlock = "";
  const isExploitableModule = ["web", "pwn", "crypto", "rev"].includes(job.module);
  // Three different questions were being answered by that one list, and the
  // answers are not the same set:
  //   canRetry  — can the backend rebuild this job? Mirrors _RETRYABLE_MODULES
  //               in api/routes/retry.py. web3 was supported there all along
  //               and hidden here; forensic and misc are supported as of their
  //               respective changes. misc was the last one out, and for a
  //               real reason rather than an oversight: its passphrase reached
  //               the orchestrator only as an RQ argument, so a rebuilt job
  //               could not open the archive. The passphrase now lives on the
  //               job-secrets rail and retry children inherit it.
  //   canContinue — can it fork the prior conversation in place? forensic can
  //               be rebuilt but has no session to fork, so this is narrower.
  //   hasTarget — does the module accept a target at all? Every module except
  //               live-fire does as of this change: misc and forensic take one
  //               additively (prompt directive only, no sandbox runner).
  // Keeping them separate is what stops the next module from inheriting a
  // gate that was never about it.
  const canRetry = ["web", "pwn", "crypto", "rev", "web3", "forensic", "misc"]
    .includes(job.module);
  //   canContinue — can the backend FORK this job's conversation in place?
  //               Not the same question as canRetry, and reusing canRetry for
  //               it drew a Continue button on finished forensic cards that the
  //               server answers with 400. /retry rebuilds forensic from its
  //               image; /continue would have to resume a provider session, and
  //               forensic's orchestrator builds none — it restarts at the
  //               collector. Mirrors _CONTINUABLE_MODULES in api/routes/retry.py.
  // Written out, not "canRetry minus forensic": a new retryable module must
  // not become continuable just by being added to canRetry. Mirrors
  // _CONTINUABLE_MODULES in api/routes/retry.py, and the parity between
  // them is asserted in scripts/test_dashboard_ui.js.
  const canContinue = ["web", "pwn", "crypto", "rev", "web3"]
    .includes(job.module);
  const hasTarget = ["web", "pwn", "crypto", "rev", "web3", "misc", "forensic"]
    .includes(job.module);
  // Retry is offered for every TERMINAL status on an exploitable module
  // — including 'finished' with a flag, so the user can rerun against a
  // suspect / placeholder flag or grab additional flags. The reviewer
  // path is still useful in that case ("the captured value looks like a
  // dummy — find the real flag").
  // TERMINAL ONLY — deliberately no "looks orphaned" escape hatch here.
  // There was one: `running` also qualified when the newest of
  // last_agent_event_at / updated_at / started_at was over 3 minutes old.
  // It fired on healthy jobs constantly, which is how a panel ends up showing
  // Stop AND Retry at once (showStopResume below is true for every running
  // job, and the two are computed independently):
  //   * nothing writes meta during the pre-agent `analyze` phase, so
  //     updated_at stays pinned to started_at and last_agent_event_at does
  //     not exist yet — the fallback chain then measures "time since the job
  //     started" and crosses 3 min at T+3min on literally every job;
  //   * a healthy agent is routinely silent far longer than 3 minutes.
  // Job 476158d89fc1, measured live: status=running, stage=analyze,
  // updated_at == started_at 443s ago, last_agent_event_at absent — while
  // rq_status=started and the worker heartbeat was 24s old. The job was
  // fine; the panel lied. (235ee5080a6a read identically earlier.)
  // Removing it costs no capability: a running job already offers ■ Stop and
  // ↻/✋ Stop & resume, and the resume backend halts the source job first —
  // exactly what a genuinely orphaned job needs. It also stops rendering
  // 💬 Continue on running jobs, which the backend 409s anyway.
  // If a real orphan affordance is ever wanted, key it on rq_status plus the
  // WORKER heartbeat (both already in the payload), never on updated_at.
  // `hold` earns a place here even though the run did not fail: the loop
  // parked itself on a dead remote and exited with the work tree and session
  // intact, so the way out is exactly what these buttons do. Continue is the
  // one that fits — its form already carries a "New target" field for the
  // restarted-instance-on-a-new-port case, which IS the hold case. Without
  // hold in this list a held job offers no way back at all: Change target
  // writes meta and nothing reads it until something re-runs the job.
  const showRetry = canRetry && [
    "failed", "no_flag", "finished", "stopped", "flag_ready", "hold",
  ].includes(job.status);
  // Stop & resume: only meaningful while the job is still in flight.
  const showStopResume = isExploitableModule && (
    job.status === "queued" || job.status === "running"
  );
  // Pure stop: halt a live job of ANY module WITHOUT deleting it or forking a
  // resume — keeps the record + ./work/ artifacts, just stops the work.
  const showStop = job.status === "queued" || job.status === "running";
  // Steering needs a LIVE session to inject into. "queued" is excluded on
  // purpose: the work tree does not exist yet, so the message would have
  // nowhere to sit and the api answers 400.
  const showSteer = job.status === "running";
  // "Change target" needs BOTH halves to be true, and they are no longer the
  // same set. PATCH /target has no module gate, so the request would succeed
  // anywhere; the gate is whether anything READS the value back, because a
  // button that writes meta and changes no behaviour is the decorative-field
  // defect the web docker_challenge round was about.
  // misc used to fail that test — no retry, no resume, no sandbox run — and
  // now passes it: modules/misc/orchestrator.py:188 reads target_url from META
  // rather than from a run_job argument precisely so a /retry or a PATCH
  // /target reaches the agent, and misc has a retry as of this change. So misc
  // gaining the button here is the gate working, not the gate leaking.
  // Visible at any status.
  const showChangeTarget = hasTarget && canRetry;
  if (
    job.runnable_script || job.exploit_present || job.solver_present
    || showRetry || showStopResume || showChangeTarget || showStop
  ) {
    const scriptName = job.runnable_script || (job.exploit_present ? "exploit.py" : "solver.py");
    // A script whose required sibling is absent exits on its second statement.
    // The button used to promise a run either way; say so instead of letting
    // the operator find out from an empty sandbox log.
    const missingDeps = Array.isArray(job.script_missing) ? job.script_missing : [];
    const runHtml = (job.runnable_script || job.exploit_present || job.solver_present)
      ? `<button class="run-now-btn" data-action="run"${missingDeps.length
            ? ` title="${escapeHtml(scriptName)} requires ${escapeHtml(missingDeps.join(", "))}, which ${missingDeps.length > 1 ? "are" : "is"} not in the job dir — it will exit immediately"` : ""
         }>▶ Run ${escapeHtml(scriptName)} in sandbox</button>${
           missingDeps.length
             ? `<span class="script-scaffold">scaffold · missing ${escapeHtml(missingDeps.join(", "))}</span>`
             : ""}`
      : "";
    const retryHtml = showRetry
      ? `<button class="retry-btn" data-action="retry">↻ Retry with reviewer hint</button>
         <button class="retry-btn retry-manual-open-btn" data-action="retry-manual">✏ Retry with my hint</button>` : "";
    // Continue-in-place: same job/cwd/session + an operator note. For when the
    // agent solved it but was blocked on an external action (instance restart,
    // remote back up). NOT a retry — no re-investigation.
    const continueHtml = showRetry && canContinue
      ? `<button class="retry-btn continue-open-btn" data-action="continue">💬 Continue (operator note)</button>` : "";
    // Hold is the one status whose next action is not a judgement call: the
    // remote died, the operator replaced it, the run should carry on. Making
    // that the fifth field of a dialog is what sent an operator to Change
    // target instead — which writes meta and resumes nothing, exactly as
    // documented, and therefore looked like the button had no effect.
    //
    // The target is passed as a data attribute and NOT interpolated into the
    // title as raw text: escapeHtml covers & < > and not quotes, and a URL is
    // allowed to contain one.
    const _resumeTarget = encodeURIComponent(job.target_url || "");
    const resumeHoldHtml = (job.status === "hold" && canContinue)
      ? `<button class="retry-btn resume-hold-btn" data-action="resume-hold"
            data-target="${_resumeTarget}"
            title="${escapeHtml(job.target_url || "(meta.target_url)")} 로 같은 세션을 이어서 실행합니다. work tree와 SDK 세션은 그대로 유지되고, 재조사는 하지 않습니다."
         >▶ 재개 (현재 타겟으로)</button>` : "";
    const stopResumeHtml = showStopResume
      ? `<button class="retry-btn retry-stop-resume-btn" data-action="stop-resume-reviewer">↻ Stop &amp; resume with reviewer hint</button>
         <button class="retry-btn retry-stop-resume-btn" data-action="stop-resume">✋ Stop &amp; resume with my hint</button>` : "";
    // Pure stop — halt only, keep everything (no delete, no resume).
    const stopHtml = showStop
      ? `<button class="stop-job-btn" data-action="stop" title="Halt this job but KEEP the record + ./work/ artifacts (not deleted, not resumed)">■ Stop</button>` : "";
    // Stop the RUN, not the job. Offered whenever the job is running: the
    // route refuses otherwise, and a stop filed while nothing is executing is
    // discarded when the next run starts rather than killing it.
    // A request stays visible for a few seconds: the runner polls every 2s,
    // so this is the window where the operator would otherwise see nothing.
    const _stopPending = job.status === "running"
      && (Date.now() - (_runnerStopAt[id] || 0)) < 12000;
    const runnerStopHtml = job.status === "running"
      ? `<button class="retry-btn runner-stop-btn" data-action="runner-stop"
            ${_stopPending ? "disabled" : ""}
            title="현재 샌드박스 실행만 중단합니다. job은 계속되고, 중단했다는 사실이 postjudge에 전달되어 main 턴으로 돌아갑니다."
         >${_stopPending ? "⏹ 중단 요청됨 — 러너가 곧 멈춥니다" : "⏹ 이 실행만 중단"}</button>` : "";
    const targetHtml = showChangeTarget
      ? `<button class="retry-btn change-target-btn" data-action="change-target">✎ Change target</button>` : "";
    // Steer: the only control on this row that changes a RUNNING job without
    // ending it. Everything else halts the session or starts a new one.
    const steerHtml = showSteer
      ? `<button class="retry-btn steer-open-btn" data-action="steer" title="Send one instruction into this running job. Delivered at the next turn boundary — it does NOT stop the run or lose the session.">🧭 Steer</button>` : "";
    const helperBits = [];
    if (stopHtml) helperBits.push("stop = halt this run, keep the job + ./work/ (no delete, no resume)");
    if (runHtml) helperBits.push("re-runs the produced script");
    if (retryHtml) helperBits.push("reviewer hint = Claude diagnoses the failure · my hint = you write the hint yourself");
    if (stopResumeHtml) helperBits.push("stop & resume = halt this job, carry over ./work/, and start fresh with a reviewer-written or hand-written hint");
    if (targetHtml) helperBits.push("change target = update only meta.target_url; no retry, no resume");
    if (resumeHoldHtml) helperBits.push("재개 = 현재 meta.target_url 로 같은 세션을 이어서 실행 (Continue와 같은 경로, 메모는 자동 작성)");
    if (steerHtml) helperBits.push("steer = one instruction into the RUNNING session at its next turn boundary (no stop, no restart)");
    // "Fresh context" toggle — applies to any retry/resume launched from this
    // panel. When checked, the new job carries ./work/ + the hint but does NOT
    // fork the prior SDK conversation, so a deep retry chain can't accumulate
    // context until "Prompt is too long". id is job-scoped so each card is
    // independent.
    const freshToggleHtml = (showRetry || showStopResume)
      ? `<label class="fresh-toggle" title="Start the retry with a clean Claude context (carry ./work/ + hint, but do NOT fork the prior conversation). Use on deep retry chains that hit 'Prompt is too long'.">
           <input type="checkbox" class="fresh-ctx-cb" id="fresh-ctx-${job.id}">
           <span class="fresh-box" aria-hidden="true"></span>
           <span class="fresh-label">✨ fresh context</span>
         </label>` : "";
    runBlock = `<div class="retry-row" style="margin:0.5rem 0">
      ${runnerStopHtml}${stopHtml} ${steerHtml} ${resumeHoldHtml} ${runHtml} ${targetHtml} ${retryHtml} ${continueHtml} ${stopResumeHtml}
      ${freshToggleHtml}
      <small style="color:var(--fg-muted)">${helperBits.join(" · ")}</small>
    </div>`;
  }

  // The operator's true/false-positive call. Two entry points, one banner:
  //   flag_ready — the run recorded candidates but promoted none, and is
  //                waiting. This is the case job f24519394073 needed: a real
  //                remote capture that read as a plain miss because nothing
  //                asked.
  //   finished   — a flag WAS promoted automatically. It can still be wrong
  //                (8d132bba21fc and its two retry children all read finished
  //                while carrying an answer later ruled wrong), so "wrong"
  //                stays available. There is no "ok" here: the job already
  //                says ok, and a second confirmation would only add a click.
  // A `finished` job gets per-value buttons too. The banner used to argue
  // that a second confirmation there adds only a click — true while the list
  // holds one value, false the moment it holds two that cannot both be right.
  let verdictBlock = "";
  const verdictValues = (job.flags && job.flags.length)
    ? job.flags
    : (job.flag_candidates || []);
  if (job.status === "flag_ready" || (job.status === "finished" && verdictValues.length)) {
    const awaiting = job.status === "flag_ready";
    const rejected = job.flag_rejected || [];
    verdictBlock = `<div class="verdict-banner${awaiting ? " verdict-banner--awaiting" : ""}"
                         data-job="${escapeHtml(id)}">
      <h4>${awaiting ? "⚑ Is this the flag?" : "🚩 Recorded flag"}</h4>
      <div class="verdict-values">${
        verdictValues.map((v) => (verdictValues.length > 1)
          ? `<span class="verdict-pick"><code>${escapeHtml(String(v))}</code
             ><button class="verdict-btn verdict-ok verdict-pick-btn"
                      data-verdict="ok" data-flag="${escapeHtml(String(v))}"
               >${awaiting ? "✓ 이 값이 정답" : "✓ 이 값만 남기기"}</button></span>`
          : `<code>${escapeHtml(String(v))}</code>`).join("")
      }</div>
      ${awaiting
        ? `<div class="verdict-why">The run produced this but could not reproduce it
             in the sandbox, so it was not registered automatically. Only you can
             say whether it is the real flag.</div>` : ""}
      <div class="verdict-actions">
        ${awaiting && verdictValues.length <= 1
          ? `<button class="verdict-btn verdict-ok" data-verdict="ok">✓ Ok — this is the flag</button>` : ""}
        <button class="verdict-btn verdict-wrong" data-verdict="wrong"
          >✗ Wrong${awaiting ? "" : " — retry this job"}</button>
      </div>
      ${rejected.length
        ? `<div class="verdict-rejected">already ruled out: ${
             rejected.map((v) => `<code>${escapeHtml(String(v))}</code>`).join(" ")
           }</div>` : ""}
      <div class="verdict-status" aria-live="polite"></div>
    </div>`;
  }

  let errorBlock = "";
  if (job.error_kind === "policy_refusal") {
    errorBlock = `<div class="refusal-banner">
      <h4>⚠ Claude Usage Policy refusal</h4>
      <div>The agent stopped mid-job because Claude refused to continue.
        Try switching the model in <strong>Settings → Claude model</strong> to
        <code>claude-sonnet-4-6</code> and re-run the job. Sonnet often
        completes CTF tasks where Opus declines.</div>
    </div>`;
  } else if (job.error) {
    errorBlock = `<div class="refusal-banner">
      <h4>⚠ Job error (${escapeHtml(job.error_kind || "unknown")})</h4>
      <div><code>${escapeHtml(String(job.error).slice(0, 400))}</code></div>
    </div>`;
  }

  // Three facts the platform already recorded and never showed. Each is the
  // reason the job is where it is, and each was reachable only by opening a
  // file on the box:
  //   hold_reason        — which remote died. The operator needs it to pick
  //                        the replacement, which is the whole point of hold.
  //   blocked_reason     — the agent's own "I am structurally blocked": every
  //                        module is told to write it, only judge-laddered
  //                        ones had a reader.
  //   report_phase_error — the report step threw; the run looked clean.
  if (job.hold_reason) {
    errorBlock += `<div class="refusal-banner hold-banner">
      <h4>⏸ Held — waiting for a new remote target</h4>
      <div><code>${escapeHtml(String(job.hold_reason).slice(0, 600))}</code></div>
      <div style="margin-top:0.35rem;color:var(--fg-muted);font-size:0.85rem">
        The work tree and the agent session are kept. Set the replacement
        address with <strong>✎ Change target</strong>, then press
        <strong>▶ 재개 (현재 타겟으로)</strong> — the run continues from here.
        <strong>💬 Continue</strong> still does the same thing when you want to
        write the note yourself.</div>
    </div>`;
  }
  if (job.blocked_reason) {
    errorBlock += `<div class="refusal-banner blocked-banner">
      <h4>🚧 The agent reported itself blocked</h4>
      <div><code>${escapeHtml(String(job.blocked_reason).slice(0, 600))}</code></div>
      <div style="margin-top:0.35rem;color:var(--fg-muted);font-size:0.85rem">
        Written by the run itself, not inferred. It is a claim, not a verdict —
        but it names what the agent believed it could not get past.</div>
    </div>`;
  }
  if (job.report_phase_error) {
    errorBlock += `<div class="refusal-banner">
      <h4>⚠ The report phase failed</h4>
      <div><code>${escapeHtml(String(job.report_phase_error).slice(0, 400))}</code></div>
    </div>`;
  }

  // Diagnostics the run records and nothing displayed. They are breadcrumbs,
  // not alarms — which is why they are collapsed rather than banners — but
  // "written to meta.json and readable only by opening meta.json" is not the
  // same as recorded. Listed by name so a field added later is a one-line
  // change here instead of another silent write.
  const DIAG = [
    ["agent_effective_effort", "effort actually used"],
    ["flag_trusted_tier", "flag trusted tier"],
    ["worker_mem", "worker memory limit"],
    ["manual_run", "flags set by a manual run"],
    ["resume_skipped_due_to_prompt_profile", "resume skipped (prompt profile)"],
    ["live_fire_stop_reason", "live-fire stop reason"],
    ["live_fire_versions", "live-fire versions"],
    ["agent_provider_label", "provider label"],
    ["agent_session_id", "agent session id"],
  ];
  const diagRows = DIAG
    .filter(([k]) => job[k] !== undefined && job[k] !== null && job[k] !== "")
    .map(([k, label]) => `<li><span class="diag-k">${escapeHtml(label)}</span>`
      + `<code>${escapeHtml(String(
          typeof job[k] === "object" ? JSON.stringify(job[k]) : job[k]).slice(0, 200))}</code></li>`)
    .join("");
  if (diagRows) {
    errorBlock += `<details class="job-diag"><summary>기록된 진단값 `
      + `(${diagRows.split("<li>").length - 1})</summary><ul>${diagRows}</ul></details>`;
  }

  // Forensic-only: log-miner findings panel. Shows category counts so the
  // user can see at a glance whether the run captured anything actionable.
  let logFindingsBlock = "";
  if (job.module === "forensic" && job.log_findings_counts) {
    const c = job.log_findings_counts;
    const cells = [
      ["passwords", c.passwords],
      ["sqli", c.sqli_attempts],
      ["xss", c.xss_attempts],
      ["lfi", c.lfi_attempts],
      ["rce", c.rce_attempts],
      ["auth events", c.auth_events],
      ["flag candidates", c.flag_candidates],
    ];
    const chips = cells
      .filter(([, v]) => typeof v === "number")
      .map(([label, v]) =>
        `<span class="lf-chip ${v > 0 ? "hit" : "zero"}">${escapeHtml(label)}: ${v}</span>`
      ).join(" ");
    const scanned = typeof c.scanned_files === "number"
      ? `<small style="color:var(--fg-muted)">scanned ${c.scanned_files} log/history files</small>` : "";
    logFindingsBlock = `<div class="log-findings-panel">
      <h4>🔎 Log mining</h4>
      <div class="lf-chips">${chips}</div>
      ${scanned}
      <small style="color:var(--fg-muted);margin-left:0.5rem">
        full report: <a href="${API}/jobs/${id}/file/log_findings.json" target="_blank">log_findings.json</a>
      </small>
    </div>`;
  }

  // [FLAG?] — flag candidates spotted live during the run (separate from
  // the curated 🚩 Flag found). Lets the operator submit fast in a CTF
  // while the job is still running. Hide ones already promoted to flags.
  let candBlock = "";
  const cands = (job.flag_candidates || []).filter(
    (c) => !(job.flags || []).includes(c));
  if (cands.length) {
    const rows = cands.map((f) =>
      `<div class="flag-row">
         <code>${escapeHtml(f)}</code>
         <button class="copy-btn" data-flag="${escapeHtml(f)}">Copy</button>
       </div>`).join("");
    candBlock = `<div class="flag-cand-banner">
        <h4>🏁 <span class="flag-q">[FLAG?]</span>
          <small>candidate(s) spotted mid-run — verify &amp; submit (not yet confirmed)</small>
        </h4>
        ${rows}
      </div>`;
  }

  let flagBlock = "";
  if (job.flags && job.flags.length) {
    const multiFlags = job.flags.length > 1;
    const rows = job.flags.map((f, i) =>
      `<div class="flag-row">
         <code id="flag-${id}-${i}">${escapeHtml(f)}</code>
         <button class="copy-btn" data-flag="${escapeHtml(f)}">Copy</button>
         <button class="flag-del-btn" data-job-id="${id}" data-flag-index="${i}" title="Delete this flag entry">🗑️ delete</button>
         ${multiFlags ? `<button class="flag-keep-btn" data-job-id="${id}" data-flag-index="${i}" title="Delete every OTHER flag, keep only this one">📌 keep only this</button>` : ""}
       </div>`).join("");
    const dummyHint = multiFlags
      ? `<small class="flag-hint">여러 flag가 캡처됨 — dummy는 🗑️로 지우거나, 진짜 flag에서 📌 keep only this 를 누르세요.</small>`
      : "";
    // Save-to-exploit-DB button. Only shown for terminal-success jobs
    // (the API also rejects no-flag jobs with 400). The button calls
    // POST /api/exploits/save with operator-supplied tags + notes.
    const saveBtn = (job.status === "finished")
      ? `<button class="exp-save-btn" data-job-id="${id}" title="Copy report.md + exploit.py into the Exploit Library (Phase: operator-curated)">💾 Save to exploit DB</button>`
      : "";
    flagBlock = `<div class="flag-banner">
        <h4>🚩 Flag${job.flags.length > 1 ? "s" : ""} found ${saveBtn}</h4>
        ${dummyHint}
        ${rows}
      </div>`;
  }

  // Multi-target jobs carry target_urls (primary first); show "+N" next to the
  // primary and the full list as a hover title so the operator can confirm all
  // their targets registered.
  const _tgts = Array.isArray(job.target_urls) ? job.target_urls.filter(Boolean) : [];
  const targetExtra = _tgts.length > 1
    ? ` <span class="target-more" title="${escapeHtml(_tgts.join("\n"))}">+${_tgts.length - 1} more</span>`
    : "";

  // The detail HTML is rebuilt on every poll. Re-creating the file browser with
  // it made a healthy job flash `Loading…` every couple of seconds and threw
  // away the list's scroll position mid-read. Keep the LIVE node and move it
  // into the rebuilt tree instead. Guarded on `data-job`: there is a separate
  // `detail.innerHTML = ""` for job switches, and an unguarded adoption would
  // drop job A's directory into job B's panel.
  const _keptFiles = detail.querySelector(`.job-files[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  // Same treatment for flag_grain, and for a sharper reason than scroll: the
  // rebuilt markup starts `hidden` with an empty list, and mountFlagGrain only
  // unhides it AFTER an awaited fetch. Without adoption the panel therefore
  // disappears and comes back on every 2 s poll — reported from the operator's
  // screen as "flag grain이 정신없이 주기적으로 깜빡거림" while job
  // 04ddd2ead5a1 was running. Carrying the live node makes the repaint
  // unnecessary: the cache guard in mountFlagGrain can finally see children and
  // skip, which is the state it was always written for and never reached.
  const _keptGrain = detail.querySelector(`.flag-grain[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  // And the patch-snapshot list, which is the same failure a third time —
  // reported as "패치 스냅샷 UI가 지속적으로 깜빡거리는데". The rebuilt markup
  // starts `hidden` with an empty list and only fills after an awaited fetch,
  // so on a live-fire job the panel vanished and returned every 2 s. It has a
  // reason of its own to be carried: the rows hold number INPUTS the operator
  // types the round's score into, and a replaced node loses the caret and the
  // half-typed value with it.
  const _keptProgress = detail.querySelector(`.live-fire-progress[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  // Carried across the repaint for the SAME reason the snapshot panel is:
  // renderJob rebuilds detail.innerHTML every couple of seconds, so a panel
  // filled by an awaited fetch would be thrown away and refetched on every
  // tick — which is exactly the flicker the operator reported.
  const _keptVulns = detail.querySelector(`.live-fire-vulns[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);

  // Skip the whole rebuild when nothing rendered differently. The poller runs
  // every 2s and re-assigns detail.innerHTML unconditionally, which re-parses
  // ~300 KB of markup and then forces every restoration below (log scroll, SDK
  // panel HTML, modal scroll, adopted .job-files) to undo the damage. When the
  // agent is quiet — and always, once a job is terminal — the new markup is
  // byte-identical to what is already on screen, so none of that work buys
  // anything. Compare first; assign only on a real change.
  const _nextHtml = `
    <h3>Job <span class="jobid-text">${job.id}</span><button class="copy-jobid-btn" data-jobid="${job.id}" title="Copy job ID">⧉</button>
      <span class="status ${job.status}">${job.status}</span>
      ${timingPill}${agentPill}${agentsPill}
    </h3>
    <div class="job-meta">
      ${job.tag ? _metaChip("tag ", job.tag) : ""}
      ${_metaChip("module ", job.module)}
      ${_metaChip("file ", job.filename || "—", job.filename || "")}
      ${_metaChip("target ", job.target_url || "(none)", _tgts.join("\n"))}${targetExtra}
      ${job.stage ? _metaChip("stage ", job.stage) : ""}
      ${job.cost_usd ? `<span class="meta-chip" data-live-cost="${id}">cost </span>` : ""}
      ${job.job_timeout ? _metaChip("timeout ", job.job_timeout + "s") : ""}
      ${job.agent_provider ? _metaChip("agent ", job.agent_provider_label || job.agent_provider) : ""}
      ${job.model ? _metaChip("model ", job.model) : ""}
    </div>
    ${timeoutBlock}
    ${runBlock}
    <!-- Two columns, because the two things an operator wants are never the
         same thing at the same time: while a job RUNS you want the log, and
         once it ENDS you want the flag and the report. In one column each was
         a scroll away from the other, in a modal 1600px wide whose right half
         was empty. Outcome on the left, activity on the right; one column
         again under 1150px. -->
    <div class="job-grid">
      <div class="job-col-outcome">
        ${flagBlock}
        ${candBlock}
        ${verdictBlock}
        ${errorBlock}
        ${descBlock}
        ${logFindingsBlock}
        ${resultBlock}
      </div>
      <div class="job-col-activity">
    <div class="sdk-live" data-job-id="${id}" hidden>
      <div class="sdk-live-head">
        <span class="sdk-live-dot"></span>
        <span class="sdk-live-label">live agent activity</span>
        <button class="sdk-live-toggle" data-action="toggle-sdk-live">hide</button>
      </div>
      <div class="sdk-live-feed"></div>
    </div>
    <h4>${isGptJob ? "GPT activity" : "Run log"} <small style="color:var(--fg-muted);font-weight:normal">(auto-follows when scrolled to bottom)</small></h4>
    <div class="run-log-window" data-view="${activityView}" data-show-tools="${gptTimelineTools ? "1" : "0"}">
      <div class="run-log-titlebar">
        <span class="run-log-dot run-log-dot-r"></span>
        <span class="run-log-dot run-log-dot-y"></span>
        <span class="run-log-dot run-log-dot-g"></span>
        <div class="rl-viewtabs">
          ${isGptJob ? `
            <button class="rl-viewtab ${activityView === "timeline" ? "active" : ""}" data-action="view-gpt-timeline"
                    title="Structured GPT progress and agent state">Timeline</button>
            <button class="rl-viewtab ${activityView === "log" ? "active" : ""}" data-action="view-gpt-log"
                    title="Full raw run log">Raw log</button>
          ` : `
            <button class="rl-viewtab ${claudeLogView === "timeline" ? "active" : ""}" data-action="view-claude-timeline"
                    title="이 세션이 한 일 — 산문과 도구 호출을 읽을 수 있는 흐름으로">Timeline</button>
            <button class="rl-viewtab ${claudeLogView === "monitor" ? "active" : ""}" data-action="view-monitor"
                    title="Curated, LLM-narrated monitor commentary">Monitor</button>
            <button class="rl-viewtab ${claudeLogView === "vuln" ? "active" : ""}" data-action="view-vuln"
                    title="모니터가 실시간으로 추려낸 취약점 — 클릭하면 main이 심층 탐색합니다">Vuln</button>
            <button class="rl-viewtab ${claudeLogView === "log" ? "active" : ""}" data-action="view-log"
                    title="Raw run log">Raw log</button>
          `}
          ${/* Not provider-specific like Monitor/Timeline: every provider
                writes events.jsonl, so every job has a trace. */""}
          <button class="rl-viewtab ${activityView === "trace" ? "active" : ""}" data-action="view-trace"
                  title="이 job이 실제로 걸어간 궤적 — 시도별 시간 분해">궤적</button>
        </div>
        <button class="gpt-tools-toggle" data-action="toggle-gpt-tools"
          title="Timeline에서 일반 tool 호출 표시 전환">${gptTimelineTools ? "도구 숨기기" : "도구 보기"}</button>
        <input class="run-log-search" data-job-id="${id}" type="search"
               spellcheck="false" autocomplete="off"
               placeholder="🔎 filter log…" value="${escapeHtml(_logSearch[id] || "")}" />
        <span class="run-log-search-count" data-job-id="${id}"></span>
        <select class="monitor-lang" data-action="monitor-lang" title="Monitor language">
          <option value="ko" ${monitorLang === "ko" ? "selected" : ""}>한국어</option>
          <option value="en" ${monitorLang === "en" ? "selected" : ""}>English</option>
        </select>
        <button class="run-log-tz-toggle" data-action="toggle-tz"
                title="Toggle timestamps (UTC ↔ ${escapeHtml(_localTzName())})"
        >${runlogTz === "utc" ? "UTC" : "Local"}</button>
      </div>
      ${/* EMPTY ON PURPOSE — painted in place below. These three grow while a
            job runs, and baking them into the hashed html meant every poll
            saw a different string and rebuilt the ENTIRE modal: the panels
            that reconcile themselves row by row were thrown away and redrawn
            two seconds later, which is the flicker the operator kept seeing.
            Each already has an incremental appender for the live stream; the
            poll now goes through the same door. */ ""}
      <div class="gpt-timeline-feed" data-job-id="${id}"></div>
      ${/* Its own container so the 2s poll repaints the trace in place. On a
            running job the open lane grows against the wall clock every tick,
            so emitting it into the hashed markup would rebuild the whole modal
            twice a second — the exact flicker the comment above describes. */""}
      <div class="tr-feed" data-job-id="${id}"></div>
      ${/* Under the flow, not behind a button in another row. Steering used to
            live on a `🧭 Steer` button in the retry row, which is a different
            panel and only appears while the job is running — an operator
            looking at the timeline could not see that the channel existed at
            all. It sits in the STATIC markup so the 2s repaint of the feed
            above cannot wipe what is half-typed. */""}
      <form class="tl-composer" data-job-id="${id}" data-live="${job.status === "running" ? "1" : "0"}">
        <textarea class="tl-composer-text" rows="2" maxlength="4000"
          placeholder="${job.status === "running"
            ? "Message the agent — 다음 턴 경계에서 전달됩니다 (실행을 멈추지 않습니다)"
            : job.status === "queued"
              ? "아직 큐 대기 중입니다 — work 트리가 생기면 보낼 수 있습니다"
              : `job이 ${escapeHtml(job.status || "종료")} 상태라 읽을 세션이 없습니다`}"
          ${job.status === "running" ? "" : "disabled"}></textarea>
        <div class="tl-composer-row">
          <span class="tl-composer-status"></span>
          <button type="submit" class="tl-composer-send"
            ${job.status === "running" ? "" : "disabled"}>보내기</button>
        </div>
      </form>
      <pre class="run-log" data-job-id="${id}" data-status="${escapeHtml(job.status || "")}"></pre>
      <div class="vuln-panel" data-job-id="${id}"></div>
      <div class="monitor-feed" data-job-id="${id}"></div>
      ${tokensPill ? `
      <div class="run-log-footer" data-job-id="${id}"></div>` : ""}
    </div>
      </div>
    </div>
  `;
  const _volatile = {
    log: !showLog ? "" : (log ? _cappedLogHtml(id, log, job.started_at) : "(empty)"),
    gpt: showTimeline ? gptTimelineHTML : null,
    trace: activityView === "trace" ? traceHTML : null,
    monitor: monitorFeedHTML,
    vuln: vulnPanelHTML,
    // Cost climbs with every agent event, on a 5s throttle — often enough
    // that leaving it in the hashed html rebuilt the modal on its own.
    cost: job.cost_usd ? "cost $" + Number(job.cost_usd).toFixed(4) : null,
    // Tokens and their cost climb on every agent event.
    tokens: tokensPill || null,
    agentAt: (job.status === "running" && job.last_agent_event_at)
      ? String(job.last_agent_event_at) : null,
    agentTitle: "Time since the agent's last SDK event.\n\nlast event: "
      + (job.last_event_actor || "main") + " · " + (job.last_event_kind || "?"),
  };
  if (isSameJob && detail.dataset.renderedHtmlLen === String(_nextHtml.length)
      && detail.dataset.renderedHtmlHash === _cheapHash(_nextHtml)) {
    _paintVolatile(id, _volatile);
    // The directory listing still refreshes: files can change while the log
    // is quiet, and loadJobFiles patches rows rather than rebuilding, so it
    // is not part of the cost this skip exists to avoid.
    mountJobFiles(id);
    mountFlagGrain(id);
    mountLiveFireProgress(id);
    mountLiveFireVulns(id);
  mountLiveFireVulns(id);
    mountLiveFireAgents(id);
    return job;
  }
  // WHAT CHANGED. `innerHTML` was still 114ms on every poll after four
  // values had been pulled out of this string, so the string is still
  // differing and reading the template again has not said why. Record the
  // first place the two renders diverge; `__htmlDiff()` prints it.
  try {
    const prev = window.__lastNextHtml;
    if (prev && prev !== _nextHtml) {
      let i = 0;
      while (i < prev.length && i < _nextHtml.length && prev[i] === _nextHtml[i]) i++;
      window.__lastHtmlDiffs = (window.__lastHtmlDiffs || []).slice(-4);
      window.__lastHtmlDiffs.push({
        at: i,
        was: prev.slice(Math.max(0, i - 60), i + 60),
        now: _nextHtml.slice(Math.max(0, i - 60), i + 60),
      });
    }
    window.__lastNextHtml = _nextHtml;
  } catch (_) {}
  detail.dataset.renderedHtmlLen = String(_nextHtml.length);
  detail.dataset.renderedHtmlHash = _cheapHash(_nextHtml);
  _mark(_marks, "build");
  detail.innerHTML = _nextHtml;
  // Same tick as the rebuild, so the three containers are never seen empty.
  _paintVolatile(id, _volatile);
  _mark(_marks, "innerHTML");

  // Spin up the per-second live timer when a running pill is on screen.
  if (job.status === "running") _ensureLivePillTimer();

  // Put the live browser back before anything measures the document. This runs
  // ahead of the scroll restores below on purpose: an adopted list is taller
  // than the empty placeholder it replaces, and restoring `detail.scrollTop`
  // against the shorter document would clamp it — the same trap the SDK panel
  // comment records.
  if (_keptFiles) {
    const _fresh = detail.querySelector(`.job-files[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
    if (_fresh) _fresh.replaceWith(_keptFiles);
  }
  if (_keptGrain) {
    const _freshG = detail.querySelector(`.flag-grain[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
    if (_freshG) _freshG.replaceWith(_keptGrain);
  }
  if (_keptProgress) {
    const _freshP = detail.querySelector(`.live-fire-progress[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
    if (_freshP) _freshP.replaceWith(_keptProgress);
  }
  if (_keptVulns) {
    const _freshV = detail.querySelector(`.live-fire-vulns[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
    if (_freshV) _freshV.replaceWith(_keptVulns);
  }
  // Re-mounted at the directory the operator had navigated to, not at the job
  // root. Same lesson the SDK panel above learned.
  _mark(_marks, "restore");
  mountJobFiles(id);
  mountFlagGrain(id);
  mountLiveFireProgress(id);
  mountLiveFireVulns(id);
  mountLiveFireAgents(id);
  _mark(_marks, "mount");

  // Restore the live SDK panel FIRST — visibility before scroll. The
  // rebuilt markup starts with `hidden`, so if we touched scroll while
  // the panel was hidden the browser would clamp to 0. Same applies to
  // the outer detail.scrollTop below: hidden panel = shorter document
  // = clamped scroll. Sequence: feed content → visibility → collapsed
  // → feed scroll → outer scroll.
  const newSdkPanel = detail.querySelector(".sdk-live");
  if (newSdkPanel) {
    const f = newSdkPanel.querySelector(".sdk-live-feed");
    if (f && prevSdkFeedHTML !== null) {
      f.innerHTML = prevSdkFeedHTML;
    }
    if (prevSdkVisible) newSdkPanel.hidden = false;
    if (_sdkLiveHidden || prevSdkCollapsed) {
      newSdkPanel.classList.add("collapsed");
      const tBtn = newSdkPanel.querySelector('.sdk-live-toggle');
      if (tBtn) tBtn.textContent = "show";
    }
    if (f && prevSdkFeedHTML !== null) {
      // Now that the feed is visible + populated, scrollHeight is real.
      f.scrollTop = prevSdkFeedAtBottom ? f.scrollHeight : prevSdkFeedScroll;
    }
  }

  const newPre = detail.querySelector("pre.run-log");
  if (newPre) {
    if (!isSameJob || prevAtBottom) {
      newPre.scrollTop = newPre.scrollHeight;
    } else {
      newPre.scrollTop = prevScrollTop;
    }
  }
  const newMonFeed = detail.querySelector(".monitor-feed");
  if (newMonFeed) {
    if (!isSameJob || prevMonAtBottom) {
      newMonFeed.scrollTop = newMonFeed.scrollHeight;
    } else {
      newMonFeed.scrollTop = prevMonScrollTop;
    }
  }
  const newTimeline = detail.querySelector(".gpt-timeline-feed .gpt-event-list");
  if (newTimeline) {
    if (!isSameJob || prevTimelineAtBottom) {
      newTimeline.scrollTop = newTimeline.scrollHeight;
    } else {
      newTimeline.scrollTop = prevTimelineScrollTop;
    }
  }
  // Restore the modal-body scroll for same-job re-renders so reading the
  // retry-hint chip / description / result links isn't yanked back to the
  // top every 2 seconds. Runs AFTER the SDK panel visibility restore so
  // the document height matches what it was at capture time.
  if (isSameJob) {
    detail.scrollTop = prevModalScrollTop;
  }

  // Read the per-card "fresh context (no conversation fork)" checkbox.
  const _freshCtx = () => {
    const cb = detail.querySelector(`#fresh-ctx-${id}`);
    return !!(cb && cb.checked);
  };
  // Mirror checked state onto the label as a class, so the chip styles work
  // even on engines without :has() support (older WebKit/Firefox).
  const _freshCb = detail.querySelector(`#fresh-ctx-${id}`);
  if (_freshCb) {
    const _lbl = _freshCb.closest(".fresh-toggle");
    const _sync = () => _lbl && _lbl.classList.toggle("checked", _freshCb.checked);
    _freshCb.addEventListener("change", _sync);
    _sync();
  }
  // Verdict buttons. Disable BOTH on the first click: the endpoint is
  // idempotent, but a double-fire would still race two renders and flash a
  // stale banner back over the new state.
  for (const vb of detail.querySelectorAll(".verdict-btn")) {
    vb.addEventListener("click", async () => {
      const banner = vb.closest(".verdict-banner");
      const note = banner && banner.querySelector(".verdict-status");
      const verdict = vb.dataset.verdict;
      // "wrong" has no per-value form: it rules out EVERYTHING on offer. With
      // the picker now inviting the operator to think one value at a time,
      // a dialog saying "this value" over a list of two is a trap — so it
      // enumerates exactly what it is about to reject.
      if (verdict === "wrong") {
        const banner0 = vb.closest(".verdict-banner");
        const vals = Array.from(
          banner0 ? banner0.querySelectorAll(".verdict-values code") : [])
          .map((c) => c.textContent);
        if (!confirm("Mark as NOT the flag?\n\n"
                     + (vals.length ? vals.join("\n") + "\n\n" : "")
                     + (vals.length > 1
                        ? `All ${vals.length} values are ruled out together — `
                          + "there is no per-value Wrong.\n"
                        : "")
                     + "They are removed from the job and recorded as ruled out, "
                     + "and the job goes back to no_flag so it can be retried.")) {
          return;
        }
      }
      for (const b of banner.querySelectorAll(".verdict-btn")) b.disabled = true;
      if (note) note.textContent = "recording…";
      try {
        const res = await fetch(`${API}/jobs/${id}/flag-verdict`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          // With several candidates on offer, "ok" without a value promotes
          // ALL of them into meta.flags — and they are mutually exclusive by
          // construction, so at most one can be right. The per-value button
          // carries which one.
          body: JSON.stringify(
            vb.dataset.flag ? { verdict, flag: vb.dataset.flag } : { verdict }),
        });
        const out = await res.json();
        if (!res.ok) throw new Error(out.detail || `HTTP ${res.status}`);
        if (note) note.textContent = `recorded — job is ${out.status}`;
        await renderJob(id);
        await refreshJobs();
        // "Wrong" means this run did not solve it. Say so and offer the
        // existing retry rather than launching one from here — that endpoint
        // owns the module/in-flight/target guards.
        if (out.retry_suggested) {
          const rb = document.querySelector(
            `#job-detail .retry-btn[data-action="retry"]`);
          if (rb) rb.scrollIntoView({ block: "nearest" });
        }
      } catch (e) {
        if (note) note.textContent = `failed: ${e.message}`;
        for (const b of banner.querySelectorAll(".verdict-btn")) b.disabled = false;
      }
    });
  }

  const retryBtn = detail.querySelector('.retry-btn[data-action="retry"]');
  if (retryBtn) {
    // Reviewer-mode retry: open an inline form with an optional MULTI-target
    // override (+/× list). Blank = keep prior, "(none)" = clear. The reviewer
    // auto-generates the hint; this form only collects target(s).
    // If the source job is still queued/running (incl. orphaned "running"),
    // use /resume/stream so the backend halts it first — plain /retry would
    // leave a ghost worker/meta race.
    retryBtn.addEventListener("click", () => {
      const live = job.status === "queued" || job.status === "running";
      openReviewerRetryForm(id, retryBtn, live ? {
        formKey: "retry",
        submitLabel: "↻ Halt & retry (reviewer)",
        streamOpts: {
          endpoint: `${API}/jobs/${id}/resume/stream`,
          flow: "resume",
        },
      } : undefined);
    });
  }
  const retryManualBtn = detail.querySelector('.retry-btn[data-action="retry-manual"]');
  if (retryManualBtn) {
    retryManualBtn.addEventListener("click", () => openManualHintForm(id, retryManualBtn));
  }
  const continueNoteBtn = detail.querySelector('.retry-btn[data-action="continue"]');
  if (continueNoteBtn) {
    continueNoteBtn.addEventListener("click", () => openContinueForm(id, continueNoteBtn));
  }
  const resumeHoldBtn = detail.querySelector('.retry-btn[data-action="resume-hold"]');
  if (resumeHoldBtn) {
    resumeHoldBtn.addEventListener("click", () => resumeHeldJob(id, resumeHoldBtn));
  }
  const stopResumeBtn = detail.querySelector('.retry-btn[data-action="stop-resume"]');
  if (stopResumeBtn) {
    stopResumeBtn.addEventListener("click", () => openStopResumeForm(id, stopResumeBtn));
  }
  const stopResumeReviewerBtn = detail.querySelector(
    '.retry-btn[data-action="stop-resume-reviewer"]',
  );
  if (stopResumeReviewerBtn) {
    // No manual hint: streamRetry fetches the reviewer over SSE, backend halts
    // the source job first, carries ./work/, and submits with a [RESUMING]
    // preamble. Inline form collects an optional MULTI-target override.
    stopResumeReviewerBtn.addEventListener("click", () =>
      openReviewerRetryForm(id, stopResumeReviewerBtn, {
        formKey: "resume",
        submitLabel: "↻ Stop & resume (reviewer)",
        streamOpts: { endpoint: `${API}/jobs/${id}/resume/stream`, flow: "resume" },
      }),
    );
  }

  // (soft-timeout decision buttons removed with the watchdog — 2026-07-30)

  const stopBtn = detail.querySelector('.stop-job-btn[data-action="stop"]');
  if (stopBtn) {
    stopBtn.addEventListener("click", () => stopJob(id, stopBtn));
  }

  // ---- Steer: one instruction into a RUNNING session -------------------
  // The form carries class `steer-form`, which the 2-second poll at the top
  // of renderJob() checks before re-rendering. Without that, the operator
  // loses what they are typing every other second — the same defect the
  // retry and stop-resume forms already guard against.
  // Clicking a finding points MAIN at it. Delegated on the panel because the
  // panel repaints whenever a new finding arrives, and a listener bound to
  // the rows would die with them.
  //
  // It rides the STEER rail rather than inventing a second one: a steer
  // reaches a running session mid-turn (measured on e925acfecb84 at 59s from
  // queue to injection) without stopping it or losing the session, which is
  // exactly the shape "go look harder at this" needs.
  // Findings are SELECTED here, and sent once. Delegated on the panel
  // because the panel repaints whenever a new finding arrives, and a
  // listener bound to the rows would die with them.
  const vulnPanel = detail.querySelector(".vuln-panel");
  if (vulnPanel && !vulnPanel._digWired) {
    vulnPanel._digWired = true;
    const repaint = () => {
      const p = detail.querySelector(".vuln-panel");
      if (p) p.innerHTML = renderVulnPanel(
        _lastMonitorEntries[id] || [], monitorLang, true, claudeLogView, id);
    };
    vulnPanel.addEventListener("click", async (ev) => {
      const row = ev.target.closest('[data-action="vuln-pick"]');
      if (row) {
        const key = row.dataset.key || "";
        if (!key) return;
        const sel = (_vulnPicks[id] = _vulnPicks[id] || Object.create(null));
        if (sel[key]) delete sel[key];
        else {
          try { sel[key] = JSON.parse(decodeURIComponent(row.dataset.vuln || "%7B%7D")); }
          catch (_) { return; }
        }
        repaint();
        return;
      }
      if (ev.target.closest('[data-action="vuln-clear"]')) {
        delete _vulnPicks[id];
        repaint();
        return;
      }
      const send = ev.target.closest('[data-action="vuln-send"]');
      if (!send || send.disabled) return;
      const sel = _vulnPicks[id] || {};
      const picked = Object.values(sel);
      if (!picked.length) return;
      const status = vulnPanel.querySelector(".vuln-bar-status");
      const say = (s) => { if (status) status.textContent = s; };
      send.disabled = true;
      say("보내는 중…");
      // One finding asks for a verdict. Several ask for a CHAIN — and the
      // answer "these do not combine, and here is why" is a real answer,
      // worth a turn, so it is named as acceptable rather than implied.
      const lines = picked.map((v, i) =>
        `  ${i + 1}) ${v.title}${v.where ? ` — ${v.where}` : ""}`
        + `${v.why ? ` — ${v.why}` : ""}`);
      const text = picked.length === 1
        ? [
            "[OPERATOR] Investigate this finding to a verdict — confirm it end",
            "to end against the real target, or refute it. Do not assume it is",
            "already settled.",
            lines[0],
            "Prioritise this over the current step. Record what you did and the",
            "verdict (confirmed / refuted, with the evidence) in report.md.",
          ].join("\n")
        : [
            `[OPERATOR] These ${picked.length} findings may only be exploitable`,
            "TOGETHER. Treat them as one candidate chain, not as a list to work",
            "through separately.",
            ...lines,
            "Say which order they compose in and what each step hands the next;",
            "then drive the chain end to end against the real target. If they do",
            "NOT combine, say so and say exactly where the chain breaks — that",
            "is a result, not a failure. Prioritise this over the current step",
            "and record the chain and its verdict in report.md.",
          ].join("\n");
      try {
        const res = await fetch(`${API}/jobs/${id}/steer`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          send.disabled = false;
          say(`✗ ${body.detail || res.status}`);
          return;
        }
        // PENDING, not "sent": delivery happens on main's next tool call.
        delete _vulnPicks[id];
        repaint();
        const p2 = detail.querySelector(".vuln-bar-status");
        if (p2) p2.textContent = picked.length > 1
          ? `🕸 ${picked.length}개 체인 지시를 대기열에 넣음 — main의 다음 도구 호출에 전달됩니다`
          : "🔎 지시를 대기열에 넣음 — main의 다음 도구 호출에 전달됩니다";
      } catch (e) {
        send.disabled = false;
        say(`✗ ${e}`);
      }
    });
  }

  const runnerStopBtn = detail.querySelector('[data-action="runner-stop"]');
  if (runnerStopBtn && !runnerStopBtn._wired) {
    runnerStopBtn._wired = true;
    runnerStopBtn.addEventListener("click", async () => {
      const why = prompt(
        "이 실행을 중단하는 이유 (선택) — postjudge와 main에게 그대로 전달됩니다:", "");
      if (why === null) return;           // cancelled
      runnerStopBtn.disabled = true;
      const before = runnerStopBtn.textContent;
      runnerStopBtn.textContent = "중단 요청 중…";
      try {
        const res = await fetch(`${API}/jobs/${id}/runner/stop`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason: why }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          alert(`runner stop: ${body.detail || res.status}`);
          runnerStopBtn.disabled = false;
          runnerStopBtn.textContent = before;
          return;
        }
        // The runner polls every 2s, so this is a request, not an event.
        // Remembered outside the DOM because the row is about to be rebuilt.
        _runnerStopAt[id] = Date.now();
        runnerStopBtn.textContent = "⏹ 중단 요청됨 — 러너가 곧 멈춥니다";
      } catch (e) {
        alert(`runner stop: ${e}`);
        runnerStopBtn.disabled = false;
        runnerStopBtn.textContent = before;
      }
    });
  }

  const steerBtn = detail.querySelector('.steer-open-btn[data-action="steer"]');
  if (steerBtn) {
    steerBtn.addEventListener("click", () => {
      if (detail.querySelector(".steer-form")) return;   // already open
      const form = document.createElement("form");
      form.className = "steer-form";
      form.style.cssText = "margin:0.5rem 0;display:flex;flex-direction:column;gap:0.35rem";
      form.innerHTML = `
        <textarea class="steer-text" rows="3" maxlength="4000"
          placeholder="One instruction for the running agent — e.g. &quot;the instance is dead, get a fresh one before analysing further&quot;"
          style="width:100%;font:inherit"></textarea>
        <div style="display:flex;gap:0.4rem;align-items:center;flex-wrap:wrap">
          <button type="submit" class="retry-btn">🧭 Send</button>
          <button type="button" class="retry-btn steer-cancel">Cancel</button>
          <small class="steer-status" style="color:var(--fg-muted)">delivered at the next TURN BOUNDARY — a long turn delays it; the run is not stopped</small>
        </div>`;
      steerBtn.insertAdjacentElement("afterend", form);
      const ta = form.querySelector(".steer-text");
      const status = form.querySelector(".steer-status");
      ta.focus();
      form.querySelector(".steer-cancel").addEventListener("click", () => form.remove());
      form.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const text = (ta.value || "").trim();
        if (!text) { status.textContent = "type something first"; return; }
        status.textContent = "sending…";
        try {
          const res = await fetch(`${API}/jobs/${id}/steer`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text }),
          });
          const body = await res.json().catch(() => ({}));
          if (!res.ok) { status.textContent = `✗ ${body.detail || res.status}`; return; }
          // Report PENDING, not "sent": the message is queued, and whether it
          // lands depends on the job reaching another turn boundary. Saying
          // "delivered" here would be the one thing this feature must never
          // do — let an operator believe they redirected something they did not.
          const dropped = body.dropped ? ` (${body.dropped} oldest dropped)` : "";
          status.textContent = `✓ queued — ${body.queued} pending${dropped}`;
          ta.value = "";
        } catch (e) {
          status.textContent = `✗ ${e.message || e}`;
        }
      });
    });
  }

  const changeTargetBtn = detail.querySelector('.change-target-btn[data-action="change-target"]');
  if (changeTargetBtn) {
    changeTargetBtn.addEventListener("click", () => {
      // Prefill with the job's current target(s) so the operator edits in place.
      const curList = (Array.isArray(job.target_urls) && job.target_urls.length
        ? job.target_urls
        : (job.target_url ? [job.target_url] : [])).filter(Boolean);
      // Inline form anchored right after the button row, mirroring
      // the retry-manual-form layout.
      if (changeTargetBtn.dataset.openForm === "1") return;
      changeTargetBtn.dataset.openForm = "1";
      const form = document.createElement("div");
      form.className = "retry-manual-form";
      form.innerHTML = `
        <label class="retry-manual-label">New target(s) · <b>+ add target</b> for several · clear all = remove</label>
        ${targetListHtml("http://challenge.example.com:8080  ·  ctf.example.com:31337", curList.join("\n"))}
        <div style="display:flex;gap:0.5rem;align-items:center">
          <button class="retry-manual-submit change-target-save" type="button">Save target</button>
          <button class="retry-manual-cancel change-target-cancel" type="button">Cancel</button>
          <small style="color:var(--fg-muted)">updates meta only · run / retry afterwards picks up the new value</small>
        </div>
      `;
      changeTargetBtn.parentNode.insertBefore(form, changeTargetBtn.nextSibling);
      const firstInput = form.querySelector(".target-input");
      if (firstInput) { firstInput.focus(); firstInput.select(); }
      const close = () => {
        form.remove();
        delete changeTargetBtn.dataset.openForm;
      };
      form.querySelector(".change-target-cancel").addEventListener("click", close);
      form.querySelector(".change-target-save").addEventListener("click", async () => {
        // PATCH /target: "" clears the target (change-target semantics), a
        // joined list sets target_url (primary) + target_urls (the rest).
        const val = gatherTargets(form);
        try {
          const res = await fetch(`${API}/jobs/${id}/target`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: val }),
          });
          const body = await res.json();
          if (!res.ok) {
            alert(`change-target failed: ${res.status} ${JSON.stringify(body)}`);
            return;
          }
          close();
          await renderJob(id, { force: true });
          // Surface the note whenever the API says so — for a RUNNING job it
          // now explains that the orchestrator hands the new endpoint over at
          // the next turn boundary; for queued/analyzing it explains the
          // timing. A finished job stays quiet. (Gating this on
          // `applies_live === false` broke once `running` became live-applying:
          // the operator got no feedback at all.)
          const showNote = body.show_note !== undefined
            ? body.show_note
            : body.applies_live === false;
          if (showNote && body.note) alert(body.note);
        } catch (e) {
          alert(`change-target error: ${e}`);
        }
      });
      form.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && e.target.classList.contains("target-input")) {
          e.preventDefault();
          form.querySelector(".change-target-save").click();
        } else if (e.key === "Escape") { close(); }
      });
    });
  }

  const runBtn = detail.querySelector('.run-now-btn[data-action="run"]');
  if (runBtn) {
    runBtn.addEventListener("click", async () => {
      // dreamhack-style instances expire fast, so the stored target is often
      // stale by re-run time — and this button used to silently reuse it,
      // which made "Run in sandbox" appear to ignore a fresh target. Prompt
      // (prefilled with the job's current target) so the operator confirms or
      // overrides it; the override is passed as ?target= and persisted to
      // meta server-side BEFORE the run (else the runner's proactive
      // meta-refresh would clobber it back to the stale value).
      const curTgt = job.target_url || "";
      const tgt = prompt(
        "Run against target (host:port or URL).\n"
        + "Edit to point at a fresh instance, or keep as-is:",
        curTgt,
      );
      if (tgt === null) return;  // cancelled — don't run
      const q = tgt.trim() ? `?target=${encodeURIComponent(tgt.trim())}` : "";
      runBtn.disabled = true;
      const origText = runBtn.textContent;
      runBtn.textContent = "⏳ running…";
      try {
        const res = await fetch(`${API}/jobs/${id}/run${q}`, { method: "POST" });
        const body = await res.json();
        if (!res.ok) {
          alert(`run failed: ${res.status} ${JSON.stringify(body)}`);
        } else {
          const sb = body.sandbox || {};
          const msg = `exit=${sb.exit_code} · stdout ${sb.stdout?.length || 0}B · `
            + `flags: ${(body.flags || []).length ? body.flags.join(", ") : "(none)"}`;
          alert(msg);
        }
      } catch (e) {
        alert(`run error: ${e}`);
      } finally {
        runBtn.disabled = false;
        runBtn.textContent = origText;
        await renderJob(id, { force: true });
        await refreshJobs();
      }
    });
  }

  // Run-log search: stash this poll's raw log + anchor, wire the input, and
  // re-apply an active filter (the poll just rebuilt the <pre> with the full
  // log). Typing is protected by the poll-skip guard up top.
  _runLogRaw[id] = log;
  _runLogAnchor[id] = job.started_at || null;
  const logSearchInput = detail.querySelector(".run-log-search");
  if (logSearchInput) {
    logSearchInput.addEventListener("input", () => {
      _logSearch[id] = logSearchInput.value;
      applyLogSearch(id);
    });
    if ((_logSearch[id] || "").trim()) applyLogSearch(id);
  }

  // "더 보기" — lift the render cap for THIS job and rebuild. Per-job and not
  // persisted: the cap exists so entry is cheap, and an operator who wanted
  // the whole log once should not pay for it on every job thereafter.
  detail.querySelectorAll('[data-action="render-uncap"]').forEach((btn) => {
    btn.addEventListener("click", () => {
      _renderUncapped.add(btn.dataset.jobId || id);
      renderJob(id, { force: true });
    });
  });

  const tzBtn = detail.querySelector('.run-log-tz-toggle[data-action="toggle-tz"]');
  if (tzBtn) {
    tzBtn.addEventListener("click", () => {
      _setRunlogTz(runlogTz === "utc" ? "local" : "utc");
    });
  }

  // Run-log ↔ Monitor view toggle + monitor language select.
  const composer = detail.querySelector(".tl-composer");
  if (composer) {
    const ta = composer.querySelector(".tl-composer-text");
    const status = composer.querySelector(".tl-composer-status");
    // Ctrl/Cmd+Enter sends; a bare Enter keeps making newlines, because a
    // steer is usually more than one clause and losing it to a stray Return
    // is worse than an extra keystroke.
    // The guard at the top of renderJob keys off this class, so it has to be
    // ON the element while there is something to lose and off again once
    // there is not — otherwise the panel either eats a draft or stops
    // updating forever.
    const _mark = () => composer.classList.toggle(
      "tl-composer-typing", (ta.value || "").trim() !== "");
    ta.addEventListener("input", _mark);
    ta.addEventListener("blur", _mark);
    ta.addEventListener("keydown", (ev) => {
      if ((ev.metaKey || ev.ctrlKey) && ev.key === "Enter") {
        ev.preventDefault();
        composer.requestSubmit();
      }
    });
    composer.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const text = (ta.value || "").trim();
      if (!text) { status.textContent = "먼저 내용을 입력하세요"; return; }
      status.textContent = "보내는 중…";
      try {
        const res = await fetch(`${API}/jobs/${id}/steer`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) { status.textContent = `✗ ${body.detail || res.status}`; return; }
        // QUEUED, never "delivered". Whether it lands depends on the job
        // reaching another turn boundary, and telling an operator they
        // redirected something they did not is the one thing this must not do.
        const dropped = body.dropped ? ` (오래된 ${body.dropped}건 밀려남)` : "";
        status.textContent = `✓ 대기열에 넣었습니다 — ${body.queued}건 대기${dropped}`;
        ta.value = "";
        _mark();
      } catch (e) {
        status.textContent = `✗ ${e.message || e}`;
      }
    });
  }
  const viewClaudeTlBtn = detail.querySelector('.rl-viewtab[data-action="view-claude-timeline"]');
  if (viewClaudeTlBtn) {
    viewClaudeTlBtn.addEventListener("click", () => { _leaveTraceView(); _setClaudeLogView("timeline"); });
  }
  const viewVulnBtn = detail.querySelector('.rl-viewtab[data-action="view-vuln"]');
  if (viewVulnBtn) {
    viewVulnBtn.addEventListener("click", () => { _leaveTraceView(); _setClaudeLogView("vuln"); });
  }
  const viewLogBtn = detail.querySelector('.rl-viewtab[data-action="view-log"]');
  if (viewLogBtn) {
    viewLogBtn.addEventListener("click", () => { _leaveTraceView(); _setClaudeLogView("log"); });
  }
  const viewMonBtn = detail.querySelector('.rl-viewtab[data-action="view-monitor"]');
  if (viewMonBtn) {
    // Keeps the legacy boolean in step so nothing else that reads it drifts.
    viewMonBtn.addEventListener("click", () => {
      _leaveTraceView(); _setMonitorView(true); _setClaudeLogView("monitor");
    });
  }
  const monLangSel = detail.querySelector('.monitor-lang[data-action="monitor-lang"]');
  if (monLangSel) {
    monLangSel.addEventListener("change", () => _setMonitorLang(monLangSel.value));
  }
  const viewTraceBtn = detail.querySelector('.rl-viewtab[data-action="view-trace"]');
  if (viewTraceBtn) {
    viewTraceBtn.addEventListener("click", () => _setTraceView(true));
  }
  const gptTimelineBtn = detail.querySelector('[data-action="view-gpt-timeline"]');
  if (gptTimelineBtn) {
    gptTimelineBtn.addEventListener("click", () => { _leaveTraceView(); _setGptLogView("timeline"); });
  }
  const gptLogBtn = detail.querySelector('[data-action="view-gpt-log"]');
  if (gptLogBtn) {
    gptLogBtn.addEventListener("click", () => { _leaveTraceView(); _setGptLogView("log"); });
  }
  const gptToolsBtn = detail.querySelector('[data-action="toggle-gpt-tools"]');
  if (gptToolsBtn) {
    gptToolsBtn.addEventListener("click", _toggleGptTimelineTools);
  }

  const sdkLiveBtn = detail.querySelector('.sdk-live-toggle[data-action="toggle-sdk-live"]');
  if (sdkLiveBtn) {
    sdkLiveBtn.addEventListener("click", () => {
      _sdkLiveHidden = !_sdkLiveHidden;
      try { localStorage.setItem("sdk_live_hidden", _sdkLiveHidden ? "1" : "0"); } catch (_) {}
      const panel = detail.querySelector('.sdk-live');
      if (panel) {
        panel.classList.toggle("collapsed", _sdkLiveHidden);
        sdkLiveBtn.textContent = _sdkLiveHidden ? "show" : "hide";
      }
    });
    // Apply the saved preference on initial render.
    const panel = detail.querySelector('.sdk-live');
    if (panel && _sdkLiveHidden) {
      panel.classList.add("collapsed");
      sdkLiveBtn.textContent = "show";
    }
  }

  for (const btn of detail.querySelectorAll(".copy-jobid-btn")) {
    btn.addEventListener("click", (e) => copyJobId(btn.dataset.jobid, e));
  }

  for (const btn of detail.querySelectorAll(".copy-btn")) {
    btn.addEventListener("click", async () => {
      const flag = btn.dataset.flag;
      try {
        await navigator.clipboard.writeText(flag);
      } catch (_) {
        // Fallback: select + execCommand
        const tmp = document.createElement("textarea");
        tmp.value = flag; document.body.appendChild(tmp);
        tmp.select(); document.execCommand("copy"); tmp.remove();
      }
      const orig = btn.textContent;
      btn.textContent = "✓ Copied"; btn.classList.add("copied");
      setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1500);
    });
  }

  // Manual flag pruning. Challenges that pad stdout with flag-shaped noise
  // leave meta.flags full of dummies — let the operator delete them (or keep
  // only the real one). After the server prunes, re-render from fresh meta.
  const _pruneFlags = async (jid, indices, btn, confirmMsg) => {
    if (confirmMsg && !confirm(confirmMsg)) return;
    const orig = btn.textContent;
    btn.disabled = true; btn.textContent = "…";
    try {
      const res = await fetch(`${API}/jobs/${jid}/flags/delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indices }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(`flag delete failed: ${res.status} — ${data.detail || ""}`);
        btn.disabled = false; btn.textContent = orig;
        return;
      }
      await renderJob(jid);   // re-fetch + re-render with the pruned list
    } catch (e) {
      alert(`flag delete failed: ${e}`);
      btn.disabled = false; btn.textContent = orig;
    }
  };

  for (const btn of detail.querySelectorAll(".flag-del-btn")) {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.dataset.flagIndex, 10);
      if (Number.isNaN(idx)) return;
      _pruneFlags(btn.dataset.jobId, [idx], btn, null);
    });
  }

  for (const btn of detail.querySelectorAll(".flag-keep-btn")) {
    btn.addEventListener("click", () => {
      const keep = parseInt(btn.dataset.flagIndex, 10);
      const total = (job.flags || []).length;
      if (Number.isNaN(keep) || total <= 1) return;
      const others = [];
      for (let i = 0; i < total; i++) if (i !== keep) others.push(i);
      _pruneFlags(btn.dataset.jobId, others, btn,
        `Delete the other ${others.length} flag(s) and keep only this one?`);
    });
  }

  for (const btn of detail.querySelectorAll(".exp-save-btn")) {
    btn.addEventListener("click", async () => {
      if (btn.disabled) return;
      const jid = btn.dataset.jobId;
      const tags = prompt(
        "Tags (comma-separated, optional)\n"
        + "e.g. heap, fsop, glibc-2.35, large-bin",
        ""
      );
      if (tags === null) return;  // cancelled
      const notes = prompt(
        "Notes (one line, optional)\n"
        + "e.g. House of Apple 2 chain; one_gadget rejected — pivoted to _IO_str_jumps",
        ""
      );
      if (notes === null) return;  // cancelled
      const body = {
        job_id: jid,
        tags: tags.split(",").map(s => s.trim()).filter(Boolean),
        notes: notes || "",
        overwrite: true,
      };
      btn.disabled = true;
      const orig = btn.textContent;
      btn.textContent = "saving…";
      try {
        const res = await fetch(`${API}/exploits/save`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          alert(`save failed: ${res.status} — ${data.detail || ""}`);
          btn.textContent = orig;
        } else {
          btn.textContent = `✓ saved ${data.id || ""}`;
          btn.classList.add("copied");
          setTimeout(() => {
            btn.textContent = orig;
            btn.classList.remove("copied");
            btn.disabled = false;
          }, 2500);
        }
      } catch (e) {
        alert(`save failed: ${e}`);
        btn.textContent = orig;
        btn.disabled = false;
      }
    });
  }
  // Restore the "reviewer in progress" panel after a full detail rebuild.
  // The stream state lives in activeReviewers (not the DOM), so this brings
  // the panel back when the operator navigates away from an in-flight retry
  // and returns — the disappearing-panel bug this fixes.
  renderReviewerPanel(id);
  _mark(_marks, "wire");
  _reportEntry(_marks);
  return job;
}

// Copy a job id to the clipboard. Used by the ⧉ button in both the job
// list cards and the detail header. stopPropagation so clicking it inside a
// list card does NOT also trigger the card's selectJob().
async function copyJobId(id, ev) {
  if (ev) { ev.stopPropagation(); ev.preventDefault(); }
  let ok = true;
  try {
    await navigator.clipboard.writeText(id);
  } catch (_) {
    try {
      const tmp = document.createElement("textarea");
      tmp.value = id; document.body.appendChild(tmp);
      tmp.select(); document.execCommand("copy"); tmp.remove();
    } catch (_) { ok = false; }
  }
  const btn = ev && ev.currentTarget;
  if (btn) {
    const orig = btn.textContent;
    btn.textContent = ok ? "✓" : "✗";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1200);
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// --- Run-log colorizer ------------------------------------------------------
// Lines look like: "[HH:MM:SS] LABEL[: body...]". Classify by LABEL and wrap
// the timestamp + label + body in spans so the run.log <pre> can show
// agent text, tool calls, tool results, thinking, and errors at a glance.

const _RUNLOG_PATTERNS = [
  // AGENT_ERROR (kind): body  — must come before plain ERROR
  { re: /^(AGENT_ERROR)(\s*\([^)]*\))?\s*:\s*([\s\S]*)$/,
    cls: "rl-agent-error",
    render: (m) => `<span class="rl-label rl-agent-error">${escapeHtml(m[1])}${escapeHtml(m[2] || "")}</span>: <span class="rl-body rl-error-body">${escapeHtml(m[3])}</span>` },
  // TOOL_RESULT: body
  { re: /^(TOOL_RESULT)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-tool-result">${escapeHtml(m[1])}</span>: <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // TOOL_ERROR: body
  { re: /^(TOOL_ERROR)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-tool-error">${escapeHtml(m[1])}</span>: <span class="rl-body rl-error-body">${escapeHtml(m[2])}</span>` },
  // TOOL <name>: body
  { re: /^(TOOL)\s+(\S+)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-tool">${escapeHtml(m[1])}</span> <span class="rl-toolname">${escapeHtml(m[2])}</span>: <span class="rl-body">${escapeHtml(m[3])}</span>` },
  // AGENT: body
  { re: /^(AGENT)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-agent">${escapeHtml(m[1])}</span>: <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // THINK: body
  { re: /^(THINK)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-think">${escapeHtml(m[1])}</span>: <span class="rl-body rl-think-body">${escapeHtml(m[2])}</span>` },
  // DONE: body
  { re: /^(DONE)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-done">${escapeHtml(m[1])}</span>: <span class="rl-body rl-done-body">${escapeHtml(m[2])}</span>` },
  // ERROR: body  (catastrophic — exception in run_job etc.)
  { re: /^(ERROR)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-error">${escapeHtml(m[1])}</span>: <span class="rl-body rl-error-body">${escapeHtml(m[2])}</span>` },
  // BUDGET_ABORT: body  — investigation budget tripwire fired
  { re: /^(BUDGET_ABORT)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-budget">${escapeHtml(m[1])}</span>: <span class="rl-body rl-budget-body">${escapeHtml(m[2])}</span>` },
  // RUNAWAY_OUTPUT detected (NNN MB)... — Bash command flooded the SDK,
  // which auto-truncated to a 2KB preview. Highlight so the agent (and
  // the human operator) doesn't blunder past it.
  { re: /^(RUNAWAY_OUTPUT)\s+([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-runaway">${escapeHtml(m[1])}</span> <span class="rl-body rl-runaway-body">${escapeHtml(m[2])}</span>` },
  // Lifecycle: ⏰ Soft timeout reached … (watchdog warning)
  { re: /^(⏰\s+Soft timeout reached[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-warn">${escapeHtml(m[1])}</span>` },
  // Lifecycle: Launching Claude agent (model=...)
  { re: /^(Launching Claude (?:agent|summary agent)[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-info">▸ ${escapeHtml(m[1])}</span>` },
  // Lifecycle: Forking prior Claude session abc12345…
  { re: /^(Forking prior Claude session[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-info">↻ ${escapeHtml(m[1])}</span>` },
  // Lifecycle: User chose CONTINUE / STOP — soft-timeout decision
  { re: /^(User chose (?:CONTINUE|STOP)[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-decision">⚑ ${escapeHtml(m[1])}</span>` },
  // Lifecycle: Source root: ... (web/crypto)
  { re: /^(Source root)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-info">${escapeHtml(m[1])}</span>: <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // Lifecycle: [manual-run] executing exploit.py ...
  { re: /^(\[manual-run\])\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-cyan">${escapeHtml(m[1])}</span> <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // Lifecycle: Spawning forensic|misc … sibling-container start
  { re: /^(Spawning [a-z]+[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-info">▸ ${escapeHtml(m[1])}</span>` },
  // Lifecycle: Skipping Claude summary (forensic/misc)
  { re: /^(Skipping Claude summary[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-system">${escapeHtml(m[1])}</span>` },
];

// Format a `HH:MM:SS` timestamp for display. The on-disk log records
// UTC time-of-day only; this helper anchors the time-of-day on the
// job's `started_at` UTC date, advances the day-counter on midnight
// rollover, and (in local mode) converts to the user's timezone via
// the browser's Date object. State is per-render, mutated as the
// caller walks lines top-to-bottom.
function _formatLogTs(hms, anchor, state) {
  const parts = hms.split(":");
  if (parts.length !== 3) return hms;
  const hh = +parts[0], mm = +parts[1], ss = +parts[2];
  if (Number.isNaN(hh) || Number.isNaN(mm) || Number.isNaN(ss)) return hms;
  const sod = hh * 3600 + mm * 60 + ss;
  // Day rollover: if the new line's seconds-of-day is well below
  // the last seen, assume we crossed at least one UTC midnight. The
  // 60-second slack tolerates concurrent-thread log lines arriving a
  // hair out of order so we don't mistakenly bump the day counter.
  if (state.lastSod >= 0 && sod < state.lastSod - 60) {
    state.dayOffset += 1;
  }
  state.lastSod = sod;
  if (runlogTz !== "local" || !anchor) {
    return hms;
  }
  const d = new Date(Date.UTC(
    anchor.getUTCFullYear(),
    anchor.getUTCMonth(),
    anchor.getUTCDate() + state.dayOffset,
    hh, mm, ss,
  ));
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  const s = String(d.getSeconds()).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function _colorizeRunLogLine(line, anchor, state) {
  // Header injected by /api/jobs/{id}/log?tail=… (e.g. "…(showing last X
  // of Y bytes — download full log via …)…"). Render dim+italic.
  if (line.startsWith("…(showing last")) {
    return `<span class="rl-system">${escapeHtml(line)}</span>`;
  }
  const m = line.match(/^\[(\d{2}:\d{2}:\d{2})\]\s+([\s\S]*)$/);
  if (!m) {
    if (!line) return "";
    return `<span class="rl-system">${escapeHtml(line)}</span>`;
  }
  const ts = _formatLogTs(m[1], anchor, state);
  let rest = m[2];

  // Per-line agent tag: analyzers prefix lines with "[main] " /
  // "[recon] " / "[judge] " / "[debugger] " right after the
  // timestamp. The isolated subagent path tags with a per-spawn
  // counter, e.g. "[recon#1] " — both forms should colorize the
  // chip identically (the # suffix is just the spawn index).
  // Strip the tag and render it as a colored chip; subagent lines
  // (recon / judge / debugger) get a slight indent so the
  // delegation reads visually like a nested call.
  let agentChip = "";
  let isSubagent = false;
  const tagMatch = rest.match(
    /^\[(main|recon|judge|debugger)(#\d+)?\]\s+([\s\S]*)$/,
  );
  if (tagMatch) {
    const tag = tagMatch[1];
    const idxSuffix = tagMatch[2] || "";
    isSubagent = tag !== "main";
    rest = tagMatch[3];
    agentChip = `<span class="rl-agent-tag rl-agent-tag-${tag}">${tag}${idxSuffix}</span>`;
  }

  const indent = isSubagent ? '<span class="rl-recon-indent">↳ </span>' : "";

  for (const p of _RUNLOG_PATTERNS) {
    const mm = rest.match(p.re);
    if (mm) {
      return `<span class="rl-ts">[${ts}]</span> ${agentChip}${indent}${p.render(mm)}`;
    }
  }
  // System / unrecognised lines (e.g. "Launching Claude agent…",
  // "User chose CONTINUE…", "⏰ Soft timeout reached…").
  return `<span class="rl-ts">[${ts}]</span> ${agentChip}${indent}<span class="rl-system">${escapeHtml(rest)}</span>`;
}

// ---- run-log search (client-side filter + highlight of the loaded log) ----
// Searches the displayed log (the 256 KB tail the poll fetches — the whole log
// for most jobs). State is keyed by job so it survives the 2s poll re-render.
// HOW MANY ITEMS EACH VIEW RENDERS.
//
// Measured on this deployment (jsdom, real jobs): a timeline card costs ~28.7
// DOM nodes, a colourised log line ~11.1, a file row exactly 3.00. Entering
// 96d867af0f04 built 51,100 nodes; 48fadce3dde7 built 52,308 in a single
// innerHTML assignment.
//
// THERE IS NO KNEE. Marginal cost is flat on every axis — nodes/line measured
// 11.80, 10.78, 11.06, 11.11, 11.18 from N=50 to N=2553; nodes/card likewise.
// So these numbers CANNOT be read off an inflection and are not pretending to
// be: they are a ~10,000-node-per-view budget divided by the measured per-item
// cost (300 x 28.7 = 8,600; 1,000 x 11.1 = 11,048). To change them, change the
// budget and say why — do not hunt for a bend that the data does not contain.
//
// Both are TAIL-anchored: an operator opens a job to see what just happened.
// "더 보기" lifts the cap for that job, and the whole file is always one click
// away in the directory browser, so nothing here makes anything unreachable.
const _RENDER_MAX_CARDS = 300;
const _RENDER_MAX_LOG_LINES = 1000;
const _renderUncapped = new Set();   // jobIds where the operator asked for all

function _tailLines(text, max) {
  if (!text) return { text: "", clipped: 0 };
  let cut = -1, seen = 0;
  for (let i = text.length - 1; i >= 0; i--) {
    if (text.charCodeAt(i) !== 10) continue;
    if (++seen > max) { cut = i + 1; break; }
  }
  if (cut < 0) return { text, clipped: 0 };
  // Count what was dropped so the banner can say so rather than silently lie
  // about being the whole log.
  let dropped = 0;
  for (let i = 0; i < cut; i++) if (text.charCodeAt(i) === 10) dropped++;
  return { text: text.slice(cut), clipped: dropped };
}

function _moreBanner(id, dropped, unit) {
  if (!dropped) return "";
  return `<div class="render-cap-more">위 ${dropped.toLocaleString()}${unit} 생략됨 ·
    <button data-action="render-uncap" data-job-id="${escapeHtml(id)}">더 보기</button></div>`;
}

const _logSearch = {};      // jobId -> query string
const _runLogRaw = {};      // jobId -> raw log text (last poll fetch)
const _runLogAnchor = {};   // jobId -> started_at iso (for timestamp colorize)

function _escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Highlight `q` only in the TEXT segments of colorized HTML (never inside a
// tag), so the run-log's colored spans aren't mangled.
function _highlightLogHtml(html, q) {
  if (!q) return html;
  const rx = new RegExp(_escapeRegExp(q), "gi");
  return html.replace(/(<[^>]+>)|([^<]+)/g, (m, tag, text) =>
    tag ? tag : text.replace(rx, '<mark class="log-hit">$&</mark>'));
}

// Re-render the run-log <pre> for `id`: the full colorized log when the query
// is empty, else only the matching lines (case-insensitive) with hits marked.
function applyLogSearch(id) {
  const esc = (window.CSS && CSS.escape) ? CSS.escape(id) : id;
  const pre = document.querySelector(`pre.run-log[data-job-id="${esc}"]`);
  if (!pre) return;
  // This function WRITES the <pre> directly, so it is a second door into the
  // render path and has to honour the same two rules renderJob does.
  //
  // (1) Not while the <pre> is hidden. renderJob re-applies an active search on
  //     every pass (app.js:4582); without this, a search left in the box while
  //     the Timeline view is up colourised the whole log into a display:none
  //     node twice a second — exactly the hidden-half cost this view guard was
  //     added to remove. Switching back to the log view re-renders and the
  //     search is applied then.
  const win = pre.closest ? pre.closest(".run-log-window") : null;
  if (win && win.dataset && win.dataset.view !== "log") return;
  const raw = _runLogRaw[id] || "";
  const q = (_logSearch[id] || "").trim();
  const anchor = _runLogAnchor[id] || null;
  const countEl = document.querySelector(`.run-log-search-count[data-job-id="${esc}"]`);
  if (!q) {
    // (2) Clearing the box restores the CAPPED view, not the whole log. It used
    // to call colorizeRunLog(raw) here, so typing one character and deleting it
    // silently uncapped the panel for the rest of its life — and poisoned the
    // single-slot colouriser memo with the full-text key, so every 2s poll
    // re-colourised all of it.
    try { pre.innerHTML = raw ? _cappedLogHtml(id, raw, anchor) : "(empty)"; } catch (_) {}
    if (countEl) countEl.textContent = "";
    return;
  }
  const ql = q.toLowerCase();
  const lines = raw.split("\n");
  const matching = lines.filter((l) => l.toLowerCase().includes(ql));
  if (!matching.length) {
    pre.innerHTML = '<span style="color:var(--fg-muted)">(no matching lines)</span>';
    if (countEl) countEl.textContent = "0";
    return;
  }
  // A loose query ("[", a timestamp fragment) matches nearly every line, so the
  // result set needs the same cap the unfiltered view has.
  const shown = _renderUncapped.has(id)
    ? { text: matching.join("\n"), clipped: 0 }
    : _tailLines(matching.join("\n"), _RENDER_MAX_LOG_LINES);
  try {
    pre.innerHTML = _moreBanner(id, shown.clipped, "줄")
      + _highlightLogHtml(colorizeRunLog(shown.text, anchor), q);
  } catch (_) {
    pre.textContent = shown.text;
  }
  if (countEl) countEl.textContent = `${matching.length} / ${lines.length} lines`;
}

// FNV-1a over the rendered markup. Not security, just a change detector: the
// alternative is holding a second 300 KB string and comparing it every 2s.
function _cheapHash(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(36);
}

// The capped view of the log. colorizeRunLog stays memoised on the exact text
// it is given, so capping BEFORE it means the memo key is the capped tail and
// the 2s poll re-colourises 1,000 lines instead of 2,639.
function _cappedLogHtml(id, log, anchor) {
  if (_renderUncapped.has(id)) return colorizeRunLog(log, anchor);
  const { text, clipped } = _tailLines(log, _RENDER_MAX_LOG_LINES);
  return _moreBanner(id, clipped, "줄") + colorizeRunLog(text, anchor);
}

let _clrKey = null, _clrVal = "";

function colorizeRunLog(text, anchorIso) {
  if (!text) return "";
  // Memoised on (text, anchor). The poller re-colourises the SAME 256 KB every
  // 2 seconds — ~3,350 lines x 7 regex operations — for as long as the panel
  // is open, and a quiet agent changes none of it. One cached string removes
  // the whole cost from every poll that brought nothing new.
  const _k = anchorIso + "\u0000" + text;
  if (_k === _clrKey) return _clrVal;
  let anchor = null;
  if (anchorIso) {
    const d = new Date(anchorIso);
    if (!Number.isNaN(d.getTime())) anchor = d;
  }
  // dayOffset / lastSod are mutated by _formatLogTs as we walk lines
  // top-to-bottom; reset for each call so toggling between jobs (or
  // re-rendering after a TZ flip) starts clean.
  const state = { dayOffset: 0, lastSod: -1 };
  _clrVal = text.split("\n").map(
    (line) => _colorizeRunLogLine(line, anchor, state),
  ).join("\n");
  _clrKey = _k;
  return _clrVal;
}

// --- File preview modal -----------------------------------------------------
// Pretty-prints JSON, renders Markdown, and syntax-highlights source code
// using highlight.js + marked (loaded from CDN in index.html). Falls back
// to plain text if the libraries didn't load (e.g. offline).

const _LANG_FROM_EXT = {
  py: "python", sage: "python",
  js: "javascript", ts: "typescript",
  json: "json", jsonl: "json",
  md: "markdown", markdown: "markdown",
  html: "xml", xml: "xml",
  css: "css",
  sh: "bash", bash: "bash",
  c: "c", h: "c", cpp: "cpp", hpp: "cpp", cc: "cpp",
  rb: "ruby", go: "go", rs: "rust",
  yml: "yaml", yaml: "yaml",
  sql: "sql",
  log: "plaintext", stdout: "plaintext", stderr: "plaintext", txt: "plaintext",
};

function _languageFor(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return _LANG_FROM_EXT[ext] || "plaintext";
}

function _isMarkdown(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return ext === "md" || ext === "markdown";
}

function _isJson(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return ext === "json" || name === "result.json";
}

/* ------------------------------------------------------ job file browser
   Lists ONE directory at a time. The job tree is not uniformly small —
   measured 2026-08-11 the median job holds 85 files but the largest holds
   8,520 at depth 14 — so a recursive render would freeze the modal on exactly
   the jobs whose output you most want to dig through.

   Files reuse `file-preview-link`, so the existing syntax-highlighting modal
   opens them and middle-click / "open in new tab" still gets the raw bytes. */
const _jobFilesPath = new Map();     // job id -> directory currently shown

function _fmtFileSize(n) {
  if (n == null) return "";
  if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
  if (n >= 1024) return Math.round(n / 1024) + " KB";
  return n + " B";
}

function _jobFilesCrumbs(id, path) {
  const parts = path ? path.split("/") : [];
  const crumb = (label, target) =>
    `<a href="#" class="job-files-crumb" data-path="${escapeHtml(target)}">${escapeHtml(label)}</a>`;
  let acc = "";
  const out = [crumb("job", "")];
  for (const p of parts) {
    acc = acc ? `${acc}/${p}` : p;
    out.push(crumb(p, acc));
  }
  return out.join('<span class="job-files-sep">/</span>');
}

/* Extensions the modal shows AS A PICTURE instead of decoding to text.
   A CTF job directory is full of them — one OSINT job shipped a single multi-megabyte
   image, and the only way to look at it was to download it —
   and `await res.text()` on a PNG produces a screenful of replacement
   characters, which reads like a corrupt file rather than a wrong viewer.

   SVG is included deliberately. These bytes are challenge-authored and
   therefore hostile by assumption, but an SVG loaded through <img> cannot run
   script or fetch anything external — that is the sandbox the element spec
   gives us. (The "Open raw" link has always opened it directly in a tab, where
   it CAN; that is pre-existing and unchanged here.) */
//
// Lives inside the file-browser block, not beside _isJson, because
// _jfRowInner needs it and scripts/test_job_files_quiet_poll.js runs that
// unit by slicing this block out of the file. A helper the slice cannot
// see is a helper the harness has to fake, and a faked dependency proves
// nothing about the unit. openFileModal (further down) reaches it by
// hoisting, exactly as before.
function _isImage(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return ["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico", "avif"]
    .includes(ext);
}

/** The inner markup of one row. Split out so the reconciler can rebuild a row
 *  without a second copy of the template drifting away from this one. */
function _jfRowInner(id, e) {
  // A symlink is shown but never followed by the API (it refuses anything
  // resolving outside the job dir). Marking it keeps "this is empty" and
  // "this points somewhere we will not go" from looking alike.
  const link = e.is_link ? ' <span class="jf-link" title="symlink">↗</span>' : "";
  if (e.is_dir) {
    return `<a href="#" class="jf-dir" data-path="${escapeHtml(e.path)}"
      >📁 ${escapeHtml(e.name)}</a>${link}`;
  }
  const url = `${API}/jobs/${encodeURIComponent(id)}/blob?path=${encodeURIComponent(e.path)}`;
  // 🖼 marks the rows that open as a picture, so "can I look at this?" is
  // answerable from the listing instead of by clicking.
  const icon = _isImage(e.name) ? "🖼" : "📄";
  return `<a href="${url}" target="_blank" class="file-preview-link jf-file"
       data-url="${url}" data-name="${escapeHtml(e.path)}">${icon} ${escapeHtml(e.name)}</a>${link}
    <span class="jf-size">${_fmtFileSize(e.size)}</span>`;
}

/** `is_dir`/`is_link` folded into one token. A row whose shape changed cannot
 *  be patched — a file replaced by a directory of the same name would keep
 *  rendering as 📄 with a size column forever. */
function _jfShape(e) { return `${e.is_dir ? "d" : "f"}${e.is_link ? "l" : ""}`; }

function _jfMakeRow(id, e) {
  const row = document.createElement("div");
  row.className = "jf-row";
  row.dataset.key = e.path;
  row.dataset.shape = _jfShape(e);
  row.innerHTML = _jfRowInner(id, e);
  return row;
}

/** Patch the rendered list towards `entries` rather than rewriting it.
 *
 *  Rewriting is what made the polling VISIBLE: every couple of seconds the
 *  listing was thrown away and rebuilt, which dropped the scroll position of a
 *  directory being read, cancelled hover, and made an unchanged directory
 *  flicker. Here a poll that changes nothing touches no DOM at all, and a file
 *  that genuinely appears mid-run fades in on its own. */
function _jfReconcile(list, id, entries, opts) {
  // Reconcile over `.jf-row` ONLY. The `(empty)` placeholder and the truncation
  // notice are siblings with no key; folding them into the keyed set would
  // remove and re-insert them on every poll — exactly the churn being removed.
  const have = new Map();
  list.querySelectorAll(":scope > .jf-row").forEach((r) => have.set(r.dataset.key, r));
  const want = new Set(entries.map((e) => e.path));
  have.forEach((row, key) => { if (!want.has(key)) row.remove(); });

  // Walk the desired order and place each node in sequence. Appending new rows
  // at the end is the tempting shortcut and it breaks the ordering the API
  // guarantees (directories before files) the moment a directory appears
  // mid-run. Sequencing also repairs a reorder for free.
  let cursor = null;
  for (const e of entries) {
    let row = have.get(e.path);
    if (row && row.dataset.shape !== _jfShape(e)) {
      const fresh = _jfMakeRow(id, e);
      row.replaceWith(fresh);
      row = fresh;
    } else if (row) {
      // During a run the only thing that moves is the size — a growing
      // `solver.sage.stdout`. Patch that text node and leave the row alone.
      const sz = row.querySelector(".jf-size");
      const txt = _fmtFileSize(e.size);
      if (sz && sz.textContent !== txt) sz.textContent = txt;
    } else {
      row = _jfMakeRow(id, e);
      // Only ARRIVALS animate. Animating a first paint would make every open of
      // the panel shimmer through its whole directory, which is the same noise
      // in a different costume.
      if (!opts.firstPaint) {
        row.classList.add("jf-new");
        // Drop the class once it has played, so a later reorder of the same row
        // does not replay the animation.
        setTimeout(() => row.classList.remove("jf-new"), 700);
      }
    }
    const next = cursor ? cursor.nextElementSibling : list.firstElementChild;
    if (next !== row) list.insertBefore(row, next);
    cursor = row;
  }

  // The two unkeyed siblings, managed explicitly.
  const empty = list.querySelector(":scope > .jf-empty");
  if (!entries.length && !empty) {
    const span = document.createElement("span");
    span.className = "c-dim jf-empty";
    span.textContent = "(empty)";
    list.appendChild(span);
  } else if (entries.length && empty) {
    empty.remove();
  }

  let trunc = list.querySelector(":scope > .jf-trunc");
  if (opts.truncated) {
    if (!trunc) {
      trunc = document.createElement("div");
      trunc.className = "jf-trunc";
      list.appendChild(trunc);
    }
    const t = `⚠ first ${opts.cap} entries only — this directory is larger`;
    if (trunc.textContent !== t) trunc.textContent = t;
    if (trunc !== list.lastElementChild) list.appendChild(trunc);
  } else if (trunc) {
    trunc.remove();
  }
}

/** Delegated, once per box. The old code re-attached a handler to every row
 *  after each rewrite, and used `{ once: true }` on Refresh — which only ever
 *  worked because the button was thrown away and rebuilt on the next poll. Now
 *  that the node survives, a one-shot handler would fire once and die. */
function _jfWire(box, id) {
  if (box.dataset.wired === "1") return;
  box.dataset.wired = "1";
  box.addEventListener("click", (ev) => {
    const nav = ev.target.closest(".jf-dir, .job-files-crumb");
    if (nav) {
      ev.preventDefault();
      loadJobFiles(id, nav.dataset.path || "");
      return;
    }
    if (ev.target.closest(".job-files-refresh")) {
      ev.preventDefault();
      loadJobFiles(id, _jobFilesPath.get(id) || "");
    }
    // `.jf-file` is deliberately not handled here — it carries
    // `file-preview-link`, whose existing delegated handler opens the modal and
    // leaves middle-click / "open in new tab" working.
  });
}

async function loadJobFiles(id, path = "") {
  const box = document.querySelector(`.job-files[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  if (!box) return;
  const list = box.querySelector(".job-files-list");
  const crumbs = box.querySelector(".job-files-crumbs");
  // A navigation shows the rows of the directory being LEFT until the new ones
  // arrive; clearing makes the click feel answered and stops the reconciler
  // from animating a whole directory as if it had streamed in.
  const navigating = _jobFilesPath.get(id) !== path;
  _jobFilesPath.set(id, path);
  if (navigating) list.innerHTML = "";

  const crumbHtml = _jobFilesCrumbs(id, path);
  if (crumbs.innerHTML !== crumbHtml) crumbs.innerHTML = crumbHtml;
  _jfWire(box, id);

  // `Loading…` belongs to a paint with nothing to show, never to a poll. The
  // browser is re-mounted on every job poll, so writing it unconditionally is
  // what made an idle directory blink every couple of seconds.
  const firstPaint = !list.querySelector(".jf-row, .jf-empty");
  if (firstPaint) list.innerHTML = '<span class="c-dim jf-loading">Loading…</span>';

  let data;
  try {
    const res = await fetch(`${API}/jobs/${encodeURIComponent(id)}/files?path=${encodeURIComponent(path)}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
    data = body;
  } catch (e) {
    // A dropped BACKGROUND poll must not erase a good listing — the operator
    // would watch the directory they are reading vanish and come back. Only a
    // paint that has nothing to preserve is allowed to report the error.
    if (firstPaint) {
      list.innerHTML = `<span style="color:var(--red)">${escapeHtml(String(e))}</span>`;
    }
    return;
  }

  // A poll for the old directory can land after the operator has clicked into a
  // new one. Rewriting the list made that self-correcting — the next poll
  // overwrote it — but a RECONCILER would merge the two directories into one
  // listing under the wrong crumb trail. Drop a response that is no longer for
  // the directory on screen.
  if (_jobFilesPath.get(id) !== path) return;

  // Written out rather than `?.remove()`: the UI test harness runs on Node 12
  // and strips optional chaining textually, which would turn a null miss into
  // a throw. Code that cannot be exercised faithfully is code without a test.
  const spinner = list.querySelector(".jf-loading");
  if (spinner) spinner.remove();

  _jfReconcile(list, id, data.entries || [], {
    firstPaint, truncated: !!data.truncated, cap: data.cap,
  });
}

/** Called after the job detail re-renders. Restores the directory the operator
 *  had navigated to — the detail HTML is rebuilt on every poll, so without
 *  this the browser would snap back to the job root every couple of seconds. */
// Last rendered body per job. renderJob() rebuilds the detail every 2s, so
// without this the box is rewritten 30x a minute — which kills text selection
// mid-drag and makes the Copy button unclickable on a moving row.
const _GRAIN_CACHE = new Map();

function _grainRow(line) {
  // Two shapes, and the error one is the point. A harvester that could not run
  // used to be indistinguishable from one that found nothing; note_error()
  // writes the failure into the same file, so it has to be visible here too.
  const f = Object.fromEntries(
    line.split("\t").map((kv) => {
      const i = kv.indexOf("=");
      return i < 0 ? [kv, ""] : [kv.slice(0, i), kv.slice(i + 1)];
    }));
  if ("error" in f || line.startsWith("error\t")) {
    return `<div class="flag-grain-row is-error">
      <span class="flag-grain-when">${escapeHtml(f.at || "")}</span>
      <span class="flag-grain-why">⚠ ${escapeHtml(f.detail || line)}</span>
    </div>`;
  }
  // The run's own adjudication counts. Written once, at the drain. It answers
  // the question an `error` row alone cannot: whether a TimeoutError was the
  // whole story or one retry out of seven. `dropped` is the number that
  // matters — a failure the retry loop absorbed lost nothing, a dropped batch
  // is candidates nobody will ever look at again.
  if (line.startsWith("tally\t")) {
    const drop = parseInt(f.dropped || "0", 10) || 0;
    return `<div class="flag-grain-row is-tally${drop ? " is-lost" : ""}">
      <span class="flag-grain-when">${escapeHtml(f.at || "")}</span>
      <span class="flag-grain-why">adjudicated ${escapeHtml(f.adjudicated || "0")} · accepted ${escapeHtml(f.accepted === undefined ? "?" : f.accepted)} · failed ${escapeHtml(f.failed || "0")} · dropped ${escapeHtml(f.dropped || "0")}</span>
    </div>`;
  }
  if (!f.flag) return "";
  const conf = f.confidence ? `${Math.round(parseFloat(f.confidence) * 100)}%` : "";
  // "후보로" — the harvester cannot promote itself and must not, but the
  // operator can. Job 3a6670825945 finished holding the template artefact
  // `{value}` as its only candidate while the confirmed answer sat here at
  // 0.93; Copy alone left no way to register it. The button posts the value
  // back and the server re-checks it against this same file, so the click is
  // a choice, not an ingress.
  return `<div class="flag-grain-row">
    <span class="flag-grain-when">${escapeHtml(f.at || "")}</span>
    <code class="flag-grain-flag">${escapeHtml(f.flag)}</code>
    <button type="button" class="btn btn-sm flag-grain-copy"
            data-flag="${escapeHtml(f.flag)}">Copy</button>
    <button type="button" class="btn btn-sm flag-grain-promote"
            title="이 값을 이 job의 플래그 후보로 격상 (판정은 별도)"
            data-flag="${escapeHtml(f.flag)}">후보로 ↑</button>
    <span class="flag-grain-conf" title="model confidence">${escapeHtml(conf)}</span>
    <span class="flag-grain-why" title="${escapeHtml(f.sources || "")}">${escapeHtml(f.why || "")}</span>
  </div>`;
}

document.addEventListener("click", async (e) => {
  const b = e.target.closest && e.target.closest(".live-fire-blocked-save");
  if (!b || b.disabled) return;
  const box = b.closest(".live-fire-progress");
  const row = b.closest(".live-fire-snap");
  const id = box && box.dataset.job;
  const input = row && row.querySelector(".live-fire-blocked-input");
  if (!id || !input) return;
  const blocked = input.value.trim();
  if (blocked === "") { input.focus(); return; }
  const slaBox = row.querySelector(".live-fire-sla-input");
  const prev = b.textContent;
  b.disabled = true;
  b.textContent = "…";
  try {
    const res = await fetch(
      `${API}/jobs/${encodeURIComponent(id)}/live-fire/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attempt: Number(b.dataset.attempt),
          blocked: Number(blocked),
          // Only sent when the box is on screen. Absent means "not reported",
          // which the API keeps distinct from false — an unchecked box the
          // operator never looked at is not a failed SLA.
          ...(slaBox ? { sla_pass: slaBox.checked } : {}),
        }),
      });
    const out = await res.json();
    if (!res.ok) throw new Error(out.detail || `HTTP ${res.status}`);
    b.textContent = "기록됨";
    _LF_PROGRESS_CACHE.delete(id);
    setTimeout(() => { b.textContent = prev; b.disabled = false; }, 1200);
  } catch (err) {
    b.textContent = prev;
    b.disabled = false;
    alert(`기록 실패: ${err.message}`);
  }
});

const _LF_PROGRESS_CACHE = new Map();

/** Per-attempt patched ZIPs, published by run_patch_loop the moment an
 *  attempt lands and its diff clears the source policy. Polled from the same
 *  render pass as the flag grain, and for the same reason: the file is on
 *  disk long before the job is over, and the operator needs it now. */
// What each assignment state means to someone reading the panel. The state
// names are the board's, not the UI's — inventing a second vocabulary here
// would mean two things to keep in step.
const _LF_VULN_STATE = {
  "pending": ["대기", "배정 대기"],
  "in-flight": ["패치 중", "blueteam 작업 중"],
  "submitted": ["검증 통과", "validator 통과, 통합 대기"],
  "integrated": ["번들 반영", "패치 통합본에 들어감"],
  "deferred": ["보류", "병합 충돌 — 다음 라운드에 재시도"],
  "failed": ["거부", "validator가 거부 — 새 방향 필요"],
};
const _LF_VULN_CACHE = new Map();
// Diffs are fetched ONCE per job, the first time a row is opened. They are
// not in the board payload because that is polled every couple of seconds and
// a rewritten app.js would cross the wire on every tick.
const _LF_PATCH_CACHE = new Map();

// The FIX cycle. Same job, continued: the workspace, the board, the blueteam
// trees and the version history are all still on disk, so the next bundle is
// V(n+1) in one history rather than a second V1 somewhere else.
document.addEventListener("click", async (e) => {
  const b = e.target.closest && e.target.closest(".live-fire-fix");
  if (!b || b.disabled) return;
  const id = b.dataset.job;
  if (!id) return;
  const prev = b.textContent;
  b.disabled = true;
  b.textContent = "…";
  try {
    const res = await fetch(
      `${API}/jobs/${encodeURIComponent(id)}/live-fire/fix`, { method: "POST" });
    const out = await res.json();
    // The API refuses without feedback, and that refusal is the useful
    // message — surface it rather than a bare HTTP code.
    if (!res.ok) throw new Error(out.detail || `HTTP ${res.status}`);
    b.textContent = "🔧 재시작됨";
    setTimeout(() => { b.textContent = prev; b.disabled = false; }, 4000);
    refreshJobs();
  } catch (err) {
    b.textContent = "🔧 FIX";
    b.disabled = false;
    alert(String(err.message || err));
  }
});

async function loadLiveFirePatches(id) {
  if (_LF_PATCH_CACHE.has(id)) return _LF_PATCH_CACHE.get(id);
  let patches = {};
  try {
    const res = await fetch(
      `${API}/jobs/${encodeURIComponent(id)}/blob?path=live-fire-patches.json`);
    if (res.ok) patches = (await res.json()).patches || {};
  } catch (e) { /* an unreadable diff must not hide the row */ }
  _LF_PATCH_CACHE.set(id, patches);
  return patches;
}

async function toggleLiveFireDiff(id, vid, row) {
  const open = row.querySelector(".live-fire-vuln-diff");
  if (open) { open.remove(); row.classList.remove("is-open"); return; }
  const patches = await loadLiveFirePatches(id);
  const patch = patches[vid];
  const box = document.createElement("pre");
  box.className = "live-fire-vuln-diff";
  // A vulnerability with no validated patch has no diff — say so rather than
  // showing an empty box the operator has to interpret.
  box.textContent = patch && patch.diff
    ? patch.diff
    : "이 취약점은 아직 검증을 통과한 패치가 없습니다.";
  row.appendChild(box);
  row.classList.add("is-open");
}

const _LF_AGENT_CACHE = new Map();
// SIGNATURES LIVE HERE, NOT IN THE DOM. Storing a card's whole markup in a
// data-sig attribute means writing a multi-kilobyte attribute per card and
// then trusting the browser to hand back the exact same string — newlines and
// quotes included — on every read. When it does not, the comparison fails
// every poll and the card is rewritten every poll, which is a flicker with no
// visible cause. A WeakMap keyed by the element cannot disagree with itself,
// and it is released with the node.


// What each lane looks like. The key is the state the round runner writes;
// the label is what the operator reads.
const _LF_AGENT_STATE = {
  running:  ["작업 중", "is-running"],
  retrying: ["재시도", "is-retrying"],
  done:     ["완료", "is-done"],
  failed:   ["실패", "is-failed"],
  idle:     ["대기", "is-idle"],
};

function _lfAgentTitle(row) {
  // The plan agent is now one per part of the bundle, so the lane has to say
  // WHICH part — "Plan agent" over and over is a grid nobody can read.
  if (row.role === "plan") {
    const part = String(row.key).split(":")[1];
    return part ? `Plan · ${part}` : "Plan agent";
  }
  if (row.role === "repo") return "Repo agent";
  return `BT · ${row.key}`;
}

function _lfElapsed(row) {
  const from = Number(row.started_at) || 0;
  if (!from) return "";
  const to = Number(row.finished_at) || (Date.now() / 1000);
  const s = Math.max(0, Math.round(to - from));
  if (s < 60) return `${s}초`;
  return `${Math.floor(s / 60)}분 ${String(s % 60).padStart(2, "0")}초`;
}

// The grid the operator asked for: one card per agent, so blueteams starting
// in the same second are separate lanes rather than identical log lines with
// no vulnerability id between them.
async function mountLiveFireAgents(id) {
  const box = document.querySelector(
    `.live-fire-agents[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  if (!box) return;
  let text = "";
  try {
    const res = await fetch(
      `${API}/jobs/${encodeURIComponent(id)}/blob?path=live-fire-agents.json`);
    // 404 until the first agent starts, and for every v1 job forever.
    if (res.ok) text = await res.text();
  } catch (e) { /* transient; keep what is on screen */ }
  if (!text) { box.hidden = true; return; }

  let payload = null;
  try { payload = JSON.parse(text); } catch (e) { return; }
  const rows = (payload && payload.agents) || [];
  if (!rows.length) { box.hidden = true; return; }
  box.hidden = false;
  const grid = box.querySelector(".live-fire-agents-grid");
  if (!grid) return;

  // Plan first, then the blueteams by id, then repo — the order the work
  // actually happens in, which is what makes the grid readable at a glance.
  const weight = (r) => (r.role === "plan" ? 0 : r.role === "repo" ? 2 : 1);
  const ordered = rows.slice().sort((a, b) =>
    weight(a) - weight(b) || String(a.key).localeCompare(String(b.key)));

  // A running lane's elapsed time changes every tick, so the payload alone
  // cannot gate the repaint the way it does for the board.
  const live = ordered.some((r) => r.state === "running" || r.state === "retrying");
  if (!live && _LF_AGENT_CACHE.get(id) === text && grid.children.length) return;
  _LF_AGENT_CACHE.set(id, text);

  const seen = new Set();
  for (const row of ordered) {
    const key = String(row.key || "");
    if (!key) continue;
    seen.add(key);
    const [label, cls] = _LF_AGENT_STATE[row.state] || [row.state || "?", "is-idle"];
    // THE CLOCK IS NOT PART OF THE SIGNATURE. A running lane's elapsed time
    // changes every tick, so folding it into the markup meant rebuilding the
    // card's whole subtree every couple of seconds — which is what the
    // flicker was. The structure is rewritten only when the state or the
    // detail actually changes; the clock is one text node, set on its own.
    const inner = `
      <div class="live-fire-agent-top">
        <span class="live-fire-agent-name">${escapeHtml(_lfAgentTitle(row))}</span>
        <span class="live-fire-agent-state ${cls}">${escapeHtml(label)}</span>
      </div>
      <div class="live-fire-agent-detail" title="${escapeHtml(row.detail || "")}">${
        escapeHtml(row.detail || "")}</div>
      <div class="live-fire-agent-clock"></div>`;
    let el = grid.querySelector(`[data-agent="${(window.CSS && CSS.escape) ? CSS.escape(key) : key}"]`);
    if (!el) {
      el = document.createElement("div");
      el.className = "live-fire-agent";
      el.dataset.agent = key;
      grid.appendChild(el);
    }
    if (_ROW_SIG.get(el) !== inner) {
      el.innerHTML = inner;
      _ROW_SIG.set(el, inner);
    }
    const clockEl = el.querySelector(".live-fire-agent-clock");
    if (clockEl) {
      const ticked = _lfElapsed(row);
      if (clockEl.textContent !== ticked) clockEl.textContent = ticked;
    }
    // Writing an attribute is a mutation whether or not the value changed.
    const role = row.role || "blueteam", state = row.state || "idle";
    if (el.dataset.role !== role) el.dataset.role = role;
    if (el.dataset.state !== state) el.dataset.state = state;
  }
  for (const el of Array.from(grid.children)) {
    if (!seen.has(el.dataset.agent)) el.remove();
  }
}

// V2 before V10. Ids are V<number>, and sorting them as text puts V10 second.
function _lfVulnOrder(vid) {
  const m = /(\d+)$/.exec(String(vid || ""));
  return m ? Number(m[1]) : Number.MAX_SAFE_INTEGER;
}

async function mountLiveFireVulns(id) {
  const box = document.querySelector(
    `.live-fire-vulns[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  if (!box) return;
  let text = "";
  try {
    const res = await fetch(
      `${API}/jobs/${encodeURIComponent(id)}/blob?path=live-fire-board.json`);
    // 404 is the normal state until the plan agent has named anything, and
    // for every v1 job forever.
    if (res.ok) text = await res.text();
  } catch (e) { /* transient; keep whatever is on screen */ }
  if (!text) { box.hidden = true; return; }

  let board = null;
  try { board = JSON.parse(text); } catch (e) { return; }
  const rows = (board && board.assignments) || [];
  if (!rows.length) { box.hidden = true; return; }
  box.hidden = false;
  const list = box.querySelector(".live-fire-vulns-list");
  if (!list) return;
  // Same rule as the snapshot panel: no wholesale repaint. This polls every
  // couple of seconds and rewriting innerHTML blinks every row even when
  // nothing changed.
  if (_LF_VULN_CACHE.get(id) === text && list.children.length) return;
  _LF_VULN_CACHE.set(id, text);

  const summary = (board && board.patch_summary) || {};
  const seen = new Set();
  for (const row of rows) {
    const v = row.vulnerability || {};
    const vid = String(v.id || "");
    if (!vid) continue;
    seen.add(vid);
    const patch = summary[vid];
    const [label, why] = _LF_VULN_STATE[row.state] || [row.state || "?", ""];
    const attempts = Number(row.attempts) || 0;
    const inner = `
      <span class="live-fire-vuln-id">${escapeHtml(vid)}</span>
      <span class="live-fire-vuln-class">${escapeHtml(v.bug_class || "?")}</span>
      <span class="live-fire-vuln-path" title="${escapeHtml(v.path || "")}">${
        escapeHtml(v.path || "?")}</span>
      <span class="live-fire-vuln-state is-${escapeHtml(row.state || "pending")}"
            title="${escapeHtml(why + (row.reason ? " — " + row.reason : ""))}">${
        escapeHtml(label)}</span>
      <span class="live-fire-vuln-tries" title="blueteam 시도 횟수">${
        attempts ? attempts + "회" : ""}</span>
      <div class="live-fire-vuln-why">${escapeHtml(v.patch_direction || "")}</div>${
        patch
          ? `<button type="button" class="live-fire-vuln-diff-btn"
                     title="blueteam이 실제로 바꾼 내용">
               diff ${patch.paths.length}개 파일
               <span class="live-fire-vuln-plus">+${patch.added}</span>
               <span class="live-fire-vuln-minus">−${patch.removed}</span>
             </button>`
          : ""}`;
    let el = list.querySelector(`[data-vuln="${(window.CSS && CSS.escape) ? CSS.escape(vid) : vid}"]`);
    if (!el) {
      el = document.createElement("div");
      el.className = "live-fire-vuln is-new";
      el.dataset.vuln = vid;
      el.innerHTML = inner;
      // IN PLACE, not appended. Rows are never reordered once drawn — that
      // would make the whole list jump on a poll — so a new one has to land
      // where it belongs. Natural order, because V10 sorted as text sits
      // between V1 and V2 and reads as a bug in the numbering.
      const before = Array.from(list.children).find(
        (other) => _lfVulnOrder(other.dataset.vuln) > _lfVulnOrder(vid));
      list.insertBefore(el, before || null);
      setTimeout(() => el.classList.remove("is-new"), 1200);
    } else if (_ROW_SIG.get(el) !== inner) {
      // An open diff is REBUILT, not lost: the operator opened it to read it,
      // and a poll two seconds later must not close it under them.
      const wasOpen = !!el.querySelector(".live-fire-vuln-diff");
      el.innerHTML = inner;
      if (wasOpen) toggleLiveFireDiff(id, vid, el);
    }
    const btn = el.querySelector(".live-fire-vuln-diff-btn");
    if (btn && !btn.dataset.wired) {
      btn.dataset.wired = "1";
      btn.addEventListener("click", () => toggleLiveFireDiff(id, vid, el));
    }
    _ROW_SIG.set(el, inner);
    const _st = row.state || "pending";
    if (el.dataset.state !== _st) el.dataset.state = _st;
  }
  // A vulnerability never disappears from the board, so a row that is not in
  // the payload is stale markup from a previous job rendered in this slot.
  for (const el of Array.from(list.children)) {
    if (!seen.has(el.dataset.vuln)) el.remove();
  }
}

async function mountLiveFireProgress(id) {
  const box = document.querySelector(
    `.live-fire-progress[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  if (!box) return;
  let text = "";
  let feedbackText = "";
  try {
    const [res, fb] = await Promise.all([
      fetch(`${API}/jobs/${encodeURIComponent(id)}/blob?path=patch-progress.json`),
      fetch(`${API}/jobs/${encodeURIComponent(id)}/blob?path=patch-feedback.json`),
    ]);
    // 404 is the normal state until the first attempt lands, and the feedback
    // file does not exist until the operator has scored a version.
    if (res.ok) text = await res.text();
    if (fb.ok) feedbackText = await fb.text();
  } catch (e) { /* transient; keep whatever is on screen */ }
  if (!text) { box.hidden = true; return; }

  let snapshots = [];
  try { snapshots = (JSON.parse(text) || {}).snapshots || []; } catch (e) { return; }
  const blockedBy = new Map();
  try {
    for (const row of (JSON.parse(feedbackText || "{}").entries || [])) {
      blockedBy.set(row.attempt, row);
    }
  } catch (e) { /* an unreadable feedback file must not hide the snapshots */ }
  if (!snapshots.length) { box.hidden = true; return; }
  box.hidden = false;
  const list = box.querySelector(".live-fire-progress-list");
  // NO WHOLESALE REPAINT. The poll runs every couple of seconds, and rewriting
  // `list.innerHTML` blinked every row even when nothing about them had
  // changed — and took the caret out of whichever input the operator was
  // typing a score into. Rows are reconciled by version instead: an existing
  // one is left alone unless its score changed, and a new version is appended.
  // That is the whole behaviour the operator asked for — the panel sits still
  // and a file appears when the loop publishes one.
  if (!list) return;
  const cacheKey = text + "\u0000" + feedbackText;
  if (_LF_PROGRESS_CACHE.get(id) === cacheKey && list.children.length) return;
  _LF_PROGRESS_CACHE.set(id, cacheKey);
  // The bundle name lives on the job, so the per-version index does not carry
  // a second copy that could disagree with it.
  const sourceName = (box.dataset.source || "").trim() || "source.zip";

  // `09-11 13:07:54` rather than the raw ISO string: the operator compares
  // versions minutes apart, so the year and the offset are noise and the
  // seconds are what tells two of them apart.
  const whenOf = (snap) => {
    const raw = String(snap.at || "");
    const m = raw.match(/^\d{4}-(\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})/);
    return m ? `${m[1]} ${m[2]}` : raw;
  };

  const rowFor = (snap) => {
    const scored = blockedBy.get(snap.attempt);
    const fb = scored && Number.isFinite(scored.blocked)
      ? String(scored.blocked) : "please input";
    const cleared = Number.isFinite(snap.vuln_clear) ? snap.vuln_clear
      : (snap.findings || []).length;
    const ver = Number.isFinite(snap.version) ? snap.version : snap.attempt;
    // `class @ filename`, not the full path: five of these on one line is a
    // paragraph, and the path is one hover away. The line number is dropped
    // when there is none — v2 integrates whole files, and ":?" on every entry
    // reads as missing data rather than as "not applicable".
    const findings = (snap.findings || []).map((f) => {
      const base = String(f.path || "?").split("/").pop();
      const at = Number(f.line) > 0 ? `:${f.line}` : "";
      return `${f.bug_class || "?"} @ ${base}${at}`;
    }).join(" · ");
    const findingsFull = (snap.findings || []).map((f) =>
      `${f.bug_class || "?"} @ ${f.path || "?"}`).join("\n");
    if (!snap.zip) {
      return `<span class="live-fire-snap-when">${escapeHtml(whenOf(snap))}</span>
        <span class="live-fire-snap-ver">V${ver}</span>
        <span class="live-fire-snap-why">⚠ ${escapeHtml(snap.error || "snapshot failed")}</span>`;
    }
    // The operator's own row: when · which version · which bundle · how many
    // bugs are closed in it · what the round said about it. "please input"
    // rather than a blank, because an unscored version is a thing to do.
    return `<span class="live-fire-snap-when">${escapeHtml(whenOf(snap))}</span>
      <span class="live-fire-snap-ver">V${ver}</span>
      <a class="live-fire-snap-dl"
         href="${API}/jobs/${encodeURIComponent(id)}/file/${encodeURIComponent(snap.zip)}"
         download title="${escapeHtml(snap.zip)}">⬇ ${escapeHtml(sourceName)}</a>
      <span class="live-fire-snap-clear">${cleared} vuln clear</span>${
        // v1 publishes a snapshot the moment an attempt lands, BEFORE any
        // verification — that is the whole point of a snapshot on a
        // short tick. v2 cuts a version only after the INTEGRATED bundle
        // has passed the validator, so `verified` is true and saying
        // otherwise would send the operator to re-check work already checked.
        // The field has always been written; nothing read it until now.
        snap.verified
          ? `<span class="live-fire-snap-verified"
                   title="이 통합본이 validator의 요청/응답 코퍼스를 통과했습니다">✓ 검증됨</span>`
          : `<span class="live-fire-snap-unverified"
                   title="검증 전 스냅샷입니다 — 업로드 전에 직접 확인하세요">검증 전</span>`}${
        (snap.unexplained_paths || []).length
          ? `<span class="live-fire-snap-unexplained"
                   title="이 버전에 포함됐지만 어떤 finding도 설명하지 않는 변경:\n${
                     escapeHtml((snap.unexplained_paths || []).join("\n"))}"
             >⚠ ${(snap.unexplained_paths || []).length} unexplained</span>`
          : ""}
      <span class="live-fire-snap-why" title="${escapeHtml(findingsFull)}"
        >${escapeHtml(findings)}</span>
      <div class="live-fire-blocked${scored ? " is-scored" : ""}">
        <label title="이 버전을 올린 뒤 라운드가 막은 공격 수">operator feedback :
        <input type="number" class="live-fire-blocked-input" min="0" max="10000"
               placeholder="${escapeHtml(fb)}"
               data-attempt="${snap.attempt}"
               value="${scored && Number.isFinite(scored.blocked) ? scored.blocked : ""}" />
        </label>
        <label class="live-fire-sla"
               title="채점 서버가 이 번들을 SLA 통과로 판정했는지. validator는 자기 코퍼스로만 판단하므로, 여기서 FAIL이면 그 코퍼스가 놓친 것이 있다는 뜻입니다.">
          <input type="checkbox" class="live-fire-sla-input"
                 data-attempt="${snap.attempt}"${
            scored && scored.sla_pass === true ? " checked" : ""} />
          <span>SLA pass</span>
        </label>
        <button type="button" class="btn btn-sm live-fire-blocked-save"
                data-attempt="${snap.attempt}">기록</button>
      </div>`;
  };

  for (const snap of snapshots) {
    const key = String(snap.attempt);
    let row = list.querySelector(`.live-fire-snap[data-attempt="${CSS && CSS.escape ? CSS.escape(key) : key}"]`);
    const html = rowFor(snap);
    if (!row) {
      row = document.createElement("div");
      row.className = "live-fire-snap" + (snap.zip ? "" : " is-error") + " is-new";
      row.dataset.attempt = key;
      row.innerHTML = html;
      list.appendChild(row);
      // One-shot: the class is dropped so a later reconcile does not replay
      // the entrance on a row that has been on screen for minutes.
      setTimeout(() => row.classList.remove("is-new"), 900);
      continue;
    }
    // Leave a row that has not changed completely alone — replacing identical
    // markup is what the flicker was.
    if (row.innerHTML !== html && !row.contains(document.activeElement)) {
      row.innerHTML = html;
    }
  }
}


async function mountFlagGrain(id) {
  const box = document.querySelector(
    `.flag-grain[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  if (!box) return;
  let text = "";
  try {
    const res = await fetch(`${API}/jobs/${encodeURIComponent(id)}/blob?path=flag_grain.txt`);
    // 404 is the normal state for most of a run — the harvester writes only
    // when it accepts something. Stay hidden rather than showing an empty box
    // on every job.
    if (res.ok) text = await res.text();
  } catch (e) { /* transient; keep whatever is on screen */ }

  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  if (!lines.length) { box.hidden = true; return; }
  box.hidden = false;
  const list = box.querySelector(".flag-grain-list");
  // Skip the repaint only when the content is unchanged AND the rows are still
  // on screen. renderJob() rewrites detail.innerHTML every 2s and only
  // `.job-files` is carried across, so this box is a BRAND NEW empty element
  // on every pass — a cache guard that looked at the text alone unhid an empty
  // box forever after the first paint, which is exactly "flag_grain 표시가
  // 안된다". The DOM check is what makes the guard safe.
  if (_GRAIN_CACHE.get(id) === text && list && list.children.length) return;
  _GRAIN_CACHE.set(id, text);

  const flags = lines.filter((l) => l.startsWith("flag=")).length;
  // Count the error lines, do NOT infer them from "everything that is not a
  // flag". The tally line broke that inference the day it was added: a healthy
  // run with one absorbed retry rendered as "1 flag · 2 errors".
  const errs = lines.filter((l) => l.startsWith("error\t")).length;
  box.querySelector(".flag-grain-count").textContent =
    `${flags} flag${flags === 1 ? "" : "s"}${errs ? ` · ${errs} error${errs === 1 ? "" : "s"}` : ""}`;
  if (list) list.innerHTML = lines.map(_grainRow).join("");
}

document.addEventListener("click", (e) => {
  const b = e.target.closest && e.target.closest(".flag-grain-copy");
  if (!b) return;
  const v = b.dataset.flag || "";
  const done = () => { const t = b.textContent; b.textContent = "copied"; setTimeout(() => { b.textContent = t; }, 1200); };
  if (navigator.clipboard) navigator.clipboard.writeText(v).then(done).catch(() => {});
  else done();
});

// Promoting mutates the job's flag state, so unlike Copy it confirms first and
// re-renders after. The job id comes from the enclosing box rather than from a
// per-row attribute: `_grainRow` is called with one line and no job context,
// and passing the id into every row would be a third place it could drift.
document.addEventListener("click", async (e) => {
  const b = e.target.closest && e.target.closest(".flag-grain-promote");
  if (!b || b.disabled) return;
  const box = b.closest(".flag-grain");
  const id = box && box.dataset.job;
  const flag = b.dataset.flag || "";
  if (!id || !flag) return;
  if (!confirm("이 값을 플래그 후보로 격상할까요?\n\n"
               + flag + "\n\n"
               + "후보가 될 뿐 정답 확정은 아닙니다 — job이 flag_ready 로 돌아가고, "
               + "판정 배너에서 따로 확인해야 합니다.")) return;
  const prev = b.textContent;
  b.disabled = true;
  b.textContent = "격상 중…";
  try {
    const res = await fetch(
      `${API}/jobs/${encodeURIComponent(id)}/flag-grain/promote`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flag }),
      });
    const out = await res.json();
    if (!res.ok) throw new Error(out.detail || `HTTP ${res.status}`);
    // renderJob() rebuilds the detail from scratch, but the grain box is
    // repaint-guarded on unchanged text — and the text has NOT changed, only
    // meta has. Drop the guard or the new state never reaches the screen.
    _GRAIN_CACHE.delete(id);
    await renderJob(id);
    await refreshJobs();
  } catch (err) {
    b.textContent = prev;
    b.disabled = false;
    alert(`격상 실패: ${err.message}`);
  }
});

function mountJobFiles(id) {
  const box = document.querySelector(`.job-files[data-job="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`);
  if (!box) return;
  loadJobFiles(id, _jobFilesPath.get(id) || "");
}

async function openFileModal(name, sourceUrl) {
  const modal = document.getElementById("file-modal");
  if (!modal) return;
  const body = modal.querySelector(".file-modal-body");
  const nameEl = modal.querySelector(".file-modal-name");
  const metaEl = modal.querySelector(".file-modal-meta");
  const rawLink = modal.querySelector(".file-modal-raw");
  const copyBtn = modal.querySelector(".file-modal-copy");

  nameEl.textContent = name;
  metaEl.textContent = "loading…";
  rawLink.href = sourceUrl;
  body.innerHTML = "";
  modal.hidden = false;
  modal.dataset.url = sourceUrl;
  modal.dataset.name = name;

  // Images short-circuit BEFORE the fetch. Two reasons, and the second is the
  // one that matters: `res.text()` would decode the bytes as UTF-8 and hand
  // back mojibake, and it would also pull the whole file into a JS string to
  // throw it away. <img> streams it and the browser decodes it properly.
  if (_isImage(name)) {
    copyBtn.hidden = true;              // "copy the raw bytes" means nothing here
    const img = document.createElement("img");
    img.className = "file-modal-image";
    img.alt = name;
    img.onload = () => {
      metaEl.textContent = `${img.naturalWidth} × ${img.naturalHeight}`;
    };
    img.onerror = () => {
      // Kept as a message rather than a broken-image glyph: a 404 and an
      // undecodable file look identical otherwise, and on a live job the
      // former is normal (the agent may still be writing it).
      metaEl.textContent = "not an image, or not readable";
      body.innerHTML = `<pre class="file-modal-error">이 파일을 이미지로 표시할 수 없습니다. `
        + `"Open raw"로 원본을 받으십시오.</pre>`;
    };
    img.src = sourceUrl;
    body.appendChild(img);
    modal.dataset.raw = "";
    return;
  }
  copyBtn.hidden = false;

  let text;
  try {
    const res = await fetch(sourceUrl);
    if (!res.ok) {
      metaEl.textContent = `error ${res.status}`;
      body.innerHTML = `<pre class="file-modal-error">${escapeHtml(await res.text())}</pre>`;
      return;
    }
    text = await res.text();
  } catch (e) {
    metaEl.textContent = "fetch failed";
    body.innerHTML = `<pre class="file-modal-error">${escapeHtml(String(e))}</pre>`;
    return;
  }
  modal.dataset.raw = text;
  metaEl.textContent = `${text.length.toLocaleString()} bytes`;

  // Render based on extension.
  if (_isJson(name)) {
    let pretty = text;
    try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch (_) {}
    const code = `<pre><code class="language-json">${escapeHtml(pretty)}</code></pre>`;
    body.innerHTML = code;
  } else if (_isMarkdown(name)) {
    if (window.marked) {
      const html = window.marked.parse(text, { mangle: false, headerIds: false });
      body.innerHTML = `<div class="markdown-rendered">${html}</div>`;
    } else {
      body.innerHTML = `<pre><code class="language-markdown">${escapeHtml(text)}</code></pre>`;
    }
  } else {
    const lang = _languageFor(name);
    body.innerHTML = `<pre><code class="language-${lang}">${escapeHtml(text)}</code></pre>`;
  }

  // Highlight every code block (including those produced by marked).
  if (window.hljs) {
    body.querySelectorAll("pre code").forEach((el) => {
      try { window.hljs.highlightElement(el); } catch (_) {}
    });
  }

  // Wire one-shot Copy that pulls from the cached raw.
  // navigator.clipboard is only defined in secure contexts (HTTPS / localhost);
  // over HTTP via a LAN IP it's undefined and `.writeText` throws TypeError.
  // Fall back to a transient textarea + document.execCommand("copy"), which
  // works on plain HTTP too.
  copyBtn.onclick = async () => {
    const text = modal.dataset.raw || "";
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        ok = true;
      }
    } catch (_) { /* fall through to legacy path */ }
    if (!ok) {
      try {
        const tmp = document.createElement("textarea");
        tmp.value = text;
        tmp.setAttribute("readonly", "");
        tmp.style.position = "fixed";
        tmp.style.left = "-9999px";
        document.body.appendChild(tmp);
        tmp.select();
        ok = document.execCommand("copy");
        tmp.remove();
      } catch (_) { ok = false; }
    }
    if (ok) {
      const orig = copyBtn.textContent;
      copyBtn.textContent = "✓ Copied";
      setTimeout(() => (copyBtn.textContent = orig), 1200);
    } else {
      alert("Copy failed. Select the text manually and use Ctrl+C.");
    }
  };
}

function _closeFileModal() {
  const modal = document.getElementById("file-modal");
  if (!modal) return;
  modal.hidden = true;
  modal.dataset.url = "";
  modal.dataset.name = "";
  modal.dataset.raw = "";
}

// Single delegated click handler for all file-preview links + the modal's
// own close/backdrop/Escape. Set up once at load.
document.addEventListener("click", (e) => {
  const link = e.target.closest("a.file-preview-link");
  if (link) {
    // Allow modifier-clicks (new tab / window / download) to fall through
    // to the browser's normal link behavior.
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) {
      return;
    }
    e.preventDefault();
    openFileModal(link.dataset.name, link.dataset.url);
    return;
  }
  if (e.target.closest(".file-modal-close, .file-modal-backdrop")) {
    _closeFileModal();
    return;
  }
  if (e.target.closest(".job-modal-close, .job-modal-backdrop")) {
    _closeJobModal();
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  // File preview is on top of the job modal — close that one first.
  const fileModal = document.getElementById("file-modal");
  if (fileModal && !fileModal.hidden) {
    _closeFileModal();
    return;
  }
  const jobModal = document.getElementById("job-modal");
  if (jobModal && !jobModal.hidden) {
    _closeJobModal();
  }
});

fillModelSelects();
fillEffortSelects();
// Load Settings once at boot so agent_provider is known before the
// operator opens a form (per-job model catalogs follow the provider).
loadSettings().catch(() => {});
loadModelPresets();
loadTunnelStatus();
try { showSettingsPane(localStorage.getItem(SETTINGS_PANE_KEY)); } catch (_) { showSettingsPane(""); }
refreshJobs();
refreshStats();

// Global heartbeat — keeps the job list AND the flag alarm live even when
// no detail panel is open (the per-job pollers only run for the open job).
// Guarded so a slow /jobs fetch can't pile up overlapping refreshes. ~7s
// is cheap (a dir scan) and well under a run's flag-capture latency.
let _globalPollBusy = false;
setInterval(async () => {
  if (_globalPollBusy) return;
  _globalPollBusy = true;
  try { await refreshJobs(); await refreshStats(); } catch (_) {} finally { _globalPollBusy = false; }
}, 7000);

// --- Version / last-patch badge -------------------------------------------
// Fills the header #version-badge from GET /api/version so the operator can
// confirm at a glance that a redeploy actually took (recurring "container ran
// the old image / stale code" class of bug). `commit` is stamped at deploy;
// `patched_at` is the live newest source mtime (always current). Shows the
// most recent of the two as the date, and flags when live code is newer than
// the stamped commit (i.e. an un-deployed/hot edit).
(function initVersionBadge() {
  const el = document.getElementById('version-badge');
  if (!el) return;
  const fmt = (iso) => {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d)) return '';
    return d.toLocaleString('ko-KR', {
      year: '2-digit', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hour12: false,
    });
  };
  fetch('/api/version', { credentials: 'same-origin' })
    .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
    .then((v) => {
      const ver = v.commit ? ('#' + v.commit) : ('v' + (v.version || '?'));
      // "last patch" = the freshest signal we have
      const dates = [v.patched_at, v.deployed_at, v.commit_date].filter(Boolean);
      dates.sort();
      const latest = dates.length ? dates[dates.length - 1] : null;
      el.textContent = ver + (latest ? ' · ' + fmt(latest) : '');
      // warn (amber) if live source is newer than the stamped commit date
      const stale = v.patched_at && v.commit_date && v.patched_at > v.commit_date
        && (!v.deployed_at || v.patched_at > v.deployed_at);
      el.classList.toggle('version-badge--dirty', !!stale);
      el.title =
        'version ' + (v.version || '?') +
        '\ncommit ' + (v.commit || 'n/a') + (v.commit_date ? ' (' + fmt(v.commit_date) + ')' : '') +
        '\ndeployed ' + (v.deployed_at ? fmt(v.deployed_at) : 'n/a') +
        '\nlast patch (live) ' + (v.patched_at ? fmt(v.patched_at) : 'n/a') +
        (stale ? '\n⚠ live code newer than stamped commit — redeploy/stamp pending' : '');
    })
    .catch(() => { el.textContent = ''; });
})();

// --- Containers tab ---------------------------------------------------------
// Inventory + manual cleanup. Exists because agent-started challenge containers
// have no lifecycle owner: `_hard_stop_job` reaps a job's siblings by the
// `hextech_ctf_tool_job_id` label, and a container the agent starts from Bash
// carries no label, so nothing ever removes it. Three from job fd844946db78
// were still running 11-19h after it finished, each holding a 2 GiB cgroup
// reservation. This is the operator's way to see and clear that.
let _containersPoll = null;

function _fmtPct(v) { return v == null ? "—" : v.toFixed ? v.toFixed(1) + "%" : v + "%"; }

function _memCell(c) {
  if (c.state !== "running") return '<span class="c-dim">—</span>';
  const use = c.mem_usage ? fmtBytes(c.mem_usage) : "?";
  const cap = c.mem_cap ? fmtBytes(c.mem_cap) : "uncapped";
  // A high `usage` that is mostly reclaimable page cache is not a container
  // about to OOM, so only the unreclaimable figure drives the warning colour.
  const real = c.mem_unreclaimable || c.mem_usage || 0;
  const hot = c.mem_cap && real > c.mem_cap * 0.8;
  const nocap = !c.mem_cap;
  const cls = hot ? "c-hot" : nocap ? "c-warn" : "";
  return `<span class="${cls}">${use} / ${cap}</span>` +
         (c.mem_pct != null ? ` <span class="c-dim">(${_fmtPct(c.mem_pct)})</span>` : "");
}

function _catBadge(cat) {
  return `<span class="c-badge c-badge--${cat}">${cat}</span>`;
}

// Attribution, with its provenance made visible. `label` is authoritative —
// the container was tagged at creation. `name` is a GUESS off an 8-12 hex run
// in the container name, which is all an older container has, so it is marked
// with ~ and says so on hover. Anything else genuinely cannot be attributed:
// the containers carry no JOB_ID env and no /data/jobs bind, and by the time
// they are noticed the job that made them has usually been deleted.
function _jobCell(c) {
  if (!c.job_id) {
    return '<span class="c-dim" title="no job label, and the name carries no job id — ' +
           'created before container labelling shipped">unknown</span>';
  }
  if (c.job_source === "label") {
    return `<code>${escapeHtml(c.job_id)}</code>`;
  }
  return `<code class="c-guess" title="guessed from the container name, not a label — verify before acting on it">` +
         `~${escapeHtml(c.job_id)}</code>`;
}

/* ---------------------------------------------------------- process detail
   Clicking a container opens its process list. Two things this deliberately
   does NOT do:

   - It does not join the 15 s auto-refresh. One detail fetch costs a stats
     call plus either two execs and a ~1 s sampling window, or a `docker top`;
     folding that into a poll that already spends ~2 s on stats would make an
     open row dominate every tick. It is one-shot, with its own Refresh.
   - It does not re-fetch when the list re-renders. The rows are rebuilt every
     poll, so the open panel is restored from the LAST payload instead — the
     same lesson the reviewer panel learned when it vanished on re-render
     (73d78c). Stale-but-labelled beats disappearing. */
const _procOpen = new Set();      // container ids currently expanded
const _procData = new Map();      // id -> last payload, or {error} / {loading}

function _procRow(p, memBase) {
  // memBase is the container's cgroup limit. A process' share of THAT is the
  // number that means something; ps' own %MEM is a share of host RAM, which
  // reads as ~0 for anything inside a 4 GiB-capped worker.
  const share = (memBase && p.rss) ? (100 * p.rss / memBase) : null;
  const cpu = p.cpu_pct == null
    ? '<span class="c-dim" title="appeared during the sampling window — no baseline to measure against">new</span>'
    : `<span class="${p.cpu_pct >= 80 ? "c-hot" : p.cpu_pct >= 20 ? "c-warn" : ""}">${_fmtPct(p.cpu_pct)}</span>`;
  return `<tr>
    <td><code>${p.pid == null ? "?" : p.pid}</code></td>
    <td class="c-dim">${p.ppid == null ? "" : p.ppid}</td>
    <td>${cpu}</td>
    <td>${p.rss == null ? '<span class="c-dim">—</span>' : fmtBytes(p.rss)}` +
      (share == null ? "" : ` <span class="c-dim">(${share.toFixed(1)}%)</span>`) + `</td>
    <td class="c-dim">${p.threads == null ? "" : p.threads}</td>
    <td class="c-dim">${escapeHtml(p.state || p.user || "")}</td>
    <td><code class="proc-cmd" title="${escapeHtml(p.cmd || "")}">${escapeHtml(p.cmd || "")}</code></td>
  </tr>`;
}

function _procPanel(id, d) {
  if (!d) return '<span class="c-dim">Loading…</span>';
  if (d.loading) return '<span class="c-dim">Reading processes…</span>';
  if (d.error) return `<span style="color:var(--red)">${escapeHtml(d.error)}</span>`;
  if (!d.running) return `<span class="c-dim">${escapeHtml(d.note || "not running")}</span>`;

  const ps = (d.processes || []).slice().sort((a, b) =>
    ((b.cpu_pct || 0) - (a.cpu_pct || 0)) || ((b.rss || 0) - (a.rss || 0)));

  const srcCls = d.source === "proc" ? "proc-src--live" : "proc-src--avg";
  const srcLabel = d.source === "proc"
    ? `live /proc · ${d.window_s}s window`
    : "docker top · lifetime average";

  // The per-process sum and the cgroup figure disagree by design. Showing them
  // side by side with the reason is the point: a reader who sees only one of
  // them will treat the other as a bug when they meet it later.
  const sum = d.rss_sum
    ? `<span title="${escapeHtml(d.rss_sum_note || "")}">Σ RSS ${fmtBytes(d.rss_sum)}</span>`
    : "";
  const cg = d.mem_usage ? `cgroup ${fmtBytes(d.mem_usage)}` : "";
  const memLine = (cg && sum)
    ? `${cg} · ${sum} <span class="c-dim">— these differ on purpose: RSS counts a shared page once per process, the cgroup counts it once</span>`
    : (cg || sum);

  // The list around this panel refreshes on its own; this panel does not. Say
  // how old it is, and say it louder once it is older than one list tick.
  const ageS = d.fetched_at ? Math.round((Date.now() - d.fetched_at) / 1000) : null;
  const age = ageS == null ? ""
    : `<span class="${ageS >= 15 ? "c-warn" : "c-dim"}" title="this panel is one-shot — the list refreshes without it">` +
      `${ageS < 2 ? "just now" : ageS + "s ago"}</span>`;

  return `
    <div class="proc-head">
      <span class="proc-src ${srcCls}" title="${escapeHtml(d.source_note || "")}">${srcLabel}</span>
      ${d.source_fallback ? `<span class="c-warn" title="${escapeHtml(d.source_fallback)}">⚠ fell back</span>` : ""}
      <span class="c-dim">${ps.length} process${ps.length === 1 ? "" : "es"}</span>
      ${age}
      <span class="proc-mem">${memLine}</span>
      <button class="btn btn-sm proc-refresh" data-id="${escapeHtml(id)}">Refresh</button>
    </div>
    <p class="proc-note c-dim">${escapeHtml(d.source_note || "")}</p>
    ${ps.length ? `<table class="proc-table">
      <thead><tr><th>PID</th><th>PPID</th><th>CPU</th><th>RSS (of cap)</th>
      <th>Thr</th><th>${d.source === "proc" ? "State" : "User"}</th><th>Command</th></tr></thead>
      <tbody>${ps.map((p) => _procRow(p, d.mem_limit)).join("")}</tbody>
    </table>` : '<span class="c-dim">No processes reported.</span>'}`;
}

async function loadProcesses(id) {
  _procData.set(id, { loading: true });
  _paintProcPanel(id);
  try {
    const res = await fetch(`/api/containers/${encodeURIComponent(id)}/processes`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
    // Stamped because the panel does NOT ride the list's auto-refresh. With
    // that refresh on by default, a stale panel would otherwise sit next to a
    // row whose CPU and memory updated 15 s ago and read as the same instant.
    body.fetched_at = Date.now();
    _procData.set(id, body);
  } catch (e) {
    _procData.set(id, { error: `Could not read processes: ${e}` });
  }
  _paintProcPanel(id);
}

/** Repaint one open panel in place, so a Refresh does not rebuild the table. */
function _paintProcPanel(id) {
  // Same guard the other four call sites use: jsdom (which the UI suites run
  // app.js under) does not always provide CSS.escape.
  const esc = (window.CSS && CSS.escape) ? CSS.escape(id) : id;
  const cell = document.querySelector(`.proc-detail[data-id="${esc}"] td`);
  if (!cell) return;
  cell.innerHTML = _procPanel(id, _procData.get(id));
  cell.querySelector(".proc-refresh")?.addEventListener("click", () => loadProcesses(id));
}

function toggleProcesses(id) {
  if (_procOpen.has(id)) {
    _procOpen.delete(id);
    _procData.delete(id);
  } else {
    _procOpen.add(id);
    loadProcesses(id);
  }
  renderContainers(_lastContainers);
}

let _lastContainers = null;

function renderContainers(data) {
  const el = document.getElementById("containers-list");
  if (!el) return;
  if (data) _lastContainers = data; else data = _lastContainers || {};
  const cs = data.containers || [];
  const sum = document.getElementById("containers-summary");
  if (sum) {
    const k = data.counts || {};
    sum.textContent = `${cs.length} total — ${k.challenge || 0} challenge · ` +
      `${k.sandbox || 0} sandbox · ${k.tunnel || 0} tunnel · ${k.core || 0} core` +
      (data.running_jobs && data.running_jobs.length
        ? ` · running jobs: ${data.running_jobs.join(", ")}` : "");
  }
  if (!cs.length) { el.innerHTML = '<p style="color:var(--fg-muted)">No containers.</p>'; return; }

  const rows = cs.map((c) => {
    const disk = c.size_rw != null ? fmtBytes(c.size_rw) : "—";
    const running = c.state === "running";
    const btn = c.protected
      ? `<button class="btn btn-sm" disabled title="${escapeHtml(c.warn || "protected")}">protected</button>`
      : `<button class="btn btn-sm c-del" data-id="${escapeHtml(c.id)}" data-name="${escapeHtml(c.name)}"` +
        ` data-warn="${escapeHtml(c.warn || "")}"` +
        ` data-job="${escapeHtml(c.job_id ? (c.job_source === "label" ? c.job_id : "~" + c.job_id) : "")}">delete</button>`;
    const age = c.age_days == null ? "" :
      `<br><span class="${c.age_days >= 7 ? "c-warn" : "c-dim"}">${c.age_days}d old</span>`;
    // Only a running container has processes to show, so only it is clickable
    // — an affordance that leads to "not running" is a worse answer than no
    // affordance.
    const open = _procOpen.has(c.id);
    const expandable = running;
    const caret = expandable
      ? `<span class="proc-caret${open ? " proc-caret--open" : ""}">▶</span>`
      : "";
    return `<tr class="${c.warn ? "c-row--warn" : ""}${expandable ? " c-row--click" : ""}"` +
      `${expandable ? ` data-proc-id="${escapeHtml(c.id)}"` : ""}` +
      `${expandable ? ' title="show processes in this container"' : ""}>
      <td>${caret}<code>${escapeHtml(c.name)}</code><br><span class="c-dim">${escapeHtml(c.id)}</span></td>
      <td>${_jobCell(c)}${age}</td>
      <td>${_catBadge(c.category)}${c.compose_service ? `<br><span class="c-dim">${escapeHtml(c.compose_service)}</span>` : ""}</td>
      <td><span class="c-state c-state--${running ? "up" : "down"}">${escapeHtml(c.state)}</span></td>
      <td>${_memCell(c)}</td>
      <td>${running ? _fmtPct(c.cpu_pct) : '<span class="c-dim">—</span>'}</td>
      <td>${disk}</td>
      <td><span class="c-dim">${escapeHtml(c.image || "")}</span><br><span class="c-dim">${escapeHtml(c.created || "")}</span></td>
      <td>${btn}</td>
    </tr>` + (c.warn ? `<tr class="c-warnrow"><td colspan="9">⚠ ${escapeHtml(c.warn)}</td></tr>` : "")
      + (open ? `<tr class="proc-detail" data-id="${escapeHtml(c.id)}"><td colspan="9"></td></tr>` : "");
  }).join("");

  el.innerHTML = `<table class="containers-table">
    <thead><tr><th>Name / id</th><th>Job / age</th><th>Kind</th><th>State</th><th>Memory</th><th>CPU</th>
    <th>Disk (rw)</th><th>Image / created</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table>`;

  el.querySelectorAll(".c-del").forEach((b) => {
    b.addEventListener("click", () => deleteContainer(b.dataset.id, b.dataset.name, b.dataset.warn, b.dataset.job));
  });
  el.querySelectorAll("tr[data-proc-id]").forEach((tr) => {
    tr.addEventListener("click", (ev) => {
      // The delete button lives inside the clickable row; a click on it must
      // not also toggle the panel underneath.
      if (ev.target.closest("button")) return;
      toggleProcesses(tr.dataset.procId);
    });
  });
  // Re-render rebuilt every row, so every open panel needs repainting from
  // cache. Without this the detail row is an empty <td> after each poll.
  _procOpen.forEach((id) => _paintProcPanel(id));
}

async function loadContainers() {
  const el = document.getElementById("containers-list");
  try {
    const res = await fetch("/api/containers");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderContainers(await res.json());
  } catch (e) {
    if (el) el.innerHTML = `<p style="color:var(--red)">Could not list containers: ${escapeHtml(String(e))}</p>`;
  }
}

async function deleteContainer(id, name, warn, job) {
  // Two-step ONLY when the backend flagged a cost — an unflagged leftover is
  // the common case and should not need a second click.
  let msg = `Delete container ${name} (${id})?`;
  if (job) msg += `\nJob: ${job}${job.startsWith("~") ? "  (guessed from the name)" : ""}`;
  if (warn) msg += `\n\n⚠ ${warn}\n\nThis cannot be undone. Continue?`;
  if (!confirm(msg)) return;
  if (warn && !confirm(`Really delete ${name}?\n\n${warn}`)) return;
  try {
    const res = await fetch(`/api/containers/${encodeURIComponent(id)}`, { method: "DELETE" });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { alert(`Delete failed:\n\n${body.detail || res.status}`); return; }
    if (body.note) alert(`Removed ${body.removed}.\n\n${body.note}`);
  } catch (e) {
    alert(`Delete failed: ${e}`);
  }
  loadContainers();
}

function _stopContainersPoll() {
  if (_containersPoll) { clearInterval(_containersPoll); _containersPoll = null; }
}

/** (Re)arm the poll from the checkbox's CURRENT state.
 *
 *  This is a function rather than the body of the `change` handler for two
 *  reasons, both of which only bite once the box defaults to checked:
 *
 *   - A checkbox that starts checked fires no `change` event, so wiring the
 *     poll to that event alone would ship a box that says it is polling and
 *     is not.
 *   - The tick below STOPS the poll when the panel is not active, which is
 *     what keeps a background tab from spending ~2 s of docker stats every
 *     15 s. Nothing restarted it on the way back in, so the box stayed
 *     checked while auto-refresh was quietly dead. Re-arming on tab entry is
 *     what makes leaving and returning work.
 */
function _startContainersPoll() {
  _stopContainersPoll();
  if (!document.getElementById("containers-auto")?.checked) return;
  // 15s, not the usual few seconds: each refresh costs ~2s of docker stats
  // calls on the daemon (one sample per running container, in parallel).
  _containersPoll = setInterval(() => {
    if (document.getElementById("panel-containers")?.classList.contains("active")) loadContainers();
    else _stopContainersPoll();
  }, 15000);
}

document.getElementById("containers-refresh")?.addEventListener("click", loadContainers);
document.getElementById("containers-auto")?.addEventListener("change", _startContainersPoll);
document.querySelector('.tab[data-tab="containers"]')?.addEventListener("click", () => {
  loadContainers();
  _startContainersPoll();
});
// Belt and braces for the default-on box: if the panel is somehow already the
// active one at load (a restored tab, a future deep link), nothing would have
// clicked the tab and the poll would never arm.
if (document.getElementById("panel-containers")?.classList.contains("active")) {
  loadContainers();
  _startContainersPoll();
}

/* ------------------------------------------------------------------ Dashboard
   One place to watch a run: live job rows plus memory rings. The jobs list is
   rendered by refreshJobs() into the same #jobs-list node it always used — it
   moved panels, it was not rewritten — so this section only owns the rings. */

// fmtBytes() answers "what is this container's CAP" and returns the string
// "unlimited" for 0, which is right there and wrong here: 0 bytes used is a
// number, not an absence of a limit.
function _dashBytes(n) {
  if (!Number.isFinite(n) || n < 0) return "?";
  if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " GiB";
  if (n >= 1048576) return Math.round(n / 1048576) + " MiB";
  return Math.round(n / 1024) + " KiB";
}

/** A donut. `pct` null renders an empty track rather than a zero-length arc,
 *  so "we could not measure this" is visibly different from "this is at 0%". */
function _dashRing(pct, label, value, size = 56, badge = "") {
  const r = (size - 8) / 2;
  const c = 2 * Math.PI * r;
  const known = Number.isFinite(pct);
  const shown = known ? Math.max(0, Math.min(100, pct)) : 0;
  const cls = !known ? "" : shown >= 90 ? " high" : shown >= 75 ? " warn" : "";
  return `<div class="dash-ring${cls}">
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img"
         aria-label="${escapeHtml(label)} ${known ? shown + "%" : "unknown"}">
      <circle class="dash-ring-track" cx="${size/2}" cy="${size/2}" r="${r}"
              fill="none" stroke-width="6"></circle>
      <circle class="dash-ring-fill" cx="${size/2}" cy="${size/2}" r="${r}"
              fill="none" stroke-width="6" stroke-linecap="round"
              stroke-dasharray="${(shown/100*c).toFixed(2)} ${c.toFixed(2)}"
              transform="rotate(-90 ${size/2} ${size/2})"></circle>
      <text x="50%" y="50%" text-anchor="middle" dominant-baseline="central"
            class="dash-ring-value" fill="currentColor"
            >${known ? Math.round(shown) + "%" : "—"}</text>
    </svg>
    <span class="dash-ring-label" title="${escapeHtml(label + (value ? " — " + value : ""))}"
      >${escapeHtml(label)}</span>
    ${value ? `<span class="dash-sub">${escapeHtml(value)}</span>` : ""}
    ${badge ? `<span class="dash-ring-job${badge === "idle" ? " idle" : ""}"
        title="${escapeHtml(badge === "idle" ? "no job on this slot" : "running job " + badge)}"
      >${escapeHtml(badge)}</span>` : ""}
  </div>`;
}

let _dashPoll = null;

async function loadDashboard() {
  const ringsEl = document.getElementById("dash-container-rings");
  const hostEl = document.getElementById("dash-host-ring");
  const detailEl = document.getElementById("dash-host-detail");
  if (!ringsEl || !hostEl) return;
  let data;
  try {
    // sizes=false skips the per-container disk walk, which is the slow half of
    // this endpoint. The rings only need memory.
    const res = await fetch(`${API}/containers?sizes=false`);
    data = await res.json();
  } catch (_) {
    ringsEl.innerHTML = '<p class="dash-sub">container stats unavailable</p>';
    return;
  }

  const hm = data.host_mem || {};
  if (hm.available) {
    hostEl.innerHTML = _dashRing(hm.used_pct, "used", "", 92);
    detailEl.textContent =
      `${_dashBytes(hm.used_bytes)} of ${_dashBytes(hm.total_bytes)} · ` +
      `${_dashBytes(hm.available_bytes)} available`;
  } else {
    hostEl.innerHTML = "";
    detailEl.textContent = "host memory unreadable";
  }

  // Running only: a stopped container reports no memory_stats, so every ring
  // would be an unmeasurable "—" and drown the ones that mean something.
  const running = (data.containers || []).filter((c) => c.state === "running");

  // Order: infrastructure first, then worker slots by NUMBER, then everything
  // else. Docker returns its own order and the previous code kept it, which
  // read fine at two slots and became worker-1, worker-10, worker-11,
  // worker-12, worker-2 at twelve — a plain string sort of a numbered series.
  const slotNo = (c) => {
    const m = /^worker-(\d+)$/.exec(c.compose_service || "");
    return m ? parseInt(m[1], 10) : null;
  };
  const rank = (c) => {
    const svc = c.compose_service || "";
    if (svc === "api") return 0;
    if (svc === "redis") return 1;
    return slotNo(c) !== null ? 2 : 3;
  };
  running.sort((a, b) => {
    const ra = rank(a), rb = rank(b);
    if (ra !== rb) return ra - rb;
    const na = slotNo(a), nb = slotNo(b);
    if (na !== null && nb !== null) return na - nb;
    return String(a.compose_service || a.name || "")
      .localeCompare(String(b.compose_service || b.name || ""), undefined,
                     { numeric: true });
  });

  ringsEl.innerHTML = running.length
    ? running.map((c) => {
        // A worker slot never carries the job label — that rides the challenge
        // containers the agent spawns — so `job_id` is null for slots and the
        // API hands us `slot_job_id` instead. Show it: a wall of identical
        // `worker-N` rings cannot answer "which slot is my job on?".
        const busy = c.slot_job_id;
        const label = c.job_id
          ? `${c.category}·${c.job_id.slice(0, 8)}`
          : (c.compose_service || c.name || "?");
        const sub = `${_dashBytes(c.mem_usage)} / ${fmtBytes(c.mem_limit)}`;
        return _dashRing(c.mem_pct, label, sub, 56,
                         busy ? busy.slice(0, 8) : (slotNo(c) !== null ? "idle" : ""));
      }).join("")
    : '<p class="dash-sub">no running containers</p>';
}

function _stopDashPoll() {
  if (_dashPoll) { clearInterval(_dashPoll); _dashPoll = null; }
}

document.querySelector('.tab[data-tab="dashboard"]')?.addEventListener("click", () => {
  loadDashboard();
  _stopDashPoll();
  // 15s for the same reason the containers panel uses it: each refresh is a
  // docker stats sample per running container, ~1s each on the daemon. The job
  // rows are NOT on this timer — the global poll already refreshes them.
  _dashPoll = setInterval(() => {
    if (document.getElementById("panel-dashboard").classList.contains("active")) loadDashboard();
    else _stopDashPoll();
  }, 15000);
});

/* ------------------------------------------------------------------ *
 * AI Player — 사이트를 탐색해 job을 만드는 에이전트
 *
 * 이 패널이 비밀번호를 다루는 유일한 지점이다. 값은 POST 한 번으로 서버의
 * 0600 저장소에 들어가고, 이후 어떤 응답에도 실려 오지 않는다. /sites 는
 * 아이디만 돌려주므로 이 화면은 비밀번호를 다시 렌더링할 수단이 없다.
 * ------------------------------------------------------------------ */
let _playerPoll = null;
let _playerSite = "";

async function playerLoadSites() {
  const tbody = document.querySelector("#player-sites tbody");
  if (!tbody) return;
  try {
    const res = await fetch("/api/player/sites");
    const data = await res.json();
    const rows = data.sites || [];
    tbody.innerHTML = rows.length
      ? rows.map((s) => `<tr>
          <td>${escapeHtml(s.site)}<br><small>${escapeHtml(s.url || "")}</small></td>
          <td>${escapeHtml(s.username || "")}</td>
          <td>${s.created} / ${s.claims}</td>
          <td>${escapeHtml(s.state || "idle")}</td>
          <td><button type="button" data-player-forget="${escapeHtml(s.site)}">삭제</button></td>
        </tr>`).join("")
      : `<tr><td colspan="5" class="player-empty">저장된 사이트가 없습니다.</td></tr>`;
  } catch (_e) {
    tbody.innerHTML = `<tr><td colspan="5" class="player-empty">목록을 불러오지 못했습니다.</td></tr>`;
  }
}

async function playerRefresh() {
  if (!_playerSite) return;
  const sum = document.getElementById("player-summary");
  const log = document.getElementById("player-log");
  const tbody = document.querySelector("#player-claims tbody");
  try {
    const res = await fetch(`/api/player/status?site=${encodeURIComponent(_playerSite)}&lines=400`);
    const d = await res.json();
    const st = (d.state && d.state.state) || "idle";
    sum.textContent = `${_playerSite} — ${st} · 생성 ${d.created}건 / 청구 ${(d.claims || []).length}건`
      + (d.state && d.state.exit_code !== undefined && d.state.exit_code !== null
         ? ` · exit ${d.state.exit_code}` : "");
    const rows = d.claims || [];
    tbody.innerHTML = rows.length
      ? rows.slice().reverse().map((c) => `<tr>
          <td>${escapeHtml(c.name || c.challenge_id || "")}</td>
          <td>${escapeHtml(c.module || "")}</td>
          <td>${c.job_id ? `<code>${escapeHtml(c.job_id)}</code>` : "—"}</td>
          <td class="${c.state === "created" ? "player-ok" : "player-warn"}">${escapeHtml(c.state || "")}${
            c.detail ? `<br><small>${escapeHtml(String(c.detail).slice(0, 120))}</small>` : ""}</td>
        </tr>`).join("")
      : `<tr><td colspan="4" class="player-empty">아직 없습니다.</td></tr>`;
    log.textContent = (d.log || []).join("\n");
    log.scrollTop = log.scrollHeight;
    // 끝난 실행을 계속 두드릴 이유가 없다.
    if (["finished", "failed", "stopped", "idle"].includes(st) && _playerPoll) {
      clearInterval(_playerPoll); _playerPoll = null;
      playerLoadSites();
    }
  } catch (_e) { /* 폴링 실패는 조용히 넘긴다 */ }
}

function playerStartPoll(site) {
  _playerSite = site;
  if (_playerPoll) clearInterval(_playerPoll);
  playerRefresh();
  _playerPoll = setInterval(playerRefresh, 4000);
}

document.addEventListener("DOMContentLoaded", () => {
  const credForm = document.getElementById("player-cred-form");
  if (!credForm) return;

  credForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = document.getElementById("player-cred-msg");
    const fd = new FormData(credForm);
    msg.textContent = "저장 중…";
    try {
      const res = await fetch("/api/player/credentials", { method: "POST", body: fd });
      const d = await res.json();
      if (!res.ok) throw new Error(d.detail || "저장 실패");
      msg.textContent = `저장됨: ${d.site}`;
      // 비밀번호 입력값은 화면에 남기지 않는다.
      credForm.querySelector('input[name="password"]').value = "";
      const startUrl = document.querySelector('#player-start-form input[name="site_url"]');
      if (startUrl && !startUrl.value) startUrl.value = fd.get("site_url");
      playerLoadSites();
    } catch (err) { msg.textContent = String(err.message || err); }
  });

  document.getElementById("player-start-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const msg = document.getElementById("player-start-msg");
    const fd = new FormData(form);
    msg.textContent = "시작 중…";
    try {
      const res = await fetch("/api/player/start", { method: "POST", body: fd });
      const d = await res.json();
      if (!res.ok) throw new Error(d.detail || "시작 실패");
      // 사이트 키 규칙은 서버(player_creds.site_key)에만 둔다. 화면에서
      // 다시 계산하면 두 곳이 조용히 갈라진다.
      const site = d.site;
      msg.textContent = `실행 중 (${d.run_id || site})`;
      playerStartPoll(site);
    } catch (err) { msg.textContent = String(err.message || err); }
  });

  document.getElementById("player-stop").addEventListener("click", async () => {
    if (!_playerSite) return;
    const msg = document.getElementById("player-start-msg");
    const fd = new FormData(); fd.append("site", _playerSite);
    try {
      await fetch("/api/player/stop", { method: "POST", body: fd });
      msg.textContent = "중지 요청함";
      playerRefresh();
    } catch (err) { msg.textContent = String(err.message || err); }
  });

  document.querySelector("#player-sites").addEventListener("click", async (e) => {
    const site = e.target && e.target.dataset && e.target.dataset.playerForget;
    if (!site) return;
    if (!confirm(`${site} 계정을 삭제할까요? 이미 만든 job 은 그대로 남습니다.`)) return;
    await fetch(`/api/player/credentials/${encodeURIComponent(site)}`, { method: "DELETE" });
    playerLoadSites();
  });

  document.querySelectorAll('.tab[data-tab="player"]').forEach((t) =>
    t.addEventListener("click", () => { playerLoadSites(); playerRefresh(); }));
});
