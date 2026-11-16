#!/usr/bin/env node
// LF-5 browser contract. Pure-source extraction keeps this runnable on the
// host's old Node without jsdom while still executing the production renderer.

const fs = require("fs");
const path = require("path");

const mutation = process.argv[2] || "none";
// A CSS mutation cannot go through `src`, so it gets its own hook.
let cssMutate = (t) => t;
const root = path.resolve(__dirname, "..");
let src = fs.readFileSync(path.join(root, "web-ui/app.js"), "utf8");
const html = fs.readFileSync(path.join(root, "web-ui/index.html"), "utf8");
const main = fs.readFileSync(path.join(root, "api/main.py"), "utf8");

let passed = 0, failed = 0;
function check(label, got, want = true) {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    passed++; console.log("PASS  " + label);
  } else {
    failed++; console.log(`FAIL  ${label}\n      got  = ${JSON.stringify(got)}\n      want = ${JSON.stringify(want)}`);
  }
}

function sliceFn(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start === -1) return null;
  let i = source.indexOf("{", start), depth = 0;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}" && --depth === 0) return source.slice(start, i + 1);
  }
  return null;
}

if (mutation === "ready-state") {
  src = src.replace("job.ready_to_deploy === true", "job.ready_to_deploy === false");
} else if (mutation === "unverified-state") {
  src = src.replace(
    "else if (job.ready_to_deploy === false)",
    "else if (job.ready_to_deploy === true)",
  );
} else if (mutation === "evidence-tier") {
  src = src.replace(
    "const tiers = Array.isArray(job.evidence_tiers)",
    "const tiers = false && Array.isArray(job.evidence_tiers)",
  );
} else if (mutation === "artifact-download") {
  src = src.replace(
    'href="${API}/jobs/${encodeURIComponent(jobId)}/file/report.md"',
    'href="${API}/jobs/${encodeURIComponent(jobId)}/file/patched.zip"',
  );
} else if (mutation === "agent-grid-file") {
  src = src.replace("path=live-fire-agents.json", "path=live-fire-board.json");
} else if (mutation === "agent-grid-live") {
  src = src.replace("  if (!live && _LF_AGENT_CACHE.get(id) === text",
                    "  if (_LF_AGENT_CACHE.get(id) === text");
} else if (mutation === "agent-grid-role") {
  src = src.replace('if (row.role === "plan") return "Plan agent";', "");
} else if (mutation === "agent-grid-order") {
  src = src.replace(
    'const weight = (r) => (r.role === "plan" ? 0 : r.role === "repo" ? 2 : 1);',
    "const weight = (r) => 1;",
  );
} else if (mutation === "sig-in-dom") {
  src = src.replace("_ROW_SIG.get(el) !== inner", "el.dataset.sig !== inner")
           .replace("_ROW_SIG.set(el, inner)", "el.dataset.sig = inner");
} else if (mutation === "pill-flicker") {
  src = src.replace('<span class="agent-pill" data-live-agent="${id}"></span>',
                    '<span class="agent-pill" data-agent-at="${escapeHtml(job.last_agent_event_at)}">⚡</span>');
} else if (mutation === "cost-flicker") {
  src = src.replace('<span class="meta-chip" data-live-cost="${id}">cost </span>',
                    '_metaChip("cost ", "$" + Number(job.cost_usd).toFixed(4))');
} else if (mutation === "tokens-flicker") {
  src = src.replace('<div class="run-log-footer" data-job-id="${id}"></div>',
                    '<div class="run-log-footer">${tokensPill}</div>');
} else if (mutation === "row-cost-in-sig") {
  src = src.replace('const cost = `<span class="row-cost"></span>`;',
                    'const cost = costText;');
} else if (mutation === "list-remove-move") {
  src = src.replace("if (ul.children[_slot] !== li) ul.insertBefore(li, ul.children[_slot] || null);",
                    "ul.appendChild(li);");
} else if (mutation === "card-attr-churn") {
  src = src.replace("if (el.dataset.role !== role) el.dataset.role = role;",
                    "el.dataset.role = role;");
} else if (mutation === "list-flicker") {
  src = src.replace("    if (_ROW_SIG.get(li) !== _rowHtml) {", "    if (true) {");
} else if (mutation === "list-handler-stack") {
  src = src.replace('if (fresh) li.addEventListener("click"', 'if (true) li.addEventListener("click"');
} else if (mutation === "detail-flicker") {
  src = src.replace('<pre class="run-log" data-job-id="${id}" data-status="${escapeHtml(job.status || "")}"></pre>',
                    '<pre class="run-log" data-job-id="${id}">${_volatile.log}</pre>');
} else if (mutation === "detail-flicker-skip") {
  src = src.replace("_cheapHash(_nextHtml)) {\n    _paintVolatile(id, _volatile);",
                    "_cheapHash(_nextHtml)) {");
} else if (mutation === "agent-grid-flicker") {
  src = src.replace('<div class="live-fire-agent-clock"></div>`',
                    '<div class="live-fire-agent-clock">${escapeHtml(_lfElapsed(row))}</div>`');
} else if (mutation === "agent-grid-clamp") {
  cssMutate = (t) => t.replace("-webkit-line-clamp: 2;", "");
}

const rendererSource = sliceFn(src, "liveFireOutcomeHtml");
check("live-fire result renderer exists", !!rendererSource);
if (!rendererSource) process.exit(1);
const escapeHtml = (value) => String(value).replace(/[&<>\"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[char]);
const render = new Function(
  "API", "escapeHtml", `${rendererSource}\nreturn liveFireOutcomeHtml;`,
)("/api", escapeHtml);

const ready = render({
  module: "live-fire", status: "finished", ready_to_deploy: true,
  evidence_tiers: ["B"],
}, "job one");
check("ready_to_deploy=true renders READY", ready.includes("<strong>READY</strong>"));
check("READY shows evidence tier B", ready.includes("tier B"));
check("READY is not labelled UNVERIFIED", ready.includes("<strong>UNVERIFIED</strong>"), false);

const unverified = render({
  module: "live-fire", status: "finished", ready_to_deploy: false,
  evidence_tiers: ["A"],
}, "job two");
check("ready_to_deploy=false renders UNVERIFIED", unverified.includes("<strong>UNVERIFIED</strong>"));
check("UNVERIFIED shows evidence tier A", unverified.includes("tier A"));
check("UNVERIFIED never inherits READY", unverified.includes("<strong>READY</strong>"), false);
check("UNVERIFIED explicitly warns against deployment", unverified.includes("do not treat as deployable"));

for (const artifact of ["patched.zip", "report.md", "verification.json"]) {
  check(`${artifact} has its own download URL`,
    unverified.includes(`/file/${artifact}`) && unverified.includes(`⬇ ${artifact}`));
}
check("job ids are URL encoded in downloads", unverified.includes("job%20two"));
check("non-live-fire jobs get no live-fire panel", render({module: "web"}, "x"), "");

const pending = render({
  module: "live-fire", status: "running", ready_to_deploy: null,
  evidence_tiers: [],
}, "pending");
check("an in-flight job says PENDING, not UNVERIFIED", pending.includes("<strong>PENDING</strong>"));
check("downloads wait for a finished job", pending.includes("patched.zip"), false);

const formStart = html.indexOf('id="live-fire-form"');
const form = html.slice(formStart, html.indexOf("</form>", formStart));
for (const field of ["file", "verification", "description", "model", "effort", "output_language", "job_timeout"]) {
  check(`live-fire form sends ${field}`, form.includes(`name="${field}"`));
}
check("live-fire submit uses its dedicated API route",
  /live-fire-form[\s\S]{0,180}\/modules\/live-fire\/analyze/.test(src));
check("API app registers only a dedicated live-fire prefix",
  main.includes('prefix="/api/modules/live-fire"'));
check("no fixed 480/120 deadline is present in the live-fire form",
  !/\b(?:480|120)\b/.test(form));

// --- the snapshot panel must not blink -------------------------------------
// THE SAME BUG, THREE TIMES. renderJob() re-assigns detail.innerHTML every
// couple of seconds, so any panel that is filled by an AWAITED fetch starts
// each pass empty and hidden. `.job-files` learned this, then `.flag-grain`
// ("flag grain이 정신없이 주기적으로 깜빡거림"), and then the patch-snapshot
// list ("패치 스냅샷 UI가 지속적으로 깜빡거리는데"). The cure is the same:
// carry the LIVE node into the rebuilt tree.
check("the snapshot panel is captured before the rebuild",
  /const _keptProgress = detail\.querySelector\(`\.live-fire-progress\[data-job=/.test(src));
check("...and put back after it",
  /if \(_keptProgress\) \{[\s\S]{0,300}?_freshP\.replaceWith\(_keptProgress\)/.test(src));

// Carrying the node is only half of it: a wholesale `list.innerHTML = ...`
// on every poll blinks rows that did not change and evicts the caret from the
// score input the operator is typing into.
const mountProgress = sliceFn(src, "mountLiveFireProgress");
check("the snapshot mount exists", !!mountProgress);
if (mountProgress) {
  check("no wholesale repaint of the row list",
    /list\.innerHTML\s*=/.test(mountProgress), false);
  check("rows are reconciled by version",
    /querySelector\(`\.live-fire-snap\[data-attempt=/.test(mountProgress));
  check("a new version is appended, not redrawn into place",
    mountProgress.includes("list.appendChild(row)"));
  check("an unchanged row is left alone",
    /row\.innerHTML !== html/.test(mountProgress));
  check("a row being typed into is never rewritten",
    /!row\.contains\(document\.activeElement\)/.test(mountProgress));
  check("an arriving version is marked so it can animate in",
    mountProgress.includes('"is-new"') && mountProgress.includes('classList.remove("is-new")'));
}
// --- the vulnerability board the plan agent fills ------------------------
// The operator asked to SEE what was identified, not only what shipped. The
// panel is fed by live-fire-board.json, which the round runner rewrites the
// moment the board changes rather than at the end of a round: a blueteam turn
// is minutes, and on a short tick news that arrives with the final
// report arrives too late to act on.
const mountVulns = sliceFn(src, "mountLiveFireVulns");
check("the vulnerability mount exists", !!mountVulns);
if (mountVulns) {
  check("it reads the board the runner publishes",
    mountVulns.includes("path=live-fire-board.json"));
  check("no wholesale repaint of the row list",
    /list\.innerHTML\s*=/.test(mountVulns), false);
  check("rows are reconciled by vulnerability id",
    /querySelector\(`\[data-vuln=/.test(mountVulns));
  check("an unchanged row is left alone",
    /_ROW_SIG\.get\(el\) !== inner/.test(mountVulns));
  // NOT in a data-sig attribute: that writes a card's whole markup — quotes
  // and newlines — into the DOM and then trusts the browser to hand back the
  // identical string on every read. When it does not, the comparison fails
  // every poll, the row is rewritten every poll, and the flicker has no
  // visible cause.
  check("...and the signature is kept out of the DOM",
    !/dataset\.sig/.test(src) && src.includes("const _ROW_SIG = new WeakMap()"));
  check("an arriving vulnerability is marked so it can animate in",
    mountVulns.includes('"is-new"') && mountVulns.includes('classList.remove("is-new")'));
  check("a missing board is the normal state, not an error",
    mountVulns.includes("box.hidden = true"));
}
// --- what the blueteam ACTUALLY changed -------------------------------
// The board carries the plan agent's `patch_direction` — what SHOULD be done.
// That is not the same as what WAS done: on job 2de379a0139f the first V2 and
// V3 attempts followed their direction exactly, were refused for breaking the
// SLA, and the second attempts succeeded by doing something the direction had
// not asked for. Only the diff shows that.
const loadPatches = sliceFn(src, "loadLiveFirePatches");
const toggleDiff = sliceFn(src, "toggleLiveFireDiff");
check("the diff loader exists", !!loadPatches);
check("the diff toggle exists", !!toggleDiff);
if (loadPatches) {
  check("diffs come from their own file, not the polled board",
    loadPatches.includes("path=live-fire-patches.json"));
  check("...and are fetched once per job",
    loadPatches.includes("_LF_PATCH_CACHE"));
}
if (toggleDiff) {
  check("a vulnerability with no validated patch says so",
    toggleDiff.includes("검증을 통과한 패치가 없습니다"));
}
if (mountVulns) {
  check("the row offers the diff only when there is one",
    /patch\s*\n?\s*\?/.test(mountVulns) || mountVulns.includes("patch\n          ?"));
  check("the row shows the size of the change",
    mountVulns.includes("patch.added") && mountVulns.includes("patch.removed"));
  check("an open diff survives the poll that rebuilds its row",
    mountVulns.includes("wasOpen"));
}

// --- a new bundle raises an alarm ---------------------------------------
// The operator asked for this to work "like the flag alarm", and it does —
// same container, same beep, same click-to-open, driven from the same jobs
// poll. It is deliberately NOT sticky: a flag ends a job and must never
// scroll past unseen, while a live-fire job publishes a version per tick and
// a pile of undismissed dialogs mid-contest is a worse outcome than a toast
// that fades. The version history panel is the durable record.
const patchToast = sliceFn(src, "_showPatchToast");
const patchDetect = sliceFn(src, "_detectPatchTransitions");
check("the patch toast exists", !!patchToast);
check("the patch transition detector exists", !!patchDetect);
if (patchToast) {
  check("it reuses the flag toast container and beep",
    patchToast.includes("_flagToastContainer()") && patchToast.includes("_flagBeep()"));
  check("clicking it opens the job", patchToast.includes("selectJob(job.id)"));
  check("it fades rather than sticking, unlike a flag",
    patchToast.includes('classList.add("leaving")'));
  // The OPTION, not the word: the comment explaining why it is absent
  // contains the word, and a bare containment check fails on the comment
  // while the option could be there. Same trap S2 hit in the stack suite.
  check("the OS notification does not demand interaction either",
    !/requireInteraction\s*:/.test(patchToast));
}
if (patchDetect) {
  check("it fires only on an INCREASE in published versions",
    patchDetect.includes("versions > seen"));
  check("...and seeds its baseline first, so opening the page is silent",
    patchDetect.includes("_patchAlarmReady"));
}
check("the detector runs on the same poll as the flag one",
  /_detectFlagTransitions\(data\.jobs\);\s*\n\s*_detectPatchTransitions\(data\.jobs\);/.test(src));
check("the patch toast has its own colour",
  fs.readFileSync(path.join(root, "web-ui/style.css"), "utf8").includes(".flag-toast.patch"));

// --- SLA verdict and the FIX cycle --------------------------------------
// `blocked` says how many attacks a bundle stopped. SLA pass says whether the
// scoring server judged the service still WORKING, and that is ground truth
// the validator cannot produce: its corpus is a guess at what the scoring
// server asks, so a failed SLA on a bundle the validator passed means the
// guess missed something.
if (mountProgress) {
  check("each version can record the scoring server's SLA verdict",
    mountProgress.includes("live-fire-sla-input"));
}
// The save is a delegated listener, not part of the mount — checked against
// the whole source rather than the mount's slice.
check("...and it is sent only when the box is on screen",
  src.includes("slaBox ? { sla_pass: slaBox.checked } : {}"));
if (mountProgress) {
  check("a recorded pass comes back checked",
    mountProgress.includes("scored.sla_pass === true"));
}
const fixHandler = src.slice(src.indexOf('closest(".live-fire-fix")'),
                             src.indexOf('closest(".live-fire-fix")') + 1400);
check("the FIX button reaches the resume route",
  fixHandler.includes("/live-fire/fix"));
check("...and surfaces the API's refusal rather than a bare status",
  fixHandler.includes("out.detail"));
check("the FIX button is offered on v2 only",
  rendererSource.indexOf("live-fire-fix") > rendererSource.indexOf("live_fire_version"));

// --- the row reads as three aligned lines ------------------------------
// It used to be a wrapping flex row, so the findings pushed themselves onto
// their own line and the feedback controls onto two more — five versions read
// as a wall of text with nothing lining up between them.
const cssNow = cssMutate(fs.readFileSync(path.join(root, "web-ui/style.css"), "utf8"));
check("the row is a grid with fixed leading columns",
  /\.live-fire-snap \{[^}]*display:\s*grid/.test(cssNow)
    && /grid-template-columns:\s*[\d.]+rem/.test(cssNow));
check("findings and controls each get a full-width line",
  /\.live-fire-snap-why,\s*\n\.live-fire-blocked \{ grid-column: 1 \/ -1/.test(cssNow));
check("the findings line never wraps",
  /\.live-fire-snap-why \{[^}]*white-space:\s*nowrap/.test(cssNow));
if (mountProgress) {
  check("findings show the filename, not the whole path",
    mountProgress.includes('String(f.path || "?").split("/").pop()'));
  check("...with the full paths in the title",
    mountProgress.includes("findingsFull"));
  check("a missing line number is omitted, not rendered as '?'",
    mountProgress.includes("Number(f.line) > 0"));
  check("the timestamp is trimmed to what distinguishes two versions",
    mountProgress.includes("whenOf(snap)"));
  check("the SLA label is a sibling, not a label inside a label",
    /<div class="live-fire-blocked/.test(mountProgress)
      && !/<label class="live-fire-blocked/.test(mountProgress));
}
check("the FIX button sits in flow, not floated out of it",
  /\.live-fire-fix \{[^}]*margin-left:\s*auto/.test(cssNow));

check("the panel is carried across the 2s repaint, like the snapshot panel",
  src.includes("_keptVulns"));
check("...and is mounted wherever the snapshot panel is",
  src.split("mountLiveFireVulns(id);").length - 1 >= 2);
check("the renderer emits the panel", rendererSource.includes("live-fire-vulns"));
// The state words come from the board, so the UI cannot drift into a second
// vocabulary for the same thing.
for (const state of ["pending", "in-flight", "submitted", "integrated", "deferred", "failed"]) {
  check(`the panel can render the '${state}' state`, src.includes(`"${state}":`));
}

// --- verified vs unverified -------------------------------------------
// The two engines publish on DIFFERENT TERMS. v1 emits a snapshot the moment
// an attempt lands, before any check — that is the point of a snapshot on a
// short tick. v2 cuts a version only once the INTEGRATED bundle has
// passed the validator. One label for both told the operator of a v2 job
// that verified vulnerabilities were "검증 전", sending them to re-check
// work the validator had already done. The `verified` field was in
// patch-progress.json from the first version and nothing read it.
if (mountProgress) {
  check("a row says whether THAT version was verified",
    mountProgress.includes("snap.verified"));
  check("...with both outcomes spelled out",
    mountProgress.includes("live-fire-snap-verified")
      && mountProgress.includes("live-fire-snap-unverified"));
}
check("the panel heading follows the engine, not v1",
  rendererSource.includes("live_fire_version") &&
  rendererSource.includes("validator 통과 후"));
check("...and v1 keeps its own wording",
  rendererSource.includes("시도마다 즉시, 검증 전"));

const css = fs.readFileSync(path.join(root, "web-ui/style.css"), "utf8");
check("the verified badge is styled", css.includes(".live-fire-snap-verified"));
check("the vulnerability entrance animation exists", css.includes("lf-vuln-in"));
check("...and is dropped for reduced motion",
  /prefers-reduced-motion[\s\S]{0,120}?\.live-fire-vuln\.is-new \{ animation: none/.test(css));
check("the entrance animation exists", css.includes("live-fire-snap-in"));
check("...and is dropped for reduced motion",
  /prefers-reduced-motion[\s\S]{0,160}?\.live-fire-snap\.is-new \{ animation: none/.test(css));

// --- every module form lays out the same way ---------------------------
// Fourteen to seventeen labels in a single column made each module a long
// scroll where a `select` owned a whole row. The fields that are genuinely
// wide keep the width; the rest pair up. Done entirely in CSS with :has(),
// which this stylesheet already relies on, so no form id, field name or
// listener had to change — the regression block below is what guarantees it.
check("module forms lay out as a grid",
  /\.panel > form \{[^}]*display:\s*grid/.test(cssNow));
check("...that collapses to one column on a narrow screen",
  /max-width:\s*780px[\s\S]{0,120}\.panel > form \{ grid-template-columns: 1fr/.test(cssNow));
check("wide fields still span the full width",
  /\.panel > form > label:has\(textarea\)/.test(cssNow)
    && /\.panel > form > label:has\(input\[type="file"\]\)/.test(cssNow));
check("the settings form keeps its own layout",
  !/^form \{[^}]*display:\s*grid/m.test(cssNow));

// One baseline for job-detail headings, at zero specificity so the sections
// that already style their own keep winning.
check("job-detail headings have a floor that nothing has to fight",
  /\.job-modal-body :where\(h4\)/.test(cssNow));
check("...and it is :where(), so existing panel rules still win",
  !/\.job-modal-body h4 \{/.test(cssNow));

// --- the flicker, at its real source ------------------------------------
// The panels reconcile themselves row by row, and then the modal around them
// was rebuilt whole every two seconds anyway: the elapsed pill and three
// blocks that GROW while a job runs were all baked into the string whose hash
// gates the rebuild, so the string differed on every poll.
// Matched on the EMITTED markup, not a loose pattern: an older comment in
// this file contains the string `<pre class="run-log">` and a bare regex
// found that instead, passing while the real element still carried the log.
check("the growing blocks are not in the hashed html",
  src.includes('<pre class="run-log" data-job-id="${id}" data-status="${escapeHtml(job.status || "")}"></pre>')
    && src.includes('<div class="gpt-timeline-feed" data-job-id="${id}"></div>')
    && src.includes('<div class="monitor-feed" data-job-id="${id}"></div>'));
check("...and the elapsed pill carries no number either",
  /timing-pill live[^`]*⏱ <span class="timing-tag">running<\/span>/.test(src));
check("the live pill is still filled, once a second, in place",
  src.includes("pill.firstChild && (pill.firstChild.nodeValue"));

const paintFn = sliceFn(src, "_paintVolatile") || "";
check("they are painted into their containers instead",
  paintFn.includes("pre.run-log") && paintFn.includes("div.gpt-timeline-feed")
    && paintFn.includes("div.monitor-feed"));
check("...only when the content actually changed",
  paintFn.includes("el.dataset.painted ==="));
check("...keeping the scroll, because a <pre> that jumps to the top is unreadable",
  paintFn.includes("wasAtBottom") && paintFn.includes("el.scrollTop = el.scrollHeight"));
check("painted on BOTH paths: the skip and the rebuild",
  (src.match(/_paintVolatile\(id, _volatile\)/g) || []).length === 2);

// Everything in the hashed html that MOVES while a job runs. Found by
// extracting every ${...} in the template and tracing each back to its
// assignment, rather than one at a time as the operator kept reporting it.
check("the agent pill carries neither a number nor a timestamp",
  src.includes('<span class="agent-pill" data-live-agent="${id}"></span>')
    && src.includes("_tickLivePill"));
// __htmlDiff() caught this one: the number was gone and the modal still
// rebuilt every poll, because `data-agent-at` carries last_agent_event_at
// and that moves every five seconds. An attribute nobody can see was worth
// 114ms of innerHTML per poll.
check("...and the timestamp is written in place instead",
  /ap\.dataset\.agentAt !== parts\.agentAt/.test(src)
    && /agentAt: \(job\.status === "running"/.test(src));
check("cost is a live span, not a baked chip",
  src.includes('data-live-cost="${id}"')
    && !src.includes('_metaChip("cost "'));
check("the tokens pill is painted, not hashed",
  src.includes('<div class="run-log-footer" data-job-id="${id}"></div>'));
check("...and all three go through the same painter",
  /put\("div\.run-log-footer", parts\.tokens\)/.test(src)
    && /parts\.cost != null/.test(src));

// The job LIST is on screen the whole time and was wiped and rebuilt every
// seven seconds by the global heartbeat, whether or not a panel was open.
const listFn = sliceFn(src, "refreshJobs") || "";
check("the job list is reconciled, not wiped",
  !/\n\s*ul\.innerHTML = "";/.test(listFn)
    && listFn.includes("_ROW_SIG.get(li) !== _rowHtml"));
check("...a row is rewritten only when its content changed",
  listFn.includes("_ROW_SIG.set(li, _rowHtml)"));
// MEASURED, not reasoned: __uiChurn() counted 1765 mutations in jobs-list in
// ten seconds — more than every other panel put together — because
// appendChild on an element already in the document MOVES it, so re-appending
// every row on every poll re-ordered the list into itself.
check("a row already in place is not moved",
  listFn.includes("ul.children[_slot] !== li")
    && !/\n\s*ul\.appendChild\(li\);/.test(listFn));
check("a running job's cost does not rewrite its whole row",
  listFn.includes('<span class="row-cost"></span>')
    && listFn.includes("costEl.textContent !== costText"));
check("...and it is put at its own index, not the end",
  listFn.includes("ul.insertBefore(li, ul.children[_slot] || null)"));
check("...and one that is gone is removed",
  listFn.includes("alive.has(li.dataset.id)") && listFn.includes("li.remove()"));
// Two lifetimes: the <li> click survives innerHTML, the buttons inside do not.
check("the row click is bound once, when the row is created",
  /if \(fresh\) li\.addEventListener\("click"/.test(listFn));
check("...and the buttons are re-bound whenever the row is rewritten",
  /_ROW_SIG\.set\(li, _rowHtml\);[\s\S]{0,220}delete-btn[\s\S]{0,220}copy-jobid-btn/.test(listFn));

// --- the agent grid ----------------------------------------------------
// run.log cannot drive this: blueteams starting in the same second write
// identical "blueteam agent starting" lines with no vulnerability id
// between them, so the grid reads a file with one row per lane.
const agentsFn = sliceFn(src, "mountLiveFireAgents") || "";
check("the grid reads its own per-agent file",
  agentsFn.includes("live-fire-agents.json"));
check("...and stays hidden until an agent has started",
  agentsFn.includes("box.hidden = true"));
check("...and a fetch that fails keeps what is on screen",
  /catch \(e\) \{ \/\* transient/.test(agentsFn));

const titleFn = sliceFn(src, "_lfAgentTitle");
const elapsedFn = sliceFn(src, "_lfElapsed");
const _lfAgentTitle = eval(`(${titleFn})`);
const _lfElapsed = eval(`(${elapsedFn})`);
check("a lane is named by the role it plays",
  [_lfAgentTitle({role: "plan", key: "plan"}),
   _lfAgentTitle({role: "repo", key: "repo"}),
   _lfAgentTitle({role: "blueteam", key: "V3"})],
  ["Plan agent", "Repo agent", "BT · V3"]);
check("a lane that never started shows no clock", _lfElapsed({}), "");
check("a finished lane shows how long it took",
  _lfElapsed({started_at: 1000, finished_at: 1094}), "1분 34초");
check("...and seconds alone under a minute",
  _lfElapsed({started_at: 1000, finished_at: 1032}), "32초");

check("the grid orders plan first, blueteams next, repo last",
  /weight = \(r\) => \(r\.role === "plan" \? 0 : r\.role === "repo" \? 2 : 1\)/.test(agentsFn));
// The board can gate its repaint on the payload alone because nothing in a
// row changes without the file changing. A running lane's elapsed time does.
check("a running lane repaints even when the payload has not changed",
  agentsFn.includes('r.state === "running"') && agentsFn.includes("!live &&"));
// …WITHOUT rewriting the card. The elapsed time changes every tick, so
// folding it into the markup rebuilt every running card's subtree a couple
// of times a second — which the operator saw as flicker.
// Writing an attribute is a mutation even when the value is unchanged.
check("a card's data attributes are written only when they change",
  agentsFn.includes("el.dataset.role !== role")
    && agentsFn.includes("el.dataset.state !== state"));
check("the clock is not part of the card's signature",
  /const inner = `[\s\S]*?live-fire-agent-clock"><\/div>`/.test(agentsFn)
    && !/live-fire-agent-clock">\$\{/.test(agentsFn));
check("...and is set as a text node instead",
  agentsFn.includes("clockEl.textContent !== ticked")
    && agentsFn.includes("clockEl.textContent = ticked"));

check("the grid is a grid, sized by how many agents there are",
  /\.live-fire-agents-grid \{[^}]*grid-template-columns:\s*repeat\(auto-fit/.test(cssNow));
check("...and a working lane is the one that stands out",
  /\.live-fire-agent\[data-state="running"\]/.test(cssNow));
check("...with detail clamped, so one long line cannot break the rows",
  /\.live-fire-agent-detail \{[^}]*-webkit-line-clamp/.test(cssNow));
check("the grid narrows rather than overflowing on a phone",
  /max-width:\s*520px[\s\S]{0,120}\.live-fire-agents-grid/.test(cssNow));
check("the job panel actually mounts the grid",
  src.includes("mountLiveFireAgents(id);")
    && rendererSource.includes('class="live-fire-agents"'));

// Shared-panel regression: adding live-fire must not remove or rename the
// existing module forms/listeners.
for (const moduleName of ["web", "pwn", "forensic", "misc", "crypto", "rev", "web3"]) {
  check(`existing ${moduleName} form remains`, html.includes(`id="${moduleName}-form"`));
  check(`existing ${moduleName} submit listener remains`, src.includes(`getElementById("${moduleName}-form")`));
}

console.log(`\n== summary: ${passed} passed, ${failed} failed; mutation=${mutation} ==`);
process.exit(failed ? 1 : 0);
