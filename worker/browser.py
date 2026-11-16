#!/usr/bin/env python3
"""A real browser, driven over CDP, kept where every job can reach it.

WHY THIS IS HERE

Job ba2725c84be2 wrote three browser drivers from scratch — `cdp_fetch.py`,
`lens2.py`, `render_vsrid.py` — before it could look at a rendered page. Every
job that needs JS pays that again: the worker image has `chromium` and `Xvfb`
and no automation library at all, so the agent hand-rolls CDP each time. The
turns go into re-deriving a transport, not into the challenge.

WHAT IT IS FOR

Rendering. A single-page app, a client-side crypto routine, an XSS payload
that only fires after script execution, a page whose DOM is nothing like its
HTTP response — `curl` cannot see any of those and this can.

ON `--stealth`, AND WHY THE FLAG WAS NOT ENOUGH

A CTF target may gate on automation; when the operator is authorised against
that host, defeating its gate is the challenge. Off by default, behind an
explicit flag -- and that did not hold. Job 117c98fac9b8 turned it on against
google.com, which is no challenge's target, and said so in its own
blocked.json. A guardrail written only in prose is a suggestion.

So the flag is checked against the job now. It applies to the job's declared
target host (`meta.target_url`) and to loopback/private addresses, which are
this platform's own sandbox. Anywhere else it is refused, out loud, and the
page still renders without it -- rendering was never the part in question.

There is a second reason, measured rather than argued: against Google it made
things WORSE. Plain `curl` from the same egress IP gets 200 on a search query
at the moment CDP-driven chromium gets /sorry. What is blocked is the
automated browser, not the network. Stealth walks INTO that gate; dropping to
curl walks around it.

USAGE

  python3 -m worker.browser render <url> --out page.html [--wait 12] [--shot s.png]
  python3 -m worker.browser eval   <url> --js "document.title"
  python3 -m worker.browser click  <url> --selector "button.go" --out after.html
  python3 -m worker.browser upload <url> --selector "input[type=file]" --file a.png

Every subcommand prints `FINAL_URL:` — a redirect to a login or an error page
is the single most useful thing to know and the easiest to miss in a DOM dump.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

UA_DEFAULT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


def _authorised_for_stealth(url: str) -> tuple[bool, str]:
    """May stealth apply to this URL? Returns (verdict, reason).

    Authorised means the job's own declared target, or an address that is by
    definition this platform's sandbox. Everything else -- a search engine, an
    image host, anything the agent is merely USING as a tool -- is not a
    target and does not get its bot detection defeated by this tool.
    """
    import ipaddress
    import json as _json
    import socket
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False, "no host in the URL"

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            ip = None
    if ip is not None and (ip.is_loopback or ip.is_private):
        return True, f"{host} is a private address (this platform's own sandbox)"

    job = os.environ.get("JOB_ID", "").strip()
    if not job:
        return False, "no JOB_ID in the environment, so there is no target to check"
    root = os.environ.get("DATA_DIR", "/data")
    try:
        with open(os.path.join(root, "jobs", os.path.basename(job), "meta.json"),
                  encoding="utf-8") as fh:
            meta = _json.load(fh)
    except Exception as exc:
        return False, f"could not read the job's meta.json ({exc.__class__.__name__})"

    targets = [meta.get("target_url")] + list(meta.get("target_urls") or [])
    hosts = {(urlparse(str(t)).hostname or "").lower() for t in targets if t}
    hosts.discard("")
    if not hosts:
        return False, "this job declares no target, so nothing is authorised"
    if host in hosts:
        return True, f"{host} is this job's declared target"
    return False, f"{host} is not this job's target ({', '.join(sorted(hosts))})"


class Browser:
    """Headful chromium under Xvfb plus one CDP websocket.

    Headful rather than `--headless`: a headless build renders some pages
    differently, and the point of this tool is to see what a browser sees.
    """

    def __init__(self, *, profile: str, port: int, proxy: str = "",
                 stealth: bool = False, ua: str = UA_DEFAULT,
                 viewport: str = "1440,2400"):
        self.port = port
        self.stealth = stealth
        os.makedirs(profile, exist_ok=True)
        flags = [
            "xvfb-run", "-a", f"--server-args=-screen 0 {viewport.replace(',', 'x')}x24",
            "chromium", "--no-sandbox", "--disable-dev-shm-usage",
            "--no-first-run", "--no-default-browser-check",
            "--disable-features=Translate,OptimizationHints",
            f"--user-data-dir={profile}", f"--window-size={viewport}",
            "--lang=en-US", f"--user-agent={ua}",
            f"--remote-debugging-port={port}", "--remote-allow-origins=*",
        ]
        if stealth:
            flags.insert(-2, "--disable-blink-features=AutomationControlled")
        if proxy:
            flags.append(f"--proxy-server={proxy}")
        flags.append("about:blank")
        self.proc = subprocess.Popen(
            flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid)
        self.ws = None
        self._id = 0

    # -- lifecycle --------------------------------------------------------
    def __enter__(self):
        url = self._wait_for_page_target()
        from websockets.sync.client import connect

        # max_size=None: a DOM dump is routinely larger than the library's
        # default 1 MiB frame cap, and truncating it would hand back a page
        # that silently is not the page.
        self.ws = connect(url, max_size=None, open_timeout=30)
        self.send("Page.enable")
        self.send("Runtime.enable")
        self.send("DOM.enable")
        if self.stealth:
            self.send("Page.addScriptToEvaluateOnNewDocument", {
                "source": "Object.defineProperty(navigator,'webdriver',"
                          "{get:()=>undefined});"})
        return self

    def __exit__(self, *exc):
        try:
            if self.ws:
                self.ws.close()
        except Exception:
            pass
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except Exception:
            pass
        return False

    def _wait_for_page_target(self, timeout: float = 45.0) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{self.port}/json", timeout=5) as r:
                    for t in json.load(r):
                        if t.get("type") == "page":
                            return t["webSocketDebuggerUrl"]
            except Exception:
                pass
            time.sleep(0.5)
        raise SystemExit("SETUP_FAILED: chromium CDP endpoint never came up")

    # -- protocol ---------------------------------------------------------
    def send(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        self.ws.send(json.dumps(
            {"id": self._id, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self._id:
                if "error" in msg:
                    raise SystemExit(f"CDP_ERROR {method}: {msg['error']}")
                return msg.get("result", {})

    def js(self, expression: str):
        r = self.send("Runtime.evaluate",
                      {"expression": expression, "returnByValue": True,
                       "awaitPromise": True})
        got = r.get("result", {})
        if got.get("subtype") == "error":
            return f"JS_ERROR: {got.get('description', '')[:400]}"
        return got.get("value")

    # -- actions ----------------------------------------------------------
    def goto(self, url: str, wait: float):
        self.send("Page.navigate", {"url": url})
        time.sleep(wait)

    def html(self) -> str:
        return self.js("document.documentElement.outerHTML") or ""

    def final_url(self) -> str:
        return self.js("location.href") or ""

    def shot(self, path: str):
        r = self.send("Page.captureScreenshot", {"format": "png"})
        with open(path, "wb") as fh:
            fh.write(base64.b64decode(r["data"]))

    def click(self, selector: str) -> bool:
        """A real mouse press at the element's centre, not `.click()`.

        A dispatched DOM click and a trusted input event are different things
        to any page that cares about the difference, and a page that gates on
        automation is exactly such a page.
        """
        box = self.js(
            "(()=>{const e=document.querySelector(%s);"
            "if(!e)return null;const r=e.getBoundingClientRect();"
            "return {x:r.x+r.width/2,y:r.y+r.height/2};})()"
            % json.dumps(selector))
        if not isinstance(box, dict):
            return False
        for kind in ("mouseMoved", "mousePressed", "mouseReleased"):
            p = {"type": kind, "x": box["x"], "y": box["y"],
                 "button": "left", "clickCount": 1}
            if kind == "mouseMoved":
                p.pop("button")
                p.pop("clickCount")
            self.send("Input.dispatchMouseEvent", p)
            time.sleep(0.05)
        return True

    def upload(self, selector: str, path: str) -> bool:
        doc = self.send("DOM.getDocument", {"depth": -1})
        found = self.send("DOM.querySelector",
                          {"nodeId": doc["root"]["nodeId"], "selector": selector})
        node = found.get("nodeId")
        if not node:
            return False
        self.send("DOM.setFileInputFiles",
                  {"nodeId": node, "files": [os.path.abspath(path)]})
        return True


def main() -> int:
    ap = argparse.ArgumentParser(prog="worker.browser")
    ap.add_argument("action", choices=("render", "eval", "click", "upload"))
    ap.add_argument("url")
    ap.add_argument("--out"), ap.add_argument("--shot"), ap.add_argument("--js")
    ap.add_argument("--selector"), ap.add_argument("--file")
    ap.add_argument("--wait", type=float, default=12.0)
    ap.add_argument("--after", type=float, default=4.0,
                    help="seconds to settle after a click or an upload")
    ap.add_argument("--port", type=int, default=9333)
    ap.add_argument("--proxy", default=os.environ.get("XPROXY", ""))
    ap.add_argument("--profile",
                    default=os.path.join(os.environ.get("TMPDIR", "."), "cdp-profile"))
    ap.add_argument("--ua", default=UA_DEFAULT)
    ap.add_argument("--viewport", default="1440,2400")
    ap.add_argument("--stealth", action="store_true",
                    help="hide automation markers -- only against a target you "
                         "are authorised to test that gates on them")
    a = ap.parse_args()

    stealth = a.stealth
    if stealth:
        allowed, why = _authorised_for_stealth(a.url)
        print(("STEALTH_ON: " if allowed else "STEALTH_REFUSED: ") + why)
        # Refused, not fatal: the page still renders, which is what this tool
        # is for. Downgrading silently would be the dishonest option.
        stealth = allowed

    with Browser(profile=a.profile, port=a.port, proxy=a.proxy,
                 stealth=stealth, ua=a.ua, viewport=a.viewport) as b:
        b.goto(a.url, a.wait)
        if a.action == "click":
            print("CLICKED:", b.click(a.selector or ""))
            time.sleep(a.after)
        elif a.action == "upload":
            print("UPLOADED:", b.upload(a.selector or "", a.file or ""))
            time.sleep(a.after)
        elif a.action == "eval":
            print("RESULT:", json.dumps(b.js(a.js or "1"), ensure_ascii=False)[:8000])
        if a.out:
            html = b.html()
            with open(a.out, "w", encoding="utf-8") as fh:
                fh.write(html)
            print("SIZE:", len(html))
        if a.shot:
            b.shot(a.shot)
            print("SHOT:", a.shot)
        print("FINAL_URL:", b.final_url())
    return 0


if __name__ == "__main__":
    sys.exit(main())
