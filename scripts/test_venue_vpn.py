#!/usr/bin/env python3
"""The venue VPN routes the venue, and nothing it needs to stay alive.

WHY THIS EXISTS — TWO BUGS THAT BOTH LOOKED LIKE THE VENUE'S FAULT (2026-09-16)

Both were caught by running the tunnel against this box rather than by reading
the script, and both would have surfaced at a contest as "the venue is
blocking us":

  1. `bridge_subnets()` matched on `$3=="dev"`. The line reads
     `172.18.0.0/16 dev br-xxx proto kernel ...`, so `dev` is $2 and the
     interface is $3. It selected NOTHING, so scope=all installed the policy
     table's default route and not one ip rule to reach it: a tunnel that was
     up, reported up, and carried no container traffic at all.

  2. The policy table then held ONLY `default dev wg0`. ip rules are consulted
     BEFORE the main table, so every packet from a docker bridge — including
     container->redis, container->api and the api's own replies — was posted
     into a tunnel with no peer. The dashboard stopped answering (curl HTTP
     000) the moment scope=all came up. Every job would have died on redis.

  2b. The fix copies the main table's routes in, and `ip route show` prints
     status flags (`linkdown`, `dead`) that `ip route add` cannot parse. Two of
     three bridges silently failed to copy, which is harmless only until a
     container lands on one of them.

Run from the repository root::

    python3 scripts/test_venue_vpn.py
    python3 scripts/test_venue_vpn.py --mutate awk-field-off-by-one
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Point the module at a throwaway key directory BEFORE importing it: CONF_DIR
# is read at import time, and the default is the deployment's real
# /data/wireguard. A suite that wrote there would be touching the keypair the
# operator's laptop is already configured against -- and on this host it cannot
# write there at all, so the whole suite died on the first key instead of
# reporting anything.
os.environ["VPN_CONF_DIR"] = tempfile.mkdtemp(prefix="ogamdo-vpn-test-")

MUTATIONS = (
    "peer-key-not-defaulted",
    "mismatch-undetected",
    "external-port-ignored",
    "awk-field-off-by-one",
    "policy-table-default-only",
    "keep-status-flags",
    "allow-default-subnet",
    "drop-table-off",
    "scope-ignored",
    "peer-key-regenerated",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

ENTRY = (ROOT / "vpn" / "entrypoint.sh").read_text(encoding="utf-8")

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


# ---------------------------------------------------------------------------
# 1. The shell that decides WHICH sources get policy-routed, run for real
#    against a captured `ip route show scope link`. The awk indices are the
#    whole bug; a test that re-derived them from the same wrong reading would
#    have passed alongside it.
# ---------------------------------------------------------------------------
SAMPLE_LINK = """172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
172.18.0.0/16 dev br-44ff5d2cddf8 proto kernel scope link src 172.18.0.1
172.19.0.0/16 dev br-1d999bf6ab1e proto kernel scope link src 172.19.0.1 linkdown
192.168.68.0/22 dev eth0 proto dhcp src 192.168.68.53 metric 1002
"""

_awk = re.search(r"\| awk '([^']+)'", ENTRY)
AWK_PROG = _awk.group(1) if _awk else ""
if args.mutate == "awk-field-off-by-one":
    AWK_PROG = AWK_PROG.replace('$2=="dev"', '$3=="dev"').replace("$3 ~", "$4 ~").replace('$3=="docker0"', '$4=="docker0"')


def run_awk(prog: str, text: str) -> list[str]:
    out = subprocess.run(["awk", prog], input=text, capture_output=True, text=True)
    return [l for l in out.stdout.split() if l]


found = run_awk(AWK_PROG, SAMPLE_LINK)
check("every docker bridge is selected, linkdown included",
      sorted(found), ["172.17.0.0/16", "172.18.0.0/16", "172.19.0.0/16"])
check("...and the LAN interface is NOT — routing the host's own subnet into "
      "the tunnel would strand this box",
      "192.168.68.0/22" in found, False)

# ---------------------------------------------------------------------------
# 2. The policy table has to carry the LOCAL routes, not just the default.
#    Asserted on the shipped script's text because the failure is structural:
#    a table with one route in it captures everything the rule matches.
# ---------------------------------------------------------------------------
body = ENTRY
# The copy is four physical lines (a pipeline with a line continuation, then
# the while/do/done). Anchored on its first and last line so the mutation
# removes the WHOLE block rather than half of it -- a half-removal would leave
# unbalanced shell and kill the suite instead of failing a check, which reads
# as "caught" on the exit code alone and is not.
_COPY_START = "  ip route show table main | grep -vE '^default'"
_COPY_END = "  done\n"
if args.mutate == "policy-table-default-only":
    i = body.index(_COPY_START)
    j = body.index(_COPY_END, i) + len(_COPY_END)
    body = body[:i] + body[j:]
if args.mutate == "keep-status-flags":
    body = body.replace(" | sed -E 's/ (linkdown|dead)//g'", "", 1)

_all_block = body.split('if [ "$SCOPE" = "all" ]', 1)[-1].split("else", 1)[0]
check("scope=all copies the main table's routes into the policy table",
      "ip route show table main" in _all_block, True)
check("...excluding its default, which is the one thing being overridden",
      "grep -vE '^default'" in _all_block, True)
check("...and strips the status flags `ip route add` cannot parse",
      bool(re.search(r"linkdown\|dead", _all_block)), True)
check("...before installing the tunnel default",
      ("ip route show table main" in _all_block
       and _all_block.index("ip route show table main")
       < _all_block.index('ip route add default dev "$IFACE"')), True)

# The teardown has to undo every one of those, or `stop` is a half-truth and
# the next start fails on "File exists".
check("teardown removes the ip rules", 'ip rule del table "$TABLE"' in ENTRY, True)
check("teardown flushes the policy table", 'ip route flush table "$TABLE"' in ENTRY, True)
check("teardown removes the masquerade", "-D POSTROUTING" in ENTRY, True)
check("teardown runs on SIGTERM, not only on a clean exit",
      "trap down TERM INT" in ENTRY, True)
check("the wait is interruptible, so the trap beats docker's SIGKILL",
      "sleep infinity &" in ENTRY and "wait $!" in ENTRY, True)

# ---------------------------------------------------------------------------
# 3. Settings validation — every one of these is a mistake an operator would
#    otherwise meet at a venue, with the contest running.
# ---------------------------------------------------------------------------
from modules import vpn  # noqa: E402

if args.mutate == "allow-default-subnet":
    _real = vpn.validate_settings
    vpn.validate_settings = lambda s: None
if args.mutate == "drop-table-off":
    _rsc = vpn.render_server_conf
    vpn.render_server_conf = lambda s: _rsc(s).replace("Table = off\n", "")
if args.mutate == "peer-key-not-defaulted":
    vpn.effective_peer_public_key = lambda s: str(s.get("vpn_peer_public_key") or "").strip()
if args.mutate == "mismatch-undetected":
    vpn.peer_key_mismatch = lambda s: False
if args.mutate == "external-port-ignored":
    _rpc = vpn.render_peer_conf
    vpn.render_peer_conf = lambda s: _rpc({**s, "vpn_external_port": 0})
if args.mutate == "scope-ignored":
    _rsc2 = vpn.render_server_conf
    vpn.render_server_conf = lambda s: _rsc2({**s, "vpn_scope": "venue"})
if args.mutate == "peer-key-regenerated":
    def _fresh_every_time():
        k = vpn._genkey()
        return k, vpn.pubkey_of(k)

    vpn.peer_keys = _fresh_every_time


def refused(patch: dict) -> bool:
    base = {"vpn_scope": "venue", "vpn_listen_port": 51820,
            "vpn_address": "10.99.0.1/24", "vpn_peer_address": "10.99.0.2/32"}
    try:
        vpn.validate_settings({**base, **patch})
        return False
    except ValueError:
        return True


check("a /0 venue subnet is refused", refused({"vpn_venue_subnets": "0.0.0.0/0"}), True)
check("...and ::/0 with it", refused({"vpn_venue_subnets": "::/0"}), True)
check("a malformed CIDR is refused", refused({"vpn_venue_subnets": "10.20.0.0/99"}), True)
check("a non-key is refused", refused({"vpn_peer_public_key": "not-a-key"}), True)
check("a short key is refused",
      refused({"vpn_peer_public_key": "c2hvcnQ="}), True)
check("an unknown scope is refused", refused({"vpn_scope": "everything"}), True)
check("a port out of range is refused", refused({"vpn_listen_port": 99999}), True)
check("a real venue subnet is ACCEPTED — the guard must not block the feature",
      refused({"vpn_venue_subnets": "10.20.0.0/16, 192.168.4.0/24"}), False)

# ---------------------------------------------------------------------------
# 4. Rendering.
# ---------------------------------------------------------------------------
S = {
    "vpn_scope": "venue", "vpn_listen_port": 51820,
    "vpn_address": "10.99.0.1/24", "vpn_peer_address": "10.99.0.2/32",
    "vpn_peer_public_key": vpn.pubkey_of(vpn._genkey()),
    "vpn_venue_subnets": "10.20.0.0/16",
    "vpn_endpoint_host": "203.0.113.10",
}
conf = vpn.render_server_conf(S)
# Without this, wg-quick writes its routes into the MAIN table and the
# entrypoint's careful policy routing is bypassed by a default it never saw.
check("the server config disables wg-quick's own route installation",
      "Table = off" in conf, True)
check("scope=venue allows exactly the peer and the advertised subnets",
      "AllowedIPs = 10.99.0.2/32, 10.20.0.0/16" in conf, True)
check("scope=all allows everything, so the policy table has somewhere to send it",
      "0.0.0.0/0" in vpn.render_server_conf({**S, "vpn_scope": "all"}), True)
check("the two scopes do not render the same config",
      vpn.render_server_conf({**S, "vpn_scope": "all"}) != conf, True)

peer = vpn.render_peer_conf(S)
check("the laptop config carries an Endpoint to dial",
      "Endpoint = 203.0.113.10:51820" in peer, True)

# A router that separates internal from external port makes these two
# different numbers. The laptop must dial the EXTERNAL one; this box must
# listen on the INTERNAL one. Confusing them fails in one direction only --
# the desktop looks healthy and the handshake simply never arrives.
_NAT = {**S, "vpn_listen_port": 51820, "vpn_external_port": 40000}
check("the laptop dials the EXTERNAL port when the router translates",
      "Endpoint = 203.0.113.10:40000" in vpn.render_peer_conf(_NAT), True)
check("...while this box still listens on the INTERNAL one",
      "ListenPort = 51820" in vpn.render_server_conf(_NAT), True)
check("external port 0 means 'same as listen port', not port zero",
      "Endpoint = 203.0.113.10:51820"
      in vpn.render_peer_conf({**S, "vpn_external_port": 0}), True)
check("an external port of 0 is accepted — it is how 'same' is spelled",
      refused({"vpn_external_port": 0}), False)
check("...but a listen port of 0 is not a port",
      refused({"vpn_listen_port": 0}), True)
check("an out-of-range external port is refused",
      refused({"vpn_external_port": 99999}), True)
check("...and this box's public key, not its private one",
      vpn.server_keys()[1] in peer and vpn.server_keys()[0] not in peer, True)
# Showing the config twice must not invalidate a laptop already carrying it —
# which would be discovered at the venue.
check("the peer keypair is STABLE across calls",
      vpn.render_peer_conf(S) == peer, True)

# ---------------------------------------------------------------------------
# 5. The peer key. Ogamdo generates the laptop's keypair and hands out the
#    private half, so making the operator read the public half off one screen
#    and type it into another is busywork with a transcription error in it --
#    performed at a venue. And a MISMATCH is the worst failure shape here:
#    WireGuard reports nothing at all, so it looks exactly like a blocked port.
# ---------------------------------------------------------------------------
_gen_pub = vpn.peer_keys()[1]
check("an empty peer key defaults to the generated keypair's public half",
      vpn.effective_peer_public_key({**S, "vpn_peer_public_key": ""}), _gen_pub)
check("...so the server config still gets a peer",
      f"PublicKey = {_gen_pub}"
      in vpn.render_server_conf({**S, "vpn_peer_public_key": ""}), True)
_other = vpn.pubkey_of(vpn._genkey())
check("an explicit key WINS — a key generated on the laptop must be honoured",
      vpn.effective_peer_public_key({**S, "vpn_peer_public_key": _other}), _other)
check("a key that disagrees with the handed-out config is detected",
      vpn.peer_key_mismatch({**S, "vpn_peer_public_key": _other}), True)
check("...and the matching one is not flagged",
      vpn.peer_key_mismatch({**S, "vpn_peer_public_key": _gen_pub}), False)
check("...nor is an empty one, which cannot disagree with anything",
      vpn.peer_key_mismatch({**S, "vpn_peer_public_key": ""}), False)

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
