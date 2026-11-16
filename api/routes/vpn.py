"""Venue VPN status and the config the laptop pastes in.

The TOGGLE deliberately does not live here. It rides on PUT /api/settings,
beside `worker_slot_mem` pushing itself to the live cgroup, because the same
rule applies: a setting that persists without taking effect looks like it
worked and changes nothing. One save, one truth.

What is left here is what has no settings row: the live state of the tunnel,
and the peer config — which is DERIVED from settings plus the keypair on disk,
so it has no business being stored as a setting of its own.
"""
from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool

from modules.settings_io import get_settings_view

router = APIRouter()


@router.get("/status")
async def vpn_status():
    """Container, interface, peers and routes — reported separately.

    Docker calls block, so this goes to the threadpool: the dashboard polls
    this and the event loop serves every other job's stream.
    """
    from modules import vpn

    return await run_in_threadpool(vpn.status)


@router.get("/peer-config")
async def vpn_peer_config():
    """The .conf for the laptop, rendered from settings + the stored keypair.

    Returned as text the operator copies. It is regenerated on every call from
    the SAME persisted keypair, so showing it twice does not invalidate a
    laptop that is already configured — which would otherwise be discovered at
    the venue, with the contest running.
    """
    from modules import vpn

    def _render():
        s = get_settings_view()
        return {
            "config": vpn.render_peer_conf(s),
            "server_public_key": vpn.server_keys()[1],
            "endpoint_set": bool(str(s.get("vpn_endpoint_host") or "").strip()),
            # The config below carries the private half of the keypair stored
            # here. If someone pinned a DIFFERENT public key in settings, the
            # two ends can never handshake — and WireGuard says nothing about
            # it, so the symptom is identical to a blocked port.
            "key_mismatch": vpn.peer_key_mismatch(s),
            "peer_public_key": vpn.peer_keys()[1],
        }

    try:
        return await run_in_threadpool(_render)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")
