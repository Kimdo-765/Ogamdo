"""The venue VPN: reaching CTF servers that only exist on the contest LAN.

THE PROBLEM THIS SOLVES

A CTF's problem servers are reachable only from the venue network. Ogamdo runs
at home. The laptop that goes to the venue is on both networks at once, so it
is the only thing that can carry traffic between them.

WHY THE TUNNEL TERMINATES HERE AND NOT IN WINDOWS

This box runs WSL2 with ``networkingMode=bridged``. That makes the WSL VM a
first-class host on the LAN with its own address and its own default route via
the LAN gateway -- it does not traverse Windows' routing table at all.
Measured on this deployment: Windows is 192.168.68.50, the WSL VM is
192.168.68.53, and a worker's default route is 172.18.0.1 -> the WSL VM -> the
LAN gateway. Windows never appears. So a WireGuard profile toggled in the
Windows client carries Windows' traffic and none of Ogamdo's, and the obvious
"just flip the Windows tunnel" shortcut cannot work.

Terminating in the WSL VM's netns instead means the route lands where every
worker, runner and challenge container already egresses, and all of them
inherit it with no per-container change and no NET_ADMIN outside the one
sidecar.

DIRECTION

This box is the SERVER: it has the stable address, reached through a port
forward on the home router to the WSL VM's LAN address (bridged mode makes
that a normal port-forward target). The laptop dials in, which is what makes
this work from a venue network nobody controls.

SCOPE

``vpn_scope`` decides what actually crosses:

  venue  routes only the subnets the laptop advertises. Everything else on this
         box -- model APIs, package mirrors -- keeps the home line. The default,
         and the one that survives a venue that firewalls outbound API calls.
  all    every CONTAINER's egress goes through the venue, via a policy rule per
         docker bridge subnet. The WSL host itself keeps the LAN default route,
         so the WireGuard handshake and Ogamdo's own control plane are not
         routed into the tunnel they depend on.

Note what ``all`` does NOT mean: a literal ``0.0.0.0/0`` in ``vpn_venue_subnets``
is refused (see ``validate_settings``). Written into the main table it would
strand this box and the tunnel with it, because the handshake's own reply path
would loop through the interface it is trying to establish.
"""
from __future__ import annotations

import base64
import ipaddress
import os
from pathlib import Path
from typing import Any

CONTAINER_NAME = "hextech_ctf_tool-vpn"
IMAGE = "hextech_ctf_tool-vpn"
IFACE = "wg0"

# Inside the api container. The host side of the same directory is resolved
# separately for the bind mount -- see `_host_conf_dir`.
CONF_DIR = Path(os.environ.get("VPN_CONF_DIR", "/data/wireguard"))
SERVER_KEY = CONF_DIR / "server.key"
PEER_KEY = CONF_DIR / "peer.key"
CONF_PATH = CONF_DIR / f"{IFACE}.conf"

VALID_SCOPES = ("venue", "all")


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------
def _raw_private(key) -> bytes:
    """32 raw bytes out of an X25519 private key, on old and new cryptography.

    `private_bytes_raw()` is the modern spelling and is NOT present on every
    version this repo runs against: the api image carries 50.x and has it,
    while the WSL host's system python carries an older one and does not. A
    module that only worked in the container would still import fine on the
    host and fail at the first key -- including in this feature's own test
    suite, which is where it was found.
    """
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat,
    )

    try:
        return key.private_bytes_raw()
    except AttributeError:
        return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _raw_public(key) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    try:
        return key.public_bytes_raw()
    except AttributeError:
        return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _genkey() -> str:
    """A fresh WireGuard private key, base64.

    WireGuard keys are raw X25519, so `cryptography` produces them directly --
    no shelling out to `wg genkey`, which would make key generation depend on
    an image that may not be built yet the first time an operator opens the
    settings page.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    return base64.b64encode(_raw_private(X25519PrivateKey.generate())).decode()


def pubkey_of(private_b64: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    raw = base64.b64decode(private_b64)
    return base64.b64encode(
        _raw_public(X25519PrivateKey.from_private_bytes(raw).public_key())
    ).decode()


def _read_or_create_key(path: Path) -> str:
    """Load a persisted private key, creating it on first use.

    0600 and a 0700 parent: this directory is bind-mounted into a container
    that runs with NET_ADMIN, and `data/` is gitignored, so the key never
    reaches a commit. Regenerating instead of reusing would silently invalidate
    the peer config the operator already copied to the laptop -- at the venue,
    where fixing it is expensive.
    """
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONF_DIR.chmod(0o700)
    except OSError:
        pass
    if path.exists():
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    key = _genkey()
    path.write_text(key + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def server_keys() -> tuple[str, str]:
    priv = _read_or_create_key(SERVER_KEY)
    return priv, pubkey_of(priv)


def peer_keys() -> tuple[str, str]:
    """The LAPTOP's keypair, generated here.

    Impure -- a peer's private key ideally never leaves the peer -- and worth
    it: the alternative is talking an operator through `wg genkey` on a laptop
    at a contest venue, and the two ends are the same person's machines on the
    same trust boundary. The key is stored 0600 beside the server's so the
    config can be shown again without invalidating a laptop already configured.
    """
    priv = _read_or_create_key(PEER_KEY)
    return priv, pubkey_of(priv)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def effective_peer_public_key(s: dict[str, Any]) -> str:
    """The peer public key the server should trust.

    An explicit setting wins -- an operator who generated the keypair ON the
    laptop (the more careful choice, since the private half never travels)
    pastes its public half here and that is what must be honoured.

    Empty falls back to the public half of the keypair THIS box generated and
    already handed out in the laptop config. Without the fallback the operator
    has to read a 44-character key off one screen and type it into another, to
    tell Ogamdo something Ogamdo itself chose -- busywork with a transcription
    error in it, performed at a venue.
    """
    explicit = str(s.get("vpn_peer_public_key") or "").strip()
    return explicit or peer_keys()[1]


def peer_key_mismatch(s: dict[str, Any]) -> bool:
    """Does the configured peer key disagree with the config we hand out?

    Only possible when the key was set explicitly: the laptop config always
    carries the private half of the keypair stored here, so a DIFFERENT public
    key means the two ends can never handshake. Nothing in WireGuard reports
    this -- both sides simply stay silent, which is indistinguishable from a
    blocked port, and would send the operator to debug the router.
    """
    explicit = str(s.get("vpn_peer_public_key") or "").strip()
    return bool(explicit) and explicit != peer_keys()[1]


def validate_settings(s: dict[str, Any]) -> None:
    """Raise ValueError on anything that would strand this box or fail at up.

    Runs BEFORE persisting, because every failure here is one an operator would
    otherwise meet at a venue with the contest already running.
    """
    scope = str(s.get("vpn_scope") or "venue").strip()
    if scope not in VALID_SCOPES:
        raise ValueError(f"vpn_scope must be one of {VALID_SCOPES}, got {scope!r}")

    for key, zero_ok in (("vpn_listen_port", False), ("vpn_external_port", True)):
        port = s.get(key)
        if port is None or str(port).strip() == "":
            continue
        try:
            p = int(port)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number, got {port!r}")
        # 0 is how vpn_external_port says "same as the listen port"; for the
        # listen port itself it is simply not a port.
        if zero_ok and p == 0:
            continue
        if not (1 <= p <= 65535):
            raise ValueError(f"{key} out of range: {p}")

    for key in ("vpn_address", "vpn_peer_address"):
        val = str(s.get(key) or "").strip()
        if not val:
            continue
        try:
            ipaddress.ip_interface(val)
        except ValueError as e:
            raise ValueError(f"{key}: {e}")

    pub = str(s.get("vpn_peer_public_key") or "").strip()
    if pub:
        try:
            if len(base64.b64decode(pub, validate=True)) != 32:
                raise ValueError("not a 32-byte key")
        except Exception as e:
            raise ValueError(f"vpn_peer_public_key is not a WireGuard key: {e}")

    for net in _split_subnets(str(s.get("vpn_venue_subnets") or "")):
        try:
            parsed = ipaddress.ip_network(net, strict=False)
        except ValueError as e:
            raise ValueError(f"vpn_venue_subnets: {net!r}: {e}")
        # A default route here would go into the MAIN table and take this box's
        # own egress with it -- including the handshake replies that keep the
        # tunnel alive. `vpn_scope=all` exists precisely so this never has to
        # be expressed as a subnet.
        if parsed.prefixlen == 0:
            raise ValueError(
                f"vpn_venue_subnets: refusing {net} — a default route here would "
                "take this box's own traffic, and the WireGuard handshake with "
                "it. Set vpn_scope=all instead: it routes every CONTAINER "
                "through the venue and leaves the host's own path alone."
            )


def _split_subnets(raw: str) -> list[str]:
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


# --------------------------------------------------------------------------
# Config rendering
# --------------------------------------------------------------------------
def render_server_conf(s: dict[str, Any]) -> str:
    """This box's wg0.conf.

    `Table = off` is load-bearing: wg-quick would otherwise write its routes
    into the main table, which is the one table this box needs untouched. The
    sidecar's entrypoint installs the routes the chosen scope calls for
    instead, after the interface exists.
    """
    priv, _ = server_keys()
    addr = str(s.get("vpn_address") or "10.99.0.1/24").strip()
    port = int(s.get("vpn_listen_port") or 51820)
    peer_pub = effective_peer_public_key(s)
    peer_addr = str(s.get("vpn_peer_address") or "10.99.0.2/32").strip()
    scope = str(s.get("vpn_scope") or "venue").strip()

    if scope == "all":
        # The peer must be ALLOWED everything for the policy table to have
        # somewhere to send it. What is actually ROUTED is decided by the ip
        # rules the entrypoint installs, not by this line.
        allowed = [peer_addr, "0.0.0.0/0"]
    else:
        allowed = [peer_addr] + _split_subnets(str(s.get("vpn_venue_subnets") or ""))

    lines = [
        "[Interface]",
        f"Address = {addr}",
        f"ListenPort = {port}",
        f"PrivateKey = {priv}",
        "Table = off",
    ]
    if peer_pub:
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {peer_pub}",
            f"AllowedIPs = {', '.join(a for a in allowed if a)}",
            "PersistentKeepalive = 25",
        ]
    return "\n".join(lines) + "\n"


def render_peer_conf(s: dict[str, Any]) -> str:
    """The config to paste into the laptop's WireGuard client.

    The laptop still has to FORWARD and masquerade from wg0 into the venue LAN
    for the advertised subnets to actually answer; that half cannot be
    expressed in a .conf and is covered in docs/venue-vpn.md.
    """
    peer_priv, _ = peer_keys()
    _, server_pub = server_keys()
    endpoint = str(s.get("vpn_endpoint_host") or "").strip()
    # The EXTERNAL port, which is only the listen port when the router does not
    # translate. Getting this wrong fails in one direction and says nothing:
    # the desktop listens correctly and reports a healthy interface, while the
    # laptop dials a port the router never forwards.
    port = int(s.get("vpn_external_port") or 0) or int(s.get("vpn_listen_port") or 51820)
    peer_addr = str(s.get("vpn_peer_address") or "10.99.0.2/32").strip()
    server_addr = str(s.get("vpn_address") or "10.99.0.1/24").strip()

    # The laptop needs a route back to the tunnel itself, and (for scope=all)
    # to accept whatever the desktop sends. The desktop's own /32 is the
    # minimum; the whole tunnel subnet is friendlier and no less safe.
    try:
        tunnel_net = str(ipaddress.ip_interface(server_addr).network)
    except ValueError:
        tunnel_net = server_addr

    lines = [
        "[Interface]",
        f"PrivateKey = {peer_priv}",
        f"Address = {peer_addr}",
        "",
        "[Peer]",
        f"PublicKey = {server_pub}",
        f"AllowedIPs = {tunnel_net}",
        "PersistentKeepalive = 25",
    ]
    if endpoint:
        lines.insert(len(lines) - 1, f"Endpoint = {endpoint}:{port}")
    return "\n".join(lines) + "\n"


def write_conf(s: dict[str, Any]) -> Path:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    CONF_PATH.write_text(render_server_conf(s), encoding="utf-8")
    try:
        CONF_PATH.chmod(0o600)
    except OSError:
        pass
    return CONF_PATH


# --------------------------------------------------------------------------
# Container lifecycle
# --------------------------------------------------------------------------
def _host_conf_dir() -> str:
    """The HOST path that backs CONF_DIR, for the sidecar's bind mount.

    The daemon resolves bind sources on the host, not in this container, and a
    wrong path does not fail: docker CREATES the missing source and mounts it
    EMPTY. The sidecar would then find no config and exit 64 — a clear enough
    message, but one that blames the config instead of the path. So prefer
    `_runner._true_host_data_dir`, which asks the daemon what this container's
    /data actually resolves to, and fall back to the env var only if that
    import is unavailable.
    """
    root = None
    try:
        from modules._runner import _true_host_data_dir

        root = _true_host_data_dir()
    except Exception:
        root = None
    root = root or os.environ.get("HOST_DATA_DIR")
    if not root:
        raise RuntimeError(
            "HOST_DATA_DIR is not set and the daemon could not be asked; "
            "the VPN sidecar has no way to find its config on the host"
        )
    return f"{root.rstrip('/')}/wireguard"


def _client():
    import docker

    return docker.from_env()


def remove_existing() -> None:
    """Drop any previous sidecar, running or exited.

    Unconditional rather than conditional on `.status`: a container left in
    `created` or `dead` still holds the name, and `containers.run` would fail
    on the collision rather than on anything the operator could act on.
    """
    try:
        c = _client().containers.get(CONTAINER_NAME)
    except Exception:
        return
    try:
        c.remove(force=True)
    except Exception:
        pass


def start(s: dict[str, Any]) -> dict[str, Any]:
    """Write the config and bring the sidecar up. Returns `status()`."""
    validate_settings(s)
    write_conf(s)
    remove_existing()

    scope = str(s.get("vpn_scope") or "venue").strip()
    subnets = ",".join(_split_subnets(str(s.get("vpn_venue_subnets") or "")))
    if scope == "venue" and not subnets:
        raise ValueError(
            "vpn_scope=venue routes only the subnets listed in "
            "vpn_venue_subnets, and that list is empty — nothing would cross "
            "the tunnel. Add the venue's subnet, or use vpn_scope=all."
        )

    _client().containers.run(
        IMAGE,
        detach=True,
        name=CONTAINER_NAME,
        network_mode="host",
        cap_add=["NET_ADMIN", "SYS_MODULE"],
        devices=["/dev/net/tun:/dev/net/tun:rwm"],
        volumes={_host_conf_dir(): {"bind": "/etc/wireguard", "mode": "ro"}},
        environment={
            "WG_INTERFACE": IFACE,
            "WG_SCOPE": scope,
            "WG_VENUE_SUBNETS": subnets,
        },
        # Deliberately NOT restart:always. The tunnel is a venue-day tool, and
        # a sidecar that resurrected itself after the operator switched it off
        # -- or after a host reboot at home -- would route job traffic at a
        # laptop that is no longer at the venue.
        restart_policy={"Name": "no"},
    )
    # Sampling status immediately returns a container that is `running` with no
    # interface and no peers yet -- wg-quick has not finished. The caller puts
    # this straight in front of the operator as `vpn_applied`, where an empty
    # peer list reads as "it did nothing". Give the bring-up a moment to become
    # true before answering.
    import time

    for _ in range(20):
        st = status()
        if st.get("interface_up") or st.get("container") not in ("running", "created"):
            return st
        time.sleep(0.25)
    return status()


def stop() -> dict[str, Any]:
    """Stop the sidecar, giving its trap time to tear the interface down.

    The timeout matters: the interface lives in the HOST netns, so a SIGKILL
    before the trap runs would leave wg0 and its rules behind, routing traffic
    that the UI reports as not routed.
    """
    try:
        c = _client().containers.get(CONTAINER_NAME)
    except Exception:
        return status()
    try:
        c.stop(timeout=15)
    except Exception:
        pass
    try:
        c.remove(force=True)
    except Exception:
        pass
    return status()


def status() -> dict[str, Any]:
    """What is TRUE right now — container, interface, peer, routes.

    Reported separately rather than folded into one boolean because they come
    apart, and the way they come apart is what an operator needs to see: a
    sidecar that exited on a bad config reports `container` exited WITH the
    last lines of its log, while `interface_up` and `peers` stay false/empty.

    One state this deliberately does NOT claim to detect: a sidecar SIGKILLed
    before its trap ran, which leaves wg0 routing in the host netns with no
    container to report it. The api container has its own netns, so it cannot
    see the host's interfaces to check — `/sys/class/net` here lists this
    container's, not the host's. `stop()` gives the trap 15s precisely so this
    state stays theoretical; if it is ever reached, `docker run --rm --net=host
    --cap-add=NET_ADMIN hextech_ctf_tool-vpn ip link del wg0` clears it.
    """
    out: dict[str, Any] = {
        "container": "absent",
        "interface_up": False,
        "peers": [],
        "routes": [],
        "error": "",
    }
    try:
        c = _client().containers.get(CONTAINER_NAME)
        out["container"] = c.status
        if c.status != "running":
            try:
                out["error"] = c.logs(tail=20).decode("utf-8", "replace").strip()
            except Exception:
                pass
    except Exception:
        out["container"] = "absent"

    # The api container is NOT in the host netns, so it cannot read wg0 itself.
    # Ask the sidecar, which is.
    if out["container"] == "running":
        try:
            code, raw = _client().containers.get(CONTAINER_NAME).exec_run(
                ["sh", "-c", f"wg show {IFACE} dump; echo ---; ip -o route show dev {IFACE}"]
            )
            text = raw.decode("utf-8", "replace")
            dump, _, routes = text.partition("---")
            # `wg show dump` line 1 is the interface; peers follow, tab-separated:
            # pubkey, psk, endpoint, allowed-ips, last-handshake, rx, tx, keepalive
            for line in dump.strip().splitlines()[1:]:
                f = line.split("\t")
                if len(f) >= 8:
                    out["peers"].append({
                        "public_key": f[0],
                        "endpoint": f[2],
                        "allowed_ips": f[3],
                        "last_handshake": int(f[4] or 0),
                        "rx_bytes": int(f[5] or 0),
                        "tx_bytes": int(f[6] or 0),
                    })
            out["interface_up"] = code == 0 and bool(dump.strip())
            out["routes"] = [r.strip() for r in routes.strip().splitlines() if r.strip()]
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
    return out
