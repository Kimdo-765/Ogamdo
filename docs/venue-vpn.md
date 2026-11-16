# Venue VPN — reaching CTF servers that only exist on the contest LAN

The contest's problem servers answer only on the venue network. Ogamdo runs at
home. The laptop you take to the venue is the only machine on both, so it is
the bridge.

```
  venue LAN                    internet                 home
  ┌──────────┐                                    ┌──────────────────┐
  │ CTF srv  │◀── forward+NAT ──┐            ┌───▶│ WSL VM .53       │
  │ 10.x.x.x │                  │            │    │  wg0 10.99.0.1   │
  └──────────┘             ┌────┴─────┐      │    │  docker bridges  │
                           │ laptop   │──────┘    │   └ workers/runner│
                           │ wg0 .0.2 │  dials in └──────────────────┘
                           └──────────┘                Windows .50 — not involved
```

## Why not just toggle the Windows WireGuard profile

This box runs WSL2 with `networkingMode=bridged`. That makes the WSL VM a
first-class host on the LAN with **its own address and its own default route**
via the LAN gateway — it never traverses Windows' routing table. Measured here:
Windows is `192.168.68.50`, the WSL VM is `192.168.68.53`, and a worker's
default route is `172.18.0.1` → the WSL VM → the LAN gateway. Windows does not
appear.

So a WireGuard profile toggled in the Windows client carries Windows' traffic
and none of Ogamdo's. The tunnel has to terminate in the WSL VM, which is what
the `vpn` sidecar does (`network_mode: host` = the WSL VM's netns). Every
worker, runner and challenge container then inherits the route through the
docker bridge with nothing to configure per container.

## Desktop side (Settings → Access → Venue VPN)

1. **Forward UDP on the home router to the WSL VM's LAN address**
   (`ip -4 addr show eth0` inside WSL), *not* to Windows'. Bridged mode makes
   the VM a normal port-forward target.

   If the router separates **external** from **internal** port, they are two
   different settings here:

   | router field | Settings field | goes into |
   |---|---|---|
   | internal / private port | *Listen port — internal* | this box's `ListenPort` |
   | external / public port | *External port* | the laptop's `Endpoint` |

   Leave *External port* at `0` when they are the same. Getting it wrong fails
   in one direction and reports nothing: the desktop listens correctly, the
   status chip goes green up to `waiting for laptop`, and only the laptop's
   `Endpoint` points at a port the router never forwards.
2. Fill in **This box's public address** (public IP or DDNS name).
3. Fill in **Venue subnets** — what the laptop can reach at the venue.
4. Press **Show laptop config**, copy it into the laptop's WireGuard client.
5. **Save** with the toggle on.

*Laptop public key* is optional and normally left **empty**: Ogamdo generated
the keypair and the config you just copied carries its private half, so there
is nothing to type back. Fill it in only if you generated the key *on the
laptop* instead — and then it must match, because a key that disagrees with the
handed-out config means the two ends can never handshake and WireGuard reports
that as silence, indistinguishable from a blocked port. The *Show laptop
config* view says so if they disagree.

**Scope** decides what crosses:

| | routes | use when |
|---|---|---|
| `venue subnets only` | just the listed subnets; model APIs and package mirrors stay on the home line | default — survives a venue that firewalls outbound API calls |
| `all container traffic` | every container's egress via the venue; the WSL host keeps its LAN default route, so the handshake and Ogamdo's control plane are never routed into the tunnel they depend on | you know the venue does not block your model provider |

A `/0` in *Venue subnets* is refused: written into the main table it would take
this box's own egress, and the WireGuard handshake with it. That is what
`all container traffic` is for, and it does the same job safely by policy
routing only the docker bridges.

## Laptop side

Copy **both** `scripts/venue-laptop.cmd` and `scripts/venue-laptop.ps1` to a
**local** folder on the laptop — `C:\ogamdo\` is fine. Not a network path:
cmd.exe cannot hold a UNC directory and silently falls back to `C:\Windows`,
so the launcher would no longer find the script beside it. (It detects this
and says so, rather than failing obscurely.)

Then run the `.cmd`. Right-click → **Run as administrator** when you want
`-Setup`; a plain double-click is enough for collection.

```
venue-laptop.cmd -Target host3.example.com:31337            (collect only)
venue-laptop.cmd -Target host3.example.com:31337 -Setup     (apply fwd + NAT)
```

**Why the `.cmd` rather than the `.ps1` directly:** Windows client defaults to
`ExecutionPolicy=Restricted`, so a bare `.ps1` dies with `PSSecurityException`
before running a line — and a script copied from a UNC path or USB stick also
carries a Zone.Identifier mark that blocks it again under `RemoteSigned`. The
launcher clears both **per run** (`-ExecutionPolicy Bypass` + `Unblock-File`)
rather than asking you to weaken the machine's policy for one contest.

Running the `.ps1` yourself works too, with the same bypass:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\venue-laptop.ps1 -Target host:port
```

It prints a `Venue subnets:` line ready to paste into Ogamdo, skips targets
that are PUBLIC (Ogamdo reaches those from home — routing them through the
venue would make the contest wifi the bottleneck for nothing), never suggests
the tunnel's own subnet, and ignores VMware / Hyper-V adapters that would
otherwise look like plausible venue networks.

Paste the generated config into the WireGuard client — and then do the half
that **cannot** live in a `.conf`: forward and masquerade from `wg0` into the
venue LAN. Without it the advertised subnets never answer, and the symptom
looks exactly like "the venue blocked us".

Linux laptop:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
VENUE_IF=wlan0            # the venue-facing interface
sudo iptables -t nat -A POSTROUTING -o "$VENUE_IF" -j MASQUERADE
sudo iptables -A FORWARD -i wg0 -o "$VENUE_IF" -j ACCEPT
sudo iptables -A FORWARD -i "$VENUE_IF" -o wg0 -m state \
     --state RELATED,ESTABLISHED -j ACCEPT
```

macOS laptop: `sudo sysctl -w net.inet.ip.forwarding=1` plus a `pf` nat rule on
the venue interface.

Windows laptop: `New-NetNat -Name venue -InternalIPInterfaceAddressPrefix 10.99.0.0/24`
in an elevated PowerShell, with `Set-NetIPInterface -Forwarding Enabled` on both
adapters.

Find the venue subnet from the laptop once you are there — `ip route` (Linux) or
`route print` (Windows) — and put the CIDR the problem servers live in into
*Venue subnets*.

## Checking it

The **Venue VPN status** block reports container, interface and peer
separately, because they come apart and the way they come apart tells you which
end to fix:

| chip | meaning |
|---|---|
| `absent` / `exited` | the sidecar is not running; the text shows the last lines of its log |
| `container up, wg0 down` | wg-quick failed — usually a malformed config |
| `no peer configured` | the laptop's public key is not saved |
| `waiting for laptop` | up and correct; the laptop has not handshaked yet. Normal until it dials in |
| `connected` | handshake within the last 3 minutes |

From a worker, `ip route get <venue-ip>` should leave via the docker bridge; on
the WSL host, `ip route show <venue-subnet>` should say `dev wg0`.

## If a sidecar is ever killed without its trap

The interface lives in the host netns, so a `SIGKILL` (rather than the
`docker stop` the UI uses, which allows 15s for teardown) would strand `wg0`
and its rules. Clear it with:

```sh
docker run --rm --net=host --cap-add=NET_ADMIN hextech_ctf_tool-vpn \
  ip link del wg0
```
