#!/bin/bash
# Bring wg0 up, install exactly the routes the chosen scope calls for, then
# stay alive holding them. Tear everything down on the way out.
#
# WHY THE TEARDOWN IS THE POINT OF THIS SCRIPT
#
# This container runs in the HOST netns, so an interface it creates OUTLIVES
# it. A bare `wg-quick up` would leave wg0, its routes and its ip rules behind
# on `docker stop`: the UI would say the VPN is off while the kernel kept
# routing, and the next start would die on "RTNETLINK answers: File exists".
# The trap makes stop mean stopped.
#
# WHY `Table = off` AND HAND-ROLLED ROUTES
#
# wg-quick's own route installation writes into the MAIN table, which is
# exactly the table this box needs left alone: the WSL VM is a first-class LAN
# host whose default route carries Ogamdo's own control plane -- the model
# APIs, the package mirrors, and the WireGuard handshake replies themselves.
# Letting wg-quick point the default at wg0 would strand the box AND the
# tunnel that was supposed to fix it, because the handshake's own reply path
# would loop into the tunnel.
#
# So the config says `Table = off` and this script installs routes itself:
#
#   scope=venue  one route per advertised subnet, in the main table. Everything
#                else on this box keeps the LAN path. The conservative default.
#   scope=all    a POLICY rule per docker bridge subnet, pointing container
#                traffic at a private table whose default is wg0. Containers
#                egress entirely through the venue; the WSL host itself does
#                not, so the handshake and the control plane stay on the LAN.
#                This is what "all job traffic" can mean without self-stranding.
set -euo pipefail

IFACE="${WG_INTERFACE:-wg0}"
CONF="/etc/wireguard/${IFACE}.conf"
SCOPE="${WG_SCOPE:-venue}"
SUBNETS="${WG_VENUE_SUBNETS:-}"
# A private table id. 51820 is the wireguard port by convention and collides
# with nothing in iproute2's reserved range (main=254, local=255).
TABLE="${WG_TABLE:-51820}"

if [ ! -s "$CONF" ]; then
  echo "[vpn] no config at $CONF — configure the venue VPN in Settings first" >&2
  exit 64
fi

# Bridge subnets are DISCOVERED, not configured: docker creates and destroys
# br-* networks on its own schedule, and a hand-maintained list would silently
# stop covering a network the day compose renumbered one.
bridge_subnets() {
  # Field positions are load-bearing and were wrong once: the line reads
  # `172.18.0.0/16 dev br-xxx proto kernel ...`, so the interface is $3 and the
  # literal `dev` is $2. Matching on $3=="dev" selected NOTHING, which under
  # scope=all installed the table's default route and not one ip rule to reach
  # it -- a tunnel that was up, looked up, and carried no container traffic.
  ip -4 route show scope link 2>/dev/null \
    | awk '$2=="dev" && ($3 ~ /^br-/ || $3=="docker0") {print $1}'
}

cleanup_rules() {
  # Delete by VALUE, repeatedly: an unclean stop can leave duplicates, and
  # `ip rule del` removes one match per call.
  while ip rule del table "$TABLE" 2>/dev/null; do :; done
  ip route flush table "$TABLE" 2>/dev/null || true
  # The masquerade goes too. It is inert once the interface is gone -- nothing
  # can match -o wg0 -- but leaving it would make `stop` a half-truth, and the
  # next reader would have to prove the harmlessness again from scratch.
  while iptables -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null; do :; done
}

down() {
  echo "[vpn] bringing ${IFACE} down"
  cleanup_rules
  wg-quick down "$IFACE" 2>/dev/null || ip link del "$IFACE" 2>/dev/null || true
  exit 0
}
trap down TERM INT

# Clear anything a SIGKILL or a host reboot mid-run left behind. Idempotent,
# and it cannot remove something a healthy start needs.
ip link del "$IFACE" 2>/dev/null || true
cleanup_rules

echo "[vpn] bringing ${IFACE} up (scope=${SCOPE})"
wg-quick up "$IFACE"

if [ "$SCOPE" = "all" ]; then
  # LOCAL ROUTES FIRST, AND THIS IS NOT OPTIONAL.
  #
  # A policy table holding only a default route captures EVERYTHING from the
  # matched sources -- including container->redis, container->api and
  # container->host, none of which have any business crossing a venue tunnel.
  # Measured here before it ever reached a contest: with `default dev wg0`
  # alone in the table, the dashboard stopped answering (curl HTTP 000) the
  # moment scope=all came up, because the api's own replies were being posted
  # into a tunnel with no peer. Every job would have died the same way, on
  # redis.
  #
  # ip rules are consulted BEFORE the main table, so the main table's link
  # routes cannot rescue this -- the exceptions have to live in THIS table.
  # Copied wholesale rather than enumerated: docker creates and destroys br-*
  # networks on its own schedule, and only `default` is being overridden.
  #
  # `linkdown` and `dead` are STATUS flags `ip route show` prints and
  # `ip route add` cannot parse, so a route carrying one fails to copy and the
  # `|| true` swallows it. Measured: docker0 and one br-* were both linkdown
  # and both silently missing from the table, which is harmless only while
  # those bridges hold no containers -- the day one does, its local traffic is
  # blackholed into the tunnel and the failure looks like the venue's fault.
  ip route show table main | grep -vE '^default' | sed -E 's/ (linkdown|dead)//g' \
  | while read -r route; do
    ip route add table "$TABLE" $route 2>/dev/null || true
  done
  ip route add default dev "$IFACE" table "$TABLE"
  n=0
  for net in $(bridge_subnets); do
    ip rule add from "$net" lookup "$TABLE" priority 1000
    echo "[vpn] container subnet ${net} -> ${IFACE}"
    n=$((n+1))
  done
  if [ "$n" -eq 0 ]; then
    echo "[vpn] WARNING: no docker bridge subnets found; scope=all routed nothing" >&2
  fi
else
  for net in ${SUBNETS//,/ }; do
    [ -n "$net" ] || continue
    ip route replace "$net" dev "$IFACE"
    echo "[vpn] venue subnet ${net} -> ${IFACE}"
  done
fi

# Container traffic leaving through wg0 carries a 172.x source the venue has
# no route back to, so it is masqueraded to the tunnel address. wg-quick's own
# PostUp is not used for this: it would run before the policy rules above.
iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE

wg show "$IFACE" || true
ip route show dev "$IFACE" || true

# `wait` on a background sleep, not a foreground one: the trap fires PROMPTLY
# on SIGTERM this way, instead of after docker's grace period expires into
# SIGKILL — which would skip the teardown and strand the interface.
sleep infinity &
wait $!
