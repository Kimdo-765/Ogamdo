# The venue-VPN sidecar.
#
# WHY THIS IS A CONTAINER AND NOT A HOST INSTALL
#
# Ogamdo runs in WSL2 with `networkingMode=bridged`, so the WSL VM is a
# first-class host on the LAN with its OWN address and its OWN default route
# via the LAN gateway -- it does not traverse Windows' routing table at all.
# A WireGuard profile toggled in Windows therefore carries Windows' traffic
# and none of Ogamdo's. The tunnel has to terminate in the WSL VM.
#
# It runs `network_mode: host`, which in WSL means the WSL VM's netns -- NOT
# Windows. So `wg0` and its routes land exactly where every worker, runner and
# challenge container already egresses (container -> docker bridge -> WSL host
# routing table), and they inherit the route with no per-container change and
# no NET_ADMIN anywhere but here.
#
# Kernel mode, not userspace: the WSL kernel ships CONFIG_WIREGUARD=m and
# carries wireguard.ko, so wg-quick gets the in-kernel datapath. That is why
# this image needs no wireguard-go and why SYS_MODULE is in the compose
# cap_add -- the module is not loaded until the first interface is created.
FROM alpine:3.22

# bash: alpine's wg-quick is a bash script, and busybox ash will not run it.
# iptables: wg-quick's PostUp masquerade, and the rule that lets container
#   traffic leave through wg0 with a tunnel source address.
# iproute2: `ip route` / `ip link`, which wg-quick shells out to.
RUN apk add --no-cache wireguard-tools iptables ip6tables iproute2 bash

COPY vpn/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
