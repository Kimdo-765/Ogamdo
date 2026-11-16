<#
.SYNOPSIS
  Collect everything Ogamdo needs from the venue, in one pass, from the laptop.

.DESCRIPTION
  Run this on the LAPTOP, at the venue, in an ELEVATED PowerShell.

  Ogamdo sits at home and can only reach the contest's problem servers through
  this laptop. Exactly one field cannot be filled in before you arrive -- which
  subnets to route -- and guessing it wrong looks identical to a blocked port.
  This prints that field ready to paste, and says which interface it came from.

  READ-ONLY BY DEFAULT. It changes nothing unless you pass -Setup, which turns
  on the forwarding and NAT that make the advertised subnets actually answer --
  the half that cannot live in a WireGuard .conf and is the usual reason a
  tunnel connects and then carries nothing.

.PARAMETER Target
  A problem server, `host:port` or bare host. The script resolves it, says
  which interface reaches it, and singles out the subnet to advertise. With
  several targets, pass them comma-separated.

.PARAMETER Setup
  Apply forwarding + NAT so traffic arriving on the tunnel can reach the venue.

.PARAMETER TunnelSubnet
  The tunnel's address range; must match Ogamdo's "Tunnel address (this box)".
  Default 10.99.0.0/24.

.EXAMPLE
  .\venue-laptop.ps1 -Target host3.dreamhack.games:12345
.EXAMPLE
  .\venue-laptop.ps1 -Target 10.20.5.7,10.20.5.8 -Setup
#>
[CmdletBinding()]
param(
  [string[]] $Target,
  [switch]   $Setup,
  [string]   $TunnelSubnet = "10.99.0.0/24"
)

$ErrorActionPreference = "Continue"

function Write-Head($t) { Write-Host ""; Write-Host "== $t" -ForegroundColor Cyan }
function Write-Ok($t)   { Write-Host "  [ok] $t"   -ForegroundColor Green }
function Write-Warn2($t){ Write-Host "  [!]  $t"   -ForegroundColor Yellow }
function Write-Bad($t)  { Write-Host "  [x]  $t"   -ForegroundColor Red }

# PowerShell has no CIDR maths, and the host address is NOT the subnet: an
# interface at 10.20.5.7/16 must be advertised as 10.20.0.0/16. Advertising the
# host address instead routes one address and silently drops the rest.
function Get-NetworkCidr([string]$ip, [int]$prefix) {
  $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
  [array]::Reverse($bytes)
  $addr = [BitConverter]::ToUInt32($bytes, 0)
  $mask = if ($prefix -eq 0) { 0 } else { [uint32]((0xFFFFFFFFL -shl (32 - $prefix)) -band 0xFFFFFFFFL) }
  $net  = $addr -band $mask
  $nb   = [BitConverter]::GetBytes([uint32]$net)
  [array]::Reverse($nb)
  "$([System.Net.IPAddress]::new($nb).IPAddressToString)/$prefix"
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Head "Laptop network"
$cands = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object {
    $_.IPAddress -ne "127.0.0.1" -and
    $_.PrefixOrigin -ne "WellKnown" -and
    $_.InterfaceAlias -notmatch "Loopback"
  }

$rows = @()
foreach ($c in $cands) {
  $cidr = Get-NetworkCidr $c.IPAddress $c.PrefixLength
  # The tunnel's own interface must never be advertised back to Ogamdo: it
  # would tell the desktop to reach the tunnel through the tunnel.
  $isTun = ($c.InterfaceAlias -match "wg|WireGuard") -or
           ($cidr -eq $TunnelSubnet)
  $rows += [pscustomobject]@{
    Interface = $c.InterfaceAlias
    Address   = "$($c.IPAddress)/$($c.PrefixLength)"
    Subnet    = $cidr
    Role      = if ($isTun) { "tunnel (do not advertise)" } else { "venue candidate" }
  }
}
$rows | Format-Table -AutoSize | Out-String | Write-Host

$gw = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
      Sort-Object RouteMetric | Select-Object -First 1
if ($gw) { Write-Ok "default route via $($gw.NextHop) on '$((Get-NetAdapter -InterfaceIndex $gw.InterfaceIndex -ErrorAction SilentlyContinue).Name)'" }

# ---------------------------------------------------------------------------
# Targets -- the authoritative way to pick the subnet. An interface list is a
# guess; a route lookup against the actual problem server is an answer.
# ---------------------------------------------------------------------------
$advertise = New-Object System.Collections.Generic.List[string]
if ($Target) {
  Write-Head "Targets"
  foreach ($t in $Target) {
    $hostPart = $t.Split(":")[0]
    $portPart = if ($t -match ":") { $t.Split(":")[1] } else { $null }

    $ips = @()
    try {
      $ips = (Resolve-DnsName -Name $hostPart -Type A -ErrorAction Stop |
              Where-Object { $_.IPAddress }).IPAddress
    } catch {
      if ($hostPart -as [ipaddress]) { $ips = @($hostPart) }
    }
    if (-not $ips) { Write-Bad "$hostPart : could not resolve"; continue }

    foreach ($ip in $ips) {
      $r = Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1
      if (-not $r) { Write-Bad "$hostPart ($ip) : no route"; continue }
      $iface = (Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue).Name
      $viaTunnel = $iface -match "wg|WireGuard"

      # A PUBLIC target does not need the tunnel at all -- Ogamdo can reach it
      # from home. Advertising it would route contest traffic through this
      # laptop's uplink for no reason, and quietly make the venue's wifi the
      # bottleneck for everything.
      $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
      $isPrivate = ($b[0] -eq 10) -or
                   ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
                   ($b[0] -eq 192 -and $b[1] -eq 168) -or
                   ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)

      $reach = "?"
      if ($portPart) {
        $tc = Test-NetConnection -ComputerName $ip -Port $portPart -WarningAction SilentlyContinue
        $reach = if ($tc.TcpTestSucceeded) { "open" } else { "no answer" }
      }

      Write-Host "  $hostPart -> $ip  via '$iface'  tcp/$portPart=$reach"
      if ($viaTunnel) {
        Write-Warn2 "reached through the tunnel already -- not a venue subnet"
      } elseif (-not $isPrivate) {
        Write-Warn2 "PUBLIC address: Ogamdo can reach this from home. No need to advertise it."
      } else {
        $src = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $r.IPAddress -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($src) {
          $cidr = Get-NetworkCidr $src.IPAddress $src.PrefixLength
          if (-not $advertise.Contains($cidr)) { $advertise.Add($cidr) }
          Write-Ok "advertise $cidr  (from $($src.IPAddress)/$($src.PrefixLength) on '$iface')"
        }
      }
    }
  }
}

# Virtual adapters are never the venue. A laptop carrying VMware, VirtualBox
# and Hyper-V switches offers half a dozen private subnets that all look
# plausible, and advertising one of them tells Ogamdo to route contest traffic
# into a hypervisor. They stay in the table above -- they just do not get
# guessed.
$VIRTUAL = "VMware|VirtualBox|Hyper-V|Default Switch|vEthernet|Bluetooth|Loopback|TAP-|wg|WireGuard"
$guessFrom = @{}
if ($advertise.Count -eq 0 -and -not $Target) {
  foreach ($r in $rows | Where-Object { $_.Role -eq "venue candidate" -and $_.Interface -notmatch $VIRTUAL }) {
    $ipStr  = $r.Address.Split("/")[0]
    $prefix = [int]$r.Address.Split("/")[1]
    $b = ([System.Net.IPAddress]::Parse($ipStr)).GetAddressBytes()

    # /30 and /31 are POINT-TO-POINT links -- two usable addresses, or none.
    # A contest LAN is never one; a VPN, LTE modem or PPP adapter almost always
    # is. Observed in the field: a laptop offered 10.241.233.180/30 as its only
    # private subnet while the real venue interface sat on a public /24, and
    # advertising the /30 would have routed two addresses and nothing else.
    if ($prefix -ge 30) { continue }
    # APIPA means DHCP failed on that adapter. It is not a network.
    if ($b[0] -eq 169 -and $b[1] -eq 254) { continue }

    if (($b[0] -eq 10) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and $b[1] -eq 168)) {
      if (-not $advertise.Contains($r.Subnet)) {
        $advertise.Add($r.Subnet)
        $guessFrom[$r.Subnet] = $r.Interface
      }
    }
  }
}

# ---------------------------------------------------------------------------
Write-Head "Paste into Ogamdo -- Settings / Access / Venue VPN"
if ($advertise.Count -gt 0) {
  Write-Host ""
  Write-Host "  Venue subnets:  " -NoNewline
  Write-Host ($advertise -join ", ") -ForegroundColor White
  Write-Host ""
  if (-not $Target) {
    foreach ($a in $advertise) {
      if ($guessFrom.ContainsKey($a)) { Write-Host "      $a  <- '$($guessFrom[$a])'" -ForegroundColor DarkGray }
    }
    Write-Host ""
    Write-Warn2 "GUESSED from this laptop's interfaces. Check the interface names above are"
    Write-Host "       the venue's, then re-run with -Target <problem server> to have it" -ForegroundColor Yellow
    Write-Host "       decided by a route lookup instead. The guess cannot tell a contest" -ForegroundColor Yellow
    Write-Host "       LAN from a corporate VPN you happen to be on." -ForegroundColor Yellow
  }
} else {
  Write-Bad "nothing to advertise."
  Write-Host "       No private subnet here looks like a venue LAN -- they belong to" -ForegroundColor DarkGray
  Write-Host "       virtual adapters, point-to-point links (/30, /31), or the tunnel." -ForegroundColor DarkGray
  Write-Host "       If this laptop's venue interface has a PUBLIC address, the problem" -ForegroundColor DarkGray
  Write-Host "       servers may be reachable from home already -- check before assuming" -ForegroundColor DarkGray
  Write-Host "       a tunnel is needed at all." -ForegroundColor DarkGray
  Write-Host "       Either way: re-run with -Target <problem server>." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
Write-Head "Tunnel"
$wg = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceAlias -match "wg|WireGuard" }
if ($wg) {
  Write-Ok "tunnel interface up: $($wg.InterfaceAlias) $($wg.IPAddress)"
} else {
  Write-Warn2 "no tunnel interface. Import the config from Ogamdo's 'Show laptop config' and activate it."
}

# ---------------------------------------------------------------------------
Write-Head "Forwarding and NAT"
if (-not $Setup) {
  Write-Host "  read-only. Re-run with -Setup to apply." -ForegroundColor DarkGray
  $nat = Get-NetNat -ErrorAction SilentlyContinue | Where-Object { $_.InternalIPInterfaceAddressPrefix -eq $TunnelSubnet }
  if ($nat) { Write-Ok "NAT for $TunnelSubnet already present: $($nat.Name)" }
  else      { Write-Warn2 "no NAT for $TunnelSubnet -- the tunnel will connect and carry nothing until -Setup" }
} elseif (-not $isAdmin) {
  Write-Bad "-Setup needs an ELEVATED PowerShell. Re-open as Administrator."
} else {
  Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.ConnectionState -eq "Connected" } |
    ForEach-Object {
      try {
        Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -Forwarding Enabled -ErrorAction Stop
        Write-Ok "forwarding on '$($_.InterfaceAlias)'"
      } catch { Write-Warn2 "forwarding on '$($_.InterfaceAlias)': $($_.Exception.Message)" }
    }

  $existing = Get-NetNat -ErrorAction SilentlyContinue | Where-Object { $_.InternalIPInterfaceAddressPrefix -eq $TunnelSubnet }
  if ($existing) {
    Write-Ok "NAT already present: $($existing.Name)"
  } else {
    # One NAT per prefix is a hard Windows limit, and WSL on this laptop may
    # already hold one. Say which, rather than fail with 'the parameter is
    # incorrect'.
    $clash = Get-NetNat -ErrorAction SilentlyContinue
    try {
      New-NetNat -Name "OgamdoVenue" -InternalIPInterfaceAddressPrefix $TunnelSubnet -ErrorAction Stop | Out-Null
      Write-Ok "created NAT 'OgamdoVenue' for $TunnelSubnet"
    } catch {
      Write-Bad "could not create NAT: $($_.Exception.Message)"
      if ($clash) {
        Write-Warn2 "existing NATs (Windows allows a limited number): $(($clash | ForEach-Object { "$($_.Name)=$($_.InternalIPInterfaceAddressPrefix)" }) -join ', ')"
      }
    }
  }
}

Write-Head "Next"
Write-Host "  1. Put 'Venue subnets' above into Ogamdo and Save with the toggle ON."
Write-Host "  2. Ogamdo's status chip should reach 'connected' within ~30s."
Write-Host "  3. From a worker:  ip route get <problem server ip>   should leave via the docker bridge."
Write-Host ""
Write-Host "  If it says connected but nothing answers, it is almost always this" -ForegroundColor DarkGray
Write-Host "  script's -Setup half missing on THIS laptop." -ForegroundColor DarkGray
