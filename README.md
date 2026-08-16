# Loki Traffic Lab

Root-level diagnostic bench for checking which application classes use Loki's
local proxy path.

The lab does not need Russian users. It compares several traffic profiles:

- native .NET direct, system proxy, explicit HTTP proxy;
- curl direct and env-proxy child process;
- Node core fetch direct/env, useful to show that plain Node does not always
  honor proxy env variables by itself;
- Chromium-family browser headless direct, system proxy and explicit proxy when
  Edge/Chrome is installed.

The main signal is `likelyReachedXray`. It is calculated by checking whether
new Xray access-log lines contain the target host during the probe.

## Run

Connect Loki first, then run from the repository root:

```powershell
.\traffic-lab\run.ps1
```

Reports are written to:

```text
traffic-lab\artifacts
```

Use a narrower run when iterating:

```powershell
.\traffic-lab\run.ps1 -Targets "https://api.ipify.org?format=json" -Profiles native-system,curl-env,browser-system
```

## Reading Results

Expected shape when Loki is connected:

```text
native-direct       likelyReachedXray = false
native-explicit     likelyReachedXray = true
curl-env            likelyReachedXray = true
browser-explicit    likelyReachedXray = true
native-system       true if Windows system proxy is active and honored
browser-system      true if browser reads current Windows system proxy
```

If explicit profiles fail, Loki/Xray is not listening on the expected local
HTTP port or the connection is off.

If explicit profiles pass but system profiles fail, the issue is system proxy
registration or process/browser proxy discovery.

If browser profiles are skipped, install Edge or Chrome, or pass a path:

```powershell
.\traffic-lab\run.ps1 -BrowserPath "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

## Observe A Real App

Use `observe-app.ps1` when the app is already running and you need to confirm
whether its live TCP connections go through the local proxy:

```powershell
.\traffic-lab\observe-app.ps1 `
  -ProcessName steam,steamwebhelper,steamservice `
  -ProxyPort 18091 `
  -ExpectedHosts store.steampowered.com,steamcommunity.com,api.steampowered.com,steamconnecttest.com,steamserver.net
```

The observer writes JSON/CSV reports to `traffic-lab\artifacts`, counts live
connections to `127.0.0.1:<proxy-port>`, and checks recent Xray access-log lines
for the expected hosts.

## Inspect And Test Individual VLESS Profiles

`profile-runner.ps1` is the staged per-profile diagnostic runner. It does not
change Windows system proxy settings and does not install a TUN route. Every
profile is started in an isolated Xray process with temporary configuration,
unique loopback ports and dedicated logs.

Pass a URI directly:

```powershell
.\traffic-lab\profile-runner.ps1 `
  -VlessUri '<vless-uri>' `
  -NetworkLabel 'office-ethernet'
```

Or pass a local text file containing one URI per line. Empty lines and lines
beginning with `#` are ignored:

```powershell
.\traffic-lab\profile-runner.ps1 `
  -InputFile '.\private\profiles.txt' `
  -NetworkLabel 'home-isp'
```

Use an explicit Xray binary when comparing core versions:

```powershell
.\traffic-lab\profile-runner.ps1 `
  -InputFile '.\private\profiles.txt' `
  -XrayPath '.\traffic-lab\Portable windows\vendor\v2rayN-windows-64\bin\xray\xray.exe'
```

The runner performs these stages where applicable:

- sanitized URI parsing without persisting UUID, REALITY credentials, short ID
  or subscription URL;
- endpoint and camouflage-host DNS through the system API, configured DNS
  servers, `1.1.1.1`, `8.8.8.8`, Google DoH and Cloudflare DoH;
- per-address TCP connect and bounded traceroute;
- RDAP, RIPEstat BGP-origin ASN, reverse DNS and approximate geolocation hints;
- ordinary TLS fallback with SNI, TLS version, ALPN and certificate metadata;
- path/Host-aware WebSocket upgrade for WebSocket profiles;
- Xray config validation and isolated core startup;
- exit-IP comparison through three independent services;
- functional HTTP, SOCKS hostname resolution, bounded download and repeated
  stability requests;
- SOCKS5 UDP ASSOCIATE with a real DNS response;
- parsed Xray access/error log evidence and conservative inferences for
  ingress/egress separation, UDP, DNS, routing scope and failure localization.

Reports are written as structured JSON plus a flattened CSV stage table under
`traffic-lab\artifacts`. Facts and inferences are kept separate. Client-side
tests cannot prove the configured second hop, exact REALITY target, panel HWID
policy or server outbound chain.

Run local parser/redaction/DNS-packet checks without using a profile:

```powershell
.\traffic-lab\profile-runner.ps1 -SelfTest
```

## Platform Distribution Layout

The shared diagnostic logic remains in `traffic-lab\src` and the root runner
scripts. Platform-specific packaging and releases are separated as follows:

- `traffic-lab\Portable windows` - Windows packaging assets, vendor runtime and releases;
- `traffic-lab\Linux` - Ubuntu/Linux headless packaging, bootstrap and releases;
- `traffic-lab\Apk` - native Android 8+ APK, local build bootstrap and releases.

The Android adaptation embeds Xray for arm64-v8a and x86_64, uses a foreground
test service, accepts one or many clipboard links, and exports the same
four-file result ZIP through Android's document picker or Sharesheet. See
`traffic-lab/Apk/README.txt` for build, coverage and privacy details.

### Ubuntu / Linux

Build the self-contained Ubuntu release:

```powershell
& '.\traffic-lab\Linux\build-linux.ps1' -RuntimeIdentifier linux-x64 -Archive
```

Install it on Ubuntu in one local command:

```bash
sudo bash ./bootstrap.sh --archive ./LokiTrafficLab-linux-x64-3.1.2.tar.gz
```

After placing VLESS URIs in `~/.config/tlab/connections.txt`, use `tlab start`,
`tlab status`, `tlab logs --follow`, and emergency `tlab stop`. Start prompts
for a loopback-only test port, displays a stable single-line progress bar and
exits automatically with an archive summary; UFW is not disabled, flushed, or modified. Linux uses
the same four-file result ZIP schema as Windows. Native commands remain
available through `tlab raw`, including the explicit root-only tcpdump capture.
See `traffic-lab/Linux/README.txt` for hosted bootstrap and operational details.

## Build The Standalone Portable Application

Build a self-contained Windows package from the repository root:

```powershell
& '.\traffic-lab\Portable windows\build-portable.ps1' -RuntimeIdentifier win-x64 -Zip
```

The resulting directory and ZIP are under
`traffic-lab\Portable windows\releases`. The package contains the single-file
`LokiTrafficLab.exe`, `xray.exe`, `connections.txt`, a manifest with SHA-256
hashes, an example test plan, third-party notices and an offline README. A target Windows PC does not need .NET, Xray,
curl, OpenSSL, Node.js, `dig`, `whois`, or PowerShell modules installed.

By default the application reads one VLESS URI per active line from the adjacent
`connections.txt`. Blank lines and lines beginning with `#`, `;` or `//` are
ignored. Order and duplicates are preserved and reports identify entries by
safe ordinal, source line, display name and sanitized fingerprint. The file is
plaintext credential storage and must not be shared. Stdin remains available so
URIs do not appear in the process command line or remain on disk. Reports never
contain the raw URI, UUID, REALITY key/password or short ID.

## Portable Commands

Double-click `LokiTrafficLab.exe` for the minimal Windows UI. It validates
`connections.txt`, blocks the start when it sees another system proxy, PAC,
active TUN/VPN adapter or proxy environment variable, then shows approximate
progress, elapsed/remaining time and a button for saving
the completed result ZIP. In version 3.0.1 and newer the button performs a
bounded asynchronous, non-overwriting copy to the Windows Downloads known
folder; it does not open the Shell Save dialog, which can hang on unavailable
Quick Access or network locations. Starting with version 3.0.2, an orphaned
proxy executable or unused loopback listener alone does not block START because
it does not alter Traffic Lab's direct route. Version 3.1.0 adds a separate
`EXTENDED TEST` button. After explicit confirmation and UAC elevation it adds a
five-minute latency/jitter/loss soak per profile, cold/warm comparison, 20
parallel TCP and UDP flows, DNS failure/recovery, an isolated Xray restart and
a five-second Windows Firewall interruption scoped only to the bundled
`xray.exe`. It never disables the adapter or blocks unrelated applications.
Every report records `NORMAL` or `EXTENDED` plus the extended parameters.
Version 3.1.1 adds `extended-test.json` as the fifth per-profile file in an
extended result package. Controlled Firewall failures are recorded with an
`expectedFailureWindow` and classified as induced; successful UDP-association
closed-pipe/EOF teardown is classified as benign. Only unexpected core markers
downgrade `tunnel.logs`. Download measurements now expose separate
RTT/TTFB-inclusive effective throughput and approximate post-first-byte payload
throughput across a cold request and repeated warm attempts.
Linux release 3.1.2 adds the dedicated `tlab extended` command, the same
separate `extended-test.json` package layout, explicit NORMAL/EXTENDED metadata,
and platform/distribution/kernel/architecture fields. Its controlled
interruption uses SIGSTOP/SIGCONT only on Traffic Lab's own Xray child and never
changes UFW, routes or network interfaces.
`STOP TEST` cancels rather than pauses: it
terminates the current Xray process tree, removes incomplete outputs and makes
the next START begin a new run from the first connection. Progress is deliberately labelled approximate because
DNS, RDAP and traceroute timeouts depend on the current network.

Paste connections into `connections.txt`, one per line, then run all of them in
order:

```powershell
.\LokiTrafficLab.exe run --plan .\ru-ethernet.json
```

To use a differently named list:

```powershell
.\LokiTrafficLab.exe run --connections .\my-connections.txt --outdir .\artifacts
```

Create a non-secret test plan for a measurement node:

```powershell
.\LokiTrafficLab.exe plan `
  --out ru-ethernet.json `
  --run-group comparison-001 `
  --node-id ru-pc-01 `
  --network-label ru-home-ethernet `
  --country RU `
  --region Moscow `
  --access ethernet `
  --scenario standalone `
  --dns-attempts 3 `
  --tcp-attempts 5 `
  --stability-attempts 10 `
  --negative-controls `
  --xudp
```

Run the same profile without putting the URI in command-line arguments:

```powershell
$uri = Read-Host 'Paste VLESS URI'
@{ uris = @($uri) } | ConvertTo-Json -Compress |
  .\LokiTrafficLab.exe run `
    --stdin `
    --plan .\ru-ethernet.json `
    --outdir .\artifacts `
    --history .\artifacts\history.sqlite
Remove-Variable uri
```

## Per-connection result package

Every `run` creates a compact `traffic-lab-results-*.zip`. For one connection
the archive root contains exactly four files:

- `connection.json` — full connection characteristics, stages, attribution,
  conclusions and heuristic probabilities for competing explanations;
- `local-machine.json` — the complete test-node/network passport;
- `osi-map.md` — seven-layer evidence table and Mermaid path map;
- `README.txt` — UTC/local start and completion time, duration, node/tool/core,
  input/order, stage counts, file guide, privacy notes and confidence legend.

For multiple connections, the ZIP contains ordered folders such as
`01-Primary Test` and `02-Secondary Test`; every folder contains the same four
files. Folder names are derived from URI display names, stripped of unsafe path
characters and made unique. Duplicate endpoints and credentials-independent
fingerprints remain separate profile instances.

Probabilities are explicitly marked as conservative heuristic evidence weights,
not calibrated statistical probabilities. Exact observations, qualitative
confidence, competing alternatives, basis and server-side limitations are all
stored together.

The archive is written directly through streaming compression. It excludes the
portable executables, packet captures, SQLite history and network test payloads;
the GUI retains only a bounded tail of console output. Direct speed buffers are
bounded to 2 MiB download and 512 KiB upload.

Other commands:

```powershell
# Network-only evidence before a profile is available
.\LokiTrafficLab.exe snapshot --plan .\ru-ethernet.json --outdir .\artifacts

# Compare two nodes or two points in time
.\LokiTrafficLab.exe compare .\local.json .\ru.json

# Build a profile x network x scenario matrix; concurrency scenarios produce
# conservative HWID/session-policy hints
.\LokiTrafficLab.exe matrix .\artifacts

# Observe whether a running application uses a local proxy, direct sockets,
# a mixed path, or a changed route/TUN interface
.\LokiTrafficLab.exe observe --process steam --process steamwebhelper --proxy-port 18091 --duration 30

# Import and list normalized SQLite history
.\LokiTrafficLab.exe history import .\artifacts --db .\artifacts\history.sqlite
.\LokiTrafficLab.exe history list --db .\artifacts\history.sqlite
```

## Extended Evidence Stages

In addition to the original profile stages, the portable runner captures:

- repeated DNS answer sets and per-record-type resolver divergence/rotation;
- repeated TCP connect min/p50/p95;
- bounded ICMP DF/path-MTU hints plus HTTPS payload sizes from 1 KiB to 1 MiB;
- separate endpoint and camouflage-host geolocation consensus with confidence
  and an explicit uncertainty radius;
- up to 20 traceroute hops with public-hop RDAP/BGP/ASN attribution;
- a TLS/SNI matrix comparing the profile SNI, endpoint host, invalid control SNI
  and direct camouflage host;
- Windows route-table hashes and TUN/system-proxy evidence before and during the
  isolated core;
- IPv4/IPv6 direct-versus-tunnel exit comparison;
- HTTP/1.1 and HTTP/2 negotiation, a native QUIC/HTTP/3-path handshake,
  download, upload, payload sweep and repeated stability requests;
- UDP DNS and an independent STUN mapped-address observation;
- one-shot invalid UUID, short-ID and SNI controls when explicitly enabled;
- an explicit `packetEncoding=xudp` A/B compatibility probe when enabled;
- conservative external signals for SNI routing, fallback/fronting, DNS
  balancing and possible load balancing.

## Test-node passport and OSI evidence map

Every run and `snapshot` now records the no-proxy side of the test node:

- local and public IPv4/IPv6, active/default-route interfaces, DHCP, MTU,
  gateways, DNS suffixes and resolvers;
- detected/declared Ethernet, Wi-Fi, WWAN/cellular, PPP or tethering access;
- bounded no-proxy latency, 2 MiB download and 512 KiB upload samples;
- public-prefix ASN/provider, reverse DNS and low-confidence IP geolocation;
- direct STUN mapping, local/private/global address comparison, private and
  CGNAT traceroute hops, and conservative multi-NAT hints;
- gateway RTT, hashed MAC identity/OUI and manufacturer/model when the gateway
  voluntarily advertises UPnP/SSDP device metadata;
- hashed Wi-Fi SSID/BSSID, radio type, security, channel, signal and negotiated
  rates without writing the raw SSID or BSSID;
- Windows system/WinHTTP/PAC proxy signals, tunnel adapters, firewall-state
  summary, hosts-file entry count/hash, NAT64/464XLAT hints and captive-portal
  behavior;
- a per-profile evidence graph covering OSI layers 1 through 7 from the test
  device to gateway, ISP/NAT, proxy entry, authenticated tunnel, exit and test
  application.

The OSI map explicitly marks hidden VLAN, carrier, server-routing, HWID and
panel state rather than inventing unreachable topology.

The matrix command combines reports from nodes with the same profile
fingerprint. When at least three plans contain trusted latitude/longitude and
TCP RTT measurements, it emits a coarse speed-of-light-bounded location region.
This is deliberately reported as a low/medium-confidence radius, never as a
physical datacenter address.

## Optional Controlled Collector

The portable executable can run a small HTTP echo, UDP echo and DNS responder:

```powershell
.\LokiTrafficLab.exe collector `
  --bind 0.0.0.0 `
  --http-port 18080 `
  --udp-port 18081 `
  --dns-port 53 `
  --dns-answer 203.0.113.10 `
  --outdir .\collector-artifacts
```

Use it only on an authorized reachable host with firewall/rate-limit rules. A
delegated per-run DNS name and `canaryUrlTemplate`, for example
`https://{id}.lab.example.net/echo`, correlate authoritative DNS source,
recursive resolver and HTTP exit address. The collector writes live JSONL and a
final structured JSON report.

## Optional Packet Capture

Packet capture is never started by ordinary `run`, `snapshot` or `observe`
commands. On an elevated Windows terminal it can be explicitly requested:

```powershell
.\LokiTrafficLab.exe capture --duration 30 --outdir .\artifacts --i-understand
```

The command refuses to modify an already-running `pktmon` session, always stops
only the capture it started, converts ETL to PCAPNG and marks the artifact as
sensitive because it can contain unrelated machine traffic.

## Distributed Limits

Two ordinary client PCs substantially improve GeoDNS, filtering, route,
performance, load-balancer and session-policy evidence. They still cannot
authoritatively reveal server `routing.rules`, a hidden second hop,
`realitySettings.target`, panel HWID state or a private load-balancer topology.
The runner therefore keeps observed facts separate from `low`, `medium` and
`high` confidence inferences. A mobile/operator scenario should be represented
by a new plan and run later rather than relabeling an Ethernet result.
