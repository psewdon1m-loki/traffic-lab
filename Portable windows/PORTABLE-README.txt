Loki Traffic Lab Portable 3.5.1
==============================

Results preserve status and add causal outcome/reason fields at stage, profile
and run level: PASS, PROXY_FAIL, UNDERLAY_FAIL, TEST_FAILURE or UNKNOWN. Windows
Location Service is queried on a best-effort basis; when permission/service is
unavailable the report records that fact and continues with IP-prefix geo only.
Device coordinates are sensitive and are stored with source and accuracy.

This directory is self-contained. The target Windows PC does not need .NET,
Xray, curl, dig, OpenSSL, Node.js, or any PowerShell module installed.

Double-click LokiTrafficLab.exe (version 3.1.3 or newer) to open the Windows interface. It checks for an
already active system proxy/PAC, proxy environment variable, or VPN/TUN route before enabling a clean baseline, displays approximate
progress and elapsed/remaining time, and offers to save the final ZIP.
An otherwise unused xray/sing-box process left behind after disconnecting is
not sufficient to block START: it cannot change Traffic Lab's direct route.
`STOP TEST` permanently cancels the current run (it is not pause), terminates
the isolated Xray process tree, removes incomplete result files and enables a
fresh START only after cleanup has completed.

START TEST runs the standard suite. SPEED TEST runs only endpoint/authentication
prerequisites and matched direct-before, tunnel and direct-after speed checks;
its ZIP contains exactly speed.json and readme.txt. EXTENDED TEST additionally runs a 5-minute
latency/jitter/loss soak for every connection, cold-versus-warm requests, 20
parallel TCP and UDP flows, DNS failure/recovery, an isolated Xray restart and
a 5-second Windows Firewall interruption scoped only to the bundled xray.exe.
The extended button asks for Administrator elevation and explicit confirmation.
It never disables the network adapter or blocks unrelated applications. A
temporary rule named LokiTrafficLab-Temporary-ProcessBlock is removed before
and after the fault test, including cancellation cleanup. With multiple
connections the five-minute soak runs once per connection, sequentially.

Every result README and structured output records Test type: NORMAL, EXTENDED or SPEED
and, for extended runs, the soak, parallel-flow, interruption and elevation
metadata.

Extended result archives contain a fifth file named extended-test.json. It
holds only the long-running/disruptive stages, expected failure windows, Xray
log classification and throughput correlation. Xray errors inside a controlled
Firewall window are labelled expected/induced. UDP closed-pipe and association
EOF teardown messages are labelled benign lifecycle events. Only genuinely
unexpected markers can downgrade tunnel.logs to partial.
Negative controls always mutate the VLESS UUID. Short-ID and SNI variants run
only when those parameters are declared by a REALITY profile; non-applicable
variants are recorded with reasons and cannot create false partial results.

Speed reports use incompressible streaming upload with bounded 64 KiB buffers,
discard bodies, exclude warm-up/calibration and synchronize parallel workers.
Raw windows, p10/median/p90, variation, byte-cap flags, idle/loaded latency and
STRAGGLER/CONCURRENCY/ENDPOINT classifications are retained. EXTENDED and SPEED
use a matched Direct-Tunnel-Tunnel-Direct sequence with full 1/4/16-flow controls;
same-flow drift above 15% lowers confidence. Only SPEED shows Download/Upload in
the UI after completion. Its theoretical cap is about 3.5 GiB per profile;
typical use is lower and memory remains bounded.
The bounded clock begins with the first payload byte; cold DNS/TCP/TLS/TTFB is
still recorded but cannot consume the sustained-transfer window. Public-edge
HTTP 403/429 is labelled ENDPOINT_REQUEST_REJECTED/ENDPOINT_RATE_LIMITED and is
not treated as proof of a proxy fault.
Cloudflare and OVH SBG/RBX/BHS 1 MiB controls are retained separately to reveal
CDN/peering bias and are never averaged into the matched primary Mbps value.
Completed uploads use full server-acknowledged request duration and are labelled
UPLOAD_ACK_BOUNDED_ESTIMATE (at most medium confidence without server timing).

1. Put one complete VLESS URI per line in connections.txt. Blank lines and
   lines beginning with #, ; or // are ignored. Lines are tested in order.
   The file contains credentials: protect it and delete it before sharing.

2. Create a non-secret plan for the measurement node:

   LokiTrafficLab.exe plan --out ru-ethernet.json --node-id ru-pc-01 --network-label ru-home-ethernet --country RU --region Moscow --access ethernet --dns-attempts 3 --tcp-attempts 5 --stability-attempts 10 --negative-controls --xudp

3. Run every active line from connections.txt:

   .\LokiTrafficLab.exe run --plan .\ru-ethernet.json

4. Alternatively, run profiles without storing URIs or putting them in process arguments:

   $uri = Read-Host "Paste VLESS URI"
   @{ uris=@($uri) } | ConvertTo-Json -Compress | .\LokiTrafficLab.exe run --stdin --plan .\ru-ethernet.json --outdir .\artifacts --history .\artifacts\history.sqlite
   Remove-Variable uri

5. Capture a network-only snapshot, including the test-node passport:

   .\LokiTrafficLab.exe snapshot --plan .\ru-ethernet.json --outdir .\artifacts

6. Compare reports from two PCs:

   .\LokiTrafficLab.exe compare .\report-local.json .\report-ru.json

7. Import and list historical reports:

   .\LokiTrafficLab.exe history import .\artifacts --db .\artifacts\history.sqlite
   .\LokiTrafficLab.exe history list --db .\artifacts\history.sqlite

8. Build a cross-node/network/scenario matrix:

   .\LokiTrafficLab.exe matrix .\artifacts

9. Observe a real application's sockets and route/TUN state:

   .\LokiTrafficLab.exe observe --process app-name --proxy-port 18091 --duration 30

10. Run a controlled collector on an authorized reachable host:

   .\LokiTrafficLab.exe collector --bind 0.0.0.0 --http-port 18080 --udp-port 18081 --dns-port 53 --dns-answer YOUR_PUBLIC_IP

11. Optional elevated packet capture (never enabled by normal tests):

   .\LokiTrafficLab.exe capture --duration 30 --outdir .\artifacts --i-understand

The application never stores the raw URI, UUID, REALITY public key, short ID,
or subscription URL in its JSON, CSV, comparison, or SQLite reports.

Each run creates a compact traffic-lab-results-*.zip. The Save button copies it
asynchronously to the current Windows Downloads known folder, never overwrites
an existing export, and does not invoke the Windows Shell file dialog. A
one-connection archive
contains connection.json, local-machine.json, osi-map.md and README.txt at its
root. A multi-connection archive has one ordered, safely named folder per
connection, with those same four files inside. Probability percentages in JSON
are heuristic evidence weights and are not calibrated statistical probabilities.
A SPEED run instead creates traffic-lab-speed-results-*.zip with exactly
speed.json and readme.txt at the archive root, including multiple connections.

The extended run also records the test PC's public/local IPs, access type,
provider/geolocation hints, direct speed, NAT/CGNAT evidence, gateway/router
metadata, Wi-Fi/cellular hints and additional proxy/DNS/route settings. It
builds a per-profile evidence map across all seven OSI layers.

Packet capture is deliberately opt-in and is not started by normal run or
snapshot commands. Network probes are bounded and the plan can restrict target
hosts with repeated --allow-host options.
