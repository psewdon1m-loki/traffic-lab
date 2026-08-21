LOKI TRAFFIC LAB - ANDROID APK
================================

This folder contains the native Android adaptation of Traffic Lab. The APK uses
the same result contract as Windows/Linux: four files per tested connection in
normal mode and a fifth, separate extended-test.json in extended mode, ordered
named folders for multiple connections, explicit facts versus bounded
inferences, and no raw URI/UUID/REALITY credential in reports.

SUPPORTED DEVICES
-----------------

- Android 8.0 / API 26 or newer;
- arm64-v8a physical phones and x86_64 emulators;
- Wi-Fi, cellular, Ethernet, USB/Bluetooth tethering and other Android networks.

BUILD
-----

From PowerShell at the traffic-lab root:

  & '.\Apk\build-apk.ps1'

The first build downloads a local Android command-line SDK, Gradle 8.9 and the
pinned official Xray Android binaries, verifies Xray's published SHA2-256
digests, runs JVM unit tests and Android lint, and builds a debug-signed APK.
Nothing is installed system-wide. Output:

  Apk\releases\LokiTrafficLab-android-3.6.0.apk

For emulator tooling and the smaller base API 35 x86_64 system image:

  & '.\Apk\build-apk.ps1' -InstallEmulator

DEVICE WORKFLOW
---------------

1. Copy one or several VLESS links as ordinary text.
2. Tap `Paste links from clipboard`. The parser finds every vless:// occurrence,
   normalizes raw spaces in display names and preserves input order/duplicates.
3. Tap `Start test` for the normal suite, use `Extended test`
   command for the normal suite plus long-running and process-disruptive checks.
   `Speed test` runs only speed-relevant endpoint/authentication prerequisites
   and direct/tunnel/direct download-upload matrices; it warns about potentially
   substantial mobile-data use before starting.
   Extended mode asks for confirmation before it starts. If Android reports an
   active VPN transport, Traffic Lab blocks the baseline and opens VPN settings
   so it can be disabled first.
4. The foreground test service shows percent, connection count, elapsed time,
   approximate ETA and the current stage. `Stop test` is emergency cancellation.
5. Only after completion, a `Result export` block appears in the main screen
   with run metadata. Use `Save ZIP` for Android's system document picker or
   `Share ZIP` for the system Sharesheet (messengers, mail, storage providers).
   The block remains available for repeated exports until a new test starts or
   `Clear connections` deletes the temporary result.
6. `Clear connections` removes the visible list and deletes the temporary ZIP.

The result ZIP is created only below the app's private cache. It is never copied
to Downloads/shared storage automatically. Save and Share grant access only to
the exact completed ZIP. A new run or Clear removes the previous cache result.
The Activity uses Android FLAG_SECURE and excludes the connection field from
autofill/state saving so pasted credentials are not captured in screenshots,
recent-app thumbnails or normal view-state restoration.

TEST COVERAGE
-------------

Implemented connection stages include URI parsing/redaction, Android/system DNS,
Google/Cloudflare DoH, direct UDP DNS, resolver comparison, repeated TCP,
TLS/REALITY fallback and SNI/certificate/SPKI matrix, plain WebSocket upgrade,
RIPEstat ASN/BGP and IP-geolocation hints, Android ping-TTL path evidence,
embedded Xray validation/start, authenticated HTTP, exit-IP comparison, SOCKS
remote-domain DNS, discarded warm-up plus robust calibration and bounded-window download/upload
measurement samples and payload matrix, stability, real
SOCKS5 UDP DNS, tunneled STUN mapping, invalid UUID/shortId/SNI controls, explicit XUDP A/B testing,
classified core logs, shared-backend grouping, infrastructure signals and OSI mapping.

Normal throughput discards a warm-up, uses repeated calibration and synchronized
workers, and records robust window and batch-completion rates separately.
A failed sample, straggler or high variation is retained instead of being hidden
behind a single Mbps number.
Upload payload is generated as an incompressible stream through a 64 KiB buffer,
so larger adaptive samples do not allocate a same-sized byte array. SPEED and
extended matrices add 1/4/16 simultaneous flows, idle/loaded latency,
p10/median/p90, coefficient of variation, byte-cap flags and matched direct
controls in an ABBA Direct-Tunnel-Tunnel-Direct sequence with the same workload
plan. Client CPU/heap context is retained. Same-flow drift above 15%, stragglers,
endpoint instability and concurrency collapse lower confidence. Only SPEED shows
the final Download/Upload result in the Android interface.
Android uses payload-transfer duration separately from cold total duration and
normalizes public Cloudflare request sizes away from rejected ranges. HTTP
403/429 is retained as ENDPOINT_REQUEST_REJECTED/ENDPOINT_RATE_LIMITED and is
not treated as proof of a proxy fault.
Separate Cloudflare and OVH SBG/RBX/BHS 1 MiB controls expose endpoint/peering
bias without averaging geographically different paths into the primary result.
Completed uploads use full server-acknowledged request duration and are labelled
UPLOAD_ACK_BOUNDED_ESTIMATE (at most medium confidence without server timing).

The Xray log classifier labels readiness EOF, completed UDP-association teardown
and loopback broken-pipe/reset caused by a completed or timed-out app probe as
expected/benign. Other failure markers remain unexpected and make tunnel.logs
PARTIAL with the exact redacted evidence in data.logAnalysis.

Extended mode additionally records the parallel speed matrix, 6 cold and 6 warm HTTP observations, 20
parallel TCP flows, 20 independent SOCKS5 UDP associations, tunneled DNS
failure/recovery using a unique reserved .invalid name, a five-minute
application latency/jitter/loss soak, forced Xray reconnect and a five-second
controlled interruption. The interruption stops only this app's isolated Xray
child process. It never disables Wi-Fi/LTE, changes Android routes or affects
other applications. Extended stages and their limitations are written only to
extended-test.json; every result file and README identify the NORMAL or
EXTENDED mode, Android release/API level and APK version. SPEED archives always
contain exactly speed.json and readme.txt at the ZIP root; speed.json stores all
connections in their original order.

Android-specific local-machine evidence includes:

- active NetworkCapabilities transports, validation, captive portal, metered,
  roaming, Data Saver and estimated link bandwidth;
- LinkProperties interface, addresses/prefixes, routes/gateways, MTU, DNS,
  Private DNS, NAT64 and HTTP proxy/PAC;
- Wi-Fi standard, frequency, RSSI, signal level and negotiated RX/TX rates;
- LTE/NR/data/voice network type, carrier/SIM summaries and signal levels;
- Android/device/API/security-patch/kernel/ABI, battery saver, idle and airplane
  modes, direct IP/provider/geolocation/performance, STUN and NAT evidence;
- an Android OS device-location fix (coordinates, accuracy, provider, age and
  mock flag) when the user grants location permission, plus distance from the
  low-confidence public-IP location hint.

SSID/BSSID/MAC are hashed. Phone number, IMSI, ICCID, precise cell identity and
cell-tower identity are not collected. Device coordinates are sensitive and are
included only when Android grants the runtime location permission. Permission
denial is recorded and does not abort the test.

Every stage keeps the compatibility status field and also records a causal
outcome, reasonCode and explanation. Profile/run outcomes are PASS, PROXY_FAIL,
UNDERLAY_FAIL, TEST_FAILURE or UNKNOWN. A reachable direct control followed by
endpoint TCP failure is PROXY_FAIL/ENDPOINT_TCP_UNREACHABLE; reachable endpoint TCP
followed by failed authenticated traffic is PROXY_FAIL/PROTOCOL_AUTH_FAIL.
Endpoint DNS failure is ENDPOINT_DNS_UNRESOLVED. Downstream TLS/auth/exit/DNS,
UDP, QUIC and payload stages are SKIPPED/DEPENDENCY_NOT_MET and retain the root
stage/code instead of being reported as independent failures. Negative controls
that do not apply to the profile are SKIP/CONTROL_NOT_APPLICABLE.

Schema 1.1 includes profile/stage UTC timing and a per-profile correlation ID
sent on authenticated HTTP controls. Without an authorized server log the
server-correlation state remains client-generated/unconfirmed.

COVERAGE ESTIMATE
-----------------

Against the 37 per-profile Windows stage families, Android implements 32 fully
and exposes 3 as explicit platform limitations: 35/37, or about 95% functional
or honestly classified coverage. Path-MTU, per-hop route attribution and
negotiated HTTP-version evidence are SKIPPED/UNSUPPORTED_ON_PLATFORM rather than
being misreported as degraded connections. The two remaining capability gaps are the
optional controlled-collector UI and a native QUIC handshake engine. This
comparison excludes Windows-only utilities such as pktmon capture, history DB
commands and the standalone collector service, and excludes Android-only node
evidence.

Acceptance tests cover canonical cross-platform profile fingerprints, causal
outcomes, benign Xray lifecycle/deprecation markers, result contracts and the
normal/extended package split. Negative-control applicability is explicit:
UUID is always tested, while short-ID and SNI mutations require corresponding
REALITY parameters. Emulator/device runs still remain necessary for
real radio, location, VPN and end-to-end profile behavior.

KNOWN GAPS
----------

Android does not offer reliable unprivileged DF/ICMP path-MTU or full traceroute
on every vendor build. The ping TTL parser only accepts responder lines and
rejects a destination reported as ttl-expired or the same ttl-expired responder
for three consecutive hops as TEST_FAILURE/INVALID_TRACEROUTE_OUTPUT. This APK
also does not embed a second native QUIC engine,
so QUIC is reported as unavailable while real UDP and XUDP remain tested.
The APK deliberately uses explicit app-local proxies and does not create a
VpnService/TUN, so it tests the supplied profiles rather than device-wide split
or full-tunnel policy. Exact REALITY target, hidden server hops/routing, panel
HWID policy and private load-balancer topology remain server-side facts.

SECURITY AND DEPENDENCIES
-------------------------

The device needs no .NET, Xray, curl, dig, whois, OpenSSL or root installation.
Xray for both supported ABIs is packaged in the APK and executed only from the
package manager's native-library directory. Inbounds bind to 127.0.0.1. Tests
contact the configured endpoint plus public DNS/DoH, RIPEstat, IP attribution,
STUN, exit-IP and bounded HTTP speed targets. The foreground service is started
only by the user and does not register a boot receiver.
