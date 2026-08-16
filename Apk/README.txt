LOKI TRAFFIC LAB - ANDROID APK
================================

This folder contains the native Android adaptation of Traffic Lab. The APK uses
the same result contract as Windows/Linux: four files per tested connection,
ordered named folders for multiple connections, explicit facts versus bounded
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

  Apk\releases\LokiTrafficLab-android-3.1.2.apk

For emulator tooling and the smaller base API 35 x86_64 system image:

  & '.\Apk\build-apk.ps1' -InstallEmulator

DEVICE WORKFLOW
---------------

1. Copy one or several VLESS links as ordinary text.
2. Tap `Paste links from clipboard`. The parser finds every vless:// occurrence,
   normalizes raw spaces in display names and preserves input order/duplicates.
3. Tap `Start test`. If Android reports an active VPN transport, Traffic Lab
   blocks the baseline and opens VPN settings so it can be disabled first.
4. The foreground test service shows percent, connection count, elapsed time,
   approximate ETA and the current stage. `Stop test` is emergency cancellation.
5. When complete, use `Save ZIP` for Android's system document picker or
   `Share ZIP` for the system Sharesheet (messengers, mail, storage providers).
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
remote-domain DNS, bounded download/upload and payload matrix, stability, real
SOCKS5 UDP DNS, tunneled STUN mapping, invalid UUID/shortId/SNI controls, explicit XUDP A/B testing,
core logs, shared-backend grouping, infrastructure signals and OSI mapping.

Android-specific local-machine evidence includes:

- active NetworkCapabilities transports, validation, captive portal, metered,
  roaming, Data Saver and estimated link bandwidth;
- LinkProperties interface, addresses/prefixes, routes/gateways, MTU, DNS,
  Private DNS, NAT64 and HTTP proxy/PAC;
- Wi-Fi standard, frequency, RSSI, signal level and negotiated RX/TX rates;
- LTE/NR/data/voice network type, carrier/SIM summaries and signal levels;
- Android/device/API/security-patch/kernel/ABI, battery saver, idle and airplane
  modes, direct IP/provider/geolocation/performance, STUN and NAT evidence.

SSID/BSSID/MAC are hashed. Phone number, IMSI, ICCID, precise cell identity and
GPS location are not collected. Permission denial reduces only Wi-Fi/cellular
detail and is recorded rather than aborting the test.

COVERAGE ESTIMATE
-----------------

Against the 37 per-profile Windows stage families, Android implements 32 fully
and 3 with an explicit partial result: 35/37, or about 95% functional/partial
coverage. The partial families are path-MTU, per-hop route attribution and
negotiated HTTP-version evidence. The two remaining capability gaps are the
optional controlled-collector UI and a native QUIC handshake engine. This
comparison excludes Windows-only utilities such as pktmon capture, history DB
commands and the standalone collector service, and excludes Android-only node
evidence.

The API 35 x86_64 emulator acceptance run with the supplied REALITY profile
produced 31 passed, 3 partial, 0 failed and 3 skipped stages. The skipped plain
WebSocket stage was not applicable to that TCP profile; controlled canary and
QUIC were unavailable. A two-profile sequential run produced two ordered ZIP
folders with exactly four result files in each. Both archives were scanned to
confirm that the supplied UUID was absent.

KNOWN GAPS
----------

Android does not offer reliable unprivileged DF/ICMP path-MTU or full traceroute
on every vendor build. This APK also does not embed a second native QUIC engine,
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
