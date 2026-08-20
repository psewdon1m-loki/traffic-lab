LOKI TRAFFIC LAB 3.5.0 - UBUNTU / LINUX
=======================================

This directory contains the headless Linux adaptation of Traffic Lab. Ubuntu
24.04/22.04 x64 is the primary target. The application is self-contained and
does not require a separately installed .NET runtime.

INSTALL
-------

From a local checkout/release directory:

  sudo bash ./Linux/bootstrap.sh --archive ./Linux/releases/LokiTrafficLab-linux-x64-3.5.0.tar.gz

For a hosted release, bootstrap also supports a one-line installation:

  curl -fsSL https://YOUR-HOST/bootstrap.sh -o /tmp/tlab-bootstrap.sh && echo 'BOOTSTRAP_SHA256  /tmp/tlab-bootstrap.sh' | sha256sum -c - && sudo bash /tmp/tlab-bootstrap.sh --url https://YOUR-HOST/LokiTrafficLab-linux-x64-3.5.0.tar.gz

The installer requires and verifies the archive SHA-256 sidecar, installs
versioned files below /opt/tlab, creates /usr/local/bin/tlab, initializes a
private per-user connections file and installs the small Ubuntu runtime set
(certificates, libnuma, iproute2, ping, traceroute and iw). The self-contained
runner uses invariant globalization and does not require system ICU. It never
disables or flushes UFW.

CONFIGURATION
-------------

Put one VLESS URI per active line in:

  ~/.config/tlab/connections.txt

The file is created with mode 0600. Blank lines and lines beginning with #, ;
or // are ignored. Treat this file as a password.

COMMANDS
--------

  tlab start
  tlab start --detach
  tlab start --port 18080
  tlab extended --port 18080
  tlab extended --port 18080 --soak-seconds 300 --parallel-flows 20
  tlab speed --port 18080
  tlab status
  tlab logs --follow
  tlab stop
  tlab raw snapshot --outdir ./snapshot
  sudo tlab raw capture --duration 30 --i-understand --outdir ./capture

`tlab start` runs the normal suite. `tlab speed` runs only speed-relevant
endpoint/authentication prerequisites plus matched direct-before, tunnel and
direct-after download/upload matrices with 1, 4 and 16 flows. Its ZIP contains
exactly speed.json and readme.txt. `tlab extended` is the separate command for
the long/disruptive suite: cold versus warm connections, 10-100 parallel
TCP/UDP flows, DNS failure/recovery, a 5-15 minute latency/jitter/loss soak,
forced Xray restart/reconnect and a controlled pause/recovery of only the Xray
process created by the current profile. Both commands ask for a local test port
unless --port is provided. They stay attached by default, keep one progress bar
on the current terminal line and print test type, connection count, total
duration and the result ZIP path when complete.
The process exits on its own after all connections are tested. `--detach` is an
explicit alternative for unattended operation. The selected port is bound only
to 127.0.0.1 and is used as Xray's HTTP inbound. UFW remains enabled and
unchanged; no public listening socket is created. The test runs in a dedicated
process group, so `tlab stop` is only an emergency early-stop command and
terminates only Traffic Lab and the Xray instance it started.

Results are written to ~/.local/share/tlab/results by default. A normal run has
four files per connection: connection.json, local-machine.json, osi-map.md and
README.txt. An extended run adds a fifth, separate extended-test.json containing
only long/disruptive stages, core-log classification and throughput correlation.
README.txt and JSON run metadata explicitly identify NORMAL, EXTENDED or SPEED.
Multiple connections receive ordered, named folders inside the archive.
A SPEED archive is run-level and always keeps its two files at the ZIP root;
speed.json contains the ordered per-connection results.

Speed measurements discard warm-up/calibration, synchronize workers and retain
bounded-window plus batch-completion observations, p10/median/p90, variation,
byte-cap flags, loaded latency and client load. EXTENDED and SPEED use the same
1/4/16-flow plan in an ABBA Direct-Tunnel-Tunnel-Direct sequence. Same-flow drift
above 15%, stragglers, concurrency collapse or endpoint instability lower
confidence. `tlab speed` prints the final Download/Upload values before the ZIP
path. Its theoretical cap is about 3.5 GiB per profile; typical use is lower.
The bounded clock starts at the first payload byte, separating cold setup from
sustained transfer. HTTP 403/429 from the public speed edge is retained as
ENDPOINT_REQUEST_REJECTED/ENDPOINT_RATE_LIMITED rather than blamed on the proxy.
Separate Cloudflare and OVH SBG/RBX/BHS 1 MiB controls expose endpoint/peering
bias without averaging geographically different paths into the primary result.
Completed uploads use full server-acknowledged request duration and are labelled
UPLOAD_ACK_BOUNDED_ESTIMATE (at most medium confidence without server timing).

Traffic Lab 3.5.0 preserves status for compatibility and adds outcome,
reasonCode and a human-readable reason to every stage, profile and run. The
causal classes are PASS, PROXY_FAIL, UNDERLAY_FAIL, TEST_FAILURE and UNKNOWN;
PROXY_PATH_FAIL and PROTOCOL_AUTH_FAIL distinguish endpoint reachability from
authentication/protocol failure.

The metadata records platform=linux, the Linux distribution from
/etc/os-release (for example Ubuntu 24.04 LTS), kernel/OS version, CPU
architecture, runtime and time zone. These fields are also present in
local-machine.json; platform and OS are repeated in connection.json and
extended-test.json so files remain attributable when extracted separately.
Coordinates supplied by --latitude/--longitude or the test plan are recorded as
device location. If a system GeoClue `where-am-i` helper is already available
and authorized, Traffic Lab also attempts to read it. This helper is optional,
not an installation dependency; without it the report retains the separate
low-confidence public-IP geolocation hint.

LINUX-SPECIFIC EVIDENCE
-----------------------

The Linux build retains the shared DNS, TCP, TLS/REALITY, VLESS, exit-IP,
ASN/RDAP/BGP, geolocation, UDP/XUDP, STUN, QUIC, performance, inference and OSI
tests. Linux additions use iproute2 for routes/socket evidence, traceroute for
path evidence, iw for Wi-Fi, optional mmcli for cellular modems, /etc/hosts,
ip-neighbour evidence for the gateway, read-only UFW status collection and an
explicit opt-in tcpdump capture capped at 50,000 packets. Packet captures are
never included in normal result ZIPs.

The extended controlled-interruption stage uses SIGSTOP/SIGCONT on only the
Xray child process started by Traffic Lab. It requires no firewall mutation,
does not change UFW, routes or interfaces, and resumes Xray from a finally block
before testing recovery. `tlab stop` remains the emergency process-group kill.

PARITY WITH WINDOWS
-------------------

All shared connection/protocol stages are built from the same C# source and are
available on Linux (100% stage parity). Packaging, four-file reports, history,
matrix, compare, collector, observation and bounded packet capture also have a
Linux path. An audit of the complete tester, including host introspection, gives
approximately 92% practical parity with Windows. The remaining approximately
8% is Windows-only metadata: Registry/WinHTTP/PAC proxy state, exact netsh WLAN
and MBN fields, and a few Windows adapter DHCP/dynamic-DNS flags. The GUI and
the active-proxy preflight are intentionally excluded from Linux by design.

RUNTIME REQUIREMENTS
--------------------

The release embeds the .NET runtime, application libraries, Xray and libmsquic.
After bootstrap, `tlab start` does not download packages and does not require a
separate dotnet, xray, curl, dig, whois, OpenSSL or Node.js installation.

Bootstrap is still an installation step: on Ubuntu it installs missing standard
OS packages for certificates/NUMA plus iproute2, ping, traceroute, iw,
tcpdump and util-linux. Network measurements also necessarily contact external
DNS/DoH, RDAP/BGP, geolocation, STUN, exit-IP and HTTP test endpoints. If one of
those services is blocked, its stage is reported as failed/partial/skipped; it
is not treated as a missing local program. `mmcli` is optional and is used only
when it already exists for future cellular-modem metadata. Normal testing needs
no root access; only the explicitly requested tcpdump capture does.

BUILD
-----

From PowerShell at the repository root:

  & '.\traffic-lab\Linux\build-linux.ps1' -RuntimeIdentifier linux-x64 -OutputDirectory 'Linux\releases\3.5.0' -Archive

Generated releases are placed in Linux/releases. Shared C# logic remains in
traffic-lab/src; this folder contains only Linux packaging, runtime assets and
releases.

The tag-triggered GitHub Release includes INSTALL-LINUX.txt with a complete
one-command installer containing the exact bootstrap SHA-256 for that release.

LIMITATIONS
-----------

Docker hides the host's physical adapter, router and UFW state, so container
tests validate Linux compatibility and packaging but cannot represent a real
Ubuntu PC's L1/L2 observations. Exact REALITY target, server routing, panel HWID
state and hidden relay topology remain server-side and are reported as
probabilistic client-side inferences.
