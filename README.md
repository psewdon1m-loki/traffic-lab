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
`%LOCALAPPDATA%\LokiClient\logs\xray-access.log` grew during the probe.

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
