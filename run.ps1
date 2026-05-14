param(
    [int]$HttpPort = 18089,
    [int]$SocksPort = 18088,
    [string[]]$Targets = @(
        "https://api.ipify.org?format=json",
        "https://www.google.com/generate_204",
        "https://github.com",
        "https://telegram.org",
        "https://api.telegram.org",
        "https://ya.ru",
        "https://ozon.ru"
    ),
    [string[]]$Profiles = @(
        "native-direct",
        "native-system",
        "native-explicit",
        "curl-direct",
        "curl-env",
        "node-direct",
        "node-env",
        "browser-direct",
        "browser-system",
        "browser-explicit"
    ),
    [int]$TimeoutSeconds = 20,
    [string]$BrowserPath = "",
    [string]$XrayAccessLog = "$env:LOCALAPPDATA\LokiClient\logs\xray-access.log",
    [string]$OutputDirectory = "traffic-lab\artifacts"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http

$repoRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $repoRoot $OutputDirectory
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

function Get-FileLengthOrZero {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        return (Get-Item -LiteralPath $Path).Length
    }

    return 0
}

function Find-Browser {
    if (-not [string]::IsNullOrWhiteSpace($BrowserPath) -and (Test-Path -LiteralPath $BrowserPath)) {
        return $BrowserPath
    }

    $commands = @("msedge.exe", "chrome.exe")
    foreach ($name in $commands) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }

    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    return $null
}

function Get-ProxySnapshot {
    $internetSettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    $winHttp = try { netsh winhttp show proxy 2>$null | Out-String } catch { "" }
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @($HttpPort, $SocksPort) } |
        Select-Object LocalAddress, LocalPort, OwningProcess

    [ordered]@{
        capturedAt = (Get-Date).ToUniversalTime().ToString("o")
        ports = [ordered]@{
            http = $HttpPort
            socks = $SocksPort
        }
        winInet = [ordered]@{
            proxyEnable = $internetSettings.ProxyEnable
            proxyServer = $internetSettings.ProxyServer
            proxyOverride = $internetSettings.ProxyOverride
            autoConfigUrl = $internetSettings.AutoConfigURL
        }
        winHttp = ($winHttp -replace "`r", "").Trim()
        userEnvironment = [ordered]@{
            HTTP_PROXY = [Environment]::GetEnvironmentVariable("HTTP_PROXY", "User")
            HTTPS_PROXY = [Environment]::GetEnvironmentVariable("HTTPS_PROXY", "User")
            ALL_PROXY = [Environment]::GetEnvironmentVariable("ALL_PROXY", "User")
            NO_PROXY = [Environment]::GetEnvironmentVariable("NO_PROXY", "User")
        }
        processEnvironment = [ordered]@{
            HTTP_PROXY = [Environment]::GetEnvironmentVariable("HTTP_PROXY", "Process")
            HTTPS_PROXY = [Environment]::GetEnvironmentVariable("HTTPS_PROXY", "Process")
            ALL_PROXY = [Environment]::GetEnvironmentVariable("ALL_PROXY", "Process")
            NO_PROXY = [Environment]::GetEnvironmentVariable("NO_PROXY", "Process")
        }
        listeners = @($listeners)
        browserPath = Find-Browser
    }
}

function New-Result {
    param(
        [string]$Profile,
        [string]$Family,
        [string]$Target,
        [bool]$Ok,
        [Nullable[int]]$StatusCode,
        [long]$ElapsedMs,
        [string]$BodySample,
        [string]$Error,
        [long]$BeforeLogLength,
        [long]$AfterLogLength,
        [bool]$Skipped = $false
    )

    $delta = [Math]::Max(0, $AfterLogLength - $BeforeLogLength)
    [ordered]@{
        profile = $Profile
        family = $Family
        target = $Target
        skipped = $Skipped
        ok = $Ok
        statusCode = $StatusCode
        elapsedMs = $ElapsedMs
        xrayAccessLogBytesDelta = $delta
        likelyReachedXray = $delta -gt 0
        bodySample = $BodySample
        error = $Error
    }
}

function Invoke-NativeProbe {
    param([string]$Profile, [string]$Target)

    $handler = [System.Net.Http.HttpClientHandler]::new()
    if ($Profile -eq "native-direct") {
        $handler.UseProxy = $false
    }
    elseif ($Profile -eq "native-explicit") {
        $handler.UseProxy = $true
        $handler.Proxy = [System.Net.WebProxy]::new("http://127.0.0.1:$HttpPort")
    }
    else {
        $handler.UseProxy = $true
    }

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $response = $client.GetAsync($Target).GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $sw.Stop()
        return @{
            ok = $true
            statusCode = [int]$response.StatusCode
            elapsedMs = $sw.ElapsedMilliseconds
            bodySample = ($body -replace "\s+", " ").Substring(0, [Math]::Min(240, ($body -replace "\s+", " ").Length))
            error = $null
        }
    }
    catch {
        $sw.Stop()
        return @{
            ok = $false
            statusCode = $null
            elapsedMs = $sw.ElapsedMilliseconds
            bodySample = ""
            error = $_.Exception.Message
        }
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function Invoke-CurlProbe {
    param([string]$Profile, [string]$Target)

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        return @{ skipped = $true; ok = $false; statusCode = $null; elapsedMs = 0; bodySample = ""; error = "curl.exe not found" }
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $curl.Source
    $extra = if ($Profile -eq "curl-direct") { "--noproxy `"*`"" } else { "" }
    $psi.Arguments = "-L --max-time $TimeoutSeconds -s -S $extra -o NUL -w `"http_code=%{http_code} remote_ip=%{remote_ip} time_total=%{time_total}`" `"$Target`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    if ($Profile -eq "curl-env") {
        $psi.Environment["HTTP_PROXY"] = "http://127.0.0.1:$HttpPort"
        $psi.Environment["HTTPS_PROXY"] = "http://127.0.0.1:$HttpPort"
        $psi.Environment["ALL_PROXY"] = "http://127.0.0.1:$HttpPort"
        $psi.Environment["NO_PROXY"] = "localhost,127.*"
    }
    elseif ($Profile -eq "curl-direct") {
        foreach ($name in @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")) {
            $psi.Environment.Remove($name) | Out-Null
        }
    }

    return Invoke-ProcessProbe -ProcessStartInfo $psi
}

function Invoke-NodeProbe {
    param([string]$Profile, [string]$Target)

    $node = Get-Command node.exe -ErrorAction SilentlyContinue
    if (-not $node) {
        return @{ skipped = $true; ok = $false; statusCode = $null; elapsedMs = 0; bodySample = ""; error = "node.exe not found" }
    }

    $script = Join-Path $PSScriptRoot "node-fetch-probe.js"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $node.Source
    $psi.Arguments = "`"$script`" `"$Target`" $($TimeoutSeconds * 1000)"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    if ($Profile -eq "node-env") {
        $psi.Environment["HTTP_PROXY"] = "http://127.0.0.1:$HttpPort"
        $psi.Environment["HTTPS_PROXY"] = "http://127.0.0.1:$HttpPort"
        $psi.Environment["ALL_PROXY"] = "http://127.0.0.1:$HttpPort"
        $psi.Environment["NO_PROXY"] = "localhost,127.*"
    }
    else {
        foreach ($name in @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")) {
            $psi.Environment.Remove($name) | Out-Null
        }
    }

    $raw = Invoke-ProcessProbe -ProcessStartInfo $psi
    try {
        $parsed = $raw.bodySample | ConvertFrom-Json
        return @{
            skipped = $false
            ok = [bool]$parsed.ok
            statusCode = $parsed.statusCode
            elapsedMs = $parsed.elapsedMs
            bodySample = $parsed.bodySample
            error = $parsed.error
        }
    }
    catch {
        return $raw
    }
}

function Invoke-BrowserProbe {
    param([string]$Profile, [string]$Target)

    $browser = Find-Browser
    if (-not $browser) {
        return @{ skipped = $true; ok = $false; statusCode = $null; elapsedMs = 0; bodySample = ""; error = "Edge/Chrome not found" }
    }

    $profileDir = Join-Path ([System.IO.Path]::GetTempPath()) ("loki-browser-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
    $proxyArg = switch ($Profile) {
        "browser-direct" { "--no-proxy-server" }
        "browser-explicit" { "--proxy-server=http://127.0.0.1:$HttpPort" }
        default { "" }
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $browser
    $psi.Arguments = "--headless=new --disable-gpu --disable-background-networking --disable-extensions --user-data-dir=`"$profileDir`" $proxyArg --dump-dom `"$Target`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    try {
        return Invoke-ProcessProbe -ProcessStartInfo $psi
    }
    finally {
        Remove-Item -LiteralPath $profileDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-ProcessProbe {
    param([System.Diagnostics.ProcessStartInfo]$ProcessStartInfo)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $process = [System.Diagnostics.Process]::Start($ProcessStartInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $completed = $process.WaitForExit(($TimeoutSeconds + 8) * 1000)
    $sw.Stop()

    if (-not $completed) {
        try { $process.Kill($true) } catch {}
        return @{ skipped = $false; ok = $false; statusCode = $null; elapsedMs = $sw.ElapsedMilliseconds; bodySample = ""; error = "process timeout" }
    }

    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()

    $statusCode = $null
    if ($stdout -match "http_code=(\d+)") {
        $statusCode = [int]$Matches[1]
    }

    $sample = ($stdout -replace "\s+", " ").Trim()
    if ($sample.Length -gt 240) {
        $sample = $sample.Substring(0, 240)
    }

    return @{
        skipped = $false
        ok = $process.ExitCode -eq 0
        statusCode = $statusCode
        elapsedMs = $sw.ElapsedMilliseconds
        bodySample = $sample
        error = if ($process.ExitCode -eq 0) { $null } else { ($stderr -replace "\s+", " ").Trim() }
    }
}

function Invoke-LabProbe {
    param([string]$Profile, [string]$Target)

    $beforeLogLength = Get-FileLengthOrZero -Path $XrayAccessLog
    Start-Sleep -Milliseconds 100

    $family = if ($Profile.StartsWith("native-")) {
        "native-desktop"
    } elseif ($Profile.StartsWith("curl-")) {
        "cli-env"
    } elseif ($Profile.StartsWith("node-")) {
        "node-electron-class"
    } elseif ($Profile.StartsWith("browser-")) {
        "web-browser"
    } else {
        "unknown"
    }

    $probe = if ($Profile.StartsWith("native-")) {
        Invoke-NativeProbe -Profile $Profile -Target $Target
    } elseif ($Profile.StartsWith("curl-")) {
        Invoke-CurlProbe -Profile $Profile -Target $Target
    } elseif ($Profile.StartsWith("node-")) {
        Invoke-NodeProbe -Profile $Profile -Target $Target
    } elseif ($Profile.StartsWith("browser-")) {
        Invoke-BrowserProbe -Profile $Profile -Target $Target
    } else {
        @{ skipped = $true; ok = $false; statusCode = $null; elapsedMs = 0; bodySample = ""; error = "unknown profile" }
    }

    Start-Sleep -Milliseconds 300
    $afterLogLength = Get-FileLengthOrZero -Path $XrayAccessLog

    New-Result `
        -Profile $Profile `
        -Family $family `
        -Target $Target `
        -Ok ([bool]$probe.ok) `
        -StatusCode $probe.statusCode `
        -ElapsedMs ([long]$probe.elapsedMs) `
        -BodySample ([string]$probe.bodySample) `
        -Error ([string]$probe.error) `
        -BeforeLogLength $beforeLogLength `
        -AfterLogLength $afterLogLength `
        -Skipped ([bool]$probe.skipped)
}

$snapshot = Get-ProxySnapshot
$results = New-Object System.Collections.Generic.List[object]

foreach ($target in $Targets) {
    foreach ($profile in $Profiles) {
        Write-Host "[$profile] $target"
        $results.Add([pscustomobject](Invoke-LabProbe -Profile $profile -Target $target))
    }
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$resultItems = $results.ToArray()
$report = [ordered]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString("o")
    note = "direct profiles should not touch Xray. explicit/env/system profiles should touch Xray when the app class honors that proxy mechanism and Loki is connected."
    xrayAccessLog = $XrayAccessLog
    proxySnapshot = $snapshot
    results = $resultItems
}

$jsonPath = Join-Path $outputPath "traffic-lab-$stamp.json"
$csvPath = Join-Path $outputPath "traffic-lab-$stamp.csv"
$report | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Traffic lab report:"
Write-Host $jsonPath
Write-Host $csvPath
Write-Host ""
$results |
    Select-Object profile, family, target, skipped, ok, statusCode, elapsedMs, likelyReachedXray, xrayAccessLogBytesDelta |
    Format-Table -AutoSize
