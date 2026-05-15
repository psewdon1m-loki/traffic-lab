param(
    [string[]]$ProcessName = @("steam", "steamwebhelper"),
    [string[]]$ExpectedHosts = @(),
    [int]$ProxyPort = 18091,
    [int]$RecentLogLines = 250,
    [string]$XrayAccessLog = "$env:LOCALAPPDATA\LokiClient\logs\xray-access.log",
    [string]$OutputDirectory = "traffic-lab\artifacts"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $repoRoot $OutputDirectory
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

$processes = foreach ($name in $ProcessName) {
    Get-Process -Name $name -ErrorAction SilentlyContinue
}

$processIds = @($processes | Select-Object -ExpandProperty Id)
$connections = @()
if ($processIds.Count -gt 0) {
    $connections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -in $processIds } |
        Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
            @{Name = "ProcessName"; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }},
            @{Name = "UsesExpectedProxy"; Expression = { $_.RemoteAddress -in @("127.0.0.1", "::1") -and $_.RemotePort -eq $ProxyPort }} |
        Sort-Object ProcessName, RemoteAddress, RemotePort, LocalPort)
}

$xrayLines = @()
if (Test-Path -LiteralPath $XrayAccessLog) {
    $xrayLines = @(Get-Content -LiteralPath $XrayAccessLog -Tail $RecentLogLines)
}

$hostMatches = foreach ($hostName in $ExpectedHosts) {
    $matchingLines = @($xrayLines | Where-Object { $_ -like "*$hostName*" })
    [ordered]@{
        host = $hostName
        matched = $matchingLines.Count -gt 0
        lines = $matchingLines
    }
}

$proxyConnectionCount = @($connections | Where-Object { $_.UsesExpectedProxy }).Count
$externalConnectionCount = @($connections | Where-Object {
    $_.RemoteAddress -notin @("0.0.0.0", "::", "127.0.0.1", "::1") -and $_.State -eq "Established"
}).Count

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$report = [ordered]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString("o")
    processNames = $ProcessName
    expectedProxyPort = $ProxyPort
    xrayAccessLog = $XrayAccessLog
    processes = @($processes | Select-Object ProcessName, Id, Path, StartTime)
    summary = [ordered]@{
        processCount = $processIds.Count
        connectionCount = $connections.Count
        proxyConnectionCount = $proxyConnectionCount
        externalEstablishedConnectionCount = $externalConnectionCount
    }
    connections = $connections
    expectedHostMatches = @($hostMatches)
}

$jsonPath = Join-Path $outputPath "observe-app-$stamp.json"
$csvPath = Join-Path $outputPath "observe-app-$stamp.csv"
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$connections | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "App observation report:"
Write-Host $jsonPath
Write-Host $csvPath
Write-Host ""
Write-Host "Processes: $($processIds.Count)"
Write-Host "Connections: $($connections.Count)"
Write-Host "Proxy connections to 127.0.0.1:${ProxyPort}: $proxyConnectionCount"
Write-Host "External established connections: $externalConnectionCount"
Write-Host ""
$connections | Format-Table -AutoSize
Write-Host ""
$hostMatches | ForEach-Object {
    Write-Host "$($_.host): matched=$($_.matched)"
}
