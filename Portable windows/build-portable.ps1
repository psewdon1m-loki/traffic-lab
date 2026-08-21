param(
    [ValidateSet("win-x64", "win-arm64")]
    [string]$RuntimeIdentifier = "win-x64",
    [string]$XrayVersion = "25.10.15",
    [string]$XrayPath = "",
    [string]$OutputDirectory = "",
    [switch]$Zip
)

$ErrorActionPreference = "Stop"
$trafficLabRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $trafficLabRoot
$project = Join-Path $trafficLabRoot "src\TrafficLab.ProfileRunner\TrafficLab.ProfileRunner.csproj"
$projectText = [IO.File]::ReadAllText($project)
$releaseVersion = [regex]::Match($projectText, '<Version>(?<version>[^<]+)</Version>').Groups['version'].Value
if ([string]::IsNullOrWhiteSpace($releaseVersion)) { throw "Project version was not found in $project." }
function Resolve-DotNetSdk {
    $requiredVersion = (Get-Content -LiteralPath (Join-Path $trafficLabRoot "global.json") -Raw | ConvertFrom-Json).sdk.version
    $command = Get-Command dotnet -ErrorAction SilentlyContinue
    $candidates = @()
    if ($env:DOTNET_ROOT) {
        $candidates += Join-Path $env:DOTNET_ROOT "dotnet.exe"
        $candidates += Join-Path $env:DOTNET_ROOT "dotnet"
    }
    if ($command) { $candidates += $command.Source }
    if ($repoRoot) { $candidates += Join-Path $repoRoot "client\win\.dotnet\dotnet.exe" }
    if ($env:USERPROFILE) { $candidates += Join-Path $env:USERPROFILE ".dotnet\dotnet.exe" }
    $candidates = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    foreach ($candidate in $candidates) {
        $installed = @(& $candidate --list-sdks 2>$null)
        if ($installed -match "^$([regex]::Escape($requiredVersion))\s+\[") { return $candidate }
    }
    throw "The pinned .NET SDK $requiredVersion from global.json is required to build the portable package."
}
$dotnet = Resolve-DotNetSdk

$xraySourceAsset = "supplied-local-file"
if ([string]::IsNullOrWhiteSpace($XrayPath)) {
    $xraySourceAsset = if ($RuntimeIdentifier -eq "win-arm64") { "Xray-windows-arm64-v8a.zip" } else { "Xray-windows-64.zip" }
    $vendorRoot = Join-Path $PSScriptRoot "vendor\xray-$XrayVersion-$RuntimeIdentifier"
    $zipPath = Join-Path $vendorRoot $xraySourceAsset
    $digestPath = "$zipPath.dgst"
    New-Item -ItemType Directory -Force -Path $vendorRoot | Out-Null
    $baseUrl = "https://github.com/XTLS/Xray-core/releases/download/v$XrayVersion"
    if (-not (Test-Path -LiteralPath $zipPath)) {
        Invoke-WebRequest -UseBasicParsing -Headers @{ "User-Agent" = "Loki-Traffic-Lab-Build" } -Uri "$baseUrl/$xraySourceAsset" -OutFile $zipPath
    }
    if (-not (Test-Path -LiteralPath $digestPath)) {
        Invoke-WebRequest -UseBasicParsing -Headers @{ "User-Agent" = "Loki-Traffic-Lab-Build" } -Uri "$baseUrl/$xraySourceAsset.dgst" -OutFile $digestPath
    }
    $digestText = [IO.File]::ReadAllText($digestPath)
    $expected = [regex]::Match($digestText, '(?im)^SHA2-256=\s*(?<hash>[0-9a-f]{64})\s*$').Groups['hash'].Value
    $actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($expected) -or $actual -ne $expected.ToLowerInvariant()) {
        throw "Official Xray SHA2-256 verification failed for $xraySourceAsset."
    }
    $extracted = Join-Path $vendorRoot "extracted"
    New-Item -ItemType Directory -Force -Path $extracted | Out-Null
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extracted -Force
    $XrayPath = Join-Path $extracted "xray.exe"
}
if ([string]::IsNullOrWhiteSpace($XrayPath) -or -not (Test-Path -LiteralPath $XrayPath)) { throw "Windows Xray executable was not found: $XrayPath" }

$outputRoot = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Join-Path $PSScriptRoot "releases"
}
elseif ([IO.Path]::IsPathRooted($OutputDirectory)) {
    [IO.Path]::GetFullPath($OutputDirectory)
}
else {
    [IO.Path]::GetFullPath((Join-Path $trafficLabRoot $OutputDirectory))
}
$publishPath = Join-Path $outputRoot "LokiTrafficLab-$RuntimeIdentifier"
New-Item -ItemType Directory -Force -Path $publishPath | Out-Null

& $dotnet restore $project --locked-mode --nologo
if ($LASTEXITCODE -ne 0) { throw "Locked .NET restore failed with exit code $LASTEXITCODE." }
& $dotnet publish $project `
    --configuration Release `
    --framework net8.0-windows `
    --runtime $RuntimeIdentifier `
    --self-contained true `
    --output $publishPath `
    --no-restore `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    --nologo
if ($LASTEXITCODE -ne 0) { throw "Portable publish failed with exit code $LASTEXITCODE." }

Copy-Item -LiteralPath $XrayPath -Destination (Join-Path $publishPath "xray.exe") -Force
$nugetRoot = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path $env:USERPROFILE ".nuget\packages" }
$runtimePackRoot = Join-Path $nugetRoot "microsoft.netcore.app.runtime.$RuntimeIdentifier"
$msQuic = Get-ChildItem -LiteralPath $runtimePackRoot -Recurse -Filter "msquic.dll" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like "*\runtimes\$RuntimeIdentifier\native\msquic.dll" } |
    Sort-Object { [version]$_.Directory.Parent.Parent.Parent.Name } -Descending |
    Select-Object -First 1
if (-not $msQuic) {
    throw "The $RuntimeIdentifier runtime pack did not provide msquic.dll; refusing to publish a package with a silently disabled QUIC probe."
}
Copy-Item -LiteralPath $msQuic.FullName -Destination (Join-Path $publishPath "msquic.dll") -Force
$generatedPdb = Join-Path $publishPath "LokiTrafficLab.pdb"
if (Test-Path -LiteralPath $generatedPdb) { Remove-Item -LiteralPath $generatedPdb -Force }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "PORTABLE-README.txt") -Destination (Join-Path $publishPath "README.txt") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "portable-connections.txt") -Destination (Join-Path $publishPath "connections.txt") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "portable-test-plan.example.json") -Destination (Join-Path $publishPath "test-plan.example.json") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "THIRD-PARTY-NOTICES.txt") -Destination (Join-Path $publishPath "THIRD-PARTY-NOTICES.txt") -Force

$manifest = [ordered]@{
    schemaVersion = 1
    componentRole = "traffic-lab-windows-portable-client"
    builtAt = (Get-Date).ToUniversalTime().ToString("o")
    releaseVersion = $releaseVersion
    runtimeIdentifier = $RuntimeIdentifier
    app = [ordered]@{
        file = "LokiTrafficLab.exe"
        version = (Get-Item -LiteralPath (Join-Path $publishPath "LokiTrafficLab.exe")).VersionInfo.FileVersion
        sha256 = (Get-FileHash -LiteralPath (Join-Path $publishPath "LokiTrafficLab.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    xray = [ordered]@{
        file = "xray.exe"
        version = ((& $XrayPath version 2>$null | Select-Object -First 1) -as [string]).Trim()
        sourceAsset = $xraySourceAsset
        sha256 = (Get-FileHash -LiteralPath (Join-Path $publishPath "xray.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    msquic = [ordered]@{
        file = "msquic.dll"
        version = (Get-Item -LiteralPath (Join-Path $publishPath "msquic.dll")).VersionInfo.FileVersion
        sha256 = (Get-FileHash -LiteralPath (Join-Path $publishPath "msquic.dll") -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $publishPath "manifest.json") -Encoding UTF8

if ($Zip) {
    $archiveArchitecture = $RuntimeIdentifier -replace '^win-', ''
    $zipPath = Join-Path $outputRoot "LokiTrafficLab-windows-$archiveArchitecture-$releaseVersion.zip"
    $distributionFiles = @(
        "LokiTrafficLab.exe",
        "xray.exe",
        "msquic.dll",
        "README.txt",
        "connections.txt",
        "test-plan.example.json",
        "THIRD-PARTY-NOTICES.txt",
        "manifest.json"
    ) | ForEach-Object { Join-Path $publishPath $_ }
    Compress-Archive -LiteralPath $distributionFiles -DestinationPath $zipPath -Force
    $archiveHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$archiveHash  $(Split-Path -Leaf $zipPath)" | Set-Content -LiteralPath "$zipPath.sha256" -Encoding ASCII
    Write-Host "Portable ZIP: $zipPath"
    Write-Host "SHA-256: $archiveHash"
}

Write-Host "Portable application: $publishPath"
Write-Host "No .NET installation is required on the target Windows machine."
