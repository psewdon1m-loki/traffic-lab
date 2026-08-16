param(
    [ValidateSet("linux-x64", "linux-arm64")]
    [string]$RuntimeIdentifier = "linux-x64",
    [string]$XrayVersion = "25.10.15",
    [string]$XrayPath = "",
    [string]$MsQuicPath = "",
    [string]$OutputDirectory = "",
    [switch]$Archive
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
    if ($repoRoot) { $candidates += Join-Path $repoRoot "client_pc\.dotnet\dotnet.exe" }
    if ($env:USERPROFILE) { $candidates += Join-Path $env:USERPROFILE ".dotnet\dotnet.exe" }
    $candidates = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    foreach ($candidate in $candidates) {
        $installed = @(& $candidate --list-sdks 2>$null)
        if ($installed -match "^$([regex]::Escape($requiredVersion))\s+\[") { return $candidate }
    }
    throw "The pinned .NET SDK $requiredVersion from global.json is required to build the Linux release."
}
$dotnet = Resolve-DotNetSdk

$asset = if ($RuntimeIdentifier -eq "linux-arm64") { "Xray-linux-arm64-v8a.zip" } else { "Xray-linux-64.zip" }
$vendorRoot = Join-Path $PSScriptRoot "vendor\xray-$XrayVersion-$RuntimeIdentifier"
New-Item -ItemType Directory -Force -Path $vendorRoot | Out-Null
if ([string]::IsNullOrWhiteSpace($XrayPath)) {
    $zipPath = Join-Path $vendorRoot $asset
    $digestPath = "$zipPath.dgst"
    if (-not (Test-Path -LiteralPath $zipPath)) {
        $baseUrl = "https://github.com/XTLS/Xray-core/releases/download/v$XrayVersion"
        Invoke-WebRequest -UseBasicParsing -Headers @{ "User-Agent" = "Loki-Traffic-Lab-Build" } -Uri "$baseUrl/$asset" -OutFile $zipPath
        Invoke-WebRequest -UseBasicParsing -Headers @{ "User-Agent" = "Loki-Traffic-Lab-Build" } -Uri "$baseUrl/$asset.dgst" -OutFile $digestPath
    }
    if (-not (Test-Path -LiteralPath $digestPath)) { throw "Official Xray digest file is missing: $digestPath" }
    $digestText = [IO.File]::ReadAllText($digestPath)
    $expected = [regex]::Match($digestText, '(?im)^SHA2-256=\s*(?<hash>[0-9a-f]{64})\s*$').Groups['hash'].Value
    $actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($expected) -or $actual -ne $expected.ToLowerInvariant()) { throw "Official Xray SHA2-256 verification failed." }
    $extracted = Join-Path $vendorRoot "extracted"
    New-Item -ItemType Directory -Force -Path $extracted | Out-Null
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extracted -Force
    $XrayPath = Join-Path $extracted "xray"
}
if (-not (Test-Path -LiteralPath $XrayPath)) { throw "Linux Xray executable was not found: $XrayPath" }

$outputRoot = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Join-Path $PSScriptRoot "releases"
} elseif ([IO.Path]::IsPathRooted($OutputDirectory)) {
    [IO.Path]::GetFullPath($OutputDirectory)
} else {
    [IO.Path]::GetFullPath((Join-Path $trafficLabRoot $OutputDirectory))
}
$publishPath = Join-Path $outputRoot "LokiTrafficLab-$RuntimeIdentifier"
New-Item -ItemType Directory -Force -Path $publishPath | Out-Null

& $dotnet restore $project --locked-mode --nologo
if ($LASTEXITCODE -ne 0) { throw "Locked .NET restore failed with exit code $LASTEXITCODE." }
& $dotnet publish $project `
    --configuration Release `
    --framework net8.0 `
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
if ($LASTEXITCODE -ne 0) { throw "Linux publish failed with exit code $LASTEXITCODE." }

Copy-Item -LiteralPath $XrayPath -Destination (Join-Path $publishPath "xray") -Force
if ([string]::IsNullOrWhiteSpace($MsQuicPath)) {
    $msQuicVersion = "2.4.17"
    $debArchitecture = if ($RuntimeIdentifier -eq "linux-arm64") { "arm64" } else { "amd64" }
    $expectedDebSha256 = if ($RuntimeIdentifier -eq "linux-arm64") {
        "01150243ac0153137adc3c802a32dc3aea5e93f00fbd620645b07c94c7b25ae4"
    } else {
        "aa971514ff2a9427df8805b0337649b270e07c4304dcd5e9c14dfab7c3632958"
    }
    $msQuicRoot = Join-Path $PSScriptRoot "vendor\msquic-$msQuicVersion-$RuntimeIdentifier"
    $debPath = Join-Path $msQuicRoot "libmsquic-ubuntu22.deb"
    New-Item -ItemType Directory -Force -Path $msQuicRoot | Out-Null
    if (-not (Test-Path -LiteralPath $debPath)) {
        $debUrl = "https://packages.microsoft.com/ubuntu/22.04/prod/pool/main/libm/libmsquic/libmsquic_${msQuicVersion}_${debArchitecture}.deb"
        Invoke-WebRequest -UseBasicParsing -Headers @{ "User-Agent" = "Loki-Traffic-Lab-Build" } -Uri $debUrl -OutFile $debPath
    }
    $actualDebSha256 = (Get-FileHash -LiteralPath $debPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualDebSha256 -ne $expectedDebSha256) { throw "Official Microsoft libmsquic package SHA-256 verification failed." }
    $data = Join-Path $msQuicRoot "data"
    New-Item -ItemType Directory -Force -Path $data | Out-Null
    if ($IsLinux) {
        & dpkg-deb -x $debPath $data
        if ($LASTEXITCODE -ne 0) { throw "Could not extract the libmsquic deb archive with dpkg-deb." }
    } else {
        $outer = Join-Path $msQuicRoot "outer"
        New-Item -ItemType Directory -Force -Path $outer | Out-Null
        & tar -xf $debPath -C $outer
        if ($LASTEXITCODE -ne 0) { throw "Could not extract the libmsquic deb archive." }
        & tar -xf (Join-Path $outer "data.tar.xz") -C $data
        if ($LASTEXITCODE -ne 0) { throw "Could not extract libmsquic data.tar.xz." }
    }
    $MsQuicPath = (Get-ChildItem -LiteralPath $data -Recurse -File -Filter "libmsquic.so.$msQuicVersion" | Select-Object -First 1).FullName
}
if ([string]::IsNullOrWhiteSpace($MsQuicPath) -or -not (Test-Path -LiteralPath $MsQuicPath)) { throw "Linux libmsquic.so.2 was not found." }
Copy-Item -LiteralPath $MsQuicPath -Destination (Join-Path $publishPath "libmsquic.so.2") -Force
$pdb = Join-Path $publishPath "LokiTrafficLab.pdb"
if (Test-Path -LiteralPath $pdb) { Remove-Item -LiteralPath $pdb -Force }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "tlab") -Destination (Join-Path $publishPath "tlab") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "bootstrap.sh") -Destination (Join-Path $publishPath "bootstrap.sh") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "connections.txt.example") -Destination (Join-Path $publishPath "connections.txt.example") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "test-plan.example.json") -Destination (Join-Path $publishPath "test-plan.example.json") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "README.txt") -Destination (Join-Path $publishPath "README.txt") -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "THIRD-PARTY-NOTICES.txt") -Destination (Join-Path $publishPath "THIRD-PARTY-NOTICES.txt") -Force
if ($IsLinux) { & chmod 0755 (Join-Path $publishPath "LokiTrafficLab") (Join-Path $publishPath "xray") (Join-Path $publishPath "tlab") (Join-Path $publishPath "bootstrap.sh") }

$manifest = [ordered]@{
    schemaVersion = 1
    componentRole = "traffic-lab-linux-client"
    builtAt = (Get-Date).ToUniversalTime().ToString("o")
    releaseVersion = $releaseVersion
    runtimeIdentifier = $RuntimeIdentifier
    framework = "net8.0-self-contained"
    app = [ordered]@{ file = "LokiTrafficLab"; version = $releaseVersion; sha256 = (Get-FileHash (Join-Path $publishPath "LokiTrafficLab") -Algorithm SHA256).Hash.ToLowerInvariant() }
    xray = [ordered]@{ file = "xray"; version = $XrayVersion; sourceAsset = $asset; sha256 = (Get-FileHash (Join-Path $publishPath "xray") -Algorithm SHA256).Hash.ToLowerInvariant() }
    msquic = [ordered]@{ file = "libmsquic.so.2"; version = "2.4.17"; sha256 = (Get-FileHash (Join-Path $publishPath "libmsquic.so.2") -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $publishPath "manifest.json") -Encoding UTF8

if ($Archive) {
    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
    $archivePath = Join-Path $outputRoot "LokiTrafficLab-$RuntimeIdentifier-$releaseVersion.tar.gz"
    $files = @("LokiTrafficLab", "xray", "libmsquic.so.2", "tlab", "bootstrap.sh", "connections.txt.example", "test-plan.example.json", "README.txt", "THIRD-PARTY-NOTICES.txt", "manifest.json")
    & tar -czf $archivePath -C $publishPath @files
    if ($LASTEXITCODE -ne 0) { throw "tar failed with exit code $LASTEXITCODE." }
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $(Split-Path -Leaf $archivePath)" | Set-Content -LiteralPath "$archivePath.sha256" -Encoding ASCII
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "bootstrap.sh") -Destination (Join-Path $outputRoot "bootstrap.sh") -Force
    $bootstrapHash = (Get-FileHash -LiteralPath (Join-Path $outputRoot "bootstrap.sh") -Algorithm SHA256).Hash.ToLowerInvariant()
    "$bootstrapHash  bootstrap.sh" | Set-Content -LiteralPath (Join-Path $outputRoot "bootstrap.sh.sha256") -Encoding ASCII
    Write-Host "Linux archive: $archivePath"
    Write-Host "SHA-256: $hash"
}

Write-Host "Linux application: $publishPath"
Write-Host "No .NET installation is required on the target Ubuntu machine."
