param(
    [Parameter(Mandatory = $false)]
    [string[]]$VlessUri = @(),
    [string]$InputFile = "",
    [string]$NetworkLabel = "local-current-network",
    [string]$XrayPath = "",
    [string]$OutputDirectory = "traffic-lab\artifacts",
    [string]$PlanPath = "",
    [string]$HistoryPath = "",
    [int]$TimeoutSeconds = 15,
    [int]$DnsAttempts = 1,
    [int]$TcpAttempts = 3,
    [int]$StabilityAttempts = 5,
    [switch]$SkipTraceroute,
    [switch]$Basic,
    [switch]$NegativeControls,
    [switch]$XudpCompatibility,
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $PSScriptRoot "src\TrafficLab.ProfileRunner\TrafficLab.ProfileRunner.csproj"
$outputPath = Join-Path $repoRoot $OutputDirectory
$toolPath = Join-Path $outputPath "profile-runner-tool"
$toolDll = Join-Path $toolPath "LokiTrafficLab.dll"

function Find-Dotnet {
    $bundled = Join-Path $repoRoot "client_pc\.dotnet\dotnet.exe"
    if (Test-Path -LiteralPath $bundled) {
        return $bundled
    }

    $command = Get-Command dotnet.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw "A .NET 8 SDK is required. The bundled client_pc\.dotnet runtime was not found."
}

function Find-Xray {
    if (-not [string]::IsNullOrWhiteSpace($XrayPath)) {
        if (-not (Test-Path -LiteralPath $XrayPath)) {
            throw "Xray executable not found: $XrayPath"
        }
        return (Resolve-Path -LiteralPath $XrayPath).Path
    }

    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "LokiClient\runtime\xray.exe"),
        (Join-Path $repoRoot "client_pc\src\Client.App.Win\Assets\xray\xray.exe"),
        (Join-Path $PSScriptRoot "Portable windows\vendor\v2rayN-windows-64\bin\xray\xray.exe")
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "Xray executable was not found. Pass -XrayPath explicitly."
}

function Read-InputUris {
    $items = New-Object System.Collections.Generic.List[string]
    foreach ($value in $VlessUri) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $items.Add($value.Trim())
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($InputFile)) {
        if (-not (Test-Path -LiteralPath $InputFile)) {
            throw "Input file not found: $InputFile"
        }

        foreach ($line in Get-Content -LiteralPath $InputFile) {
            $value = $line.Trim()
            if ($value -and -not $value.StartsWith("#")) {
                $items.Add($value)
            }
        }
    }

    return $items.ToArray()
}

$dotnet = Find-Dotnet
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

$sourceDirectory = Split-Path -Parent $projectPath
$sourceFiles = @(
    Get-ChildItem -LiteralPath $sourceDirectory -File -Filter "*.cs"
    Get-Item -LiteralPath $projectPath
)
$needsBuild = -not (Test-Path -LiteralPath $toolDll)
if (-not $needsBuild) {
    $builtAt = (Get-Item -LiteralPath $toolDll).LastWriteTimeUtc
    $needsBuild = @($sourceFiles | Where-Object LastWriteTimeUtc -gt $builtAt).Count -gt 0
}

if ($needsBuild) {
    Write-Host "Building TrafficLab.ProfileRunner..."
    & $dotnet build $projectPath `
        --configuration Release `
        --framework net8.0-windows `
        --output $toolPath `
        --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "TrafficLab.ProfileRunner build failed with exit code $LASTEXITCODE."
    }
}

if ($SelfTest) {
    & $dotnet $toolDll --self-test
    exit $LASTEXITCODE
}

$uris = @(Read-InputUris)
if ($uris.Count -eq 0) {
    throw "Pass at least one VLESS URI with -VlessUri or -InputFile."
}

$resolvedXray = Find-Xray
$payload = [ordered]@{
    uris = $uris
    networkLabel = $NetworkLabel
} | ConvertTo-Json -Depth 4 -Compress

$arguments = @(
    $toolDll,
    "--stdin",
    "--xray", $resolvedXray,
    "--outdir", $outputPath,
    "--timeout", $TimeoutSeconds,
    "--dns-attempts", $DnsAttempts,
    "--tcp-attempts", $TcpAttempts,
    "--stability-attempts", $StabilityAttempts
)
if (-not [string]::IsNullOrWhiteSpace($PlanPath)) {
    $arguments += @("--plan", (Resolve-Path -LiteralPath $PlanPath).Path)
}
if (-not [string]::IsNullOrWhiteSpace($HistoryPath)) {
    $resolvedHistory = if ([IO.Path]::IsPathRooted($HistoryPath)) { $HistoryPath } else { Join-Path $repoRoot $HistoryPath }
    $arguments += @("--history", [IO.Path]::GetFullPath($resolvedHistory))
}
if ($SkipTraceroute) {
    $arguments += "--skip-traceroute"
}
if ($Basic) {
    $arguments += "--basic"
}
if ($NegativeControls) {
    $arguments += "--negative-controls"
}
if ($XudpCompatibility) {
    $arguments += "--xudp"
}

$payload | & $dotnet @arguments
exit $LASTEXITCODE
