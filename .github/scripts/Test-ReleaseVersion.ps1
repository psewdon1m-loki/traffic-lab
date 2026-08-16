param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [string]$ProjectPath = "src/TrafficLab.ProfileRunner/TrafficLab.ProfileRunner.csproj"
)

$ErrorActionPreference = "Stop"
if ($Tag -notmatch '^v(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)$') {
    throw "Release tag must be a stable semantic version such as v3.1.2: $Tag"
}
$version = "$($Matches.major).$($Matches.minor).$($Matches.patch)"
$projectText = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ProjectPath))
$projectVersion = [regex]::Match($projectText, '<Version>(?<version>[^<]+)</Version>').Groups['version'].Value
if ($projectVersion -ne $version) {
    throw "Tag/project version mismatch: tag=$version project=$projectVersion"
}

$major = [int64]$Matches.major
$minor = [int64]$Matches.minor
$patch = [int64]$Matches.patch
if ($major -gt 2000 -or $minor -gt 999 -or $patch -gt 999) { throw "Version is too large for Android versionCode." }
$versionCode = [int]($major * 1000000 + $minor * 1000 + $patch)
if ($versionCode -le 0) { $versionCode = 1 }

$pointingTags = @(& git tag --points-at HEAD)
if ($LASTEXITCODE -ne 0 -or $pointingTags -notcontains $Tag) {
    throw "Checked-out commit is not pointed to by exact release tag $Tag."
}

if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT)) {
    "version=$version" | Add-Content -LiteralPath $env:GITHUB_OUTPUT -Encoding utf8
    "version_code=$versionCode" | Add-Content -LiteralPath $env:GITHUB_OUTPUT -Encoding utf8
}
Write-Host "Validated immutable release identity: tag=$Tag version=$version versionCode=$versionCode"
