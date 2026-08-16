param(
    [string]$XrayVersion = "25.10.15",
    [string]$Version = "3.1.2",
    [int]$VersionCode = 0,
    [switch]$InstallEmulator,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$apkRoot = $PSScriptRoot
$vendorRoot = Join-Path $apkRoot "vendor"
$downloadRoot = Join-Path $vendorRoot "downloads"
$sdkRoot = Join-Path $apkRoot ".android-sdk"
$releases = Join-Path $apkRoot "releases"
New-Item -ItemType Directory -Force -Path $vendorRoot,$downloadRoot,$releases | Out-Null

if ($Version -notmatch '^(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$') {
    throw "Version must be semantic versioning without a leading v: $Version"
}
if ($VersionCode -le 0) {
    $major = [int64]$Matches['major']; $minor = [int64]$Matches['minor']; $patch = [int64]$Matches['patch']
    if ($major -gt 2000 -or $minor -gt 999 -or $patch -gt 999) { throw "Version components are too large for an Android versionCode." }
    $VersionCode = [int]($major * 1000000 + $minor * 1000 + $patch)
    if ($VersionCode -le 0) { $VersionCode = 1 }
}

function Find-JavaHome {
    if ((-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) -and
        (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe")) -and
        (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\javac.exe")) -and
        (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\jlink.exe"))) {
        return $env:JAVA_HOME
    }
    $javac = Get-Command javac.exe -ErrorAction SilentlyContinue
    if ($javac) { return Split-Path -Parent (Split-Path -Parent $javac.Source) }
    $candidate = Get-ChildItem "C:\Program Files\Eclipse Adoptium" -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-Path -LiteralPath (Join-Path $_.FullName "bin\java.exe"))
            -and (Test-Path -LiteralPath (Join-Path $_.FullName "bin\javac.exe"))
            -and (Test-Path -LiteralPath (Join-Path $_.FullName "bin\jlink.exe"))
        } |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($candidate) { return $candidate.FullName }
    throw "JDK 17 or newer was not found."
}

function Download-IfMissing([string]$Url, [string]$Path) {
    if (Test-Path -LiteralPath $Path) { return }
    Write-Host "Downloading $Url"
    $partial = "$Path.part"
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source --fail --location --retry 4 --retry-all-errors --continue-at - `
            --user-agent "Loki-Traffic-Lab-Build" --output $partial $Url
        if ($LASTEXITCODE -ne 0) { throw "Download failed with exit code $LASTEXITCODE`: $Url" }
    } else {
        Invoke-WebRequest -UseBasicParsing -Headers @{ "User-Agent" = "Loki-Traffic-Lab-Build" } -Uri $Url -OutFile $partial
    }
    Move-Item -LiteralPath $partial -Destination $Path -Force
}

function Assert-Sha256([string]$Path, [string]$ExpectedSha256) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "SHA-256 verification failed for $Path. Expected $ExpectedSha256, got $actual."
    }
}

$taskJavaHome = Find-JavaHome
$env:JAVA_HOME = $taskJavaHome
$env:PATH = "$(Join-Path $taskJavaHome 'bin');$env:PATH"

$toolsZip = Join-Path $downloadRoot "commandlinetools-win-13114758_latest.zip"
Download-IfMissing "https://dl.google.com/android/repository/commandlinetools-win-13114758_latest.zip" $toolsZip
Assert-Sha256 $toolsZip "98b565cb657b012dae6794cefc0f66ae1efb4690c699b78a614b4a6a3505b003"
$sdkManager = Join-Path $sdkRoot "cmdline-tools\latest\bin\sdkmanager.bat"
if (-not (Test-Path -LiteralPath $sdkManager)) {
    $extract = Join-Path $vendorRoot "commandline-tools-extract"
    if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $extract,(Join-Path $sdkRoot "cmdline-tools") | Out-Null
    Expand-Archive -LiteralPath $toolsZip -DestinationPath $extract -Force
    Move-Item -LiteralPath (Join-Path $extract "cmdline-tools") -Destination (Join-Path $sdkRoot "cmdline-tools\latest")
    Remove-Item -LiteralPath $extract -Recurse -Force
}

$env:ANDROID_SDK_ROOT = $sdkRoot
$env:ANDROID_HOME = $sdkRoot
$sdkPackages = @("platform-tools", "platforms;android-35", "build-tools;35.0.0")
if ($InstallEmulator) { $sdkPackages += @("emulator", "system-images;android-35;default;x86_64") }
$installedPackages = & $sdkManager --sdk_root=$sdkRoot --list_installed 2>$null | Out-String
$missingPackages = @($sdkPackages | Where-Object { $installedPackages -notmatch [regex]::Escape($_) })
if ($missingPackages.Count -gt 0) {
    1..40 | ForEach-Object { "y" } | & $sdkManager --sdk_root=$sdkRoot --licenses | Out-Null
    & $sdkManager --sdk_root=$sdkRoot @missingPackages
    if ($LASTEXITCODE -ne 0) { throw "Android SDK package installation failed with exit code $LASTEXITCODE." }
}

$localProperties = "sdk.dir=$($sdkRoot.Replace('\','\\'))`n"
[IO.File]::WriteAllText((Join-Path $apkRoot "local.properties"), $localProperties, [Text.UTF8Encoding]::new($false))

$gradle = Join-Path $apkRoot "gradlew.bat"
if (-not (Test-Path -LiteralPath $gradle)) { throw "Gradle wrapper is missing: $gradle" }
$env:TLAB_VERSION_NAME = $Version
$env:TLAB_VERSION_CODE = $VersionCode.ToString([Globalization.CultureInfo]::InvariantCulture)

$abis = @(
    @{ AndroidAbi = "arm64-v8a"; Asset = "Xray-android-arm64-v8a.zip" },
    @{ AndroidAbi = "x86_64"; Asset = "Xray-android-amd64.zip" }
)
foreach ($abi in $abis) {
    $xrayRoot = Join-Path $vendorRoot "xray-$XrayVersion-$($abi.AndroidAbi)"
    $zip = Join-Path $xrayRoot $abi.Asset
    $digest = "$zip.dgst"
    New-Item -ItemType Directory -Force -Path $xrayRoot | Out-Null
    $base = "https://github.com/XTLS/Xray-core/releases/download/v$XrayVersion"
    Download-IfMissing "$base/$($abi.Asset)" $zip
    Download-IfMissing "$base/$($abi.Asset).dgst" $digest
    $digestText = [IO.File]::ReadAllText($digest)
    $expected = [regex]::Match($digestText, '(?im)^SHA2-256=\s*(?<hash>[0-9a-f]{64})\s*$').Groups['hash'].Value
    $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($expected) -or $actual -ne $expected.ToLowerInvariant()) { throw "Official Xray digest verification failed for $($abi.Asset)." }
    $extract = Join-Path $xrayRoot "extracted"
    if (-not (Test-Path -LiteralPath (Join-Path $extract "xray"))) {
        New-Item -ItemType Directory -Force -Path $extract | Out-Null
        Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
    }
    $target = Join-Path $apkRoot "app\src\main\jniLibs\$($abi.AndroidAbi)"
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Copy-Item -LiteralPath (Join-Path $extract "xray") -Destination (Join-Path $target "libxray.so") -Force
}

$tasks = @("--no-daemon", "--stacktrace")
if (-not $SkipTests) { $tasks += @("testDebugUnitTest", "lintDebug") }
$tasks += @("lintRelease", "assembleRelease")
& $gradle -p $apkRoot @tasks
if ($LASTEXITCODE -ne 0) { throw "Android Gradle build failed with exit code $LASTEXITCODE." }

$builtApk = Join-Path $apkRoot "app\build\outputs\apk\release\app-release.apk"
if (-not (Test-Path -LiteralPath $builtApk)) { throw "Built APK was not found: $builtApk" }
$releaseApkName = "LokiTrafficLab-android-$Version.apk"
$releaseApk = Join-Path $releases $releaseApkName
Copy-Item -LiteralPath $builtApk -Destination $releaseApk -Force
$hash = (Get-FileHash -LiteralPath $releaseApk -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $releaseApkName" | Set-Content -LiteralPath "$releaseApk.sha256" -Encoding ASCII
$metadata = [ordered]@{
    schemaVersion = 1
    componentRole = "traffic-lab-android-client"
    builtAt = (Get-Date).ToUniversalTime().ToString("o")
    version = $Version
    versionCode = $VersionCode
    applicationId = "com.loki.trafficlab"
    minSdk = 26
    targetSdk = 35
    abis = @("arm64-v8a", "x86_64")
    xrayVersion = $XrayVersion
    artifact = [ordered]@{ file = $releaseApkName; bytes = (Get-Item -LiteralPath $releaseApk).Length; sha256 = $hash }
    apkSha256 = $hash
    signing = "Android package signature uses the build environment debug key; GitHub release provenance and SHA-256 authenticate CI bytes, but this APK signing identity is not suitable for store publication or stable in-place upgrades"
    compatibility = [ordered]@{ minAndroidApi = 26; targetAndroidApi = 35; abis = @("arm64-v8a", "x86_64") }
    dependencies = [ordered]@{ androidGradlePlugin = "8.7.3"; gradle = "8.9"; xray = $XrayVersion }
}
$metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $releases "manifest.json") -Encoding UTF8
Copy-Item -LiteralPath (Join-Path $apkRoot "README.txt") -Destination (Join-Path $releases "README.txt") -Force
Copy-Item -LiteralPath (Join-Path $apkRoot "THIRD-PARTY-NOTICES.txt") -Destination (Join-Path $releases "THIRD-PARTY-NOTICES.txt") -Force

Write-Host "Android APK: $releaseApk"
Write-Host "SHA-256: $hash"
Write-Host "Embedded ABIs: arm64-v8a, x86_64"
