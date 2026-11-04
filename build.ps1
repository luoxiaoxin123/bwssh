# Builds the bwssh installer: artifacts\installer\bwssh-setup-<version>-<architecture>.exe
param(
    [string]$Version = "1.0.0",
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",
    # Publish and verify only; skip building the installer (used by CI).
    [switch]$SkipInstaller
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$publish = Join-Path $root "artifacts\publish"
$installer = Join-Path $root "artifacts\installer"

if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }
dotnet publish (Join-Path $root "src\BwSshAgent.App\BwSshAgent.App.csproj") `
    -c Release -r "win-$Architecture" "-p:Platform=$Architecture" --self-contained "-p:Version=$Version" -o $publish
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

# Unpackaged WinUI loads compiled XAML through bwssh.pri; without it the app crashes on startup.
if (-not (Test-Path (Join-Path $publish "bwssh.pri"))) { throw "bwssh.pri missing from publish output" }

if ($SkipInstaller) { return }

$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 (ISCC.exe) not found" }

& $iscc "/DAppVersion=$Version" "/DAppArchitecture=$Architecture" "/DPublishDir=$publish" "/DOutputDir=$installer" (Join-Path $root "installer\bwssh.iss")
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
Get-ChildItem $installer -Filter *.exe
