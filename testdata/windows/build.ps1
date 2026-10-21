[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$FixtureRoot = $PSScriptRoot
$RepositoryRoot = (Resolve-Path (Join-Path $FixtureRoot "../..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RepositoryRoot ".scratch/fixtures/bin"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Assert-LastExitCode {
    param([string]$Operation)
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE"
    }
}

$PreviousGOOS = $env:GOOS
$PreviousGOARCH = $env:GOARCH
try {
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    & go build -o (Join-Path $OutputDirectory "command-probe.exe") `
        (Join-Path $FixtureRoot "payloads/command")
    Assert-LastExitCode "building the command fixture"
    & go build -o (Join-Path $OutputDirectory "service-probe.exe") `
        (Join-Path $FixtureRoot "payloads/service")
    Assert-LastExitCode "building the service fixture"
}
finally {
    $env:GOOS = $PreviousGOOS
    $env:GOARCH = $PreviousGOARCH
}

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $VSWhere = Join-Path ${env:ProgramFiles(x86)} `
        "Microsoft Visual Studio/Installer/vswhere.exe"
    if (-not (Test-Path -LiteralPath $VSWhere)) {
        throw "cl.exe is unavailable and vswhere.exe was not found"
    }
    $Installation = & $VSWhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if ([string]::IsNullOrWhiteSpace($Installation)) {
        throw "a Visual Studio C++ toolchain was not found"
    }
    $VCVars = Join-Path $Installation "VC/Auxiliary/Build/vcvars64.bat"
    $EnvironmentCommand = "call `"$VCVars`" >nul && set"
    $EnvironmentLines = & $env:COMSPEC /d /s /c $EnvironmentCommand
    Assert-LastExitCode "initializing the Visual Studio C++ toolchain"
    foreach ($Line in $EnvironmentLines) {
        if ($Line -match "^([^=]+)=(.*)$") {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
        }
    }
}

& cl.exe /nologo /LD /W4 /WX `
    "/Fo$(Join-Path $OutputDirectory 'launcher-probe.obj')" `
    (Join-Path $FixtureRoot "launcher-contracts/native-dll/probe.c") `
    /link "/OUT:$(Join-Path $OutputDirectory 'launcher-probe.dll')"
Assert-LastExitCode "building the native DLL fixture"

& cl.exe /nologo /LD /W4 /WX `
    "/Fo$(Join-Path $OutputDirectory 'control-probe.obj')" `
    (Join-Path $FixtureRoot "launcher-contracts/cpl/probe.c") `
    /link "/OUT:$(Join-Path $OutputDirectory 'control-probe.cpl')"
Assert-LastExitCode "building the CPL fixture"

& cl.exe /nologo /LD /W4 /WX `
    "/Fo$(Join-Path $OutputDirectory 'wmi-provider-probe.obj')" `
    (Join-Path $FixtureRoot "techniques/wmi-provider/provider.c") `
    wbemuuid.lib ole32.lib `
    /link "/DEF:$(Join-Path $FixtureRoot 'techniques/wmi-provider/exports.def')" `
    "/OUT:$(Join-Path $OutputDirectory 'wmi-provider-probe.dll')"
Assert-LastExitCode "building the WMI provider fixture"

$KeyPath = Join-Path $OutputDirectory "managed-probe.snk"
try {
    & go run (Join-Path $FixtureRoot "tools/generate-snk/main.go") `
        -output $KeyPath
    Assert-LastExitCode "generating the managed fixture signing key"

    $CSC = Join-Path $env:WINDIR "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    if (-not (Test-Path -LiteralPath $CSC)) {
        throw ".NET Framework x64 csc.exe was not found"
    }
    & $CSC /nologo /target:library /warnaserror+ `
        "/keyfile:$KeyPath" `
        /reference:System.Configuration.Install.dll `
        /reference:System.EnterpriseServices.dll `
        "/out:$(Join-Path $OutputDirectory 'managed-probe.dll')" `
        (Join-Path $FixtureRoot "launcher-contracts/managed/probe.cs")
    Assert-LastExitCode "building the managed fixture"
}
finally {
    Remove-Item -LiteralPath $KeyPath -Force -ErrorAction SilentlyContinue
}

Get-ChildItem -LiteralPath $OutputDirectory -File |
    Where-Object Extension -In ".obj", ".exp", ".lib", ".pdb" |
    Remove-Item -Force

Write-Host "Built Windows fixtures in $OutputDirectory"
