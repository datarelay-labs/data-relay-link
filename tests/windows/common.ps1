# Common test helpers for Windows client tests (pwsh 5.1 / 7).
$ErrorActionPreference = 'Stop'

$script:WindowsTestsRoot = $PSScriptRoot
$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$script:WindowsLib = Join-Path $script:RepoRoot 'windows/lib'

function Import-FrpWindowsTestModules {
    throw 'ERROR: dot-source tests/windows/_import.ps1 instead of calling Import-FrpWindowsTestModules'
}

function Assert-FrpTrue {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERT: $Message" }
}

function Assert-FrpEqual {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -ne $Actual) {
        throw "ASSERT: $Message (expected='$Expected' actual='$Actual')"
    }
}

function Write-FrpTestPass {
    param([string]$Name)
    Write-Host "PASS $Name"
}

function Remove-FrpWindowsTestRoot {
    if ($env:FRP_WINDOWS_ROOT -and (Test-Path -LiteralPath $env:FRP_WINDOWS_ROOT)) {
        Remove-Item -LiteralPath $env:FRP_WINDOWS_ROOT -Recurse -Force -ErrorAction SilentlyContinue
    }
}
