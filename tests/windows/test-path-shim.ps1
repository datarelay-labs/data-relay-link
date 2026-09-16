# test-path-shim.ps1 — F32: post-install bare `drlink` resolves via product PATH
# entry / shim. Uninstall removes only the product-owned PATH change.
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

try {
    $script:FrpWindowsSrcRoot = Join-Path $script:RepoRoot 'windows'
    $fakePath = Join-Path $env:FRP_WINDOWS_ROOT 'machine-path.simulated'
    $env:FRP_WINDOWS_FAKE_MACHINE_PATH = $fakePath
    # Start with an unrelated PATH entry and a foreign drlink elsewhere.
    $foreignDir = Join-Path $env:FRP_WINDOWS_ROOT 'foreign-bin'
    New-Item -ItemType Directory -Path $foreignDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $foreignDir 'drlink.cmd') -Value '@echo foreign' -Encoding ASCII
    Set-Content -LiteralPath $fakePath -Value $foreignDir -Encoding ASCII

    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win-shim' -MachineId $mid -HostId 'abcd1234' `
        -Services @{} -Transport 'tcp' -InstallStatus 'enrolled_incomplete' | Out-Null

    $env:FRP_WINDOWS_SKIP_DOWNLOAD = '1'
    $env:FRP_WINDOWS_SKIP_AUTOSTART = '1'
    $rc = Complete-FrpZeroTouchPostEnroll -SkipStart -SkipDownload -Services @{}
    Assert-FrpEqual 0 $rc 'post-enroll install succeeds'

    $tools = Get-FrpToolsDir
    $shim = Get-FrpShimPath
    Assert-FrpTrue (Test-Path -LiteralPath $shim) 'product drlink.cmd installed'
    $pathValue = Get-FrpMachinePathValue
    Assert-FrpTrue ($pathValue -like ("*{0}*" -f $tools)) 'tools dir appended to machine PATH'
    Assert-FrpTrue ($pathValue.StartsWith($foreignDir)) 'foreign PATH entry keeps precedence (append-only)'

    $status = Get-FrpCommandShimStatus
    Assert-FrpTrue ($status.ShimPresent) 'shim present'
    Assert-FrpTrue ($status.ToolsOnPath) 'tools on PATH'
    # Foreign drlink keeps precedence when it already existed.
    Assert-FrpTrue (-not [string]::IsNullOrWhiteSpace([string]$status.ForeignCommand)) 'foreign drlink not hijacked'

    # Clean install with empty PATH: product resolves.
    Set-Content -LiteralPath $fakePath -Value '' -Encoding ASCII
    Remove-Item -LiteralPath (Get-FrpShimMarkerPath) -Force -ErrorAction SilentlyContinue
    Install-FrpCommandShim -Quiet | Out-Null
    $status2 = Get-FrpCommandShimStatus
    Assert-FrpTrue ($status2.ResolvesToProduct) 'product owns bare drlink when no foreign command'
    Assert-FrpTrue (Test-FrpCommandShimHealthy) 'shim healthy'

    Uninstall-FrpCommandShim -Quiet | Out-Null
    $after = Get-FrpMachinePathValue
    Assert-FrpTrue ($after -notlike ("*{0}*" -f $tools)) 'uninstall removes product PATH entry'
    Assert-FrpTrue (-not (Test-Path -LiteralPath (Get-FrpShimMarkerPath))) 'shim marker removed'

    Write-FrpTestPass 'test-path-shim'
} finally {
    Remove-Item Env:FRP_WINDOWS_SKIP_DOWNLOAD -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_SKIP_AUTOSTART -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_FAKE_MACHINE_PATH -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
