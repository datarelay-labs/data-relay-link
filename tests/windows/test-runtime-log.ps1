# test-runtime-log.ps1 — F23: advertised logs\frpc.log exists, is bounded, and
# sanitized tails never leak the FRP token.
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    $services = @{
        rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60030; enabled = $true }
    }
    $token = 'frp-token-runtime-log-secret-value'
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win-log' -MachineId $mid -HostId 'abcd1234' `
        -Services $services -Transport 'tcp' -InstallStatus 'installed' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token $token `
        -HostId 'abcd1234' -Services $services -Transport 'tcp' | Out-Null

    $toml = [System.IO.File]::ReadAllText((Get-FrpTomlPath))
    Assert-FrpTrue ($toml -match 'log\.to\s*=') 'frpc.toml configures log.to'
    Assert-FrpTrue ($toml -match 'frpc\.log') 'log.to points at frpc.log'

    $logPath = Initialize-FrpRuntimeLog
    Assert-FrpEqual (Get-FrpLogPath) $logPath 'Initialize-FrpRuntimeLog returns advertised path'
    Assert-FrpTrue (Test-Path -LiteralPath $logPath) 'logs\frpc.log exists before start'

    # Bound retention: oversized log must shrink under an explicit ceiling.
    $env:FRP_WINDOWS_LOG_MAX_BYTES = '65536'
    $big = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt 5000; $i++) {
        [void]$big.AppendLine(("line-{0} token={1}" -f $i, $token))
    }
    [System.IO.File]::WriteAllText($logPath, $big.ToString())
    $before = (Get-Item -LiteralPath $logPath).Length
    Assert-FrpTrue ($before -gt 65536) "test log is oversized before trim ($before)"
    $trimmed = Limit-FrpRuntimeLog -MaxBytes 65536
    Assert-FrpTrue ($trimmed) 'Limit-FrpRuntimeLog reports a trim'
    $after = (Get-Item -LiteralPath $logPath).Length
    Assert-FrpTrue ($after -lt $before) "Limit-FrpRuntimeLog shrinks oversized log ($before -> $after)"
    Assert-FrpTrue ($after -gt 0) 'bounded log still has content'

    $tail = @(Get-FrpSanitizedLogTail -Lines 50)
    Assert-FrpTrue ($tail.Count -gt 0) 'sanitized tail returns lines'
    $joined = ($tail -join "`n")
    Assert-FrpTrue ($joined -notmatch [regex]::Escape($token)) 'sanitized tail redacts FRP token'

    Write-FrpTestPass 'test-runtime-log'
} finally {
    Remove-FrpWindowsTestRoot
}
