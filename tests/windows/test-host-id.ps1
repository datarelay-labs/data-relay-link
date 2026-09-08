# test-host-id.ps1 — host_id / proxy name must match Linux + Access Control
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $mid = '7f5c8a83bd68bf76a8380d416322f568'
    Assert-FrpEqual 'DESKTOP-SLBCN3A-7f5c8a83' (Get-FrpExpectedHostId -Hostname 'DESKTOP-SLBCN3A' -MachineId $mid) 'windows hostname'
    Assert-FrpEqual 'win-host-abcdef12' (Get-FrpExpectedHostId -Hostname 'win host' -MachineId 'abcdef1234567890') 'sanitize spaces'
    Assert-FrpEqual 'a.b_c-12345678' (Get-FrpExpectedHostId -Hostname 'a.b_c' -MachineId '1234567890abcdef') 'keep safe chars'

    $services = @(
        [pscustomobject]@{ id = 'ssh'; name = 'SSH'; preset = 'ssh'; local_ip = '127.0.0.1'; local_port = 22; remote_port = 6003; enabled = $true; ssh_user = 'aella' }
    )
    $hostId = Get-FrpExpectedHostId -Hostname 'DESKTOP-SLBCN3A' -MachineId $mid
    $toml = New-FrpClientToml -ServerAddr '203.0.113.10' -ServerPort 443 -Token 'tok' `
        -HostId $hostId -Services $services -Transport 'tcp'
    $text = Get-Content -LiteralPath $toml -Raw
    Assert-FrpTrue ($text -match 'name = "DESKTOP-SLBCN3A-7f5c8a83-ssh"') 'proxy name matches AC expected_proxy_name'

    Write-FrpTestPass 'test-host-id'
} finally {
    Remove-FrpWindowsTestRoot
}
