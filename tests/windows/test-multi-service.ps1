# test-multi-service.ps1
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $json = @'
[
  {"id":"rdp","name":"RDP","preset":"rdp","local_ip":"127.0.0.1","local_port":3389},
  {"id":"web","name":"HTTP","preset":"http","local_ip":"127.0.0.1","local_port":8080}
]
'@
    $svcs = Get-FrpDefaultServices -Platform 'windows' -ServicesJson $json
    Assert-FrpEqual 2 @($svcs).Count 'two services'
    $list = Get-FrpEnrollServiceList -Services $svcs
    $presets = @($list | ForEach-Object { $_.preset })
    # RDP is a local UX alias; the wire protocol uses preset=custom (server ALLOWED_PRESETS).
    Assert-FrpTrue ($presets -contains 'custom') 'rdp maps to wire preset custom'
    Assert-FrpTrue ($presets -contains 'http') 'http kept'
    $rdpEntry = @($list | Where-Object { $_.id -eq 'rdp' })[0]
    Assert-FrpEqual 'custom' $rdpEntry.preset 'rdp wire preset is custom'

    $merged = Merge-FrpAllocatedPorts -LocalServices $svcs -AllocatedList @(
        @{ id = 'rdp'; remote_port = 60001 },
        @{ id = 'web'; remote_port = 60002 }
    )
    $toml = New-FrpClientToml -ServerAddr '203.0.113.9' -ServerPort 7000 -Token 'tok-deadbeef' `
        -HostId 'host1' -Services $merged -Transport 'tcp'
    $text = Get-Content -LiteralPath $toml -Raw
    Assert-FrpTrue ($text -match 'remotePort = 60001') 'rdp remote'
    Assert-FrpTrue ($text -match 'remotePort = 60002') 'web remote'
    Assert-FrpTrue (($text -split '\[\[proxies\]\]').Count -eq 3) 'two proxies'

    Write-FrpTestPass 'test-multi-service'
} finally {
    Remove-FrpWindowsTestRoot
}
