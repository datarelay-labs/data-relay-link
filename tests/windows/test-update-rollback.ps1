# test-update-rollback.ps1 — update failure restores snapshotted files
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    $services = @{
        rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'
                 local_port = 3389; remote_port = 60003; enabled = $true }
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'abcd' `
        -Services $services -Transport 'tcp' -InstallStatus 'installed' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok-original' `
        -HostId 'abcd' -Services $services -Transport 'tcp' | Out-Null
    New-Item -ItemType Directory -Path (Get-FrpBinDir) -Force | Out-Null
    Set-Content -LiteralPath (Get-FrpFrpcPath) -Value 'ORIGINAL_BINARY'
    Set-Content -LiteralPath (Get-FrpVersionPath) -Value "PROJECT_VERSION=1.0.0`n"

    $origToml = (Get-Content -LiteralPath (Get-FrpTomlPath) -Raw).Trim()
    $origState = (Get-Content -LiteralPath (Get-FrpStatePath) -Raw).Trim()
    $origVer = (Get-Content -LiteralPath (Get-FrpVersionPath) -Raw).Trim()

    $clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
    $clientText = Get-Content -LiteralPath $clientPath -Raw
    $m = [regex]::Match($clientText, '(?ms)^function Invoke-FrpClientUpdate \{.*?\n\}')
    Assert-FrpTrue $m.Success 'found Invoke-FrpClientUpdate'
    Invoke-Expression $m.Value

    function Install-FrpWindowsBinary {
        param($DownloadUrl, $ExpectedSha256)
        Set-Content -LiteralPath (Get-FrpFrpcPath) -Value 'NEW_BINARY'
        Set-Content -LiteralPath (Get-FrpVersionPath) -Value "PROJECT_VERSION=9.9.9`n"
        return (Get-FrpFrpcPath)
    }
    $DownloadUrl = 'https://example.test/frp.zip'
    $ExpectedSha256 = 'a' * 64
    $env:FRP_WINDOWS_FAIL_AFTER_BINARY_REPLACE = '1'
    $rc = Invoke-FrpClientUpdate
    Assert-FrpEqual 1 $rc 'update returns failure'
    Assert-FrpEqual 'ORIGINAL_BINARY' ((Get-Content -LiteralPath (Get-FrpFrpcPath) -Raw).Trim()) 'exe restored'
    Assert-FrpEqual $origToml ((Get-Content -LiteralPath (Get-FrpTomlPath) -Raw).Trim()) 'toml restored'
    Assert-FrpEqual $origState ((Get-Content -LiteralPath (Get-FrpStatePath) -Raw).Trim()) 'state restored'
    Assert-FrpEqual $origVer ((Get-Content -LiteralPath (Get-FrpVersionPath) -Raw).Trim()) 'version restored'

    Write-FrpTestPass 'test-update-rollback'
} finally {
    Remove-Item Env:FRP_WINDOWS_FAIL_AFTER_BINARY_REPLACE -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
