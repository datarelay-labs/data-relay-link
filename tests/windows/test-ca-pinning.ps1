# test-ca-pinning.ps1 — unit-level helpers
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $norm = Normalize-FrpCaSha256 -Value 'SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    Assert-FrpEqual 64 $norm.Length 'normalized length'
    Assert-FrpEqual '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' $norm 'normalized value'

    $origin = Get-FrpAllocatorOrigin -AllocatorUrl 'https://frp.example.test:9443/enroll'
    Assert-FrpTrue ($origin -match '^https://frp\.example\.test:9443') 'origin host'

    try {
        Get-FrpAllocatorOrigin -AllocatorUrl 'http://frp.example.test/enroll' | Out-Null
        throw 'expected http reject'
    } catch {
        Assert-FrpTrue ($_.Exception.Message -match 'https') 'http rejected'
    }

    try {
        Normalize-FrpCaSha256 -Value 'deadbeef' | Out-Null
        throw 'expected short fingerprint reject'
    } catch {
        Assert-FrpTrue ($_.Exception.Message -match 'fingerprint') 'short fp rejected'
    }

    Write-FrpTestPass 'test-ca-pinning'
} finally {
    Remove-FrpWindowsTestRoot
}
