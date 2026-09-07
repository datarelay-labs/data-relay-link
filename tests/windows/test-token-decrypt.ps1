# test-token-decrypt.ps1
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $secret = 'secret-deadbeef0123456789abcdef'
    $token = 'frp-token-deadbeef-do-not-use'
    $ct = Protect-FrpTokenPbkdf2 -Token $token -Secret $secret
    Assert-FrpTrue ($ct.Length -gt 20) 'ciphertext present'
    $pt = Unprotect-FrpTokenPbkdf2 -Ciphertext $ct -Secret $secret
    Assert-FrpEqual $token $pt 'decrypt matches'

    $raw = [Convert]::FromBase64String($ct)
    $magic = [System.Text.Encoding]::ASCII.GetString($raw, 0, 8)
    Assert-FrpEqual 'Salted__' $magic 'openssl magic'

    Write-FrpTestPass 'test-token-decrypt'
} finally {
    Remove-FrpWindowsTestRoot
}
