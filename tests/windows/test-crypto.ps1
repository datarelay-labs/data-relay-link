# test-crypto.ps1 — roundtrip + basic vectors
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $id = New-FrpEcdsaIdentity
    Assert-FrpTrue ($id.PublicPem -match 'BEGIN PUBLIC KEY') 'public pem'
    Assert-FrpTrue ($id.PrivatePem -like '*-*PRIVATE KEY*-*') 'private pem'

    $msg = Get-FrpSignedMessage -MachineId 'machine-deadbeef' -Body '{}' -Timestamp 1700000000 -Nonce ('ab' * 32)
    $sig = Protect-FrpSignMessage -PrivatePem $id.PrivatePem -Message $msg
    Assert-FrpTrue (Test-FrpSignature -PublicPem $id.PublicPem -Message $msg -SignatureBase64 $sig) 'sign/verify'

    $ct = Protect-FrpTokenPbkdf2 -Token 'tok-deadbeef' -Secret 'secret-deadbeef0123456789'
    $pt = Unprotect-FrpTokenPbkdf2 -Ciphertext $ct -Secret 'secret-deadbeef0123456789'
    Assert-FrpEqual 'tok-deadbeef' $pt 'token roundtrip'

    $mac = Get-FrpDerivedMacKey -Secret 'enroll-secret-deadbeef' -MachineId 'machine-deadbeef'
    Assert-FrpEqual 64 $mac.Length 'mac hex length'

    $cj = Get-FrpCanonicalJson -Object (@{ b = 1; a = 2 })
    Assert-FrpEqual '{"a":2,"b":1}' $cj 'canonical sort'

    Write-FrpTestPass 'test-crypto'
} finally {
    Remove-FrpWindowsTestRoot
}
