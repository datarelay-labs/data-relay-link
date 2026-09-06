# test-cross-language.ps1 — Python ↔ PowerShell vectors
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

$crossDir = Join-Path $PSScriptRoot 'cross'
$gen = Join-Path $crossDir 'generate_python_vectors.py'
$verify = Join-Path $crossDir 'verify_ps_signature.py'
$vectorsPath = Join-Path $crossDir 'vectors.json'

try {
    Assert-FrpTrue (Test-Path -LiteralPath $gen) 'generator exists'
    $env:PYTHONUTF8 = '1'
    $env:PYTHONIOENCODING = 'utf-8'
    & python3 $gen
    if ($LASTEXITCODE -ne 0) { throw 'generator failed' }
    Assert-FrpTrue (Test-Path -LiteralPath $vectorsPath) 'vectors.json written'

    $v = Get-Content -LiteralPath $vectorsPath -Raw -Encoding UTF8 | ConvertFrom-Json

    # PowerShell decrypts Python ciphertext
    $pt = Unprotect-FrpTokenPbkdf2 -Ciphertext $v.token_ciphertext_python -Secret $v.secret
    Assert-FrpEqual $v.token $pt 'PS decrypts Python ciphertext'

    # Python decrypts PowerShell ciphertext
    $psCt = Protect-FrpTokenPbkdf2 -Token $v.token -Secret $v.secret
    $env:FRP_ENROLL_SECRET = $v.secret
    $pyPt = $psCt | & python3 (Join-Path $script:RepoRoot 'lib/frp_mgmt_auth.py') decrypt-token
    Remove-Item Env:FRP_ENROLL_SECRET -ErrorAction SilentlyContinue
    Assert-FrpTrue ($null -ne $pyPt) 'Python decrypt produced output'
    Assert-FrpEqual $v.token ([string]$pyPt).Trim() 'Python decrypts PS ciphertext'

    # MAC derivation matches
    $mac = Get-FrpDerivedMacKey -Secret $v.secret -MachineId $v.machine_id
    Assert-FrpEqual $v.derive_mac_key $mac 'derive_mac_key match'

    # Canonical signed message matches Python
    $msg = Get-FrpSignedMessage -MachineId $v.machine_id -Body $v.body -Timestamp ([int64]$v.ts) -Nonce $v.nonce
    Assert-FrpEqual $v.signed_message $msg 'signed_message match'

    # PowerShell verifies Python signature
    Assert-FrpTrue (
        Test-FrpSignature -PublicPem $v.python_public_pem -Message $v.signed_message -SignatureBase64 $v.python_signature_b64
    ) 'PS verifies Python signature'

    # PowerShell signs; Python verifies
    $id = New-FrpEcdsaIdentity
    $sig = Protect-FrpSignMessage -PrivatePem $id.PrivatePem -Message $msg
    $pubFile = Join-Path $crossDir 'ps-pub.pem'
    [System.IO.File]::WriteAllText($pubFile, $id.PublicPem)
    & python3 $verify --pubkey-pem $pubFile --body $v.body --ts $v.ts --nonce $v.nonce `
        --machine-id $v.machine_id --sig-b64 $sig
    if ($LASTEXITCODE -ne 0) { throw 'Python verify of PS signature failed' }

    # Canonical sample
    $sample = Get-FrpCanonicalJson -Object (@{ b = 1; a = 2; z = @('x', 'y'); n = $null; t = $true })
    Assert-FrpEqual $v.canonical_sample $sample 'canonical sample match'

    Write-FrpTestPass 'test-cross-language'
} finally {
    Remove-Item Env:FRP_ENROLL_SECRET -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
