# test-tls-hostname-negative.ps1 — hostname verification must fail closed
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

try {
    $tlsPath = Join-Path $script:WindowsLib 'FrpTls.ps1'
    $tlsSrc = Get-Content -LiteralPath $tlsPath -Raw
    Assert-FrpTrue ($tlsSrc -notmatch '-or\s*\$true') 'FrpTls.ps1 must not contain -or $true bypass'
    Assert-FrpTrue ($tlsSrc -match 'function\s+Test-FrpCertificateHostname') 'Test-FrpCertificateHostname defined'
    Assert-FrpTrue ($tlsSrc -match 'FRP_WINDOWS_FORCE_DOTNET_HTTP') 'force .NET HTTP env hook present'
    Assert-FrpTrue ($tlsSrc -match 'FRP_WINDOWS_FORCE_CURL') 'curl allocator JSON is opt-in'
    Assert-FrpTrue ($tlsSrc -match 'ExpectedHost') 'POST pin validator uses explicit hostname'
    Write-FrpTestPass 'tls-source-no-or-true'

    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $openssl) {
        Write-Host 'SKIP openssl cert generation (openssl unavailable); source guard still enforced'
        Write-FrpTestPass 'test-tls-hostname-negative'
        return
    }

    $work = Join-Path $env:FRP_WINDOWS_ROOT 'tls-hostname'
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $caKey = Join-Path $work 'ca.key'
    $caCrt = Join-Path $work 'ca.crt'
    $goodKey = Join-Path $work 'good.key'
    $goodCsr = Join-Path $work 'good.csr'
    $goodCrt = Join-Path $work 'good.crt'
    $badKey = Join-Path $work 'bad.key'
    $badCsr = Join-Path $work 'bad.csr'
    $badCrt = Join-Path $work 'bad.crt'
    $ipKey = Join-Path $work 'ip.key'
    $ipCsr = Join-Path $work 'ip.csr'
    $ipCrt = Join-Path $work 'ip.crt'
    $wildKey = Join-Path $work 'wild.key'
    $wildCsr = Join-Path $work 'wild.csr'
    $wildCrt = Join-Path $work 'wild.crt'
    $extGood = Join-Path $work 'good.ext'
    $extBad = Join-Path $work 'bad.ext'
    $extIp = Join-Path $work 'ip.ext'
    $extWild = Join-Path $work 'wild.ext'

    & openssl genrsa -out $caKey 2048 2>$null | Out-Null
    & openssl req -new -x509 -key $caKey -out $caCrt -days 2 -subj '/CN=FRP Test CA' 2>$null | Out-Null

    # OpenSSL writes progress to stderr; PS5.1 treats that as a terminating error
    # under $ErrorActionPreference=Stop even when redirected with 2>$null.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & openssl genrsa -out $goodKey 2048 2>$null | Out-Null
    & openssl req -new -key $goodKey -out $goodCsr -subj '/CN=correct.example.test' 2>$null | Out-Null
    Set-Content -LiteralPath $extGood -Value @"
subjectAltName=DNS:correct.example.test,DNS:www.correct.example.test
extendedKeyUsage=serverAuth
"@
    & openssl x509 -req -in $goodCsr -CA $caCrt -CAkey $caKey -CAcreateserial -out $goodCrt -days 2 -extfile $extGood 2>$null | Out-Null

    & openssl genrsa -out $badKey 2048 2>$null | Out-Null
    & openssl req -new -key $badKey -out $badCsr -subj '/CN=wrong.example.test' 2>$null | Out-Null
    Set-Content -LiteralPath $extBad -Value @"
subjectAltName=DNS:wrong.example.test
extendedKeyUsage=serverAuth
"@
    & openssl x509 -req -in $badCsr -CA $caCrt -CAkey $caKey -CAcreateserial -out $badCrt -days 2 -extfile $extBad 2>$null | Out-Null

    & openssl genrsa -out $ipKey 2048 2>$null | Out-Null
    & openssl req -new -key $ipKey -out $ipCsr -subj '/CN=127.0.0.1' 2>$null | Out-Null
    Set-Content -LiteralPath $extIp -Value @"
subjectAltName=IP:127.0.0.1
extendedKeyUsage=serverAuth
"@
    & openssl x509 -req -in $ipCsr -CA $caCrt -CAkey $caKey -CAcreateserial -out $ipCrt -days 2 -extfile $extIp 2>$null | Out-Null

    & openssl genrsa -out $wildKey 2048 2>$null | Out-Null
    & openssl req -new -key $wildKey -out $wildCsr -subj '/CN=wildcard.example.test' 2>$null | Out-Null
    Set-Content -LiteralPath $extWild -Value @"
subjectAltName=DNS:*.example.test
extendedKeyUsage=serverAuth
"@
    & openssl x509 -req -in $wildCsr -CA $caCrt -CAkey $caKey -CAcreateserial -out $wildCrt -days 2 -extfile $extWild 2>$null | Out-Null
    $ErrorActionPreference = $prevEap

    $goodCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($goodCrt)
    $badCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($badCrt)
    $ipCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ipCrt)
    $wildCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($wildCrt)
    try {
        Assert-FrpTrue (Test-FrpCertificateHostname -Certificate $goodCert -Hostname 'correct.example.test') 'correct host PASS'
        Assert-FrpTrue (-not (Test-FrpCertificateHostname -Certificate $goodCert -Hostname 'evil.example.test')) 'wrong host FAIL'
        Assert-FrpTrue (-not (Test-FrpCertificateHostname -Certificate $badCert -Hostname 'correct.example.test')) 'wrong-SAN cert FAIL for correct host'
        Assert-FrpTrue (Test-FrpCertificateHostname -Certificate $ipCert -Hostname '127.0.0.1') 'IP SAN PASS'
        Assert-FrpTrue (-not (Test-FrpCertificateHostname -Certificate $ipCert -Hostname '10.0.0.1')) 'wrong IP FAIL'
        Assert-FrpTrue (Test-FrpCertificateHostname -Certificate $wildCert -Hostname 'a.example.test') 'wildcard single-label PASS'
        Assert-FrpTrue (-not (Test-FrpCertificateHostname -Certificate $wildCert -Hostname 'example.test')) 'wildcard apex FAIL'
        Assert-FrpTrue (-not (Test-FrpCertificateHostname -Certificate $wildCert -Hostname 'a.b.example.test')) 'wildcard multi-label FAIL'
        Assert-FrpTrue (-not (Test-FrpCertificateHostname -Certificate $goodCert -Hostname '')) 'empty hostname FAIL'

        # Manual SAN path / dns helper unit cases (independent of MatchesHostname)
        Assert-FrpTrue (Test-FrpDnsNameMatchesHostname -Pattern 'foo.bar' -Hostname 'foo.bar') 'dns exact'
        Assert-FrpTrue (Test-FrpDnsNameMatchesHostname -Pattern '*.bar.test' -Hostname 'x.bar.test') 'dns wildcard ok'
        Assert-FrpTrue (-not (Test-FrpDnsNameMatchesHostname -Pattern '*.bar.test' -Hostname 'y.x.bar.test')) 'dns wildcard deep fail'

        Write-FrpTestPass 'tls-hostname-unit'
    } finally {
        $goodCert.Dispose()
        $badCert.Dispose()
        $ipCert.Dispose()
        $wildCert.Dispose()
    }

    Write-FrpTestPass 'test-tls-hostname-negative'
} finally {
    Remove-FrpWindowsTestRoot
}
