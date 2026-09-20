# Hermetic Windows FRP binary smoke: download + SHA256 + frpc -v against the
# vendored qualified server-local artifact served over loopback HTTPS.
#
# Preserves product fail-closed / no-public-fallback behavior. Does not weaken
# Get-FrpWindowsAmd64Url or Install-FrpWindowsBinary.
#
# On Windows (CI target: PowerShell 5.1) the HTTPS fixture is .NET SslStream +
# CertificateRequest (no OpenSSL). Non-Windows hosts only verify the URL contract.
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $RepoRoot

. .\windows\lib\FrpPaths.ps1
. .\windows\lib\FrpCrypto.ps1
. .\windows\lib\FrpState.ps1
. .\windows\lib\FrpTls.ps1
. .\windows\lib\FrpBootstrap.ps1

function New-FrpSmokeServerCertificate {
    # CertificateRequest + IP SAN — same API surface already used by WinPS 5.1
    # unit tests (e.g. test-ticket-scope.ps1). Avoid New-SelfSignedCertificate
    # TextExtension IP SAN quirks that fail product hostname pinning.
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        'CN=127.0.0.1',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
    $san.AddIpAddress([System.Net.IPAddress]::Parse('127.0.0.1'))
    $req.CertificateExtensions.Add($san.Build($false))
    $req.CertificateExtensions.Add(
        (New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($true, $false, 0, $true))
    )
    $ku = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign
    $req.CertificateExtensions.Add(
        (New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension($ku, $true))
    )
    $oids = New-Object System.Security.Cryptography.OidCollection
    [void]$oids.Add((New-Object System.Security.Cryptography.Oid '1.3.6.1.5.5.7.3.1'))
    $req.CertificateExtensions.Add(
        (New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oids, $false))
    )
    $ephemeral = $req.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddDays(-1),
        [DateTimeOffset]::UtcNow.AddDays(2)
    )
    $pfxPass = New-Object System.Security.SecureString
    foreach ($ch in ([guid]::NewGuid().ToString('N').ToCharArray())) { $pfxPass.AppendChar($ch) }
    $pfxBytes = $ephemeral.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
        $pfxPass
    )
    $der = $ephemeral.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $ephemeral.Dispose()
    $serverCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $pfxBytes,
        $pfxPass,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    )
    return @{
        ServerCert = $serverCert
        DerBytes   = $der
        Rsa        = $rsa
    }
}

function Start-FrpQualifiedArtifactHttpsFixture {
    <#
    .SYNOPSIS
      Loopback TLS server that serves one qualified Windows FRP zip path.
      Uses the same .NET TLS stack the product download path pins against.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)][string]$PkiDir
    )
    if (-not (Test-Path -LiteralPath $PkiDir)) {
        New-Item -ItemType Directory -Path $PkiDir -Force | Out-Null
    }

    $built = New-FrpSmokeServerCertificate
    $serverCert = $built.ServerCert
    $caDerPath = Join-Path $PkiDir 'ca.crt'
    [System.IO.File]::WriteAllBytes($caDerPath, $built.DerBytes)

    $probe = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $built.DerBytes)
    try {
        if (-not (Test-FrpCertificateHostname -Certificate $probe -Hostname '127.0.0.1')) {
            $san = Get-FrpCertificateSanEntries -Certificate $probe
            throw ("fixture cert rejected by Test-FrpCertificateHostname; dns=[{0}] ip=[{1}] parseFailed={2}" -f `
                (($san.DnsNames) -join ','), (($san.IpAddresses) -join ','), [bool]$san.ParseFailed)
        }
    } finally {
        $probe.Dispose()
    }

    $payload = [System.IO.File]::ReadAllBytes($ZipPath)
    $listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback, 0)
    [void]$listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $origin = "https://127.0.0.1:$port"

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    # PS 5.1: [void]$obj.Foo().Bar() voids Foo()'s result before Bar() — do not void mid-chain.
    $null = $ps.AddScript({
        param($Listener, $ServerCert, $ArtifactPath, $Payload)
        $ErrorActionPreference = 'Stop'
        try {
            while ($true) {
                $client = $Listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $ssl = New-Object System.Net.Security.SslStream($stream, $false)
                    try {
                        $ssl.AuthenticateAsServer(
                            $ServerCert,
                            $false,
                            [System.Security.Authentication.SslProtocols]::Tls12,
                            $false
                        )
                        $reader = New-Object System.IO.StreamReader($ssl, [System.Text.Encoding]::ASCII, $false, 1024, $true)
                        $requestLine = $reader.ReadLine()
                        while ($true) {
                            $line = $reader.ReadLine()
                            if ($null -eq $line -or $line.Length -eq 0) { break }
                        }
                        $path = ''
                        if ($requestLine -match '^(GET|HEAD)\s+(\S+)\s+HTTP/') {
                            $path = $Matches[2]
                        }
                        if ($path -eq $ArtifactPath) {
                            $header = "HTTP/1.1 200 OK`r`nContent-Type: application/zip`r`nContent-Length: $($Payload.Length)`r`nConnection: close`r`n`r`n"
                            $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
                            $ssl.Write($headerBytes, 0, $headerBytes.Length)
                            if ($requestLine.StartsWith('GET')) {
                                $ssl.Write($Payload, 0, $Payload.Length)
                            }
                            $ssl.Flush()
                        } else {
                            $body = [System.Text.Encoding]::ASCII.GetBytes('not found')
                            $header = "HTTP/1.1 404 Not Found`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
                            $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
                            $ssl.Write($headerBytes, 0, $headerBytes.Length)
                            $ssl.Write($body, 0, $body.Length)
                            $ssl.Flush()
                        }
                    } finally {
                        $ssl.Dispose()
                    }
                } finally {
                    $client.Close()
                }
            }
        } catch {
            # Listener stop / dispose ends the accept loop.
        }
    })
    $null = $ps.AddArgument($listener).AddArgument($serverCert).AddArgument($ArtifactPath).AddArgument($payload)
    $handle = $ps.BeginInvoke()

    return @{
        Origin     = $origin
        Port       = $port
        CaPemPath  = $caDerPath
        Listener   = $listener
        PowerShell = $ps
        Handle     = $handle
        Runspace   = $runspace
        ServerCert = $serverCert
        Rsa        = $built.Rsa
    }
}

function Stop-FrpQualifiedArtifactHttpsFixture {
    param($Fixture)
    if (-not $Fixture) { return }
    try { if ($Fixture.Listener) { $Fixture.Listener.Stop() } } catch { }
    try {
        if ($Fixture.PowerShell -and $Fixture.Handle) {
            $Fixture.PowerShell.EndInvoke($Fixture.Handle) | Out-Null
        }
    } catch { }
    try { if ($Fixture.PowerShell) { $Fixture.PowerShell.Dispose() } } catch { }
    try { if ($Fixture.Runspace) { $Fixture.Runspace.Dispose() } } catch { }
    try { if ($Fixture.ServerCert) { $Fixture.ServerCert.Dispose() } } catch { }
    try { if ($Fixture.Rsa) { $Fixture.Rsa.Dispose() } } catch { }
}

$ver = Get-FrpUpstreamVersion
$zipPath = [System.IO.Path]::Combine($RepoRoot, 'third_party', 'frp', "v$ver", 'binaries', "frp_${ver}_windows_amd64.zip")
if (-not (Test-Path -LiteralPath $zipPath)) {
    throw "qualified Windows FRP zip missing: $zipPath"
}
$artifactPath = "/artifacts/frp/$ver/frp_${ver}_windows_amd64.zip"

$tempRoot = [System.IO.Path]::GetTempPath().TrimEnd('\', '/')
$clientRoot = Join-Path $tempRoot ('frp-frpc-smoke-' + [guid]::NewGuid().ToString('N'))
$env:FRP_WINDOWS_ROOT = $clientRoot
try {
    Initialize-FrpDirectories | Out-Null
    $env:FRP_ALLOCATOR_URL = 'https://127.0.0.1:65535/enroll'
    Remove-Item Env:FRP_WINDOWS_DOWNLOAD_URL -ErrorAction SilentlyContinue
    $resolved = Get-FrpWindowsAmd64Url
    $expectedContract = "https://127.0.0.1:65535$artifactPath"
    if ($resolved -ne $expectedContract) {
        throw "URL contract mismatch: got=$resolved expected=$expectedContract"
    }
    Write-Host "FRP_WINDOWS_AMD64_URL_CONTRACT=PASS url=$resolved"

    if ($env:OS -ne 'Windows_NT') {
        Write-Host 'FRP_BINARY_SMOKE=PASS_CONTRACT_ONLY'
        return
    }

    $fixtureRoot = Join-Path $tempRoot ('frp-frpc-fixture-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    $pkiDir = Join-Path $fixtureRoot 'pki'
    $fixture = $null
    try {
        $fixture = Start-FrpQualifiedArtifactHttpsFixture -ZipPath $zipPath -ArtifactPath $artifactPath -PkiDir $pkiDir
        $origin = $fixture.Origin
        $caCrt = $fixture.CaPemPath

        $caDest = Get-FrpAllocatorCaPath
        $caDir = Split-Path -Parent $caDest
        if (-not (Test-Path -LiteralPath $caDir)) {
            New-Item -ItemType Directory -Path $caDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $caCrt -Destination $caDest -Force

        # WinPS 5.1 defaults can omit TLS1.2; product download requires https.
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = `
                [System.Net.ServicePointManager]::SecurityProtocol -bor
                [System.Net.SecurityProtocolType]::Tls12
        } catch { }

        $env:FRP_ALLOCATOR_URL = "$origin/enroll"
        $resolvedLive = Get-FrpWindowsAmd64Url
        $expectedLive = "$origin$artifactPath"
        if ($resolvedLive -ne $expectedLive) {
            throw "live URL mismatch: got=$resolvedLive expected=$expectedLive"
        }

        Install-FrpWindowsBinary | Out-Null
        $frpc = Get-FrpFrpcPath
        if (-not (Test-Path -LiteralPath $frpc)) {
            throw 'frpc.exe missing after Install-FrpWindowsBinary'
        }
        & $frpc -v
        if ($LASTEXITCODE -ne 0) {
            throw "frpc -v failed (exit=$LASTEXITCODE)"
        }
        Write-Host 'FRP_BINARY_SMOKE=PASS'
    } finally {
        Stop-FrpQualifiedArtifactHttpsFixture -Fixture $fixture
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item -LiteralPath $clientRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_ROOT -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_ALLOCATOR_URL -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_DOWNLOAD_URL -ErrorAction SilentlyContinue
}
