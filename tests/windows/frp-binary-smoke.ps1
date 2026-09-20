# Hermetic Windows FRP binary smoke: download + SHA256 + frpc -v against the
# vendored qualified server-local artifact served over loopback HTTPS.
#
# Preserves product fail-closed / no-public-fallback behavior. Does not weaken
# Get-FrpWindowsAmd64Url or Install-FrpWindowsBinary.
#
# TLS materials come from tests/windows/gen_frp_smoke_certs.py (cryptography),
# producing a real CA→leaf chain the product pin validator accepts on WinPS 5.1.
# Non-Windows hosts only verify the URL contract.
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $RepoRoot

. .\windows\lib\FrpPaths.ps1
. .\windows\lib\FrpCrypto.ps1
. .\windows\lib\FrpState.ps1
. .\windows\lib\FrpTls.ps1
. .\windows\lib\FrpBootstrap.ps1

function Get-FrpSmokePython {
    foreach ($cand in @('python', 'python3')) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    throw 'python/python3 required to generate FRP smoke TLS materials'
}

function New-FrpSmokeTlsMaterials {
    param([Parameter(Mandatory = $true)][string]$PkiDir)
    $python = Get-FrpSmokePython
    $gen = Join-Path $RepoRoot 'tests\windows\gen_frp_smoke_certs.py'
    & $python $gen --out-dir $PkiDir
    if ($LASTEXITCODE -ne 0) { throw "gen_frp_smoke_certs.py failed (exit=$LASTEXITCODE)" }
    $status = Join-Path $PkiDir 'status.txt'
    $map = @{}
    Get-Content -LiteralPath $status | ForEach-Object {
        $line = $_.Trim()
        if ($line -match '^(CA_DER|LEAF_DER|LEAF_PFX|LEAF_PASS)=(.*)$') {
            $map[$Matches[1]] = $Matches[2].Trim()
        }
    }
    if ($map.Count -lt 4) {
        Write-Host "smoke cert status dump:`n$((Get-Content -LiteralPath $status) -join "`n")"
    }
    foreach ($k in @('CA_DER', 'LEAF_DER', 'LEAF_PFX', 'LEAF_PASS')) {
        if (-not $map.ContainsKey($k)) { throw "smoke cert status missing $k" }
        if (-not (Test-Path -LiteralPath $map[$k])) { throw "smoke cert file missing: $($map[$k])" }
    }
    return @{
        CaDerPath    = $map['CA_DER']
        LeafPfxPath  = $map['LEAF_PFX']
        LeafPassPath = $map['LEAF_PASS']
        PfxBytes     = [System.IO.File]::ReadAllBytes($map['LEAF_PFX'])
        PfxPassPlain = ([System.IO.File]::ReadAllText($map['LEAF_PASS'])).Trim()
        LeafDer      = [System.IO.File]::ReadAllBytes($map['LEAF_DER'])
    }
}

function Start-FrpQualifiedArtifactHttpsFixture {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)][string]$PkiDir
    )
    if (-not (Test-Path -LiteralPath $PkiDir)) {
        New-Item -ItemType Directory -Path $PkiDir -Force | Out-Null
    }

    $mat = New-FrpSmokeTlsMaterials -PkiDir $PkiDir
    $caDerPath = $mat.CaDerPath

    $leafProbe = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $mat.LeafDer)
    try {
        if (-not (Test-FrpCertificateHostname -Certificate $leafProbe -Hostname '127.0.0.1')) {
            $san = Get-FrpCertificateSanEntries -Certificate $leafProbe
            throw ("fixture leaf rejected by Test-FrpCertificateHostname; dns=[{0}] ip=[{1}] parseFailed={2}" -f `
                (($san.DnsNames) -join ','), (($san.IpAddresses) -join ','), [bool]$san.ParseFailed)
        }
        Write-Host 'FRP_SMOKE_HOSTNAME_PROBE=PASS'
    } finally {
        $leafProbe.Dispose()
    }

    $payload = [System.IO.File]::ReadAllBytes($ZipPath)
    $listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback, 0)
    [void]$listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $origin = "https://127.0.0.1:$port"

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable('Listener', $listener)
    $runspace.SessionStateProxy.SetVariable('PfxBytes', $mat.PfxBytes)
    $runspace.SessionStateProxy.SetVariable('PfxPassPlain', $mat.PfxPassPlain)
    $runspace.SessionStateProxy.SetVariable('ArtifactPath', $ArtifactPath)
    $runspace.SessionStateProxy.SetVariable('Payload', $payload)
    $runspace.SessionStateProxy.SetVariable('ServerError', '')
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    $null = $ps.AddScript({
        $ErrorActionPreference = 'Stop'
        try {
            $pass = New-Object System.Security.SecureString
            foreach ($ch in $PfxPassPlain.ToCharArray()) { $pass.AppendChar($ch) }
            $keyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
            $serverCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxBytes, $pass, $keyFlags)
            try {
                while ($true) {
                    $client = $Listener.AcceptTcpClient()
                    try {
                        $stream = $client.GetStream()
                        $ssl = New-Object System.Net.Security.SslStream($stream, $false)
                        try {
                            $ssl.AuthenticateAsServer(
                                $serverCert,
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
            } finally {
                $serverCert.Dispose()
            }
        } catch {
            $ServerError = ($_ | Out-String)
        }
    })
    $handle = $ps.BeginInvoke()
    Start-Sleep -Milliseconds 200

    return @{
        Origin     = $origin
        Port       = $port
        CaPemPath  = $caDerPath
        Listener   = $listener
        PowerShell = $ps
        Handle     = $handle
        Runspace   = $runspace
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
    try {
        if ($Fixture.Runspace) {
            $err = $Fixture.Runspace.SessionStateProxy.GetVariable('ServerError')
            if ($err) { Write-Host "fixture_server_error=$err" }
        }
    } catch { }
    try { if ($Fixture.PowerShell) { $Fixture.PowerShell.Dispose() } } catch { }
    try { if ($Fixture.Runspace) { $Fixture.Runspace.Dispose() } } catch { }
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

        try {
            [System.Net.ServicePointManager]::SecurityProtocol = ([System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12)
        } catch { }

        $env:FRP_ALLOCATOR_URL = "$origin/enroll"
        $resolvedLive = Get-FrpWindowsAmd64Url
        $expectedLive = "$origin$artifactPath"
        if ($resolvedLive -ne $expectedLive) {
            throw "live URL mismatch: got=$resolvedLive expected=$expectedLive"
        }

        function Invoke-FrpHttpsDownload {
            param(
                [Parameter(Mandatory = $true)][string]$Url,
                [Parameter(Mandatory = $true)][string]$DestinationPath,
                [string]$CaPath,
                [int]$TimeoutSec = 180
            )
            if ($Url -notmatch '^https://') { throw 'ERROR: only https:// URLs are supported' }
            if (-not $CaPath) { $CaPath = Get-FrpAllocatorCaPath }
            if (-not (Test-Path -LiteralPath $CaPath)) {
                throw "ERROR: trusted allocator CA is missing ($CaPath)"
            }
            $expectedHost = $null
            try { $expectedHost = ([Uri]$Url).Host } catch { }
            $pin = New-FrpPinnedServerCertificateValidator -CaPath $CaPath -ExpectedHost $expectedHost
            $previous = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
            try {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $pin.Callback
                $req = [System.Net.HttpWebRequest]::Create($Url)
                $req.Method = 'GET'
                $req.Timeout = $TimeoutSec * 1000
                $req.ReadWriteTimeout = $TimeoutSec * 1000
                $req.KeepAlive = $false
                $req.ProtocolVersion = [System.Net.HttpVersion]::Version11
                $req.ConnectionGroupName = ('frp-art-' + [guid]::NewGuid().ToString('N'))
                try { $req.ServicePoint.Expect100Continue = $false } catch { }
                $resp = $req.GetResponse()
                try {
                    $src = $resp.GetResponseStream()
                    $fs = [System.IO.File]::Create($DestinationPath)
                    try { $src.CopyTo($fs) } finally { $fs.Dispose(); $src.Close() }
                } finally {
                    $resp.Close()
                }
            } catch [System.Net.WebException] {
                $detail = $_.Exception.Message
                if ($_.Exception.InnerException) {
                    $detail = $detail + ' | inner=' + $_.Exception.InnerException.Message
                }
                throw ("ERROR: FRP download failed: " + $detail)
            } finally {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previous
                if ($pin.Ca) { $pin.Ca.Dispose() }
            }
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
