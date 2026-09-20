# Hermetic Windows FRP binary smoke: download + SHA256 + frpc -v against the
# vendored qualified server-local artifact served over loopback HTTPS.
#
# Preserves product fail-closed / no-public-fallback behavior. Does not weaken
# Get-FrpWindowsAmd64Url or Install-FrpWindowsBinary.
#
# TLS materials: tests/windows/gen_frp_smoke_certs.py (cryptography).
# HTTPS fixture: tests/windows/serve_frp_smoke_https.py (stdlib ssl).
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
    throw 'python/python3 required for FRP smoke TLS fixture'
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

    $python = Get-FrpSmokePython
    $fixtureRoot = Join-Path $tempRoot ('frp-frpc-fixture-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    $pkiDir = Join-Path $fixtureRoot 'pki'
    $statusFile = Join-Path $fixtureRoot 'status.txt'
    $server = $null
    try {
        & $python (Join-Path $RepoRoot 'tests\windows\gen_frp_smoke_certs.py') --out-dir $pkiDir
        if ($LASTEXITCODE -ne 0) { throw "gen_frp_smoke_certs.py failed (exit=$LASTEXITCODE)" }

        $map = @{}
        Get-Content -LiteralPath (Join-Path $pkiDir 'status.txt') | ForEach-Object {
            $line = $_.Trim()
            if ($line -match '^(CA_DER|LEAF_PEM|LEAF_KEY)=(.*)$') {
                $map[$Matches[1]] = $Matches[2].Trim()
            }
        }
        foreach ($k in @('CA_DER', 'LEAF_PEM', 'LEAF_KEY')) {
            if (-not $map.ContainsKey($k)) { throw "smoke cert status missing $k" }
        }

        $leafProbe = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, ([System.IO.File]::ReadAllBytes((Join-Path $pkiDir 'leaf.crt'))))
        try {
            if (-not (Test-FrpCertificateHostname -Certificate $leafProbe -Hostname 'localhost')) {
                throw 'fixture leaf rejected by Test-FrpCertificateHostname for localhost'
            }
            Write-Host 'FRP_SMOKE_HOSTNAME_PROBE=PASS'
        } finally {
            $leafProbe.Dispose()
        }

        $server = Start-Process -FilePath $python -ArgumentList @(
            (Join-Path $RepoRoot 'tests\windows\serve_frp_smoke_https.py'),
            '--zip-path', $zipPath,
            '--artifact-path', $artifactPath,
            '--cert-pem', $map['LEAF_PEM'],
            '--key-pem', $map['LEAF_KEY'],
            '--status-file', $statusFile,
            '--origin-host', 'localhost'
        ) -PassThru -WindowStyle Hidden -WorkingDirectory $RepoRoot

        $origin = $null
        for ($i = 0; $i -lt 100; $i++) {
            if (Test-Path -LiteralPath $statusFile) {
                Get-Content -LiteralPath $statusFile | ForEach-Object {
                    if ($_ -match '^ORIGIN=(.*)$') { $origin = $Matches[1].Trim() }
                }
                if ($origin) { break }
            }
            if ($server.HasExited) { throw "smoke HTTPS server exited early (code=$($server.ExitCode))" }
            Start-Sleep -Milliseconds 100
        }
        if (-not $origin) { throw 'smoke HTTPS server did not publish ORIGIN' }

        $caDest = Get-FrpAllocatorCaPath
        $caDir = Split-Path -Parent $caDest
        if (-not (Test-Path -LiteralPath $caDir)) {
            New-Item -ItemType Directory -Path $caDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $map['CA_DER'] -Destination $caDest -Force

        try {
            [System.Net.ServicePointManager]::SecurityProtocol = ([System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12)
        } catch { }

        $env:FRP_ALLOCATOR_URL = "$origin/enroll"
        $resolvedLive = Get-FrpWindowsAmd64Url
        $expectedLive = "$origin$artifactPath"
        if ($resolvedLive -ne $expectedLive) {
            throw "live URL mismatch: got=$resolvedLive expected=$expectedLive"
        }
        Write-Host "FRP_WINDOWS_AMD64_URL_LIVE=PASS url=$resolvedLive"

        # Live pin preflight: prove ServicePointManager callback accepts the fixture
        # using the product validator (must be self-contained for WinPS 5.1).
        $caPath = Get-FrpAllocatorCaPath
        $expectedHost = ([Uri]$resolvedLive).Host
        $pin = New-FrpPinnedServerCertificateValidator -CaPath $caPath -ExpectedHost $expectedHost
        $diag = [ordered]@{ Hits = 0; Result = $false }
        $innerCb = $pin.Callback
        $diagCb = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            $diag.Hits++
            $r = [bool](& $innerCb $sender $certificate $chain $sslPolicyErrors)
            $diag.Result = $r
            return $r
        }.GetNewClosure()
        $prevCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        $preflightPath = Join-Path $fixtureRoot 'preflight.bin'
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $diagCb
            $req = [System.Net.HttpWebRequest]::Create($resolvedLive)
            $req.Method = 'GET'
            $req.Timeout = 30000
            $req.ReadWriteTimeout = 30000
            $req.KeepAlive = $false
            $resp = $req.GetResponse()
            try {
                $src = $resp.GetResponseStream()
                $fs = [System.IO.File]::Create($preflightPath)
                try { $src.CopyTo($fs) } finally { $fs.Dispose(); $src.Close() }
            } finally {
                $resp.Close()
            }
            Write-Host "FRP_SMOKE_PIN_PREFLIGHT=PASS hits=$($diag.Hits) result=$($diag.Result)"
        } catch {
            Write-Host "FRP_SMOKE_PIN_PREFLIGHT=FAIL hits=$($diag.Hits) result=$($diag.Result) err=$($_.Exception.Message)"
            throw
        } finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb
            if ($pin.Ca) { $pin.Ca.Dispose() }
            Remove-Item -LiteralPath $preflightPath -Force -ErrorAction SilentlyContinue
        }

        # Exercise the product Install-FrpWindowsBinary → Invoke-FrpHttpsDownload path
        # (no local override) so WinPS 5.1 CI covers the real pin callback.
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
        if ($server -and -not $server.HasExited) {
            Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
            try { $server.WaitForExit(5000) | Out-Null } catch { }
        }
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item -LiteralPath $clientRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_ROOT -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_ALLOCATOR_URL -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_DOWNLOAD_URL -ErrorAction SilentlyContinue
}
