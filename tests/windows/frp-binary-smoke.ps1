# Hermetic Windows FRP binary smoke: download + SHA256 + frpc -v against the
# vendored qualified server-local artifact served over loopback HTTPS.
#
# Preserves product fail-closed / no-public-fallback behavior. Does not weaken
# Get-FrpWindowsAmd64Url or Install-FrpWindowsBinary.
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $RepoRoot

. .\windows\lib\FrpPaths.ps1
. .\windows\lib\FrpCrypto.ps1
. .\windows\lib\FrpState.ps1
. .\windows\lib\FrpTls.ps1
. .\windows\lib\FrpBootstrap.ps1

$ver = Get-FrpUpstreamVersion
$zipPath = [System.IO.Path]::Combine($RepoRoot, 'third_party', 'frp', "v$ver", 'binaries', "frp_${ver}_windows_amd64.zip")
if (-not (Test-Path -LiteralPath $zipPath)) {
    throw "qualified Windows FRP zip missing: $zipPath"
}
$artifactPath = "/artifacts/frp/$ver/frp_${ver}_windows_amd64.zip"

# URL contract is pure string construction from FRP_ALLOCATOR_URL origin.
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

    # Install-FrpWindowsBinary uses ServicePointManager pin callbacks that are
    # reliable on Windows PowerShell 5.1 (CI target). Exercise download+hash+
    # extract+version only on Windows with a hermetic Python HTTPS fixture.
    if ($env:OS -ne 'Windows_NT') {
        Write-Host 'FRP_BINARY_SMOKE=PASS_CONTRACT_ONLY'
        return
    }

    $python = $null
    foreach ($cand in @('python3', 'python')) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) { $python = $cmd.Source; break }
    }
    if (-not $python) { throw 'python3/python required for Windows FRP binary smoke fixture' }

    $fixtureRoot = Join-Path $tempRoot ('frp-frpc-fixture-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    $pkiDir = Join-Path $fixtureRoot 'pki'
    $statusFile = Join-Path $fixtureRoot 'status.txt'
    $serverScript = Join-Path $RepoRoot 'tests\windows\serve_qualified_frp_https.py'
    $server = Start-Process -FilePath $python -ArgumentList @(
        $serverScript,
        '--frp-version', $ver,
        '--zip-path', $zipPath,
        '--pki-dir', $pkiDir,
        '--status-file', $statusFile
    ) -PassThru -WindowStyle Hidden -WorkingDirectory $RepoRoot
    try {
        $origin = $null
        $caCrt = $null
        for ($i = 0; $i -lt 100; $i++) {
            if (Test-Path -LiteralPath $statusFile) {
                $map = @{}
                Get-Content -LiteralPath $statusFile | ForEach-Object {
                    if ($_ -match '^(ORIGIN|CA_CRT)=(.*)$') {
                        $map[$Matches[1]] = $Matches[2]
                    }
                }
                if ($map.ContainsKey('ORIGIN') -and $map.ContainsKey('CA_CRT')) {
                    $origin = $map['ORIGIN']
                    $caCrt = $map['CA_CRT']
                    break
                }
            }
            if ($server.HasExited) {
                throw "fixture server exited early (code=$($server.ExitCode))"
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not $origin -or -not $caCrt) {
            throw 'fixture server did not publish ORIGIN/CA_CRT'
        }

        $caDest = Get-FrpAllocatorCaPath
        $caDir = Split-Path -Parent $caDest
        if (-not (Test-Path -LiteralPath $caDir)) {
            New-Item -ItemType Directory -Path $caDir -Force | Out-Null
        }
        # Product path is PEM (allocator-ca.crt); match that format for the pin.
        Copy-Item -LiteralPath $caCrt -Destination $caDest -Force

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
