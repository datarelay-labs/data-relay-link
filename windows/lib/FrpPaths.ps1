# FrpPaths.ps1 — filesystem layout for the Windows FRP client.
# Dot-source only. Respects FRP_WINDOWS_ROOT for non-Windows / test hosts.

if ((Test-Path variable:script:FrpPathsLoaded) -and $script:FrpPathsLoaded) { return }
$script:FrpPathsLoaded = $true

function Test-FrpIsWindowsHost {
    $edition = $null
    if ($PSVersionTable.ContainsKey('PSEdition')) {
        $edition = [string]$PSVersionTable['PSEdition']
    }
    if ($edition -eq 'Core') {
        $isWin = $false
        try { $isWin = [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction Stop) } catch { $isWin = $false }
        return $isWin
    }
    return ($env:OS -match 'Windows_NT')
}

function Get-FrpWindowsRoot {
    if ($env:FRP_WINDOWS_ROOT -and $env:FRP_WINDOWS_ROOT.Trim().Length -gt 0) {
        return $env:FRP_WINDOWS_ROOT.Trim().TrimEnd('\', '/')
    }
    if (-not (Test-FrpIsWindowsHost)) {
        $fallback = '/tmp/frp-auto-deploy-windows-test'
        return $fallback
    }
    return (Join-Path $env:ProgramData 'frp-auto-deploy')
}

function Get-FrpBinDir { Join-Path (Get-FrpWindowsRoot) 'bin' }
function Get-FrpConfigDir { Join-Path (Get-FrpWindowsRoot) 'config' }
function Get-FrpStateDir { Join-Path (Get-FrpWindowsRoot) 'state' }
function Get-FrpCertsDir { Join-Path (Get-FrpWindowsRoot) 'certs' }
function Get-FrpLogsDir { Join-Path (Get-FrpWindowsRoot) 'logs' }
function Get-FrpToolsDir { Join-Path (Get-FrpWindowsRoot) 'tools' }
function Get-FrpLibDir { Join-Path (Get-FrpWindowsRoot) 'lib' }
function Get-FrpBackupDir { Join-Path (Get-FrpWindowsRoot) 'backups' }

function Get-FrpFrpcPath { Join-Path (Get-FrpBinDir) 'frpc.exe' }
function Get-FrpTomlPath { Join-Path (Get-FrpConfigDir) 'frpc.toml' }
function Get-FrpStatePath { Join-Path (Get-FrpStateDir) 'client-state.json' }
function Get-FrpClientIdPath { Join-Path (Get-FrpStateDir) 'client-id' }
function Get-FrpIdentityKeyPath {
    $root = Get-FrpStateDir
    $dpapi = Join-Path $root 'client-identity.key.dpapi'
    $plain = Join-Path $root 'client-identity.key'
    if (Test-Path -LiteralPath $dpapi) { return $dpapi }
    if (Test-Path -LiteralPath $plain) { return $plain }
    # Prefer DPAPI path on Windows; plain key path elsewhere / until written.
    if (Test-FrpIsWindowsHost) { return $dpapi }
    return $plain
}
function Get-FrpIdentityPubPath { Join-Path (Get-FrpStateDir) 'client-identity.pub' }
function Get-FrpIdentityMacPath { Join-Path (Get-FrpStateDir) 'client-identity.mac' }
function Get-FrpAllocatorCaPath { Join-Path (Get-FrpCertsDir) 'allocator-ca.crt' }
function Get-FrpLogPath { Join-Path (Get-FrpLogsDir) 'frpc.log' }
function Get-FrpPidPath { Join-Path (Get-FrpLogsDir) 'frpc.pid' }
function Get-FrpVersionPath { Join-Path (Get-FrpWindowsRoot) 'version' }

function Get-FrpProjectVersion {
    if ($env:PROJECT_VERSION -and $env:PROJECT_VERSION.Trim().Length -gt 0) {
        return $env:PROJECT_VERSION.Trim()
    }
    # Prefer installed version file (written at install/update).
    try {
        $verPath = Get-FrpVersionPath
        if (Test-Path -LiteralPath $verPath) {
            foreach ($line in Get-Content -LiteralPath $verPath -ErrorAction Stop) {
                if ($line -match '^\s*PROJECT_VERSION\s*=\s*(.+)\s*$') {
                    $v = $Matches[1].Trim()
                    if ($v) { return $v }
                }
            }
        }
    } catch { }
    # Packaged fallback must track canonical VERSION (do not hardcode stale releases).
    return '2.1.3'
}

function Get-FrpUpstreamVersion {
    if ($env:FRP_VERSION -and $env:FRP_VERSION.Trim().Length -gt 0) {
        return $env:FRP_VERSION.Trim()
    }
    return '0.70.1'
}

function Get-FrpWindowsAmd64Sha256 {
    if ($env:FRP_SHA256_WINDOWS_AMD64 -and $env:FRP_SHA256_WINDOWS_AMD64.Trim().Length -gt 0) {
        return $env:FRP_SHA256_WINDOWS_AMD64.Trim().ToLowerInvariant()
    }
    return '531f3cd3cc41c0b4f077b54fe6b7dd83c0ff727e7f0bf412a4c78fa279165de5'
}

function Get-FrpWindowsAmd64Url {
    $ver = Get-FrpUpstreamVersion
    if ($env:FRP_WINDOWS_DOWNLOAD_URL -and $env:FRP_WINDOWS_DOWNLOAD_URL.Trim().Length -gt 0) {
        return $env:FRP_WINDOWS_DOWNLOAD_URL.Trim()
    }
    return "https://github.com/fatedier/frp/releases/download/v${ver}/frp_${ver}_windows_amd64.zip"
}
