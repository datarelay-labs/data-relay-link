# FrpConfig.ps1 — render frpc.toml matching Linux client semantics.

if ((Test-Path variable:script:FrpConfigLoaded) -and $script:FrpConfigLoaded) { return }
$script:FrpConfigLoaded = $true

function Escape-FrpTomlString {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $s = [string]$Value
    $s = $s.Replace('\', '\\').Replace('"', '\"')
    return $s
}

function New-FrpClientToml {
    param(
        [Parameter(Mandatory = $true)][string]$ServerAddr,
        [Parameter(Mandatory = $true)][int]$ServerPort,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$HostId,
        [Parameter(Mandatory = $true)]$Services,
        [string]$Transport = 'tcp',
        [string]$TrustedCaFile,
        [string]$DestinationPath
    )
    if (-not $DestinationPath) { $DestinationPath = Get-FrpTomlPath }
    $transport = ([string]$Transport).Trim().ToLowerInvariant()
    if (-not $transport) { $transport = 'tcp' }
    if ($transport -ne 'tcp' -and $transport -ne 'wss') {
        throw 'ERROR: unsupported FRP transport'
    }
    if ($transport -eq 'wss') {
        if (-not $TrustedCaFile) { $TrustedCaFile = Get-FrpAllocatorCaPath }
        if (-not (Test-Path -LiteralPath $TrustedCaFile)) {
            throw 'ERROR: allocator CA is required for WSS FRP control'
        }
    }

    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add(('serverAddr = "{0}"' -f (Escape-FrpTomlString $ServerAddr)))
    [void]$lines.Add(('serverPort = {0}' -f [int]$ServerPort))
    [void]$lines.Add('')
    [void]$lines.Add('auth.method = "token"')
    [void]$lines.Add(('auth.token = "{0}"' -f (Escape-FrpTomlString $Token)))
    [void]$lines.Add('')
    [void]$lines.Add('transport.tls.enable = true')
    if ($transport -eq 'wss') {
        # FRP hard-codes websocket path /~!frp; not configurable.
        [void]$lines.Add('transport.protocol = "wss"')
        [void]$lines.Add(('transport.tls.trustedCaFile = "{0}"' -f (Escape-FrpTomlString $TrustedCaFile)))
    }

    $map = ConvertTo-FrpServiceMap -Services $Services
    foreach ($sid in $map.Keys) {
        $item = $map[$sid]
        if ($item.enabled -eq $false) { continue }
        if ($null -eq $item.remote_port) {
            throw ("ERROR: service '{0}' is missing remote_port" -f $sid)
        }
        [void]$lines.Add('')
        [void]$lines.Add('[[proxies]]')
        [void]$lines.Add(('name = "{0}-{1}"' -f (Escape-FrpTomlString $HostId), (Escape-FrpTomlString $item.id)))
        [void]$lines.Add('type = "tcp"')
        [void]$lines.Add(('localIP = "{0}"' -f (Escape-FrpTomlString $item.local_ip)))
        [void]$lines.Add(('localPort = {0}' -f [int]$item.local_port))
        [void]$lines.Add(('remotePort = {0}' -f [int]$item.remote_port))
    }

    $text = ($lines -join "`n") + "`n"
    $dir = Split-Path -Parent $DestinationPath
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $tmp = Join-Path $dir ("frpc.toml." + [guid]::NewGuid().ToString('N') + '.tmp')
    [System.IO.File]::WriteAllText($tmp, $text)
    Restrict-FrpFileAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $DestinationPath -Force
    Restrict-FrpFileAcl -Path $DestinationPath
    return $DestinationPath
}

function Test-FrpClientToml {
    param([string]$TomlPath, [string]$FrpcPath)
    if (-not $TomlPath) { $TomlPath = Get-FrpTomlPath }
    if (-not $FrpcPath) { $FrpcPath = Get-FrpFrpcPath }
    if (-not (Test-Path -LiteralPath $FrpcPath)) {
        return @{ Ok = $false; Skipped = $true; Message = 'frpc.exe not available' }
    }
    if (-not (Test-Path -LiteralPath $TomlPath)) {
        return @{ Ok = $false; Skipped = $false; Message = 'frpc.toml missing' }
    }
    # On Linux test hosts frpc.exe cannot run; skip.
    if (-not (Test-FrpIsWindowsHost)) {
        return @{ Ok = $true; Skipped = $true; Message = 'verify skipped on non-Windows host' }
    }
    $p = Start-Process -FilePath $FrpcPath -ArgumentList @('verify', '-c', $TomlPath) -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path (Get-FrpLogsDir) 'verify.out') `
        -RedirectStandardError (Join-Path (Get-FrpLogsDir) 'verify.err')
    if ($p.ExitCode -eq 0) {
        return @{ Ok = $true; Skipped = $false; Message = 'ok' }
    }
    return @{ Ok = $false; Skipped = $false; Message = 'frpc verify failed' }
}

function Get-FrpTokenFromToml {
    param([string]$TomlPath)
    if (-not $TomlPath) { $TomlPath = Get-FrpTomlPath }
    if (-not (Test-Path -LiteralPath $TomlPath)) { return $null }
    foreach ($line in [System.IO.File]::ReadAllLines($TomlPath)) {
        if ($line -match '^\s*auth\.token\s*=\s*"(.*)"\s*$') {
            return $Matches[1]
        }
    }
    return $null
}
