#Requires -Version 5.1
<#
.SYNOPSIS
  frp-client lifecycle tool for Windows (start/stop/status/info/update/uninstall/doctor/support-bundle/autostart).
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        'start', 'stop', 'status', 'info', 'update', 'uninstall', 'doctor', 'support-bundle', 'autostart', 'help',
        'list', 'add-service', 'add', 'set-service', 'enable-service', 'disable-service',
        'apply', 'discard', 'sync', 'reconcile', 'pause', 'resume'
    )]
    [string]$Command = 'help',

    [Parameter(Position = 1)][string]$Id,
    [Parameter(Position = 2)][string]$Property,
    [Parameter(Position = 3)][string]$Value,

    [switch]$Check,
    [switch]$Force,
    [string]$DownloadUrl,
    [string]$ExpectedSha256,

    [string]$Preset = 'custom',
    [string]$Name,
    [string]$TargetHost = '127.0.0.1',
    [int]$TargetPort,
    [string]$SshUser,

    [switch]$Enable,
    [switch]$Disable,

    [string]$Output
)

$ErrorActionPreference = 'Stop'

function Import-FrpWindowsModules {
    $roots = New-Object System.Collections.ArrayList
    [void]$roots.Add((Join-Path $PSScriptRoot '..\lib'))
    if ($env:FRP_WINDOWS_ROOT) {
        [void]$roots.Add((Join-Path $env:FRP_WINDOWS_ROOT 'lib'))
    }
    if ($env:ProgramData) {
        [void]$roots.Add((Join-Path $env:ProgramData 'frp-auto-deploy\lib'))
    }

    $libDir = $null
    foreach ($r in $roots) {
        $full = [System.IO.Path]::GetFullPath($r)
        if (Test-Path -LiteralPath (Join-Path $full 'FrpPaths.ps1')) {
            $libDir = $full
            break
        }
    }
    if (-not $libDir) {
        throw 'ERROR: cannot locate windows/lib modules'
    }
    foreach ($mod in @(
            'FrpPaths.ps1', 'FrpLock.ps1', 'FrpCrypto.ps1', 'FrpTls.ps1', 'FrpState.ps1', 'FrpDraft.ps1',
            'FrpConfig.ps1', 'FrpProcess.ps1', 'FrpAutostart.ps1', 'FrpBootstrap.ps1'
        )) {
        . (Join-Path $libDir $mod)
    }
}

# Dot-source so dotted lib functions stay in this script scope. A normal
# function call would discard them when Import-FrpWindowsModules returns
# (powershell.exe -File FrpClient.ps1 doctor|status|update).
. Import-FrpWindowsModules
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null } catch { }

function Show-FrpClientHelp {
    @'
frp-client (Windows)

  start             Start frpc from existing config (no re-enroll)
  stop              Stop project-managed frpc
  status            Running / enrolled summary
  info              Connection details (RDP/SSH/HTTP)
  list              List configured services (read-only)
  add-service       Add a pending service to the draft (alias: add)
                       -Preset ssh|http|https|custom
                       [-Id <id>]  (advanced override; usually omitted)
                       [-Name <name>] [-TargetHost <ip>] [-TargetPort <port>]
                       [-SshUser <user>]  (required for ssh)
  set-service       Edit a pending service: <id> <property> <value>
                       properties: name, target-host, target-port, ssh-user
  enable-service    Enable a pending service: <id> (reuses same public port)
  disable-service   Disable a pending service: <id> (public port preserved)
  apply             Send pending draft changes to the server (identity auth)
  discard           Discard pending draft changes
  sync              Reconcile local services against server releases
                       (alias: reconcile; after frpctl release service)
  update            Update frpc.exe (preserve identity/ports); -Check for dry run
  pause             Stop frpc and disable autostart (identity/ports preserved)
  resume            Re-enable autostart and start frpc
  uninstall         Remove local software (SERVER RESERVATIONS PRESERVED)
  doctor            Basic local checks
  support-bundle    Create a sanitized local diagnostic zip (-Output <path>)
  autostart         Show/enable/disable the startup autostart task
                       (-Enable / -Disable; no args shows current status)

Service IDs are generated automatically (ssh, http, https, tcp-<port>,
with -2/-3 suffixes on collision). Pass -Id only as an advanced override.

Target host is the service machine as seen from this FRP client:
  127.0.0.1       service runs on this FRP client
  192.168.x.x     another server reachable on the LAN
  hostname        another resolvable internal host

Autostart registers a product-owned Scheduled Task (FRPAutoDeployClient)
that runs `frp-client start` as SYSTEM at system boot, so frpc survives a
reboot without an interactive login. Zero-touch install registers it
automatically for clients with public services; management-only clients
do not need it.

Adding, editing, enabling, or disabling a service only edits a local pending
draft (client-draft.json). Run `apply` to authenticate with this client's
management identity and make the change live. `frpctl release service` on
the server is the only way to release a public port reservation; then run
`sync` on this client to drop the released service and avoid ghost proxies.
'@ | Write-Host
}

function Show-FrpClientInfo {
    if (-not (Test-Path -LiteralPath (Get-FrpStatePath))) {
        Write-Host 'ERROR: not enrolled (client-state.json missing)'
        return 1
    }
    $state = Read-FrpClientState
    $server = [string]$state.frp_server
    $alias = ''
    if (Test-FrpObjectHasProperty -Object $state -Name 'public_hostname') {
        $alias = ([string]$state.public_hostname).Trim()
    }
    $preferred = ''
    if ($alias -and $alias -ne $server) { $preferred = $alias }
    Write-Host ("FRP Server: {0}" -f $server)
    Write-Host ("Transport: {0}" -f $state.frp_transport)
    Write-Host ("Machine ID: {0}" -f $state.machine_id)
    Write-Host ''
    Write-Host 'Services:'
    Write-Host ''
    $services = $state.services
    $items = @()
    if ($services -is [System.Collections.IDictionary]) {
        foreach ($k in $services.Keys) {
            $items += $services[$k]
        }
    } else {
        foreach ($p in $services.PSObject.Properties) {
            $items += $p.Value
        }
    }
    $httpsGuidanceShown = $false
    foreach ($item in $items) {
        $enabled = $true
        if ($null -ne $item.enabled) { $enabled = [bool]$item.enabled }
        if (-not $enabled) { continue }
        $sid = [string]$item.id
        $name = [string]$item.name
        $preset = [string]$item.preset
        if (-not $preset) { $preset = 'custom' }
        $remote = $item.remote_port
        $localIp = [string]$item.local_ip
        $localPort = $item.local_port
        Write-Host ("{0} ({1})" -f $sid, $name)
        Write-Host ("  Target : {0}:{1}" -f $localIp, $localPort)
        if ($preferred) {
            Write-Host ("  Public : {0}:{1}" -f $preferred, $remote)
            Write-Host ("  Fallback public : {0}:{1}" -f $server, $remote)
        } else {
            Write-Host ("  Public : {0}:{1}" -f $server, $remote)
        }
        $isRdp = ($preset -eq 'rdp') -or ($sid -eq 'rdp') -or ([int]$localPort -eq 3389 -and $preset -eq 'custom')
        if ($isRdp) {
            Write-Host '  Connect:'
            if ($preferred) {
                Write-Host '    Preferred:'
                Write-Host ("      mstsc /v:{0}:{1}" -f $preferred, $remote)
                Write-Host '    Fallback:'
                Write-Host ("      mstsc /v:{0}:{1}" -f $server, $remote)
            } else {
                Write-Host ("    mstsc /v:{0}:{1}" -f $server, $remote)
            }
        } elseif ($preset -eq 'ssh') {
            $user = [string]$item.ssh_user
            if ($user) {
                Write-Host '  Connect:'
                if ($preferred) {
                    Write-Host '    Preferred:'
                    Write-Host ("      ssh -p {0} {1}@{2}" -f $remote, $user, $preferred)
                    Write-Host '    Fallback:'
                    Write-Host ("      ssh -p {0} {1}@{2}" -f $remote, $user, $server)
                } else {
                    Write-Host ("    ssh -p {0} {1}@{2}" -f $remote, $user, $server)
                }
            } else {
                Write-Host '  SSH user: legacy / unspecified'
            }
        } elseif ($preset -eq 'http') {
            Write-Host '  URL:'
            if ($preferred) {
                Write-Host '    Preferred:'
                Write-Host ("      http://{0}:{1}" -f $preferred, $remote)
                Write-Host '    Fallback:'
                Write-Host ("      http://{0}:{1}" -f $server, $remote)
            } else {
                Write-Host ("    http://{0}:{1}" -f $server, $remote)
            }
        } elseif ($preset -eq 'https') {
            Write-Host '  URL:'
            if ($preferred) {
                Write-Host '    Preferred:'
                Write-Host ("      https://{0}:{1}" -f $preferred, $remote)
                Write-Host '    Fallback:'
                Write-Host ("      https://{0}:{1}" -f $server, $remote)
            } else {
                Write-Host ("    https://{0}:{1}" -f $server, $remote)
            }
            if ($preferred -and -not $httpsGuidanceShown) {
                Write-Host '  Note:'
                Write-Host '    TLS is passed through to the target HTTPS service.'
                Write-Host '    To avoid certificate warnings, the target service certificate'
                Write-Host ("    must be valid for {0}." -f $preferred)
                $httpsGuidanceShown = $true
            }
        } else {
            Write-Host '  Connect:'
            if ($preferred) {
                Write-Host '    Preferred:'
                Write-Host ("      {0}:{1}" -f $preferred, $remote)
                Write-Host '    Fallback:'
                Write-Host ("      {0}:{1}" -f $server, $remote)
            } else {
                Write-Host ("    {0}:{1}" -f $server, $remote)
            }
        }
        Write-Host ''
    }
    return 0
}

function Invoke-FrpClientUpdate {
    param([switch]$CheckOnly)
    $url = $DownloadUrl
    if (-not $url) { $url = Get-FrpWindowsAmd64Url }
    $sha = $ExpectedSha256
    if (-not $sha) { $sha = Get-FrpWindowsAmd64Sha256 }
    if ($CheckOnly) {
        Write-Host ("Would download: {0}" -f $url)
        Write-Host ("Expected SHA256: {0}" -f $sha)
        Write-Host 'Identity, ports, and frpc.toml token would be preserved.'
        return 0
    }
    if (-not (Enter-FrpClientLock)) { return 1 }
    try {
    Initialize-FrpDirectories
    $backupRoot = Join-Path (Get-FrpBackupDir) ("update-" + (Get-Date -Format 'yyyyMMddHHmmss'))
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    $snapshotMap = [ordered]@{
        'frpc.exe'          = (Get-FrpFrpcPath)
        'frpc.toml'         = (Get-FrpTomlPath)
        'client-state.json' = (Get-FrpStatePath)
        'version'           = (Get-FrpVersionPath)
    }
    foreach ($name in @($snapshotMap.Keys)) {
        $src = $snapshotMap[$name]
        if (Test-Path -LiteralPath $src) {
            Copy-Item -LiteralPath $src -Destination (Join-Path $backupRoot $name) -Force
        }
    }
    $wasRunning = $false
    try {
        $st = Get-FrpClientStatus
        if ($st.Running) {
            $wasRunning = $true
            Stop-FrpClient | Out-Null
        }
        Install-FrpWindowsBinary -DownloadUrl $url -ExpectedSha256 $sha | Out-Null
        if ($env:FRP_WINDOWS_FAIL_AFTER_BINARY_REPLACE -eq '1') {
            throw 'ERROR: simulated failure after binary replace (FRP_WINDOWS_FAIL_AFTER_BINARY_REPLACE=1)'
        }
        # Preserve identity/ports: do not rewrite state or toml here.
        if ($env:FRP_WINDOWS_FAIL_AFTER_METADATA_WRITE -eq '1') {
            throw 'ERROR: simulated failure after metadata write (FRP_WINDOWS_FAIL_AFTER_METADATA_WRITE=1)'
        }
        if ($wasRunning) {
            if ($env:FRP_WINDOWS_FAIL_BEFORE_RESTART -eq '1') {
                throw 'ERROR: simulated failure before restart (FRP_WINDOWS_FAIL_BEFORE_RESTART=1)'
            }
            Start-FrpClient | Out-Null
        }
        Write-Host 'Update complete (identity and port reservations preserved).'
        return 0
    } catch {
        Write-Host ("ERROR: update failed: {0}" -f $_.Exception.Message)
        Write-Host 'Attempting full rollback from backup...'
        $rollbackOk = $true
        try {
            foreach ($name in @('frpc.exe', 'frpc.toml', 'client-state.json', 'version')) {
                $bak = Join-Path $backupRoot $name
                if (-not (Test-Path -LiteralPath $bak)) { continue }
                $dest = $snapshotMap[$name]
                $destDir = Split-Path -Parent $dest
                if (-not (Test-Path -LiteralPath $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                Copy-Item -LiteralPath $bak -Destination $dest -Force
            }
            if ($wasRunning) {
                Start-FrpClient | Out-Null
            }
            Write-Host 'Rollback restored snapshotted files and prior run state.'
        } catch {
            $rollbackOk = $false
            Write-Host ("ERROR: rollback failed: {0}" -f $_.Exception.Message)
            Write-Host 'RECOVERY_REQUIRED=YES'
        }
        if (-not $rollbackOk) {
            Write-Host 'RECOVERY_REQUIRED=YES'
        }
        return 1
    }
    } finally {
        Exit-FrpClientLock
    }
}


function Invoke-FrpClientPause {
    $taskName = Get-FrpAutostartTaskName
    $wasAutostart = Test-FrpAutostartTaskExists -TaskName $taskName
    $st = Get-FrpClientStatus
    if ((-not $st.Running) -and (-not $wasAutostart)) {
        Write-Host 'Client already paused. FRP remote access remains blocked.'
        return 0
    }
    try {
        Stop-FrpClient | Out-Null
    } catch {
        Write-Host ("ERROR: failed to stop frpc: {0}" -f $_.Exception.Message)
        return 1
    }
    if ($wasAutostart) {
        try {
            Uninstall-FrpAutostartTask -TaskName $taskName | Out-Null
        } catch {
            Write-Host ("ERROR: failed to disable autostart: {0}" -f $_.Exception.Message)
            return 1
        }
    }
    Write-Host 'Client paused. All FRP remote access is blocked.'
    Write-Host 'Identity, services, and public ports are preserved.'
    return 0
}

function Invoke-FrpClientResume {
    $taskName = Get-FrpAutostartTaskName
    $st = Get-FrpClientStatus
    $hasAutostart = Test-FrpAutostartTaskExists -TaskName $taskName
    if ($st.Running -and $hasAutostart) {
        Write-Host 'Client already running.'
        return 0
    }
    try {
        if (-not $hasAutostart) {
            Install-FrpAutostartTask -TaskName $taskName | Out-Null
        }
        if (-not $st.Running) {
            Start-FrpClient | Out-Null
        }
    } catch {
        Write-Host ("ERROR: failed to resume FRP client: {0}" -f $_.Exception.Message)
        return 1
    }
    Write-Host 'Client resumed. FRP remote access is restored.'
    return 0
}

function Invoke-FrpClientUninstall {
    if (-not (Enter-FrpClientLock)) { return 1 }
    try {
        return (Invoke-FrpClientUninstallLocked)
    } finally {
        Exit-FrpClientLock
    }
}

function Invoke-FrpClientUninstallLocked {
    Write-Host 'LOCAL SOFTWARE REMOVED, SERVER RESERVATIONS PRESERVED'
    Write-Host 'This removes local frpc binaries, config, state, and tools.'
    Write-Host 'Public port reservations on the server remain until an administrator revokes them.'
    try {
        Stop-FrpClient | Out-Null
    } catch {
        Write-Host ("ERROR: failed to stop project-owned frpc: {0}" -f $_.Exception.Message)
        Write-Host 'ERROR: leaving product files in place. Uninstall did not complete.'
        return 1
    }
    try {
        Uninstall-FrpAutostartTask | Out-Null
    } catch {
        Write-Host ("ERROR: failed to remove autostart task: {0}" -f $_.Exception.Message)
        Write-Host 'ERROR: leaving product files in place so autostart can be recovered. Uninstall did not complete.'
        return 1
    }
    if (Test-FrpAutostartTaskExists) {
        Write-Host 'ERROR: autostart task still present; leaving product files in place.'
        return 1
    }
    $root = Get-FrpWindowsRoot
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host ("Removed: {0}" -f $root)
    return 0
}

function Invoke-FrpClientDoctor {
    $issues = 0
    Write-Host 'frp-client doctor (basic)'
    Write-Host ("Root: {0}" -f (Get-FrpWindowsRoot))
    if (Test-FrpIsEnrolled) {
        Write-Host 'Enrolled: yes'
    } else {
        Write-Host 'Enrolled: no'
        $issues++
    }
    foreach ($p in @((Get-FrpTomlPath), (Get-FrpStatePath), (Get-FrpAllocatorCaPath), (Get-FrpIdentityPubPath))) {
        if (Test-Path -LiteralPath $p) {
            Write-Host ("OK  {0}" -f $p)
        } else {
            Write-Host ("MISS {0}" -f $p)
            $issues++
        }
    }
    if (Test-Path -LiteralPath (Get-FrpFrpcPath)) {
        Write-Host ("OK  {0}" -f (Get-FrpFrpcPath))
    } else {
        Write-Host ("MISS {0}" -f (Get-FrpFrpcPath))
        $issues++
    }
    $st = Get-FrpClientStatus
    Write-Host ("Running: {0} pid={1}" -f $st.Running, $st.Pid)
    if ($issues -gt 0) {
        Write-Host ("Doctor found {0} issue(s)" -f $issues)
        return 1
    }
    Write-Host 'Doctor: basic checks passed'
    return 0
}

function Invoke-FrpClientSupportBundle {
    param([string]$OutputPath)
    # Read-only Windows stub: collect sanitized metadata into a zip. Never
    # include private keys, tokens, DPAPI blobs, or identity secret material.
    $root = Get-FrpWindowsRoot
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $hostName = $env:COMPUTERNAME
    if (-not $hostName) { $hostName = 'windows' }
    $hostName = ($hostName -replace '[^A-Za-z0-9._-]', '-')
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $dir = Join-Path $root 'support-bundles'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $OutputPath = Join-Path $dir ("frp-support-{0}-{1}.zip" -f $hostName, $stamp)
    }
    $stage = Join-Path $env:TEMP ("frp-support-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    $sections = New-Object System.Collections.Generic.List[string]
    try {
        $meta = @{
            format = 'frp-auto-deploy-support-bundle-windows'
            created_at = (Get-Date).ToUniversalTime().ToString('o')
            hostname = $hostName
            role = 'client'
            root = $root
            read_only = $true
            secrets_policy = 'private keys, tokens, and DPAPI secrets omitted'
        } | ConvertTo-Json -Depth 4
        Set-Content -LiteralPath (Join-Path $stage 'meta.json') -Value $meta -Encoding UTF8
        [void]$sections.Add('meta')

        $doctorOut = & {
            $ErrorActionPreference = 'Continue'
            Invoke-FrpClientDoctor | Out-String
        }
        Set-Content -LiteralPath (Join-Path $stage 'doctor.txt') -Value $doctorOut -Encoding UTF8
        [void]$sections.Add('doctor')

        $safeCopies = @()
        $publicSources = @(
            @{ Src = (Get-FrpAllocatorCaPath); Name = 'allocator-ca.crt' },
            @{ Src = (Get-FrpIdentityPubPath); Name = 'client-identity.pub' }
        )
        foreach ($item in $publicSources) {
            if (Test-Path -LiteralPath $item.Src) {
                $destDir = Join-Path $stage 'certs'
                New-Item -ItemType Directory -Force -Path $destDir | Out-Null
                Copy-Item -LiteralPath $item.Src -Destination (Join-Path $destDir $item.Name) -Force
                $safeCopies += $item.Name
            }
        }
        if ($safeCopies.Count) { [void]$sections.Add('public-certs') }

        # Summarize client-state without secret fields.
        $statePath = Get-FrpStatePath
        if (Test-Path -LiteralPath $statePath) {
            try {
                $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
                $machineId = $(if ($state.machine_id) { [string]$state.machine_id } else { [string]$state.client_id })
                $svcOut = [ordered]@{}
                if ($null -ne $state.services) {
                    $map = ConvertTo-FrpServiceMap -Services $state.services
                    foreach ($sid in $map.Keys) {
                        $item = $map[$sid]
                        $localIp = $(if ($item.local_ip) { [string]$item.local_ip } else { '127.0.0.1' })
                        $localPort = $item.local_port
                        $entry = [ordered]@{
                            enabled     = ($item.enabled -ne $false)
                            type        = $(if ($item.preset) { [string]$item.preset } else { [string]$item.protocol })
                            local_ip    = $localIp
                            local_port  = $localPort
                            remote_port = $item.remote_port
                            name        = $item.name
                            target      = ('{0}:{1}' -f $localIp, $localPort)
                        }
                        if ($null -ne $item.health_check -and $item.health_check) {
                            $entry['health_check'] = $item.health_check
                        }
                        $svcOut[[string]$sid] = [pscustomobject]$entry
                    }
                }
                $summary = [ordered]@{
                    machine_id       = $machineId
                    client_id        = $(if ($state.client_id) { [string]$state.client_id } else { $machineId })
                    label            = $state.label
                    hostname         = $state.hostname
                    allocator_url    = $state.allocator_url
                    frp_server       = $state.frp_server
                    frp_server_port  = $state.frp_server_port
                    frp_transport    = $(if ($state.frp_transport) { $state.frp_transport } else { $state.transport })
                    services         = [pscustomobject]$svcOut
                }
                ($summary | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath (Join-Path $stage 'client-summary.json') -Encoding UTF8
                [void]$sections.Add('client-summary')
            } catch {
                Set-Content -LiteralPath (Join-Path $stage 'client-summary.json') -Value '{"error":"unreadable"}' -Encoding UTF8
                [void]$sections.Add('client-summary')
            }
        }

        # Sanitized generated frpc.toml (tokens redacted); never copy raw secrets.
        $tomlPath = Get-FrpTomlPath
        if (Test-Path -LiteralPath $tomlPath) {
            try {
                $lines = New-Object System.Collections.Generic.List[string]
                foreach ($line in Get-Content -LiteralPath $tomlPath -ErrorAction Stop) {
                    $stripped = $line.Trim()
                    $lower = $stripped.ToLowerInvariant()
                    if ($lower.StartsWith('auth.token') -or ($lower.Contains('token') -and $lower.Contains('='))) {
                        $key = ($line -split '=', 2)[0].TrimEnd()
                        [void]$lines.Add(('{0} = "<redacted>"' -f $key))
                        continue
                    }
                    if ($lower.Contains('begin') -and $lower.Contains('private key')) {
                        [void]$lines.Add('# <private key omitted>')
                        continue
                    }
                    [void]$lines.Add($line)
                }
                $genDir = Join-Path $stage 'generated'
                New-Item -ItemType Directory -Force -Path $genDir | Out-Null
                Set-Content -LiteralPath (Join-Path $genDir 'frpc.toml.sanitized') -Value ($lines -join "`n") -Encoding UTF8
                [void]$sections.Add('generated-config')
            } catch { }
        }

        # Process / service status via existing helpers when available.
        try {
            $st = Get-FrpClientStatus
            $statusLines = @(
                ('Running   : {0}' -f $st.Running),
                ('Pid       : {0}' -f $st.Pid),
                ('Enrolled  : {0}' -f $st.Enrolled),
                ('Server    : {0}' -f $st.Server),
                ('Transport : {0}' -f $st.Transport),
                ('StatePath : {0}' -f $st.StatePath),
                ('TomlPath  : {0}' -f $st.TomlPath),
                ('FrpcPath  : {0}' -f $st.FrpcPath)
            )
            Set-Content -LiteralPath (Join-Path $stage 'service-status.txt') -Value ($statusLines -join "`n") -Encoding UTF8
            [void]$sections.Add('service-status')
        } catch {
            Set-Content -LiteralPath (Join-Path $stage 'service-status.txt') -Value 'service status unavailable' -Encoding UTF8
        }

        $omitted = @(
            'client-identity.key',
            'client-identity.key.dpapi',
            'client-identity.mac',
            'enroll-pending.json (DPAPI / enrollment secrets)',
            'any auth.token / server token material'
        )
        Set-Content -LiteralPath (Join-Path $stage 'OMITTED_SECRETS.txt') -Value ($omitted -join "`n") -Encoding UTF8

        if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $OutputPath)
        $size = (Get-Item -LiteralPath $OutputPath).Length
        Write-Host 'Support bundle created'
        Write-Host ("  path     : {0}" -f $OutputPath)
        Write-Host ("  size     : {0} bytes" -f $size)
        Write-Host ("  sections : {0}" -f ($sections -join ', '))
        Write-Host '  redaction: private keys, tokens, and DPAPI secrets omitted'
        return 0
    } catch {
        Write-Host ("ERROR: support-bundle failed: {0}" -f $_.Exception.Message)
        return 1
    } finally {
        if (Test-Path -LiteralPath $stage) {
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-FrpClientAutostart {
    param([switch]$Enable, [switch]$Disable)
    if ($Enable -and $Disable) {
        Write-Host 'ERROR: specify only one of -Enable or -Disable'
        return 2
    }
    $taskName = Get-FrpAutostartTaskName
    if ($Disable) {
        try {
            Uninstall-FrpAutostartTask -TaskName $taskName | Out-Null
        } catch {
            Write-Host $_.Exception.Message
            return 1
        }
        Write-Host ("Autostart disabled ({0} removed)." -f $taskName)
        return 0
    }
    if ($Enable) {
        try {
            Install-FrpAutostartTask -TaskName $taskName | Out-Null
        } catch {
            Write-Host $_.Exception.Message
            return 1
        }
        Write-Host ("Autostart enabled: {0} runs 'frp-client start' at system startup." -f $taskName)
        Write-Host 'Runs as SYSTEM; no interactive login is required.'
        return 0
    }
    if (Test-FrpAutostartTaskExists -TaskName $taskName) {
        Write-Host ("Autostart: enabled ({0})" -f $taskName)
        Write-Host ("Runs   : {0}" -f (Get-FrpAutostartRunCommand))
    } else {
        Write-Host 'Autostart: not configured'
        Write-Host 'Run: frp-client autostart -Enable'
    }
    return 0
}

function Show-FrpClientList {
    if (-not (Test-Path -LiteralPath (Get-FrpStatePath))) {
        Write-Host 'ERROR: not enrolled (client-state.json missing)'
        return 1
    }
    $state = Read-FrpClientState
    $map = ConvertTo-FrpServiceMap -Services $state.services
    if ($map.Count -eq 0) {
        Write-Host '(none)'
    } else {
        $labels = @{ ssh = 'SSH / TCP'; http = 'HTTP / TCP'; https = 'HTTPS / TCP' }
        $n = 0
        foreach ($sid in $map.Keys) {
            $n++
            $item = $map[$sid]
            $enabled = ($item.enabled -ne $false)
            $stateLabel = $(if ($enabled) { 'enabled' } else { 'disabled' })
            $preset = [string]$item.preset
            $typeLabel = $labels[$preset]
            if (-not $typeLabel) { $typeLabel = 'Custom TCP' }
            Write-Host ("{0}. {1}" -f $n, $sid)
            Write-Host ("   Type        : {0}" -f $typeLabel)
            Write-Host ("   Target      : {0}:{1}" -f $item.local_ip, $item.local_port)
            if ($item.remote_port) {
                Write-Host ("   Public port : {0}" -f $item.remote_port)
            }
            Write-Host ("   State       : {0}" -f $stateLabel)
            Write-Host ''
        }
    }
    if (Test-FrpDraftPending) {
        Write-Host 'Pending service changes exist.'
        Write-Host 'Run:'
        Write-Host '  apply'
        Write-Host 'or:'
        Write-Host '  discard'
    }
    return 0
}

function Invoke-FrpAddServiceCli {
    param([string]$Preset, [string]$Id, [string]$Name, [string]$TargetHost, [int]$TargetPort, [string]$SshUser)
    return (Invoke-FrpWithClientLock {
        try {
            $sid = Add-FrpDraftService -Preset $Preset -Id $Id -Name $Name -TargetHost $TargetHost -TargetPort $TargetPort -SshUser $SshUser
        } catch {
            Write-Host $_.Exception.Message
            return 1
        }
        Write-Host ("Pending service '{0}' added." -f $sid)
        Write-Host ''
        Write-Host 'Apply:'
        Write-Host '  apply'
        Write-Host ''
        Write-Host 'Discard:'
        Write-Host '  discard'
        return 0
    })
}

function Invoke-FrpSetServiceCli {
    param([string]$Id, [string]$Property, [string]$Value)
    if (-not $Id -or -not $Property -or [string]::IsNullOrEmpty($Value)) {
        Write-Host 'ERROR: usage: frp-client set-service <id> <property> <value>'
        return 2
    }
    return (Invoke-FrpWithClientLock {
        try {
            Set-FrpDraftServiceField -Id $Id -Property $Property -Value $Value | Out-Null
        } catch {
            Write-Host $_.Exception.Message
            return 1
        }
        Write-Host ("Pending service '{0}' {1} updated." -f $Id, $Property)
        Write-Host ''
        Write-Host 'Apply:'
        Write-Host '  apply'
        Write-Host ''
        Write-Host 'Discard:'
        Write-Host '  discard'
        return 0
    })
}

function Invoke-FrpEnableServiceCli {
    param([string]$Id, [bool]$Enable)
    if (-not $Id) {
        Write-Host ("ERROR: usage: frp-client {0} <id>" -f $(if ($Enable) { 'enable-service' } else { 'disable-service' }))
        return 2
    }
    return (Invoke-FrpWithClientLock {
        $wasEnabled = $true
        try {
            Ensure-FrpDraftPending | Out-Null
            $map = Get-FrpDraftServiceMap
            $sid = $Id.Trim().ToLowerInvariant()
            if (-not $map.Contains($sid)) { throw ("ERROR: unknown service: {0}" -f $sid) }
            $wasEnabled = ($map[$sid]['enabled'] -ne $false)
            Set-FrpDraftServiceEnabled -Id $Id -Enable $Enable | Out-Null
        } catch {
            Write-Host $_.Exception.Message
            return 1
        }
        if ($Enable) {
            Write-Host ("Service '{0}' will be enabled (same public port reused)." -f $Id)
        } elseif ($wasEnabled) {
            Write-Host ("Service '{0}' will be disabled. The public reservation remains until released server-side." -f $Id)
        } else {
            Write-Host ("Service '{0}' is already disabled in the pending state." -f $Id)
        }
        Write-Host ''
        Write-Host 'Apply:'
        Write-Host '  apply'
        Write-Host ''
        Write-Host 'Discard:'
        Write-Host '  discard'
        return 0
    })
}

function Invoke-FrpClientDiscardDraft {
    return (Invoke-FrpWithClientLock {
        $existed = Remove-FrpDraftState
        if ($existed) {
            Write-Host 'Pending service changes discarded.'
        } else {
            Write-Host 'No pending service changes.'
        }
        return 0
    })
}

switch ($Command) {
    'help' { Show-FrpClientHelp; exit 0 }
    'start' {
        if (-not (Test-FrpIsEnrolled)) {
            Write-Host 'ERROR: not enrolled; run install-client.ps1 -ZeroTouch first'
            exit 1
        }
        Start-FrpClient -Force:$Force | Out-Null
        exit 0
    }
    'stop' { Stop-FrpClient | Out-Null; exit 0 }
    'status' {
        $st = Get-FrpClientStatus
        Write-Host ("enrolled={0}" -f $st.Enrolled)
        Write-Host ("running={0}" -f $st.Running)
        if ($null -ne $st.Pid) { Write-Host ("pid={0}" -f $st.Pid) }
        if ($st.Server) { Write-Host ("server={0}" -f $st.Server) }
        if ($st.Transport) { Write-Host ("transport={0}" -f $st.Transport) }
        exit 0
    }
    'info' { exit (Show-FrpClientInfo) }
    'list' { exit (Show-FrpClientList) }
    'add-service' { exit (Invoke-FrpAddServiceCli -Preset $Preset -Id $Id -Name $Name -TargetHost $TargetHost -TargetPort $TargetPort -SshUser $SshUser) }
    'add' { exit (Invoke-FrpAddServiceCli -Preset $Preset -Id $Id -Name $Name -TargetHost $TargetHost -TargetPort $TargetPort -SshUser $SshUser) }
    'set-service' { exit (Invoke-FrpSetServiceCli -Id $Id -Property $Property -Value $Value) }
    'enable-service' { exit (Invoke-FrpEnableServiceCli -Id $Id -Enable $true) }
    'disable-service' { exit (Invoke-FrpEnableServiceCli -Id $Id -Enable $false) }
    'apply' { exit (Invoke-FrpClientApplyDraft) }
    'discard' { exit (Invoke-FrpClientDiscardDraft) }
    'sync' { exit (Invoke-FrpClientSync) }
    'reconcile' { exit (Invoke-FrpClientSync) }
    'update' { exit (Invoke-FrpClientUpdate -CheckOnly:$Check) }
    'pause' { exit (Invoke-FrpClientPause) }
    'resume' { exit (Invoke-FrpClientResume) }
    'uninstall' { exit (Invoke-FrpClientUninstall) }
    'doctor' { exit (Invoke-FrpClientDoctor) }
    'support-bundle' { exit (Invoke-FrpClientSupportBundle -OutputPath $Output) }
    'autostart' { exit (Invoke-FrpClientAutostart -Enable:$Enable -Disable:$Disable) }
    default { Show-FrpClientHelp; exit 1 }
}
