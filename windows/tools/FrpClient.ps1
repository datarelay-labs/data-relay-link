#Requires -Version 5.1
<#
.SYNOPSIS
  drlink client lifecycle tool for Windows.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command = 'help',

    [Parameter(Position = 1)]
    [string]$SubCommand,

    [Parameter(Position = 2)][string]$Id,
    [Parameter(Position = 3)][string]$Property,
    [Parameter(Position = 4)][string]$Value,

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

# --- Canonical public grammar (legacy root verbs remain as compatibility) ---
$script:FrpUpdateMode = 'engine'  # engine | project | both-check
$normalized = $false
$fromServiceResource = $false
$cmdLower = $Command.ToLowerInvariant()
$subLower = if ($SubCommand) { $SubCommand.ToLowerInvariant() } else { '' }

switch -Regex ($cmdLower) {
    '^show$' {
        switch ($subLower) {
            'status' { $Command = 'status'; $normalized = $true }
            'services' { $Command = 'list'; $normalized = $true }
            'info' { $Command = 'info'; $normalized = $true }
            'version' { $Command = 'version'; $normalized = $true }
            default {
                Write-Host ("ERROR: unknown show command: {0}" -f $SubCommand)
                Write-Host 'Next: drlink show status | show services | system info'
                exit 1
            }
        }
    }
    '^set$' {
        if ($subLower -eq 'service') {
            $fromServiceResource = $true
            $Command = 'set-service'
            $normalized = $true
            # drlink set service <id> <property> <value>
            # → Command=set, Sub=service, Id, Property, Value already positioned.
        } else {
            Write-Host ("ERROR: unknown set command: {0}" -f $SubCommand)
            Write-Host 'Next: drlink set service <id> <property> <value>'
            exit 1
        }
    }
    '^unset$' {
        if ($subLower -eq 'service') {
            $fromServiceResource = $true
            $Command = 'disable-service'
            $normalized = $true
            # drlink unset service <id> → Id already positioned.
        } else {
            Write-Host ("ERROR: unknown unset command: {0}" -f $SubCommand)
            Write-Host 'Next: drlink unset service <id>'
            exit 1
        }
    }
    '^system$' {
        switch ($subLower) {
            'info' { $Command = 'info'; $normalized = $true }
            'version' { $Command = 'version'; $normalized = $true }
            'pause' { $Command = 'pause'; $normalized = $true }
            'resume' { $Command = 'resume'; $normalized = $true }
            'restart' { $Command = 'restart'; $normalized = $true }
            'autostart' {
                $Command = 'autostart'
                $normalized = $true
                $autoSub = if ($Id) { $Id.ToLowerInvariant() } else { '' }
                if ($autoSub -eq 'enable') { $Enable = $true; $Id = $null }
                elseif ($autoSub -eq 'disable') { $Disable = $true; $Id = $null }
                elseif (-not [string]::IsNullOrWhiteSpace($autoSub)) {
                    Write-Host ("ERROR: unknown system autostart command: {0}" -f $Id)
                    Write-Host 'Next: drlink system autostart | system autostart enable | system autostart disable'
                    exit 1
                }
            }
            'diagnostics' { $Command = 'doctor'; $normalized = $true }
            'support-bundle' { $Command = 'support-bundle'; $normalized = $true }
            'uninstall' { $Command = 'uninstall'; $normalized = $true }
            'update' {
                $Command = 'update'
                $normalized = $true
                $upd = if ($Id) { $Id.ToLowerInvariant() } else { '' }
                if ($upd -eq 'product') { $script:FrpUpdateMode = 'project'; $Id = $null }
                elseif ($upd -eq 'engine') { $script:FrpUpdateMode = 'engine'; $Id = $null }
                else {
                    Write-Host ("ERROR: unknown system update command: {0}" -f $Id)
                    Write-Host 'Next: drlink system update product | system update engine'
                    exit 1
                }
            }
            'services' {
                $svcOp = if ($Id) { $Id.ToLowerInvariant() } else { '' }
                switch ($svcOp) {
                    'apply' { $Command = 'apply'; $normalized = $true; $Id = $null }
                    'discard' { $Command = 'discard'; $normalized = $true; $Id = $null }
                    'sync' { $Command = 'sync'; $normalized = $true; $Id = $null }
                    default {
                        Write-Host ("ERROR: unknown system services command: {0}" -f $Id)
                        Write-Host 'Next: drlink system services apply | discard | sync'
                        exit 1
                    }
                }
            }
            default {
                Write-Host ("ERROR: unknown system command: {0}" -f $SubCommand)
                Write-Host 'Next: drlink system info | pause | resume | restart | autostart | uninstall'
                exit 1
            }
        }
    }
    '^status$' {
        $Command = 'status'
        $normalized = $true
    }
    '^client$' {
        if ([string]::IsNullOrWhiteSpace($SubCommand) -or $SubCommand.ToLowerInvariant() -eq 'info') {
            $Command = 'info'
            $normalized = $true
        } else {
            Write-Host ("ERROR: unknown client command: {0}" -f $SubCommand)
            Write-Host 'Next: drlink system info'
            exit 1
        }
    }
    '^service$' {
        $fromServiceResource = $true
        switch ($subLower) {
            'list' { $Command = 'list'; $normalized = $true }
            'add' { $Command = 'add-service'; $normalized = $true }
            'set' { $Command = 'set-service'; $normalized = $true }
            'enable' { $Command = 'enable-service'; $normalized = $true }
            'disable' { $Command = 'disable-service'; $normalized = $true }
            'apply' { $Command = 'apply'; $normalized = $true }
            'discard' { $Command = 'discard'; $normalized = $true }
            default {
                Write-Host ("ERROR: unknown service command: {0}" -f $SubCommand)
                Write-Host 'Next: drlink show services | set service | system services apply'
                exit 1
            }
        }
    }
    '^update$' {
        if ($subLower -eq 'project' -or $subLower -eq 'product') {
            $script:FrpUpdateMode = 'project'
            $Command = 'update'
            $normalized = $true
        } elseif ($subLower -eq 'engine') {
            $script:FrpUpdateMode = 'engine'
            $Command = 'update'
            $normalized = $true
        } elseif ($Check -or $subLower -eq '--check' -or $subLower -eq 'check') {
            $script:FrpUpdateMode = 'both-check'
            $Command = 'update'
            $Check = $true
            $normalized = $true
        } elseif ([string]::IsNullOrWhiteSpace($subLower)) {
            $script:FrpUpdateMode = 'engine'
            $Command = 'update'
            $normalized = $true
        } else {
            Write-Host ("ERROR: unknown update command: {0}" -f $SubCommand)
            Write-Host 'Next: drlink system update product | system update engine'
            exit 1
        }
    }
    '^support$' {
        if ($subLower -eq 'bundle' -or [string]::IsNullOrWhiteSpace($subLower)) {
            $Command = 'support-bundle'
            $normalized = $true
        } else {
            Write-Host ("ERROR: unknown support command: {0}" -f $SubCommand)
            Write-Host 'Next: drlink system support-bundle'
            exit 1
        }
    }
    '^(pause|resume|restart)$' {
        $Command = $cmdLower
        $normalized = $true
    }
}

# Legacy verb-first used Position 1 as <id>. Resource-first uses Position 1 as
# the subcommand, so remap when the caller did not use `service …` / `set service`.
if (-not $fromServiceResource -and $Command -in @('set-service', 'enable-service', 'disable-service')) {
    if (-not [string]::IsNullOrWhiteSpace($SubCommand) -and $SubCommand.ToLowerInvariant() -ne 'service') {
        if ($Command -eq 'set-service') {
            $Value = $Property
            $Property = $Id
            $Id = $SubCommand
        } else {
            $Id = $SubCommand
        }
        $SubCommand = $null
    }
}

# Legacy aliases: keep working, but they are not primary discovery output.
$legacyAllowed = @(
    'start', 'stop', 'status', 'info', 'version', 'update', 'uninstall', 'doctor', 'support-bundle', 'autostart', 'help',
    'list', 'add-service', 'add', 'set-service', 'enable-service', 'disable-service',
    'apply', 'discard', 'sync', 'reconcile', 'pause', 'resume', 'restart'
)
if (-not $normalized -and $Command -notin $legacyAllowed) {
    Write-Host ("ERROR: unknown command: {0}" -f $Command)
    Write-Host 'Run: drlink help'
    exit 1
}

function Import-FrpWindowsModules {
    $roots = New-Object System.Collections.ArrayList
    [void]$roots.Add((Join-Path $PSScriptRoot '..\lib'))
    if ($env:FRP_WINDOWS_ROOT) {
        [void]$roots.Add((Join-Path $env:FRP_WINDOWS_ROOT 'lib'))
    }
    if ($env:ProgramData) {
        [void]$roots.Add((Join-Path $env:ProgramData 'drlink\lib'))
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
            'FrpConfig.ps1', 'FrpProcess.ps1', 'FrpShim.ps1', 'FrpAutostart.ps1', 'FrpBootstrap.ps1'
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
drlink (Windows client)

REMOTE ACCESS
  show status            Running / enrolled summary
  system info            Connection details (RDP/SSH/HTTP)
  show services          List configured services

  set service <id> <property> <value>
  unset service <id>

  system services apply  Send pending draft to the server
  system services discard
  system services sync

SYSTEM
  system pause           Stop runtime and disable autostart
  system resume          Enable autostart and start runtime
  system restart         Restart local relay runtime only
  system autostart
  system autostart enable
  system autostart disable
  system update product
  system update engine
  system diagnostics
  system support-bundle
  system version
  system uninstall       Remove local software (SERVER RESERVATIONS PRESERVED)

Pending service edits become live only after:
  system services apply
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
    Write-Host ("Data Relay Link Server: {0}" -f $server)
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

function Install-FrpProjectManagementFiles {
    param([Parameter(Mandatory = $true)][string]$SrcRoot)
    Initialize-FrpDirectories
    $srcClient = Join-Path $SrcRoot 'tools/FrpClient.ps1'
    $srcCmd = Join-Path $SrcRoot 'tools/frp-client.cmd'
    $srcDrlink = Join-Path $SrcRoot 'tools/drlink.cmd'
    $srcAuto = Join-Path $SrcRoot 'tools/frp-autostart.cmd'
    if (-not (Test-Path -LiteralPath $srcClient)) {
        throw ("ERROR: project source missing FrpClient.ps1 under {0}" -f $SrcRoot)
    }
    Copy-Item -LiteralPath $srcClient -Destination (Join-Path (Get-FrpToolsDir) 'FrpClient.ps1') -Force
    if (Test-Path -LiteralPath $srcCmd) {
        Copy-Item -LiteralPath $srcCmd -Destination (Join-Path (Get-FrpToolsDir) 'frp-client.cmd') -Force
    }
    if (Test-Path -LiteralPath $srcDrlink) {
        Copy-Item -LiteralPath $srcDrlink -Destination (Join-Path (Get-FrpToolsDir) 'drlink.cmd') -Force
    }
    if (Test-Path -LiteralPath $srcAuto) {
        Copy-Item -LiteralPath $srcAuto -Destination (Join-Path (Get-FrpToolsDir) 'frp-autostart.cmd') -Force
    }
    $srcLib = Join-Path $SrcRoot 'lib'
    if (Test-Path -LiteralPath $srcLib) {
        $destLib = Get-FrpLibDir
        Get-ChildItem -LiteralPath $srcLib -Filter '*.ps1' -File -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $destLib $_.Name) -Force
        }
    }
    # Keep the bare `drlink` command resolvable after a tools refresh.
    try { Install-FrpCommandShim -Quiet | Out-Null } catch { }
    # Preserve identity/ports: do not rewrite client-state or frpc.toml.
    $verSrc = Join-Path $SrcRoot '..\VERSION'
    if (-not (Test-Path -LiteralPath $verSrc)) {
        $verSrc = Join-Path $SrcRoot 'VERSION'
    }
    if (Test-Path -LiteralPath $verSrc) {
        Copy-Item -LiteralPath $verSrc -Destination (Get-FrpVersionPath) -Force
    }
}

function Test-FrpIsInstalledProductTree {
    param([Parameter(Mandatory = $true)][string]$CandidateRoot)
    try {
        $productRoot = [System.IO.Path]::GetFullPath((Get-FrpWindowsRoot).TrimEnd('\', '/'))
        $cand = [System.IO.Path]::GetFullPath($CandidateRoot.TrimEnd('\', '/'))
        return ($cand -eq $productRoot)
    } catch {
        return $false
    }
}

function Resolve-FrpProjectSourceRoot {
    # Production installed clients do not ship a downloadable project artifact
    # pipeline in historical pre-v2.4 installs. Only an explicit source tree (or a distinct repo
    # checkout) may refresh management files; never copy the installed tree onto itself.
    if ($env:FRP_WINDOWS_PROJECT_SRC) {
        if (-not (Test-Path -LiteralPath $env:FRP_WINDOWS_PROJECT_SRC)) {
            return $null
        }
        $explicit = $env:FRP_WINDOWS_PROJECT_SRC.TrimEnd('\', '/')
        if (Test-FrpIsInstalledProductTree -CandidateRoot $explicit) {
            return $null
        }
        return $explicit
    }
    if ($script:FrpWindowsSrcRoot -and (Test-Path -LiteralPath $script:FrpWindowsSrcRoot)) {
        $srcRoot = $script:FrpWindowsSrcRoot.TrimEnd('\', '/')
        if (-not (Test-FrpIsInstalledProductTree -CandidateRoot $srcRoot)) {
            return $srcRoot
        }
    }
    # Repo layout when running from a checkout: windows/tools/FrpClient.ps1
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    if (Test-Path -LiteralPath (Join-Path $candidate 'tools/FrpClient.ps1')) {
        if (Test-FrpIsInstalledProductTree -CandidateRoot $candidate) {
            return $null
        }
        $hasInstaller = Test-Path -LiteralPath (Join-Path $candidate 'install-client.ps1')
        $hasVersion = Test-Path -LiteralPath (Join-Path $candidate '..\VERSION')
        if ($hasInstaller -or $hasVersion) {
            return $candidate
        }
    }
    return $null
}

function Write-FrpProjectUpdateCheck {
    param([string]$InstalledProject)
    Write-Host 'Data Relay Link project:'
    Write-Host ("  installed : {0}" -f $InstalledProject)
    Write-Host '  apply path : re-run the Windows client installer (supported)'
    Write-Host '  note       : no in-place project artifact download in this release'
    Write-Host '  developers : set FRP_WINDOWS_PROJECT_SRC to a windows/ tree (tools + lib)'
}

function Write-FrpEngineUpdateCheck {
    param([string]$Url, [string]$Sha256)
    Write-Host 'FRP engine (project-pinned/tested only):'
    Write-Host ("  Would download: {0}" -f $Url)
    Write-Host ("  Expected SHA256: {0}" -f $Sha256)
    Write-Host '  note      : Does not install latest upstream FRP — only the pinned release.'
    Write-Host 'Identity, ports, and frpc.toml token would be preserved.'
}

function Invoke-FrpClientUpdate {
    param([switch]$CheckOnly)
    $mode = $script:FrpUpdateMode
    if (-not $mode) { $mode = 'engine' }

    $installedProject = Get-FrpProjectVersion
    $engineUrl = $DownloadUrl
    if (-not $engineUrl) { $engineUrl = Get-FrpWindowsAmd64Url }
    $engineSha = $ExpectedSha256
    if (-not $engineSha) { $engineSha = Get-FrpWindowsAmd64Sha256 }

    # Distinct -Check semantics:
    #   update --check           -> both-check (project + engine)
    #   update project -Check    -> project only
    #   update engine -Check     -> engine only (Would download)
    if ($mode -eq 'both-check') {
        Write-FrpProjectUpdateCheck -InstalledProject $installedProject
        Write-Host ''
        Write-FrpEngineUpdateCheck -Url $engineUrl -Sha256 $engineSha
        Write-Host 'Identity, ports, services, CA trust, and management state are preserved.'
        return 0
    }

    if ($mode -eq 'project') {
        if ($CheckOnly) {
            Write-FrpProjectUpdateCheck -InstalledProject $installedProject
            Write-Host 'Identity, ports, services, CA trust, and management state are preserved.'
            return 0
        }
        $src = Resolve-FrpProjectSourceRoot
        if (-not $src) {
            Write-Host 'ERROR: Windows project auto-update from an installed client is not supported in this release.'
            Write-Host 'Supported path: re-run the canonical Windows client installer (identity and ports are preserved).'
            Write-Host 'Developers/CI: set FRP_WINDOWS_PROJECT_SRC to a windows/ tree containing tools/ and lib/.'
            Write-Host 'FAILURE_CLASS=PROJECT_UPDATE_USE_INSTALLER'
            return 1
        }
        if (-not (Enter-FrpClientLock)) { return 1 }
        try {
            Install-FrpProjectManagementFiles -SrcRoot $src
            Write-Host ("Project update complete from {0}" -f $src)
            Write-Host 'Identity, ports, services, and CA trust were preserved.'
            Write-Host 'Restart this PowerShell session (or re-run drlink) to load updated CLI modules.'
            return 0
        } catch {
            Write-Host ("ERROR: project update failed: {0}" -f $_.Exception.Message)
            return 1
        } finally {
            Exit-FrpClientLock
        }
    }

    # Engine update (frpc.exe) — mode engine (also bare `update`)
    $url = $engineUrl
    $sha = $engineSha
    if ($CheckOnly) {
        Write-FrpEngineUpdateCheck -Url $url -Sha256 $sha
        return 0
    }
    if (-not (Enter-FrpClientLock)) { return 1 }
    try {
    Initialize-FrpDirectories
    # The snapshot includes frpc.toml, which carries the plaintext FRP token,
    # so the backup directory and every copy get the product-enforced ACL.
    $backupRoot = New-FrpBackupRoot -Prefix 'update'
    $snapshotMap = [ordered]@{
        'frpc.exe'          = (Get-FrpFrpcPath)
        'frpc.toml'         = (Get-FrpTomlPath)
        'client-state.json' = (Get-FrpStatePath)
        'version'           = (Get-FrpVersionPath)
    }
    foreach ($name in @($snapshotMap.Keys)) {
        $src = $snapshotMap[$name]
        if (Test-Path -LiteralPath $src) {
            Copy-FrpProtectedFile -Source $src -Destination (Join-Path $backupRoot $name) | Out-Null
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
        Write-Host 'FRP engine update complete (identity and port reservations preserved).'
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


function Invoke-FrpClientUninstall {
    if (-not (Enter-FrpClientLock)) { return 1 }
    try {
        return (Invoke-FrpClientUninstallLocked)
    } finally {
        Exit-FrpClientLock
    }
}

function Invoke-FrpClientUninstallLocked {
    Write-Host 'LOCAL SOFTWARE / STATE REMOVED'
    Write-Host 'SERVER-SIDE RESERVATIONS PRESERVED'
    Write-Host ''
    Write-Host 'WHAT WILL BE REMOVED'
    Write-Host ''
    Write-Host 'Local Data Relay Link software'
    Write-Host 'Local client identity'
    Write-Host 'Local client configuration'
    Write-Host 'Local service state'
    Write-Host 'Local autostart configuration'
    Write-Host ''
    Write-Host 'WHAT WILL REMAIN ON THE SERVER'
    Write-Host ''
    Write-Host 'Client record'
    Write-Host 'Published service reservations'
    Write-Host 'Public port reservations'
    Write-Host 'Server-side policy state'
    Write-Host ''
    Write-Host 'This uninstall does not contact the server and does not release ports.'
    Write-Host 'Remote Managed Host records and reservations remain until removed on the server.'
    Write-Host 'On the DRLink Server:'
    Write-Host '  unset managed-host <HOST>'
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
    # Must run while state\path-shim.json is still readable: it records whether
    # this product added the PATH entry, so nothing else on PATH is touched.
    try {
        Uninstall-FrpCommandShim | Out-Null
    } catch {
        Write-Host ("WARNING: could not update the system PATH: {0}" -f $_.Exception.Message)
    }
    $root = Get-FrpWindowsRoot
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host ("Removed: {0}" -f $root)
    return 0
}

function Get-FrpClientDoctorReport {
    $lines = New-Object System.Collections.Generic.List[string]
    $issues = 0
    [void]$lines.Add('Data Relay Link client diagnostics')
    [void]$lines.Add(("Root: {0}" -f (Get-FrpWindowsRoot)))
    if (Test-FrpIsEnrolled) {
        [void]$lines.Add('Enrolled: yes')
    } else {
        [void]$lines.Add('Enrolled: no')
        $issues++
    }
    foreach ($p in @((Get-FrpTomlPath), (Get-FrpStatePath), (Get-FrpAllocatorCaPath), (Get-FrpIdentityPubPath))) {
        if (Test-Path -LiteralPath $p) {
            [void]$lines.Add(("OK  {0}" -f $p))
        } else {
            [void]$lines.Add(("MISS {0}" -f $p))
            $issues++
        }
    }
    if (Test-Path -LiteralPath (Get-FrpFrpcPath)) {
        [void]$lines.Add(("OK  {0}" -f (Get-FrpFrpcPath)))
    } else {
        [void]$lines.Add(("MISS {0}" -f (Get-FrpFrpcPath)))
        $issues++
    }
    $enrolledNow = Test-FrpIsEnrolled
    $logPath = Get-FrpLogPath
    if (Test-Path -LiteralPath $logPath) {
        [void]$lines.Add(("OK  {0}" -f $logPath))
    } else {
        [void]$lines.Add(("MISS {0} (runtime log)" -f $logPath))
        if ($enrolledNow) { $issues++ }
    }
    $shim = Get-FrpCommandShimStatus
    if ($shim.ResolvesToProduct) {
        [void]$lines.Add(("OK  drlink resolves from a new shell: {0}" -f $shim.Resolved))
    } elseif ($shim.ForeignCommand) {
        [void]$lines.Add(("WARN drlink on PATH belongs to another product: {0}" -f $shim.ForeignCommand))
        [void]$lines.Add(("     run this client as {0}" -f $shim.ShimPath))
    } else {
        [void]$lines.Add(("MISS drlink is not on the system PATH; run it as {0}" -f $shim.ShimPath))
        if ($enrolledNow) { $issues++ }
    }
    $st = Get-FrpClientStatus
    [void]$lines.Add(("Running: {0} pid={1}" -f $st.Running, $st.Pid))
    if ($issues -gt 0) {
        [void]$lines.Add(("Doctor found {0} issue(s)" -f $issues))
    } else {
        [void]$lines.Add('Doctor: basic checks passed')
    }
    $exitCode = 0
    if ($issues -gt 0) {
        $exitCode = 1
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Text = ($lines -join "`n")
    }
}

function Invoke-FrpClientDoctor {
    $report = Get-FrpClientDoctorReport
    Write-Host $report.Text
    return $report.ExitCode
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
    $tempRoot = [System.IO.Path]::GetTempPath()
    if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = $root }
    $stage = Join-Path $tempRoot ("frp-support-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    $sections = New-Object System.Collections.Generic.List[string]
    try {
        $meta = @{
            format = 'data-relay-link-support-bundle-windows'
            created_at = (Get-Date).ToUniversalTime().ToString('o')
            hostname = $hostName
            role = 'client'
            root = $root
            read_only = $true
            secrets_policy = 'private keys, tokens, and DPAPI secrets omitted'
        } | ConvertTo-Json -Depth 4
        Set-Content -LiteralPath (Join-Path $stage 'meta.json') -Value $meta -Encoding UTF8
        [void]$sections.Add('meta')

        $doctorReport = Get-FrpClientDoctorReport
        Set-Content -LiteralPath (Join-Path $stage 'doctor.txt') -Value $doctorReport.Text -Encoding UTF8
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

        # Sanitized tail of the advertised runtime log (logs\frpc.log). The
        # tail is redacted line by line; the raw log is never copied.
        try {
            $logTail = @(Get-FrpSanitizedLogTail -Lines 200)
            $logDir = Join-Path $stage 'logs'
            New-Item -ItemType Directory -Force -Path $logDir | Out-Null
            if ($logTail.Count -gt 0) {
                Set-Content -LiteralPath (Join-Path $logDir 'frpc.log.tail') -Value ($logTail -join "`n") -Encoding UTF8
            } else {
                Set-Content -LiteralPath (Join-Path $logDir 'frpc.log.tail') -Value ('runtime log not present: {0}' -f (Get-FrpLogPath)) -Encoding UTF8
            }
            [void]$sections.Add('runtime-log-tail')
        } catch { }

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
        Write-Host 'Autostart : disabled'
        Write-Host 'Supervisor: Scheduled Task'
        return 0
    }
    if ($Enable) {
        try {
            Install-FrpAutostartTask -TaskName $taskName | Out-Null
        } catch {
            Write-Host $_.Exception.Message
            return 1
        }
        Write-Host ("Autostart enabled: {0} starts the Data Relay Link client at system startup." -f $taskName)
        Write-Host 'Runs as SYSTEM; no interactive login is required.'
        return 0
    }
    if (Test-FrpAutostartTaskExists -TaskName $taskName) {
        Write-Host 'Autostart : enabled'
        Write-Host 'Supervisor: Scheduled Task'
    } else {
        Write-Host 'Autostart : disabled'
        Write-Host 'Supervisor: Scheduled Task'
        Write-Host 'Run: drlink system autostart enable'
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
        return 0
    }
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
        Write-Host "Pending change saved."; Write-Host ""; Write-Host "Apply:"; Write-Host "  system services apply"; Write-Host ""; Write-Host "Discard:"; Write-Host "  system services discard"
        return 0
    })
}

function Invoke-FrpSetServiceCli {
    param([string]$Id, [string]$Property, [string]$Value)
    if (-not $Id -or -not $Property -or [string]::IsNullOrEmpty($Value)) {
        Write-Host 'ERROR: usage: set service <id> <property> <value>'
        return 2
    }
    return (Invoke-FrpWithClientLock {
        try {
            Set-FrpDraftServiceField -Id $Id -Property $Property -Value $Value | Out-Null
        } catch {
            Write-Host $_.Exception.Message
            return 1
        }
        Write-Host "Pending change saved."; Write-Host ""; Write-Host "Apply:"; Write-Host "  system services apply"; Write-Host ""; Write-Host "Discard:"; Write-Host "  system services discard"
        return 0
    })
}

function Invoke-FrpEnableServiceCli {
    param([string]$Id, [bool]$Enable)
    if (-not $Id) {
        Write-Host ("ERROR: usage: {0} service <id>" -f $(if ($Enable) { 'set' } else { 'unset' }))
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
            Write-Host ("Service {0} will be enabled (same public port reused)." -f $Id); Write-Host ""; Write-Host "Apply:"; Write-Host "  system services apply"; Write-Host ""; Write-Host "Discard:"; Write-Host "  system services discard"
        } elseif ($wasEnabled) {
            Write-Host ("Service {0} will be disabled. The public reservation remains until released server-side." -f $Id)
        } else {
            Write-Host ("Service {0} is already disabled in the pending state." -f $Id)
        }
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
        try {
            Install-FrpAutostartTask | Out-Null
        } catch { }
        Start-FrpClient -Force:$Force | Out-Null
        Write-Host 'Client resumed.'
        Write-Host 'Runtime    : active'
        Write-Host 'Autostart  : enabled'
        Write-Host 'Identity   : preserved'
        exit 0
    }
    'resume' {
        if (-not (Test-FrpIsEnrolled)) {
            Write-Host 'ERROR: not enrolled; run install-client.ps1 -ZeroTouch first'
            exit 1
        }
        $st = Get-FrpClientStatus
        $autoOn = Test-FrpAutostartTaskExists
        if ($st.Running -and $autoOn) {
            Write-Host 'Client is already active.'
            Write-Host 'Runtime    : active'
            Write-Host 'Autostart  : enabled'
            Write-Host 'Identity   : preserved'
            exit 0
        }
        try { Install-FrpAutostartTask | Out-Null } catch {
            Write-Host $_.Exception.Message
            exit 1
        }
        Start-FrpClient -Force:$Force | Out-Null
        Write-Host 'Client resumed.'
        Write-Host 'Runtime    : active'
        Write-Host 'Autostart  : enabled'
        Write-Host 'Identity   : preserved'
        exit 0
    }
    'stop' {
        Stop-FrpClient | Out-Null
        try { Uninstall-FrpAutostartTask | Out-Null } catch { }
        exit 0
    }
    'pause' {
        $st = Get-FrpClientStatus
        $autoOn = Test-FrpAutostartTaskExists
        if (-not $st.Running -and -not $autoOn) {
            Write-Host 'Client is already paused.'
            Write-Host 'Runtime is stopped and autostart is disabled.'
            exit 0
        }
        Stop-FrpClient | Out-Null
        try { Uninstall-FrpAutostartTask | Out-Null } catch {
            Write-Host $_.Exception.Message
            exit 1
        }
        Write-Host 'Client paused.'
        Write-Host 'Runtime    : stopped'
        Write-Host 'Autostart  : disabled'
        Write-Host 'Identity   : preserved'
        Write-Host 'Services   : preserved'
        Write-Host 'Public ports: preserved'
        exit 0
    }
    'restart' {
        if (-not (Test-FrpIsEnrolled)) {
            Write-Host 'ERROR: not enrolled; run install-client.ps1 -ZeroTouch first'
            exit 1
        }
        Stop-FrpClient | Out-Null
        Start-FrpClient -Force:$true | Out-Null
        Write-Host 'Client restarted.'
        Write-Host 'Identity and public port reservations were preserved.'
        exit 0
    }
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
    'version' {
        $verPath = Join-Path (Get-FrpWindowsRoot) 'version'
        if (Test-Path -LiteralPath $verPath) {
            Get-Content -LiteralPath $verPath -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
        } else {
            Write-Host 'Data Relay Link Windows client'
        }
        exit 0
    }
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
    'uninstall' { exit (Invoke-FrpClientUninstall) }
    'doctor' { exit (Invoke-FrpClientDoctor) }
    'support-bundle' { exit (Invoke-FrpClientSupportBundle -OutputPath $Output) }
    'autostart' { exit (Invoke-FrpClientAutostart -Enable:$Enable -Disable:$Disable) }
    default { Show-FrpClientHelp; exit 1 }
}
