# FrpDraft.ps1 — pending/draft service changes CRUD.
# Mirrors Unix client-draft.json: a scratch copy of client-state.json that
# `add-service`/`set-service`/`enable-service`/`disable-service` mutate.
# `apply` sends the draft to the allocator and commits it; `discard` deletes it.

if ((Test-Path variable:script:FrpDraftLoaded) -and $script:FrpDraftLoaded) { return }
$script:FrpDraftLoaded = $true

function Get-FrpDraftPath { Join-Path (Get-FrpStateDir) 'client-draft.json' }

function Test-FrpDraftPending { Test-Path -LiteralPath (Get-FrpDraftPath) }

function Save-FrpDraftRaw {
    <#
    .SYNOPSIS
      Write a plain hashtable/PSCustomObject state document to the draft file
      (pretty JSON, atomic replace).
    #>
    param([Parameter(Mandatory = $true)]$State)
    Initialize-FrpDirectories
    $path = Get-FrpDraftPath
    $pretty = ($State | ConvertTo-Json -Depth 8)
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $pretty + "`n")
    Restrict-FrpFileAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $path -Force
    Restrict-FrpFileAcl -Path $path
    return $path
}

function Ensure-FrpDraftPending {
    <#
    .SYNOPSIS
      Create the draft from current client-state.json if one does not already
      exist, then return the draft path. Mirrors Unix frp_client_ensure_pending.
    #>
    if (-not (Test-Path -LiteralPath (Get-FrpStatePath))) {
        throw 'ERROR: client-state.json is missing; enroll this client first'
    }
    if (-not (Test-FrpDraftPending)) {
        Initialize-FrpDirectories
        $current = [System.IO.File]::ReadAllText((Get-FrpStatePath))
        $path = Get-FrpDraftPath
        $tmp = "$path.tmp"
        [System.IO.File]::WriteAllText($tmp, $current)
        Restrict-FrpFileAcl -Path $tmp
        Move-Item -LiteralPath $tmp -Destination $path -Force
        Restrict-FrpFileAcl -Path $path
    }
    return (Get-FrpDraftPath)
}

function Read-FrpDraftState {
    $path = Get-FrpDraftPath
    if (-not (Test-Path -LiteralPath $path)) {
        throw 'ERROR: no pending service changes'
    }
    $raw = [System.IO.File]::ReadAllText($path)
    return ($raw | ConvertFrom-Json)
}

function Remove-FrpDraftState {
    <#
    .SYNOPSIS
      Discard pending changes. Returns $true if a draft existed.
    #>
    $path = Get-FrpDraftPath
    $existed = Test-Path -LiteralPath $path
    if ($existed) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    return $existed
}

function Get-FrpDraftServiceMap {
    $state = Read-FrpDraftState
    return (ConvertTo-FrpServiceMap -Services $state.services)
}

function Save-FrpDraftServiceMap {
    <#
    .SYNOPSIS
      Persist an edited service map back into the draft, preserving other
      top-level state fields (allocator_url, machine_id, etc).
    #>
    param([Parameter(Mandatory = $true)]$ServiceMap)
    $state = Read-FrpDraftState
    $ht = ConvertTo-FrpPlainObject $state
    $ht['services'] = $ServiceMap
    Save-FrpDraftRaw -State $ht | Out-Null
}

function Test-FrpValidServiceId {
    param([string]$Id)
    return ([string]$Id -cmatch '^[a-z0-9][a-z0-9._-]{0,31}$')
}

function Test-FrpValidServiceName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name) -or $Name.Length -gt 64) { return $false }
    foreach ($ch in $Name.ToCharArray()) {
        $code = [int]$ch
        if ($code -lt 32 -or ($code -ge 127 -and $code -le 159)) { return $false }
    }
    return $true
}

function Test-FrpValidTargetHost {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 253) { return $false }
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        if ($code -lt 32 -or ($code -ge 127 -and $code -le 159)) { return $false }
    }
    if ($Value -match '[ /\\;|&$`''"<>]') { return $false }
    return $true
}

function Test-FrpValidSshUser {
    param([string]$Value)
    return ([string]$Value -cmatch '^[A-Za-z0-9._@-]{1,32}$')
}

function Add-FrpDraftService {
    <#
    .SYNOPSIS
      Add a pending service to the draft. Mirrors Unix
      frp_client_add_service_cli / frp_state_add_payload validation.
    #>
    param(
        [string]$Preset = 'custom',
        [string]$Id,
        [string]$Name,
        [string]$TargetHost = '127.0.0.1',
        [int]$TargetPort,
        [string]$SshUser
    )
    $preset = ([string]$Preset).Trim().ToLowerInvariant()
    switch ($preset) {
        'ssh' {
            if (-not $Id) { $Id = 'ssh' }
            if (-not $Name) { $Name = 'SSH' }
            if ($TargetPort -le 0) { $TargetPort = 22 }
            if (-not $SshUser) { throw 'ERROR: -SshUser is required for ssh services' }
        }
        'http' {
            if (-not $Id) { $Id = 'http' }
            if (-not $Name) { $Name = 'HTTP' }
            if ($TargetPort -le 0) { $TargetPort = 80 }
        }
        'https' {
            if (-not $Id) { $Id = 'https' }
            if (-not $Name) { $Name = 'HTTPS' }
            if ($TargetPort -le 0) { $TargetPort = 443 }
        }
        'custom' {
            if (-not $Id) { throw 'ERROR: -Id is required for custom services' }
            if (-not $Name) { $Name = $Id }
            if ($TargetPort -le 0) { throw 'ERROR: -TargetPort is required' }
        }
        default { throw 'ERROR: preset must be ssh, http, https, or custom' }
    }
    $sid = $Id.Trim().ToLowerInvariant()
    if (-not (Test-FrpValidServiceId -Id $sid)) {
        throw 'ERROR: invalid service id; use [a-z0-9][a-z0-9._-]{0,31}'
    }
    if (-not (Test-FrpValidServiceName -Name $Name)) {
        throw 'ERROR: invalid service display name'
    }
    if (-not (Test-FrpValidTargetHost -Value $TargetHost)) {
        throw 'ERROR: invalid target host'
    }
    if ($TargetPort -lt 1 -or $TargetPort -gt 65535) {
        throw 'ERROR: invalid local_port; must be an integer 1-65535'
    }
    if ($preset -eq 'ssh' -and -not (Test-FrpValidSshUser -Value $SshUser)) {
        throw 'ERROR: invalid ssh_user'
    }

    Ensure-FrpDraftPending | Out-Null
    $map = Get-FrpDraftServiceMap
    if ($map.Contains($sid)) {
        throw ("ERROR: duplicate service id: {0}`n`nA service with this ID already exists.`nService IDs are lowercase and case-insensitive." -f $sid)
    }
    if ($map.Count -ge 32) {
        throw 'ERROR: too many services'
    }
    $rec = [ordered]@{
        id         = $sid
        name       = $Name
        preset     = $preset
        protocol   = 'tcp'
        local_ip   = $TargetHost
        local_port = [int]$TargetPort
        enabled    = $true
    }
    if ($preset -eq 'ssh') { $rec['ssh_user'] = $SshUser }
    $map[$sid] = $rec
    Save-FrpDraftServiceMap -ServiceMap $map
    return $sid
}

function Set-FrpDraftServiceField {
    <#
    .SYNOPSIS
      Edit a pending service property. Mirrors Unix
      frp_client_set_service_field. Editing target host/port never touches
      remote_port (the public reservation is preserved).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Property,
        [Parameter(Mandatory = $true)][string]$Value
    )
    Ensure-FrpDraftPending | Out-Null
    $map = Get-FrpDraftServiceMap
    $sid = $Id.Trim().ToLowerInvariant()
    if (-not $map.Contains($sid)) {
        throw ("ERROR: unknown service: {0}" -f $sid)
    }
    $item = $map[$sid]
    switch ($Property.Trim().ToLowerInvariant()) {
        'name' {
            $trimmed = $Value.Trim()
            if (-not (Test-FrpValidServiceName -Name $Value)) { throw 'ERROR: invalid service display name' }
            $item['name'] = $(if ($trimmed) { $trimmed } else { $sid })
        }
        'target-host' {
            if (-not (Test-FrpValidTargetHost -Value $Value)) { throw 'ERROR: invalid target host' }
            $item['local_ip'] = $Value
        }
        'target-port' {
            $port = 0
            if (-not [int]::TryParse($Value, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
                throw 'ERROR: invalid local_port; must be an integer 1-65535'
            }
            $item['local_port'] = $port
        }
        'ssh-user' {
            if ([string]$item['preset'] -ne 'ssh') { throw 'ERROR: ssh-user is only valid for ssh services' }
            if (-not (Test-FrpValidSshUser -Value $Value)) { throw 'ERROR: invalid ssh_user' }
            $item['ssh_user'] = $Value
        }
        'health-type' {
            $type = $Value.Trim().ToLowerInvariant()
            if ($type -eq 'disabled') {
                if ($item -is [hashtable] -or $item -is [System.Collections.IDictionary]) {
                    if ($item.Contains('health_check')) { $item.Remove('health_check') }
                } else {
                    $item.PSObject.Properties.Remove('health_check')
                }
            } elseif ($type -eq 'tcp' -or $type -eq 'http') {
                $existing = $null
                if ($item -is [hashtable] -or $item -is [System.Collections.IDictionary]) {
                    if ($item.Contains('health_check')) { $existing = $item['health_check'] }
                } elseif ($null -ne $item.PSObject.Properties['health_check']) {
                    $existing = $item.health_check
                }
                $timeout = 3; $interval = 10; $maxFailed = 1; $path = '/health'
                if ($null -ne $existing) {
                    $hcMap = @{}
                    if ($existing -is [hashtable] -or $existing -is [System.Collections.IDictionary]) {
                        foreach ($k in $existing.Keys) { $hcMap[[string]$k] = $existing[$k] }
                    } else {
                        foreach ($p in $existing.PSObject.Properties) { $hcMap[$p.Name] = $p.Value }
                    }
                    if ($hcMap.ContainsKey('timeout_seconds')) { [void][int]::TryParse([string]$hcMap['timeout_seconds'], [ref]$timeout) }
                    if ($hcMap.ContainsKey('interval_seconds')) { [void][int]::TryParse([string]$hcMap['interval_seconds'], [ref]$interval) }
                    if ($hcMap.ContainsKey('max_failed')) { [void][int]::TryParse([string]$hcMap['max_failed'], [ref]$maxFailed) }
                    if ($hcMap.ContainsKey('path') -and [string]$hcMap['path']) { $path = [string]$hcMap['path'] }
                }
                $hc = [ordered]@{
                    type = $type
                    timeout_seconds = $timeout
                    interval_seconds = $interval
                    max_failed = $maxFailed
                }
                if ($type -eq 'http') { $hc['path'] = $path }
                $item['health_check'] = [pscustomobject]$hc
            } else {
                throw 'ERROR: invalid health type; use tcp, http, or disabled'
            }
        }
        'health-timeout' {
            if (-not $item['health_check']) { throw 'ERROR: enable health-type (tcp|http) before setting health-timeout' }
            $n = 0
            if (-not [int]::TryParse($Value, [ref]$n) -or $n -lt 1) { throw 'ERROR: invalid health-timeout; must be a positive integer' }
            $hc = [ordered]@{}
            foreach ($p in $item['health_check'].PSObject.Properties) { $hc[$p.Name] = $p.Value }
            $hc['timeout_seconds'] = $n
            $item['health_check'] = [pscustomobject]$hc
        }
        'health-interval' {
            if (-not $item['health_check']) { throw 'ERROR: enable health-type (tcp|http) before setting health-interval' }
            $n = 0
            if (-not [int]::TryParse($Value, [ref]$n) -or $n -lt 1) { throw 'ERROR: invalid health-interval; must be a positive integer' }
            $hc = [ordered]@{}
            foreach ($p in $item['health_check'].PSObject.Properties) { $hc[$p.Name] = $p.Value }
            $hc['interval_seconds'] = $n
            $item['health_check'] = [pscustomobject]$hc
        }
        'health-max-failed' {
            if (-not $item['health_check']) { throw 'ERROR: enable health-type (tcp|http) before setting health-max-failed' }
            $n = 0
            if (-not [int]::TryParse($Value, [ref]$n) -or $n -lt 1) { throw 'ERROR: invalid health-max-failed; must be a positive integer' }
            $hc = [ordered]@{}
            foreach ($p in $item['health_check'].PSObject.Properties) { $hc[$p.Name] = $p.Value }
            $hc['max_failed'] = $n
            $item['health_check'] = [pscustomobject]$hc
        }
        'health-path' {
            if (-not $item['health_check']) { throw 'ERROR: enable health-type (tcp|http) before setting health-path' }
            $hcType = [string]$item['health_check'].type
            if ($hcType -ne 'http') { throw 'ERROR: health-path is only valid when health-type is http' }
            $path = $Value.Trim()
            if (-not $path.StartsWith('/')) { throw 'ERROR: invalid health path; must start with /' }
            $hc = [ordered]@{}
            foreach ($p in $item['health_check'].PSObject.Properties) { $hc[$p.Name] = $p.Value }
            $hc['path'] = $path
            $item['health_check'] = [pscustomobject]$hc
        }
        default { throw 'ERROR: unknown service property' }
    }
    $map[$sid] = $item
    Save-FrpDraftServiceMap -ServiceMap $map
    return $true
}

function Set-FrpDraftServiceEnabled {
    <#
    .SYNOPSIS
      Enable/disable a pending service. Disabling preserves the public port
      reservation locally (remote_port is untouched); the server-side release
      is a separate operation (drlink release service). At least one enabled
      service must remain. Re-enabling reuses the same remote_port on apply.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Enable
    )
    Ensure-FrpDraftPending | Out-Null
    $map = Get-FrpDraftServiceMap
    $sid = $Id.Trim().ToLowerInvariant()
    if (-not $map.Contains($sid)) {
        throw ("ERROR: unknown service: {0}" -f $sid)
    }
    $item = $map[$sid]
    $currentlyEnabled = ($item['enabled'] -ne $false)
    if ($Enable) {
        $item['enabled'] = $true
    } elseif ($currentlyEnabled) {
        $enabledCount = 0
        foreach ($k in $map.Keys) { if ($map[$k]['enabled'] -ne $false) { $enabledCount++ } }
        if ($enabledCount -le 1) {
            throw 'ERROR: at least one enabled service is required.'
        }
        $item['enabled'] = $false
    }
    $map[$sid] = $item
    Save-FrpDraftServiceMap -ServiceMap $map
    return [bool]$item['enabled']
}
