# test-client-id-recovery.ps1 — F21: the client id is immutable. A missing,
# truncated, or corrupt state\client-id must be recovered as the exact enrolled
# machine id, and a client id that disagrees with client-state.json must fail
# closed. Silently minting a fresh random id would orphan this client's
# server-side identity and its public port reservations.
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

function Reset-FrpIdTestRoot {
    Remove-FrpWindowsTestRoot
    $env:FRP_WINDOWS_ROOT = Join-Path ([System.IO.Path]::GetTempPath()) ('frp-win-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $env:FRP_WINDOWS_ROOT -Force | Out-Null
    Initialize-FrpDirectories
}

function Save-FrpTestState {
    param([Parameter(Mandatory = $true)][string]$MachineId)
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win-id' -MachineId $MachineId -HostId ('win-id-' + $MachineId.Substring(0, 8)) `
        -Services @{ rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60050; enabled = $true } } `
        -Transport 'tcp' -InstallStatus 'installed' | Out-Null
}

try {
    # Baseline: a genuinely fresh host still mints an id, and it is stable.
    $fresh = Get-FrpOrCreateClientId
    Assert-FrpTrue (Test-FrpClientIdWellFormed -Value $fresh) 'fresh install generates a well-formed client id'
    Assert-FrpEqual $fresh (Get-FrpOrCreateClientId) 'client id is stable across calls'
    Write-FrpTestPass 'test-client-id-recovery (fresh install)'

    # Regression 1 — MISSING: the file is gone but the host is enrolled. The
    # exact enrolled machine id must come back, never a new random one.
    Reset-FrpIdTestRoot
    $enrolled = Get-FrpOrCreateClientId
    Save-FrpTestState -MachineId $enrolled
    Remove-Item -LiteralPath (Get-FrpClientIdPath) -Force
    $recovered = Get-FrpOrCreateClientId
    Assert-FrpEqual $enrolled $recovered 'missing client id recovers the exact enrolled machine id'
    Assert-FrpTrue (Test-Path -LiteralPath (Get-FrpClientIdPath)) 'recovered client id is written back to disk'
    Assert-FrpEqual $enrolled (([System.IO.File]::ReadAllText((Get-FrpClientIdPath))).Trim()) 'persisted id matches client-state.machine_id'
    Assert-FrpEqual $enrolled (Get-FrpOrCreateClientId) 'recovery is stable on the next call'

    # Missing file with no state at all, but a crash-safe pending enrollment:
    # the pending record is authoritative for the in-flight machine id.
    Reset-FrpIdTestRoot
    $pendingId = Get-FrpOrCreateClientId
    Save-FrpPendingEnroll -Phase 'redeemed' -MachineId $pendingId -Hostname 'win-id' `
        -AllocatorUrl 'https://example.test/enroll' -EnrollmentId 'enroll-id' `
        -EnrollmentSecret 'enroll-secret-do-not-use' -Services @() | Out-Null
    Remove-Item -LiteralPath (Get-FrpClientIdPath) -Force
    Assert-FrpEqual $pendingId (Get-FrpOrCreateClientId) 'missing client id recovers from the pending enrollment record'
    Write-FrpTestPass 'test-client-id-recovery (missing)'

    # Regression 2 — SHORT / CORRUPT: a truncated id is not usable, but the
    # committed machine id still is; without one, fail closed.
    Reset-FrpIdTestRoot
    $enrolled2 = Get-FrpOrCreateClientId
    Save-FrpTestState -MachineId $enrolled2
    [System.IO.File]::WriteAllText((Get-FrpClientIdPath), "abc123`n")
    $recovered2 = Get-FrpOrCreateClientId
    Assert-FrpEqual $enrolled2 $recovered2 'short client id recovers the exact enrolled machine id'
    Assert-FrpEqual $enrolled2 (([System.IO.File]::ReadAllText((Get-FrpClientIdPath))).Trim()) 'corrupt file repaired in place'

    Reset-FrpIdTestRoot
    [System.IO.File]::WriteAllText((Get-FrpClientIdPath), "zz`n")
    $threw = $false
    $message = ''
    try {
        Get-FrpOrCreateClientId | Out-Null
    } catch {
        $threw = $true
        $message = [string]$_.Exception.Message
    }
    Assert-FrpTrue $threw 'corrupt client id with nothing to recover from fails closed'
    Assert-FrpTrue ($message -match 'Refusing to generate a new') 'fail-closed message refuses to mint a new identity'
    Assert-FrpEqual 'zz' (([System.IO.File]::ReadAllText((Get-FrpClientIdPath))).Trim()) 'the corrupt file is left untouched for inspection'

    # An unreadable client-state.json is also a fail-closed condition: the
    # machine id cannot be confirmed, so a new one must not be invented.
    Reset-FrpIdTestRoot
    $enrolled3 = Get-FrpOrCreateClientId
    Save-FrpTestState -MachineId $enrolled3
    [System.IO.File]::WriteAllText((Get-FrpStatePath), "{ this is not json")
    Remove-Item -LiteralPath (Get-FrpClientIdPath) -Force
    $threw = $false
    try { Get-FrpOrCreateClientId | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'unreadable client-state.json fails closed instead of regenerating'
    Assert-FrpTrue (-not (Test-Path -LiteralPath (Get-FrpClientIdPath))) 'no replacement client id was written'
    Write-FrpTestPass 'test-client-id-recovery (short / corrupt)'

    # Regression 3 — MISMATCH: a well-formed client id that is not the enrolled
    # machine id. Both values are plausible, so the product must refuse rather
    # than pick one (and must never mint a third).
    Reset-FrpIdTestRoot
    $enrolled4 = Get-FrpOrCreateClientId
    Save-FrpTestState -MachineId $enrolled4
    $foreign = 'ffffffffffffffffffffffffffffffff'
    Assert-FrpTrue ($foreign -ne $enrolled4) 'mismatch fixture differs from the enrolled id'
    [System.IO.File]::WriteAllText((Get-FrpClientIdPath), $foreign + "`n")
    $threw = $false
    $message = ''
    try {
        Get-FrpOrCreateClientId | Out-Null
    } catch {
        $threw = $true
        $message = [string]$_.Exception.Message
    }
    Assert-FrpTrue $threw 'client id mismatched against client-state.machine_id fails closed'
    Assert-FrpTrue ($message -match 'mismatch') 'mismatch is named in the error'
    Assert-FrpTrue ($message -match [regex]::Escape($enrolled4)) 'error reports the enrolled machine id'
    Assert-FrpTrue ($message -match 'Refusing to generate a new') 'mismatch never mints a new identity'
    Assert-FrpEqual $foreign (([System.IO.File]::ReadAllText((Get-FrpClientIdPath))).Trim()) 'mismatched file is not silently rewritten'
    Assert-FrpEqual $enrolled4 ([string](Read-FrpClientState).machine_id) 'client-state.machine_id is not rewritten either'

    # Same rule when the disagreement is between the two local records.
    Reset-FrpIdTestRoot
    $enrolled5 = Get-FrpOrCreateClientId
    Save-FrpTestState -MachineId $enrolled5
    Save-FrpPendingEnroll -Phase 'redeemed' -MachineId $foreign -Hostname 'win-id' `
        -AllocatorUrl 'https://example.test/enroll' -EnrollmentId 'enroll-id' `
        -EnrollmentSecret 'enroll-secret-do-not-use' -Services @() | Out-Null
    Remove-Item -LiteralPath (Get-FrpClientIdPath) -Force
    $threw = $false
    try { Get-FrpOrCreateClientId | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'disagreeing local records fail closed'
    Write-FrpTestPass 'test-client-id-recovery (mismatch)'
} finally {
    Remove-FrpWindowsTestRoot
}
