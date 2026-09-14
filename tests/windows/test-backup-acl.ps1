# test-backup-acl.ps1 — F08: backups contain frpc.toml, which carries the
# plaintext FRP token. Every backup directory and every copied file must get
# the product-enforced restrictive ACL, so an unauthorized principal can never
# read the token out of backups\.
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

function Assert-FrpPathRestricted {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('File', 'Directory')][string]$Kind = 'File',
        [string]$Label
    )
    if (-not $Label) { $Label = $Path }
    Assert-FrpTrue (Test-Path -LiteralPath $Path) ("$Label exists")
    if (Test-FrpIsWindowsHost) {
        $acl = Get-Acl -LiteralPath $Path
        Assert-FrpTrue ($acl.AreAccessRulesProtected) "$Label does not inherit parent ACLs"
        $allowed = @('NT AUTHORITY\SYSTEM', 'BUILTIN\ADMINISTRATORS')
        foreach ($rule in @($acl.Access)) {
            $who = ([string]$rule.IdentityReference.Value).ToUpperInvariant()
            Assert-FrpTrue ($allowed -contains $who) ("$Label grants no access to unauthorized principal '$who'")
        }
        return
    }
    $mode = ''
    try { $mode = ([string]([System.IO.File]::GetUnixFileMode($Path))) } catch { $mode = '' }
    if (-not $mode) { $mode = (& stat -c '%A' -- $Path) }
    $expected = $(if ($Kind -eq 'Directory') { 'UserExecute, UserWrite, UserRead' } else { 'UserWrite, UserRead' })
    Assert-FrpEqual $expected $mode "$Label is owner-only (no group/other access)"
}

function New-FrpSignedEnrollResponse {
    param($Services)
    $respObj = [ordered]@{
        frp_server      = 'example.test'
        frp_server_port = 7000
        frp_transport   = 'tcp'
        services        = @($Services)
    }
    $respObj['response_hmac'] = (Get-FrpHmacHex -Secret (Read-FrpIdentityMac) `
            -Message (Get-FrpCanonicalJson -Object $respObj))
    return (Get-FrpCanonicalJson -Object $respObj)
}

$token = 'frp-token-backup-secret'
try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    Save-FrpIdentityMac -MacKeyHex (New-FrpNonce) | Out-Null

    $services = @{
        rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60030; enabled = $true }
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win-backup' -MachineId $mid -HostId 'abcd1234' `
        -Services $services -Transport 'tcp' -InstallStatus 'installed' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token $token `
        -HostId 'abcd1234' -Services $services -Transport 'tcp' | Out-Null

    # The shared backups directory itself must be restricted, not just its children.
    Assert-FrpPathRestricted -Path (Get-FrpBackupDir) -Kind Directory -Label 'backups\'

    # Apply snapshots frpc.toml before activating; force the activation failure
    # path so the snapshot is written and the rollback reads it back.
    Add-FrpDraftService -Preset 'custom' -Id 'web' -Name 'Web' -TargetHost '10.0.0.5' -TargetPort 8080 | Out-Null
    $env:FRP_SKIP_CONNECTIVITY_CHECK = '1'
    function Invoke-FrpHttpsJson {
        param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
        return (New-FrpSignedEnrollResponse -Services @(
                [ordered]@{ id = 'rdp'; remote_port = 60030 }
                [ordered]@{ id = 'web'; remote_port = 60031 }
            ))
    }
    $env:FRP_WINDOWS_FAIL_APPLY_ACTIVATE = '1'
    $rc = Invoke-FrpClientApplyDraft
    Remove-Item Env:FRP_WINDOWS_FAIL_APPLY_ACTIVATE -ErrorAction SilentlyContinue
    Assert-FrpEqual 1 $rc 'apply rolled back (snapshot exercised)'

    $applyBackups = @(Get-ChildItem -LiteralPath (Get-FrpBackupDir) -Directory | Where-Object { $_.Name -like 'apply-*' })
    Assert-FrpTrue ($applyBackups.Count -ge 1) 'apply created a backup directory'
    foreach ($dir in $applyBackups) {
        Assert-FrpPathRestricted -Path $dir.FullName -Kind Directory -Label ("backup dir " + $dir.Name)
        foreach ($file in @(Get-ChildItem -LiteralPath $dir.FullName -File)) {
            Assert-FrpPathRestricted -Path $file.FullName -Kind File -Label ("backup file " + $file.Name)
        }
    }
    $backupToml = Join-Path $applyBackups[0].FullName 'frpc.toml'
    Assert-FrpTrue (Test-Path -LiteralPath $backupToml) 'apply backup snapshotted frpc.toml'
    Assert-FrpTrue ((Get-Content -LiteralPath $backupToml -Raw) -match [regex]::Escape($token)) `
        'backup really does hold the plaintext token (so the ACL is what protects it)'

    # Engine update snapshots the same secret-bearing file.
    $clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
    $clientText = Get-Content -LiteralPath $clientPath -Raw
    $m = [regex]::Match($clientText, '(?ms)^function Invoke-FrpClientUpdate \{.*?\n\}')
    Assert-FrpTrue $m.Success 'found Invoke-FrpClientUpdate'
    Invoke-Expression $m.Value
    function Install-FrpWindowsBinary {
        param($DownloadUrl, $ExpectedSha256)
        Set-Content -LiteralPath (Get-FrpFrpcPath) -Value 'NEW_BINARY'
        return (Get-FrpFrpcPath)
    }
    New-Item -ItemType Directory -Path (Get-FrpBinDir) -Force | Out-Null
    Set-Content -LiteralPath (Get-FrpFrpcPath) -Value 'ORIGINAL_BINARY'
    $DownloadUrl = 'https://example.test/frp.zip'
    $ExpectedSha256 = 'a' * 64
    $rcUpdate = Invoke-FrpClientUpdate
    Assert-FrpEqual 0 $rcUpdate 'engine update completed'

    $updateBackups = @(Get-ChildItem -LiteralPath (Get-FrpBackupDir) -Directory | Where-Object { $_.Name -like 'update-*' })
    Assert-FrpTrue ($updateBackups.Count -ge 1) 'update created a backup directory'
    foreach ($dir in $updateBackups) {
        Assert-FrpPathRestricted -Path $dir.FullName -Kind Directory -Label ("backup dir " + $dir.Name)
        foreach ($file in @(Get-ChildItem -LiteralPath $dir.FullName -File)) {
            Assert-FrpPathRestricted -Path $file.FullName -Kind File -Label ("backup file " + $file.Name)
        }
    }
    $updateToml = Join-Path $updateBackups[0].FullName 'frpc.toml'
    Assert-FrpTrue ((Get-Content -LiteralPath $updateToml -Raw) -match [regex]::Escape($token)) `
        'update backup holds the plaintext token'

    # Fail closed: a backup must never be created with an ACL the product could
    # not enforce.
    $env:FRP_WINDOWS_FAIL_ACL = '1'
    $threw = $false
    try { New-FrpBackupRoot -Prefix 'acl-probe' | Out-Null } catch { $threw = $true }
    Remove-Item Env:FRP_WINDOWS_FAIL_ACL -ErrorAction SilentlyContinue
    Assert-FrpTrue $threw 'backup creation fails closed when the ACL cannot be applied'

    Write-FrpTestPass 'test-backup-acl'
} finally {
    Remove-Item Env:FRP_WINDOWS_FAIL_ACL -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_FAIL_APPLY_ACTIVATE -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_SKIP_CONNECTIVITY_CHECK -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
