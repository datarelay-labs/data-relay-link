# Behavioral proof for the 420-character Windows hash-before-execute launcher.
$ErrorActionPreference = 'Stop'

function Assert-FrpTrue {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERT: $Message" }
}
function Write-FrpTestPass { param([string]$Name) Write-Host "PASS $Name" }

function New-StrictLauncher {
    param([string]$Digest)
    $url = 'https://remote.xdr.ooo/i/' + ('A' * 22) + '?platform=windows'
    return "`$h='$Digest';`$p=`"`$env:TEMP\d-`$([guid]::NewGuid()).ps1`";try{curl.exe -fsSLo `$p $url;if(`$LASTEXITCODE){exit `$LASTEXITCODE};if((Get-FileHash `$p).Hash -ne `$h){exit 90};&powershell.exe -NoProfile -ExecutionPolicy Bypass -File `$p;exit `$LASTEXITCODE}finally{Remove-Item `$p -Force -ErrorAction SilentlyContinue}"
}

$root = Join-Path ([IO.Path]::GetTempPath()) 'frp-strict-launcher'
if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
New-Item -ItemType Directory -Path $root | Out-Null
$shim = Join-Path $root 'shim'
$temp = Join-Path $root 'temp'
$stage = Join-Path $root 'stage1.ps1'
$other = Join-Path $root 'other.ps1'
New-Item -ItemType Directory -Path $shim, $temp | Out-Null
Set-Content -LiteralPath $stage -Value "Write-Output 'stage1'`n" -Encoding ascii
Set-Content -LiteralPath $other -Value "Write-Output 'other'`n" -Encoding ascii
$digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $stage).Hash.ToLowerInvariant()
$launcher = New-StrictLauncher -Digest $digest
Assert-FrpTrue ($launcher.Length -eq 420) "launcher length $($launcher.Length)"
Assert-FrpTrue ($launcher.Contains('curl.exe')) 'explicit curl.exe'
Assert-FrpTrue ($launcher.Contains('Get-FileHash')) 'hash before execute'
Assert-FrpTrue ($launcher.Contains('$([guid]::NewGuid())')) 'GUID temp name'
Assert-FrpTrue (-not $launcher.Contains('-Command')) 'no outer -Command'
Assert-FrpTrue (-not $launcher.Contains('Invoke-Expression')) 'no Invoke-Expression'
Assert-FrpTrue (-not $launcher.Contains('iex')) 'no iex'

$onWindows = $env:OS -eq 'Windows_NT'
if ($onWindows) {
    $src = Join-Path $root 'shim.cs'
    @'
using System;
using System.IO;
public class FrpShim {
  public static int Main(string[] args) {
    string name = Path.GetFileName(Environment.GetCommandLineArgs()[0]).ToLowerInvariant();
    if (name.StartsWith("curl")) {
      string rc = Environment.GetEnvironmentVariable("FRP_CURL_RC");
      if (!string.IsNullOrEmpty(rc) && rc != "0") return int.Parse(rc);
      string dest = null;
      for (int i = 0; i < args.Length; i++) {
        if ((args[i] == "-fsSLo" || args[i] == "-o") && i + 1 < args.Length) dest = args[i + 1];
      }
      File.Copy(Environment.GetEnvironmentVariable("FRP_STAGE1_FILE"), dest, true);
      File.WriteAllText(Environment.GetEnvironmentVariable("FRP_CURL_LOG"), dest ?? "");
      return 0;
    }
    File.WriteAllText(Environment.GetEnvironmentVariable("FRP_MARK"), "invoked");
    string child = Environment.GetEnvironmentVariable("FRP_CHILD_RC");
    return string.IsNullOrEmpty(child) ? 0 : int.Parse(child);
  }
}
'@ | Set-Content -LiteralPath $src -Encoding ascii
    # PowerShell 7 rejects Add-Type -OutputType ConsoleApplication and WindowsApplication.
    # The Framework compiler emits the same console shim on Windows PowerShell 5.1 and PowerShell 7.
    $curlExe = Join-Path $shim 'curl.exe'
    $csc = @(
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    Assert-FrpTrue ([bool]$csc) 'Windows csc.exe available for shim'
    & $csc /nologo /target:exe "/out:$curlExe" $src
    Assert-FrpTrue ($LASTEXITCODE -eq 0) "csc.exe exit $LASTEXITCODE"
    Copy-Item -LiteralPath $curlExe -Destination (Join-Path $shim 'powershell.exe')
} else {
    @'
#!/bin/sh
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-fsSLo" ] || [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
rc="${FRP_CURL_RC:-0}"
if [ "$rc" != "0" ]; then exit "$rc"; fi
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|Windows*) ;;
  *) out=$(printf '%s' "$out" | tr '\\' '/') ;;
esac
cp "$FRP_STAGE1_FILE" "$out"
printf '%s' "$out" > "$FRP_CURL_LOG"
exit 0
'@ | Set-Content -LiteralPath (Join-Path $shim 'curl.exe') -Encoding ascii
    @'
#!/bin/sh
printf '%s' invoked > "$FRP_MARK"
exit "${FRP_CHILD_RC:-0}"
'@ | Set-Content -LiteralPath (Join-Path $shim 'powershell.exe') -Encoding ascii
    chmod +x (Join-Path $shim 'curl.exe') (Join-Path $shim 'powershell.exe')
}

function Get-FrpTestHostExe {
    try {
        $p = (Get-Process -Id $PID -ErrorAction Stop).Path
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    } catch { }
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return 'powershell.exe' }
    return 'pwsh'
}

function Invoke-LauncherCase {
    param([string]$Name, [int]$Expect, [string]$StageFile, [string]$CurlRc, [string]$ChildRc)
    $case = Join-Path $root $Name
    New-Item -ItemType Directory -Path $case | Out-Null
    $env:TEMP = $case
    $env:TMP = $case
    $env:FRP_STAGE1_FILE = $StageFile
    $env:FRP_CURL_RC = $CurlRc
    $env:FRP_CHILD_RC = $ChildRc
    $env:FRP_MARK = Join-Path $case 'child.mark'
    $env:FRP_CURL_LOG = Join-Path $case 'curl.log'
    $script = Join-Path $case 'launcher.ps1'
    Set-Content -LiteralPath $script -Value $launcher -Encoding ascii
    $oldPath = $env:PATH
    $env:PATH = $shim + [IO.Path]::PathSeparator + $oldPath
    $hostExe = Get-FrpTestHostExe
    $proc = Start-Process -FilePath $hostExe -ArgumentList @('-NoProfile','-File',$script) -Wait -PassThru -NoNewWindow
    $env:PATH = $oldPath
    Remove-Item Env:FRP_CURL_RC -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CHILD_RC -ErrorAction SilentlyContinue
    Assert-FrpTrue ($proc.ExitCode -eq $Expect) "$Name exit $($proc.ExitCode)"
    $left = @(Get-ChildItem -LiteralPath $case -Filter 'd-*.ps1' -ErrorAction SilentlyContinue)
    Assert-FrpTrue ($left.Count -eq 0) "$Name left temp $($left.Count)"
    return $case
}

$ok = Invoke-LauncherCase -Name 'success' -Expect 0 -StageFile $stage -CurlRc '' -ChildRc '0'
Assert-FrpTrue (Test-Path -LiteralPath (Join-Path $ok 'child.mark')) 'success invoked child'
$dest = Get-Content -LiteralPath (Join-Path $ok 'curl.log') -Raw
Assert-FrpTrue ($dest -match 'd-[0-9a-fA-F-]{36}\.ps1') "GUID temp path $dest"

$curl = Invoke-LauncherCase -Name 'curlfail' -Expect 37 -StageFile $stage -CurlRc '37' -ChildRc '0'
Assert-FrpTrue (-not (Test-Path -LiteralPath (Join-Path $curl 'child.mark'))) 'curl failure skipped child'

$hash = Invoke-LauncherCase -Name 'hashfail' -Expect 90 -StageFile $other -CurlRc '' -ChildRc '0'
Assert-FrpTrue (-not (Test-Path -LiteralPath (Join-Path $hash 'child.mark'))) 'hash mismatch skipped child'

$child = Invoke-LauncherCase -Name 'childfail' -Expect 7 -StageFile $stage -CurlRc '' -ChildRc '7'
Assert-FrpTrue (Test-Path -LiteralPath (Join-Path $child 'child.mark')) 'child failure still ran child'

Remove-Item -LiteralPath $root -Recurse -Force
Write-FrpTestPass 'test-windows-strict-launcher'
