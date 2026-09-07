# Morning Human Real E2E Checklist

Candidate platforms/features in this branch are **not stable** until this
checklist passes. Never paste enrollment codes, bootstrap tickets, `/i/<ticket>`
URLs, tokens, or generated commands into reports.

## FAST PATH (10 steps)

1. Owner: bring up every host/tunnel. Overnight, `frp-e2e-macos`
   (`127.0.0.1:2222`) was unreachable and `frp-e2e-windows`
   (`221.139.249.115:22`) timed out.
2. Check out and identify the exact candidate:
   `git checkout integration/morning-e2e-ready && git fetch origin && git rev-parse HEAD && git rev-parse origin/integration/morning-e2e-ready`.
   The two SHAs must match.
3. Preflight aliases:
   `for h in frp-e2e-server frp-e2e-client frp-e2e-aws frp-e2e-rocky8 frp-e2e-macos frp-e2e-windows; do ssh -o ConnectTimeout=8 "$h" hostname || echo "BLOCKED $h"; done`.
4. On the server run:
   `ssh frp-e2e-server 'sudo frpctl show version; sudo frpctl show status; sudo frpctl doctor'`.
5. Run Linux baseline:
   `FRP_E2E_PROFILE=baseline-linux ./tests/run-real-e2e.sh`.
6. Run Rocky and Amazon:
   `FRP_E2E_PROFILE=rocky-linux-8.10 ./tests/run-real-e2e.sh` then
   `FRP_E2E_PROFILE=amazon-linux-2023 ./tests/run-real-e2e.sh`.
7. Run the macOS launchd scenario in section D and the Windows hash-verified
   PowerShell `-File` scenario in section E.
8. Run the Short URL and Group MVP checks in sections F and G.
9. Run update/automatic-rollback and backup/restore checks in sections H and I.
10. Save only redacted evidence (commands, timestamps, SHAs, status/doctor
    output, assigned non-secret ports, and failure logs) and record PASS,
    FAIL, or BLOCKED for every section.

## A. Linux baseline

- **Prerequisite:** `frp-e2e-server` and `frp-e2e-client` resolve through SSH;
  the client has an existing SSH user/key and outbound access.
- **Command:** `FRP_E2E_PROFILE=baseline-linux ./tests/run-real-e2e.sh`.
  Then verify with
  `ssh frp-e2e-server 'sudo frpctl show clients; sudo frpctl doctor'` and
  `ssh frp-e2e-client 'sudo frpctl show status; sudo frpctl show services; sudo frpctl doctor'`.
- **Expected result:** install, Zero-Touch enrollment, published SSH, service
  lifecycle, reboot reconnect, backup/restore, and reinstall checks pass.
- **What must remain unchanged:** CLIENT ID, management identity, CA, FRP
  token, SSH public port, and server-side reservations across reboot/update;
  client uninstall must not release server reservations.
- **Failure evidence to collect:** the redacted `e2e-reports/real-e2e-*`
  directory, `summary.txt`, failing step log, `sudo frpctl doctor`, and
  `systemctl status frps frp-port-allocator frpc` as applicable.

## B. Rocky Linux 8.10

- **Prerequisite:** owner confirms `frp-e2e-rocky8` is Rocky Linux 8.10,
  reachable, and SELinux state is recorded with `getenforce`.
- **Command:** `FRP_E2E_PROFILE=rocky-linux-8.10 ./tests/run-real-e2e.sh`;
  inspect with
  `ssh frp-e2e-rocky8 'cat /etc/rocky-release; getenforce; sudo frpctl show status; sudo frpctl doctor'`.
- **Expected result:** the full Real E2E completes and SSH through the assigned
  public port reconnects after reboot.
- **What must remain unchanged:** SELinux mode and host firewall policy are not
  changed by the installer; identity, CA/token, and public ports persist.
- **Failure evidence to collect:** redacted E2E report, `getenforce`,
  `sudo journalctl -u frpc --no-pager`, `sudo frpctl doctor`, and any AVC lines
  from `sudo ausearch -m AVC -ts recent`.

## C. Amazon Linux

- **Prerequisite:** owner confirms `frp-e2e-aws` is the intended Amazon Linux
  host and its security group permits the existing management path.
- **Command:** `FRP_E2E_PROFILE=amazon-linux-2023 ./tests/run-real-e2e.sh`;
  inspect with
  `ssh frp-e2e-aws 'cat /etc/os-release; sudo frpctl show status; sudo frpctl show services; sudo frpctl doctor'`.
- **Expected result:** the full Real E2E passes, including outbound enrollment,
  published SSH, reboot reconnect, and lifecycle checks.
- **What must remain unchanged:** security groups, host firewall, SSH account,
  CLIENT ID, identity, CA/token, and assigned public ports.
- **Failure evidence to collect:** redacted E2E report, OS release,
  `sudo journalctl -u frpc --no-pager`, client/server doctor output, and the
  failed external SSH command/result.

## D. macOS

- **Prerequisite:** owner restores the tunnel/host for `frp-e2e-macos`
  (`127.0.0.1:2222` was unreachable overnight); Apple Silicon, macOS 11+,
  `sudo`, `curl`, `openssl`, `python3`, `tar`, and `shasum` are available.
- **Command:** on `frp-e2e-server`, run `sudo frpctl create zero-touch`, choose
  Linux/Unix and the required service profile, then run the generated command
  directly on the Mac without recording it. Verify:
  `ssh frp-e2e-macos 'sudo frpctl show status; sudo frpctl show services; sudo frpctl doctor; sudo launchctl print system/com.datarelay.frp-auto-deploy.frpc'`.
- **Expected result:** Darwin arm64 is detected, FRP 0.71.0 is installed, the
  launchd daemon is running, enrollment appears on the server, and the
  published service is reachable.
- **What must remain unchanged:** Remote Login, firewall, users, Homebrew
  packages, CLIENT ID, identity, CA/token, and public port reservations.
- **Failure evidence to collect:** `sw_vers`, `uname -m`, redacted generated
  command output, `launchctl print`, `sudo frpctl doctor`, and
  `/Library/Application Support/frp-auto-deploy/logs/frpc.err.log`.

## E. Windows

- **Prerequisite:** owner restores SSH/host access to `frp-e2e-windows`
  (`221.139.249.115:22` timed out overnight); Windows 10/11 or Server 2019+,
  amd64, and Windows PowerShell 5.1+ are present.
- **Command:** on `frp-e2e-server`, run `sudo frpctl create zero-touch`, choose
  Windows and RDP/custom service. On Windows run the generated PowerShell
  command. For Short URL it must fetch `/i/<ticket>?platform=windows`, download
  `SHA256SUMS` and `bootstrap-client.ps1`, verify SHA256, and invoke
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`; never use
  `irm | iex`. Verify with
  `powershell.exe -NoProfile -Command "& 'C:\ProgramData\frp-auto-deploy\tools\frp-client.cmd' status; & 'C:\ProgramData\frp-auto-deploy\tools\frp-client.cmd' info; & 'C:\ProgramData\frp-auto-deploy\tools\frp-client.cmd' doctor"`.
- **Expected result:** hash verification succeeds before `-File`, one-time
  enrollment completes, `frpc.exe` starts, and the RDP/custom port is reachable.
- **What must remain unchanged:** Windows firewall, RDP enablement,
  credentials, CLIENT ID, DPAPI-protected identity, CA/token, and public port.
- **Failure evidence to collect:** redacted PowerShell transcript, exit code,
  `frp-client.cmd doctor`, Windows version/architecture, and
  `C:\ProgramData\frp-auto-deploy\logs\frpc.log`.

## F. Zero-Touch Short URL

- **Prerequisite:** operator-managed bootstrap DNS, publicly trusted TLS, and
  reverse proxy are healthy; raw `/i/<ticket>` access logging is disabled or
  redacted.
- **Command:** check
  `ssh frp-e2e-server 'sudo frpctl show status; sudo frpctl doctor'`; create
  Linux with `sudo frpctl create zero-touch` or Windows with the same guided
  command. Run the generated command once on the target. Use
  `sudo frpctl create enrollment` separately to confirm manual Enrollment Code
  creation remains available.
- **Expected result:** Linux output uses `https://<bootstrap-host>/i/<ticket>`;
  Windows uses the same path with `?platform=windows`; stock OS TLS succeeds,
  enrollment is one-time, and `sudo frpctl show enrollments` exposes no secret.
- **What must remain unchanged:** Private CA management trust, WSS `/~!frp`,
  the `zt1` fallback when bootstrap hostname is unset, and existing clients.
- **Failure evidence to collect:** redacted HTTP status/TLS issuer and expiry,
  reverse-proxy logs with URI removed, server `show enrollments`, allocator
  journal, and client bootstrap error.

## G. Group MVP

- **Prerequisite:** at least one enrolled client; note its non-secret CLIENT ID
  from `sudo frpctl show clients`.
- **Command:** on the server run:
  `sudo frpctl show groups`;
  `sudo frpctl create group morning-e2e --description "Morning human E2E"`;
  `sudo frpctl add client <CLIENT-ID> group morning-e2e`;
  `sudo frpctl show clients --group morning-e2e`;
  `sudo frpctl show client <CLIENT-ID> groups`.
- **Expected result:** the group has an immutable `grp_...` ID, the client is
  listed once, membership survives server restart, and no secret is displayed.
- **What must remain unchanged:** CLIENT ID, services, status, identity,
  labels/tags, and public ports.
- **Failure evidence to collect:** command output, `sudo frpctl show audit`,
  `sudo frpctl doctor`, and the redacted group/client records involved.

## H. Update / rollback

- **Prerequisite:** sections A/G pass, a current backup exists, and server is
  updated before clients.
- **Command:** server:
  `sudo frpctl update project --check` then `sudo frpctl update project`;
  client: `sudo frpctl update project --check` then
  `sudo frpctl update project`. Verify each side with
  `sudo frpctl show version; sudo frpctl show status; sudo frpctl doctor`.
- **Expected result:** verified update succeeds. If any commit/restart/health
  step fails, transactional rollback restores the prior healthy build and
  reports rollback; rollback failure reports `RECOVERY_REQUIRED` and is not a
  success.
- **What must remain unchanged:** CLIENT/service/group IDs, group membership,
  labels/notes/tags, CA, FRP token, management identity, release channel, and
  public ports; no re-enrollment.
- **Failure evidence to collect:** check/update output, pre/post version and
  build SHA, doctor output, relevant journals, rollback markers, and any
  `*-update-pending.json` path (do not print its contents).

## I. Backup / restore

- **Prerequisite:** same project version on backup and restore target; record a
  client's label, groups, services, and public ports before starting.
- **Command:** on the server:
  `sudo frpctl create backup /var/lib/frp-auto-deploy/backups/morning-e2e.tar.gz`;
  make a harmless metadata change with
  `sudo frpctl set client <CLIENT-ID> label morning-e2e-mutated`;
  restore with
  `sudo frpctl restore backup /var/lib/frp-auto-deploy/backups/morning-e2e.tar.gz`;
  then run `sudo frpctl show client <CLIENT-ID>; sudo frpctl show groups; sudo frpctl doctor`.
- **Expected result:** archive validation, snapshot, restore, service restart,
  and doctor pass; the pre-backup label/group state and tunnel are restored.
- **What must remain unchanged:** CA, FRP token, CLIENT/management identity,
  service IDs, public ports, and unaffected clients; cross-version restore must
  fail closed.
- **Failure evidence to collect:** backup path/mode/size (not contents),
  restore output, pre/post non-secret inventory, doctor/journal output,
  rollback message, and pending-marker paths.

## CLOCK_SKEW decision

**USEFUL_LATER.** `feature/clock-skew-tolerant-auth` is stacked with unrelated
Windows, enrollment-retention, release, and generated-bundle work. There is no
tiny isolated patch suitable for tonight; do not implement or cherry-pick clock
skew before the morning human E2E.
