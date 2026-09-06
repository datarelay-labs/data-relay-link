# Morning Human Real E2E — Final Release Gate

This is the operator checklist for tomorrow morning. It is the last gate
before v2.2.0. Do **not** merge PR #9, tag, or publish a GitHub release until
this checklist passes.

Never paste enrollment codes, bootstrap tickets, `/i/<ticket>` URLs, FRP
tokens, private keys, or generated Zero-Touch secrets into notes.

## Candidate identity

Record after `git fetch origin`:

```bash
cd ~/frp-auto-deploy-dev
git checkout integration/morning-e2e-ready
git pull --ff-only origin integration/morning-e2e-ready
git rev-parse HEAD
git rev-parse origin/integration/morning-e2e-ready
git rev-parse origin/main
```

| Item | Value |
|------|--------|
| Branch | `integration/morning-e2e-ready` |
| PR | https://github.com/datarelay-labs/frp-auto-deploy/pull/9 (do **not** merge) |
| Overnight start HEAD | `54b86e7bc09c15908d654eeee6c6f8ec7193277d` |
| Code+test+dist candidate | `f234b727f097845ab0b9d33b320106c017c9d5d8` |
| Exact candidate HEAD | `git rev-parse origin/integration/morning-e2e-ready` (must match local HEAD; may be this docs commit on top of `f234b72`) |
| Project version | `2.1.3` (dev channel; v2.2.0 not tagged) |
| FRP version | `0.70.1` |

PASS: local HEAD == `origin/integration/morning-e2e-ready`. FAIL: diverge or dirty worktree.

## Overnight close (read first)

Do these **before** section C (final-candidate Mac reboot).

1. **Wake the Mac** (lid / power / Wi-Fi). Overnight it became unreachable after the reboot baseline; public `:6001` dropped and the reverse tunnel hung. The controller **cleared** the stale `127.0.0.1:2222` listener so `com.frp-e2e.reverse-ssh` can bind again.
2. Confirm reverse + product tunnel:
   ```bash
   ssh -o ConnectTimeout=8 frp-e2e-macos hostname
   ssh -o ConnectTimeout=8 -p 6001 -i ~/.ssh/frp_e2e_ed25519 leeruda@221.139.249.112 hostname
   ```
3. **Mac in-place update was NOT applied overnight** (`sudo` password required; do not kickstart launchd to fake reboot PASS). Windows **was** staged in place (same CLIENT `1851ce75`, `:6003`).
4. From **this controller**, after `frp-e2e-macos` works, copy the candidate tree and run **source `--upgrade`** (not channel `frpctl update`, which would miss PR #9). This needs a sudo password at the Mac keyboard or a TTY:
   ```bash
   cd ~/frp-auto-deploy-dev
   git pull --ff-only origin integration/morning-e2e-ready
   rsync -a --delete --exclude .git --exclude tests/tmp ./ frp-e2e-macos:frp-candidate/
   ssh -t frp-e2e-macos 'sudo bash "$HOME/frp-candidate/install-client.sh" --upgrade --source "$HOME/frp-candidate"'
   ssh -t frp-e2e-macos 'sudo frpctl show status; sudo frpctl doctor'
   ```
   PASS: CLIENT ID still `2d6b3b90…`, public port still `6001`, one product `frpc`, launchd loaded, doctor PASS. Then continue at **C**.
5. Windows is already on the overnight candidate libs (`FrpLock.ps1` present). Do **not** re-enroll. Expected `:6003` only — never `:6002`.

## Hosts and expected live state

| Alias | Role | Expected |
|-------|------|----------|
| `frp-e2e-server` | allocator / FRPS (`dp-os-upgrade`) | doctor PASS, 3 clients |
| `frp-e2e-client` | Ubuntu Linux client | optional targeted check |
| `frp-e2e-aws` | Amazon Linux 2023 | CLIENT `ec27f112…`, SSH `:6000` |
| `frp-e2e-rocky8` | Rocky Linux 8.10 | optional targeted check |
| `frp-e2e-macos` | Mac reverse `127.0.0.1:2222` | CLIENT `2d6b3b90…`, SSH `:6001` |
| `frp-e2e-windows` | Windows reverse `127.0.0.1:2223` | CLIENT `1851ce75…`, SSH `:6003` |

Mac: `Leeui-MacBookAir.local`, user `leeruda`, Apple Silicon. Product LaunchDaemon `com.datarelay.frp-auto-deploy.frpc`. E2E-only LaunchAgent `com.frp-e2e.reverse-ssh` (not product).

Windows: `DESKTOP-SLBCN3A`, user `aella`, Windows 10 Pro amd64. Product task `FRPAutoDeployClient` (SYSTEM, boot). Do **not** treat `:6002` as current.

Test reverse SSH is **not** product acceptance.

Public SSH (from controller):

```bash
ssh -o BatchMode=yes -o ConnectTimeout=8 -p 6001 -i ~/.ssh/frp_e2e_ed25519 leeruda@221.139.249.112 hostname
ssh -o BatchMode=yes -o ConnectTimeout=8 -p 6003 -i ~/.ssh/frp_e2e_ed25519 aella@221.139.249.112 hostname
ssh -o BatchMode=yes -o ConnectTimeout=8 -p 6000 -i ~/.ssh/frp_e2e_ed25519 ec2-user@221.139.249.112 hostname
```

---

Legend for every step: **Destructive** = yes/no. **Cleanup** = command or n/a.

## A. Server health

- **Destructive:** no
- **Command:**
  ```bash
  ssh frp-e2e-server 'sudo frpctl show version; sudo frpctl show status; sudo frpctl doctor'
  ```
- **Expected:** Role Server, project 2.1.3, FRP 0.70.1, frps/allocator active, doctor PASS.
- **PASS:** doctor PASS, registry ready, 3 reserved ports.
- **FAIL:** doctor FAIL, allocator/frps down, registry invalid.
- **Cleanup:** n/a

## B. Existing clients

- **Destructive:** no
- **Command:**
  ```bash
  ssh frp-e2e-server 'sudo frpctl show clients; sudo frpctl show client 2d6b3b90; sudo frpctl show client 1851ce75; sudo frpctl show client ec27f112'
  ```
- **Expected:** Mac `2d6b3b90` online `ssh:6001`; Windows `1851ce75` online `ssh:6003`; AL2023 `ec27f112` online `ssh:6000`. No `:6002`.
- **PASS:** all three online with those ports.
- **FAIL:** missing client, wrong port, or `:6002` resurrected.
- **Cleanup:** n/a

## C. Mac reboot persistence (final candidate)

Overnight reboot of the **pre-change** install already passed (`MAC_REBOOT_BASELINE=PASS`, boot `Sep 7 00:16`). `MAC_FINAL_CANDIDATE_POST_CHANGE_REBOOT` is **not** claimed overnight.

This morning reboot is the **final candidate** gate **after** the in-place update in Overnight close step 4.

- **Destructive:** reboot only (identity must survive)
- **Command:**
  ```bash
  ssh frp-e2e-macos 'sysctl -n kern.boottime; hostname'
  ssh frp-e2e-macos 'ps auxww | grep "[f]rpc "; launchctl print system/com.datarelay.frp-auto-deploy.frpc | head -40'
  ssh -p 6001 -i ~/.ssh/frp_e2e_ed25519 leeruda@221.139.249.112 'hostname; sysctl -n kern.boottime'
  ssh frp-e2e-macos 'sudo frpctl show status; sudo frpctl show services; sudo frpctl doctor'
  ```
  Then reboot the Mac from the GUI, wait for reverse `:2222` **and** public `:6001`, and repeat the checks. Confirm boot time changed.
- **Expected:** LaunchDaemon loaded without kickstart, exactly one product `frpc`, CLIENT ID still `2d6b3b90…`, port 6001, doctor PASS. Reverse agent `com.frp-e2e.reverse-ssh` remains separate.
- **PASS:** all of the above after the new boot time.
- **FAIL:** job not loaded, multiple/unrelated frpc, identity/port change, `:6001` SSH fail.
- **Cleanup:** n/a (do not kickstart to fake PASS)

## D. Windows reboot persistence

- **Destructive:** reboot only
- **Command:**
  ```bash
  ssh frp-e2e-windows cmd.exe /c "schtasks /Query /TN FRPAutoDeployClient /V /FO LIST"
  ssh frp-e2e-windows cmd.exe /c "tasklist /FI \"IMAGENAME eq frpc.exe\""
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\frp-auto-deploy\tools\FrpClient.ps1 doctor
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\frp-auto-deploy\tools\FrpClient.ps1 status
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\frp-auto-deploy\tools\FrpClient.ps1 info
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\frp-auto-deploy\tools\FrpClient.ps1 list
  ```
  Reboot Windows, wait for `:2223` and `:6003`, repeat.
- **Expected:** task `FRPAutoDeployClient` SYSTEM + At system start up + `frp-autostart.cmd`; one `frpc.exe` in Services; CLIENT `1851ce75…`; public `:6003`; doctor/status/info/list PASS.
- **PASS:** all persist across reboot without login.
- **FAIL:** task missing/not SYSTEM, extra frpc, identity/port change, `:6002` appears.
- **Cleanup:** n/a

## E. Identity preservation

- **Destructive:** no
- **Command:** compare server `show client` CLIENT ID + `mgmt_fingerprint` before/after reboot and after `frpctl update` (section O).
  - Mac fingerprint (known): `7f9b9d26423ce0db5864b00d21ace9522fd640dce78f683d329d2d0ab16d0645`
  - Windows fingerprint (known): `63c46b0aa720abf553682b3162476b1b02b953152d6921dd93746b787c0ef192`
- **PASS:** CLIENT ID and fingerprint unchanged; no re-enrollment.
- **FAIL:** new CLIENT ID, new fingerprint, or Enrollment Code required for a normal update.
- **Cleanup:** n/a

## F. Port preservation

- **Destructive:** no
- **Command:** `sudo frpctl show clients` and public SSH commands in the host table.
- **PASS:** Mac 6001, Windows 6003, AL2023 6000 unchanged.
- **FAIL:** any of those ports moved or `:6002` returned.
- **Cleanup:** n/a

## G. Windows lifecycle

- **Destructive:** yes (draft/apply on the real Windows client; restore SSH service)
- **Command** (on Windows, via `frp-client.cmd`):
  1. `list` — note `ssh` public 6003
  2. `disable-service ssh` then `apply` — reservation remains, same port
  3. `enable-service ssh` then `apply` — port 6003 reused
  4. `set-service ssh` target if supported — same service ID and 6003
  5. Optional extra custom service, `apply`, then `frpctl release service` **on server** for only that extra ID
- **PASS:** disable keeps reservation; enable reuses 6003; extra release does not drop `ssh`/6003/CLIENT ID.
- **FAIL:** new port allocated, CLIENT ID change, or autostart lost with enabled services.
- **Cleanup:** leave `ssh:6003` enabled. If a temp service was added: `sudo frpctl release service <id>` on server, then Windows `sync`.

## H. Mac lifecycle

- **Destructive:** yes (draft/apply; restore ssh)
- **Command:**
  ```bash
  ssh frp-e2e-macos 'sudo frpctl show services'
  ssh frp-e2e-macos 'sudo frp-client disable-service ssh && sudo frp-client apply-pending'
  ssh frp-e2e-macos 'sudo frp-client enable-service ssh && sudo frp-client apply-pending'
  ```
- **PASS:** same CLIENT ID, same 6001 on enable, launchd still loaded, one frpc.
- **FAIL:** port change, launchctl enable swallowed, or identity change.
- **Cleanup:** ssh service enabled on 6001.

## I. Zero-service

- **Destructive:** yes (use a **temporary** extra service on a non-E2E host, or add then release the last extra — do **not** release Mac/Windows/AL2023 SSH as last service unless you will restore it immediately)
- **Command (preferred):** on an isolated test client or after adding a disposable custom service:
  - release that extra service only → identity remains
  - if last service: zero-service client stays enrolled; frpc may stop; no ghost proxy; autostart not required
  - add/enable a service again → same CLIENT ID, frpc starts, autostart established
- **PASS:** identity preserved; no ghost proxy; autostart required only when enabled public services exist.
- **FAIL:** client deleted on last-service release, or autostart missing with enabled services.
- **Cleanup:** restore the three production SSH reservations (6000/6001/6003).

## J. Release / reconcile

- **Destructive:** yes if you release a real service; prefer a temp service
- **Command:**
  ```bash
  ssh frp-e2e-server 'sudo frpctl release service <TEMP-SERVICE-ID>'
  # then on that client:
  sudo frp-client sync    # Linux/macOS
  # Windows: frp-client.cmd sync
  ssh frp-e2e-server 'sudo frpctl show client <ID>'
  ```
- **PASS:** only that service/reservation gone; client identity remains; `sync` drops local ghost.
- **FAIL:** whole client released, or other ports moved.
- **Cleanup:** do not `release client` on 2d6b3b90 / 1851ce75 / ec27f112 unless replacing them.

## K. Group MVP

- **Destructive:** yes (create/delete a temp group only)
- **Command:**
  ```bash
  ssh frp-e2e-server 'sudo frpctl create group morning-e2e --description "Morning human E2E"'
  ssh frp-e2e-server 'sudo frpctl add client 2d6b3b90 group morning-e2e'
  ssh frp-e2e-server 'sudo frpctl show groups; sudo frpctl show clients --group morning-e2e; sudo frpctl show client 2d6b3b90 groups'
  ssh frp-e2e-server 'sudo frpctl delete group morning-e2e'
  ```
- **PASS:** `grp_…` ID, duplicate name rejected, membership does not change CLIENT ID/ports, delete leaves no dangling IDs. Optional: allocator restart still has groups (if you created a keeper group).
- **FAIL:** dangling IDs, ports/identity changed, malformed registry accepted.
- **Cleanup:** `sudo frpctl delete group morning-e2e` if still present.

## L. Zero-Touch fresh temporary client

- **Destructive:** yes (new temp client; must release afterward)
- **Command:** on server `sudo frpctl create zero-touch` (Linux). Run the generated command **once** on a disposable host or VM — never on `dev-dp-mirror`. Do not save the ticket.
- **PASS:** enroll once, CLIENT ID assigned, doctor PASS, public service works.
- **FAIL:** re-enrollment required on retry with same ticket, or TLS verification disabled.
- **Cleanup:** `sudo frpctl release client <TEMP-ID>` on server; local uninstall on the temp host (does **not** auto-release).

## M. Short URL (only if `bootstrap_hostname` is configured)

Overnight server status: **bootstrap host not configured**. If still unset:

- **Command:** `ssh frp-e2e-server 'sudo frpctl show status'` — confirm `Bootstrap host`.
- **PASS (N/A):** compact `zt1` / full explicit command still work; Windows still download → SHA256 → `powershell.exe -File`. Never `irm | iex`.
- **FAIL:** `curl -k` or `irm | iex` in generated command.
- **Cleanup:** n/a

If bootstrap hostname **is** now set: create Zero-Touch, confirm Linux `https://<bootstrap-host>/i/<ticket>` and Windows `?platform=windows`, run once, then release the temp client.

## N. public_hostname

Overnight: **public hostname not configured**; IP `221.139.249.112` works.

- **Destructive:** no unless you set then unset a hostname
- **Command:** `ssh frp-e2e-server 'sudo frpctl show status'` — Public host / Public hostname.
- **PASS:** IP-based SSH still works; if hostname is set, info text uses the alias without changing CLIENT ID or ports. Product does not manage DNS/ACME/NAT/firewall.
- **FAIL:** ports/identity change, or installer requires DNS.
- **Cleanup:** restore prior `public_hostname` if you changed it.

## O. Update preservation

- **Destructive:** no if `--check` only; in-place update must not re-enroll
- **Command:**
  ```bash
  ssh frp-e2e-server 'sudo frpctl show version; sudo frpctl update --check'
  ssh frp-e2e-macos 'sudo frpctl show version; sudo frpctl update --check'
  # Windows:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\frp-auto-deploy\tools\FrpClient.ps1 update -Check
  ```
- **PASS:** `--check` mutates nothing. A real update keeps CLIENT ID, fingerprint, CA, FRP token, ports, service IDs.
- **FAIL:** re-enrollment, new CLIENT ID, or port change.
- **Cleanup:** n/a

## P. Uninstall / reinstall semantics

- **Destructive:** yes — **do not** uninstall the three production E2E clients unless you are prepared to Zero-Touch re-enroll and may get a **new** CLIENT ID. Prefer a temp client from L.
- **Command (temp client):** local `sudo frpctl uninstall` / Windows `frp-client uninstall`. Confirm server reservations **remain**. Then `sudo frpctl release client <TEMP-ID>` if the reservation should go.
- **PASS:** local uninstall does not release server ports; autostart task/launchd gone; if autostart removal fails, uninstall fails closed and files remain. Reinstall is a new Enrollment Code, not a silent re-use of a used ticket.
- **FAIL:** uninstall reports success while SYSTEM task/launchd still present; or local uninstall dropped server reservations.
- **Cleanup:** release temp client on server if still reserved.

## Q. Final cleanup

- **Destructive:** yes (temp groups/clients/codes only)
- **Command:**
  ```bash
  ssh frp-e2e-server 'sudo frpctl show clients; sudo frpctl show groups; sudo frpctl show enrollments; sudo frpctl doctor'
  ```
- **PASS:** only the three production clients (or documented keepers); no orphan temp reservations; no leftover Enrollment Codes unless documented; Mac `:6001` and Windows `:6003` still work; E2E reverse `:2222`/`:2223` may remain until you decide to remove them.
- **FAIL:** orphan ports, secret material in logs, production clients gone.
- **Cleanup:** delete temp groups; `release client` temp IDs; leave E2E reverse jobs if still needed.

---

## Preflight (do first)

If `frp-e2e-macos` is BLOCKED: wake the Mac, wait for Wi-Fi, then retry. Overnight the reverse `:2222` listener was freed so the E2E LaunchAgent can rebind.

```bash
for h in frp-e2e-server frp-e2e-client frp-e2e-aws frp-e2e-rocky8 frp-e2e-macos frp-e2e-windows; do
  echo -n "$h: "
  ssh -o ConnectTimeout=8 -o BatchMode=yes "$h" hostname || echo BLOCKED
done
```

## E2E-only reverse management (not product)

| Host | Bind | Mechanism |
|------|------|-----------|
| Mac | `127.0.0.1:2222` | LaunchAgent `com.frp-e2e.reverse-ssh` |
| Windows | `127.0.0.1:2223` | E2E scheduled task if present (not `FRPAutoDeployClient`) |

These must stay **separate** from product autostart. Product PASS is public `:6001` / `:6003` plus product launchd/task.

## Release decision

| Flag | Rule |
|------|------|
| Human Real E2E | this checklist |
| Merge PR #9 | only after this checklist PASS **by the owner** |
| Tag `v2.2.0` / GitHub release | only after merge decision |

Until this checklist PASS: **READY_FOR_V2_2_0_RELEASE=NO**.
