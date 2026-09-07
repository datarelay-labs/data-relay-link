# Real E2E Final Checklist (template)

> **Documentation examples only.** Hostnames, IPs, usernames, and CLIENT ID
> prefixes below are RFC documentation placeholders (`203.0.113.0/24`,
> `example.invalid`). They are not live lab values.

Operator checklist for a release-candidate Real E2E pass. Do **not** merge,
tag, or publish until the chosen required real gates pass.

Never paste enrollment codes, bootstrap tickets, `/i/<ticket>` URLs, FRP
tokens, private keys, or generated Zero-Touch secrets into notes or public
docs.

## Candidate identity

```bash
git fetch origin
git rev-parse HEAD
git rev-parse origin/<candidate-branch>
git rev-parse origin/main
```

| Item | Value |
|------|--------|
| Candidate branch | `<candidate-branch>` |
| Exact candidate HEAD | `<full SHA>` |
| Project version | `2.2.0` |
| Pinned FRP version | `0.71.0` |

PASS: local HEAD matches the recorded exact candidate. FAIL: diverge or dirty
product tree.

## Example hosts (placeholders)

| Alias | Role | Expected |
|-------|------|----------|
| `frp-server.example.invalid` | allocator / FRPS | doctor PASS |
| `client-linux.example.invalid` | Ubuntu Linux client | SSH on reserved public port |
| `client-al2023.example.invalid` | Amazon Linux 2023 | SSH on reserved public port |
| `client-rocky8.example.invalid` | Rocky Linux 8 | SSH on reserved public port |
| `client-mac.example.invalid` | macOS Apple Silicon | SSH on reserved public port |
| `client-win.example.invalid` | Windows 10 | SSH on reserved public port |

Example public endpoints (documentation IPs only):

```bash
ssh -o BatchMode=yes -o ConnectTimeout=8 -p 6001 -i ~/.ssh/lab_ed25519 \
  operator@203.0.113.20 hostname
ssh -o BatchMode=yes -o ConnectTimeout=8 -p 6003 -i ~/.ssh/lab_ed25519 \
  admin@203.0.113.20 hostname
ssh -o BatchMode=yes -o ConnectTimeout=8 -p 6000 -i ~/.ssh/lab_ed25519 \
  ec2-user@203.0.113.20 hostname
```

## Required gates (record PASS/FAIL)

- [ ] Exact candidate HEAD recorded
- [ ] Server doctor / allocator healthy
- [ ] Zero-Touch fresh enroll (single-use; revoke)
- [ ] Physical Ubuntu client update preserves CLIENT ID + ports
- [ ] Rocky 8 / Rocky 9 where in scope
- [ ] Amazon Linux 2023 identity preservation
- [ ] Amazon Linux 2: container/CI portability only unless a real host exists
- [ ] macOS: FRP version, launchd, doctor, public SSH, reboot
- [ ] macOS: `frpctl` Tab completion under real PTY (`statu` → `status`)
- [ ] Windows PS5.1: task, doctor, public SSH, reboot
- [ ] Windows PS7: CI required; same-host PS7 only if `pwsh` exists
- [ ] `public_hostname` set / unset / IP fallback without identity change
- [ ] Real SSH + HTTP markers (not CLI-only)
- [ ] Groups MVP / backup-restore / sync-reconcile as in release plan
- [ ] FRP rolling: new server / old client when required
- [ ] No unresolved P0/P1/P2

## Windows installer security

Windows Zero-Touch must remain:

```text
download → SHA256 verify → powershell.exe -File
```

Never `irm | iex`.

## After PASS

Only then: update PR body to the exact candidate HEAD, merge if gates allow,
verify `main`, tag, and publish the GitHub Release.
