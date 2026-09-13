# OCI acceptance plan (operator)

Automated integration may PASS while this real-environment cycle is still
`NOT_RUN_PENDING_OPERATOR_ACCEPTANCE`. Do not tag `v2.1.1` until this list
PASSes. Do not destroy the production OCI instance merely to test restore.

## Existing server upgrade

1. Record registry, labels, notes, tags, ports, CA fingerprint, token digest, installer URL.
2. `sudo drlink update project`
3. Confirm registry/labels/notes/tags/ports/CA/token/mode retained.
4. `sudo drlink doctor`

## Existing client update

1. Record identity files, public ports, SSH reachability.
2. `sudo drlink update` on the client
3. Identity, ports, SSH still work. No re-enrollment.

## New client

1. `sudo drlink zero-touch create` / `sudo drlink enrollment create` / one-line installer with label + SSH user
2. List client (`sudo drlink client list`), connect over published SSH

## Server metadata

1. Change label, note, tags
2. Client machine identity and public ports unchanged

## Pending enrollment

1. Create ticket → list shows pending (no raw secret)
2. Revoke pending/bound
3. Confirm expired and completed states

## Bulk enrollment

1. Create at least 3 independent tickets (CSV or `--count`)
2. Prove one ticket cannot enroll two machines

## Zero-service client

1. Enroll with no published service
2. Visible in `sudo drlink client list` with 0 services
3. Add SSH later → port allocated → SSH succeeds

## Backup / Restore

1. `sudo drlink backup create`
2. Record state, change metadata
3. Restore from that backup (`sudo drlink backup restore <path>`)
4. Exact expected state; `doctor` PASS
5. Use a controlled restore; do not wipe the live host as the only copy

## Updates

1. Client project update
2. Server project update
3. `sudo drlink update engine --check` / pinned FRP only
4. `sudo drlink server upstream` informational, no install

## Reboot recovery

Reboot the server. Verify frontend, allocator, frps, client proxies, SSH.
