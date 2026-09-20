# OCI acceptance plan (operator)

Automated integration may PASS while this real-environment cycle is still
`NOT_RUN_PENDING_OPERATOR_ACCEPTANCE`. Do not tag `v2.1.1` until this list
PASSes. Do not destroy the production OCI instance merely to test restore.

## Existing server upgrade

1. Record registry, labels, notes, tags, ports, CA fingerprint, token digest, installer URL.
2. `sudo drlink system update product`
3. Confirm registry/labels/notes/tags/ports/CA/token/mode retained.
4. `sudo drlink system diagnostics`

## Existing client update

1. Record identity files, public ports, SSH reachability.
2. `sudo drlink` → `update product` on the client
3. Identity, ports, SSH still work. No re-enrollment.

## New client

1. `sudo drlink` → `set client` / `set enrollment`
2. List client (`show clients`), connect over published SSH

## Server metadata

1. Change label, note, tags (`set client …`)
2. Client machine identity and public ports unchanged

## Pending enrollment

1. Create ticket → list shows pending (no raw secret)
2. Revoke pending/bound (`revoke enrollment …`)
3. Confirm expired and completed states

## Bulk enrollment

1. Create at least 3 independent tickets (`set enrollment bulk`)
2. Prove one ticket cannot enroll two machines

## Zero-service client

1. Enroll with no Remote Service
2. Visible in `show clients` with 0 services
3. Add SSH later → port allocated → SSH succeeds

## Backup / Restore

1. `create backup`
2. Record state, change metadata
3. Restore from that backup (`restore backup <path>`)
4. Exact expected state; `system diagnostics` PASS
5. Use a controlled restore; do not wipe the live host as the only copy

## Updates

1. Client project update
2. Server project update
3. `sudo drlink system update check-engine` / pinned Relay Engine (FRP) only
4. `sudo drlink system update check-engine` informational, no install

## Reboot recovery

Reboot the server. Verify frontend, allocator, frps, client proxies, SSH.
