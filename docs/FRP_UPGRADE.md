# Future upstream FRP upgrades

frp-auto-deploy pins a **tested** FRP version. It never installs GitHub
`latest` automatically.

Current pin: see `VERSION` (`FRP_VERSION`) and `lib/frp-common.sh`
(`FRP_SHA256_AMD64`, `FRP_SHA256_ARM64`, `FRP_WEBSOCKET_PATH=/~!frp`).
`release-manifest.json` records the same pin under `supported_frp_versions`.

## When NOT to upgrade

- A new FRP release exists but this project has not run the compatibility gate.
- The candidate changes `FrpWebsocketPath` away from `/~!frp`.
- Config verify, token file auth, allowPorts, Direct mode, or single443 WSS fails.
- You only want "whatever is newest".

## When to consider upgrading

- The pinned version has a security fix that affects this deployment.
- A required protocol or bugfix is only in a newer tested release.
- You can run the full automated suite plus OCI acceptance afterward.

## How to test a new upstream version

```bash
./scripts/check-frp-compatibility.sh 0.xx.x
```

The script:

1. downloads linux amd64 and arm64 release archives (HTTPS)
2. records SHA256
3. fetches `pkg/util/net/websocket.go` from the same tag
4. **fails** if `/~!frp` is missing
5. runs `frps verify` when a candidate binary is present

It does **not** change production version numbers.

Minimum checks before `--apply`:

- frps/frpc config verify
- token file authentication
- allowPorts
- TLS / Direct / single443 / WSS `/~!frp`
- proxy registration, SSH TCP, multiple services
- zero-service client behavior
- reconnect

## How to update checksums and the pin

```bash
export FRP_NEW_SHA256_AMD64=...
export FRP_NEW_SHA256_ARM64=...
./scripts/bump-frp-version.sh 0.xx.x --apply
./tests/run-all.sh
./tests/run-distro-matrix.sh
./scripts/build-bundles.sh
./scripts/update-sha256sums.sh
./scripts/verify-sha256sums.sh
./scripts/secret-scan.sh
```

Install on a server only with `sudo frpctl frp-update`, which installs the
**pinned** version, never upstream latest.

Informational check:

```bash
sudo frpctl upstream
# or: frp-upstream
```

## How to perform OCI E2E

Follow `docs/OCI_ACCEPTANCE.md`. Do not claim production-ready until that
operator cycle PASSes.

## How to publish a new project release

Follow `docs/RELEASE_CHECKLIST.md` and `docs/RELEASE_VALIDATION.md`.
Do not move or rewrite the frozen `v2.1.0` or `v2.1.1` tags.

## Product upgrade (FRP Auto Deploy)

Product upgrade is separate from upstream FRP binary upgrade.

### Supported upgrade order

```text
1. Upgrade the server first
2. Then upgrade clients
```

- **Server N + Client N-1** is supported during the upgrade window (existing
  tunnels, ports, and management identity remain).
- **Client N + Server N-1** is blocked before mutation with
  `SERVER_VERSION_TOO_OLD`. Clients must not race ahead of the server.

### State preservation contract

A normal project upgrade must preserve:

- CLIENT IDs, service IDs, public ports
- labels / notes / tags / public_hostname
- FRP token, private CA, management identities
- enrollment / bootstrap / audit operational state
- release channel metadata

Update is never re-enrollment.

### Backup / restore version policy

```text
same-version restore = SUPPORTED
cross-version restore = FAIL CLOSED
```

Audit logs (`audit.jsonl` and rotated companions) are part of server
operational state and are included in backup/restore.

### Transaction model

```text
PRECHECK → DOWNLOAD → VERIFY → SNAPSHOT → STAGE → COMMIT → RESTART → HEALTH → SUCCESS
```

Failure after mutation triggers rollback. If rollback fails, the operator
sees an explicit `RECOVERY_REQUIRED` marker.

## Legacy client secure bridge

Legacy clients installed before secure project-update metadata
require a one-time verified bridge.

Those installs have no trustworthy persisted `RELEASE_CHANNEL`,
`SOURCE_REF`, or `BUNDLE_SHA256`. The updater that was on the host
then cannot retroactively verify an artifact before executing it.
A later bundle that hashes itself only proves **artifact identity**,
not **externally verified artifact integrity**. Do not pipe a mutable
`main` URL into `sudo`.

One-time verified bridge (development line: `channel=dev`,
`source_ref=main`):

1. Choose an **immutable commit SHA** (logical identity stays `dev` / `main`).
2. Download `SHA256SUMS` and `dist/bootstrap-client.sh` from **that same commit**.
3. Extract the expected digest for `dist/bootstrap-client.sh`.
4. Hash the downloaded bundle. Require `expected == actual`.
5. Run the verified bundle with explicit channel and source-ref.

```bash
COMMIT=<immutable-commit-sha>
BASE="https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/${COMMIT}"
curl -fsSL "${BASE}/SHA256SUMS" -o SHA256SUMS
curl -fsSL "${BASE}/dist/bootstrap-client.sh" -o bootstrap-client.sh
expected="$(awk '$2=="dist/bootstrap-client.sh" {print $1; exit}' SHA256SUMS)"
actual="$(sha256sum bootstrap-client.sh | awk '{print $1}')"
[[ "$expected" == "$actual" ]] || { echo "SHA256 mismatch"; exit 1; }
sudo env FRP_RELEASE_CHANNEL=dev FRP_EXPECTED_SOURCE_REF=main \
  FRP_BUNDLE_SHA256="$actual" bash bootstrap-client.sh --upgrade
```

`sudo frpctl update --check` is read-only. If it reports
`LEGACY_CLIENT_SECURE_BRIDGE_REQUIRED` or `Legacy secure bridge required`,
do not mutate the host until the procedure above succeeds.

A client that was incorrectly labeled `stable` / `v2.1.0` with
`BUNDLE_SHA256` unknown is not automatically `dev`. Recover it the same
way: explicit `FRP_RELEASE_CHANNEL=dev`, expected `source_ref=main`, and
a verified candidate whose manifest is `dev` / `main`.

## Server project-update build identity

`sudo frpctl project-update --check` is read-only. Availability is not decided
from `PROJECT_VERSION` alone:

- installed version **less than** candidate → update available
- installed version **greater than** candidate → downgrade refused
- same version and installed bundle SHA **equals** the SHA256SUMS digest → not needed
- same version and SHA differs, or installed SHA is unknown while the target
  SHA was externally verified → update available

Production remote updates persist `FRP_BUNDLE_SHA256` from SHA256SUMS.
`frp-project-update --source DIR` is local-source identity (staged project-tree
digest). That digest is not a substitute for SHA256SUMS verification.

## Rollback

- Server FRP binary: `frp-update` restores the previous binary on health failure.
- Server project tools: use `frp-project-update` rollback / restore from backup.
- Disaster recovery: `sudo frpctl restore <backup>` after a validated backup.
