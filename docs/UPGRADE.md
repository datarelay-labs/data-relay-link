# Data Relay Link — Upgrade and Release Channels

> **Status:** v2.4 development operator guide
> **Authority:** `VERSION_POLICY.md` is normative for version, channel, tag, and provenance behavior.

## 1. Product and Relay Engine versions are separate

```text
Data Relay Link product version
≠
Relay Engine (FRP) version
```

Normal version output must identify both.

## 2. Release channels

```text
stable
  immutable fully qualified releases only

preview
  explicit operator opt-in release candidates

development
  exact-SHA engineering builds
```

A version file containing `2.4.0` does not by itself make a build stable.

## 3. Normal update commands

Server:

```text
system update
```

Agent Host:

```text
system update product
system update engine
```

The product update and Relay Engine update are separate lifecycle operations.

## 4. Development and pre-release updates

Before an immutable stable tag exists, candidate validation must use an exact immutable SHA or qualified candidate artifact.

Do not silently fall back from a missing immutable ref to mutable `main` or `latest`.

Normal operator documentation must not advertise mutable development-channel environment variables as the standard update workflow.

## 5. Upgrade invariants

Ordinary product upgrade must preserve, where applicable:

```text
Managed Host / Agent identity
enrollment trust
Remote Service identity
public endpoint reservations
control-plane state
policy state
backup/restore compatibility
release provenance
```

A normal update must not require re-enrollment unless the release explicitly documents an incompatible migration.

## 6. Control-plane migration

The v2.4 target authoritative state is:

```text
/var/lib/drlink/drlink.db
```

Database evolution uses ordered migrations and integrity validation.

Upgrade sequence conceptually follows:

```text
pre-upgrade consistent backup
→ compatibility check
→ migration transaction
→ foreign-key/integrity validation
→ runtime compile/activation
→ generation verification
```

An older binary encountering an unsupported newer schema fails closed rather than guessing.

## 7. Backup before risky upgrade

Release qualification and significant migration paths require a consistent backup.

A live WAL database is backed up using SQLite Online Backup or equivalent consistent snapshot behavior. Do not document naive copying of the live DB as the canonical backup method.

## 8. Rollback and failure

A failed critical activation must restore the prior authoritative/runtime state where possible.

If automatic restoration is incomplete, the product must report that truthfully and direct the operator to diagnostics.

Rollback/restore is a configuration mutation and remains subject to validation and security-impact rules.

## 9. Relay Engine upgrade

Relay Engine is the pinned upstream `fatedier/frp` dependency.

`FRP_UPGRADE.md` contains internal/upstream compatibility detail. Internal `frp-*` helper names or compatibility environment variables in that document are not the public Data Relay Link management interface.

## 10. Stable release transition

Stable publication requires the exact qualified HEAD, immutable tag, immutable artifacts, checksums, release manifest, release notes, and required E2E evidence.

If product/dependency/generated release bytes change after final qualification, qualification must be repeated according to `RELEASE_CHECKLIST.md`.
