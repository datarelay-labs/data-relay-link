# Data Relay Link Version Policy

Normative version and release-channel rules for Data Relay Link (`drlink`).
This document does not redefine product behavior described in
`docs/PRODUCT_MASTER.md`; it is the version/release governance contract.

Cross-references:

- Product truth: `docs/PRODUCT_MASTER.md`
- Release operator checklist: `docs/RELEASE_CHECKLIST.md`
- Release validation evidence: `docs/RELEASE_VALIDATION.md`
- CLI surface: `docs/Data Relay Link CLI Information Architecture.md`
- Manifest schema: `RELEASE_MANIFEST.schema.json`

## Single source of truth

`VERSION` is the authoritative product-version source:

```text
PROJECT_VERSION=<SemVer MAJOR.MINOR.PATCH>
FRP_VERSION=<independently pinned Relay Engine version>
RELEASE_CHANNEL=<development|preview|stable>
```

Rules:

- Do not mechanically couple `PROJECT_VERSION` to the upstream FRP version.
- A plain `PROJECT_VERSION=2.4.0` does **not** by itself make a build stable.
- Internal phases, audits, worktrees, and commits do not consume product versions.
- Fixes made before the immutable `v2.4.0` tag do **not** become `2.4.1`.

Logical provenance fields (persisted at install / recorded in the release
manifest):

```text
PRODUCT_VERSION     = PROJECT_VERSION
RELEASE_CHANNEL     = development | preview | stable
SOURCE_HEAD         = exact 40-character Git SHA
SOURCE_REF          = immutable tag, RC tag, exact SHA, or explicit main tip
UPSTREAM_ENGINE_VERSION = FRP_VERSION
```

## Display identities

| Build class              | Display identity        | Channel       |
|--------------------------|-------------------------|---------------|
| Non-tag engineering build | `2.4.0-dev+g<SHORT_SHA>` | `development` |
| Release candidate        | `2.4.0-rc.N`            | `preview`     |
| Stable tagged release    | `2.4.0`                 | `stable`      |
| First post-release fix   | `2.4.1`                 | `stable`      |
| Compatible feature       | `2.5.0`                 | `stable`      |
| Incompatible change      | `3.0.0`                 | `stable`      |

`show version` must never report `Channel: stable` without matching immutable
stable-tag provenance. Product version and Relay Engine (FRP) version remain
distinct labels.

## Channel and installer refs

### Before the stable tag exists

```text
installer_ref = exact 40-character SHA (or immutable RC artifact)
channel       = development (engineering) or preview (explicit RC)
```

Never advertise or generate URLs for a future stable tag such as `v2.4.0`
before that tag exists. Missing immutable refs must fail closed; do not silently
fall back to `main` or `latest`.

### After the stable release

```text
installer_ref = immutable vMAJOR.MINOR.PATCH tag (or immutable release artifact)
channel       = stable
```

Explicit tip-following remains an opt-in (`FRP_RELEASE_CHANNEL=development` or
legacy alias `dev`, with `SOURCE_REF=main`) and is never the default for stable
installs.

## Stable release existence

A stable version exists only after **all** of:

1. Immutable git tag `vMAJOR.MINOR.PATCH`
2. Release artifacts + checksums bound to that tag's commit
3. Qualification evidence recorded for that exact HEAD

Published tags are immutable. Never move, recreate, retarget, delete, or
force-push a published tag. Do not manufacture gap-fill tags. Do not renumber
the product back to `1.0.0`.

Historical note for this line: published stable baseline is `v2.2.1`; `v2.3.0`
is published history and must remain untouched. The next stable target is
`v2.4.0`.

## MCP exclusion (v2.4.0)

For the v2.4.0 product line:

```text
MCP_COMMANDS_INCLUDED=NO
MCP_RUNTIME_DEPENDENCY=NO
MCP_INSTALLER_PAYLOAD_INCLUDED=NO
MCP_ENABLED_CODE_PATH=NO
MCP_STABLE_SUPPORT_CLAIM=NO
features.mcp_included=false
```

## Release manifest

`release-manifest.json` must validate against `RELEASE_MANIFEST.schema.json`
and record at least:

- schema version
- product version and channel
- exact Git SHA (`source_head`)
- immutable source ref / tag (`git_ref`)
- upstream FRP version
- `features.mcp_included`
- artifact paths and SHA256 digests
- qualification evidence for stable releases

## Guardrails

Repository-native checks enforce:

- `VERSION_SSOT_CONSISTENT`
- `TAG_MATCHES_PRODUCT_VERSION`
- `TAG_HEAD_MATCHES_SOURCE_HEAD`
- `SOURCE_DIST_PARITY`
- `INSTALLER_SOURCE_REF_IMMUTABLE`
- `RELEASE_MANIFEST_VALID`
- `MCP_V2_4_EXCLUSION`
- `HISTORICAL_TAG_IMMUTABILITY`

Release publication is triggered only from an explicitly qualified immutable
tag (see `.github/workflows/release-attest.yml`), never merely from a feature
branch push.
