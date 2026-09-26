# Data Relay Link Version Policy

> **Document role:** Normative product versioning, release-channel, tag, provenance, and release-line policy
> **Target:** v2.4.0 development
> **Related:** `PRODUCT_MASTER.md`, `CONTROL_PLANE_ARCHITECTURE.md`, `RELEASE_CHECKLIST.md`, `CHANGELOG.md`

## 1. Version source of truth

`VERSION` is the Single source of truth for product identity. Every release document, manifest, and operator-facing version string must match it.

`VERSION` is the authoritative product-version source:

```text
PROJECT_VERSION=<MAJOR.MINOR.PATCH>
FRP_VERSION=<independently pinned upstream engine version>
RELEASE_CHANNEL=<development|preview|stable>
```

Channels: development | preview | stable

Rules:

- Data Relay Link product version and FRP version are independent.
- A plain `PROJECT_VERSION=2.4.0` does not make a build stable.
- Internal phases, audits, commits, worktrees, and test rounds do not consume product versions.
- Fixes and architecture changes made before the first immutable `v2.4.0` stable tag remain part of the 2.4.0 target.

## 2. Current release direction

```text
Documented stable baseline             v2.3.0
Older published release                v2.2.1
Not manufactured                       v2.3.1
Current development target             2.4.0
Current release channel                development
Pinned Relay Engine                    FRP 0.71.0
MCP included in final 2.4.0 target     YES
Stable v2.4.0 tag exists               NO
```

Historical tags remain immutable regardless of whether they represented stable, RC, or historical release-line milestones.

The v2.4 prior-stable upgrade lane is immutable `v2.3.0` to `v2.4.0`. `v2.2.1` stays available for historical and rollback evidence. It is not the supported prior-stable baseline. `v2.3.1` was not manufactured.

Do not manufacture missing numbers, move old tags, or recreate them merely to make a sequence look continuous.

## 3. Semantic versioning

Data Relay Link uses:

```text
MAJOR.MINOR.PATCH
```

After stable release:

| Change | Increment |
|---|---|
| Backward-compatible defect/security fix | PATCH |
| Backward-compatible supported feature | MINOR |
| Incompatible supported public behavior | MAJOR |
| Test/audit/internal-only change | none by itself |
| Docs-only correction outside shipped behavior | none by itself |

The supported compatibility surface includes documented CLI grammar, config/state formats, enrollment/identity continuity, backup/restore format, install/service identity, update semantics, and security-policy behavior.

## 4. Pre-stable redesign rule

v2.4.0 has not been released and has no production user compatibility promise.

Therefore the current pre-stable architecture closure may replace development-only public models such as:

```text
ACL / Access Rule grammar
Service Profile
Internet Profile
JSON authoritative control-plane state
MCP exclusion
```

without renaming the target to 3.0.0.

This exception exists because the incompatible behavior was never part of an immutable qualified stable v2.4.0 release.

Once v2.4.0 is stable, incompatible changes to its supported public surface require a future MAJOR version unless an automatic safe compatibility path preserves the contract.

## 5. Build identities

### Development

```text
2.4.0-dev+g<SHORT_SHA>
Channel: development
Source HEAD: <exact 40-character SHA>
```

### Release candidate

```text
2.4.0-rc.N
Channel: preview
Source HEAD: <exact 40-character SHA>
```

Code/dependency changes after an RC require a new RC identity and reset final double-E2E evidence.

### Stable

```text
2.4.0
Channel: stable
Source HEAD: <exact qualified 40-character SHA>
Tag: v2.4.0
```

Stable exists only after immutable tag + artifacts + qualification evidence are all present.

## 6. Stable existence

A stable release requires all of:

1. Immutable `vMAJOR.MINOR.PATCH` tag.
2. Tag points to the exact HEAD that PASS1 and PASS2 qualified. `PASS1_HEAD == PASS2_HEAD == FINAL_QUALIFIED_HEAD == tag commit`. No tracked commit is created after PASS2.
3. Required automated and Real E2E gates passed on that exact HEAD.
4. Immutable release artifacts.
5. SHA256 checksums.
6. Release manifest.
7. Final release notes.
8. Stable-channel publication.

A branch, milestone, `VERSION` value, README claim, or generated URL is not a release.

## 7. Release channels

```text
stable
  immutable fully qualified releases only

preview
  explicit operator opt-in RCs only

development
  exact-SHA engineering builds only
```

Stable installers/updates never silently consume preview/development artifacts.

## 8. Source provenance

Runtime/release metadata preserves:

```text
PRODUCT_VERSION
RELEASE_CHANNEL
SOURCE_HEAD
SOURCE_REF
UPSTREAM_ENGINE_VERSION
```

Installs without `.git` must still retain exact provenance through build/install metadata.

Never fabricate `SOURCE_HEAD` or stable provenance.

Never fabricate `SOURCE_HEAD` or stable provenance.

Committed release metadata cannot self-describe the Git commit that contains it.
For development/preview candidates the canonical workflow is:

```text
1. Establish the content HEAD to qualify.
2. Run scripts/build-release-artifacts.sh (stamps release-manifest + embeds
   provenance into dist/bootstrap-* and regenerates SHA256SUMS/SBOM).
3. Commit the stamped artifacts as a follow-on provenance commit.
```

After step 3, `source_head` / embedded installer provenance correctly names the
content HEAD from step 1. The containing provenance commit differs by design.
`scripts/sync-release-manifest-provenance.py --check` therefore WARNs on
development trees when `source_head != HEAD`, and only fails closed under
`STRICT_SOURCE_HEAD=1` or stable channel. Do not invent a fake self-referential
SHA to silence that warning.

`scripts/check-release-attest-binding.py` is the release-attest gate. It binds:

```text
provenance commit = checked-out HEAD = github.sha
qualified content HEAD = manifest source_head = first parent of the provenance commit
immutable release ref = stable or RC tag pointing at the provenance commit,
  or that commit's full SHA for development
generated artifacts = the provenance commit differs from its parent only by
  generated provenance files
```

Development `git_ref` is the content SHA. Stable and RC `git_ref` is the tag.
The attest-time SBOM is generated, not committed: `gitCommit` is the provenance
commit and `gitRef` is manifest `git_ref`.

Stable publication does not add a Git commit. PASS1 and PASS2 run on the
provenance commit. The immutable tag is that same commit. `scripts/project-stable-release.py`
then builds a deterministic publication manifest from that tagged tree plus
retained PASS1/PASS2 evidence. The projection may change only release
metadata: `channel=stable`, `git_ref` = the tag, and qualification whose
`pass1_head`, `pass2_head`, and `final_qualified_head` all equal the tag
commit. It must not rewrite product or source payload hashes, accept
`pending` evidence, or move the tag. Committed `source_head` stays the
content parent of the tagged provenance commit.

## 9. Installer/bootstrap references

Before stable tag:

```text
source ref = exact 40-character SHA or immutable RC artifact
```

After stable release:

```text
source ref = immutable stable tag or immutable release artifact
```

Prohibited:

```text
future nonexistent v2.4.0 URL
qualified install from mutable main/latest
silent fallback from missing immutable ref to main/latest
moving/replacing bytes behind an existing released version
```

## 10. Product vs Relay Engine

Canonical display:

```text
Data Relay Link: 2.4.0-dev+g<sha>
Channel: development
Source HEAD: <sha>
Relay Engine (FRP): 0.71.0
Control DB Schema: <schema version>
```

An upstream FRP version change changes Data Relay Link version only according to Data Relay Link user-visible compatibility/behavior.

## 11. v2.4.0 architecture inclusion

Current authoritative product decision:

```text
MCP_INCLUDED_IN_V2_4_0=YES
MCP_RELEASE_BLOCKER=YES
features.mcp_included=true   # on the development candidate once MCP Bridge/AI Access are present
```

The final v2.4.0 target includes the Control Plane/Object/Policy/MCP behavior frozen by `PRODUCT_MASTER.md` and `DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md`; `CONTROL_PLANE_ARCHITECTURE.md` remains an internal schema/history reference.

The earlier exclusion rule is obsolete historical decision text only (do not treat as current scope):

```text
MCP_COMMANDS_INCLUDED=NO
MCP_RUNTIME_DEPENDENCY=NO
MCP_INSTALLER_PAYLOAD_INCLUDED=NO
MCP_ENABLED_CODE_PATH=NO
features.mcp_included=false
```

That earlier rule is superseded as a product decision.

Before v2.4.0 candidate qualification, all implementation/governance artifacts must remain consistent with MCP inclusion. Do not revive MCP-exclusion wording as current release scope.

## 12. Release manifest

`release-manifest.json` must validate against `RELEASE_MANIFEST.schema.json` and record at least:

```text
schema version
product version
channel
exact source HEAD
immutable source ref/tag
upstream FRP version
features.mcp_included
artifact names/sizes/SHA256
qualification evidence for stable
```

For the final qualified v2.4.0 artifact:

```text
features.mcp_included=true
```

only after MCP Bridge/AI Access are actually present and qualified.

Before implementation completes, the development manifest may reflect current code truth rather than future target scope; it must not be used to claim release readiness.

## 13. Governance guardrails

The final release-governance implementation must enforce:

```text
VERSION_SSOT_CONSISTENT
TAG_MATCHES_PRODUCT_VERSION
TAG_HEAD_MATCHES_SOURCE_HEAD
SOURCE_DIST_PARITY
INSTALLER_SOURCE_REF_IMMUTABLE
RELEASE_MANIFEST_VALID
HISTORICAL_TAG_IMMUTABILITY
CONTROL_PLANE_SCHEMA_COMPATIBLE
MCP_V2_4_INCLUDED_AND_QUALIFIED
```

The old `MCP_V2_4_EXCLUSION` guard is retired during the implementation phase, not carried into candidate qualification.

## 14. Branch model

Use lightweight isolated feature/fix worktrees.

`main` represents the latest releasable/stable product state. Incomplete v2.4.0 architecture work stays on its isolated feature branch until qualification and explicit integration.

Do not create a permanent develop branch merely for process aesthetics.

## 15. Exact-HEAD release sequence

An exact-SHA development candidate may be qualified directly and then tagged on that same PASS2 provenance HEAD. A preview or release-candidate channel is optional, not mandatory. No tracked commit is created after PASS2.

1. Freeze architecture/scope.
2. Implement the full target.
3. Run targeted + full automated tests.
4. Establish the content HEAD.
5. Stamp provenance with `scripts/build-release-artifacts.sh` and commit only generated provenance outputs. That provenance commit is the qualification HEAD.
6. Run Full Real E2E pass 1 on that provenance HEAD.
7. Run Full Real E2E pass 2 on the same provenance HEAD.
8. Verify no code, dependency, or generated artifact changed and HEAD is still that provenance commit.
9. Create immutable `v2.4.0` on exactly that HEAD. Do not create another tracked commit to carry stable identity or qualification.
10. Project the stable publication manifest from the tagged HEAD and retained PASS1/PASS2 evidence (`scripts/project-stable-release.py`). Release-attest must reject the tag unless `PASS1_HEAD == PASS2_HEAD == FINAL_QUALIFIED_HEAD == tag HEAD`.
11. Publish the projected manifest, checksums, and notes. The Git tag still points at the qualified provenance HEAD.

If final integration creates a new commit, repeat qualification on the new HEAD.

## 16. Post-v2.4 maintenance

After stable v2.4.0:

```text
compatible defect/security fix → 2.4.1, 2.4.2 ...
compatible feature             → 2.5.0
incompatible supported change  → 3.0.0
```

Do not backport new features into a PATCH release.

## 17. Prohibited practices

These practices are never allowed. Published tags are immutable.
- Incrementing version for every phase/audit.
- Using 2.4.1 for a fix before 2.4.0 exists.
- Publishing development as stable.
- Advertising future tags.
- Moving/deleting/recreating historical tags.
- Mixing product and FRP versions.
- Silently adding a feature to an already released PATCH line.
- Claiming MCP support before implementation/qualification.
- Preserving a superseded MCP exclusion solely because old tests/scripts still encode it.

## 18. Adoption gate

Before qualifying the v2.4.0 candidate (exact-SHA development, or an optional preview/RC):

```text
[ ] architecture docs synchronized
[ ] old MCP exclusion implementation removed/replaced
[ ] release schema/generator/checks aligned
[ ] tests aligned to MCP included target
[ ] exact-SHA development provenance preserved
[ ] new SQLite schema/version surfaced
[ ] all product/runtime features implemented
[ ] release manifest reflects actual candidate bytes
```
