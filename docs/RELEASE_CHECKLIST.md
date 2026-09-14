# Release checklist

Use this list before tagging a release. Automated items are required before a
release candidate or stable tag. Real-environment policy and evidence live in
`docs/RELEASE_VALIDATION.md` (authoritative for which real gates are mandatory).

## Automated gate (required for any tag)

- [ ] `VERSION` matches intended project version; `FRP_VERSION=0.71.0`
- [ ] `./scripts/check-version-consistency.sh` PASS — derives every assertion
  from `VERSION` and covers README, CHANGELOG, `docs/SECURITY.md`,
  `docs/RELEASE_VALIDATION.md`, `docs/PRODUCT_MASTER.md`, this checklist,
  `release-manifest.json`, and `lib/frp-common.sh`
- [ ] Support matrix claims match evidence (no SELinux/real-VM overclaim)
- [ ] `./tests/run-all.sh` PASS
- [ ] `./tests/run-distro-matrix.sh` PASS (seven vendor images, including Rocky 8)
- [ ] `./scripts/secret-scan.sh` PASS (includes forbidden real-IP literals)
- [ ] `./scripts/build-release-artifacts.sh` PASS (build → SHA256SUMS → SBOM → verify)
- [ ] `git diff --exit-code dist/` clean after that rebuild
- [ ] `./scripts/verify-sha256sums.sh` PASS
- [ ] `./scripts/verify-sbom.sh` PASS (SBOM binds to the release commit)
- [ ] `git diff --check HEAD` PASS
- [ ] Worktree clean after the release commit
- [ ] Commit is on `main`
- [ ] Stable release URLs resolve to immutable `vPROJECT_VERSION` (not `main`)

## Real-environment gate (authoritative policy)

**Authoritative classification** is the Gate classification table in
`docs/RELEASE_VALIDATION.md`.

For **2.4.0 FINAL PRODUCT CLOSURE**, required Real E2E evidence covers Ubuntu 24
physical, Rocky Linux 8.10, Rocky Linux 9.4, Amazon Linux 2023, macOS Apple
Silicon, and Windows 10 / PowerShell 5.1, plus the automated gates in this
checklist. Amazon Linux 2 remains **container/CI only**. PowerShell 7 remains
**CI validated** unless same-host Real E2E with `pwsh` is recorded. The
following remain **RECOMMENDED / NOT_TESTED** and must **not** be advertised as
field-validated:

- Rocky Linux 9 SELinux Enforcing
- AlmaLinux 9 real VM / SELinux Enforcing
- Amazon Linux 2 real VM / systemd 219 / TTY
- Native ARM64 Linux systemd
- Real OpenSSL 1.0.2 TLS enrollment
- Firewall DNAT / private FRP-server topology

Do not convert Docker, LXD, or QEMU TCG into `REAL_VM=PASS`.

## Tag policy

- [ ] `RELEASE_CANDIDATE_READY=YES` only if the automated gate PASS
- [ ] `STABLE_TAG_READY=YES` only if the chosen required real gates PASS
  (see `docs/RELEASE_VALIDATION.md`)
- [ ] Do **not** create a stable tag while required real gates are `NOT_TESTED`
- [ ] Do **not** claim Rocky/Alma SELinux Enforcing, Amazon Linux 2 live Real E2E,
  ARM64 Linux systemd, or OpenSSL 1.0.2 real TLS unless those columns are PASS

Published tags are immutable. Once a tag has been pushed it is never moved,
deleted, recreated, retargeted, or force-pushed — not to correct a premature
tag, not to absorb later fixes, not for any reason. A tag that points at the
wrong commit is superseded by a **new** version tag; the wrong one stays as
published history. Downstream installs, `SHA256SUMS` references, and artifact
attestations all resolve through tags, so repointing one silently invalidates
evidence that consumers have already verified.

`./scripts/check-version-consistency.sh` enforces this on the documents
themselves and fails if any release doc reads as an instruction to mutate a
published tag.

For **2.1.3** (historical), keep published **v2.1.2** untouched. Ideal
`/i/<ticket>` short URL Real E2E evidence for **2.1.3** is recorded in
`docs/ZERO_TOUCH_SHORT_URL.md` and summarized in `docs/RELEASE_VALIDATION.md`.
Implementation lives behind optional `bootstrap_hostname` (Option B); `zt1`
fallback remains when unset. `public_hostname` stays the published-service
access alias and is not the bootstrap TLS hostname.

## Preparing the 2.4.0 immutable tag

Do **not** tag a tree whose `PROJECT_VERSION` does not match the intended tag.
`./scripts/validate-release-tag.sh` rejects that mismatch automatically.

This tree prepares **2.4.0**. `v2.3.1`, `v2.3.0`, `v2.2.1`, `v2.2.0`, `v2.1.2`,
`v2.1.1`, `v2.1.0` and earlier are published history and stay exactly as they
are. `v2.4.0` is a brand-new tag on the closure HEAD. A dedicated release
commit must, in order:

1. Set `PROJECT_VERSION=2.4.0` in `VERSION` and `lib/frp-common.sh` default
2. Set `release-manifest.json` `channel=stable` and `git_ref=v2.4.0`
3. Run `./scripts/build-release-artifacts.sh` (build → `SHA256SUMS` → SBOM → verify)
4. Run all automated gates in this checklist
5. Only then create the new `v2.4.0` tag, pointing at that release commit
6. Run `.github/workflows/release-attest.yml` with the `v2.4.0` tag as `ref`

Step 6 is not optional for a stable release: it is what binds the tag to a
commit, that commit to the checked-out tree, and the tree to the attested
artifacts. Its `gh attestation verify` step is authoritative — if verification
fails, the release fails.

## Release artifact ordering

There is exactly one correct order, and `./scripts/build-release-artifacts.sh`
implements it:

```text
build bundles  ->  update SHA256SUMS  ->  generate SBOM  ->  verify
```

Do not hand-edit digests, and do not regenerate a later stage without
rerunning the earlier ones. `SHA256SUMS`, `release-manifest.json`, and
`dist/sbom.spdx.json` are derived metadata and are never checksummed into
`SHA256SUMS` — see "Release integrity gate" in `docs/RELEASE_VALIDATION.md` for
why each exclusion is required.

`dist/sbom.spdx.json` is generated at release time and is not tracked in git,
because a committed SBOM cannot record the hash of the commit containing it.
