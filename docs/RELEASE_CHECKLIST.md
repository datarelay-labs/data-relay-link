# Release checklist

Use this list before tagging a release. Automated items are required before a
release candidate or stable tag. Real-environment policy and evidence live in
`docs/RELEASE_VALIDATION.md` (authoritative for which real gates are mandatory).

## Automated gate (required for any tag)

- [ ] `VERSION` matches intended project version; `FRP_VERSION=0.71.0`
- [ ] README, CHANGELOG, and `docs/SECURITY.md` match that version
- [ ] Support matrix claims match evidence (no SELinux/real-VM overclaim)
- [ ] `./tests/run-all.sh` PASS
- [ ] `./tests/run-distro-matrix.sh` PASS (seven vendor images, including Rocky 8)
- [ ] `./scripts/secret-scan.sh` PASS (includes forbidden real-IP literals)
- [ ] `./scripts/build-bundles.sh` then `git diff --exit-code dist/`
- [ ] `./scripts/verify-sha256sums.sh` PASS
- [ ] `git diff --check HEAD` PASS
- [ ] Worktree clean after the release commit
- [ ] Commit is on `main`
- [ ] Stable release URLs resolve to immutable `vPROJECT_VERSION` (not `main`)

## Real-environment gate (authoritative policy)

**Authoritative classification** is the Gate classification table in
`docs/RELEASE_VALIDATION.md`.

For **2.3.0 FINAL AUDIT CLOSURE**, required Real E2E evidence covers Ubuntu 24
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

For **2.1.3** (historical), keep published **v2.1.2** untouched. Ideal
`/i/<ticket>` short URL Real E2E evidence for **2.1.3** is recorded in
`docs/ZERO_TOUCH_SHORT_URL.md` and summarized in `docs/RELEASE_VALIDATION.md`.
Implementation lives behind optional `bootstrap_hostname` (Option B); `zt1`
fallback remains when unset. `public_hostname` stays the published-service
access alias and is not the bootstrap TLS hostname.

## Preparing the 2.3.1 immutable tag

Do **not** tag a tree whose `PROJECT_VERSION` does not match the intended tag.
`./scripts/validate-release-tag.sh` rejects that mismatch automatically.
Do **not** move or retag published **v2.2.1**, **v2.2.0**, or earlier tags.

This tree prepares **2.3.1**. Historical GitHub `v2.3.0`
tag/release already exists; after audit-closure fixes land, **recreate or move**
that tag onto the final HEAD (operator step). A dedicated release commit must,
in order:

1. Set `PROJECT_VERSION=2.3.1` in `VERSION` and `lib/frp-common.sh` default
2. Set `release-manifest.json` `channel=stable` and `git_ref=v2.3.1`
3. Rebuild bundles and regenerate `SHA256SUMS`
4. Run all automated gates in this checklist
5. Only then create the immutable `v2.3.1` tag (do not move/delete `v2.3.0`)

Do not move frozen tags such as `v2.2.1`, `v2.2.0`, `v2.1.0`, `v2.1.1`, or `v2.1.2` after publication.
