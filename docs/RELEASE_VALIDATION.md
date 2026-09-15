# Real-environment release validation

This file is the **authoritative** policy for which real-environment gates are
required for a stable tag versus recommended. `docs/RELEASE_CHECKLIST.md`
defers to this classification.

Docker `./tests/run-distro-matrix.sh` is **userspace portability** only. It does
not start the distro's systemd as PID 1, does not prove SELinux Enforcing, and
does not prove a real VM.

`tests/live-distro-smoke.sh` is a **read-only** collector for an already
installed systemd host. It does not install, enroll, update, uninstall, or
mutate firewall/SELinux.

## Gate classification — v2.4.0 FINAL PRODUCT CLOSURE

Current project version **2.4.0** / FRP **0.71.0**. Values here are checked
against `VERSION` by `./scripts/check-version-consistency.sh`; that script, not
this prose, is authoritative for version agreement.

Published tags are immutable. `v2.3.1`, `v2.3.0`, `v2.2.1` and earlier stay
exactly where they were published. Field installs become final when the new
`v2.4.0` tag is created on the closure HEAD — no existing tag is repointed to
get there.

| Item | Classification | Current candidate status |
| --- | --- | --- |
| Ubuntu 24 physical host Real E2E | REQUIRED_FOR_STABLE (2.4.0) | **REQUIRED / PENDING FINAL SAME-HEAD VALIDATION** |
| Rocky Linux 8.10 Real E2E | REQUIRED_FOR_STABLE (2.4.0) | **REQUIRED / PENDING FINAL SAME-HEAD VALIDATION** |
| Rocky Linux 9.4 Real E2E | REQUIRED_FOR_STABLE (2.4.0) | **REQUIRED / PENDING FINAL SAME-HEAD VALIDATION** |
| Amazon Linux 2023 Real E2E | REQUIRED_FOR_STABLE (2.4.0) | **REQUIRED / PENDING FINAL SAME-HEAD VALIDATION** |
| macOS Apple Silicon Real E2E | REQUIRED_FOR_STABLE (2.4.0) | **REQUIRED / PENDING FINAL SAME-HEAD VALIDATION** |
| Windows 10 / PowerShell 5.1 Real E2E | REQUIRED_FOR_STABLE (2.4.0) | **REQUIRED / PENDING FINAL SAME-HEAD VALIDATION** |
| Amazon Linux 2 | CI / container portability | **Container / CI only** — no live-host Real E2E |
| PowerShell 7 | CI | **CI validated** unless same-host Real E2E with `pwsh` installed |
| Rocky 8/9, AlmaLinux 9, AL2023, AL2 container matrix | REQUIRED_FOR_STABLE (automated) | container PASS |
| Release artifact / SBOM / attestation integrity | REQUIRED_FOR_STABLE (automated) | see "Release integrity gate" below |
| Rocky 9 SELinux Enforcing | RECOMMENDED | NOT_TESTED; do not advertise Enforcing support |
| AlmaLinux 9 real VM / SELinux Enforcing | RECOMMENDED | NOT_TESTED |
| Native ARM64 Linux systemd | RECOMMENDED | architecture mapping unit-tested only |
| Real OpenSSL 1.0.2 TLS enrollment | RECOMMENDED | AL2 container userspace is not this gate |
| Ubuntu 24.04 x86_64 single-443 (direct public-IP, enterprise-restricted client) | Historical REQUIRED (2.1.0) | PASS (2026-08-29); see historical section |
| Zero-Touch Short URL Real E2E (baseline Linux, AL2023, Rocky 8.10) | Historical REQUIRED (2.1.3) | PASS; see historical Short URL section |

## Release integrity gate (automated, required for stable)

Release artifacts are produced in one authoritative order by
`./scripts/build-release-artifacts.sh`:

```text
build bundles  ->  update SHA256SUMS  ->  generate SBOM  ->  verify
```

Each stage reads only the output of earlier stages, so the relation is acyclic
and a rebuild converges in a single pass. Three files are derived release
metadata and are deliberately **not** checksummed into `SHA256SUMS`:

| File | Why it is excluded |
| --- | --- |
| `SHA256SUMS` | cannot contain its own digest |
| `release-manifest.json` | carries artifact digests copied from `SHA256SUMS` |
| `dist/sbom.spdx.json` | its inventory is built **from** `SHA256SUMS` |

`dist/sbom.spdx.json` is generated, not committed. A file stored in a commit
cannot record the hash of the commit that contains it, so a committed SBOM can
only ever bind to some earlier tree. The SBOM is built from the checked-out
release commit and published as an attested workflow artifact instead.

`./scripts/verify-sbom.sh` is the binding gate. It fails unless the SBOM
records the expected release commit (`SBOM_EXPECTED_COMMIT`, default `HEAD`),
records the `git_ref` from `release-manifest.json`, matches `VERSION` for both
the project and pinned FRP versions, and agrees with `SHA256SUMS`
entry-for-entry in both directions.

The SBOM is deterministic for a given commit: its creation timestamp comes from
`SOURCE_DATE_EPOCH` or the HEAD commit time, never wall-clock `now()`.
Regenerating twice on one commit yields identical bytes, which
`tests/test-release-artifact-ordering.sh` asserts.

Attestation is **authoritative, not advisory**. In
`.github/workflows/release-attest.yml` the `gh attestation verify` step must
succeed for every subject; a verification failure fails the job. There is no
`DEFERRED` outcome. The workflow also binds the chain
`expected tag -> expected commit -> checked-out HEAD -> attested subjects`
before it will attest anything, and refuses a ref that is not immutable.

```text
RELEASE_ARTIFACT_ORDERING=
SHA256SUMS=
SBOM=
VERSION_CONSISTENCY=
ATTESTATION_VERIFY=
```

`ATTESTATION_VERIFY` accepts `PASS` or `NOT_RUN` (workflow not yet executed for
the candidate). `DEFERRED` is not a valid value.

## Result format

Copy per host. Values: `PASS`, `FAIL`, `NOT_TESTED`, `BLOCKED`.

```text
HOST=
OS=
ARCH=
KERNEL=
SELINUX_GETENFORCE=
SYSTEMD_VERSION=
BASH_VERSION=
PYTHON_VERSION=
OPENSSL_VERSION=
PID1=

ROCKY_9_SELINUX_ENFORCING=NOT_TESTED

ALMA_9_REAL_VM=NOT_TESTED
ALMA_9_SELINUX_ENFORCING=NOT_TESTED

AMAZON_LINUX_2_REAL_VM=NOT_TESTED
AMAZON_LINUX_2_SYSTEMD_219_REAL=NOT_TESTED
AMAZON_LINUX_2_REAL_TTY=NOT_TESTED

REAL_ARM_SYSTEMD=NOT_TESTED
REAL_OPENSSL_1_0_2_TLS_ENROLLMENT=NOT_TESTED
```

Do **not** map Docker, LXD, or QEMU TCG to `REAL_VM=PASS`.

## Per disposable test VM

On a throwaway VM only:

1. Fresh install (server and/or client bootstrap)
2. `systemctl is-enabled` / `is-active` for `drlink-server`, `drlink-allocator`, `drlink-client` as applicable
3. Reboot; confirm units and `sudo drlink show status`
4. `sudo drlink system diagnostics` (read-only)
5. Zero-touch **or** manual enrollment
6. Publish a service; connect with the **public** host and **public** service port
   (`ssh -p <public-port> <user>@<public-host>`)
7. Disable and re-enable; confirm the same public port
8. `sudo drlink update`
9. Uninstall only on the test host (`uninstall-client.sh` does not release server ports;
   server uninstall preserves state; purge requires `--purge --yes`)

Then run `tests/live-distro-smoke.sh` for a non-destructive evidence dump.

## SELinux (Rocky / Alma real VM)

Require `getenforce` => `Enforcing`. Do not `setenforce 0` to obtain PASS.

Validate server install, client install, allocator HTTPS, `drlink-server`, `drlink-client`,
systemd, local file access, ports, and doctor.

If policy blocks legitimate product behavior, record the exact AVC and decide
whether it is a site policy issue. Do not install custom SELinux policy unless
release-blocking evidence requires it.

## Amazon Linux 2 real gate

Prove systemd 219, Bash 4.2, Python 3.7, OpenSSL 1.0.2k, real PID 1, reboot,
and TTY. Docker userspace PASS is not this column. For **2.4.0**, Amazon Linux 2
remains **container/CI portability only** until a live-host Real E2E exists.

## ARM64

Native host only for `REAL_ARM_SYSTEMD=PASS`: architecture detection, FRP
arm64 artifact, install, systemd, basic connection, doctor. QEMU userspace
emulation is not that gate. macOS Apple Silicon Real E2E is a separate client
platform claim (validated for 2.4.0).

## Real OpenSSL 1.0.2 TLS enrollment

Prove allocator CA bootstrap, SHA256 DER fingerprint, TLS 1.2, bootstrap
ticket redemption, and Enrollment on an actual OpenSSL 1.0.2 client. The
Amazon Linux 2 container only proves userspace parsing compatibility.

Until then: `REAL_OPENSSL_1_0_2_TLS_ENROLLMENT=NOT_TESTED`.

## Historical — 2.1.3 Zero-Touch Short URL Real E2E

Authoritative Short URL evidence for stable **2.1.3** lives in
`docs/ZERO_TOUCH_SHORT_URL.md` (section "v2.1.3 Real E2E evidence").

Summary (do not treat Docker/unit PASS as these rows):

```text
RELEASE=2.1.3
BASELINE_LINUX=PASS
AMAZON_LINUX_2023=PASS
ROCKY_LINUX_8_10=PASS
PUBLIC_TLS_STOCK_OS_TRUST=PASS
SHORT_URL_GENERATION=PASS
ZERO_TOUCH_ENROLLMENT=PASS
FIRST_MACHINE_BINDING=PASS (automated suite; not in Real E2E harness)
TICKET_SINGLE_USE=PASS (automated suite; not in Real E2E harness)
MULTI_SERVICE=PASS (automated suite; Real E2E used --ssh profile)
MANAGEMENT_ONLY=PASS (automated suite; not in Real E2E harness)
REBOOT_RECONNECT=PASS
INVALID_TLS_FAIL_CLOSED=PASS
ZT1_FALLBACK=PASS
TESTED_PRODUCTION_HEAD=091f9a99b5e8d648099da97457781bcd24980142
CANDIDATE_HEAD=40bc05967ebfd93c3723a8edff206967c4711c35
EVIDENCE_REUSED_BY_CODE_EQUIVALENCE=YES
```

Rocky Linux 8.10 is a **release-validated Short URL Real E2E platform** for
2.1.3. That is distinct from Rocky 9 SELinux Enforcing, which remains
`RECOMMENDED` / `NOT_TESTED`.

## Historical — 2.1.0 real-environment acceptance (2026-08-29)

Field-validated topology only. Do **not** treat this block as covering DNAT,
SELinux Enforcing, ARM64, or OpenSSL 1.0.2.

```text
REAL_SERVER_OS=Ubuntu 24.04.4 LTS x86_64
REAL_SERVER_FRP=0.71.0
REAL_SERVER_TOPOLOGY=direct public-IP
REAL_CLIENT_OS=Ubuntu 24.04.3 LTS x86_64
REAL_CLIENT_NETWORK=enterprise restricted

OBSERVED_BEFORE_SINGLE443=TLS on non-443 ports was reset
OBSERVED_AFTER_SINGLE443=HTTPS enrollment and FRP WSS control succeeded over TCP/443; published SSH TCP/6000 reachable end-to-end

REAL_SERVER_MIGRATION_1_9_1_TO_2_1_0=PASS
REAL_SINGLE443_SERVER_CUTOVER=PASS
REAL_ENTERPRISE_TLS_443_PATH=PASS
REAL_CA_BOOTSTRAP_443=PASS
REAL_VERIFIED_HTTPS_443=PASS
REAL_ZERO_TOUCH_BOOTSTRAP=PASS
REAL_ENROLLMENT_443=PASS
REAL_CLIENT_CA_PINNING=PASS
REAL_WSS_E2E=PASS
REAL_FRPC_LOGIN=PASS
REAL_PROXY_REGISTRATION=PASS
REAL_SSH_SERVICE_E2E=PASS
REAL_ENTERPRISE_RESTRICTED_NETWORK_E2E=PASS
REAL_CLIENT_REBOOT_RECONNECT=PASS
REAL_SERVER_REBOOT_RECONNECT=PASS
REAL_END_TO_END_REBOOT_RECOVERY=PASS
PUBLIC_6099_NOT_EXPOSED=PASS
PUBLIC_7000_NOT_EXPOSED=PASS
PUBLIC_80_NOT_EXPOSED=PASS
SERVER_DOCTOR_AFTER_REBOOT=PASS
```

Real tested:

- Ubuntu x86_64
- Direct public-IP server
- Enterprise restricted client network
- HTTPS/443 enrollment
- WSS/443 control
- SSH published service
- Client reboot recovery
- Server reboot recovery

Not real-environment tested (remain `NOT_TESTED`; do not advertise as
field-validated):

- Firewall DNAT / private FRP-server topology
- SELinux Enforcing
- ARM64 Linux host
- OpenSSL 1.0.2 host

```text
FIREWALL_DNAT_PRIVATE_FRP_SERVER=NOT_TESTED
ROCKY_9_SELINUX_ENFORCING=NOT_TESTED
REAL_ARM_SYSTEMD=NOT_TESTED
REAL_OPENSSL_1_0_2_TLS_ENROLLMENT=NOT_TESTED
```

## Production-realistic qualification (v2.3.1+)

Authoritative orchestrator:

```bash
./tests/run-production-realistic-qualification.sh PASS1
./tests/run-production-realistic-qualification.sh PASS2
```

Extended load/perf/recovery phases:

```bash
PROD_QUAL_OUT=e2e-reports/manual-extended \
  ./tests/run-prod-qual-extended.sh
```

This suite is designed so a separate manual E2E is not required when both
PASS1 and PASS2 succeed on the **same exact HEAD**.

### Gate families

| Family | Coverage | Cadence |
| --- | --- | --- |
| EVERY RELEASE | Multi-OS Real E2E matrix, Access, Egress allow/deny, backup/restore, support bundle, status/doctor, docs-free UX, PASS1+PASS2 | Required for stable |
| PERFORMANCE BASELINE | Concurrent CONNECT 1..500, churn, noisy-neighbor, failure-load, remote-access + egress latency/throughput samples, server RSS/FD/threads | Required for stable; establishes baseline (overhead ≠ automatic fail) |
| UPGRADE FROM PREVIOUS RELEASE | Golden baseline compare; server-first then clients; mixed-version rolling; upgrade under traffic | Required when shipping N→N+1 |
| DISASTER RECOVERY | Fresh-server restore from golden backup; clients reconnect without reinstall | Required when changing backup/restore or identity contracts |
| OPTIONAL EXTENDED STRESS | 1000-conn exploratory, multi-hour soak beyond 30m, 100/sec churn sustained | Recommended when capacity claims change |

### Environment variables

```text
FRP_E2E_QUAL_OUT              Evidence directory
FRP_E2E_SOAK_SECONDS          Default 1800 (30m)
FRP_E2E_CHURN_SECONDS         Default 300 (5m)
FRP_E2E_QUAL_SKIP_LOCAL=1     Skip local run-all when CI already green for HEAD
FRP_E2E_QUAL_SERVER_REBOOT=0  Skip extra server reboot (matrix already reboots)
FRP_E2E_EGRESS_PORT           Default 16080 for Real E2E egress listener
```

### Golden v2.3.1 upgrade baseline

On successful qualification, sanitized artifacts are written under:

```text
e2e-reports/v2.3.1-golden-upgrade-baseline/
```

Contents are fingerprints/listings only — never raw tokens or private keys.
