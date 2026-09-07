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

## Gate classification

| Item | Classification | Current support claim |
| --- | --- | --- |
| Ubuntu 22.04 / 24.04 real VM | REQUIRED_FOR_STABLE (live baseline) | documented PASS |
| Ubuntu 24.04 x86_64 single-443 (direct public-IP, enterprise-restricted client) | REQUIRED_FOR_STABLE (2.1.0) | PASS (2026-08-29) |
| Rocky 8 container | REQUIRED_FOR_STABLE (automated) | container PASS |
| Rocky 9 container | REQUIRED_FOR_STABLE (automated) | container PASS |
| AlmaLinux 9 container | REQUIRED_FOR_STABLE (automated) | container PASS |
| Amazon Linux 2023 container | REQUIRED_FOR_STABLE (automated) | container PASS |
| Amazon Linux 2 container | REQUIRED_FOR_STABLE (automated) | container PASS |
| Zero-Touch Short URL Real E2E (baseline Linux, Amazon Linux 2023, Rocky Linux 8.10) | REQUIRED_FOR_STABLE (2.1.3) | PASS; see Short URL evidence section |
| Rocky 9 real VM | RECOMMENDED | NOT_TESTED; do not advertise full VM support |
| Rocky 9 SELinux Enforcing | RECOMMENDED | NOT_TESTED; do not advertise Enforcing support |
| AlmaLinux 9 real VM | RECOMMENDED | NOT_TESTED |
| AlmaLinux 9 SELinux Enforcing | RECOMMENDED | NOT_TESTED |
| Amazon Linux 2023 real VM | RECOMMENDED | NOT_TESTED (fresh-install matrix beyond Short URL / upgrade E2E) |
| Amazon Linux 2 real VM / systemd 219 / TTY | RECOMMENDED | NOT_TESTED |
| Native ARM64 systemd | RECOMMENDED | architecture mapping unit-tested only |
| macOS | OUT_OF_SCOPE_STABLE | not stable supported |
| Windows | OUT_OF_SCOPE_STABLE | not stable supported |
| Real OpenSSL 1.0.2 TLS enrollment | RECOMMENDED | AL2 container userspace is not this gate |

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

ROCKY_9_REAL_VM=NOT_TESTED
ROCKY_9_SELINUX_ENFORCING=NOT_TESTED

ALMA_9_REAL_VM=NOT_TESTED
ALMA_9_SELINUX_ENFORCING=NOT_TESTED

AMAZON_LINUX_2023_REAL_VM=NOT_TESTED

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
2. `systemctl is-enabled` / `is-active` for `frps`, `frp-port-allocator`, `frpc` as applicable
3. Reboot; confirm units and `frpctl status`
4. `sudo frpctl doctor` (read-only)
5. Zero-touch **or** manual enrollment
6. Publish a service; connect with the **public** host and **public** service port
   (`ssh -p <public-port> <user>@<public-host>`)
7. Disable and re-enable; confirm the same public port
8. `sudo frpctl update`
9. Uninstall only on the test host (`uninstall-client.sh` does not release server ports;
   server uninstall preserves state; purge requires `--purge --yes`)

Then run `tests/live-distro-smoke.sh` for a non-destructive evidence dump.

## SELinux (Rocky / Alma real VM)

Require `getenforce` => `Enforcing`. Do not `setenforce 0` to obtain PASS.

Validate server install, client install, allocator HTTPS, `frps`, `frpc`,
systemd, local file access, ports, and doctor.

If policy blocks legitimate product behavior, record the exact AVC and decide
whether it is a site policy issue. Do not install custom SELinux policy unless
release-blocking evidence requires it.

## Amazon Linux 2 real gate

Prove systemd 219, Bash 4.2, Python 3.7, OpenSSL 1.0.2k, real PID 1, reboot,
and TTY. Docker userspace PASS is not this column.

## ARM64

Native host only for `REAL_ARM_SYSTEMD=PASS`: architecture detection, FRP
arm64 artifact, install, systemd, basic connection, doctor. QEMU userspace
emulation is not that gate.

## Real OpenSSL 1.0.2 TLS enrollment

Prove allocator CA bootstrap, SHA256 DER fingerprint, TLS 1.2, bootstrap
ticket redemption, and Enrollment on an actual OpenSSL 1.0.2 client. The
Amazon Linux 2 container only proves userspace parsing compatibility.

Until then: `REAL_OPENSSL_1_0_2_TLS_ENROLLMENT=NOT_TESTED`.

## 2.1.3 Zero-Touch Short URL Real E2E

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
2.1.3. That is distinct from Rocky 9 real VM / SELinux Enforcing, which remain
`RECOMMENDED` / `NOT_TESTED`.

## 2.1.0 real-environment acceptance (2026-08-29)

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
- ARM64 host
- OpenSSL 1.0.2 host

```text
FIREWALL_DNAT_PRIVATE_FRP_SERVER=NOT_TESTED
ROCKY_9_SELINUX_ENFORCING=NOT_TESTED
REAL_ARM_SYSTEMD=NOT_TESTED
REAL_OPENSSL_1_0_2_TLS_ENROLLMENT=NOT_TESTED
```
