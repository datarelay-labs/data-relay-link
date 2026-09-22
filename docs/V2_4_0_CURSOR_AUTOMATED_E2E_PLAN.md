# Data Relay Link v2.4.0 — Cursor Automated E2E Plan

```text
PURPOSE=Focused automated coverage of the SAME frozen candidate Rick validates manually
EXECUTE_IN_THIS_READINESS_PHASE=NO
EXECUTE_AFTER=Rick starts / alongside Rick Manual E2E (separate phase)
FORBIDDEN_IN_READINESS=tests/run-all.sh, Full Product Qualification, PASS1/PASS2, performance, soak
```

## Candidate identity

```bash
git rev-parse HEAD
git status --short --branch
# Must match Rick's recorded Manual E2E HEAD
```

## Goals

1. Automate everything that does **not** require external SaaS UI or public ACME DNS.
2. Avoid duplicating Rick-only UX judgments.
3. Produce machine evidence for Final Qualification later — **do not** claim Final Qualification credit here.

## Execution order (when the next phase starts)

### Gate 0 — Candidate identity

```bash
git rev-parse HEAD
git rev-parse origin/feature/v2.4.0-final-product-closure
test -z "$(git status --porcelain)"
```

### Gate 1 — Legacy surface / CLI discovery

```bash
python3 tests/test-no-legacy-current-surface.py
bash tests/test-create-zero-touch.sh
bash tests/test-cli-information-architecture.sh
bash tests/test-cli-catalog-parity.sh
python3 tests/test-verb-first-cli-ux.sh 2>/dev/null || bash tests/test-verb-first-cli-ux.sh
bash tests/test-frpctl.sh
```

### Gate 2 — Control plane / Bundle / Zero-Touch

```bash
python3 tests/test-configuration-bundle.py
python3 tests/test-bounded-zero-touch.py
bash tests/test-zero-touch-bootstrap.sh
python3 tests/test-canonical-runtime-policy.py
```

### Gate 3 — Remote / Internet / Fixed TCP

```bash
bash tests/test-access-control.sh
python3 tests/test-access-control.py
bash tests/run-access-control-e2e.sh
bash tests/test-egress-control.sh
python3 tests/test-fixed-tcp-egress.py
bash tests/test-fixed-tcp-egress.sh
bash tests/run-egress-real-e2e-smoke.sh
```

### Gate 4 — MCP (local / lab TLS — not external SaaS)

```bash
python3 tests/test-ai-access-mcp-e2e.py
python3 tests/test-mcp-public-endpoint-e2e.py
python3 tests/test-mcp-public-tls-lifecycle.py
python3 tests/test-mcp-remote-connector-interop.py
```

### Gate 5 — Lifecycle / backup / uninstall

```bash
bash tests/test-lifecycle.sh
bash tests/test-install-lifecycle.sh
bash tests/test-core-correctness-lifecycle.sh
python3 tests/test-state-paths-backup-restore.py
bash tests/test-server-uninstall-fail-closed.sh
bash tests/test-uninstall-zero-residue.sh
bash tests/test-partial-client-install-recovery.sh
```

### Gate 6 — Optional multi-OS focused (only if hosts ready)

```text
Ubuntu24 server/client   -> Real E2E harness subsets
Rocky8 / AL2023 / macOS / Windows -> platform-specific scripts only when host reachable
```

Do **not** fail the automated plan solely because a host is temporarily unreachable; record `SKIPPED_HOST_UNAVAILABLE`.

## Explicitly deferred to Final Qualification

```text
tests/run-all.sh
tests/run-production-realistic-qualification.sh
PASS1 / PASS2
performance / soak / failure injection
multi-host packet lab beyond smoke
release governance / tag
```

## Pass criteria for Cursor Automated E2E phase

```text
SAME_HEAD_AS_RICK=YES
FOCUSED_GATES=PASS (or SKIPPED_HOST_UNAVAILABLE with evidence)
NO_PRODUCT_SCOPE_EXPANSION=YES
RUN_ALL=NOT_RUN_UNTIL_AFTER_FINDINGS_FIXED_AND_FINAL_CANDIDATE_FREEZE
```

## Mapping to Rick sections

| Rick section | Cursor automated approach |
|--------------|---------------------------|
| A Clean install | install-lifecycle + sandbox install tests |
| B Zero-Touch | test-bounded-zero-touch / zero-touch-bootstrap / create-zero-touch |
| C Client lifecycle | lifecycle + platform scripts |
| D Remote Access | access-control e2e + real e2e smoke |
| E Objects/Groups | control-plane / configuration-bundle / client-groups tests |
| F Internet Access | egress tests + smoke |
| G Fixed TCP | fixed-tcp tests |
| H ConfigurationBundle | test-configuration-bundle.py |
| I Public MCP TLS | local TLS lifecycle tests; **real public ACME = Rick** |
| J Claude UI | **Rick only** |
| K ChatGPT UI | **Rick only** |
| L MCP security | ai-access / mcp e2e tests |
| M Backup/Restore | state-paths backup-restore |
| N Reboot/Update | partial automated; reboot persistence heavily Rick |
| O Uninstall | uninstall tests |
| P Doctor/Bundle | doctor coverage inside diagnostics tests + support-bundle unit paths |
| Q Blind UX | **Rick only** (Cursor enforces no legacy surface via gate 1) |
