# Data Relay Link v2.4.0 — Rick / Cursor / Final Qualification Evidence Matrix

Purpose: prevent duplicated expensive testing. Same frozen candidate HEAD for Rick Manual and Cursor Automated; Final Qualification runs only after findings are fixed and candidate is re-frozen.

```text
Rick=YES     human operator UX + external/real traffic Rick can reach
Cursor=YES   automated focused suites on same HEAD
Final=YES    run-all + production-realistic qualification + PASS1/PASS2 + perf/soak
```

| Capability | Rick Manual | Cursor Automated | Final Qualification |
|------------|-------------|------------------|---------------------|
| Clean server install UX | YES | YES (lifecycle/sandbox) | YES |
| Branding / no legacy product UX | YES | YES (legacy surface gate) | YES |
| `?` / help / menu / Tab discoverability | YES | PARTIAL (grammar/catalog/legacy gates) | YES |
| Zero-Touch UX (secret once, reuse deny, capacity) | YES | YES | YES |
| Client lifecycle Linux | YES if host up | YES | YES |
| Client lifecycle Windows | YES if host up | PARTIAL (CI/scripts) | YES |
| Client lifecycle macOS | YES if host up | PARTIAL (CI/scripts) | YES |
| Remote Access real SSH/HTTP/HTTPS/TCP | YES | PARTIAL (e2e/smoke) | YES |
| Objects / Groups / nested / cycle | YES | YES | YES |
| Internet Access real curl/wget/git/apt | YES | PARTIAL | YES |
| Fixed TCP real probe | YES | YES | YES |
| ConfigurationBundle UX (stdin, confirm, absent) | YES | YES | YES |
| MCP local endpoint / OAuth interop fixtures | PARTIAL | YES | YES |
| REAL_PUBLIC_TLS / REAL_PUBLIC_ACME | YES (mandatory) | NO (local/lab only) | external/manual evidence |
| Claude Remote Connector UI | YES | NO | external/manual evidence |
| ChatGPT Remote Connector UI | YES | NO | external/manual evidence |
| MCP security allow/deny/audit | YES | YES | YES |
| Backup / restore functional | YES | YES | YES |
| Reboot persistence | YES | PARTIAL | YES |
| Uninstall / reinstall residue | YES | YES | YES |
| Doctor / support-bundle sanitization | YES | PARTIAL | YES |
| Blind-user UX judgment | YES | NO | NO |
| `tests/run-all.sh` | NO | NO | YES |
| Full Product Qualification PASS1/PASS2 | NO | NO | YES |
| Performance / soak / failure | NO | NO | YES |
| Multi-host packet lab (full) | PARTIAL | PARTIAL | YES |
| Version / release governance / tag | NO | NO | YES (later phase) |

## Current external residuals (classified)

| Item | Classification | Owner |
|------|----------------|-------|
| REAL_PUBLIC_TLS | Rick Manual E2E (mandatory) | Rick |
| REAL_PUBLIC_ACME | Rick Manual E2E (mandatory) | Rick |
| CLAUDE_REMOTE_CONNECTOR | Rick Manual E2E; may be BLOCKED_EXTERNAL_ACCOUNT_UI | Rick |
| CHATGPT_REMOTE_CONNECTOR | Rick Manual E2E; may be BLOCKED_EXTERNAL_PLAN | Rick |
| Multi-host packet lab (full matrix) | Final Qualification | Cursor+Rick evidence |
| `tests/run-all.sh` | Final Qualification only | Cursor |
| Performance / soak | Final Qualification | Cursor |

## Infra snapshot (readiness assessment)

| Platform | SSH alias | Reachable at readiness | Notes |
|----------|-----------|------------------------|-------|
| Ubuntu 24 server | frp-e2e-server | YES | Reachable via SSH alias; not yet on final Manual E2E HEAD until Rick installs |
| Ubuntu 24 client | frp-e2e-linux114 | YES | |
| Rocky 8 | frp-e2e-rocky8 | YES | |
| Rocky 9 | frp-e2e-rocky9-rescue | YES | rescue host |
| Amazon Linux 2023 | frp-e2e-aws | YES | |
| macOS Apple Silicon | frp-e2e-macos | YES | product may be absent until install |
| Windows 10 | frp-e2e-windows | PARTIAL | SSH responds with Windows hostname quirks |
| Extra Linux client | frp-e2e-client | INTERMITTENT | timeout observed during readiness |

## Public MCP infra

```text
PUBLIC_MCP_INFRA_READINESS=NEEDS_OPERATOR_ACTION
PUBLIC_MCP_REQUIRED_HOSTNAME=<Rick chooses project-controlled FQDN>
PUBLIC_MCP_REQUIRED_DNS=A/AAAA to server public IP
PUBLIC_MCP_REQUIRED_PORTS=TCP/80 + TCP/443
```
