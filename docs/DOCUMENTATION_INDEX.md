# Data Relay Link — Documentation Index

> **Purpose:** Identify the authoritative specification for each product area and prevent historical/internal documents from being mistaken for the current public contract.
> **Target:** v2.4.0 development

## Authority order

When documents disagree, use this order:

1. `PRODUCT_MASTER.md` — product charter and product-level decisions.
2. `DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md` — canonical CLI and AI-assisted configuration behavior.
3. `VERSION_POLICY.md` — version, release-channel, provenance, tag, and release-line rules.
4. Area-specific canonical documents listed below.
5. Exact-HEAD implementation and retained qualification evidence.

Historical documents and internal storage names never override the public SSOT.

## Canonical product and CLI specifications

| Area | Canonical document |
|---|---|
| Product model / scope | `PRODUCT_MASTER.md` |
| CLI + AI configuration | `DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md` |
| Direct CLI grammar | `CLI_REFERENCE.md` |
| Guided CLI / UX | `Data Relay Link CLI Information Architecture.md` |
| ConfigurationBundle | `CONFIGURATION_BUNDLE.md` |
| Internet Access datapath/security | `CONTROLLED_EGRESS.md` |
| Security / trust boundaries | `SECURITY.md` |
| Version governance | `VERSION_POLICY.md` |
| Release qualification | `RELEASE_CHECKLIST.md`, `RELEASE_VALIDATION.md` |
| Internal control-plane/schema history | `CONTROL_PLANE_ARCHITECTURE.md` |

## Operator lifecycle documents

| Task | Document |
|---|---|
| Install Server / Agent | `INSTALLATION.md` |
| Upgrade / release channels | `UPGRADE.md` |
| Remote Service + Remote Access operation | `REMOTE_ACCESS.md` |
| AI Identity / AI Access / MCP | `AI_ACCESS_MCP.md` |
| Troubleshooting | `TROUBLESHOOTING.md` |
| Deployment topology | `DEPLOYMENT_MODES.md` |
| Windows Agent details | `WINDOWS_CLIENT.md` |
| macOS Agent details | `MACOS_CLIENT.md` |

## Qualification and evidence documents

These documents are useful for qualification but do not redefine product semantics:

- [`USER_E2E_SCENARIOS.md`](../USER_E2E_SCENARIOS.md) — canonical FULL_USER_E2E matrix and v2.4 operator manual runbook
- `HUMAN_UX_ADVERSARIAL_E2E.md`
- `OCI_ACCEPTANCE.md`

## Historical / internal compatibility documents

- `SCHEMA_V2_DEPLOYMENT.md` — historical JSON registry schema-v2 deployment material. It is not v2.4 control-plane authority.
- `FRP_UPGRADE.md` — Relay Engine/upstream compatibility and migration detail. FRP/internal helper names in this file are not public Data Relay Link CLI vocabulary.
- `WINDOWS_CLIENT_DESIGN.md` — platform design notes; public command behavior remains governed by the CLI/AI Master.
- `PRIVILEGE_SEPARATION_DEFERRED.md` — deferred privilege-separation record for the current v2.4 target. v2.3.1 was not manufactured.

## Current v2.4 public model

```text
Managed Host / DRLink Agent

Network Object / Network Group
Service Object / Service Group
Permission Object / Permission Group

AI Identity
Remote Service

Remote Access
Internet Access
AI Access

BLACKLIST / WHITELIST

ConfigurationBundle
```

Public command examples should use `drlink`, not internal `frp-*` helpers.

## Engineering development standard

Software-development process, AI-agent workflow, testing strategy, change lifecycle, and release workflow are governed by the canonical Engineering System:

```text
https://github.com/datarelay-labs/engineering-system
```

Product specifications in this repository define **what Data Relay Link must do**. The Engineering System defines **how product changes are designed, implemented, tested, reviewed, released, and operated**.

Engineering System managed-adoption files such as `AGENTS.md` and `.engineering/*` are lifecycle/governance surfaces, not substitutes for the product specifications above. Their adoption or version upgrade must follow the Engineering System adoption workflow rather than being hand-copied as part of a documentation-only change.

## Documentation maintenance rule

A product behavior change is incomplete until the affected canonical document is updated.

A historical/internal document may retain implementation names only when the document clearly labels them as internal or historical and does not present them as current public CLI.

Before release qualification, run a documentation consistency review against the exact candidate HEAD and verify that README, Product Master, CLI Reference, release documents, and generated/help output describe the same behavior.
