# Human UX Adversarial E2E Framework

## Purpose

Emulate a first-time Data Relay Link operator — including realistic mistakes —
and detect defects that ordinary unit/integration tests miss:

- confusing / contradictory UX
- stale or unexecutable guidance
- Server vs Agent role confusion
- cross-output endpoint/hostname/version drift
- success claims incompatible with Doctor health
- Wizard input misuse recovery gaps

This suite does **not** replace Real E2E, Double Full Real E2E, or Rick’s short
final human smoke validation.

## What it catches

| Class | Examples |
| --- | --- |
| Functional | command fails; mutation incomplete |
| Contract | grammar/role mismatch; missing Agent Host label |
| Cross-output | Remote Service port differs across views |
| Invalid guidance | Doctor recommends unknown command |
| Role confusion | `set remote-access` on Agent without Server guidance |
| Human UX blocking | Wizard accepts pasted CLI without recovery help |

## What it does not replace

- Live lab mutation / exact-HEAD Real E2E
- Security penetration testing
- Subjective “does it feel natural?” judgment (optional LLM review only)

## Architecture (five layers)

1. **Normal workflow** — lifecycle state machine + happy-path scenarios
2. **Adversarial / misuse** — wrong role, typos, duplicates, paste, cancel
3. **PTY human input** — Backspace/Enter/Ctrl+C/EOF on real PTYs
4. **Cross-output consistency** — extractors + validators across commands
5. **First-time user review** — optional LLM over sanitized transcripts

Layout:

```text
tests/human-ux-e2e/
  framework/     session, PTY, assertions, state machine, validators
  scenarios/     HUX-* scenario modules
  fixtures/      deterministic identities
  reports/       runtime transcripts (gitignored)
  runner.py
tests/run-human-ux-e2e.sh
```

## Scenario format

Scenarios register with stable IDs:

```python
@scenario(
    "HUX-AGT-006",
    "Agent show agent",
    execution_context=ExecutionContext.AGENT_HOST,
    interaction_mode=InteractionMode.ONE_SHOT,
    layer=Layer.NORMAL,
    domain="agent",
)
def hux_agt_006(env: ScenarioEnv) -> None:
    ...
```

Every transcript is marked with:

- `EXECUTION_CONTEXT=DRLINK_SERVER|AGENT_HOST|EXTERNAL_TEST_CLIENT`
- `INTERACTION_MODE=WIZARD|ONE_SHOT|PTY|CONTRACT|MIXED`

## How to run

```bash
./tests/run-human-ux-e2e.sh
./tests/run-human-ux-e2e.sh --list
./tests/run-human-ux-e2e.sh --domain wizard -v
./tests/run-human-ux-e2e.sh --scenario HUX-CONS-002
./tests/run-human-ux-e2e.sh --tag regression
```

Exit `0` only when all selected mandatory deterministic scenarios PASS.
Optional LLM review never changes the deterministic exit code.

## Severity model

| Severity | Meaning | Release |
| --- | --- | --- |
| P0 | security / destructive catastrophe | blocking |
| P1 | workflow broken, unsafe/unusable guidance, false success | blocking |
| P2-USER-BLOCKING | cannot complete without undocumented workaround | blocking |
| P2-UX | completes with significant avoidable confusion | backlog |
| P3 | cosmetic | backlog |

Finding classes: `FUNCTIONAL_FAILURE`, `SECURITY_FAILURE`, `CONTRACT_MISMATCH`,
`CROSS_OUTPUT_INCONSISTENCY`, `INVALID_GENERATED_GUIDANCE`,
`ROLE_CONTEXT_CONFUSION`, `HUMAN_UX_CONFUSION`, `COSMETIC_ONLY`.

## How to add scenarios

1. Choose a stable `HUX-…` ID and domain module under `scenarios/`.
2. Use `ScenarioEnv` fixtures (`ensure_server` / `ensure_agent` / `ensure_dual`).
3. Assert with `framework.assertions` (classified findings).
4. For product-emitted commands, run `command_validator.validate_*`.
5. Re-run `./tests/run-human-ux-e2e.sh --scenario HUX-…`.

## Deterministic vs LLM review

Deterministic PASS/FAIL is authoritative.

LLM review (layer 5) is optional:

```bash
DRLINK_HUX_LLM_REVIEW_CMD='…' ./tests/run-human-ux-e2e.sh --llm-review
```

Without a hook, the runner writes a sanitized transcript artifact and reports
`LLM_UX_REVIEW=NOT_RUN`.

## Live-lab safety boundary

This framework uses temporary directories, PTYs, ephemeral management servers,
and fixtures only. It must **not** mutate Rick’s manually prepared Server or
Managed Agents. Anything requiring live-lab mutation stays for final
qualification and is either skipped or expressed as a contract/harness scenario
here.
