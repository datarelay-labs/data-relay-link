# AI Operating Rules

## Source of Truth

- Current accepted product behavior lives in `openspec/specs/`.
- Accepted decision history lives in archived OpenSpec changes.
- Code and tests are implementation/evidence; they do not silently redefine accepted behavior.
- Never infer undocumented design rationale from implementation.

## Automatic Decision Capture

When Rick explicitly accepts or finalizes a product/design decision (for example: "확정", "이걸로 가자", "최종", "그렇게 하자"):

1. Read the relevant current OpenSpec specs before proposing a delta.
2. Convert the accepted conclusion into a Decision Event matching `automation/decision_capture/decision-event.schema.json`.
3. Include the rationale, rejected alternatives, affected capabilities, normative requirement deltas, and verification tasks.
4. Run `python3 automation/decision_capture/capture_decision.py --event <event.json>`.
5. Commit/push the generated OpenSpec change or create a draft PR when repository access permits.
6. Do not ask Rick to manually update Markdown, project charters, master docs, or copy files between systems.

Do not capture exploratory or uncertain discussion. If the decision is materially unresolved, mark it as unresolved in conversation and do not mutate OpenSpec.

Never auto-archive a newly captured decision. Implementation and required tests/E2E evidence must complete before archive/sync into current specs.
