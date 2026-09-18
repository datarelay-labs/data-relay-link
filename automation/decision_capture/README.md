# Decision Capture Automation

This directory bridges an explicitly accepted AI discussion decision into a validated OpenSpec change.

## Operating model

```text
Discussion
  -> explicit acceptance
  -> AI builds Decision Event JSON
  -> capture_decision.py
  -> OpenSpec proposal/design/delta/tasks
  -> strict validation
  -> implementation + E2E
  -> archive/sync
```

Rick is not expected to create or maintain these files manually. The conversational/coding AI owns Decision Event creation and repository updates.

## Safety rules

- Only `status: accepted` can create a change.
- Product behavior changes require explicit capability deltas.
- Existing capability and requirement names are checked against current OpenSpec.
- Duplicate semantic decisions are rejected by fingerprint.
- Generated changes are strict-validated; failed generation is removed.
- Capture never automatically archives or changes current specs.
- Code cannot be used to invent missing design rationale.

The GitHub `decision-capture.yml` workflow accepts a base64-encoded Decision Event and attempts to create a decision branch plus draft PR. Direct connected-AI execution may invoke the same script on the development worktree.
