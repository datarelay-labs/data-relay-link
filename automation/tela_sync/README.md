# Tela Knowledge Sync

OpenSpec is canonical. Tela is a searchable projection for ChatGPT and Cursor.

## Automatic flow

1. A qualified product change is archived in OpenSpec.
2. Run:
   python3 automation/tela_sync/render_canonical.py
3. Read automation/tela_sync/config.json.
4. Use the connected Tela MCP session to update canonical_page_id with the generated file body.
5. Read the page back and verify a representative decision query returns the canonical rationale.
6. If Tela is unavailable, do not roll back OpenSpec. Report KNOWLEDGE_SYNC_PENDING and retry later.

## Security

No Tela OAuth token, PAT, or API secret is stored in Git.
ChatGPT and Cursor use their existing authenticated Tela MCP sessions.

## Authority

knowledge/CANONICAL_SOURCE_OF_TRUTH.md is generated and must not be hand-edited.
If it or Tela disagrees with OpenSpec, OpenSpec wins.
