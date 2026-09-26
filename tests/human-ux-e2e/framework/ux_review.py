"""Optional first-time user LLM review — offline by default."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .transcript import sanitize


REVIEW_PROMPT = """Assume you are a first-time Data Relay Link operator.

From only this transcript:

1. Is the next action obvious?
2. Does any output contradict earlier output?
3. Does the CLI expose implementation terminology unnecessarily?
4. Does it recommend a command the user is unlikely to understand?
5. Is Server vs Agent execution context clear?
6. Does anything appear unsafe or suspicious despite being legitimate?
7. Is success claimed before the workflow is actually healthy?

LLM REVIEW DOES NOT DEFINE PRODUCT CORRECTNESS.
Emit UX_REVIEW_FINDINGS only.
"""


def prepare_review_artifact(reports_dir: Path, transcripts: list[str]) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / "first_time_user_review_input.txt"
    body = [REVIEW_PROMPT, "", "=" * 72, ""]
    for t in transcripts:
        body.append(sanitize(t))
        body.append("")
        body.append("-" * 72)
        body.append("")
    path.write_text("\n".join(body), encoding="utf-8")
    return path


def try_run_llm_review(artifact: Path) -> tuple[str, Optional[str]]:
    """Return (status, findings_text). Never fails the deterministic suite."""
    # No hard network dependency. If an env hook exists, call it.
    import os
    import subprocess

    hook = os.environ.get("DRLINK_HUX_LLM_REVIEW_CMD", "").strip()
    if not hook:
        return "NOT_RUN", None
    try:
        proc = subprocess.run(
            hook,
            shell=True,
            input=artifact.read_text(encoding="utf-8"),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            return "NOT_RUN", proc.stderr[:2000]
        return "RAN", proc.stdout
    except Exception as exc:
        return "NOT_RUN", str(exc)
