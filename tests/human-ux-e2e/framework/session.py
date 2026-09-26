"""CLI session helpers with explicit execution-context markers."""
from __future__ import annotations

import io
import os
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .transcript import TranscriptRecorder
from .types import ExecutionContext, InteractionMode


@dataclass
class CommandResult:
    rc: int
    stdout: str
    stderr: str
    context: ExecutionContext
    cmdline: str

    @property
    def combined(self) -> str:
        return (self.stdout or "") + ("\n" + self.stderr if self.stderr else "")


class CliSession:
    def __init__(
        self,
        *,
        root: Path,
        context: ExecutionContext,
        recorder: Optional[TranscriptRecorder] = None,
        use_subprocess: bool = True,
    ):
        self.root = Path(root)
        self.context = context
        self.recorder = recorder
        self.use_subprocess = use_subprocess
        self.repo = Path(__file__).resolve().parents[3]

    def _role_token(self) -> str:
        return self.context.value

    def run(self, *tokens: str, env_extra: Optional[dict] = None) -> CommandResult:
        cmdline = " ".join(tokens)
        if self.recorder:
            self.recorder.command(self._role_token(), cmdline)

        prev_root = os.environ.get("FRP_DEPLOY_TEST_ROOT")
        os.environ["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
        os.environ.setdefault("DRLINK_CONFIRM", "yes")
        try:
            if self.use_subprocess:
                env = {**os.environ, **(env_extra or {})}
                env["FRP_DEPLOY_TEST_ROOT"] = str(self.root)
                proc = subprocess.run(
                    [str(self.repo / "tools" / "drlink"), *tokens],
                    capture_output=True,
                    text=True,
                    env=env,
                )
                result = CommandResult(proc.returncode, proc.stdout, proc.stderr, self.context, cmdline)
            else:
                import drlink_control_cli as cli
                from drlink_control_plane import ControlPlane

                buf = io.StringIO()
                err = io.StringIO()
                plane = ControlPlane(str(self.root))
                rc = 1
                try:
                    with redirect_stdout(buf), redirect_stderr(err):
                        try:
                            rc = cli.dispatch(list(tokens), root=str(self.root), plane=plane)
                            if rc is None:
                                rc = 0
                        except SystemExit as exc:
                            # CLI uses SystemExit for operator-facing errors.
                            code = exc.code
                            if code is None:
                                rc = 0
                            elif isinstance(code, int):
                                rc = code
                            else:
                                rc = 1
                                msg = str(code)
                                if msg and msg not in err.getvalue():
                                    err.write(msg if msg.endswith("\n") else msg + "\n")
                finally:
                    plane.close()
                result = CommandResult(int(rc), buf.getvalue(), err.getvalue(), self.context, cmdline)
        finally:
            if prev_root is None:
                os.environ.pop("FRP_DEPLOY_TEST_ROOT", None)
            else:
                os.environ["FRP_DEPLOY_TEST_ROOT"] = prev_root

        if self.recorder:
            self.recorder.output(result.stdout, stream="stdout")
            if result.stderr:
                self.recorder.output(result.stderr, stream="stderr")
            self.recorder.note("exit_code=%s" % result.rc)
        return result

    def grammar_help(self, *tokens: str) -> str:
        from frp_ctl_grammar import help_text

        role = "server" if self.context == ExecutionContext.DRLINK_SERVER else "client"
        text = help_text(list(tokens), role)
        if self.recorder:
            self.recorder.command(self._role_token(), "help " + " ".join(tokens))
            self.recorder.output(text)
        return text

    def catalog_menu(self) -> str:
        import frp_cli_catalog as catalog

        role = "server" if self.context == ExecutionContext.DRLINK_SERVER else "client"
        # Prefer workflow/menu surfaces
        parts = []
        if hasattr(catalog, "workflow_help"):
            parts.append(catalog.workflow_help(role))
        if hasattr(catalog, "root_help"):
            parts.append(catalog.root_help(role))
        text = "\n".join(p for p in parts if p)
        if self.recorder:
            self.recorder.command(self._role_token(), "menu")
            self.recorder.output(text)
        return text

    def catalog_help(self) -> str:
        import frp_cli_catalog as catalog

        role = "server" if self.context == ExecutionContext.DRLINK_SERVER else "client"
        text = catalog.root_help(role) if hasattr(catalog, "root_help") else ""
        if self.recorder:
            self.recorder.command(self._role_token(), "help")
            self.recorder.output(text)
        return text

    def context_help_question(self) -> str:
        from frp_ctl_grammar import help_text

        role = "server" if self.context == ExecutionContext.DRLINK_SERVER else "client"
        text = help_text([], role)
        if self.recorder:
            self.recorder.command(self._role_token(), "?")
            self.recorder.output(text)
        return text
