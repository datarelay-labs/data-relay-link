#!/usr/bin/env python3
"""Zero-flicker frpctl line editor.

Uses the stdlib readline module only. Never writes a history file.
Never runs eval, bash -c, or the command dispatcher from Tab.

Tab shows ambiguous next-token candidates on the first press. Repeated Tab
on the same line does not reprint the same list. Unique matches complete
inline. The input buffer is never cleared or rewritten by Tab.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

try:
    import readline
except ImportError:  # pragma: no cover
    readline = None


def readline_backend():
    """Identify the actual Python readline backend (not the OS name).

    Returns ``gnu``, ``libedit``, or ``unknown``. Detection prefers module
    metadata over ``uname`` so Homebrew GNU Readline on macOS and
    libedit-backed builds elsewhere are handled correctly.
    """
    if readline is None:
        return "unknown"
    doc = (getattr(readline, "__doc__", "") or "").lower()
    if "libedit" in doc or "editline" in doc:
        return "libedit"
    if "gnu readline" in doc or "gnu's readline" in doc:
        return "gnu"
    # GNU readline exposes this; libedit/editline typically does not.
    if getattr(readline, "_READLINE_LIBRARY_VERSION", None):
        return "gnu"
    return "unknown"


def _load_grammar():
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import frp_ctl_grammar as grammar  # noqa: WPS433

    return grammar


class LineEditor:
    def __init__(self, payload):
        self.grammar = _load_grammar()
        self.payload = payload
        self.role = payload.get("role") or "unknown"
        self.names = payload.get("names") or []
        self.clients = payload.get("clients") or []
        self.services = payload.get("services") or {}
        self.local_services = payload.get("local_services") or []
        self.groups = payload.get("groups") or []
        self._matches = []
        self._last_display_key = None
        self.prompt = os.environ.get("FRP_CTL_PROMPT") or "drlink> "

    def completer(self, text, state):
        if state == 0:
            line = readline.get_line_buffer() if readline else (text or "")
            trailing = bool(line) and line[-1:] in " \t"
            cands = self.grammar.completion_candidates(
                line,
                self.role,
                self.names,
                self.services,
                self.local_services,
                trailing=trailing,
                groups=self.groups,
            )
            # Unique -> replace current word (append space). Longer common
            # prefix -> extend only. Fully ambiguous -> return candidates so
            # readline can display them via the display hook.
            if not cands:
                self._matches = []
            elif len(cands) == 1:
                self._matches = [cands[0] + " "]
                self._last_display_key = None
            else:
                shared = cands[0]
                for item in cands[1:]:
                    while shared and not item.startswith(shared):
                        shared = shared[:-1]
                prefix = text or ""
                if shared and shared != prefix and len(shared) > len(prefix):
                    self._matches = [shared]
                    self._last_display_key = None
                else:
                    self._matches = list(cands)
        try:
            return self._matches[state]
        except IndexError:
            return None

    def display_matches(self, _substitution, matches, _longest):
        """Print candidates above the prompt; leave the buffer intact."""
        if readline is None:
            return
        cleaned = []
        for item in matches or []:
            text = str(item).rstrip()
            if text:
                cleaned.append(text)
        if len(cleaned) <= 1:
            return
        line = readline.get_line_buffer() or ""
        key = (line, tuple(cleaned))
        if key == self._last_display_key:
            # Same line / same candidates: do not spam the list again.
            return
        self._last_display_key = key
        # Readline may alphabetize matches; restore grammar order for display.
        preferred = self.grammar.completion_candidates(
            line,
            self.role,
            self.names,
            self.services,
            self.local_services,
            trailing=bool(line) and line[-1:] in " \t",
            groups=self.groups,
        )
        if preferred:
            rank = {name: idx for idx, name in enumerate(preferred)}
            cleaned.sort(key=lambda item: (rank.get(item, 10**6), item.lower()))
        body = self.grammar.format_tab_candidates(
            line,
            cleaned,
            self.role,
            names=self.names,
            clients=self.clients,
        )
        if not body:
            return
        sys.stdout.write("\n")
        sys.stdout.write(body)
        if not body.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.write("\n")
        # Python's input()+readline often does not redisplay the prompt after a
        # custom completion display hook. Reprint prompt + exact buffer so the
        # operator can keep editing without flicker or buffer loss.
        sys.stdout.write(self.prompt)
        sys.stdout.write(line)
        sys.stdout.flush()

    def bind(self):
        if readline is None:
            return False
        backend = readline_backend()
        try:
            if backend == "libedit":
                # libedit/editline uses bind syntax, not GNU "tab: complete".
                # Without this, Tab inserts a literal tab and the incomplete
                # token is executed as a command (e.g. "statu" → Unknown).
                for stmt in (
                    "bind -e",
                    "bind '^I' rl_complete",
                    "bind '\\t' rl_complete",
                ):
                    try:
                        readline.parse_and_bind(stmt)
                    except Exception:
                        pass
            else:
                # GNU Readline (and unknown backends that accept GNU syntax).
                for stmt in (
                    "set show-all-if-ambiguous on",
                    "set show-all-if-unmodified on",
                    "set page-completions off",
                    "set completion-query-items 999999",
                    "set bell-style none",
                    "set horizontal-scroll-mode off",
                    "tab: complete",
                ):
                    try:
                        readline.parse_and_bind(stmt)
                    except Exception:
                        pass
                if backend == "unknown":
                    # Also attempt libedit Tab binding when detection is unsure.
                    for stmt in ("bind -e", "bind '^I' rl_complete"):
                        try:
                            readline.parse_and_bind(stmt)
                        except Exception:
                            pass
            readline.set_completer(self.completer)
            readline.set_completer_delims(" \t")
            hook = getattr(readline, "set_completion_display_matches_hook", None)
            if hook is not None:
                hook(self.display_matches)
        except Exception:
            try:
                readline.set_completer(self.completer)
                readline.set_completer_delims(" \t")
                hook = getattr(readline, "set_completion_display_matches_hook", None)
                if hook is not None:
                    hook(self.display_matches)
            except Exception:
                return False
        try:
            readline.clear_history()
        except Exception:
            pass
        try:
            readline.set_history_length(1000)
        except Exception:
            pass
        return True


def _looks_secret(grammar, line):
    try:
        return grammar.looks_secret(line)
    except Exception:
        return False


def run_repl(frpctl_bin, payload):
    grammar = _load_grammar()
    editor = LineEditor(payload)
    editor.bind()
    if payload.get("inventory_warning"):
        sys.stderr.write(
            "WARNING: completion inventory could not be loaded; "
            "Tab candidates may be incomplete. Run: doctor\n"
        )
    hist = []
    while True:
        try:
            line = input(editor.prompt)
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            continue
        # Any submitted line resets Tab duplicate-suppression state.
        editor._last_display_key = None
        stripped = line.strip()
        if not stripped:
            continue
        if _looks_secret(grammar, line):
            if readline is not None:
                try:
                    n = readline.get_current_history_length()
                    if n and readline.get_history_item(n) == line:
                        readline.remove_history_item(n - 1)
                except Exception:
                    pass
        else:
            hist.append(line)
            if readline is not None:
                try:
                    n = readline.get_current_history_length()
                    last = readline.get_history_item(n) if n else None
                    if last != line:
                        readline.add_history(line)
                except Exception:
                    pass
        try:
            tokens = grammar.tokenize(line)
        except grammar.ParseError as exc:
            sys.stderr.write("ERROR: %s\n" % exc)
            continue
        if not tokens:
            continue
        if tokens[0].startswith("!") or tokens[0] in grammar.SHELL_REJECT:
            sys.stderr.write("ERROR: arbitrary shell execution is not allowed.\n")
            continue
        if tokens[0] in ("exit", "quit", "q"):
            return 0
        if tokens[0] == "history" and (len(tokens) == 1 or tokens[-1] != "?"):
            if not hist:
                print("(no session history)")
            else:
                for idx, item in enumerate(hist, start=1):
                    print("%5s  %s" % (idx, item))
            continue
        env = os.environ.copy()
        env["FRP_CTL_REPL"] = "1"
        env.pop("FRP_CTL_SOURCED", None)
        env.pop("FRP_CTL_TEST_INPUT", None)
        try:
            proc = subprocess.run([frpctl_bin] + tokens, env=env, check=False)
        except OSError as exc:
            sys.stderr.write(
                "ERROR: could not run the Data Relay Link CLI backend: %s\n" % exc
            )
            continue
        if proc.returncode not in (0, 130) and tokens[0] not in ("?", "help"):
            print()
            print("Command failed with exit code %s." % proc.returncode)
            print()
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--self-test" in argv:
        if readline is None:
            print("READLINE_UNAVAILABLE")
            return 1
        print("READLINE_OK")
        print("READLINE_BACKEND=%s" % readline_backend())
        return 0
    frpctl_bin = os.environ.get("FRPCTL_BIN") or "drlink"
    if "--frpctl" in argv:
        idx = argv.index("--frpctl")
        if idx + 1 < len(argv):
            frpctl_bin = argv[idx + 1]
    payload = {}
    raw = os.environ.get("FRP_CTL_GRAMMAR_PAYLOAD") or ""
    if raw.strip():
        payload = json.loads(raw)
    elif not sys.stdin.isatty():
        incoming = sys.stdin.read()
        if incoming.strip():
            payload = json.loads(incoming)
    if readline is None:
        sys.stderr.write("ERROR: Python readline is unavailable.\n")
        return 2
    return run_repl(frpctl_bin, payload)


if __name__ == "__main__":
    raise SystemExit(main())
