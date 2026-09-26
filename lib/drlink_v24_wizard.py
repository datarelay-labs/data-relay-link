#!/usr/bin/env python3
"""Interactive Guided Wizards for the v2.4 CLI/AI Master.

Draft state stays in memory until Apply. Cancel leaves authoritative state unchanged.
Inline Object drafts are part of the same Change Plan as the parent Wizard.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from drlink_control_db import ControlPlaneError
from drlink_control_plane import ControlPlane
import drlink_v24 as v24

CIDR_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)/(?:3[0-2]|[12]?\d)$"
)
IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

# Test hook: ScriptedIO instance or None
_WIZARD_IO: Optional["WizardIO"] = None


def set_wizard_io(io: Optional["WizardIO"]) -> None:
    global _WIZARD_IO
    _WIZARD_IO = io


class WizardCancelled(Exception):
    """User cancelled; no authoritative mutation."""


class WizardIO:
    def write(self, text: str) -> None:
        raise NotImplementedError

    def ask(self, prompt: str = "") -> str:
        raise NotImplementedError

    def is_interactive(self) -> bool:
        return True


class TtyIO(WizardIO):
    def write(self, text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()

    def ask(self, prompt: str = "") -> str:
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt) as exc:
            raise WizardCancelled() from exc


class ScriptedIO(WizardIO):
    def __init__(self, answers: list[str], *, out: Optional[list[str]] = None):
        self.answers = list(answers)
        self.out = out if out is not None else []
        self._idx = 0

    def write(self, text: str) -> None:
        self.out.append(text)

    def ask(self, prompt: str = "") -> str:
        if prompt:
            self.out.append(prompt)
        if self._idx >= len(self.answers):
            raise WizardCancelled()
        ans = self.answers[self._idx]
        self._idx += 1
        return ans


def _io() -> WizardIO:
    if _WIZARD_IO is not None:
        return _WIZARD_IO
    env = os.environ.get("DRLINK_WIZARD_ANSWERS")
    if env is not None:
        answers = env.split("\n") if env else []
        return ScriptedIO(answers)
    if sys.stdin.isatty() and sys.stdout.isatty():
        return TtyIO()
    raise ControlPlaneError(
        "ERROR:\nInteractive wizard requires a TTY session.\n\nNo changes were applied."
    )


def wizard_available() -> bool:
    if _WIZARD_IO is not None:
        return True
    if os.environ.get("DRLINK_WIZARD_ANSWERS") is not None:
        return True
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        return False


@dataclass
class DraftObject:
    kind: str
    name: str
    fields: dict = field(default_factory=dict)


@dataclass
class WizardSession:
    resource: str
    name: str
    mode: str  # create | edit
    before: dict = field(default_factory=dict)
    draft: dict = field(default_factory=dict)
    inline: list[DraftObject] = field(default_factory=list)
    policy_mode: Optional[str] = None


def _emit(io: WizardIO, text: str) -> None:
    if not text.endswith("\n"):
        text += "\n"
    io.write(text)


CANCEL_TOKENS = frozenset({"cancel", "c"})
DRLINK_CMD_RE = re.compile(
    r"^(show|set|unset|test|system|create|help|menu|exit|quit)\b",
    re.IGNORECASE,
)


def _is_cancel(raw: str) -> bool:
    return str(raw or "").strip().lower() in CANCEL_TOKENS


def _looks_like_drlink_command(raw: str) -> bool:
    text = str(raw or "").strip()
    if not text:
        return False
    if "\n" in text or "\r" in text:
        # Multi-line paste almost always means the operator intended REPL commands.
        first = text.splitlines()[0].strip()
        return bool(DRLINK_CMD_RE.match(first) or DRLINK_CMD_RE.match(text))
    return bool(DRLINK_CMD_RE.match(text))


def _menu_selection_error(io: WizardIO, raw: str, lo: int, hi: int) -> None:
    if _looks_like_drlink_command(raw):
        _emit(
            io,
            "ERROR:\n"
            "This prompt is waiting for a menu selection (%d-%d).\n\n"
            "The entered text looks like a DRLink command.\n\n"
            "Choose Back/Cancel to leave this Wizard,\n"
            "then run the command at the drlink> prompt.\n\n"
            "No changes were applied." % (lo, hi),
        )
        return
    _emit(io, "ERROR: Invalid selection. Stay on this step.")


def _ask_choice(io: WizardIO, title: str, options: list[str], *, allow_create: list[tuple[str, str]] = None) -> str:
    """Return selected option text, or '+create:<kind>' for inline create markers."""
    while True:
        _emit(io, "")
        _emit(io, title)
        _emit(io, "-" * len(title.split("\n")[0]))
        idx = 1
        mapping: dict[str, str] = {}
        for opt in options:
            _emit(io, "%d) %s" % (idx, opt))
            mapping[str(idx)] = opt
            idx += 1
        for kind, label in allow_create or []:
            token = "+create:%s" % kind
            _emit(io, "%d) %s" % (idx, label))
            mapping[str(idx)] = token
            idx += 1
        _emit(io, "c) Cancel")
        raw = io.ask("Select: ").strip()
        if _is_cancel(raw):
            raise WizardCancelled()
        if raw in mapping:
            return mapping[raw]
        # allow typing the option name directly
        for opt in options:
            if raw.lower() == opt.lower():
                return opt
        _menu_selection_error(io, raw, 1, max(1, idx - 1))


def _ask_text(io: WizardIO, prompt: str, *, default: Optional[str] = None, validate: Callable[[str], Optional[str]] = None) -> str:
    while True:
        suffix = " [%s]" % default if default not in (None, "") else ""
        raw = io.ask("%s%s: " % (prompt, suffix)).strip()
        if _is_cancel(raw):
            raise WizardCancelled()
        if not raw and default is not None:
            raw = default
        if validate:
            err = validate(raw)
            if err:
                _emit(io, "ERROR: %s" % err)
                continue
        return raw


def _ask_yes_no(io: WizardIO, prompt: str, *, default: Optional[bool] = None) -> bool:
    while True:
        hint = " [Y/n]" if default is True else (" [y/N]" if default is False else "")
        raw = io.ask("%s%s: " % (prompt, hint)).strip().lower()
        if _is_cancel(raw):
            raise WizardCancelled()
        if not raw and default is not None:
            return default
        if raw in ("y", "yes", "1"):
            return True
        if raw in ("n", "no", "0"):
            return False
        _emit(io, "ERROR: Enter yes or no. Type cancel to abort.")


def _validate_network_value(typ: str, value: str) -> Optional[str]:
    if typ == "ip":
        if not IP_RE.match(value):
            return "Invalid IP '%s'." % value
    elif typ == "cidr":
        if not CIDR_RE.match(value):
            return "Invalid CIDR '%s'." % value
    elif typ == "fqdn":
        if not FQDN_RE.match(value):
            return "Invalid FQDN '%s'." % value
    return None


def _apply_inline_then(plane: ControlPlane, session: WizardSession, apply_fn: Callable[[], Any]) -> Any:
    """Apply inline drafts then the primary mutation in one batch Change Plan."""
    prev = plane._batch_mode
    plane._batch_mode = True
    plane._batch_results = []
    try:
        for draft in session.inline:
            if draft.kind == "network-object":
                v24.set_network_object(
                    plane,
                    draft.name,
                    type=draft.fields.get("type"),
                    value=draft.fields.get("value"),
                    oneshot=True,
                )
            elif draft.kind == "network-group":
                v24.set_network_group(
                    plane, draft.name, members=list(draft.fields.get("members") or []), oneshot=True
                )
            elif draft.kind == "service-object":
                v24.set_service_object(
                    plane,
                    draft.name,
                    type=draft.fields.get("type"),
                    port=int(draft.fields["port"]),
                    oneshot=True,
                )
            elif draft.kind == "service-group":
                v24.set_service_group(
                    plane, draft.name, members=list(draft.fields.get("members") or []), oneshot=True
                )
            elif draft.kind == "permission-object":
                v24.set_permission_object(
                    plane,
                    draft.name,
                    permissions=list(draft.fields.get("permissions") or []),
                    oneshot=True,
                )
            elif draft.kind == "permission-group":
                v24.set_permission_group(
                    plane, draft.name, members=list(draft.fields.get("members") or []), oneshot=True
                )
        return apply_fn()
    finally:
        plane._batch_mode = prev
        plane._batch_results = []


def _inline_network_object(io: WizardIO, session: WizardSession) -> str:
    name = _ask_text(io, "Network Object name", validate=lambda n: None if n else "Name is required.")
    typ = _ask_choice(io, "Type", ["ip", "cidr", "fqdn"])
    value = _ask_text(
        io,
        "Value",
        validate=lambda v: _validate_network_value(typ, v) or (None if v else "Value is required."),
    )
    session.inline.append(DraftObject("network-object", name, {"type": typ, "value": value}))
    _emit(io, "Draft Network Object '%s' created (not applied yet)." % name)
    return name


def _inline_network_group(io: WizardIO, plane: ControlPlane, session: WizardSession) -> str:
    name = _ask_text(io, "Network Group name", validate=lambda n: None if n else "Name is required.")
    members: list[str] = []
    while True:
        existing = [r["name"] for r in v24.list_network_objects(plane)]
        existing += [d.name for d in session.inline if d.kind == "network-object"]
        choice = _ask_choice(
            io,
            "Add member",
            existing + (["(done)"] if members else []),
            allow_create=[("network-object", "+ Create Network Object")],
        )
        if choice == "(done)":
            break
        if choice.startswith("+create:"):
            members.append(_inline_network_object(io, session))
        else:
            members.append(choice)
        if not _ask_yes_no(io, "Add another member?", default=False):
            break
    if not members:
        raise ControlPlaneError("Network Group requires at least one member")
    session.inline.append(DraftObject("network-group", name, {"members": members}))
    _emit(io, "Draft Network Group '%s' created (not applied yet)." % name)
    return name


def _inline_service_object(io: WizardIO, session: WizardSession) -> str:
    name = _ask_text(io, "Service Object name", validate=lambda n: None if n else "Name is required.")
    typ = _ask_choice(io, "Type", ["tcp", "udp", "fixed-tcp"])
    port_s = _ask_text(
        io,
        "Port",
        validate=lambda p: (
            None
            if p.isdigit() and 1 <= int(p) <= 65535
            else "Enter a port between 1 and 65535."
        ),
    )
    session.inline.append(DraftObject("service-object", name, {"type": typ, "port": int(port_s)}))
    _emit(io, "Draft Service Object '%s' created (not applied yet)." % name)
    return name


def _inline_service_group(io: WizardIO, plane: ControlPlane, session: WizardSession) -> str:
    name = _ask_text(io, "Service Group name", validate=lambda n: None if n else "Name is required.")
    existing = [r["name"] for r in plane.conn.execute("SELECT name FROM service_objects ORDER BY name")]
    existing += [d.name for d in session.inline if d.kind == "service-object"]
    members: list[str] = []
    while True:
        choice = _ask_choice(
            io,
            "Add member",
            existing + (["(done)"] if members else []),
            allow_create=[("service-object", "+ Create Service Object")],
        )
        if choice == "(done)":
            break
        if choice.startswith("+create:"):
            members.append(_inline_service_object(io, session))
        else:
            members.append(choice)
        if not _ask_yes_no(io, "Add another member?", default=False):
            break
    session.inline.append(DraftObject("service-group", name, {"members": members}))
    return name


def _inline_permission_object(io: WizardIO, session: WizardSession) -> str:
    name = _ask_text(io, "Permission Object name", validate=lambda n: None if n else "Name is required.")
    perms = []
    options = sorted(v24.PERMISSIONS)
    while True:
        choice = _ask_choice(io, "Add permission", options + (["(done)"] if perms else []))
        if choice == "(done)":
            break
        perms.append(choice)
        if not _ask_yes_no(io, "Add another permission?", default=False):
            break
    session.inline.append(DraftObject("permission-object", name, {"permissions": perms}))
    return name


def _inline_permission_group(io: WizardIO, plane: ControlPlane, session: WizardSession) -> str:
    name = _ask_text(io, "Permission Group name", validate=lambda n: None if n else "Name is required.")
    existing = [r["name"] for r in plane.conn.execute("SELECT name FROM permission_objects ORDER BY name")]
    existing += [d.name for d in session.inline if d.kind == "permission-object"]
    members: list[str] = []
    while True:
        choice = _ask_choice(
            io,
            "Add member",
            existing + (["(done)"] if members else []),
            allow_create=[("permission-object", "+ Create Permission Object")],
        )
        if choice == "(done)":
            break
        if choice.startswith("+create:"):
            members.append(_inline_permission_object(io, session))
        else:
            members.append(choice)
        if not _ask_yes_no(io, "Add another member?", default=False):
            break
    session.inline.append(DraftObject("permission-group", name, {"members": members}))
    return name


def _review_menu(io: WizardIO, session: WizardSession, lines: list[str]) -> str:
    _emit(io, "")
    _emit(io, "Review")
    _emit(io, "======")
    for line in lines:
        _emit(io, line)
    if session.mode == "edit" and session.before:
        _emit(io, "")
        _emit(io, "Before")
        _emit(io, "------")
        for k, v in session.before.items():
            _emit(io, "%s : %s" % (k, v))
        _emit(io, "")
        _emit(io, "After")
        _emit(io, "-----")
        for k, v in session.draft.items():
            if session.before.get(k) != v:
                _emit(io, "%s : %s" % (k, v))
    _emit(io, "")
    _emit(io, "1) Apply")
    _emit(io, "2) Edit")
    _emit(io, "3) Cancel")
    while True:
        raw = io.ask("Select: ").strip()
        if raw in ("1", "apply"):
            return "apply"
        if raw in ("2", "edit"):
            return "edit"
        if raw in ("3", "cancel", "c"):
            return "cancel"
        if _looks_like_drlink_command(raw):
            _emit(
                io,
                "ERROR:\n"
                "This prompt is waiting for a menu selection (1-3).\n\n"
                "The entered text looks like a DRLink command.\n\n"
                "Choose Cancel (3) to leave this Wizard,\n"
                "then run the command at the drlink> prompt.\n\n"
                "No changes were applied.",
            )
            continue
        _emit(io, "ERROR: Invalid selection. Type 1, 2, 3, or cancel.")


def _cancel_message() -> str:
    return "No changes were applied.\n"


# ---------------------------------------------------------------------------
# Resource wizards
# ---------------------------------------------------------------------------


def run_network_object_wizard(plane: ControlPlane, name: str) -> int:
    io = _io()
    existing = plane.get_object(name)
    session = WizardSession(
        "network-object",
        name,
        "edit" if existing else "create",
        before=(
            {
                "type": v24.display_network_type(existing["type"]),
                "value": (plane._object_values(existing["id"]) or ["-"])[0],
            }
            if existing
            else {}
        ),
        draft={},
    )
    try:
        while True:
            typ = _ask_choice(io, "Network Object type", ["ip", "cidr", "fqdn"])
            value = _ask_text(
                io,
                "Value",
                default=session.draft.get("value") or session.before.get("value"),
                validate=lambda v: _validate_network_value(typ, v),
            )
            session.draft = {"type": typ, "value": value}
            action = _review_menu(
                io,
                session,
                ["Name : %s" % name, "Type : %s" % typ.upper(), "Value : %s" % value],
            )
            if action == "cancel":
                sys.stdout.write(_cancel_message())
                return 0
            if action == "edit":
                continue

            def apply_fn():
                return v24.set_network_object(
                    plane, name, type=typ, value=value, oneshot=True
                )

            result = plane._mutate(
                "set network-object %s" % name,
                "wizard network object",
                lambda: _apply_inline_then(plane, session, apply_fn),
            )
            sys.stdout.write("Network Object %s: %s\n" % (result.get("operation", "set"), name))
            return 0
    except WizardCancelled:
        sys.stdout.write(_cancel_message())
        return 0


def run_network_group_wizard(plane: ControlPlane, name: str) -> int:
    io = _io()
    existing = plane.get_object_group(name)
    session = WizardSession("network-group", name, "edit" if existing else "create")
    try:
        while True:
            members: list[str] = []
            available = [r["name"] for r in v24.list_network_objects(plane)]
            while True:
                choice = _ask_choice(
                    io,
                    "Members",
                    available + (["(done)"] if members else []),
                    allow_create=[
                        ("network-object", "+ Create Network Object"),
                        ("network-group", "+ Create Network Group"),
                    ],
                )
                if choice == "(done)":
                    break
                if choice == "+create:network-object":
                    members.append(_inline_network_object(io, session))
                elif choice == "+create:network-group":
                    members.append(_inline_network_group(io, plane, session))
                else:
                    members.append(choice)
                if not _ask_yes_no(io, "Add another member?", default=len(members) == 0):
                    break
            session.draft = {"members": ",".join(members)}
            action = _review_menu(
                io, session, ["Name : %s" % name, "Members : %s" % ", ".join(members)]
            )
            if action == "cancel":
                sys.stdout.write(_cancel_message())
                return 0
            if action == "edit":
                continue

            def apply_fn():
                return v24.set_network_group(plane, name, members=members, oneshot=True)

            plane._mutate(
                "set network-group %s" % name,
                "wizard network group",
                lambda: _apply_inline_then(plane, session, apply_fn),
            )
            sys.stdout.write("Network Group set: %s\n" % name)
            return 0
    except WizardCancelled:
        sys.stdout.write(_cancel_message())
        return 0


def run_service_object_wizard(plane: ControlPlane, name: str) -> int:
    io = _io()
    existing = v24.get_service_object(plane, name)
    session = WizardSession(
        "service-object",
        name,
        "edit" if existing else "create",
        before={"type": existing["type"], "port": str(existing["port"])} if existing else {},
    )
    # User-recognizable presets. UDP is intentionally omitted from the normal
    # public Wizard (v2.4 Remote Service is TCP / Fixed TCP only).
    presets = [
        ("SSH", "tcp", 22),
        ("HTTP", "tcp", 80),
        ("HTTPS", "tcp", 443),
        ("RDP", "tcp", 3389),
        ("Custom TCP", "tcp", None),
        ("Fixed TCP", "fixed-tcp", None),
    ]
    try:
        while True:
            _emit(io, "")
            _emit(io, "Service Object type")
            _emit(io, "------------------")
            for i, (label, _typ, port) in enumerate(presets, 1):
                if port is not None:
                    _emit(io, "%d) %s (TCP/%d)" % (i, label, port))
                else:
                    _emit(io, "%d) %s" % (i, label))
            _emit(io, "c) Cancel")
            _emit(io, "")
            _emit(
                io,
                "Custom TCP uses the normal published-service port pool.\n"
                "Fixed TCP reserves a stable public port equal to the service port.",
            )
            raw = io.ask("Select: ").strip()
            if _is_cancel(raw):
                sys.stdout.write(_cancel_message())
                return 0
            choice = None
            if raw.isdigit() and 1 <= int(raw) <= len(presets):
                choice = presets[int(raw) - 1]
            else:
                for preset in presets:
                    if raw.lower() == preset[0].lower():
                        choice = preset
                        break
            if choice is None:
                _menu_selection_error(io, raw, 1, len(presets))
                continue
            label, typ, default_port = choice
            if default_port is None:
                port_s = _ask_text(
                    io,
                    "Port",
                    default=session.draft.get("port") or session.before.get("port"),
                    validate=lambda p: (
                        None
                        if p.isdigit() and 1 <= int(p) <= 65535
                        else "Enter a port between 1 and 65535."
                    ),
                )
            else:
                port_s = str(default_port)
            session.draft = {"type": typ, "port": port_s, "label": label}
            action = _review_menu(
                io,
                session,
                [
                    "Name : %s" % name,
                    "Type : %s (%s)" % (label, typ),
                    "Port : %s" % port_s,
                ],
            )
            if action == "cancel":
                sys.stdout.write(_cancel_message())
                return 0
            if action == "edit":
                continue
            v24.set_service_object(plane, name, type=typ, port=int(port_s), oneshot=True)
            sys.stdout.write("Service Object set: %s\n" % name)
            return 0
    except WizardCancelled:
        sys.stdout.write(_cancel_message())
        return 0


def run_service_group_wizard(plane: ControlPlane, name: str) -> int:
    io = _io()
    existing = v24.get_service_group(plane, name)
    session = WizardSession("service-group", name, "edit" if existing else "create")
    try:
        while True:
            members: list[str] = []
            available = [r["name"] for r in plane.conn.execute("SELECT name FROM service_objects ORDER BY name")]
            while True:
                choice = _ask_choice(
                    io,
                    "Members",
                    available + (["(done)"] if members else []),
                    allow_create=[("service-object", "+ Create Service Object")],
                )
                if choice == "(done)":
                    break
                if choice.startswith("+create:"):
                    members.append(_inline_service_object(io, session))
                else:
                    members.append(choice)
                if not _ask_yes_no(io, "Add another member?", default=False):
                    break
            session.draft = {"members": ",".join(members)}
            action = _review_menu(io, session, ["Name : %s" % name, "Members : %s" % ", ".join(members)])
            if action == "cancel":
                sys.stdout.write(_cancel_message())
                return 0
            if action == "edit":
                continue

            def apply_fn():
                return v24.set_service_group(plane, name, members=members, oneshot=True)

            plane._mutate(
                "set service-group %s" % name,
                "wizard service group",
                lambda: _apply_inline_then(plane, session, apply_fn),
            )
            sys.stdout.write("Service Group set: %s\n" % name)
            return 0
    except WizardCancelled:
        sys.stdout.write(_cancel_message())
        return 0


def run_permission_object_wizard(plane: ControlPlane, name: str) -> int:
    io = _io()
    existing = v24.get_permission_object(plane, name)
    session = WizardSession("permission-object", name, "edit" if existing else "create")
    try:
        while True:
            perms: list[str] = []
            options = sorted(v24.PERMISSIONS)
            while True:
                choice = _ask_choice(io, "Permissions", options + (["(done)"] if perms else []))
                if choice == "(done)":
                    break
                perms.append(choice)
                if not _ask_yes_no(io, "Add another permission?", default=False):
                    break
            session.draft = {"permissions": ",".join(perms)}
            action = _review_menu(io, session, ["Name : %s" % name, "Permissions : %s" % ", ".join(perms)])
            if action == "cancel":
                sys.stdout.write(_cancel_message())
                return 0
            if action == "edit":
                continue
            v24.set_permission_object(plane, name, permissions=perms, oneshot=True)
            sys.stdout.write("Permission Object set: %s\n" % name)
            return 0
    except WizardCancelled:
        sys.stdout.write(_cancel_message())
        return 0


def run_permission_group_wizard(plane: ControlPlane, name: str) -> int:
    io = _io()
    existing = v24.get_permission_group(plane, name)
    session = WizardSession("permission-group", name, "edit" if existing else "create")
    try:
        while True:
            members: list[str] = []
            available = [r["name"] for r in plane.conn.execute("SELECT name FROM permission_objects ORDER BY name")]
            while True:
                choice = _ask_choice(
                    io,
                    "Members",
                    available + (["(done)"] if members else []),
                    allow_create=[("permission-object", "+ Create Permission Object")],
                )
                if choice == "(done)":
                    break
                if choice.startswith("+create:"):
                    members.append(_inline_permission_object(io, session))
                else:
                    members.append(choice)
                if not _ask_yes_no(io, "Add another member?", default=False):
                    break
            action = _review_menu(io, session, ["Name : %s" % name, "Members : %s" % ", ".join(members)])
            if action == "cancel":
                sys.stdout.write(_cancel_message())
                return 0
            if action == "edit":
                continue

            def apply_fn():
                return v24.set_permission_group(plane, name, members=members, oneshot=True)

            plane._mutate(
                "set permission-group %s" % name,
                "wizard permission group",
                lambda: _apply_inline_then(plane, session, apply_fn),
            )
            sys.stdout.write("Permission Group set: %s\n" % name)
            return 0
    except WizardCancelled:
        sys.stdout.write(_cancel_message())
        return 0


def _select_network_selector(
    io: WizardIO, plane: ControlPlane, session: WizardSession, title: str, *, internet_dest: bool = False
) -> str:
    options = [r["name"] for r in v24.list_network_objects(plane)]
    options += [d.name for d in session.inline if d.kind in ("network-object", "network-group")]
    for g in plane.conn.execute("SELECT name FROM object_groups ORDER BY name"):
        if g["name"] not in options:
            options.append(g["name"])
    while True:
        choice = _ask_choice(
            io,
            title,
            options,
            allow_create=[
                ("network-object", "+ Create Network Object"),
                ("network-group", "+ Create Network Group"),
            ],
        )
        if choice == "+create:network-object":
            return _inline_network_object(io, session)
        if choice == "+create:network-group":
            return _inline_network_group(io, plane, session)
        if internet_dest:
            obj = plane.get_object(choice)
            if obj and obj["type"] == "managed_endpoint":
                _emit(
                    io,
                    "ERROR: Managed Host cannot be used as an Internet Access destination.\n"
                    "Stay on this step.",
                )
                continue
        return choice


def _select_service(io: WizardIO, plane: ControlPlane, session: WizardSession) -> str:
    options = [r["name"] for r in plane.conn.execute("SELECT name FROM service_objects ORDER BY name")]
    options += [r["name"] for r in plane.conn.execute("SELECT name FROM service_groups ORDER BY name")]
    options += [d.name for d in session.inline if d.kind in ("service-object", "service-group")]
    # Built-in presets referenced by one-shot tests
    for builtin in ("ssh", "http", "https", "postgres"):
        if builtin not in options:
            options.append(builtin)
    choice = _ask_choice(
        io,
        "Service",
        options,
        allow_create=[
            ("service-object", "+ Create Service Object"),
            ("service-group", "+ Create Service Group"),
        ],
    )
    if choice == "+create:service-object":
        return _inline_service_object(io, session)
    if choice == "+create:service-group":
        return _inline_service_group(io, plane, session)
    return choice


def run_access_rule_wizard(plane: ControlPlane, family: str, name: str) -> int:
    io = _io()
    plane_key = v24._plane_key(family)
    existing = plane._get_rule(plane_key, name)
    pol = v24.get_access_policy(plane, plane_key)
    session = WizardSession(
        "%s-access" % plane_key,
        name,
        "edit" if existing else "create",
        before={},
    )
    title = "Remote Access" if plane_key == "remote" else "Internet Access"
    try:
        while True:
            if pol["mode"] is None and session.policy_mode is None:
                mode = _ask_choice(io, "Policy Mode", ["blacklist", "whitelist"])
                session.policy_mode = mode
            else:
                mode = session.policy_mode or pol["mode"]
            source = _select_network_selector(io, plane, session, "Source")
            destination = _select_network_selector(
                io, plane, session, "Destination", internet_dest=(plane_key == "internet")
            )
            service = _select_service(io, plane, session)
            enabled = _ask_yes_no(io, "Enabled", default=True)
            session.draft = {
                "Source": source,
                "Destination": destination,
                "Service": service,
                "Enabled": "YES" if enabled else "NO",
                "Mode": (mode or "").upper(),
            }
            effect = (
                "Matching access will be BLOCKED.\n  All other access remains ALLOWED."
                if (mode or "").lower() == "blacklist"
                else "Matching access will be ALLOWED.\n  All other access remains DENIED."
            )
            action = _review_menu(
                io,
                session,
                [
                    "Name        : %s" % name,
                    "Source      : %s" % source,
                    "Destination : %s" % destination,
                    "Service     : %s" % service,
                    "Enabled     : %s" % ("YES" if enabled else "NO"),
                    "",
                    "Effect:",
                    "  %s" % effect,
                ],
            )
            if action == "cancel":
                sys.stdout.write(_cancel_message())
                return 0
            if action == "edit":
                continue

            def apply_fn():
                return v24.set_access_rule(
                    plane,
                    plane_key,
                    name,
                    mode=mode,
                    source=source,
                    destination=destination,
                    service=service,
                    enabled=enabled,
                    oneshot=True,
                )

            plane._mutate(
                "set %s %s" % (family, name),
                "wizard access rule",
                lambda: _apply_inline_then(plane, session, apply_fn),
            )
            sys.stdout.write("%s rule set: %s\n" % (family, name))
            return 0
    except WizardCancelled:
        sys.stdout.write(_cancel_message())
        return 0


def run_ai_access_wizard(plane: ControlPlane, name: str) -> int:
    io = _io()
    existing = plane.conn.execute(
        "SELECT * FROM ai_policy_rules WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()
    pol = v24.get_access_policy(plane, "ai")
    session = WizardSession("ai-access", name, "edit" if existing else "create")
    try:
        while True:
            if pol["mode"] is None and session.policy_mode is None:
                mode = _ask_choice(io, "Policy Mode", ["blacklist", "whitelist"])
                session.policy_mode = mode
            else:
                mode = session.policy_mode or pol["mode"]
            identities = [
                r["name"]
                for r in plane.conn.execute(
                    "SELECT name FROM ai_principals WHERE name != ? ORDER BY name",
                    ("__oauth_unbound__",),
                )
            ]
            source = _ask_choice(io, "AI Identity (source)", identities or ["(none — create identity first)"])
            if source.startswith("("):
                raise ControlPlaneError(
                    "ERROR:\nNo verified AI Identity is available.\n\nNo changes were applied."
                )
            destination = _select_network_selector(io, plane, session, "Destination")
            perms = [r["name"] for r in plane.conn.execute("SELECT name FROM permission_objects ORDER BY name")]
            perms += [r["name"] for r in plane.conn.execute("SELECT name FROM permission_groups ORDER BY name")]
            choice = _ask_choice(
                io,
                "Permission",
                perms,
                allow_create=[
                    ("permission-object", "+ Create Permission Object"),
                    ("permission-group", "+ Create Permission Group"),
                ],
            )
            if choice == "+create:permission-object":
                permission = _inline_permission_object(io, session)
            elif choice == "+create:permission-group":
                permission = _inline_permission_group(io, plane, session)
            else:
                permission = choice
            paths: list[str] | None = None
            try:
                if v24.permission_includes_file_capability(plane, permission):
                    existing_paths = []
                    if existing is not None:
                        existing_paths = v24.list_ai_policy_path_scopes(plane, name)
                    default_paths = ",".join(existing_paths) if existing_paths else None
                    raw_paths = _ask_text(
                        io,
                        "Path scopes (comma-separated absolute globs; required for file permissions)",
                        default=default_paths,
                    )
                    paths = v24.parse_ai_paths_field(raw_paths)
            except ControlPlaneError:
                paths = None
            enabled = _ask_yes_no(io, "Enabled", default=True)
            session.draft = {
                "Source": source,
                "Destination": destination,
                "Permission": permission,
                "Paths": ", ".join(paths) if paths else "-",
                "Enabled": "YES" if enabled else "NO",
            }
            review_lines = [
                "Name        : %s" % name,
                "Source      : %s" % source,
                "Destination : %s" % destination,
                "Permission  : %s" % permission,
                "Paths       : %s" % (", ".join(paths) if paths else "-"),
                "Enabled     : %s" % ("YES" if enabled else "NO"),
            ]
            action = _review_menu(
                io,
                session,
                review_lines,
            )
            if action == "cancel":
                sys.stdout.write(_cancel_message())
                return 0
            if action == "edit":
                continue

            def apply_fn():
                return v24.set_ai_access_rule(
                    plane,
                    name,
                    mode=mode,
                    source=source,
                    destination=destination,
                    permission=permission,
                    paths=paths,
                    enabled=enabled,
                    oneshot=True,
                )

            plane._mutate(
                "set ai-access %s" % name,
                "wizard ai access",
                lambda: _apply_inline_then(plane, session, apply_fn),
            )
            sys.stdout.write("AI Access rule set: %s\n" % name)
            return 0
    except WizardCancelled:
        sys.stdout.write(_cancel_message())
        return 0


def run_ai_identity_wizard(plane: ControlPlane, name: str) -> int:
    """Guided AI Identity connect → OAuth verify → VERIFIED binding.

    All configuration remains draft until successful verification. Cancel must
    leave configuration revision and authoritative AI Identity state unchanged.
    """
    from drlink_v24_ai_identity import (
        discard_staged_ai_identity,
        verify_authorization_code,
        verify_client_credentials,
        WizardAuthCancelled,
    )

    io = _io()
    existing = plane.get_principal(name)
    existed_before = existing is not None
    rev_before = plane.current_revision()
    try:
        _emit(io, "Connect AI")
        _emit(io, "==========")
        _emit(io, "Name: %s" % name)
        kind = _ask_choice(io, "Type", ["Interactive AI", "Automation / Custom AI"])
        if kind.startswith("Interactive"):
            # Staging (no config revision) happens inside begin/verify.
            result = verify_authorization_code(plane, name, io=io, stage=True)
        else:
            if not existed_before:
                # Client Credentials requires a pre-provisioned credential identity.
                # Stage a pending principal without revision so Cancel stays atomic;
                # verification still demands an externally supplied secret.
                from drlink_v24_ai_identity import stage_ai_identity_oauth

                stage_ai_identity_oauth(plane, name)
            result = verify_client_credentials(plane, name, io=io)
        sys.stdout.write(
            "AI Identity verified: %s\nStatus: VERIFIED\nAuth: %s\n"
            % (name, result.get("grant") or "oauth")
        )
        return 0
    except (WizardCancelled, WizardAuthCancelled):
        if not existed_before:
            discard_staged_ai_identity(plane, name, only_if_unverified=True)
        # Drop any leftover pending OAuth request rows (non-config).
        try:
            plane.conn.execute(
                "DELETE FROM ai_oauth_pending WHERE principal_id IN "
                "(SELECT id FROM ai_principals WHERE name = ? COLLATE NOCASE)",
                (name,),
            )
            if not existed_before:
                discard_staged_ai_identity(plane, name, only_if_unverified=True)
            plane.conn.commit()
        except Exception:
            pass
        if plane.current_revision() != rev_before:
            # Should never happen; surface truthfully rather than lying.
            sys.stdout.write(
                "ERROR:\nWizard cancel left configuration revision changed.\n\n"
                "No trusted AI Identity binding was created.\n"
            )
            return 1
        sys.stdout.write(_cancel_message())
        return 0
    except ControlPlaneError:
        if not existed_before:
            discard_staged_ai_identity(plane, name, only_if_unverified=True)
        raise


def run_remote_service_wizard(plane: ControlPlane, name: str) -> int:
    io = _io()
    existing = plane.conn.execute(
        "SELECT * FROM agent_remote_services WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()
    session = WizardSession(
        "remote-service",
        name,
        "edit" if existing else "create",
        before=(
            {
                "Destination": existing["destination"],
                "Service": existing["service_object"],
                "Enabled": "YES" if existing["enabled"] else "NO",
            }
            if existing
            else {}
        ),
    )
    try:
        while True:
            dest = _ask_text(
                io,
                "Destination (this-host or Network Object)",
                default=session.draft.get("destination") or session.before.get("Destination"),
            )
            svc_options = [
                r["name"] for r in plane.conn.execute("SELECT name FROM service_objects ORDER BY name")
            ]
            for row in plane.conn.execute(
                "SELECT name FROM agent_object_catalog WHERE kind = 'service-object' ORDER BY name"
            ):
                if row["name"] not in svc_options:
                    svc_options.append(row["name"])
            service = _ask_choice(io, "Service Object", svc_options or ["ssh"])
            enabled = _ask_yes_no(io, "Enabled", default=True)
            session.draft = {"destination": dest, "service": service, "enabled": enabled}
            action = _review_menu(
                io,
                session,
                [
                    "Name        : %s" % name,
                    "Destination : %s" % dest,
                    "Service     : %s" % service,
                    "Enabled     : %s" % ("YES" if enabled else "NO"),
                ],
            )
            if action == "cancel":
                sys.stdout.write(_cancel_message())
                return 0
            if action == "edit":
                continue
            reachable = v24.detect_server_reachable(plane)
            result = v24.set_remote_service_agent(
                plane,
                name,
                destination=dest,
                service=service,
                enabled=enabled,
                oneshot=True,
                root=plane.root,
                server_reachable=reachable,
            )
            sys.stdout.write(
                v24.format_remote_service_view(
                    result.get("view")
                    or {
                        "name": name,
                        "destination": dest,
                        "service": service,
                        "status": "HEALTHY",
                        "endpoint": "-",
                    }
                )
            )
            return 0
    except WizardCancelled:
        sys.stdout.write(_cancel_message())
        return 0


WIZARDS = {
    "network-object": run_network_object_wizard,
    "network-group": run_network_group_wizard,
    "service-object": run_service_object_wizard,
    "service-group": run_service_group_wizard,
    "permission-object": run_permission_object_wizard,
    "permission-group": run_permission_group_wizard,
    "remote-access": lambda p, n: run_access_rule_wizard(p, "remote-access", n),
    "internet-access": lambda p, n: run_access_rule_wizard(p, "internet-access", n),
    "ai-access": run_ai_access_wizard,
    "ai-identity": run_ai_identity_wizard,
    "remote-service": run_remote_service_wizard,
}


def run_wizard(plane: ControlPlane, resource: str, name: str) -> int:
    fn = WIZARDS.get(resource)
    if not fn:
        raise ControlPlaneError("No guided wizard for resource '%s'" % resource)
    if not wizard_available():
        raise ControlPlaneError(
            "ERROR:\nInteractive %s wizard requires a TTY session.\n\nNo changes were applied."
            % resource.replace("-", " ").title()
        )
    try:
        return fn(plane, name)
    except (WizardCancelled, KeyboardInterrupt, EOFError):
        sys.stdout.write(_cancel_message())
        return 0
