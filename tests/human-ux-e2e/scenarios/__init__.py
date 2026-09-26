"""Import all scenario modules so @scenario registrations run."""
from __future__ import annotations

from scenarios import (  # noqa: F401
    ai_access,
    bundle,
    consistency,
    cross_role,
    discovery_agent,
    discovery_server,
    discovery_wizard,
    internet_access,
    lifecycle,
    misuse,
    pty_and_regressions,
    remote_access,
    remote_service,
    service_object,
)
