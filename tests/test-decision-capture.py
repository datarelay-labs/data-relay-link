#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "automation" / "decision_capture" / "capture_decision.py"
SPEC = importlib.util.spec_from_file_location("decision_capture", MODULE_PATH)
dc = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(dc)


class DecisionCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="drlink-decision-")
        self.root = Path(self.tmp.name)
        (self.root / "openspec" / "specs" / "remote-service").mkdir(parents=True)
        (self.root / "openspec" / "changes" / "archive").mkdir(parents=True)
        (self.root / "openspec" / "config.yaml").write_text(
            "schema: spec-driven\n", encoding="utf-8"
        )
        (self.root / "openspec" / "specs" / "remote-service" / "spec.md").write_text(
            """# remote-service Specification

## Purpose

Defines externally observable Remote Service behavior for decision-capture testing.

## Requirements

### Requirement: Existing behavior
The system SHALL preserve an existing Remote Service configuration.

#### Scenario: Existing service
- **WHEN** the service already exists
- **THEN** the configuration remains available
""",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def event(self):
        return {
            "schema_version": 1,
            "status": "accepted",
            "accepted_at": "2026-09-18T20:30:00+09:00",
            "project": "data-relay-link",
            "title": "Retain valid configuration while disconnected",
            "summary": "A valid configuration remains durable during a temporary management disconnect.",
            "rationale": "Configuration validity is separate from temporary runtime reachability.",
            "behavior_change": True,
            "capabilities": [{
                "path": "remote-service",
                "kind": "existing",
                "requirements": [{
                    "operation": "ADDED",
                    "name": "Disconnected desired state",
                    "text": "The Agent SHALL retain valid desired state during a temporary Server disconnect.",
                    "scenarios": [{
                        "name": "Temporary disconnect",
                        "when": "the Server becomes temporarily unreachable",
                        "then": "the valid desired state is retained for later synchronization",
                    }],
                }],
            }],
        }

    def write_event(self, event, name="event.json"):
        path = self.root / name
        path.write_text(json.dumps(event), encoding="utf-8")
        return path

    def test_rejects_non_accepted_event(self):
        event = self.event()
        event["status"] = "proposed"
        with self.assertRaisesRegex(dc.DecisionError, "status=accepted"):
            dc.validate_event(self.root, event)

    def test_rejects_unknown_capability(self):
        event = self.event()
        event["capabilities"][0]["path"] = "does-not-exist"
        with self.assertRaisesRegex(dc.DecisionError, "does not exist"):
            dc.validate_event(self.root, event)

    def test_rejects_modified_requirement_that_does_not_exist(self):
        event = self.event()
        req = event["capabilities"][0]["requirements"][0]
        req["operation"] = "MODIFIED"
        req["name"] = "Missing requirement"
        with self.assertRaisesRegex(dc.DecisionError, "does not exist"):
            dc.validate_event(self.root, event)

    @unittest.skipUnless(shutil.which("openspec"), "OpenSpec CLI not installed")
    def test_capture_generates_strict_valid_change_and_rejects_duplicate(self):
        event_path = self.write_event(self.event())
        result = dc.capture(self.root, event_path)
        self.assertEqual(result["status"], "created")
        self.assertTrue(result["knowledge_id"].startswith("DRL-DEC-20260918-"))
        change = Path(result["change_path"])
        self.assertTrue((change / "proposal.md").is_file())
        self.assertTrue((change / "design.md").is_file())
        self.assertTrue((change / "tasks.md").is_file())
        self.assertTrue((change / "decision-event.json").is_file())
        self.assertTrue((change / "specs" / "remote-service" / "spec.md").is_file())
        with self.assertRaisesRegex(dc.DecisionError, "duplicate accepted decision"):
            dc.capture(self.root, event_path)

    @unittest.skipUnless(shutil.which("openspec"), "OpenSpec CLI not installed")
    def test_non_behavior_decision_uses_skip_specs(self):
        event = self.event()
        event["title"] = "Adopt decision capture governance"
        event["summary"] = "Accepted governance automation does not alter product behavior."
        event["rationale"] = "Governance tooling must remain separate from the product contract."
        event["behavior_change"] = False
        event["capabilities"] = []
        result = dc.capture(self.root, self.write_event(event, "governance.json"))
        change = Path(result["change_path"])
        metadata = (change / ".openspec.yaml").read_text(encoding="utf-8")
        self.assertIn("skip_specs: true", metadata)
        self.assertFalse((change / "specs").exists())


if __name__ == "__main__":
    unittest.main()
