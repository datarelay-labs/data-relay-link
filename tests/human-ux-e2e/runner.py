#!/usr/bin/env python3
"""Human UX Adversarial E2E runner."""
from __future__ import annotations

import argparse
import sys
import time
import traceback
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HUX_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(HUX_DIR))

# Make "human_ux_e2e" importable for docs/examples while keeping the on-disk
# directory name repository-native ("human-ux-e2e").
if "human_ux_e2e" not in sys.modules:
    pkg = types.ModuleType("human_ux_e2e")
    pkg.__path__ = [str(HUX_DIR)]  # type: ignore[attr-defined]
    sys.modules["human_ux_e2e"] = pkg

from framework.assertions import ScenarioFailure  # noqa: E402
from framework.report import render_summary, write_failure_transcript  # noqa: E402
from framework.scenario_api import ScenarioEnv, all_scenarios  # noqa: E402
from framework.types import ScenarioResult, ScenarioStatus  # noqa: E402
from framework.ux_review import prepare_review_artifact, try_run_llm_review  # noqa: E402

import scenarios as _scenarios_pkg  # noqa: E402,F401


def _match(spec, *, scenario_filter: str, domain_filter: str, layer_filter: str, tag_filter: str) -> bool:
    if scenario_filter:
        key = scenario_filter.lower()
        if key not in spec.scenario_id.lower() and key not in spec.title.lower():
            return False
    if domain_filter and domain_filter.lower() not in (spec.domain or "").lower():
        return False
    if layer_filter and layer_filter.lower() not in spec.layer.value.lower():
        return False
    if tag_filter and tag_filter not in spec.tags:
        return False
    return True


def run_one(spec, reports_dir: Path, verbose: bool) -> ScenarioResult:
    env = ScenarioEnv(spec=spec, reports_dir=reports_dir, verbose=verbose)
    started = time.time()
    result = ScenarioResult(
        scenario_id=spec.scenario_id,
        title=spec.title,
        status=ScenarioStatus.PASS,
        execution_context=spec.execution_context,
        interaction_mode=spec.interaction_mode,
        layer=spec.layer,
    )
    try:
        if verbose:
            print("RUN %s  [%s] %s" % (spec.scenario_id, spec.execution_context.value, spec.title))
        spec.fn(env)
        result.extracted = dict(env.extracted)
        result.transcript = env.recorder.render() if env.recorder else ""
    except ScenarioFailure as exc:
        result.status = ScenarioStatus.FAIL
        result.findings = [exc.finding]
        result.error = exc.finding.message
        result.transcript = env.recorder.render() if env.recorder else ""
        write_failure_transcript(reports_dir, result)
        if verbose:
            print("FAIL %s: %s" % (spec.scenario_id, exc.finding.message))
    except Exception as exc:
        result.status = ScenarioStatus.FAIL
        result.error = "%s: %s" % (type(exc).__name__, exc)
        result.transcript = (env.recorder.render() if env.recorder else "") + "\n" + traceback.format_exc()
        write_failure_transcript(reports_dir, result)
        if verbose:
            print("FAIL %s: %s" % (spec.scenario_id, result.error))
    finally:
        env.close()
        result.duration_s = time.time() - started
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Human UX Adversarial E2E")
    ap.add_argument("--scenario", default="", help="Filter by scenario ID or title substring")
    ap.add_argument("--domain", default="", help="Filter by domain (server, agent, wizard, ...)")
    ap.add_argument("--layer", default="", help="Filter by layer name substring")
    ap.add_argument("--tag", default="", help="Filter by tag")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose transcript mode")
    ap.add_argument("--list", action="store_true", help="List scenarios and exit")
    ap.add_argument("--llm-review", action="store_true", help="Attempt optional LLM UX review")
    args = ap.parse_args(argv)

    specs = sorted(all_scenarios(), key=lambda s: s.scenario_id)
    if args.list:
        for s in specs:
            print(
                "%s  %-14s %-22s %s"
                % (s.scenario_id, s.domain or "-", s.layer.value, s.title)
            )
        print("TOTAL %d" % len(specs))
        return 0

    selected = [
        s
        for s in specs
        if _match(
            s,
            scenario_filter=args.scenario,
            domain_filter=args.domain,
            layer_filter=args.layer,
            tag_filter=args.tag,
        )
    ]
    reports_dir = HUX_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    results = [run_one(s, reports_dir, args.verbose) for s in selected]
    print(render_summary(results))

    transcripts = [r.transcript for r in results if r.transcript]
    artifact = prepare_review_artifact(reports_dir, transcripts[:20])
    llm_status = "NOT_RUN"
    if args.llm_review:
        llm_status, findings = try_run_llm_review(artifact)
        if findings:
            (reports_dir / "UX_REVIEW_FINDINGS.txt").write_text(findings, encoding="utf-8")
    print("LLM_UX_REVIEW=%s" % llm_status)
    print("REVIEW_ARTIFACT=%s" % artifact)

    failed = sum(1 for r in results if r.status == ScenarioStatus.FAIL)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
