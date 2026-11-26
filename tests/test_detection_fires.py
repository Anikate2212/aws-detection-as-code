"""Replay tests: each rule's pattern must match its captured event.

tests/events/<id>.json is a REAL event captured after the Stratus
simulation (redacted with tools/make_fixture.py). These tests run in CI
with no AWS access, so they use a small local matcher that implements the
subset of EventBridge pattern syntax our rules use: nested objects, lists
of exact values, and {"exists": true|false}. Any other operator (prefix,
anything-but, numeric, wildcard) fails the test loudly instead of guessing.

The authoritative check is `aws events test-event-pattern` against the
DEPLOYED rule (see README, "Testing"). The local matcher keeps that
guarantee on every push.
"""

import copy
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = ROOT / "detections"
EVENTS_DIR = ROOT / "tests" / "events"

RULES = {p.stem: yaml.safe_load(p.read_text()) for p in sorted(DETECTIONS_DIR.glob("*.yml"))}
FIXTURES = sorted(EVENTS_DIR.glob("*.json"))


def matches(pattern, event) -> bool:
    """EventBridge semantics for exact-value patterns.

    Every key in the pattern must be present in the event. A list in the
    pattern means "the event value equals any of these" (or, if the event
    value is itself a list, any element does).
    [{"exists": false}] means the key must be absent; [{"exists": true}]
    means it must be present.
    """
    for key, want in pattern.items():
        if isinstance(want, list) and any(isinstance(v, dict) and "exists" in v for v in want):
            if len(want) != 1:
                raise NotImplementedError(f"exists combined with other values on {key!r}")
            if (key in event) != bool(want[0]["exists"]):
                return False
            continue
        if key not in event:
            return False
        have = event[key]
        if isinstance(want, dict):
            if not isinstance(have, dict) or not matches(want, have):
                return False
        elif isinstance(want, list):
            for v in want:
                if isinstance(v, dict):
                    raise NotImplementedError(f"unsupported pattern operator {v} on {key!r}")
            values = have if isinstance(have, list) else [have]
            if not any(v in want for v in values):
                return False
        else:
            raise ValueError(f"pattern value for {key!r} must be a list or object")
    return True


@pytest.mark.parametrize("rule_id", [r for r, v in RULES.items() if v["status"] == "tested"])
def test_tested_rules_have_a_fixture(rule_id):
    assert (EVENTS_DIR / f"{rule_id}.json").exists(), (
        "status: tested requires a captured event in tests/events/"
    )


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_rule_fires_on_captured_event(path):
    assert path.stem in RULES, f"fixture {path.name} has no matching rule file"
    event = json.loads(path.read_text())
    assert matches(RULES[path.stem]["event_pattern"], event)


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_rule_ignores_benign_variant(path):
    """Same event with a different eventName must NOT match.

    Catches an over-broad pattern (for example one that dropped eventName
    and fires on every CloudTrail API call).
    """
    event = json.loads(path.read_text())
    benign = copy.deepcopy(event)
    benign["detail"]["eventName"] = "DescribeTrails"
    assert not matches(RULES[path.stem]["event_pattern"], benign)


def test_no_real_account_id_in_fixtures():
    for path in FIXTURES:
        event = json.loads(path.read_text())
        assert event["account"] == "123456789012", f"{path.name} is not redacted"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_rule_ignores_failed_call_when_pattern_excludes_errors(path):
    """A denied attempt (errorCode set) must not trigger containment rules."""
    pattern = RULES[path.stem]["event_pattern"]
    if pattern.get("detail", {}).get("errorCode") != [{"exists": False}]:
        pytest.skip("rule does not exclude failed calls")
    event = json.loads(path.read_text())
    failed = copy.deepcopy(event)
    failed["detail"]["errorCode"] = "AccessDenied"
    assert not matches(pattern, failed)


def test_exists_operator_semantics():
    assert matches({"a": [{"exists": False}]}, {})
    assert not matches({"a": [{"exists": False}]}, {"a": 1})
    assert matches({"a": [{"exists": True}]}, {"a": 1})
    assert not matches({"a": [{"exists": True}]}, {})
