"""Schema checks for detections/*.yml.

These run in CI with no AWS access. They prove each rule file is complete
and well-formed. Proof that a rule FIRES comes from the live simulation
tests (added per detection as each technique is simulated).
"""

import re
from pathlib import Path

import pytest
import yaml

DETECTIONS_DIR = Path(__file__).resolve().parent.parent / "detections"
RULE_FILES = sorted(DETECTIONS_DIR.glob("*.yml"))

REQUIRED_TOP = {
    "id", "title", "status", "severity", "attack", "simulation",
    "log_source", "expected_evidence", "false_positives", "response",
}
# Each rule is EITHER a single-event EventBridge rule (event_pattern) OR a
# count rule on the trail's log group (metric_filter), never both.
KINDS = {"event_pattern", "metric_filter"}
ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
SOURCE_FOR_LOG = {"cloudtrail": None, "guardduty": "aws.guardduty"}


def load(path):
    return yaml.safe_load(path.read_text())


def test_at_least_one_rule():
    assert RULE_FILES, "no detection files found"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_schema(path):
    rule = load(path)

    missing = REQUIRED_TOP - rule.keys()
    assert not missing, f"missing fields: {sorted(missing)}"

    assert rule["id"] == path.stem, "id must match the file name"
    assert re.fullmatch(r"[a-z0-9-]+", rule["id"])
    assert rule["status"] in {"draft", "tested"}
    assert rule["severity"] in {"low", "medium", "high", "critical"}
    assert rule["response"] in {"notify", "contain"}

    attack = rule["attack"]
    assert ATTACK_ID.match(attack["technique_id"]), attack["technique_id"]
    assert attack["tactic"] and attack["technique"]

    assert rule["simulation"]["tool"] and rule["simulation"]["technique"]

    assert rule["log_source"] in SOURCE_FOR_LOG
    assert rule["expected_evidence"].strip()
    assert isinstance(rule["false_positives"], list) and rule["false_positives"]

    kinds = KINDS & rule.keys()
    assert len(kinds) == 1, f"need exactly one of {sorted(KINDS)}, found {sorted(kinds)}"
    if "metric_filter" in rule:
        mf = rule["metric_filter"]
        assert rule["log_source"] == "cloudtrail", "metric filters run on the CloudTrail log group"
        assert rule["response"] == "notify", "alarms publish to SNS; they cannot drive containment"
        assert isinstance(mf["match"], dict) and mf["match"]
        assert all(re.fullmatch(r"[A-Za-z.]+", k) for k in mf["match"])
        assert int(mf["threshold"]) >= 1
        assert int(mf["period_seconds"]) in {60, 300, 900, 3600}


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_event_pattern_matches_log_source(path):
    rule = load(path)
    if "event_pattern" not in rule:
        pytest.skip("count rule (metric_filter)")
    pattern = rule["event_pattern"]

    assert "source" in pattern and "detail-type" in pattern
    if rule["log_source"] == "cloudtrail":
        assert pattern["detail-type"] == ["AWS API Call via CloudTrail"]
    else:
        assert pattern["source"] == ["aws.guardduty"]
        assert pattern["detail-type"] == ["GuardDuty Finding"]


def test_ids_unique():
    ids = [load(p)["id"] for p in RULE_FILES]
    assert len(ids) == len(set(ids))
