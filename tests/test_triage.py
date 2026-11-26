"""Unit tests for the triage Lambda (src/triage/handler.py).

They replay each captured fixture through the handler exactly as the
EventBridge input transformer delivers it, with a fake SNS client, so they
run in CI without AWS credentials or boto3.
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "triage"))

import handler  # noqa: E402

FIXTURES = sorted((ROOT / "tests" / "events").glob("*.json"))


class FakeSNS:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)
        return {"MessageId": "test"}


def payload_for(path):
    """Build the payload the input transformer sends: rule metadata + event."""
    rule = yaml.safe_load((ROOT / "detections" / f"{path.stem}.yml").read_text())
    detection = {
        "id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "technique_id": rule["attack"]["technique_id"],
        "technique": rule["attack"]["technique"],
        "response": rule["response"],
    }
    return {"detection": detection, "event": json.loads(path.read_text())}


@pytest.fixture
def sns(monkeypatch):
    fake = FakeSNS()
    monkeypatch.setattr(handler, "_sns", fake)
    monkeypatch.setenv("TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test-topic")
    return fake


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_publishes_one_alert_per_event(path, sns):
    result = handler.handler(payload_for(path), None)

    assert result == {"detection_id": path.stem, "published": True}
    assert len(sns.published) == 1
    msg = sns.published[0]
    assert msg["TopicArn"].endswith(":test-topic")
    assert len(msg["Subject"]) <= 100
    assert msg["Subject"].isascii() and "\n" not in msg["Subject"]


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_alert_names_the_attack_and_the_actor(path, sns):
    payload = payload_for(path)
    handler.handler(payload, None)
    body = sns.published[0]["Message"]

    assert payload["detection"]["technique_id"] in sns.published[0]["Subject"]
    detail = payload["event"]["detail"]
    if payload["event"]["source"] != "aws.guardduty":
        assert detail["eventName"] in body
        assert detail["userIdentity"]["arn"] in body
        assert detail["sourceIPAddress"] in body


def test_subject_is_truncated_and_ascii():
    finding = {"severity": "high", "attack": "T0000 x", "title": "é" * 200}
    subject = handler.subject_for(finding)
    assert len(subject) <= 100 and subject.isascii()


def test_missing_fields_do_not_crash(sns):
    payload = {"detection": {"id": "x"}, "event": {"source": "aws.iam", "detail": {}}}
    assert handler.handler(payload, None)["published"] is True
