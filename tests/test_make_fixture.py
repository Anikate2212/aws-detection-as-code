"""Redaction tests for tools/make_fixture.py: nothing identifying reaches a fixture."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "make_fixture.py"
REAL = "987654321098"


def run(stdin: dict, *args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(TOOL), "--account", REAL, *args],
        input=json.dumps(stdin), capture_output=True, text=True,
    )


def test_lookup_events_record_is_wrapped_and_redacted():
    record = {
        "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey",
        "eventTime": "2026-01-01T00:00:00Z", "awsRegion": "us-east-1",
        "sourceIPAddress": "98.1.2.3", "recipientAccountId": REAL,
        "userIdentity": {"arn": f"arn:aws:iam::{REAL}:user/x", "accessKeyId": "AKIA" + "Q" * 16},
    }
    out = run({"Events": [{"CloudTrailEvent": json.dumps(record)}]})
    assert out.returncode == 0, out.stderr
    event = json.loads(out.stdout)
    assert event["source"] == "aws.iam" and event["detail-type"] == "AWS API Call via CloudTrail"
    assert REAL not in out.stdout and "98.1.2.3" not in out.stdout
    assert event["detail"]["userIdentity"]["accessKeyId"].endswith("EXAMPLEEXAMPLE00")


def test_guardduty_event_from_lambda_log_strips_ip_and_geolocation():
    raw = {
        "source": "aws.guardduty", "detail-type": "GuardDuty Finding", "account": REAL,
        "detail": {"type": "x", "service": {"action": {"awsApiCallAction": {"remoteIpDetails": {
            "ipAddressV4": "73.1.2.3", "city": {"cityName": "Home"},
            "organization": {"isp": "My ISP"}, "geoLocation": {"lat": 1, "lon": 2}}}}},
            "resource": {"instanceDetails": {"networkInterfaces": [{"privateIpAddress": "10.0.1.5"}]}}},
    }
    line = json.dumps({"detection_id": "d1", "raw_event": raw})
    logs = {"events": [{"message": f"[INFO]\t2026-01-01T00:00:00Z\treq\t{line}"}]}
    out = run(logs, "--from-lambda-log", "d1")
    assert out.returncode == 0, out.stderr
    for leaked in (REAL, "73.1.2.3", "Home", "My ISP"):
        assert leaked not in out.stdout
    assert "10.0.1.5" in out.stdout  # private VPC addresses are kept


def test_refuses_when_nothing_to_convert():
    assert run({"Events": []}).returncode == 1
    assert run({"events": []}, "--from-lambda-log", "d1").returncode == 1


def test_other_accounts_get_a_different_placeholder():
    """A backdoored policy names an outside account; it must stay distinguishable."""
    outside = "193672423079"
    record = {
        "eventSource": "s3.amazonaws.com", "eventName": "PutBucketPolicy",
        "eventTime": "2026-01-01T00:00:00Z", "awsRegion": "us-east-1",
        "sourceIPAddress": "98.1.2.3", "recipientAccountId": REAL,
        "requestParameters": {"bucketPolicy": {"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{outside}:root"}}]}},
    }
    out = run({"Events": [{"CloudTrailEvent": json.dumps(record)}]})
    assert out.returncode == 0, out.stderr
    event = json.loads(out.stdout)
    assert event["account"] == "123456789012"
    principal = event["detail"]["requestParameters"]["bucketPolicy"]["Statement"][0]["Principal"]["AWS"]
    assert principal == "arn:aws:iam::111122223333:root"
    assert outside not in out.stdout and REAL not in out.stdout
