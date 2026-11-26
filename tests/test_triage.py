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


class FakeIAM:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def update_access_key(self, **kwargs):
        if self.fail:
            raise RuntimeError("AccessDenied")
        self.calls.append(kwargs)


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


@pytest.fixture(autouse=True)
def no_aws(monkeypatch):
    """No test may reach real AWS: containment clients default to fakes.

    Fixture replays run containment for contain rules; an untagged fake
    bucket and a recording fake IAM keep that offline. Tests that need
    other behaviour replace these.
    """
    monkeypatch.setattr(handler, "_iam", FakeIAM())
    monkeypatch.setattr(handler, "_s3", FakeS3(tags=None))


@pytest.fixture
def sns(monkeypatch):
    fake = FakeSNS()
    monkeypatch.setattr(handler, "_sns", fake)
    monkeypatch.setenv("TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test-topic")
    return fake


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_publishes_one_alert_per_event(path, sns):
    result = handler.handler(payload_for(path), None)

    assert result["detection_id"] == path.stem and result["published"] is True
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


# ---- Containment: iam-backdoor-access-key ---------------------------------
BACKDOOR = {"id": "iam-backdoor-access-key", "title": "t", "severity": "high",
            "technique_id": "T1098.001", "technique": "x", "response": "contain"}


def create_key_event(caller="anikate-cli", target="victim", key_id="AKIAIOSFODNN7EXAMPLE"):
    detail = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "userIdentity": {"type": "IAMUser", "userName": caller,
                         "arn": f"arn:aws:iam::123456789012:user/{caller}"},
        "sourceIPAddress": "203.0.113.10",
        "requestParameters": {"userName": target} if target else None,
        "responseElements": {"accessKey": {"userName": target or caller,
                                           "accessKeyId": key_id, "status": "Active"}},
    }
    return {"source": "aws.iam", "account": "123456789012", "region": "us-east-1", "detail": detail}


@pytest.fixture
def iam(monkeypatch):
    fake = FakeIAM()
    monkeypatch.setattr(handler, "_iam", fake)
    monkeypatch.setenv("PROTECTED_USERS", "anikate-cli,breakglass")
    return fake


def test_disables_key_created_for_another_user(sns, iam):
    result = handler.handler({"detection": BACKDOOR, "event": create_key_event()}, None)
    assert result["containment"] == "disabled_access_key"
    assert iam.calls == [{"UserName": "victim", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Status": "Inactive"}]
    assert "[CONTAINED]" in sns.published[0]["Subject"]
    assert "--status Active" in sns.published[0]["Message"]  # undo command is in the alert


@pytest.mark.parametrize("caller,target", [("bob", "bob"), ("bob", None)])
def test_self_service_key_is_alert_only(sns, iam, caller, target):
    result = handler.handler({"detection": BACKDOOR, "event": create_key_event(caller, target)}, None)
    assert result["containment"] == "none" and iam.calls == []
    assert len(sns.published) == 1


def test_protected_admin_is_never_touched(sns, iam):
    result = handler.handler({"detection": BACKDOOR, "event": create_key_event("attacker", "anikate-cli")}, None)
    assert result["containment"] == "none" and iam.calls == []


def test_failed_containment_still_alerts(sns, monkeypatch):
    monkeypatch.setattr(handler, "_iam", FakeIAM(fail=True))
    result = handler.handler({"detection": BACKDOOR, "event": create_key_event()}, None)
    assert result["containment"] == "failed"
    assert "[CONTAIN FAILED]" in sns.published[0]["Subject"]


def test_notify_rules_never_contain(sns, iam):
    notify = dict(BACKDOOR, response="notify")
    handler.handler({"detection": notify, "event": create_key_event()}, None)
    assert iam.calls == []


# ---- Containment: s3-bucket-policy-external-access ------------------------
S3_RULE = {"id": "s3-bucket-policy-external-access", "title": "t", "severity": "high",
           "technique_id": "T1537", "technique": "x", "response": "contain"}
OWN, OTHER = "123456789012", "111122223333"


class NoSuchTagSet(Exception):
    pass


class FakeS3:
    def __init__(self, tags=None, policy=None, fail=False):
        self.tags = tags
        self.policy = policy
        self.fail = fail
        self.calls = []

    def get_bucket_tagging(self, Bucket):
        if self.tags is None:
            raise NoSuchTagSet("NoSuchTagSet")
        return {"TagSet": [{"Key": k, "Value": v} for k, v in self.tags.items()]}

    def get_bucket_policy(self, Bucket):
        return {"Policy": json.dumps(self.policy)}

    def put_bucket_policy(self, **kwargs):
        if self.fail:
            raise RuntimeError("AccessDenied")
        self.calls.append(("put_bucket_policy", kwargs))
        self.policy = json.loads(kwargs["Policy"])

    def put_public_access_block(self, **kwargs):
        self.calls.append(("put_public_access_block", kwargs))

    def put_bucket_tagging(self, **kwargs):
        self.calls.append(("put_bucket_tagging", kwargs))


def bucket_policy(principal):
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": principal, "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::demo/*"]}]}


def put_policy_event(policy, caller_arn=f"arn:aws:iam::{OWN}:user/attacker"):
    return {"source": "aws.s3", "account": OWN, "region": "us-east-1", "time": "2026-11-26T18:00:00Z",
            "detail": {"eventSource": "s3.amazonaws.com", "eventName": "PutBucketPolicy",
                       "userIdentity": {"type": "IAMUser", "arn": caller_arn},
                       "sourceIPAddress": "203.0.113.10",
                       "requestParameters": {"bucketName": "demo", "bucketPolicy": policy}}}


def run_s3(monkeypatch, sns, fake, policy, **kw):
    monkeypatch.setattr(handler, "_s3", fake)
    return handler.handler({"detection": S3_RULE, "event": put_policy_event(policy, **kw)}, None)


def test_external_account_on_demo_bucket_gets_sid_deny(monkeypatch, sns):
    policy = bucket_policy({"AWS": f"arn:aws:iam::{OTHER}:root"})
    fake = FakeS3(tags={"detection-demo": "true"}, policy=policy)
    result = run_s3(monkeypatch, sns, fake, policy)

    assert result["containment"] == "contained_bucket_policy"
    statements = fake.policy["Statement"]
    assert statements[0] == policy["Statement"][0]  # attacker statement kept as evidence
    deny = statements[-1]
    assert deny["Sid"] == handler.DENY_SID and deny["Effect"] == "Deny"
    assert deny["Condition"]["StringNotEquals"]["aws:PrincipalAccount"] == OWN
    assert [c[0] for c in fake.calls] == ["put_bucket_policy", "put_bucket_tagging"]
    assert "[CONTAINED]" in sns.published[0]["Subject"]


def test_public_policy_on_demo_bucket_gets_block_public_access(monkeypatch, sns):
    policy = bucket_policy("*")
    fake = FakeS3(tags={"detection-demo": "true"}, policy=policy)
    result = run_s3(monkeypatch, sns, fake, policy)

    assert result["containment"] == "contained_bucket_policy"
    names = [c[0] for c in fake.calls]
    assert "put_public_access_block" in names and "put_bucket_policy" not in names
    assert "delete-public-access-block" in sns.published[0]["Message"]  # undo is in the alert


def test_untagged_bucket_is_alert_only(monkeypatch, sns):
    policy = bucket_policy({"AWS": f"arn:aws:iam::{OTHER}:root"})
    fake = FakeS3(tags=None, policy=policy)
    result = run_s3(monkeypatch, sns, fake, policy)
    assert result["containment"] == "none" and fake.calls == []
    assert OTHER in sns.published[0]["Message"]  # the alert still names the outside account


@pytest.mark.parametrize("principal", [
    {"AWS": f"arn:aws:iam::{OWN}:role/app"},
    {"AWS": OWN},
    {"Service": "cloudfront.amazonaws.com"},
])
def test_same_account_and_service_principals_are_not_external(monkeypatch, sns, principal):
    policy = bucket_policy(principal)
    fake = FakeS3(tags={"detection-demo": "true"}, policy=policy)
    result = run_s3(monkeypatch, sns, fake, policy)
    assert result["containment"] == "none" and fake.calls == []


def test_existing_deny_is_not_added_twice(monkeypatch, sns):
    policy = bucket_policy({"AWS": f"arn:aws:iam::{OTHER}:root"})
    current = {"Version": "2012-10-17",
               "Statement": policy["Statement"] + [handler._deny_statement("demo", OWN)]}
    fake = FakeS3(tags={"detection-demo": "true"}, policy=current)
    run_s3(monkeypatch, sns, fake, policy)
    assert [c[0] for c in fake.calls] == ["put_bucket_tagging"]


def test_own_containment_write_is_not_alerted(monkeypatch, sns):
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "detection-as-code-triage")
    policy = bucket_policy({"AWS": f"arn:aws:iam::{OTHER}:root"})
    fake = FakeS3(tags={"detection-demo": "true"}, policy=policy)
    own_arn = f"arn:aws:sts::{OWN}:assumed-role/detection-as-code-triage/detection-as-code-triage"
    result = run_s3(monkeypatch, sns, fake, policy, caller_arn=own_arn)
    assert result["published"] is False and sns.published == [] and fake.calls == []


def test_s3_containment_failure_still_alerts(monkeypatch, sns):
    policy = bucket_policy({"AWS": f"arn:aws:iam::{OTHER}:root"})
    fake = FakeS3(tags={"detection-demo": "true"}, policy=policy, fail=True)
    result = run_s3(monkeypatch, sns, fake, policy)
    assert result["containment"] == "failed"
    assert "[CONTAIN FAILED]" in sns.published[0]["Subject"]
