"""Triage Lambda: turn a matched detection into a readable alert.

Invoked by EventBridge. Each detection rule's target uses an input
transformer, so the payload is always:

    {"detection": {id, title, severity, technique_id, technique, response},
     "event":     <the full EventBridge event that matched the rule>}

The Lambda:
  1. pulls the who / what / where / when out of the event,
  2. writes one structured JSON log line (the audit record),
  3. publishes a short plain-text alert to the baseline SNS topic.

For detections with response: contain, a containment function runs first
and its outcome is included in the log line and the alert. Containment is
always reversible, and a failure to contain never suppresses the alert.
Standard library plus boto3 (bundled in the Lambda runtime).
"""

import json
import logging
import os

log = logging.getLogger()
log.setLevel(logging.INFO)

_sns = None  # created on first use; tests replace them with fakes
_iam = None


def _sns_client():
    global _sns
    if _sns is None:
        import boto3  # imported lazily so unit tests run without boto3

        _sns = boto3.client("sns")
    return _sns


def _iam_client():
    global _iam
    if _iam is None:
        import boto3

        _iam = boto3.client("iam")
    return _iam


def _protected_users() -> set:
    return {u.strip() for u in os.environ.get("PROTECTED_USERS", "").split(",") if u.strip()}


# ---- Containment ---------------------------------------------------------
def contain_backdoor_access_key(event: dict) -> dict:
    """T1098.001: disable an access key that someone created for another user.

    Self-service keys and protected admins are left alone (alert only).
    Setting the key Inactive is reversible and keeps it for forensics.
    """
    detail = event.get("detail", {}) or {}
    target = (detail.get("requestParameters") or {}).get("userName")
    key = ((detail.get("responseElements") or {}).get("accessKey") or {})
    key_id = key.get("accessKeyId")
    owner = target or key.get("userName")
    identity = detail.get("userIdentity", {}) or {}
    caller = identity.get("userName") if identity.get("type") == "IAMUser" else None

    if not target or not key_id:
        return {"action": "none", "reason": "self-service key (no target user in request)"}
    if caller and caller == target:
        return {"action": "none", "reason": "caller created a key for itself"}
    if target in _protected_users():
        return {"action": "none", "reason": f"{target} is a protected admin; investigate manually"}

    try:
        _iam_client().update_access_key(UserName=owner, AccessKeyId=key_id, Status="Inactive")
    except Exception as exc:  # report, never swallow the alert
        return {"action": "failed", "user": owner, "access_key_id": key_id, "error": repr(exc)}

    return {
        "action": "disabled_access_key",
        "user": owner,
        "access_key_id": key_id,
        "undo": f"aws iam update-access-key --user-name {owner} --access-key-id {key_id} --status Active",
    }


CONTAINMENT = {
    "iam-backdoor-access-key": contain_backdoor_access_key,
}


def summarize(detection: dict, event: dict) -> dict:
    """Extract the fields a responder needs from a CloudTrail or GuardDuty event."""
    detail = event.get("detail", {}) or {}
    finding = {
        "detection_id": detection.get("id"),
        "title": detection.get("title"),
        "severity": detection.get("severity"),
        "attack": f'{detection.get("technique_id")} {detection.get("technique")}',
        "response": detection.get("response"),
        "account": event.get("account"),
        "region": event.get("region"),
        "time": event.get("time"),
        "source": event.get("source"),
    }

    if event.get("source") == "aws.guardduty":
        finding.update(
            {
                "finding_type": detail.get("type"),
                "finding_title": detail.get("title"),
                "guardduty_severity": detail.get("severity"),
                "resource": detail.get("resource"),
                "finding_id": detail.get("id"),
            }
        )
    else:
        identity = detail.get("userIdentity", {}) or {}
        finding.update(
            {
                "event_name": detail.get("eventName"),
                "event_source": detail.get("eventSource"),
                "actor_arn": identity.get("arn"),
                "actor_type": identity.get("type"),
                "access_key_id": identity.get("accessKeyId"),
                "source_ip": detail.get("sourceIPAddress"),
                "user_agent": detail.get("userAgent"),
                "request_parameters": detail.get("requestParameters"),
                "error_code": detail.get("errorCode"),
                "event_id": detail.get("eventID"),
            }
        )
    return finding


def subject_for(finding: dict) -> str:
    """SNS email subjects: ASCII, no newlines, at most 100 characters."""
    technique_id = str(finding.get("attack", "")).split(" ")[0]
    action = (finding.get("containment") or {}).get("action")
    tag = {"disabled_access_key": "[CONTAINED] ", "failed": "[CONTAIN FAILED] "}.get(action, "")
    text = f'[{str(finding.get("severity", "")).upper()}] {tag}{technique_id} {finding.get("title")}'
    text = text.encode("ascii", "replace").decode().replace("\n", " ")
    return text[:100]


def message_for(finding: dict) -> str:
    lines = [f'{k}: {json.dumps(v) if isinstance(v, (dict, list)) else v}'
             for k, v in finding.items() if v not in (None, "", {}, [])]
    return "\n".join(lines)


def handler(payload, context):
    detection = payload["detection"]
    event = payload["event"]

    finding = summarize(detection, event)

    if detection.get("response") == "contain" and detection.get("id") in CONTAINMENT:
        finding["containment"] = CONTAINMENT[detection["id"]](event)

    # One JSON line per detection: searchable in CloudWatch Logs Insights.
    log.info(json.dumps({"finding": finding}, default=str))
    # The exact event EventBridge delivered. Evidence for the responder, and
    # the source for test fixtures of events that lookup-events never shows
    # (GuardDuty findings). The log group is KMS-encrypted, 1-year retention.
    log.info(json.dumps({"detection_id": detection.get("id"), "raw_event": event}, default=str))

    _sns_client().publish(
        TopicArn=os.environ["TOPIC_ARN"],
        Subject=subject_for(finding),
        Message=message_for(finding),
    )
    return {
        "detection_id": finding["detection_id"],
        "published": True,
        "containment": (finding.get("containment") or {}).get("action"),
    }
