"""Triage Lambda: turn a matched detection into a readable alert.

Invoked by EventBridge. Each detection rule's target uses an input
transformer, so the payload is always:

    {"detection": {id, title, severity, technique_id, technique, response},
     "event":     <the full EventBridge event that matched the rule>}

The Lambda:
  1. pulls the who / what / where / when out of the event,
  2. writes one structured JSON log line (the audit record),
  3. publishes a short plain-text alert to the baseline SNS topic.

Containment actions (response: contain) are added per detection later.
Standard library plus boto3 (bundled in the Lambda runtime).
"""

import json
import logging
import os

log = logging.getLogger()
log.setLevel(logging.INFO)

_sns = None  # created on first use; tests replace it with a fake


def _sns_client():
    global _sns
    if _sns is None:
        import boto3  # imported lazily so unit tests run without boto3

        _sns = boto3.client("sns")
    return _sns


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
    text = f'[{str(finding.get("severity", "")).upper()}] {technique_id} {finding.get("title")}'
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

    # One JSON line per detection: searchable in CloudWatch Logs Insights.
    log.info(json.dumps({"finding": finding}, default=str))

    _sns_client().publish(
        TopicArn=os.environ["TOPIC_ARN"],
        Subject=subject_for(finding),
        Message=message_for(finding),
    )
    return {"detection_id": finding["detection_id"], "published": True}
