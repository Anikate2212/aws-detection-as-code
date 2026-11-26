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
import re

log = logging.getLogger()
log.setLevel(logging.INFO)

_sns = None  # created on first use; tests replace them with fakes
_iam = None
_s3 = None


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


def _s3_client():
    global _s3
    if _s3 is None:
        import boto3

        _s3 = boto3.client("s3")
    return _s3


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


# ---- Containment: s3-bucket-policy-external-access -----------------------
DEMO_TAG = "detection-demo"
CONTAINED_TAG = "detection-as-code-contained"
DENY_SID = "DetectionAsCodeDenyOtherAccounts"


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def external_grants(policy: dict, own_account: str) -> tuple:
    """(public, accounts): does any Allow statement reach outside own_account?

    public: Principal "*" (or {"AWS": "*"}), or an Allow with NotPrincipal.
    accounts: other 12-digit account IDs named in AWS principals.
    Service principals (cloudfront.amazonaws.com, ...) are not accounts and
    are ignored. Conditions are not evaluated: a "*" grant narrowed by a
    condition still counts as public here, and Block Public Access, which
    does evaluate conditions, decides whether it really is.
    """
    public, accounts = False, set()
    for st in _as_list((policy or {}).get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        if "NotPrincipal" in st:
            public = True
        principal = st.get("Principal")
        if principal == "*":
            public = True
        elif isinstance(principal, dict):
            for p in _as_list(principal.get("AWS")):
                if p == "*":
                    public = True
                    continue
                m = re.search(r"(?<!\d)(\d{12})(?!\d)", str(p))
                if m and m.group(1) != own_account:
                    accounts.add(m.group(1))
    return public, accounts


def _deny_statement(bucket: str, own_account: str) -> dict:
    """Deny every principal outside this account that is not an AWS service.

    Both conditions must hold, so the bucket's own account and AWS service
    principals (log delivery, replication) keep working. Anonymous callers
    have no account, so this also blocks public access.
    """
    return {
        "Sid": DENY_SID,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        "Condition": {
            "StringNotEquals": {"aws:PrincipalAccount": own_account},
            "Bool": {"aws:PrincipalIsAWSService": "false"},
        },
    }


def _bucket_tags(s3, bucket: str) -> dict:
    try:
        tag_set = s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
    except Exception as exc:
        if "NoSuchTagSet" in repr(exc):
            return {}
        raise
    return {t["Key"]: t["Value"] for t in tag_set}


def contain_s3_bucket_policy(event: dict) -> dict:
    """T1537: cut off outside access granted by a new bucket policy.

    Acts only on buckets tagged detection-demo=true. Reversible: it adds one
    Sid-tagged Deny statement and/or turns on Block Public Access, and never
    deletes the bucket, objects or the attacker's statement (evidence).
    """
    detail = event.get("detail", {}) or {}
    params = detail.get("requestParameters") or {}
    bucket = params.get("bucketName")
    policy = params.get("bucketPolicy")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            policy = None
    own = event.get("account") or detail.get("recipientAccountId")

    if not bucket or not isinstance(policy, dict) or not own:
        return {"action": "none", "reason": "bucket name or policy missing from the event"}

    public, accounts = external_grants(policy, own)
    if not public and not accounts:
        return {"action": "none", "reason": "policy grants access only within this account"}

    done = []
    try:
        s3 = _s3_client()
        tags = _bucket_tags(s3, bucket)
        if tags.get(DEMO_TAG) != "true":
            return {"action": "none", "bucket": bucket, "external_accounts": sorted(accounts),
                    "public": public,
                    "reason": f"bucket not tagged {DEMO_TAG}=true; alert only, investigate manually"}

        if accounts:
            current = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
            statements = _as_list(current.get("Statement"))
            if not any(isinstance(st, dict) and st.get("Sid") == DENY_SID for st in statements):
                current["Statement"] = statements + [_deny_statement(bucket, own)]
                s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(current))
            done.append("deny_other_accounts")
        if public:
            # After the policy write: with BlockPublicPolicy on, S3 would
            # reject writing a policy that still holds a public statement.
            s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
            done.append("block_public_access")

        tags[CONTAINED_TAG] = str(event.get("time") or detail.get("eventTime") or "yes")
        s3.put_bucket_tagging(Bucket=bucket, Tagging={
            "TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]})
        done.append("tagged")
    except Exception as exc:  # report, never swallow the alert
        return {"action": "failed", "bucket": bucket, "steps_done": done, "error": repr(exc)}

    undo = []
    if "deny_other_accounts" in done:
        undo.append(f"remove the statement with Sid {DENY_SID} from the bucket policy "
                    f"(aws s3api get-bucket-policy --bucket {bucket}, edit, put-bucket-policy)")
    if "block_public_access" in done:
        undo.append(f"aws s3api delete-public-access-block --bucket {bucket}")
    return {
        "action": "contained_bucket_policy",
        "bucket": bucket,
        "external_accounts": sorted(accounts),
        "public": public,
        "steps_done": done,
        "undo": "; ".join(undo),
    }


CONTAINMENT = {
    "iam-backdoor-access-key": contain_backdoor_access_key,
    "s3-bucket-policy-external-access": contain_s3_bucket_policy,
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
    tag = {None: "", "none": "", "failed": "[CONTAIN FAILED] "}.get(action, "[CONTAINED] ")
    text = f'[{str(finding.get("severity", "")).upper()}] {tag}{technique_id} {finding.get("title")}'
    text = text.encode("ascii", "replace").decode().replace("\n", " ")
    return text[:100]


def message_for(finding: dict) -> str:
    lines = [f'{k}: {json.dumps(v) if isinstance(v, (dict, list)) else v}'
             for k, v in finding.items() if v not in (None, "", {}, [])]
    return "\n".join(lines)


def is_own_write(event: dict) -> bool:
    """True when this function's own containment call caused the event.

    Containment that writes a bucket policy emits a new PutBucketPolicy
    event, which matches the rule again. Lambda sessions are named after the
    function, so the caller ARN ends in assumed-role/<role>/<function name>.
    """
    name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    arn = str(((event.get("detail") or {}).get("userIdentity") or {}).get("arn") or "")
    return bool(name) and ":assumed-role/" in arn and arn.endswith(f"/{name}")


def handler(payload, context):
    detection = payload["detection"]
    event = payload["event"]

    if is_own_write(event):
        log.info(json.dumps({"detection_id": detection.get("id"), "skipped": "own containment write",
                             "event_id": (event.get("detail") or {}).get("eventID")}))
        return {"detection_id": detection.get("id"), "published": False, "containment": "none"}

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
