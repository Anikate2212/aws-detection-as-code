#!/usr/bin/env python3
"""Turn a real CloudTrail event into a redacted EventBridge test fixture.

Usage (CloudTrail API events, from the CloudTrail lookup index):
  aws cloudtrail lookup-events ... --max-results 1 --output json \
    | python3 -I tools/make_fixture.py --account "<12-digit account ID>" \
    > tests/events/<detection-id>.json

Usage (any event the triage Lambda received, e.g. GuardDuty findings,
which never appear in lookup-events):
  aws logs filter-log-events --log-group-name /aws/lambda/detection-as-code-triage \
      --filter-pattern '"raw_event"' --output json \
    | python3 -I tools/make_fixture.py --account "<id>" --from-lambda-log <detection-id> \
    > tests/events/<detection-id>.json

Why: the "fires" test replays a REAL event that the simulation produced,
not a hand-written one, so the fixture proves the pattern matches what
AWS actually emits. Redaction runs before anything touches the repo:
  - the account ID (exact match, plus any other 12-digit number)
  - access key IDs (AKIA/ASIA) and IAM unique IDs (AIDA/AROA)
  - every public IPv4 address (replaced with a TEST-NET-3 documentation IP)
  - GuardDuty geolocation of the caller (city, country, ISP, coordinates)

Lookup-events returns the raw CloudTrail record. EventBridge wraps that
record in an envelope (source, detail-type, account, region, detail), and
the rule pattern is evaluated against the envelope, so this script builds
the envelope the same way.

Standard library only (pip is blocked on the build VM).
"""

import argparse
import json
import re
import sys

FAKE_ACCOUNT = "123456789012"  # allowlisted in .gitleaks.toml
FAKE_IP = "203.0.113.10"  # RFC 5737 documentation range

SUBS = [
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), r"\1EXAMPLEEXAMPLE00"),
    (re.compile(r"\b(AIDA|AROA)[A-Z0-9]{12,}\b"), r"\1EXAMPLEEXAMPLE00"),
    (re.compile(r"\b\d{12}\b"), FAKE_ACCOUNT),
]


IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRIVATE = re.compile(r"^(10\.|192\.168\.|169\.254\.|127\.|172\.(1[6-9]|2\d|3[01])\.)")
GEO_KEYS = {"city", "country", "geoLocation", "organization"}


def redact(text: str, account: str) -> str:
    text = text.replace(account, FAKE_ACCOUNT)
    for pattern, repl in SUBS:
        text = pattern.sub(repl, text)
    text = IPV4.sub(lambda m: m.group(0) if PRIVATE.match(m.group(0)) else FAKE_IP, text)
    return text


def strip_geo(node):
    """GuardDuty remoteIpDetails locate the caller (here: the operator's home)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "remoteIpDetails" and isinstance(value, dict):
                for geo in GEO_KEYS & value.keys():
                    value[geo] = "REDACTED"
            else:
                strip_geo(value)
    elif isinstance(node, list):
        for item in node:
            strip_geo(item)
    return node


def from_lambda_log(data: dict, detection_id: str):
    """Newest raw_event line the triage Lambda logged for this detection."""
    for ev in reversed(data.get("events", [])):
        msg = ev.get("message", "")
        start = msg.find("{")
        if start < 0 or '"raw_event"' not in msg:
            continue
        line = json.loads(msg[start:])
        if line.get("detection_id") == detection_id:
            return line["raw_event"]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--account", required=True, help="real account ID to redact")
    parser.add_argument("--from-lambda-log", metavar="DETECTION_ID",
                        help="read filter-log-events output from the triage Lambda instead of lookup-events")
    args = parser.parse_args()

    if not re.fullmatch(r"\d{12}", args.account):
        print("error: --account must be a 12-digit account ID", file=sys.stderr)
        return 1

    data = json.load(sys.stdin)

    if args.from_lambda_log:
        envelope = from_lambda_log(data, args.from_lambda_log)
        if envelope is None:
            print(f"error: no raw_event for {args.from_lambda_log} in the log output", file=sys.stderr)
            return 1
        return emit(strip_geo(envelope), args.account)

    events = data.get("Events", [])
    if not events:
        print("error: lookup-events returned no events (try again in a few minutes)", file=sys.stderr)
        return 1

    record = json.loads(events[0]["CloudTrailEvent"])

    ip = record.get("sourceIPAddress", "")
    if re.fullmatch(r"[0-9a-fA-F.:]+", ip):
        record["sourceIPAddress"] = FAKE_IP

    envelope = {
        "version": "0",
        "id": record.get("eventID", "00000000-0000-0000-0000-000000000000"),
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws." + record["eventSource"].split(".")[0],
        "account": record.get("recipientAccountId", args.account),
        "time": record["eventTime"],
        "region": record["awsRegion"],
        "resources": [],
        "detail": record,
    }
    return emit(envelope, args.account)


def emit(envelope: dict, account: str) -> int:
    out = redact(json.dumps(envelope, indent=2, sort_keys=True), account)

    # Fail closed: never print anything that still holds the real ID.
    if account in out:
        print("error: account ID survived redaction, refusing to write", file=sys.stderr)
        return 1

    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
