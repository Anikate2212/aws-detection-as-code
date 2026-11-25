#!/usr/bin/env python3
"""Turn a real CloudTrail event into a redacted EventBridge test fixture.

Usage:
  aws cloudtrail lookup-events ... --max-results 1 --output json \
    | python3 -I tools/make_fixture.py --account "<12-digit account ID>" \
    > tests/events/<detection-id>.json

Why: the "fires" test replays a REAL event that the simulation produced,
not a hand-written one, so the fixture proves the pattern matches what
AWS actually emits. Redaction runs before anything touches the repo:
  - the account ID (exact match, plus any other 12-digit number)
  - access key IDs (AKIA/ASIA) and IAM unique IDs (AIDA/AROA)
  - the caller's source IP (replaced with a TEST-NET-3 documentation IP)

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


def redact(text: str, account: str) -> str:
    text = text.replace(account, FAKE_ACCOUNT)
    for pattern, repl in SUBS:
        text = pattern.sub(repl, text)
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--account", required=True, help="real account ID to redact")
    args = parser.parse_args()

    if not re.fullmatch(r"\d{12}", args.account):
        print("error: --account must be a 12-digit account ID", file=sys.stderr)
        return 1

    events = json.load(sys.stdin).get("Events", [])
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

    out = redact(json.dumps(envelope, indent=2, sort_keys=True), args.account)

    # Fail closed: never print anything that still holds the real ID.
    if args.account in out:
        print("error: account ID survived redaction, refusing to write", file=sys.stderr)
        return 1

    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
