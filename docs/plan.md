# Build plan

## Definition of done (from the project brief)

- [ ] At least 6 techniques simulated, each with a detection, an ATT&CK ID, expected log evidence, and a test that proves the detection fires
- [ ] Detections stored as code (Terraform and rule files), with false-positive notes
- [ ] Python Lambda that contains an incident
- [ ] README that walks one full incident from simulation to detection to containment
- [ ] Threat model and a short architecture diagram
- [ ] fmt, validate, Checkov, gitleaks passing in GitHub Actions
- [ ] Budget alert confirmed active before any simulation; `terraform destroy` documented

## Dependency on cloud-security-baseline

This repo does not redeploy CloudTrail, GuardDuty, or the budget. It
assumes the baseline is applied in the same account and region:

| Needs | Comes from |
|---|---|
| CloudTrail management events in EventBridge | Baseline trail (EventBridge receives them in-region) |
| GuardDuty findings | Baseline detector (one per account per region, so it cannot be created twice) |
| Alert delivery | Baseline SNS topic, published to by this repo's response Lambda |
| Budget alert | Baseline bootstrap budget |
| Remote state | Baseline state bucket, separate key |

Interview point: the baseline topic is encrypted with a customer-managed
KMS key and its policy only allows CloudWatch alarms. Rather than editing
the baseline's topic and key policies, rules target a Lambda in this repo,
and that Lambda's role publishes to the topic.

## Candidate techniques (6 required)

Verify each ID with `stratus list` and the ATT&CK site before simulating.
Mappings below are a starting point, not checked yet.

| # | Stratus technique | ATT&CK | Source | Response |
|---|---|---|---|---|
| 1 | `aws.defense-evasion.cloudtrail-stop` | T1562.008 Disable or Modify Cloud Logs | CloudTrail | notify |
| 2 | `aws.persistence.iam-backdoor-user` | T1098.001 Additional Cloud Credentials | CloudTrail | **contain: disable the new access key** (README incident walkthrough) |
| 3 | `aws.persistence.iam-create-admin-user` | T1136.003 Create Cloud Account | CloudTrail | notify |
| 4 | `aws.exfiltration.s3-backdoor-bucket-policy` | T1537 Transfer Data to Cloud Account | CloudTrail | notify |
| 5 | `aws.credential-access.ec2-steal-instance-credentials` | T1552.005 Cloud Instance Metadata API | GuardDuty | contain (optional) |
| 6 | `aws.initial-access.console-login-without-mfa` | T1078.004 Valid Accounts: Cloud Accounts | CloudTrail | notify |

Spread: 5 tactics, CloudTrail and GuardDuty sources, one full containment path.
Cost watch: #5 runs an EC2 instance (free-tier size, destroy right after).

## Build order (about 10 days at 2 hours a day)

1. Repo scaffold, CI green (this step)
2. Confirm budget alert active; install Stratus Red Team; dry-run one technique
3. Detection 1 (cloudtrail-stop): deploy rule, simulate, capture evidence, write the fires test
4. Response Lambda (notify path) wired as the rule target, publishing to the baseline topic
5. Detection 2 + containment (disable access key) end to end
6. Detections 3 and 4
7. Detections 5 and 6
8. Threat model and architecture diagram
9. README incident walkthrough with real captured output
10. Clean destroy, final CI run, review against definition of done

## Open questions

- How "test proves it fires" is recorded: proposed `tests/live/` scripts that
  run the Stratus technique, then poll for the rule's invocation in
  CloudWatch metrics or the Lambda log, with redacted output saved to
  `docs/evidence/`.
