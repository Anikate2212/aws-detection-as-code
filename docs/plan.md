# Build plan

## Definition of done (from the project brief)

- [ ] At least 6 techniques simulated, each with a detection, an ATT&CK ID, expected log evidence, and a test that proves the detection fires. 5 simulated live with Stratus; the EC2 credential theft technique was proven with a GuardDuty sample finding only (live run skipped to avoid NAT gateway cost) and stays `draft`.
- [x] Detections stored as code (Terraform and rule files), with false-positive notes
- [x] Python Lambda that contains an incident (backdoor key, bucket policy)
- [x] README that walks one full incident from simulation to detection to containment
- [x] Threat model and a short architecture diagram ([threat-model.md](threat-model.md), README)
- [x] fmt, validate, Checkov, gitleaks passing in GitHub Actions
- [x] Budget alert confirmed active before any simulation; `terraform destroy` documented

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

## Techniques (final)

The original candidate list had `iam-create-admin-user` (T1136.003); it was
moved to the bench and Secrets Manager mass read (T1555.006) took its place.
See the README detections table for the final six.

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
