# Detection-as-Code on AWS

![ci](https://github.com/Anikate2212/aws-detection-as-code/actions/workflows/ci.yml/badge.svg)

Simulated attacker techniques in my own AWS account, detections written as code from CloudTrail and GuardDuty, each mapped to MITRE ATT&CK, and a Python Lambda that contains the incident.

**Status:** In progress. Build plan and definition of done: [docs/plan.md](docs/plan.md)

Builds on [cloud-security-baseline](https://github.com/Anikate2212/cloud-security-baseline), which provides CloudTrail, GuardDuty, alerting and the budget.

## Problem

_TBD_

## Architecture

```
API call ─► CloudTrail ─► EventBridge ─► detection rule ─┐
GuardDuty finding ──────► EventBridge ─► detection rule ─┼─► response Lambda ─► SNS
                                                         └─► contain (e.g. disable key)
```

## Detections

| ID | ATT&CK | Source | Status |
|---|---|---|---|
| [cloudtrail-stop-logging](detections/cloudtrail-stop-logging.yml) | T1562.008 | CloudTrail | draft |

Rule file schema: [detections/README.md](detections/README.md)

## Threat model

_TBD_

## Incident walkthrough

_TBD: one incident from simulation to detection to containment, with real output._

## Design decisions and trade-offs

_TBD_

## Deploy and destroy

_TBD_

## Test evidence

_TBD_

## Lessons learned

_TBD_

## Repository layout

```
detections/               # one YAML rule per detection (source of truth)
terraform/
├── main.tf               # wires modules together
└── modules/detections/   # YAML -> EventBridge rules
tests/                    # rule schema tests (CI), live fire tests (later)
docs/                     # plan, threat model, evidence
.github/workflows/ci.yml  # fmt, validate, checkov, gitleaks, tests
.pre-commit-config.yaml   # terraform fmt on commit, gitleaks on push
.gitleaks.toml            # default rules + AWS account ID rule
```

## Local setup

```bash
pip install pre-commit -r requirements-dev.txt
pre-commit install          # installs pre-commit and pre-push hooks
pytest tests                # rule schema checks
```

## License

MIT
