# Detection rule files

One YAML file per detection. Terraform turns each file into an EventBridge
rule (`terraform/modules/detections`). CI checks every file against the
schema below (`tests/test_detection_files.py`).

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Matches the file name. Lowercase, hyphens. Used in the rule name. |
| `title` | yes | One line, what the detection means. |
| `status` | yes | `draft` until the simulation has fired it in a real account, then `tested`. |
| `severity` | yes | `low`, `medium`, `high`, `critical` |
| `attack.tactic` | yes | MITRE ATT&CK tactic name |
| `attack.technique_id` | yes | ATT&CK ID, e.g. `T1562.008` |
| `attack.technique` | yes | ATT&CK technique name |
| `simulation.tool` | yes | e.g. `stratus-red-team` |
| `simulation.technique` | yes | Tool-specific technique ID |
| `log_source` | yes | `cloudtrail` or `guardduty` |
| `event_pattern` | yes | EventBridge event pattern, passed through unchanged |
| `expected_evidence` | yes | Which log fields prove the technique ran |
| `false_positives` | yes | At least one note on benign causes |
| `response` | yes | `notify` or `contain` |
