# Threat Model

## Assets

- Flow metadata from monitored network segments.
- Detection model and baseline state.
- Decision policies and thresholds.
- Enforcement action history.
- Tamper-evident audit chain.

## Threats

- Evasion through low-and-slow scans that stay below static thresholds.
- False positives during backup windows or patch rollouts.
- Agent failure or network partition that hides affected segments.
- Unauthorized containment API calls.
- Audit log tampering after an incident.

## Controls

- Combine statistical rules and ML anomaly score instead of relying on one detector.
- Keep medium-confidence alerts in analyst review.
- Log every detection, decision, and enforcement action into a hash chain.
- Default to simulated enforcement for demos.
- Make fail-open or fail-closed behavior a policy setting.

