# Evidence Integrity & Limitations

This project deliberately separates what was **observed** from what was merely **expected**.

## Snapshot rollback

During the lab, a snapshot rollback removed part of the original Wazuh state. Some defensive telemetry therefore had to be revalidated in a later controlled session.

The repository preserves two evidence classes:

1. **Attack-emulation evidence** — RDP password guessing, HTTP delivery and the controlled reverse/callback behavior.
2. **Telemetry-validation evidence** — certutil process creation, Sysmon file creation, Wazuh FIM, PowerShell 4104 and the safe callback marker.

These runs demonstrate the attack mechanics and defensive visibility, but their timestamps are not merged into one fake continuous incident.

## Alert index vs raw event data

The investigation used the Wazuh alert index for much of its hunting. Because only rule-matched events are guaranteed to appear there, some locally generated Sysmon events may not be searchable in `wazuh-alerts-*`.

A production improvement would be to retain raw archives or a dedicated event stream for investigation, with suitable retention and access controls.

## Current coverage gaps

- Re-run the entire chain inside a single UTC-normalized attack window.
- Preserve raw Sysmon network events even when they do not trigger a Wazuh rule.
- Add Windows Firewall, DNS, proxy or network-sensor telemetry for stronger C2 validation.
- Convert Sigma to the deployed backend and test against both positive and benign datasets.
- Track false-positive rate over time rather than relying only on lab validation.

## Why this section exists

A clean story is less valuable than a defensible one. Detection engineering depends on knowing the limits of the telemetry and the confidence of each conclusion.
