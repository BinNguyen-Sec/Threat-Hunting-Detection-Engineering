# Evidence Index

This directory is reserved for a **curated subset** of lab screenshots rather than a dump of the original report.

Planned evidence groups:

- `architecture/` — lab topology and telemetry path
- `red-team/` — authorized RDP / HTTP / controlled callback proof
- `telemetry/` — Wazuh agent, Security/Sysmon/FIM/PowerShell proof
- `hunting/` — Saved Hunts, certutil correlation and investigation views
- `detection/` — Sigma / response evidence where useful

## Integrity rule

Attack-emulation screenshots and later telemetry-validation screenshots may originate from separate controlled runs due a snapshot rollback. Their timestamps must not be presented as a single continuous attack window.

## Redaction rule

Before publication, screenshots should be cropped/redacted where needed to avoid exposing unrelated desktop content, secrets or personal identifiers. Real API keys and credentials are never included.
