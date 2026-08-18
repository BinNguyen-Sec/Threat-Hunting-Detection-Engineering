# Evidence Index

This directory contains a **curated, sanitized evidence set** reconstructed from the completed lab report. The goal is to preserve investigation value without turning the repository into a dump of report screenshots.

## Public evidence records

- [`telemetry/rdp-authentication.md`](telemetry/rdp-authentication.md) — repeated RDP failures followed by valid RDP access and the fields needed for correlation.
- [`telemetry/certutil-transfer.md`](telemetry/certutil-transfer.md) — process creation and command-line evidence for `certutil.exe` transferring an artifact into `C:\Users\Public`.
- [`telemetry/file-corroboration.md`](telemetry/file-corroboration.md) — Sysmon FileCreate plus Wazuh FIM corroboration for the same artifact.
- [`telemetry/powershell-callback.md`](telemetry/powershell-callback.md) — PowerShell Event `4104`, `ScriptBlockText`, direct TCP client behavior and the safe incident marker.

The original report also preserves screenshots for the Wazuh dashboard, saved hunts, HTTP delivery, Red Team validation, process/file telemetry, FIM and PowerShell Script Block Logging. Screenshots that expose lab credentials or unrelated desktop information are not published unredacted.

## Integrity rule

Attack-emulation evidence and later telemetry-validation evidence may originate from separate controlled runs because the environment was restored from snapshot during the project. Their timestamps are therefore **not** presented as one continuous attack window.

## Redaction rule

Public evidence must not contain reusable passwords, API keys or unrelated personal data. IOC values that are necessary to explain the controlled lab may remain when they do not create a reusable secret.
