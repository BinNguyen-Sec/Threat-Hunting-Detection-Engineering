# Triage, Response & Hardening

## Triage model

Severity and confidence are evaluated separately: **severity** describes potential impact, while **confidence** describes how strongly the available evidence supports the conclusion.

| Finding | Severity | Confidence | Recommended response |
|---|---|---|---|
| repeated RDP failures | Medium | Medium | inspect source, user, baseline and lockout state |
| RDP success after failures | High | High when same source/user | terminate session, reset credentials, investigate source |
| certutil remote file retrieval | High | High | isolate endpoint, collect hash, block source, inspect parent process |
| file added to user-writable path | Medium–High | High when correlated with certutil | quarantine and investigate persistence |
| PowerShell TCP client behavior | High | High | stop process, restrict outbound traffic, preserve 4104/network evidence |

## Response playbook

1. **Validate** — establish the time window and correlate authentication, process, file, PowerShell and network evidence.
2. **Isolate** — remove the endpoint from production connectivity while preserving approved investigation access.
3. **Contain** — disable or reset exposed credentials, terminate unauthorized sessions, block relevant infrastructure and stop suspicious processes.
4. **Eradicate** — remove artifacts and inspect services, scheduled tasks, autoruns and other persistence locations.
5. **Recover** — patch, restore required services, reset credentials and verify telemetry after reintroduction.
6. **Improve** — tune Sigma/Wazuh logic, document false positives and update the detection baseline.

## RDP hardening

- Do not expose RDP directly to untrusted networks; use VPN, Zero Trust access or an administrative jump host.
- Enable Network Level Authentication and MFA where supported.
- Use an appropriate account-lockout policy and monitor failure→success sequences.
- Restrict `Remote Desktop Users` membership and local-admin privileges.
- Apply host-firewall allowlists for management networks.
- Manage local administrator credentials with a dedicated mechanism such as LAPS where appropriate.

## PowerShell and LOLBin hardening

- Keep Script Block Logging and Module Logging enabled and centralized.
- Use AppLocker or Windows Defender Application Control where operationally viable.
- Monitor LOLBins such as certutil, bitsadmin, mshta, regsvr32 and rundll32 **with command-line and parent-process context**.
- Restrict execution from `Users\Public`, `Temp`, `Downloads` and `AppData` when possible.
- Use Defender/ASR controls and outbound filtering.
- Do not treat PowerShell Execution Policy as the sole security boundary.

## Protect the telemetry plane

- Restrict modification of Wazuh and Sysmon configuration.
- Monitor Security Event IDs **1102** and **4719** for log/audit tampering.
- Centralize logs with suitable retention and synchronized time.
- Protect threat-intelligence API keys and never commit real secrets.
- Monitor agent health, indexer capacity and ingestion delay.
