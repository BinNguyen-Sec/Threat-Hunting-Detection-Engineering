# MITRE ATT&CK Mapping

The project maps techniques only where the lab produced matching behavioral evidence. ATT&CK is used as an investigation and coverage framework, not as a substitute for evidence.

| Tactic | Technique | Evidence in the lab |
|---|---|---|
| Credential Access | **T1110.001 — Password Guessing** | repeated failed RDP authentication from the controlled source |
| Lateral Movement | **T1021.001 — Remote Desktop Protocol** | successful RemoteInteractive / LogonType 10 access |
| Defense Evasion | **T1078.003 — Valid Accounts: Local Accounts** | local lab account used for valid remote access |
| Command and Control | **T1105 — Ingress Tool Transfer** | certutil retrieves a test artifact over HTTP |
| Execution | **T1059.001 — PowerShell** | Event ID 4104 exposes script-block behavior |
| Command and Control | **T1095 — Non-Application Layer Protocol** | direct TCP-client callback behavior in the controlled validation |

## Mapping discipline

A technique is not asserted merely because it is plausible. For example, **T1204.002 User Execution: Malicious File** is not claimed because the available evidence does not prove that a user manually launched the artifact.

Likewise, T1095 describes the observed TCP socket behavior in the lab; the project does not overstate the safe callback as evidence of a complete commodity C2 framework.

## Detection coverage

| Technique | Main telemetry | Hunt / detection | Coverage note |
|---|---|---|---|
| T1110.001 | Security 4625 | RDP authentication + threshold correlation | partial until a new single-window full run is captured |
| T1021.001 | Security 4624 / LogonType 10 | RDP authentication hunt | telemetry available |
| T1105 | 4688, Sysmon 11, FIM | certutil download + file-create Sigma | validated |
| T1059.001 | PowerShell 4104 | TCP-client ScriptBlock Sigma | validated |
| T1095 | 4104, Sysmon 3 when available, listener | network hunt + callback evidence | partial due alert-index visibility |
