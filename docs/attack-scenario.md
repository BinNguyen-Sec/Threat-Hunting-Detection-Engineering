# Authorized Attack Emulation Scenario

## Objective

Generate a realistic but controlled trail from initial access through execution and outbound callback so the defensive pipeline can be evaluated end to end.

No persistence, data theft or external target was involved. The final telemetry-validation callback sent a marker and closed the connection rather than providing a remote shell.

## Scenario chain

| Phase | Controlled behavior | Expected evidence |
|---|---|---|
| Initial Access | limited RDP password guessing | Security 4625, source, target user, LogonType |
| Valid Access | successful RDP authentication | Security 4624, LogonType 10 |
| Delivery | temporary HTTP distribution | HTTP request/response + endpoint process evidence |
| Tool Transfer | `certutil.exe` retrieves test artifact | 4688, Sysmon 1/11, FIM |
| Execution | PowerShell processes the test script | PowerShell 4104, process context |
| Callback | controlled TCP marker sent to lab listener | Sysmon 3 when available, 4104, listener evidence |

## Investigation hypothesis

A useful hypothesis is not “does `update.ps1` exist?” but:

> Did remote authentication activity lead to a trusted Windows binary retrieving content into a user-writable location, followed by script execution and unusual outbound TCP behavior?

That hypothesis remains useful even if the filename, lab IP or callback port changes.

## Expected defensive chain

```text
4625 burst
  ↓
4624 / LogonType 10
  ↓
4688 / Sysmon 1 — suspicious certutil command line
  ↓
Sysmon 11 + FIM — new file in user-writable directory
  ↓
4104 — PowerShell script content
  ↓
network evidence / listener marker
  ↓
incident correlation
```

## Evidence handling

The original attack-emulation run and a later telemetry-validation run occurred at different times after a snapshot rollback. Their artifacts prove different things and are not merged into a fabricated single timeline. See [`limitations.md`](limitations.md).
