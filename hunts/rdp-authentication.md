# Hunt — RDP Authentication

**Hypothesis:** repeated remote-authentication failures followed by a successful RemoteInteractive logon may indicate password guessing that resulted in valid access.

## Data to inspect

- Security Event ID `4625` — failed logon
- Security Event ID `4624` — successful logon
- `LogonType: 10` — RemoteInteractive / RDP
- source address
- target user
- timestamp

## Hunt logic

Search for bursts of 4625 grouped by **source + target user**, then look forward for 4624 with LogonType 10 for the same entities.

Proposed correlation threshold for testing:

```text
same Source + TargetUser
AND >= 5 x 4625 within 10 minutes
THEN 4624 LogonType 10 within 5 minutes
```

## Tuning questions

- Is the source an approved jump host or vulnerability scanner?
- Does the account have a known stale credential in an automated task?
- What is the normal RDP baseline for this endpoint?
- Did process/file activity become suspicious after the successful logon?

A successful logon after failures increases suspicion, but the downstream endpoint activity determines incident confidence.
