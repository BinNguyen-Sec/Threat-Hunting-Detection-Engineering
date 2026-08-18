# Architecture & Telemetry

## Lab topology

The lab uses three primary systems connected over a private overlay network:

- **Kali Linux** — authorized attack emulation and listener-side validation.
- **Windows 10 Endpoint** — monitored target with Sysmon and Wazuh Agent.
- **Ubuntu Wazuh Server** — Manager, Indexer and Dashboard for centralized analysis.

Public documentation intentionally avoids treating lab IP addresses as durable detection logic. They are incident-context IOCs, not behavioral indicators.

## Telemetry pipeline

```text
Windows Endpoint
  ├─ Windows Security Event Log
  │    ├─ 4624 successful logon
  │    ├─ 4625 failed logon
  │    └─ 4688 process creation
  ├─ Sysmon
  │    ├─ 1  process creation
  │    ├─ 3  network connection
  │    └─ 11 file creation
  ├─ PowerShell Operational
  │    └─ 4104 Script Block Logging
  └─ Wazuh FIM
       └─ realtime monitoring of C:\Users\Public
              ↓
          Wazuh Agent
              ↓
        Manager / Indexer
              ↓
           Dashboard
              ↓
 hunting → correlation → triage → detection
```

## Why multiple sources matter

A single event is rarely enough to support a high-confidence conclusion. The lab deliberately collects overlapping evidence:

| Question | Primary evidence | Corroborating evidence |
|---|---|---|
| Was RDP authentication attempted? | Security 4625 | source/user/time pattern |
| Did valid RDP access occur? | Security 4624 + LogonType 10 | preceding failures |
| What process executed? | Security 4688 | Sysmon 1 |
| Was a file created? | Sysmon 11 | Wazuh FIM |
| What did PowerShell process? | PowerShell 4104 | process context / file path |
| Did a process connect outbound? | Sysmon 3 when available | 4104 + listener-side evidence |

## Correlation pivots

The investigation prioritizes stable fields rather than only IOCs:

- **Identity:** `TargetUserName`, `User`, source address, `LogonType`
- **Process:** `Image`, `CommandLine`, `ProcessGuid`, `ParentProcessGuid`
- **File:** `TargetFilename`, `syscheck.path`, hash, size
- **Network:** process image/GUID, destination address and port
- **Temporal:** event time, ingest time and a bounded investigation window

`ProcessGuid` is especially valuable because a PID may later be reused, while the GUID identifies a specific process lifetime.

## Wazuh alert-index limitation

The lab primarily searched `wazuh-alerts-*`. An event can exist locally on Windows while not appearing in that index when it does not match a Wazuh rule. Therefore, absence from the alert index is treated as a **visibility limitation**, not proof that the behavior did not occur.

For production-like hunting, raw archives or a dedicated event data stream would improve visibility and reduce this gap.
