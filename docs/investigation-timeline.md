# Investigation Timeline & Correlation

## Correlation method

Rather than treating each alert as a separate finding, the investigation selects an entity as a pivot and expands before and after it within a bounded time window.

The primary pivots are:

| Pivot | Fields | Purpose |
|---|---|---|
| Identity | `TargetUserName`, `User`, source address, `LogonType` | connect authentication activity |
| Process | `Image`, `CommandLine`, `ProcessGuid`, `ParentProcessGuid` | reconstruct execution context |
| File | `TargetFilename`, `syscheck.path`, hash, size | connect transfer and file creation |
| Network | process + destination address/port | connect execution to outbound activity |
| Time | event time + attack window | preserve order and reject unrelated events |

## Validation evidence observed

The following timestamps came from controlled telemetry-validation sessions after a lab rollback. They demonstrate that each telemetry source was working; they are **not presented as one continuous attack**.

| Observed time | Source | Evidence | Interpretation |
|---|---|---|---|
| 20:25:34 | PowerShell Operational 4104 | ScriptBlock text contains TCP-client logic | PowerShell processed callback logic |
| 20:28:31 | Security 4688 | `certutil.exe` with remote-download command line | LOLBin transfer behavior |
| 20:28:31–32 | Sysmon 11 | file created under `C:\Users\Public` | process-linked file creation |
| 20:28:31–32 | Wazuh FIM rule 554 | file added to system | independent confirmation of file creation |
| same callback validation | lab listener | marker received from Windows endpoint | network-side corroboration |

## Certutil correlation

The strongest transfer conclusion comes from combining:

1. process creation showing `certutil.exe`;
2. command-line switches associated with remote retrieval;
3. a remote URL;
4. a destination under a user-writable directory;
5. Sysmon FileCreate for the same target;
6. Wazuh FIM independently confirming the file.

This is materially stronger than alerting on the process name alone.

## PowerShell correlation

Event ID **4104** provides script content rather than merely showing `powershell.exe`. During validation, the script block contained `System.Net.Sockets.TcpClient` and a controlled callback marker. This supports the conclusion that TCP client logic was processed.

Where Sysmon Event ID 3 was unavailable in the Wazuh alert index, the investigation did not invent network evidence. It instead used PowerShell 4104 plus listener-side confirmation and documented the visibility limitation.

## Incident verdict

- **Verdict:** True Positive — Authorized Simulation
- **Potential severity if real:** High
- **Confidence:** High for transfer/file/PowerShell behavior; lower for claiming a single uninterrupted full-chain timeline because the surviving evidence spans separate controlled runs.
