# Hunt — File Activity

**Hypothesis:** a new artifact in a user-writable directory is more suspicious when its creating process and nearby execution behavior are unusual.

## Primary telemetry

- Sysmon Event ID `11` — File Create
- Wazuh FIM — file added/modified, including rule 554 in the lab

## Fields

`Image`, `ProcessGuid`, `TargetFilename`, `syscheck.path`, file hash, size and timestamp.

## Correlation pattern

```text
suspicious process
   ↓
Sysmon 11 creates file in user-writable location
   ↓
Wazuh FIM independently confirms same path
   ↓
subsequent script/process/network activity
```

The independent Sysmon + FIM confirmation raises confidence compared with a single decoder/rule result.

## User-writable locations worth reviewing

- `C:\Users\Public\`
- `AppData`
- `Temp`
- `Downloads`

These locations are not malicious by themselves; process context, provenance and follow-on activity determine severity.
