# Evidence — Sysmon + Wazuh FIM File Corroboration

The test artifact written to `C:\Users\Public` was independently observed by two telemetry sources.

| Source | Observation |
|---|---|
| Sysmon Event ID `11` | file creation associated with the transfer process |
| Wazuh FIM rule `554` | `File added to the system` for the same path |
| SHA-256 observed during validation | `93E00F4628D430E340014CA5F357F8815E07E5BF152DA1DBB2FEA0AD6138B377` |

## Why this matters

Independent telemetry reduces the chance that an investigation conclusion depends on one decoder, one rule or one event source. In this case, Sysmon provides process-linked file creation while FIM provides a separate integrity-monitoring confirmation.

The related behavioral detection is [`../../detections/sigma/certutil-user-writable-file.yml`](../../detections/sigma/certutil-user-writable-file.yml).
