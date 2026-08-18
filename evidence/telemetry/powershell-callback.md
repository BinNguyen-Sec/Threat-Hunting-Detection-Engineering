# Evidence — PowerShell ScriptBlock & Controlled Callback

PowerShell Event ID **4104** captured the script content processed during the telemetry-validation run.

## Observed fields

- Path: `C:\Users\Public\update.ps1`
- Script content included: `System.Net.Sockets.TcpClient`
- Controlled listener: lab-only destination
- Marker: `INC_CASE3_001_SAFE_CALLBACK`
- Behavior: create TCP client → send marker → close connection

## Interpretation

This evidence supports the conclusion that PowerShell processed direct TCP-client logic. It is **not** described as a remote shell: the validation script was intentionally constrained to send a marker and terminate.

Where Sysmon Event ID 3 was unavailable in the Wazuh alert index, 4104 was corroborated with listener-side evidence rather than assuming network telemetry existed.

The derived Sigma rule is [`../../detections/sigma/powershell-tcp-client.yml`](../../detections/sigma/powershell-tcp-client.yml).
