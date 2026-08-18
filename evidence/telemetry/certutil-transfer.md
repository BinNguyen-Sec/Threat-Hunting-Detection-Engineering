# Evidence — Certutil Transfer

**Observed in the controlled lab telemetry validation.**

| Field | Observed value / characteristic | Why it matters |
|---|---|---|
| Process | `C:\Windows\System32\certutil.exe` | trusted Windows binary / LOLBin |
| Event | Windows Security `4688` | process creation evidence |
| Command line | contained remote URL retrieval switches including `-urlcache`, `-split` and `-f` | establishes transfer intent rather than normal certificate inspection |
| Target | `C:\Users\Public\update.ps1` | user-writable destination |
| Corroboration | Sysmon Event ID `11` | confirms file creation by endpoint telemetry |
| Corroboration | Wazuh FIM | independently confirms the same new file |

## Analyst conclusion

`certutil.exe` alone is not malicious. Confidence becomes high because **process + command line + remote source + user-writable target + independent file telemetry** all support the same transfer behavior.

The production Sigma rule derived from this observation is [`../../detections/sigma/certutil-remote-download.yml`](../../detections/sigma/certutil-remote-download.yml).
