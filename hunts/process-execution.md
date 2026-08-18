# Hunt — Process Execution

**Hypothesis:** trusted Windows binaries or script interpreters become suspicious when command line, parent process and surrounding activity indicate transfer or execution behavior.

## Primary telemetry

- Security Event ID `4688`
- Sysmon Event ID `1`
- PowerShell Event ID `4104`

## Fields to pivot on

`Image`, `NewProcessName`, `CommandLine`, `ParentImage`, `ProcessGuid`, `ParentProcessGuid`, user and event time.

## Analyst approach

- Do not alert on `certutil.exe` or `powershell.exe` by name alone.
- Inspect remote-URL switches, destination paths and parent-child context.
- Use Sysmon `ProcessGuid` to connect later file/network events to the same process lifetime.
- Use 4104 to understand PowerShell content rather than inferring behavior from process creation only.

### Scenario-validation clues

In this lab, certutil remote-retrieval behavior and PowerShell TCP-client logic were useful incident-specific pivots. They support validation after a suspicious chain is identified; the broader hunt remains behavior-focused.
