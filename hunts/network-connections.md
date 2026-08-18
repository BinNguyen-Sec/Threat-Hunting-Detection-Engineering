# Hunt — Network Connections

**Hypothesis:** an unusual outbound connection becomes meaningful when it can be tied to suspicious process or script execution on the endpoint.

## Primary telemetry

- Sysmon Event ID `3` when retained/indexed
- PowerShell Event ID `4104`
- listener / firewall / proxy evidence where available

## Fields

`Image`, `ProcessGuid`, `DestinationIp`, `DestinationPort`, protocol, user and time.

## Analyst workflow

1. Identify uncommon process-to-destination relationships.
2. Pivot from the process GUID to process creation and file events.
3. Inspect PowerShell ScriptBlock content when PowerShell is involved.
4. Check whether the destination is expected for that host/user.
5. Corroborate with network-side evidence rather than relying on one alert.

## Visibility note

During this lab, not every Sysmon Event ID 3 appeared in the Wazuh **alert** index. The investigation therefore treated missing alert-index data as a telemetry limitation and used 4104 plus controlled listener evidence to corroborate the callback validation.
