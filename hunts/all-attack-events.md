# Hunt — All Expected Attack Events

**Purpose:** create a broad workspace for building an investigation timeline on the monitored Windows endpoint.

```text
agent.name:"Window10" AND (
  data.win.system.eventID:"4625" OR
  data.win.system.eventID:"4624" OR
  data.win.system.eventID:"4688" OR
  data.win.system.eventID:"1" OR
  data.win.system.eventID:"3" OR
  data.win.system.eventID:"11" OR
  data.win.system.eventID:"4104"
)
```

## Analyst workflow

1. Bound the time range first.
2. Sort chronologically and normalize event time vs ingest time.
3. Identify authentication activity and the relevant user/session.
4. Pivot into process creation and parent-child context.
5. Follow created files and hashes.
6. Correlate script-block and network evidence.
7. Separate events from unrelated validation runs.

This query is intentionally broad. It is a timeline workspace, not a standalone detection rule.
