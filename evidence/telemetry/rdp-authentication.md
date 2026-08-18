# Evidence — RDP Authentication Chain

The controlled attack-emulation run generated the authentication pattern needed to test RDP hunting logic:

```text
repeated failed authentication
        ↓
Security Event ID 4625
        ↓
successful RDP authentication
        ↓
Security Event ID 4624 / LogonType 10
```

## Investigation fields

- source address
- target username
- failure count
- event time
- status / substatus
- LogonType

## Detection hypothesis

Repeated failures alone can be user error, stale credentials or approved testing. A later successful RemoteInteractive logon for the same source/user materially increases suspicion and should trigger downstream investigation of process, file and network activity.

The proposed lab threshold is documented in [`../../hunts/rdp-authentication.md`](../../hunts/rdp-authentication.md).
