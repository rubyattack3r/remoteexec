# WMIService

## Mechanism and prerequisites

Uses WMI `Win32_Service` methods to snapshot and temporarily reconfigure an existing service so it launches the staged service executable. It requires local-administrator rights, reachable WMI, an explicitly selected existing service, and readable original configuration. Preflight must prove the configuration can be restored before modification.

Payload support: `service` only. The file must implement the Windows service lifecycle expected by the selected existing service.

```mermaid
sequenceDiagram
    participant R as remoteexec
    participant S as SMB staging
    participant W as WMI service
    participant M as Service manager
    R->>S: Stage service executable
    R->>W: Read existing Win32_Service configuration
    R->>W: Change service binary path
    W->>M: Start reconfigured service
    R-->>W: Restore configuration and prior state
    R-->>S: Remove staged executable
```

## Privilege and network surface

- Local administrator on the target
- WMI/DCOM via TCP 135 and negotiated dynamic RPC ports
- SMB on TCP 445

## Operator recovery

Restore the complete original service configuration and prior running state, then remove the staged executable. See [operator recovery](../recovery.md).

## Detection considerations

Relative detectability: **high**. Service configuration changes, unusual image paths, WMI administration, and service starts are well-signatured. Reusing a commonly modified service may change baseline rarity, but does not remove host telemetry.
