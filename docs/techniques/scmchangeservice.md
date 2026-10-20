# SCMChangeService

## Mechanism and prerequisites

Uses Service Control Manager RPC to snapshot and temporarily replace an existing service's binary path, then starts that service. It requires local-administrator rights, reachable SCM RPC, an explicitly selected existing service, and readable original configuration. Preflight must prove restoration is possible before modification.

Payload support: `service` only. The file must implement the Windows service lifecycle expected by the selected existing service.

```mermaid
sequenceDiagram
    participant R as remoteexec
    participant S as SMB staging
    participant C as SCM RPC
    participant V as Existing service
    R->>S: Stage service executable
    R->>C: Read service configuration and state
    R->>C: Replace service binary path
    C->>V: Start reconfigured service
    R-->>C: Restore configuration and prior state
    R-->>S: Remove staged executable
```

## Privilege and network surface

- Local administrator on the target
- SCM RPC, commonly over SMB on TCP 445
- RPC endpoint mapper on TCP 135 where required

## Operator recovery

Restore the complete original service configuration and running state, then remove the staged executable. See [operator recovery](../recovery.md).

## Detection considerations

Relative detectability: **high**. SCM configuration changes, service starts, and anomalous image paths are well-signatured. Selecting a service that is already noisy can change alert priority, but does not make the technique undetectable.
