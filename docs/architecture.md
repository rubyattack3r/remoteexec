# Architecture

remoteexec follows a feature-first Go CLI layout. The `exec` command owns shared orchestration and nests each platform or transport implementation beneath the same feature boundary.

```text
cmd/                         Cobra input and output only
internal/config/             Global flags and runtime configuration
internal/exec/               Shared execution contracts and orchestration
  credentials/               Secret-bearing credential value and redaction
  engine/                    Batch preflight and execution orchestration
  errs/                      Error categories
  journal/                   Process-local mutation event recorder
  model/                     Stable result schema
  payload/                   Typed DLL, CPL, managed, executable, service, and command contract
  plan/                      Generic execution and recovery steps
  target/                    Platform and transport identifiers
  technique/                 Generic descriptor and registry mechanics
  ssh/                       Platform-neutral SSH execution feature
    catalog/                 SSH technique inventory
    delivery/                Command-only SSH plan construction
    technique/               SSHExec invocation and artifact adapter
  windows/                   Windows execution feature
    backend.go               Preflight policy and transaction binding
    catalog/                 Eight stable public selectors
    delivery/                Service and LOLBAS plan construction
    native/                  Direct Win32 and COM integrations
    technique/               Transactional Windows adapters
internal/output/             JSON, YAML, and Signal rendering
```

## Dependency direction

Platform packages may import shared packages elsewhere under `internal/exec`. Shared execution packages must not import a concrete platform implementation. The CLI composes a catalog, planner, backend, and renderer; it does not contain selector-specific branches.

A technique descriptor declares its platform, transport, supported payload types, file-delivery mode, and a per-payload invocation map (`direct`, `native`, `launcher`, or `service`). A platform catalog owns its selectors and metadata. A platform planner translates the typed payload into a generic `plan.Plan`, keeping remote paths and delivery conventions outside the engine. Command-only techniques do not need file delivery, which leaves the registry usable for future SSH-backed primitives.

Built-in LOLBin metadata, payload compatibility, required options, and argument templates live in one delivery registry. Custom launchers use the same resolved plan shape but require an absolute target-resident executable path and a constrained placeholder template. The Windows backend verifies absolute launcher paths during batch preflight; adapters receive only the resolved command and typed process context, never selector-specific branches.

The Windows mutation implementation remains experimental and build-gated. Mutation events exist only in memory while constructing artifact results; remoteexec writes no recovery journal. Native API conformance tests on disposable Windows targets are required before enabling it.

## Adding another platform

Add a package beneath `internal/exec` containing:

1. A catalog of platform-specific selectors.
2. A planner that returns generic execution and recovery steps.
3. A read-only preflight backend.
4. Narrow capability interfaces for any platform operations.
5. Mutation adapters that report complete operator recovery artifacts.
6. Platform-native CI and integration tests.

The `ssh` package is the minimal transport-oriented example. `SSHExec` passes a command to the server's default command processor after credentialed preflight, without requiring or probing an operating system. It supports OpenSSH servers on Linux, macOS, and Windows, has no file-delivery contract, and does not model platform-specific lateral-movement mechanisms.
