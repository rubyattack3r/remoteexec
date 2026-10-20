# Contributing

By contributing, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md) and [Acceptable Use Policy](ACCEPTABLE_USE_POLICY.md).

Create a focused branch, run `make verify`, and include tests and documentation. A new Windows technique must be registered through `internal/exec/windows/catalog`, use the shared contracts under `internal/exec`, document privileges, API/port surface, cleanup, manual recovery, and detection considerations, and include prerequisite and cleanup-failure tests. The Cobra layer must not contain selector-specific branching.

New execution transports belong under `internal/exec/<platform-or-transport>`. Keep protocol or native API details inside that feature package and expose only shared plans, results, and validation errors to the execution engine. See the [architecture guide](docs/architecture.md) before adding a backend.

Do not include live credentials, engagement data, payloads, or target identifiers in commits or issues.
