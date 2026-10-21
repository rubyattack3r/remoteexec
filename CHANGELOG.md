# Changelog

Notable changes to remoteexec are documented here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, incompatible changes
increment the minor version.

## [0.2.0] - 2026-10-21

### Added

- Native Windows execution backends for WMI, WinRM, DCOM, Task Scheduler, and
  SCM techniques in ordinary Windows release builds.
- Cross-platform, command-only `SSHExec` support for Linux, macOS, and Windows
  OpenSSH targets.
- Typed executable, service, native DLL, Control Panel, managed assembly,
  process-injection, and custom-launcher contracts.
- Benign Windows fixture sources and live-validation documentation.

### Changed

- Replaced the original result contract with schema `0.2.0`, separating
  execution evidence from operator recovery context.
- Made recovery explicitly operator-controlled: successful runs report the
  state needed for recovery and do not perform automatic cleanup.
- Strengthened prerequisite validation so target-wide preflight completes
  before any target is allowed to execute.
- Redacted raw command and launcher arguments from persisted result fields in
  favor of SHA-256 invocation identifiers.

## [0.1.0] - 2026-10-20

- Initial public release with the Cobra command tree, technique registry,
  shared result model, documentation site, and release packaging.

[0.2.0]: https://github.com/rubyattack3r/remoteexec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rubyattack3r/remoteexec/releases/tag/v0.1.0
