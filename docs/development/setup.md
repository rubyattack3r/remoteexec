# Development setup

## Toolchain

Use the Go version declared in
[`go.mod`](https://github.com/rubyattack3r/remoteexec/blob/main/go.mod).
Release snapshots also require GoReleaser.

## Build and validate

```bash
make build
make verify
```

`make verify` checks formatting, runs `go vet`, runs the race-enabled test
suite, and builds `bin/remoteexec` from `cmd/remoteexec`. CI repeats those
checks on Linux, exercises the native backend on Windows, validates local
Markdown links and technique diagrams, and creates a GoReleaser snapshot.

Documentation is ordinary Markdown under `docs/` and is rendered directly by
GitHub. It has no separate package manager or site build.

## Windows fixtures

Benign fixture sources and their contracts live under
[`testdata/windows/`](https://github.com/rubyattack3r/remoteexec/tree/main/testdata/windows). Build outputs belong in
the ignored `.scratch/` tree and must not be committed. Live validation must
use disposable hosts covered by explicit authorization; never commit target
configuration, credentials, logs, or generated payloads.

## Record the demo

The README demo is recorded locally from a real Windows PowerShell session;
CI does not regenerate it. Put `remoteexec.exe` on `PATH`, configure token
access to the disposable `wks01` target, install
[VHS](https://github.com/charmbracelet/vhs), and run:

```powershell
make demo
```

[`docs/demo.tape`](../demo.tape) writes `docs/assets/demo.gif`. Review the GIF
before committing both the tape and asset together.
