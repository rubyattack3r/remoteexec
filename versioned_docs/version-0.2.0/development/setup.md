# Development setup

## Toolchain

Use the Go version declared in
[`go.mod`](https://github.com/rubyattack3r/remoteexec/blob/v0.2.0/go.mod) and Node.js 22.12 or newer
for the Docusaurus site. Release snapshots also require GoReleaser.

## Build and validate

```bash
make build
make verify
```

`make verify` checks formatting, runs `go vet`, runs the race-enabled test
suite, and builds `bin/remoteexec` from `cmd/remoteexec`. CI repeats those
checks on Linux, exercises the native backend on Windows, builds the Docusaurus
site, and creates a GoReleaser snapshot.

Build or preview the documentation with:

```bash
npm ci
npm run build
npm run start
```

Use `npm run serve` to preview the production build locally.

## Windows fixtures

Benign fixture sources and their contracts live under
[`testdata/windows/`](https://github.com/rubyattack3r/remoteexec/tree/v0.2.0/testdata/windows). Build outputs belong in
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
