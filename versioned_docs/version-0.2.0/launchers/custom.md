# Custom launchers

The reserved `custom` selector describes a target-resident executable without adding it to remoteexec's built-in registry. remoteexec validates the executable path and argument-template syntax; the launcher owns the payload ABI, success semantics, and side effects.

## Selecting a launcher

Start with the [LOLBAS catalog](https://lolbas-project.github.io/) and search for an execution function compatible with the target environment and payload format. Treat a catalog entry as a candidate, not as proof that it will work on a particular host. Confirm that:

1. the exact executable and required optional features exist on the target;
2. the documented function accepts the staged payload format (`dll`, `cpl`, or `managed`);
3. its invocation fits a single-line argument template using `{remote_path}` and, when needed, `{entry_point}` or `{process_id}`;
4. payload and process architectures are compatible; and
5. the engagement permits the launcher's side effects and associated telemetry.

Prefer a built-in selector when remoteexec already models the candidate because built-ins provide typed prerequisite and payload-contract validation. Use `custom` for a suitable target-resident executable that is not in the built-in registry. A LOLBAS entry limited to downloading, copying, compiling, or another non-execution function is not automatically a valid custom launcher.

```bash
remoteexec exec technique --dry-run \
  --targets server01 --technique WMIExec \
  --payload-type dll --payload ./payload.dll \
  --remote-path 'D:\Staging\payload.dll' \
  --lolbin custom \
  --launcher-program 'D:\Approved Tools\host.exe' \
  --launcher-arguments '--module {remote_path} --export {entry_point}' \
  --entry-point Run \
  --domain CORP --username operator --password-stdin
```

The launcher program must be an absolute path to an existing `.exe`. Templates must be single-line, must contain `{remote_path}`, and may contain `{entry_point}` and `{process_id}`. Using either optional placeholder makes its corresponding flag required. Unknown placeholders are rejected.

Document the custom ABI beside the launcher, including:

- accepted payload formats and architectures;
- placeholder quoting and parsing behavior;
- exit-status and verification semantics;
- dependencies and target prerequisites;
- persistent side effects; and
- recovery steps beyond removal of the staged payload.

Test the exact rendered command on a disposable host. `--dry-run` proves launcher presence and template validity, but it cannot prove that an arbitrary executable implements the documented contract.
