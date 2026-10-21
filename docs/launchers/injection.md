# Process-bound injection

The `mavinject.exe` selector loads a native DLL into an existing process and therefore requires `--process-id`. The PID is an explicit operator input, not a discovery feature.

Before execution:

1. Select a disposable process approved by the engagement plan.
2. Confirm that the PID still identifies that process immediately before the run.
3. Match the DLL architecture to the target process architecture.
4. Keep `DllMain` loader-safe and make repeated loads harmless.
5. Confirm the process has sufficient lifetime for the intended validation.

Preflight confirms that the PID exists, resolves its executable path through WMI, reads the remote process image, and compares its PE machine type with the local DLL before staging. An x86/x64/ARM64 mismatch fails with both architectures and the image path in the error. This check does not prove process ownership, process suitability, or safe DLL behavior. The result records `related_process_id`. Injection cannot be generically undone; recovery may require terminating the disposable process or using a payload-specific unload mechanism before removing the staged DLL.

Injection and cross-process module loads are highly observable. Treat a successful process start as proof that the launcher was invoked, not proof that every payload-defined action completed.
