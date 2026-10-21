# Managed launchers

`RegAsm.exe`, `RegSvcs.exe`, and `InstallUtil.exe` consume .NET Framework assemblies with different metadata and type contracts. They are not interchangeable with native DLLs or with each other.

## RegAsm

Expose appropriate COM-visible types. When registration callbacks are required, implement idempotent static methods marked with `[ComRegisterFunction]` and `[ComUnregisterFunction]`; each receives the registered `Type`.

## RegSvcs

Build a strong-named .NET Framework Enterprise Services assembly. The component derives from `System.EnterpriseServices.ServicedComponent` and includes the application and activation metadata required by the intended registration mode.

## InstallUtil

Expose a public class derived from `System.Configuration.Install.Installer` and mark it `[RunInstaller(true)]`. Implement `Install`, `Commit`, `Rollback`, and `Uninstall` consistently so partial installation and operator recovery have defined behavior.

## Runtime and architecture

The built-in selectors use the 64-bit .NET Framework v4 tool paths. Build for .NET Framework rather than modern .NET unless an explicitly selected launcher supports that runtime. For 32-bit assemblies, override `--launcher-program` with the corresponding `Framework` path. Confirm that every referenced assembly exists on the target.

Inspect the final artifact with `corflags`, `ildasm`, or an equivalent metadata reader. Test registration and unregistration as a pair on a disposable host. Registry, COM+, installer, service, and file changes made by managed callbacks are payload-defined and are not included automatically in remoteexec's staged-file recovery record.

References: [`ComRegisterFunctionAttribute`](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.comregisterfunctionattribute), [`ServicedComponent`](https://learn.microsoft.com/en-us/dotnet/api/system.enterpriseservices.servicedcomponent), [`Installer`](https://learn.microsoft.com/en-us/dotnet/api/system.configuration.install.installer), and [`InstallUtil`](https://learn.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool).
