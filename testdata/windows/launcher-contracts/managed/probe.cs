using System;
using System.Collections;
using System.ComponentModel;
using System.Configuration.Install;
using System.EnterpriseServices;
using System.IO;
using System.Runtime.InteropServices;

[assembly: ApplicationName("RemoteExecFixture")]
[assembly: ApplicationActivation(ActivationOption.Library)]

[ComVisible(true)]
[Guid("D5AF73E0-2B0D-4F81-A1A8-7D24E379A218")]
public sealed class RemoteExecComFixture : ServicedComponent
{
    private static void Mark(string name)
    {
        File.WriteAllText(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "Temp",
                name),
            "remoteexec managed fixture");
    }

    [ComRegisterFunction]
    public static void Register(Type type)
    {
        Mark("remoteexec-regasm-register.marker");
    }

    [ComUnregisterFunction]
    public static void Unregister(Type type)
    {
        Mark("remoteexec-regasm-unregister.marker");
    }
}

[RunInstaller(true)]
public sealed class RemoteExecInstallerFixture : Installer
{
    public override void Install(IDictionary stateSaver)
    {
        base.Install(stateSaver);
        File.WriteAllText(
            @"C:\Windows\Temp\remoteexec-installutil-install.marker",
            "installed");
    }

    public override void Uninstall(IDictionary savedState)
    {
        File.WriteAllText(
            @"C:\Windows\Temp\remoteexec-installutil-uninstall.marker",
            "uninstalled");
        base.Uninstall(savedState);
    }
}
