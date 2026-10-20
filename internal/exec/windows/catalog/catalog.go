// Package catalog owns the stable Windows technique inventory.
package catalog

import (
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/target"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

func Registry() *technique.Registry {
	r, err := technique.NewRegistry(descriptors()...)
	if err != nil {
		panic(err)
	}
	return r
}

func descriptors() []technique.Descriptor {
	admin := "Local administrator on target"
	base := func(d technique.Descriptor) technique.Descriptor {
		d.Platforms = []target.Platform{target.Windows}
		d.Transport = target.Native
		if d.Invocations == nil {
			d.Invocations = make(map[payload.Kind]technique.InvocationMode, len(d.Payloads))
			for _, kind := range d.Payloads {
				switch {
				case kind == payload.Service:
					d.Invocations[kind] = technique.InvocationService
				case kind.UsesLauncher():
					d.Invocations[kind] = technique.InvocationLauncher
				default:
					d.Invocations[kind] = technique.InvocationDirect
				}
			}
		}
		return d
	}
	staged := technique.DeliveryStaged
	return []technique.Descriptor{
		base(technique.Descriptor{Name: "WMIProvider", Title: "Malicious WMI Provider", Mechanism: "Registers __Win32Provider metadata and invokes MSFT_Providers.Load", Prerequisites: []string{"WMI reachable"}, Requirements: []technique.Requirement{technique.RequireLocalAdmin, technique.RequireWMI}, Privilege: admin, Surface: []string{"WMI/DCOM TCP 135 + dynamic RPC", "SMB TCP 445"}, FileDelivery: staged, Invocations: map[payload.Kind]technique.InvocationMode{payload.DLL: technique.InvocationNative}, Payloads: []payload.Kind{payload.DLL}, Recovery: "Unload and remove provider registration, registry keys, and staged DLL", OPSEC: "high", Detection: "Well-signatured: provider registration, registry writes, and DLL load telemetry are high-signal."}),
		base(technique.Descriptor{Name: "WMIService", Title: "Win32_Service Change", Mechanism: "Reconfigures and starts an existing service through WMI Win32_Service", Prerequisites: []string{"WMI reachable", "Existing service selected", "Original configuration readable"}, Requirements: []technique.Requirement{technique.RequireLocalAdmin, technique.RequireWMI, technique.RequireExistingService, technique.RequireServiceSnapshot}, Privilege: admin, Surface: []string{"WMI/DCOM TCP 135 + dynamic RPC", "SMB TCP 445"}, FileDelivery: technique.DeliveryServiceChange, Payloads: []payload.Kind{payload.Service}, Recovery: "Restore the complete original service configuration and delete the staged executable", OPSEC: "high", Detection: "Well-signatured: service configuration changes and unusual service images are commonly monitored."}),
		base(technique.Descriptor{Name: "WMIExec", Title: "Win32_Process Create", Mechanism: "Calls Win32_Process.Create over WMI", Prerequisites: []string{"WMI reachable"}, Requirements: []technique.Requirement{technique.RequireLocalAdmin, technique.RequireWMI}, Privilege: admin, Surface: []string{"WMI/DCOM TCP 135 + dynamic RPC", "SMB TCP 445 for file payloads"}, FileDelivery: staged, Payloads: []payload.Kind{payload.DLL, payload.CPL, payload.Managed, payload.Executable, payload.Command}, Recovery: "Remove staged files after execution; command mode creates no staged file", OPSEC: "high", Detection: "Well-signatured remote WMI process creation. Command mode avoids SMB, DLL-load, and LOLBAS signals, but the WMI invocation and command line remain detectable."}),
		base(technique.Descriptor{Name: "WSManExec", Title: "WSMan RunShellCommand", Mechanism: "Creates a WSMan session and shell, then calls WSManRunShellCommand", Prerequisites: []string{"WinRM enabled", "configured HTTP or HTTPS listener reachable (HTTP TCP 5985 by default)"}, Requirements: []technique.Requirement{technique.RequireLocalAdmin, technique.RequireWinRM}, Privilege: admin, Surface: []string{"WinRM HTTP TCP 5985 by default (configurable HTTP/HTTPS)", "SMB TCP 445 for file payloads"}, FileDelivery: staged, Payloads: []payload.Kind{payload.DLL, payload.CPL, payload.Managed, payload.Executable, payload.Command}, Recovery: "Close command/shell/session handles and remove staged files", OPSEC: "medium", Detection: "Mature WinRM and process telemetry. Command mode avoids SMB, DLL-load, and LOLBAS signals, but shell creation and the command remain detectable."}),
		base(technique.Descriptor{Name: "TaskSchedExec", Title: "DCOM TaskScheduler Service Run", Mechanism: "Registers and runs a temporary task through the Task Scheduler COM service", Prerequisites: []string{"Task Scheduler service available", "DCOM reachable"}, Requirements: []technique.Requirement{technique.RequireLocalAdmin, technique.RequireDCOM, technique.RequireTaskScheduler}, Privilege: admin, Surface: []string{"DCOM TCP 135 + dynamic RPC", "SMB TCP 445 for file payloads"}, FileDelivery: staged, Payloads: []payload.Kind{payload.DLL, payload.CPL, payload.Managed, payload.Executable, payload.Command}, Recovery: "Delete the registered task and any staged file", OPSEC: "high", Detection: "Well-signatured task registration and execution. Command mode avoids SMB and DLL-loader signals but retains scheduled-task telemetry."}),
		base(technique.Descriptor{Name: "DCOMIShellDispatch2", Title: "DCOM IShellDispatch2 ShellExecute", Mechanism: "Uses the remote Shell IShellDispatch2.ShellExecute method", Prerequisites: []string{"DCOM reachable", "Interactive user shell active on target"}, Requirements: []technique.Requirement{technique.RequireLocalAdmin, technique.RequireDCOM, technique.RequireActiveShell}, Privilege: admin, Surface: []string{"DCOM TCP 135 + dynamic RPC", "SMB TCP 445 for file payloads"}, FileDelivery: staged, Payloads: []payload.Kind{payload.DLL, payload.CPL, payload.Managed, payload.Executable, payload.Command}, Recovery: "Release COM objects and remove any staged file", OPSEC: "medium", Detection: "Comparatively quiet only where DCOM activation telemetry is sparse. Command mode avoids SMB, DLL-load, and LOLBAS signals, but DCOM activation, ShellExecute, and the resulting process remain detectable. Requires an active shell."}),
		base(technique.Descriptor{Name: "SCMChangeService", Title: "SCM Change Service", Mechanism: "Changes and starts an existing service through SCM RPC", Prerequisites: []string{"SCM reachable", "Existing service selected", "Original configuration readable"}, Requirements: []technique.Requirement{technique.RequireLocalAdmin, technique.RequireSCM, technique.RequireExistingService, technique.RequireServiceSnapshot}, Privilege: admin, Surface: []string{"SCM RPC over SMB TCP 445", "RPC endpoint mapper TCP 135"}, FileDelivery: technique.DeliveryServiceChange, Payloads: []payload.Kind{payload.Service}, Recovery: "Restore the complete original service configuration and delete the staged executable", OPSEC: "high", Detection: "Well-signatured: SCM configuration changes and service starts are standard lateral-movement detections."}),
		base(technique.Descriptor{Name: "SCMCreateService", Title: "SCM Create Service", Mechanism: "Creates and starts a temporary service through SCM RPC (PsExec-style primitive)", Prerequisites: []string{"SCM reachable", "Temporary service name absent"}, Requirements: []technique.Requirement{technique.RequireLocalAdmin, technique.RequireSCM}, Privilege: admin, Surface: []string{"SCM RPC over SMB TCP 445", "RPC endpoint mapper TCP 135"}, FileDelivery: technique.DeliveryServiceCreate, Payloads: []payload.Kind{payload.Service}, Recovery: "Stop and delete the temporary service and remove the staged executable", OPSEC: "high", Detection: "Well-signatured: service creation, administrative-share writes, and service starts are standard PsExec-style lateral-movement detections."}),
	}
}
