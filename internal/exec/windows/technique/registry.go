package technique

// Mutations builds the registry of technique adapters. Every registered
// technique selector must resolve here before any mutation is allowed.
func Mutations() (*Registry, error) {
	serviceRecovery := "Restore the complete original service configuration and delete the staged executable"
	return NewRegistry(
		Registration{Selector: "WMIExec", Adapter: WMIExec{}, Recovery: "Remove any staged file after the created process releases it"},
		Registration{Selector: "WSManExec", Adapter: WSManExec{}, Recovery: "Close command/shell/session handles and remove any staged file"},
		Registration{Selector: "TaskSchedExec", Adapter: TaskSchedExec{}, Recovery: "Delete the registered task and any staged file"},
		Registration{Selector: "DCOMIShellDispatch2", Adapter: DCOMShellExecute{}, Recovery: "Release COM objects and remove any staged file"},
		Registration{Selector: "WMIService", Adapter: ServiceAdapter{NameValue: "WMIService", Mechanism: MechanismWMI}, Recovery: serviceRecovery},
		Registration{Selector: "SCMChangeService", Adapter: ServiceAdapter{NameValue: "SCMChangeService", Mechanism: MechanismSCM}, Recovery: serviceRecovery},
		Registration{Selector: "SCMCreateService", Adapter: SCMCreateService{}, Recovery: "Stop and delete the temporary service and remove the staged executable"},
		Registration{Selector: "WMIProvider", Adapter: WMIProvider{}, Recovery: "Remove provider registration and the staged DLL"},
		Registration{Selector: VerifyMarkerSelector, Adapter: VerifyMarker{}, Recovery: "Remove the verification marker file from the staging root"},
	)
}
