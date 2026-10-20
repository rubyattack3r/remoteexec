package catalog

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/target"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

func TestSelectorsAndPlatformMetadata(t *testing.T) {
	want := []string{"DCOMIShellDispatch2", "SCMChangeService", "SCMCreateService", "TaskSchedExec", "WMIExec", "WMIProvider", "WMIService", "WSManExec"}
	descriptors := Registry().List()
	got := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		got = append(got, descriptor.Name)
		if len(descriptor.Platforms) != 1 || descriptor.Platforms[0] != target.Windows || descriptor.Transport != target.Native {
			t.Fatalf("%s metadata = %v/%s", descriptor.Name, descriptor.Platforms, descriptor.Transport)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectors = %v, want %v", got, want)
	}
}

func TestEveryTechniqueValidatesPrerequisites(t *testing.T) {
	available := technique.Capabilities{
		LocalAdmin: true, WMI: true, RemoteRegistry: true, WinRM: true,
		DCOM: true, TaskScheduler: true, ActiveShell: true, SCM: true,
		ExistingService: true, ServiceSnapshot: true,
	}
	for _, descriptor := range Registry().List() {
		t.Run(descriptor.Name, func(t *testing.T) {
			if err := descriptor.ValidatePrerequisites(available); err != nil {
				t.Fatal(err)
			}
			if err := descriptor.ValidatePrerequisites(technique.Capabilities{}); err == nil {
				t.Fatal("expected missing-prerequisite error")
			}
		})
	}
}

func TestPayloadInvocationContractsAreTechniqueCapabilities(t *testing.T) {
	want := map[string]technique.InvocationMode{
		"WMIProvider":         technique.InvocationNative,
		"WMIExec":             technique.InvocationLauncher,
		"WSManExec":           technique.InvocationLauncher,
		"TaskSchedExec":       technique.InvocationLauncher,
		"DCOMIShellDispatch2": technique.InvocationLauncher,
		"WMIService":          technique.InvocationService,
		"SCMChangeService":    technique.InvocationService,
		"SCMCreateService":    technique.InvocationService,
	}
	for _, descriptor := range Registry().List() {
		kind := payload.DLL
		if strings.Contains(descriptor.Name, "Service") {
			kind = payload.Service
		}
		if got, _ := descriptor.InvocationFor(kind); got != want[descriptor.Name] {
			t.Errorf("%s %s invocation = %q, want %q", descriptor.Name, kind, got, want[descriptor.Name])
		}
	}
}
