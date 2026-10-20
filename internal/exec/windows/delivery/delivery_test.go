package delivery

import (
	"strings"
	"testing"

	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

const testRemoteDirectory = `C:\Windows\Temp`

func TestBuildServicePlanIncludesRecovery(t *testing.T) {
	plan, err := Build(Request{Kind: Service, Payload: payload.Spec{Kind: payload.Service, LocalPath: "svc.exe", RemotePath: `C:\Windows\Temp\svc.exe`}, ServiceName: "Spooler"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Recovery) != 2 || plan.Recovery[0].Action != "restore_service_configuration" {
		t.Fatalf("unexpected recovery plan: %#v", plan.Recovery)
	}
	if plan.StagingRoot != testRemoteDirectory || plan.Steps[1].Artifact != `C:\Windows\Temp\svc.exe` {
		t.Fatalf("unexpected staging destination: %#v", plan)
	}
}

func TestBuildLOLBASRejectsUnknownSelector(t *testing.T) {
	_, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: payload.Spec{Kind: payload.DLL, LocalPath: "loader.dll", RemotePath: `C:\Windows\Temp\loader.dll`, LOLBin: "unknown.exe"}})
	if err == nil {
		t.Fatal("expected unknown selector error")
	}
}

func TestBuildUsesConfiguredRemotePath(t *testing.T) {
	plan, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: payload.Spec{Kind: payload.DLL, LocalPath: "loader.dll", RemotePath: `D:\Staging\renamed.dll`, LOLBin: "rundll32.exe", EntryPoint: "Entry"}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.StagingRoot != `D:\Staging` || plan.Steps[0].Artifact != `D:\Staging\renamed.dll` {
		t.Fatalf("unexpected plan: %#v", plan)
	}
}

func TestBuildRejectsUnsafeRemotePath(t *testing.T) {
	for _, remote := range []string{`Windows\Temp\loader.dll`, `C:\Windows\..\loader.dll`, `\\server\share\loader.dll`, `C:\Windows\Temp\`} {
		t.Run(strings.ReplaceAll(remote, `\`, "_"), func(t *testing.T) {
			if _, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: payload.Spec{Kind: payload.DLL, LocalPath: "loader.dll", RemotePath: remote, LOLBin: "rundll32.exe"}}); err == nil {
				t.Fatalf("accepted unsafe remote path %q", remote)
			}
		})
	}
}

func TestBuildCommandPlanHasNoStaging(t *testing.T) {
	plan, err := Build(Request{Kind: LOLBAS, Payload: payload.Spec{Kind: payload.Command, Command: `whoami.exe /all`}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != "command" || plan.StagingRoot != "" || len(plan.Steps) != 1 || plan.Steps[0].Action != "execute_command" {
		t.Fatalf("unexpected command plan: %#v", plan)
	}
}

func TestBuildCommandRejectsMultilineInput(t *testing.T) {
	_, err := Build(Request{Kind: LOLBAS, Payload: payload.Spec{Kind: payload.Command, Command: "whoami.exe\r\nipconfig.exe"}})
	if err == nil || !strings.Contains(err.Error(), "single command line") {
		t.Fatalf("expected command validation error, got %v", err)
	}
}

func TestBuildExecutablePlanStagesAndExecutesDirectly(t *testing.T) {
	plan, err := Build(Request{Kind: LOLBAS, Payload: payload.Spec{Kind: payload.Executable, LocalPath: "agent.exe", RemotePath: `C:\Windows\Temp\agent.exe`, Arguments: "--check"}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != "executable" || len(plan.Steps) != 2 || plan.Steps[1].Action != "execute_staged" {
		t.Fatalf("unexpected executable plan: %#v", plan)
	}
}

func TestBuildServiceCreatePlanIncludesDeletion(t *testing.T) {
	plan, err := Build(Request{Kind: ServiceCreate, Payload: payload.Spec{Kind: payload.Service, LocalPath: "svc.exe", RemotePath: `C:\Windows\Temp\svc.exe`}, ServiceName: "RemoteExecTmp"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Steps[0].Action != "verify_service_absent" || plan.Recovery[0].Action != "stop_and_delete_service" {
		t.Fatalf("unexpected service-create plan: %#v", plan)
	}
}

func TestBuildRequiresExplicitRemotePath(t *testing.T) {
	_, err := Build(Request{Kind: LOLBAS, Payload: payload.Spec{Kind: payload.Executable, LocalPath: "agent.exe"}})
	if err == nil || !strings.Contains(err.Error(), "--remote-path is required") {
		t.Fatalf("expected explicit remote path error, got %v", err)
	}
}

func TestBuildRequiresExplicitLOLBinForLaunchedDLL(t *testing.T) {
	_, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: payload.Spec{Kind: payload.DLL, LocalPath: "loader.dll", RemotePath: `C:\Windows\Temp\loader.dll`}})
	if err == nil || !strings.Contains(err.Error(), "--lolbin is required") {
		t.Fatalf("expected explicit LOLBin error, got %v", err)
	}
}

func TestBuildNativeDLLLoadDoesNotUseLOLBin(t *testing.T) {
	plan, err := Build(Request{Kind: Staged, Invocation: technique.InvocationNative, Payload: payload.Spec{Kind: payload.DLL, LocalPath: "provider.dll", RemotePath: `C:\Windows\Temp\provider.dll`}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Action != "stage_loader" {
		t.Fatalf("unexpected native DLL plan: %#v", plan)
	}
}

func TestBuildNativeDLLLoadRejectsLOLBin(t *testing.T) {
	_, err := Build(Request{Kind: Staged, Invocation: technique.InvocationNative, Payload: payload.Spec{Kind: payload.DLL, LocalPath: "provider.dll", RemotePath: `C:\Windows\Temp\provider.dll`, LOLBin: "rundll32.exe"}})
	if err == nil || !strings.Contains(err.Error(), "not used") {
		t.Fatalf("expected native-load LOLBin rejection, got %v", err)
	}
}

func TestBinaryInventoryHasCompleteContracts(t *testing.T) {
	if len(Binaries()) != 17 {
		t.Fatalf("binary count = %d, want 17", len(Binaries()))
	}
	for _, binary := range Binaries() {
		if binary.Selector == "" || binary.Program == "" || !binary.PayloadType.UsesLauncher() || binary.RequiredExport == "" || binary.InvocationTemplate == "" || binary.Detectability == "" || binary.Notes == "" {
			t.Errorf("incomplete binary contract: %#v", binary)
		}
	}
}

func TestBuiltInLOLBinCommandsComeFromInventory(t *testing.T) {
	want := map[string]string{
		"rundll32.exe":                       `rundll32.exe C:\Windows\Temp\loader.dll,Entry`,
		"rundll32.exe (advpack RegisterOCX)": `rundll32.exe advpack.dll,RegisterOCX C:\Windows\Temp\loader.dll`,
		"msiexec.exe (/y)":                   `msiexec.exe /y C:\Windows\Temp\loader.dll`,
		"msiexec.exe (/z)":                   `msiexec.exe /z C:\Windows\Temp\loader.dll`,
		"odbcconf.exe":                       `odbcconf.exe /a {REGSVR C:\Windows\Temp\loader.dll}`,
		"regsvr32.exe":                       `regsvr32.exe /s C:\Windows\Temp\loader.dll`,
		"regsvr32.exe (/u)":                  `regsvr32.exe /s /u C:\Windows\Temp\loader.dll`,
		"regsvr32.exe (/i)":                  `regsvr32.exe /s /n /i C:\Windows\Temp\loader.dll`,
		"regsvr32.exe (/u /i)":               `regsvr32.exe /s /u /n /i C:\Windows\Temp\loader.dll`,
	}
	for selector, command := range want {
		t.Run(selector, func(t *testing.T) {
			plan, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: payload.Spec{
				Kind: payload.DLL, LocalPath: "loader.dll", RemotePath: `C:\Windows\Temp\loader.dll`, LOLBin: selector, EntryPoint: "Entry",
			}})
			if err != nil {
				t.Fatal(err)
			}
			if got := invocationOf(plan); got != command {
				t.Fatalf("command = %q, want %q", got, command)
			}
		})
	}
}

func TestBuildCustomLOLBin(t *testing.T) {
	plan, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: payload.Spec{
		Kind: payload.DLL, LocalPath: "loader.dll", RemotePath: `D:\Stage Area\loader.dll`, LOLBin: "custom",
		LauncherProgram: `D:\Tools\Acme Loader.exe`, LauncherArguments: `--load {remote_path} --export {entry_point}`, EntryPoint: "Run",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 3 || plan.Steps[0].Action != "verify_launcher" || plan.Steps[0].Artifact != `D:\Tools\Acme Loader.exe` {
		t.Fatalf("unexpected custom plan: %#v", plan)
	}
	want := `"D:\Tools\Acme Loader.exe" --load "D:\Stage Area\loader.dll" --export Run`
	if got := invocationOf(plan); got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestBuildCustomLOLBinRejectsIncompleteContract(t *testing.T) {
	base := payload.Spec{Kind: payload.DLL, LocalPath: "loader.dll", RemotePath: `C:\Windows\Temp\loader.dll`, LOLBin: "custom"}
	tests := []payload.Spec{
		base,
		func() payload.Spec {
			s := base
			s.LauncherProgram = `C:\Tools\loader.exe`
			s.LauncherArguments = "--load fixed.dll"
			return s
		}(),
		func() payload.Spec {
			s := base
			s.LauncherProgram = `loader.exe`
			s.LauncherArguments = "{remote_path}"
			return s
		}(),
		func() payload.Spec {
			s := base
			s.LauncherProgram = `C:\Tools\loader.exe`
			s.LauncherArguments = "{unknown}"
			return s
		}(),
	}
	for i, spec := range tests {
		if _, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: spec}); err == nil {
			t.Errorf("case %d accepted incomplete custom launcher", i)
		}
	}
}

func TestTypedLauncherContracts(t *testing.T) {
	tests := []struct {
		name string
		spec payload.Spec
		want string
	}{
		{
			name: "control panel module",
			spec: payload.Spec{Kind: payload.CPL, LocalPath: "module.cpl", RemotePath: `C:\Stage\module.cpl`, LOLBin: "control.exe"},
			want: `control.exe C:\Stage\module.cpl`,
		},
		{
			name: "process injection",
			spec: payload.Spec{Kind: payload.DLL, LocalPath: "module.dll", RemotePath: `C:\Stage\module.dll`, LOLBin: "mavinject.exe", ProcessID: 4242},
			want: `mavinject.exe 4242 /INJECTRUNNING C:\Stage\module.dll`,
		},
		{
			name: "managed installer",
			spec: payload.Spec{Kind: payload.Managed, LocalPath: "installer.dll", RemotePath: `C:\Stage\installer.dll`, LOLBin: "InstallUtil.exe (/U)"},
			want: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /LogFile= /LogToConsole=false /U C:\Stage\installer.dll`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: test.spec})
			if err != nil {
				t.Fatal(err)
			}
			if got := invocationOf(plan); got != test.want {
				t.Fatalf("command = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTypedLauncherContractsRejectMismatches(t *testing.T) {
	base := payload.Spec{Kind: payload.DLL, LocalPath: "module.dll", RemotePath: `C:\Stage\module.dll`}
	tests := []payload.Spec{
		func() payload.Spec { s := base; s.LOLBin = "control.exe"; return s }(),
		func() payload.Spec { s := base; s.LOLBin = "mavinject.exe"; return s }(),
		func() payload.Spec { s := base; s.LOLBin = "rundll32.exe"; s.ProcessID = 42; return s }(),
	}
	for i, spec := range tests {
		if _, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: spec}); err == nil {
			t.Errorf("case %d accepted an invalid typed launcher contract", i)
		}
	}
}

func TestCustomLauncherSupportsEveryLauncherPayload(t *testing.T) {
	for _, kind := range []payload.Kind{payload.DLL, payload.CPL, payload.Managed} {
		spec := payload.Spec{Kind: kind, LocalPath: "input", RemotePath: `C:\Stage\input`, LOLBin: "custom", LauncherProgram: `C:\Tools\host.exe`, LauncherArguments: `{remote_path}`}
		if _, err := Build(Request{Kind: LOLBAS, Invocation: technique.InvocationLauncher, Payload: spec}); err != nil {
			t.Errorf("%s custom launcher: %v", kind, err)
		}
	}
}

func invocationOf(plan Plan) string {
	for _, step := range plan.Steps {
		if step.Action == "invoke_loader" {
			return step.Artifact
		}
	}
	return ""
}
