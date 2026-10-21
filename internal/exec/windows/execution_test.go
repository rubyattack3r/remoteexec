package windows

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
	"github.com/rubyattack3r/remoteexec/internal/exec/windows/catalog"
	"github.com/rubyattack3r/remoteexec/internal/exec/windows/delivery"
	adapter "github.com/rubyattack3r/remoteexec/internal/exec/windows/technique"
)

const testRemoteDirectory = `C:\Windows\Temp`

func TestRequiredPorts(t *testing.T) {
	tests := map[string][]int{
		"WMIExec":          {135, 445},
		"WSManExec":        {445, 5985},
		"SCMChangeService": {135, 445},
	}
	for technique, want := range tests {
		if got := requiredPorts(technique, engine.DefaultWinRMHTTPPort, payload.DLL); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s ports = %v, want %v", technique, got, want)
		}
	}
	if got := requiredPorts("WSManExec", 55986, payload.DLL); !reflect.DeepEqual(got, []int{445, 55986}) {
		t.Fatalf("custom WSMan ports = %v", got)
	}
	if got := requiredPorts("WSManExec", 55986, payload.Command); !reflect.DeepEqual(got, []int{55986}) {
		t.Fatalf("command WSMan ports = %v", got)
	}
	if got := requiredPorts("WMIExec", 5985, payload.Command); !reflect.DeepEqual(got, []int{135}) {
		t.Fatalf("command WMI ports = %v", got)
	}
}

var execCredentials = credentials.Credentials{Domain: "EXAMPLE", Username: "admin", Password: "test-secret-value"}

type fakeProbes struct {
	authErr     error
	adminErr    error
	admin       bool
	services    map[string]string
	images      map[string]string
	activeShell bool
	shellErr    error
	free        uint64
	existing    map[string]bool
	globbed     []string
	diskPath    string
}

func (f *fakeProbes) Authenticate(context.Context, string, credentials.Credentials) error {
	return f.authErr
}

func (f *fakeProbes) LocalAdmin(context.Context, string, credentials.Credentials) (bool, error) {
	return f.admin, f.adminErr
}

func (f *fakeProbes) ServiceState(_ context.Context, _, name string, _ credentials.Credentials) (string, bool, error) {
	state, ok := f.services[name]
	return state, ok, nil
}

func (f *fakeProbes) ServiceImagePath(_ context.Context, _, name string, _ credentials.Credentials) (string, bool, error) {
	path, ok := f.images[name]
	return path, ok, nil
}

func (f *fakeProbes) ActiveSession(context.Context, string, credentials.Credentials) (bool, error) {
	return f.activeShell, f.shellErr
}

func (f *fakeProbes) DiskFree(_ context.Context, _, path string, _ credentials.Credentials) (uint64, error) {
	f.diskPath = path
	return f.free, nil
}

func (f *fakeProbes) FileExists(_ context.Context, _, path string, _ credentials.Credentials) (bool, error) {
	return f.existing[path], nil
}

func (f *fakeProbes) Glob(context.Context, string, string, credentials.Credentials) ([]string, error) {
	return f.globbed, nil
}

func preflightFixture() (Backend, *fakeProbes) {
	probes := &fakeProbes{
		admin:    true,
		services: map[string]string{"RemoteRegistry": "Stopped", "Schedule": "Running"},
		images:   map[string]string{},
		free:     1024 * 1024 * 1024,
		existing: map[string]bool{testRemoteDirectory: true},
	}
	backend := Backend{
		Probes:   probes,
		clock:    func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		dialPort: func(context.Context, string, int) error { return nil },
		// Technique adapters drive native sessions on Windows; these tests
		// cover the shared probe layer only.
		adapterCheck: func(context.Context, engine.Prepared, credentials.Credentials, *engine.PreflightReport) error {
			return nil
		},
	}
	return backend, probes
}

func lolbasPrepared(selector string) engine.Prepared {
	descriptor, _ := catalog.Registry().Get(selector)
	loader := filepath.Join(os.TempDir(), "fixture-loader.dll")
	spec := payload.Spec{Kind: payload.DLL, LocalPath: loader, RemotePath: `C:\Windows\Temp\fixture-loader.dll`, LOLBin: "rundll32.exe", EntryPoint: "ServiceMain"}
	plan, err := delivery.Build(delivery.Request{Kind: delivery.LOLBAS, Invocation: func() technique.InvocationMode { m, _ := descriptor.InvocationFor(payload.DLL); return m }(), Payload: spec})
	if err != nil {
		panic(err)
	}
	return engine.Prepared{Target: "10.10.10.20", Technique: descriptor, Delivery: plan, Payload: spec}
}

func TestPreflightCollectsEvidenceAndCapabilities(t *testing.T) {
	backend, _ := preflightFixture()
	report, err := backend.Preflight(context.Background(), lolbasPrepared("WMIExec"), execCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if report.Target != "10.10.10.20" || report.RunID == "" {
		t.Fatalf("incomplete report: %#v", report)
	}
	caps := report.Capabilities
	if !caps.LocalAdmin || !caps.WMI || !caps.DCOM || !caps.SCM || caps.WinRM {
		t.Fatalf("unexpected capabilities: %#v", caps)
	}
	if !caps.TaskScheduler || caps.RemoteRegistry {
		t.Fatalf("service capabilities wrong: %#v", caps)
	}
	found := map[string]bool{}
	for _, check := range report.Evidence {
		found[check.Name] = check.Passed
	}
	for _, want := range []string{"authentication", "administrative_authorization", "network_surface", "technique_state", "staging_space", "staging_no_collision", "rollback_values_readable"} {
		if _, ok := found[want]; !ok {
			t.Errorf("evidence missing %s", want)
		}
	}
	if len(report.Snapshot.Entries) != 2 {
		t.Fatalf("snapshot = %#v", report.Snapshot.Entries)
	}
}

func TestPreflightServiceTechniqueRecordsSnapshot(t *testing.T) {
	backend, probes := preflightFixture()
	probes.services["Spooler"] = "Stopped"
	probes.images["Spooler"] = `C:\Windows\System32\spoolsv.exe`

	descriptor, _ := catalog.Registry().Get("SCMChangeService")
	spec := payload.Spec{Kind: payload.Service, LocalPath: "svc.exe", RemotePath: `C:\Windows\Temp\svc.exe`}
	plan, err := delivery.Build(delivery.Request{Kind: delivery.Service, Payload: spec, ServiceName: "Spooler"})
	if err != nil {
		t.Fatal(err)
	}
	prepared := engine.Prepared{Target: "wks01", Technique: descriptor, Delivery: plan, Payload: spec}
	report, err := backend.Preflight(context.Background(), prepared, execCredentials)
	if err != nil {
		t.Fatal(err)
	}
	caps := report.Capabilities
	if !caps.ExistingService || !caps.ServiceSnapshot {
		t.Fatalf("service capabilities = %#v", caps)
	}
	var serviceEntry bool
	for _, entry := range report.Snapshot.Entries {
		if entry.Kind == "service_path" && entry.Identifier == "Spooler" && strings.Contains(entry.Original, "spoolsv.exe") {
			serviceEntry = true
		}
	}
	if !serviceEntry {
		t.Fatalf("snapshot = %#v", report.Snapshot.Entries)
	}
}

func TestPreflightUsesConfiguredStagingDirectory(t *testing.T) {
	backend, probes := preflightFixture()
	probes.existing[`D:\Drop`] = true
	descriptor, _ := catalog.Registry().Get("WMIExec")
	deliveryPlan, err := delivery.Build(delivery.Request{
		Kind: delivery.LOLBAS, Invocation: func() technique.InvocationMode { m, _ := descriptor.InvocationFor(payload.DLL); return m }(), Payload: payload.Spec{Kind: payload.DLL, LocalPath: "loader.dll", RemotePath: `D:\Drop\custom.dll`, LOLBin: "rundll32.exe", EntryPoint: "Entry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared := engine.Prepared{Target: "wks01", Technique: descriptor, Delivery: deliveryPlan, Payload: payload.Spec{Kind: payload.DLL}}
	report, err := backend.Preflight(context.Background(), prepared, execCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if probes.diskPath != `D:\Drop` {
		t.Fatalf("disk probe path = %q", probes.diskPath)
	}
	found := false
	for _, entry := range report.Snapshot.Entries {
		if entry.Kind == "staged_file" && entry.Identifier == `D:\Drop\custom.dll` {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom staged path missing from snapshot: %#v", report.Snapshot.Entries)
	}
}

func TestPreflightUsesConfiguredWinRMPort(t *testing.T) {
	backend, _ := preflightFixture()
	var ports []int
	backend.dialPort = func(_ context.Context, _ string, port int) error {
		ports = append(ports, port)
		return nil
	}
	prepared := lolbasPrepared("WSManExec")
	prepared.Runtime = engine.RuntimeOptions{WinRMPort: 8443, WinRMHTTPS: true}
	report, err := backend.Preflight(context.Background(), prepared, execCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ports, []int{8443}) || !report.Capabilities.WinRM {
		t.Fatalf("ports = %v, capabilities = %#v", ports, report.Capabilities)
	}
}

func TestPreflightCommandSkipsStagingChecks(t *testing.T) {
	backend, probes := preflightFixture()
	probes.existing = map[string]bool{}
	var ports []int
	backend.dialPort = func(_ context.Context, _ string, port int) error {
		ports = append(ports, port)
		return nil
	}
	descriptor, _ := catalog.Registry().Get("WMIExec")
	spec := payload.Spec{Kind: payload.Command, Command: `whoami.exe /all`}
	deliveryPlan, err := delivery.Build(delivery.Request{Kind: delivery.LOLBAS, Payload: spec})
	if err != nil {
		t.Fatal(err)
	}
	prepared := engine.Prepared{Target: "wks01", Technique: descriptor, Delivery: deliveryPlan, Payload: spec}
	report, err := backend.Preflight(context.Background(), prepared, execCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ports, []int{135}) || probes.diskPath != "" {
		t.Fatalf("ports = %v, staging disk probe = %q", ports, probes.diskPath)
	}
	for _, check := range report.Evidence {
		if strings.HasPrefix(check.Name, "staging_") {
			t.Fatalf("command preflight emitted staging evidence: %#v", check)
		}
	}
}

func TestPreflightUsesConfiguredMinimumStagingSpace(t *testing.T) {
	backend, probes := preflightFixture()
	probes.free = 1024
	prepared := lolbasPrepared("WMIExec")
	prepared.Runtime.MinStagingBytes = 2048
	_, err := backend.Preflight(context.Background(), prepared, execCredentials)
	if err == nil || !strings.Contains(err.Error(), "insufficient free space") {
		t.Fatalf("expected staging space error, got %v", err)
	}
}

func TestPreflightValidatesCustomLauncherPath(t *testing.T) {
	backend, probes := preflightFixture()
	descriptor, _ := catalog.Registry().Get("WMIExec")
	launcher := `C:\Program Files\Assessment\loader-host.exe`
	spec := payload.Spec{
		Kind: payload.DLL, LocalPath: "loader.dll", RemotePath: `C:\Windows\Temp\loader.dll`, LOLBin: "custom",
		LauncherProgram: launcher, LauncherArguments: `--load {remote_path}`,
	}
	deliveryPlan, err := delivery.Build(delivery.Request{Kind: delivery.LOLBAS, Invocation: func() technique.InvocationMode { m, _ := descriptor.InvocationFor(payload.DLL); return m }(), Payload: spec})
	if err != nil {
		t.Fatal(err)
	}
	prepared := engine.Prepared{Target: "wks01", Technique: descriptor, Delivery: deliveryPlan, Payload: spec}
	if _, err := backend.Preflight(context.Background(), prepared, execCredentials); err == nil || !strings.Contains(err.Error(), "launcher program") {
		t.Fatalf("expected missing launcher program error, got %v", err)
	}
	probes.existing[launcher] = true
	report, err := backend.Preflight(context.Background(), prepared, execCredentials)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, check := range report.Evidence {
		found = found || check.Name == "launcher_program" && check.Passed
	}
	if !found {
		t.Fatalf("launcher program evidence missing: %#v", report.Evidence)
	}
}

func TestMutationRequestUsesResolvedCustomLauncher(t *testing.T) {
	descriptor, _ := catalog.Registry().Get("WMIExec")
	localPath := filepath.Join(t.TempDir(), "loader.dll")
	if err := os.WriteFile(localPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := payload.Spec{
		Kind: payload.DLL, LocalPath: localPath, RemotePath: `D:\Stage Area\loader.dll`, LOLBin: "custom",
		LauncherProgram: `D:\Approved Tools\loader-host.exe`, LauncherArguments: `--load {remote_path}`,
	}
	deliveryPlan, err := delivery.Build(delivery.Request{Kind: delivery.LOLBAS, Invocation: func() technique.InvocationMode { m, _ := descriptor.InvocationFor(payload.DLL); return m }(), Payload: spec})
	if err != nil {
		t.Fatal(err)
	}
	request, err := (Backend{}).mutationRequest(engine.Prepared{
		Target: "wks01", Technique: descriptor, Delivery: deliveryPlan, Payload: spec,
		Report: engine.PreflightReport{RunID: "custom-launcher-run"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `"D:\Approved Tools\loader-host.exe" --load "D:\Stage Area\loader.dll"`
	if request.LoaderCommand != want {
		t.Fatalf("loader command = %q, want %q", request.LoaderCommand, want)
	}
}

func TestPreflightRejectsMissingStagingDirectory(t *testing.T) {
	backend, probes := preflightFixture()
	delete(probes.existing, testRemoteDirectory)
	_, err := backend.Preflight(context.Background(), lolbasPrepared("WMIExec"), execCredentials)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing staging directory error, got %v", err)
	}
}

func TestPreflightClassifiesFailures(t *testing.T) {
	backend, probes := preflightFixture()
	probes.authErr = errs.New(errs.Authentication, "bad password")
	_, err := backend.Preflight(context.Background(), lolbasPrepared("WMIExec"), execCredentials)
	if err == nil || errs.CategoryOf(err) != errs.Authentication {
		t.Fatalf("expected authentication classification, got %v", err)
	}

	backend, probes = preflightFixture()
	probes.admin = false
	_, err = backend.Preflight(context.Background(), lolbasPrepared("WMIExec"), execCredentials)
	if err == nil || errs.CategoryOf(err) != errs.Authorization {
		t.Fatalf("expected authorization classification, got %v", err)
	}

	backend, _ = preflightFixture()
	backend.dialPort = func(context.Context, string, int) error { return errors.New("refused") }
	_, err = backend.Preflight(context.Background(), lolbasPrepared("WMIExec"), execCredentials)
	if err == nil || errs.CategoryOf(err) != errs.Reachability {
		t.Fatalf("expected reachability classification, got %v", err)
	}
}

func TestPreflightRejectsCollisionAndMissingService(t *testing.T) {
	backend, probes := preflightFixture()
	probes.globbed = []string{"remoteexec-verify-leftover.marker"}
	_, err := backend.Preflight(context.Background(), lolbasPrepared("WMIExec"), execCredentials)
	if err == nil || errs.CategoryOf(err) != errs.Conflict {
		t.Fatalf("expected conflict classification, got %v", err)
	}

	backend, probes = preflightFixture()
	_, err = backend.Preflight(context.Background(), servicePrepared("SCMChangeService"), execCredentials)
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("expected missing service failure, got %v", err)
	}
}

func TestPreflightSCMCreateServiceRequiresUnusedName(t *testing.T) {
	backend, probes := preflightFixture()
	descriptor, _ := catalog.Registry().Get("SCMCreateService")
	spec := payload.Spec{Kind: payload.Service, LocalPath: "svc.exe", RemotePath: `C:\Windows\Temp\svc.exe`}
	deliveryPlan, err := delivery.Build(delivery.Request{Kind: delivery.ServiceCreate, Payload: spec, ServiceName: "RemoteExecTmp"})
	if err != nil {
		t.Fatal(err)
	}
	prepared := engine.Prepared{Target: "wks01", Technique: descriptor, Delivery: deliveryPlan, Payload: spec}
	if _, err := backend.Preflight(context.Background(), prepared, execCredentials); err != nil {
		t.Fatalf("unused service name rejected: %v", err)
	}
	probes.services["RemoteExecTmp"] = "Stopped"
	if _, err := backend.Preflight(context.Background(), prepared, execCredentials); err == nil || errs.CategoryOf(err) != errs.Conflict {
		t.Fatalf("expected service collision, got %v", err)
	}
}

func servicePrepared(selector string) engine.Prepared {
	descriptor, _ := catalog.Registry().Get(selector)
	spec := payload.Spec{Kind: payload.Service, LocalPath: "svc.exe", RemotePath: `C:\Windows\Temp\svc.exe`}
	plan, err := delivery.Build(delivery.Request{Kind: delivery.Service, Payload: spec, ServiceName: "Spooler"})
	if err != nil {
		panic(err)
	}
	return engine.Prepared{Target: "wks01", Technique: descriptor, Delivery: plan, Payload: spec}
}

type txSession struct {
	files       map[string][]byte
	nextPID     uint32
	processes   map[uint32]string
	tasks       map[string]bool
	providers   map[string]bool
	providerCOM map[string]string
	services    map[string]adapter.ServiceConfig
}

func newTxSession() *txSession {
	return &txSession{files: map[string][]byte{}, nextPID: 5000, processes: map[uint32]string{}, tasks: map[string]bool{}, providers: map[string]bool{}, providerCOM: map[string]string{}, services: map[string]adapter.ServiceConfig{}}
}

func (s *txSession) WriteFile(_ context.Context, path string, content []byte) (string, error) {
	s.files[path] = content
	return adapter.Digest(content), nil
}

func (s *txSession) ReadFile(_ context.Context, path string) ([]byte, error) {
	content, ok := s.files[path]
	if !ok {
		return nil, errors.New("missing " + path)
	}
	return content, nil
}

func (s *txSession) RemoveFile(_ context.Context, path string) error {
	delete(s.files, path)
	return nil
}

func (s *txSession) FileExists(_ context.Context, path string) (bool, error) {
	_, ok := s.files[path]
	return ok, nil
}

func (s *txSession) Glob(context.Context, string) ([]string, error) { return nil, nil }

func (s *txSession) ProcessCreate(_ context.Context, commandLine string) (uint32, error) {
	s.nextPID++
	s.processes[s.nextPID] = commandLine
	return s.nextPID, nil
}

func (s *txSession) ProcessStart(context.Context, string, string) (uint32, error) {
	return 0, errors.New("unused")
}

func (s *txSession) ShellExecute(context.Context, string, string) error { return errors.New("unused") }

func (s *txSession) ShellAvailable(context.Context) error { return nil }

func (s *txSession) ProcessFind(context.Context, string, string) ([]uint32, error) {
	return nil, nil
}

func (s *txSession) ProcessExists(_ context.Context, pid uint32) (bool, error) {
	_, ok := s.processes[pid]
	return ok, nil
}

func (s *txSession) ProcessImage(context.Context, uint32) (string, error) {
	return "", errors.New("unused")
}

func (s *txSession) ServiceGet(_ context.Context, name string) (adapter.ServiceConfig, error) {
	config, ok := s.services[name]
	if !ok {
		return adapter.ServiceConfig{}, errors.New("absent service " + name)
	}
	return config, nil
}

func (s *txSession) ServiceExists(_ context.Context, name string) (bool, error) {
	_, ok := s.services[name]
	return ok, nil
}

func (s *txSession) ServiceCreate(_ context.Context, name, pathName string) error {
	s.services[name] = adapter.ServiceConfig{Name: name, PathName: pathName, StartMode: "Manual", State: "Stopped"}
	return nil
}

func (s *txSession) ServiceDelete(_ context.Context, name string) error {
	delete(s.services, name)
	return nil
}

func (s *txSession) ServiceChangePath(_ context.Context, name, pathName string, _ adapter.Mechanism) error {
	config := s.services[name]
	config.PathName = pathName
	s.services[name] = config
	return nil
}

func (s *txSession) ServiceStart(_ context.Context, name string, _ adapter.Mechanism) error {
	config := s.services[name]
	config.State = "Running"
	s.services[name] = config
	return nil
}

func (s *txSession) ServiceStop(_ context.Context, name string, _ adapter.Mechanism) error {
	config := s.services[name]
	config.State = "Stopped"
	s.services[name] = config
	return nil
}

func (s *txSession) TaskCreate(_ context.Context, name, _, _ string) error {
	s.tasks[name] = true
	return nil
}

func (s *txSession) TaskRun(context.Context, string) error { return nil }

func (s *txSession) TaskDelete(_ context.Context, name string) error {
	delete(s.tasks, name)
	return nil
}

func (s *txSession) TaskExists(_ context.Context, name string) (bool, error) {
	return s.tasks[name], nil
}

func (s *txSession) ProviderRegister(_ context.Context, name, _ string) error {
	s.providers[name] = true
	return nil
}

func (s *txSession) ProviderDelete(_ context.Context, name string) error {
	delete(s.providers, name)
	return nil
}

func (s *txSession) ProviderExists(_ context.Context, name string) (bool, error) {
	return s.providers[name], nil
}

func (s *txSession) ProviderCOMRegister(_ context.Context, clsid, dllPath string) error {
	s.providerCOM[clsid] = dllPath
	return nil
}

func (s *txSession) ProviderCOMDelete(_ context.Context, clsid string) error {
	delete(s.providerCOM, clsid)
	return nil
}

func (s *txSession) ProviderCOMExists(_ context.Context, clsid string) (bool, error) {
	_, ok := s.providerCOM[clsid]
	return ok, nil
}

func (s *txSession) ProviderLoad(context.Context, string, string) error   { return nil }
func (s *txSession) ProviderUnload(context.Context, string, string) error { return nil }

func mutationFixture(t *testing.T, selector string) (Backend, engine.Prepared, *txSession, journal.Journal) {
	t.Helper()
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	jrn := journal.NewMemory(func() time.Time { return fixed })
	descriptor, _ := catalog.Registry().Get(selector)
	payloadPath := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(payloadPath, []byte("payload-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := payload.Spec{Kind: payload.DLL, LocalPath: payloadPath, RemotePath: `C:\Windows\Temp\fixture.dll`, LOLBin: "rundll32.exe", EntryPoint: "ServiceMain"}
	plan, err := delivery.Build(delivery.Request{Kind: delivery.LOLBAS, Invocation: func() technique.InvocationMode { m, _ := descriptor.InvocationFor(payload.DLL); return m }(), Payload: spec})
	if err != nil {
		t.Fatal(err)
	}
	prepared := engine.Prepared{
		Target:    "wks01",
		Technique: descriptor,
		Delivery:  plan,
		Auth:      engine.AuthCredential,
		Payload:   spec,
		Report:    engine.PreflightReport{RunID: "deadbeefdeadbeef"},
	}
	backend := Backend{}
	return backend, prepared, newTxSession(), jrn
}

func TestRunMutationDispatchesAndRollsBack(t *testing.T) {
	backend, prepared, session, jrn := mutationFixture(t, "WMIExec")
	ctx := shortExecContext(t)
	artifacts, err := backend.runMutation(ctx, prepared, session, jrn)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("artifacts = %#v", artifacts)
	}
	entries, err := jrn.Entries(ctx, prepared.Report.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("journal events = %d, want 4", len(entries))
	}
	session.processes = map[uint32]string{}
	if err := backend.rollbackMutation(ctx, prepared, session, jrn, artifacts); err != nil {
		t.Fatal(err)
	}
	if len(session.files) != 0 {
		t.Fatalf("files left behind: %v", session.files)
	}
	entries, _ = jrn.Entries(ctx, prepared.Report.RunID)
	for _, entry := range entries {
		if journal.CurrentState(entries, entry.Sequence) == journal.StateRollbackFailed {
			t.Fatal("rollback recorded a failure")
		}
	}
}

func TestRunMutationRejectsUnknownTechnique(t *testing.T) {
	backend, prepared, session, jrn := mutationFixture(t, "WMIExec")
	prepared.Technique.Name = "NoSuchTechnique"
	if _, err := backend.runMutation(shortExecContext(t), prepared, session, jrn); err == nil {
		t.Fatal("unknown technique must be rejected")
	}
}

func TestRollbackMutationMarksFailures(t *testing.T) {
	backend, prepared, session, jrn := mutationFixture(t, "WMIExec")
	ctx := shortExecContext(t)
	artifacts, err := backend.runMutation(ctx, prepared, session, jrn)
	if err != nil {
		t.Fatal(err)
	}
	staged := artifacts[0].Location
	session.files[staged] = []byte("tampered by someone else")
	if err := backend.rollbackMutation(ctx, prepared, session, jrn, artifacts); err == nil {
		t.Fatal("expected conflict")
	}
	entries, _ := jrn.Entries(ctx, prepared.Report.RunID)
	for _, entry := range entries {
		if entry.Mutation != "" && entry.Identifier == staged {
			if state := journal.CurrentState(entries, entry.Sequence); state != journal.StateRollbackFailed {
				t.Fatalf("staged entry state = %q, want rollback_failed", state)
			}
		}
	}
}

func TestSecretsNeverReachJournal(t *testing.T) {
	backend, prepared, session, jrn := mutationFixture(t, "WMIExec")
	ctx := shortExecContext(t)
	artifacts, err := backend.runMutation(ctx, prepared, session, jrn)
	if err != nil {
		t.Fatal(err)
	}
	session.processes = map[uint32]string{}
	if err := backend.rollbackMutation(ctx, prepared, session, jrn, artifacts); err != nil {
		t.Fatal(err)
	}
	entries, err := jrn.Entries(ctx, prepared.Report.RunID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), execCredentials.Password) {
		t.Fatal("secret found in journal")
	}
}

func TestArtifactsCarryRecoveryGuidance(t *testing.T) {
	backend, prepared, session, jrn := mutationFixture(t, "TaskSchedExec")
	artifacts, err := backend.runMutation(shortExecContext(t), prepared, session, jrn)
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range artifacts {
		if artifact.Recovery == "" {
			t.Fatalf("artifact %s lacks manual recovery guidance", artifact.Location)
		}
	}
}

func TestArtifactsCanBeRecoveredFromPreparedJournalEvents(t *testing.T) {
	entries := []journal.Entry{
		{Sequence: 1, ArtifactKind: "staged_file", Identifier: `C:\Windows\Temp\fixture.dll`, Mutation: "stage payload"},
		{Sequence: 1, State: journal.StateApplied},
		{Sequence: 2, ArtifactKind: "process_invocation", Identifier: "launcher:sha256:abc", Location: `C:\Windows\Temp\fixture.dll`, InvocationID: "launcher:sha256:abc", Program: "rundll32.exe", Mutation: "invoke loader"},
	}
	artifacts := artifactsFromJournal(entries)
	if len(artifacts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(artifacts))
	}
	if artifacts[0].Kind != "staged_file" || artifacts[1].Kind != "process_invocation" {
		t.Fatalf("unexpected artifacts: %#v", artifacts)
	}
	if artifacts[1].Location != `C:\Windows\Temp\fixture.dll` || artifacts[1].Program != "rundll32.exe" || artifacts[1].InvocationID != "launcher:sha256:abc" {
		t.Fatalf("process recovery artifact = %#v", artifacts[1])
	}
}
