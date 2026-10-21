package technique

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/windows/catalog"
)

func TestRegistryValidation(t *testing.T) {
	valid := Registration{Selector: VerifyMarkerSelector, Adapter: VerifyMarker{}, Recovery: "Remove the verification marker"}
	if _, err := NewRegistry(valid); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegistry(Registration{Selector: "Orphan", Recovery: "c"}); err == nil {
		t.Error("missing adapter accepted")
	}
	if _, err := NewRegistry(Registration{Selector: VerifyMarkerSelector, Adapter: VerifyMarker{}}); err == nil {
		t.Error("incomplete recovery metadata accepted")
	}
	if _, err := NewRegistry(Registration{Selector: "Other", Adapter: VerifyMarker{}, Recovery: "c"}); err == nil {
		t.Error("adapter name and selector mismatch accepted")
	}
	if _, err := NewRegistry(Registration{Selector: "1bad", Adapter: VerifyMarker{}, Recovery: "c"}); err == nil {
		t.Error("invalid selector accepted")
	}
	if _, err := NewRegistry(valid, valid); err == nil {
		t.Error("duplicate selector accepted")
	}
}

func TestEveryRegisteredTechniqueHasAdapter(t *testing.T) {
	mutations, err := Mutations()
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range catalog.Registry().List() {
		registration, ok := mutations.Get(descriptor.Name)
		if !ok {
			t.Errorf("no mutation adapter registered for %s", descriptor.Name)
			continue
		}
		if registration.Adapter.Name() != descriptor.Name {
			t.Errorf("adapter name %q does not match selector %q", registration.Adapter.Name(), descriptor.Name)
		}
		if registration.Recovery == "" {
			t.Errorf("adapter %s has incomplete recovery metadata", descriptor.Name)
		}
	}
}

type fakeJournal struct {
	entries []journal.Entry
	seq     uint64
}

func (j *fakeJournal) Append(_ context.Context, entry journal.Entry) (journal.Entry, error) {
	j.seq++
	entry.Sequence = j.seq
	entry.State = journal.StatePrepared
	j.entries = append(j.entries, entry)
	return entry, nil
}

func (j *fakeJournal) UpdateState(_ context.Context, runID string, sequence uint64, state journal.State) error {
	j.entries = append(j.entries, journal.Entry{RunID: runID, Sequence: sequence, State: state})
	return nil
}

func (j *fakeJournal) snapshot() RecoverySnapshot {
	var snapshot RecoverySnapshot
	seen := map[uint64]bool{}
	for _, entry := range j.entries {
		if entry.Mutation == "" || seen[entry.Sequence] {
			continue
		}
		seen[entry.Sequence] = true
		snapshot.Entries = append(snapshot.Entries, engineSnapshotEntry{
			Kind: entry.ArtifactKind, Identifier: entry.Identifier, Original: entry.Original, Digest: entry.Digest,
		}.toEngine())
	}
	return snapshot
}

type fakeSession struct {
	files        map[string][]byte
	writeErr     error
	nextPID      uint32
	processes    map[uint32]string
	startPIDZero bool
	services     map[string]ServiceConfig
	tasks        map[string]bool
	providers    map[string]bool
	providerCOM  map[string]string
	shells       []string
	shellErr     error
	taskRuns     int
}

func newFakeSession() *fakeSession {
	return &fakeSession{
		files:       map[string][]byte{},
		nextPID:     1000,
		processes:   map[uint32]string{},
		services:    map[string]ServiceConfig{},
		tasks:       map[string]bool{},
		providers:   map[string]bool{},
		providerCOM: map[string]string{},
	}
}

func (s *fakeSession) WriteFile(_ context.Context, path string, content []byte) (string, error) {
	if s.writeErr != nil {
		return "", s.writeErr
	}
	s.files[path] = content
	return Digest(content), nil
}

func (s *fakeSession) ReadFile(_ context.Context, path string) ([]byte, error) {
	content, ok := s.files[path]
	if !ok {
		return nil, errMissing(path)
	}
	return content, nil
}

func (s *fakeSession) RemoveFile(_ context.Context, path string) error {
	delete(s.files, path)
	return nil
}

func (s *fakeSession) FileExists(_ context.Context, path string) (bool, error) {
	_, ok := s.files[path]
	return ok, nil
}

func (s *fakeSession) Glob(_ context.Context, pattern string) ([]string, error) {
	parts := strings.SplitN(pattern, "*", 2)
	if len(parts) != 2 {
		return nil, nil
	}
	var out []string
	for path := range s.files {
		if strings.HasPrefix(path, parts[0]) && strings.HasSuffix(path, parts[1]) {
			out = append(out, path)
		}
	}
	return out, nil
}

func (s *fakeSession) ProcessCreate(_ context.Context, commandLine string) (uint32, error) {
	s.nextPID++
	s.processes[s.nextPID] = commandLine
	return s.nextPID, nil
}

func (s *fakeSession) ProcessStart(_ context.Context, path, args string) (uint32, error) {
	if s.startPIDZero {
		s.processes[0] = path + " " + args
		s.processes[7] = path + " " + args
		return 0, nil
	}
	s.nextPID++
	s.processes[s.nextPID] = path + " " + args
	return s.nextPID, nil
}

func (s *fakeSession) ShellExecute(_ context.Context, path, args string) error {
	s.shells = append(s.shells, path+" "+args)
	s.processes[9] = path + " " + args
	return nil
}

func (s *fakeSession) ShellAvailable(context.Context) error { return s.shellErr }

func (s *fakeSession) ProcessFind(_ context.Context, imageName, contains string) ([]uint32, error) {
	var out []uint32
	for pid, commandLine := range s.processes {
		if pid == 0 {
			continue
		}
		if imageOfCommand(commandLine) != imageName {
			continue
		}
		if contains != "" && !strings.Contains(commandLine, contains) {
			continue
		}
		out = append(out, pid)
	}
	return out, nil
}

func (s *fakeSession) ProcessExists(_ context.Context, pid uint32) (bool, error) {
	_, ok := s.processes[pid]
	return ok, nil
}

func (s *fakeSession) ProcessImage(_ context.Context, pid uint32) (string, error) {
	command, ok := s.processes[pid]
	if !ok {
		return "", errMissing(fmt.Sprintf("process %d", pid))
	}
	image, _ := splitCommand(command)
	return image, nil
}

func TestDCOMPreflightRequiresAccessibleShellAutomation(t *testing.T) {
	session := newFakeSession()
	session.shellErr = errors.New("access denied")
	_, _, err := (DCOMShellExecute{}).Preflight(context.Background(), session, commandRequest("DCOMIShellDispatch2"))
	if err == nil || !strings.Contains(err.Error(), "shell automation interface") {
		t.Fatalf("expected actionable shell automation error, got %v", err)
	}
}

func (s *fakeSession) ServiceGet(_ context.Context, name string) (ServiceConfig, error) {
	config, ok := s.services[name]
	if !ok {
		return ServiceConfig{}, errMissing(name)
	}
	return config, nil
}

func (s *fakeSession) ServiceExists(_ context.Context, name string) (bool, error) {
	_, ok := s.services[name]
	return ok, nil
}

func (s *fakeSession) ServiceCreate(_ context.Context, name, pathName string) error {
	if _, exists := s.services[name]; exists {
		return errors.New("service exists")
	}
	s.services[name] = ServiceConfig{Name: name, DisplayName: name, PathName: pathName, StartMode: "Manual", State: "Stopped"}
	return nil
}

func (s *fakeSession) ServiceDelete(_ context.Context, name string) error {
	delete(s.services, name)
	return nil
}

func (s *fakeSession) ServiceChangePath(_ context.Context, name, pathName string, _ Mechanism) error {
	config := s.services[name]
	config.PathName = pathName
	s.services[name] = config
	return nil
}

func (s *fakeSession) ServiceStart(_ context.Context, name string, _ Mechanism) error {
	config := s.services[name]
	config.State = "Running"
	s.services[name] = config
	return nil
}

func (s *fakeSession) ServiceStop(_ context.Context, name string, _ Mechanism) error {
	config := s.services[name]
	config.State = "Stopped"
	s.services[name] = config
	return nil
}

func (s *fakeSession) TaskCreate(_ context.Context, name, _, _ string) error {
	s.tasks[name] = true
	return nil
}

func (s *fakeSession) TaskRun(_ context.Context, name string) error {
	if !s.tasks[name] {
		return errMissing(name)
	}
	s.taskRuns++
	return nil
}

func (s *fakeSession) TaskDelete(_ context.Context, name string) error {
	delete(s.tasks, name)
	return nil
}

func (s *fakeSession) TaskExists(_ context.Context, name string) (bool, error) {
	return s.tasks[name], nil
}

func (s *fakeSession) ProviderRegister(_ context.Context, name, _ string) error {
	s.providers[name] = true
	return nil
}

func (s *fakeSession) ProviderDelete(_ context.Context, name string) error {
	delete(s.providers, name)
	return nil
}

func (s *fakeSession) ProviderExists(_ context.Context, name string) (bool, error) {
	return s.providers[name], nil
}

func (s *fakeSession) ProviderCOMRegister(_ context.Context, clsid, dllPath string) error {
	s.providerCOM[clsid] = dllPath
	return nil
}

func (s *fakeSession) ProviderCOMDelete(_ context.Context, clsid string) error {
	delete(s.providerCOM, clsid)
	return nil
}

func (s *fakeSession) ProviderCOMExists(_ context.Context, clsid string) (bool, error) {
	_, ok := s.providerCOM[clsid]
	return ok, nil
}

func (s *fakeSession) ProviderLoad(context.Context, string, string) error   { return nil }
func (s *fakeSession) ProviderUnload(context.Context, string, string) error { return nil }

// exited removes every process, simulating natural loader exit.
func (s *fakeSession) exited() {
	s.processes = map[uint32]string{}
}

func fixtureRequest(selector string) Request {
	descriptor, _ := catalog.Registry().Get(selector)
	return Request{
		RunID:         "run123",
		Target:        "wks01",
		Technique:     descriptor,
		StagingRoot:   `C:\Windows\Temp`,
		StagedPath:    `C:\Windows\Temp\loader.dll`,
		Payload:       []byte("loader-bytes"),
		PayloadKind:   payload.DLL,
		Digest:        Digest([]byte("loader-bytes")),
		Export:        "ServiceMain",
		LoaderCommand: `rundll32.exe C:\Windows\Temp\loader.dll,ServiceMain`,
	}
}

func commandRequest(selector string) Request {
	descriptor, _ := catalog.Registry().Get(selector)
	return Request{
		RunID: "run123", Target: "wks01", Technique: descriptor,
		PayloadKind: payload.Command, Command: `cmd.exe /c whoami.exe /all`,
	}
}

func TestDirectCommandAdaptersDoNotStageFiles(t *testing.T) {
	tests := []struct {
		name    string
		adapter Adapter
	}{
		{name: "WMIExec", adapter: WMIExec{}},
		{name: "WSManExec", adapter: WSManExec{}},
		{name: "DCOMIShellDispatch2", adapter: DCOMShellExecute{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := shortContext(t)
			session := newFakeSession()
			j := &fakeJournal{}
			req := commandRequest(test.name)
			if _, _, err := test.adapter.Preflight(ctx, session, req); err != nil {
				t.Fatal(err)
			}
			artifacts, err := test.adapter.Apply(ctx, session, req, j)
			if err != nil {
				t.Fatal(err)
			}
			if len(artifacts) != 1 || artifacts[0].Kind != kindProcess || len(session.files) != 0 {
				t.Fatalf("artifacts = %#v, files = %v", artifacts, session.files)
			}
			if strings.Contains(artifacts[0].Location, "whoami") {
				t.Fatalf("command leaked into result artifact: %#v", artifacts[0])
			}
			for _, entry := range j.entries {
				if strings.Contains(entry.Identifier, "whoami") {
					t.Fatalf("command leaked into journal entry: %#v", entry)
				}
			}
			if err := test.adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProcessBoundLauncherPreflightRequiresExistingPID(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	req := fixtureRequest("WMIExec")
	req.ProcessID = 4242
	if _, _, err := (WMIExec{}).Preflight(ctx, session, req); err == nil {
		t.Fatal("expected missing process validation error")
	}
	session.processes[4242] = `C:\Tools\disposable.exe`
	session.files[`C:\Tools\disposable.exe`] = peFixture(0x8664)
	req.Payload = peFixture(0x8664)
	evidence, _, err := (WMIExec{}).Preflight(ctx, session, req)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, check := range evidence {
		found = found || check.Name == "launcher_process" && check.Passed
	}
	if !found {
		t.Fatal("expected successful launcher_process evidence")
	}
}

func TestProcessBoundLauncherPreflightRejectsArchitectureMismatch(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	req := fixtureRequest("WMIExec")
	req.ProcessID = 4242
	req.Payload = peFixture(0x014c)
	session.processes[4242] = `C:\Tools\disposable.exe`
	session.files[`C:\Tools\disposable.exe`] = peFixture(0x8664)
	_, _, err := (WMIExec{}).Preflight(ctx, session, req)
	if err == nil || !strings.Contains(err.Error(), "does not match") || !strings.Contains(err.Error(), "x86") || !strings.Contains(err.Error(), "x64") {
		t.Fatalf("expected actionable architecture mismatch, got %v", err)
	}
}

func peFixture(machine uint16) []byte {
	content := make([]byte, 0x86)
	content[0], content[1] = 'M', 'Z'
	content[0x3c] = 0x80
	copy(content[0x80:], []byte{'P', 'E', 0, 0})
	content[0x84] = byte(machine)
	content[0x85] = byte(machine >> 8)
	return content
}

func TestTaskSchedDirectCommandDeletesTaskWithoutStaging(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	req := commandRequest("TaskSchedExec")
	adapter := TaskSchedExec{}
	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 || len(session.files) != 0 {
		t.Fatalf("artifacts = %#v, files = %v", artifacts, session.files)
	}
	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
	if session.tasks["remoteexec-run123"] {
		t.Fatal("temporary task was not deleted")
	}
}

func journalStates(t *testing.T, j *fakeJournal) map[uint64]journal.State {
	t.Helper()
	states := map[uint64]journal.State{}
	for _, entry := range j.entries {
		states[entry.Sequence] = entry.State
	}
	return states
}

func TestWMIExecApplyRollback(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	adapter := WMIExec{}
	req := fixtureRequest("WMIExec")

	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 || artifacts[0].Kind != "staged_file" || artifacts[1].Kind != "process_invocation" {
		t.Fatalf("artifacts = %#v", artifacts)
	}
	process := artifacts[1]
	if process.Location != req.StagedPath || process.Program != "rundll32.exe" || !strings.HasPrefix(process.InvocationID, "launcher:sha256:") || process.ProcessID == 0 {
		t.Fatalf("process artifact = %#v", process)
	}
	if strings.Contains(process.InvocationID+process.Recovery, "ServiceMain") {
		t.Fatalf("launcher arguments leaked into artifact: %#v", process)
	}
	if len(j.entries) != 4 {
		t.Fatalf("journal events = %d, want 4", len(j.entries))
	}
	for sequence, state := range journalStates(t, j) {
		if state != journal.StateApplied {
			t.Fatalf("journal sequence %d state = %q", sequence, state)
		}
	}

	session.exited()
	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
	if len(session.files) != 0 {
		t.Fatalf("files left behind: %v", session.files)
	}
}

func TestProcessBoundInvocationReturnsRecoveryContext(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	req := fixtureRequest("WMIExec")
	req.ProcessID = 4242
	req.LoaderCommand = `mavinject.exe 4242 /INJECTRUNNING C:\Windows\Temp\loader.dll`
	artifacts, err := (WMIExec{}).Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	process := artifacts[len(artifacts)-1]
	if process.RelatedProcessID != 4242 || !strings.Contains(process.Recovery, "cannot be generically reversed") || strings.Contains(process.Recovery, "/INJECTRUNNING") {
		t.Fatalf("process recovery context = %#v", process)
	}
}

func TestLauncherArgumentsNeverReachArtifactOrJournal(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	req := fixtureRequest("WMIExec")
	req.LoaderCommand = `C:\Tools\runner.exe --token topsecret --load C:\Windows\Temp\loader.dll`
	artifacts, err := (WMIExec{}).Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(struct {
		Artifacts []model.Artifact
		Journal   []journal.Entry
	}{Artifacts: artifacts, Journal: j.entries})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "topsecret") || strings.Contains(string(encoded), "--load") {
		t.Fatalf("launcher arguments leaked into recovery record: %s", encoded)
	}
	process := artifacts[len(artifacts)-1]
	if process.Program != "runner.exe" || process.Location != req.StagedPath || !strings.HasPrefix(process.InvocationID, "launcher:sha256:") {
		t.Fatalf("process artifact = %#v", process)
	}
}

func TestWMIExecExecutableApplyRollback(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	req := fixtureRequest("WMIExec")
	req.PayloadKind = payload.Executable
	req.StagedPath = `C:\Windows\Temp\agent.exe`
	req.Arguments = "--check --verbose"
	artifacts, err := (WMIExec{}).Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 || artifacts[1].Location != `C:\Windows\Temp\agent.exe` {
		t.Fatalf("artifacts = %#v", artifacts)
	}
	session.exited()
	if err := (WMIExec{}).Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
}

func TestSCMCreateServiceApplyRollback(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	req := serviceFixtureRequest("SCMCreateService")
	req.StagedPath = `C:\Program Data\Remote Exec\svc.exe`
	req.ServiceName = "RemoteExecTmp"
	adapter := SCMCreateService{}
	if _, _, err := adapter.Preflight(ctx, session, req); err != nil {
		t.Fatal(err)
	}
	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("artifacts = %#v", artifacts)
	}
	created, exists := session.services[req.ServiceName]
	if !exists {
		t.Fatal("temporary service was not created")
	}
	if created.PathName != `"C:\Program Data\Remote Exec\svc.exe"` {
		t.Fatalf("service image path = %q", created.PathName)
	}
	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
	if _, exists := session.services[req.ServiceName]; exists || len(session.files) != 0 {
		t.Fatalf("cleanup left service=%t files=%v", exists, session.files)
	}
	session.services[req.ServiceName] = ServiceConfig{Name: req.ServiceName, State: "Stopped"}
	if _, _, err := adapter.Preflight(ctx, session, req); err == nil {
		t.Fatal("existing temporary service name was accepted")
	}
}

func TestWMIExecRollbackRefusesRunningProcess(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	adapter := WMIExec{}
	req := fixtureRequest("WMIExec")
	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.Rollback(ctx, session, j.snapshot(), artifacts)
	if err == nil || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("expected still-running failure, got %v", err)
	}
	if len(session.files) == 0 {
		t.Fatal("staged file must not be removed while the loader runs")
	}
}

func TestWMIExecRollbackDetectsTampering(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	adapter := WMIExec{}
	req := fixtureRequest("WMIExec")
	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	session.files[req.StagedPath] = []byte("tampered")
	session.exited()
	err = adapter.Rollback(ctx, session, j.snapshot(), artifacts)
	if err == nil || !strings.Contains(err.Error(), "third-party") {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestWSManExecAcceptsNativeCommandWithoutPID(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	session.startPIDZero = true
	j := &fakeJournal{}
	adapter := WSManExec{}
	req := fixtureRequest("WSManExec")

	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("artifacts = %#v", artifacts)
	}
	session.exited()
	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
}

func TestDCOMShellExecuteApplyRollback(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	adapter := DCOMShellExecute{}
	req := fixtureRequest("DCOMIShellDispatch2")
	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.shells) != 1 {
		t.Fatalf("shell invocations = %v", session.shells)
	}
	session.exited()
	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
}

func TestTaskSchedExecApplyRollback(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	adapter := TaskSchedExec{}
	req := fixtureRequest("TaskSchedExec")

	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 3 {
		t.Fatalf("artifacts = %#v", artifacts)
	}
	if artifacts[1].Kind != "scheduled_task" || artifacts[1].Location != "remoteexec-run123" {
		t.Fatalf("task artifact = %#v", artifacts[1])
	}
	if session.taskRuns != 1 {
		t.Fatalf("task runs = %d", session.taskRuns)
	}
	session.exited()
	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
	if session.tasks["remoteexec-run123"] {
		t.Fatal("task was not deleted")
	}
	if len(session.files) != 0 {
		t.Fatalf("files left behind: %v", session.files)
	}
}

func serviceFixtureRequest(selector string) Request {
	req := fixtureRequest(selector)
	req.StagedPath = `C:\Windows\Temp\svc.exe`
	req.Payload = []byte("service-bytes")
	req.Digest = Digest([]byte("service-bytes"))
	req.ServiceName = "Spooler"
	req.LoaderCommand = ""
	return req
}

func serviceFakeSession() *fakeSession {
	session := newFakeSession()
	session.services["Spooler"] = ServiceConfig{
		Name: "Spooler", DisplayName: "Print Spooler", PathName: `C:\Windows\System32\spoolsv.exe`,
		StartMode: "Auto", StartName: "LocalSystem", State: "Stopped",
	}
	return session
}

func TestServiceAdapterApplyRollbackSCM(t *testing.T) {
	ctx := shortContext(t)
	session := serviceFakeSession()
	j := &fakeJournal{}
	adapter := ServiceAdapter{NameValue: "SCMChangeService", Mechanism: MechanismSCM}
	req := serviceFixtureRequest("SCMChangeService")

	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 3 {
		t.Fatalf("artifacts = %#v", artifacts)
	}
	config := session.services["Spooler"]
	if config.PathName != serviceImagePath(req.StagedPath) || config.State != "Running" {
		t.Fatalf("service after apply = %#v", config)
	}
	var servicePathEntry journal.Entry
	for _, entry := range j.entries {
		if entry.ArtifactKind == "service_path" {
			servicePathEntry = entry
		}
	}
	if !strings.Contains(servicePathEntry.Original, "spoolsv.exe") {
		t.Fatalf("snapshot missing original path: %q", servicePathEntry.Original)
	}

	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
	config = session.services["Spooler"]
	if config.PathName != `C:\Windows\System32\spoolsv.exe` || config.State != "Stopped" {
		t.Fatalf("service after rollback = %#v", config)
	}
	if len(session.files) != 0 {
		t.Fatalf("files left behind: %v", session.files)
	}
}

func TestServiceAdapterRollbackIsIdempotent(t *testing.T) {
	ctx := shortContext(t)
	session := serviceFakeSession()
	j := &fakeJournal{}
	adapter := ServiceAdapter{NameValue: "WMIService", Mechanism: MechanismWMI}
	req := serviceFixtureRequest("WMIService")
	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal("repeat rollback must be a no-op")
	}
}

func TestServiceAdapterRollbackDetectsThirdPartyChange(t *testing.T) {
	ctx := shortContext(t)
	session := serviceFakeSession()
	j := &fakeJournal{}
	adapter := ServiceAdapter{NameValue: "SCMChangeService", Mechanism: MechanismSCM}
	req := serviceFixtureRequest("SCMChangeService")
	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	config := session.services["Spooler"]
	config.PathName = `C:\Windows\evil.exe`
	session.services["Spooler"] = config

	err = adapter.Rollback(ctx, session, j.snapshot(), artifacts)
	if err == nil || !strings.Contains(err.Error(), "third-party") {
		t.Fatalf("expected conflict, got %v", err)
	}
	if session.services["Spooler"].PathName != `C:\Windows\evil.exe` {
		t.Fatal("third-party change must not be overwritten")
	}
}

func TestWMIProviderApplyRollback(t *testing.T) {
	ctx := shortContext(t)
	session := newFakeSession()
	j := &fakeJournal{}
	adapter := WMIProvider{}
	req := fixtureRequest("WMIProvider")
	req.ProviderName = "RRVerify"
	req.ProviderCLSID = "{12345678-1234-1234-1234-1234567890AB}"

	artifacts, err := adapter.Apply(ctx, session, req, j)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 3 || artifacts[1].Kind != "registry_key" || artifacts[2].Kind != "wmi_provider" {
		t.Fatalf("artifacts = %#v", artifacts)
	}
	if !session.providers["RRVerify"] {
		t.Fatal("provider was not registered")
	}
	if err := adapter.Rollback(ctx, session, j.snapshot(), artifacts); err != nil {
		t.Fatal(err)
	}
	if session.providers["RRVerify"] {
		t.Fatal("provider was not deleted")
	}
	if len(session.providerCOM) != 0 {
		t.Fatalf("provider COM registrations left behind: %v", session.providerCOM)
	}
	if len(session.files) != 0 {
		t.Fatalf("files left behind: %v", session.files)
	}
}

func TestWMIProviderPreflightValidatesInputs(t *testing.T) {
	session := newFakeSession()
	req := fixtureRequest("WMIProvider")
	if _, _, err := (WMIProvider{}).Preflight(context.Background(), session, req); err == nil {
		t.Fatal("missing provider inputs accepted")
	}
	req.ProviderName = "RRVerify"
	req.ProviderCLSID = "not-a-guid"
	if _, _, err := (WMIProvider{}).Preflight(context.Background(), session, req); err == nil {
		t.Fatal("invalid clsid accepted")
	}
	req.ProviderCLSID = "{12345678-1234-1234-1234-1234567890AB}"
	session.providers["RRVerify"] = true
	if _, _, err := (WMIProvider{}).Preflight(shortContext(t), session, req); err == nil {
		t.Fatal("existing provider accepted")
	}
	delete(session.providers, "RRVerify")
	session.providerCOM[req.ProviderCLSID] = req.StagedPath
	if _, _, err := (WMIProvider{}).Preflight(shortContext(t), session, req); err == nil {
		t.Fatal("existing provider COM registration accepted")
	}
}
