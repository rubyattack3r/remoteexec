package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/plan"
	"github.com/rubyattack3r/remoteexec/internal/exec/target"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

const (
	testExecSelector    = "TestExec"
	testServiceSelector = "TestService"
	testLoaderDelivery  = technique.DeliveryStaged
	testServiceDelivery = technique.DeliveryServiceChange
)

func testRegistry(t *testing.T) *technique.Registry {
	t.Helper()
	descriptor := func(name string, delivery technique.DeliveryMode) technique.Descriptor {
		payloads := []payload.Kind{payload.DLL, payload.Command}
		invocations := map[payload.Kind]technique.InvocationMode{payload.DLL: technique.InvocationLauncher, payload.Command: technique.InvocationDirect}
		if delivery == testServiceDelivery {
			payloads = []payload.Kind{payload.Service}
			invocations = map[payload.Kind]technique.InvocationMode{payload.Service: technique.InvocationService}
		}
		return technique.Descriptor{
			Name: name, Title: name, Mechanism: "test", Platforms: []target.Platform{target.Windows},
			Transport: target.Native, FileDelivery: delivery, Invocations: invocations,
			Prerequisites: []string{"WMI"}, Requirements: []technique.Requirement{technique.RequireWMI},
			Privilege: "test", Surface: []string{"test"}, Recovery: "test",
			Telemetry: "test", Payloads: payloads,
		}
	}
	registry, err := technique.NewRegistry(
		descriptor(testExecSelector, testLoaderDelivery),
		descriptor(testServiceSelector, testServiceDelivery),
	)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

type testPlanner struct{}

func (testPlanner) Build(descriptor technique.Descriptor, opts plan.DeliveryOptions) (plan.Plan, string, error) {
	localPath := opts.Payload.LocalPath
	if descriptor.FileDelivery == testServiceDelivery {
		if strings.TrimSpace(opts.ServiceName) == "" {
			return plan.Plan{}, "", errors.New("delivery validation: --service-name is required for service techniques")
		}
	}
	return plan.Plan{
		Kind:     string(descriptor.FileDelivery),
		Steps:    []plan.Step{{Action: "test", Artifact: localPath}},
		Recovery: []plan.Step{{Action: "recover", Artifact: localPath}},
	}, localPath, nil
}

func TestPrepareValidatesEveryTechniquePrerequisiteShape(t *testing.T) {
	tmp := t.TempDir()
	loader := filepath.Join(tmp, "loader.dll")
	binary := filepath.Join(tmp, "svc.exe")
	for _, path := range []string{loader, binary} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	registry := testRegistry(t)
	e := Engine{Registry: registry, Planner: testPlanner{}}
	for _, descriptor := range registry.List() {
		t.Run(descriptor.Name, func(t *testing.T) {
			opts := Options{Targets: []string{"10.0.0.15"}, Technique: descriptor.Name, Payload: payload.Spec{Kind: payload.DLL, LocalPath: loader}, Credentials: credentials.Credentials{Username: "admin", Password: "secret"}, DryRun: true}
			if descriptor.FileDelivery == testServiceDelivery {
				opts.Payload = payload.Spec{Kind: payload.Service, LocalPath: binary}
				opts.ServiceName = "Spooler"
			}
			prepared, err := e.Prepare(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(prepared) != 1 || len(prepared[0].Delivery.Recovery) == 0 {
				t.Fatalf("incomplete prepared execution: %#v", prepared)
			}
			if prepared[0].Runtime.WinRMPort != DefaultWinRMHTTPPort || prepared[0].Runtime.MinStagingBytes != DefaultStagingBytes {
				t.Fatalf("runtime defaults = %#v", prepared[0].Runtime)
			}
		})
	}
}

func TestPrepareResolvesRuntimeConfiguration(t *testing.T) {
	loader := filepath.Join(t.TempDir(), "loader.dll")
	if err := os.WriteFile(loader, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}}
	opts := Options{
		Targets: []string{"host"}, Technique: testExecSelector, Payload: payload.Spec{Kind: payload.DLL, LocalPath: loader},
		Credentials: credentials.Credentials{Username: "admin", Password: "secret"},
		DryRun:      true, WinRMHTTPS: true, MinStagingBytes: 4096,
	}
	prepared, err := e.Prepare(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	want := RuntimeOptions{WinRMPort: DefaultWinRMHTTPSPort, WinRMHTTPS: true, MinStagingBytes: 4096, SSHPort: DefaultSSHPort}
	if prepared[0].Runtime != want {
		t.Fatalf("runtime = %#v, want %#v", prepared[0].Runtime, want)
	}

	opts.WinRMPort = 70000
	if _, err := e.Prepare(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "winrm-port") {
		t.Fatalf("expected port validation error, got %v", err)
	}
}

func TestPrepareCommandPayloadDoesNotRequireLocalFile(t *testing.T) {
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}}
	prepared, err := e.Prepare(context.Background(), Options{
		Targets: []string{"host"}, Technique: testExecSelector,
		Payload:     payload.Spec{Kind: payload.Command, Command: `whoami.exe /all`},
		Credentials: credentials.Credentials{Username: "admin", Password: "secret"},
		DryRun:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 1 || prepared[0].Payload.Kind != payload.Command {
		t.Fatalf("prepared command = %#v", prepared)
	}
}

func TestPrepareFailsBeforeBackendWhenPrerequisiteInvalid(t *testing.T) {
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}}
	_, err := e.Prepare(context.Background(), Options{Targets: []string{"10.0.0.15"}, Technique: testExecSelector, Payload: payload.Spec{Kind: payload.DLL, LocalPath: "missing.dll"}, Credentials: credentials.Credentials{Username: "admin", Password: "secret"}, DryRun: true})
	if err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrepareRequiresServiceName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "svc.exe")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}}
	_, err := e.Prepare(context.Background(), Options{Targets: []string{"host"}, Technique: testServiceSelector, Payload: payload.Spec{Kind: payload.Service, LocalPath: path}, Credentials: credentials.Credentials{Username: "admin", Password: "secret"}, DryRun: true})
	if err == nil || !strings.Contains(err.Error(), "service-name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type recordingBackend struct {
	mu           sync.Mutex
	events       []string
	preflightErr map[string]error
	missing      string
	executeErr   error
	artifacts    []model.Artifact
}

func (b *recordingBackend) Preflight(_ context.Context, p Prepared, _ credentials.Credentials) (PreflightReport, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, "preflight:"+p.Target)
	if err := b.preflightErr[p.Target]; err != nil {
		return PreflightReport{Target: p.Target}, err
	}
	caps := fullCapabilities()
	switch b.missing {
	case "wmi":
		caps.WMI = false
	}
	return PreflightReport{Target: p.Target, Capabilities: caps}, nil
}

func (b *recordingBackend) Execute(ctx context.Context, p Prepared, _ credentials.Credentials) ([]model.Artifact, error) {
	b.mu.Lock()
	b.events = append(b.events, "execute:"+p.Target)
	b.mu.Unlock()
	if b.executeErr != nil {
		return b.artifacts, b.executeErr
	}
	if b.artifacts != nil {
		return b.artifacts, nil
	}
	return []model.Artifact{{Kind: "test_artifact", Location: "C:\\Windows\\Temp\\test", Recovery: "delete it"}}, nil
}

func fullCapabilities() technique.Capabilities {
	return technique.Capabilities{
		LocalAdmin: true, WMI: true, RemoteRegistry: true, WinRM: true,
		DCOM: true, TaskScheduler: true, ActiveShell: true, SCM: true,
		ExistingService: true, ServiceSnapshot: true,
	}
}

func operationalOpts(t *testing.T, targets ...string) Options {
	t.Helper()
	loader := filepath.Join(t.TempDir(), "loader.dll")
	if err := os.WriteFile(loader, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Options{
		Targets:     targets,
		Technique:   testExecSelector,
		Payload:     payload.Spec{Kind: payload.DLL, LocalPath: loader},
		Credentials: credentials.Credentials{Username: "admin", Password: "secret"},
	}
}

func TestPreflightCompletesForEveryTargetBeforeFirstExecution(t *testing.T) {
	backend := &recordingBackend{}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	results, err := e.Run(context.Background(), operationalOpts(t, "10.0.0.1", "10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	firstExecution := -1
	for i, event := range backend.events {
		if strings.HasPrefix(event, "execute:") {
			firstExecution = i
			break
		}
	}
	if firstExecution < 0 {
		t.Fatal("no execution recorded")
	}
	for i, event := range backend.events[:firstExecution] {
		if !strings.HasPrefix(event, "preflight:") {
			t.Fatalf("event %d (%s) ran before all preflights completed", i, event)
		}
	}
}

func TestOneFailedPreflightAbortsBatchWithZeroMutations(t *testing.T) {
	backend := &recordingBackend{preflightErr: map[string]error{"10.0.0.2": errors.New("unreachable")}}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	if _, err := e.Run(context.Background(), operationalOpts(t, "10.0.0.1", "10.0.0.2")); err == nil {
		t.Fatal("batch should abort")
	}
	for _, event := range backend.events {
		if strings.HasPrefix(event, "execute:") {
			t.Fatal("mutation happened despite failed preflight")
		}
	}
}

func TestPreflightReportIsRetainedAndValidated(t *testing.T) {
	backend := &recordingBackend{}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	if _, err := e.Run(context.Background(), operationalOpts(t, "10.0.0.1")); err != nil {
		t.Fatal(err)
	}
}

func TestCapabilitiesGateExecution(t *testing.T) {
	backend := &recordingBackend{missing: "wmi"}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	if _, err := e.Run(context.Background(), operationalOpts(t, "10.0.0.1")); err == nil || !strings.Contains(err.Error(), "prerequisites not met") {
		t.Fatalf("expected prerequisite failure, got %v", err)
	}
	for _, event := range backend.events {
		if strings.HasPrefix(event, "execute:") {
			t.Fatal("mutation happened despite missing capabilities")
		}
	}
}

func TestExecuteFailureReportsArtifactsForOperatorRecovery(t *testing.T) {
	backend := &recordingBackend{executeErr: errors.New("boom")}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	results, err := e.Run(context.Background(), operationalOpts(t, "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	if result.Status != model.StatusFailed || !strings.Contains(result.Error, "boom") {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Recovery.Artifacts == nil || len(result.Recovery.Artifacts) != 0 {
		t.Fatalf("failed execution must report an empty, non-nil recovery artifact list: %#v", result.Recovery.Artifacts)
	}
	if result.Execution.Disposition != model.DispositionFailed {
		t.Fatalf("execution disposition = %q", result.Execution.Disposition)
	}
	if result.ErrorKind != errs.Execution {
		t.Fatalf("error_kind = %q, want %q", result.ErrorKind, errs.Execution)
	}
}

func TestErrorKindReflectsClassifiedFailure(t *testing.T) {
	backend := &recordingBackend{executeErr: errs.New(errs.Authorization, "access denied")}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	results, err := e.Run(context.Background(), operationalOpts(t, "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if results[0].ErrorKind != errs.Authorization {
		t.Fatalf("error_kind = %q, want %q", results[0].ErrorKind, errs.Authorization)
	}
}

type cancellingBackend struct {
	recordingBackend
	cancel context.CancelFunc
}

func (b *cancellingBackend) Execute(ctx context.Context, p Prepared, creds credentials.Credentials) ([]model.Artifact, error) {
	artifacts, err := b.recordingBackend.Execute(ctx, p, creds)
	b.cancel()
	return artifacts, err
}

func TestCancelledRunReportsEveryTarget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &cancellingBackend{cancel: cancel}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	opts := operationalOpts(t, "10.0.0.1", "10.0.0.2", "10.0.0.3")
	opts.Sleep = time.Hour
	results, err := e.Run(ctx, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %d, want one per target", len(results))
	}
	if results[0].Status != model.StatusSucceeded || len(results[0].Recovery.Artifacts) != 1 {
		t.Fatalf("executed target lost its recovery record: %#v", results[0])
	}
	for _, result := range results[1:] {
		if result.Status != model.StatusFailed || !strings.HasPrefix(result.Error, "not attempted:") || result.Recovery.Artifacts == nil || result.Execution.Disposition != model.DispositionNotAttempted {
			t.Fatalf("unattempted target = %#v", result)
		}
	}
}

func TestPartialMutationArtifactsRemainInResult(t *testing.T) {
	backend := &recordingBackend{
		executeErr: context.DeadlineExceeded,
		artifacts:  []model.Artifact{{Kind: "test_artifact", Location: "C:\\Windows\\Temp\\test", Recovery: "delete it"}},
	}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	results, err := e.Run(context.Background(), operationalOpts(t, "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	if result.Status != model.StatusFailed {
		t.Fatalf("status = %q", result.Status)
	}
	if !strings.HasPrefix(result.Error, "timeout:") {
		t.Fatalf("timeout must be explicit, got %q", result.Error)
	}
	if len(result.Recovery.Artifacts) != 1 || result.Recovery.Artifacts[0].Recovery == "" || !result.Recovery.Required {
		t.Fatalf("artifacts after partial execution = %#v", result.Recovery)
	}
}

func TestProcessInvocationBecomesEvidenceAndRecoveryConstraint(t *testing.T) {
	backend := &recordingBackend{artifacts: []model.Artifact{
		{Kind: "staged_file", Location: `C:\Windows\Temp\fixture.dll`, Original: "absent", Recovery: "delete it"},
		{Kind: "process_invocation", InvocationID: "launcher:sha256:abc", Program: "rundll32.exe", ProcessID: 4242, Recovery: "wait for exit"},
	}}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	results, err := e.Run(context.Background(), operationalOpts(t, "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	if len(result.Execution.Evidence) != 1 || result.Execution.Evidence[0].ProcessID != 4242 {
		t.Fatalf("execution evidence = %#v", result.Execution.Evidence)
	}
	if len(result.Recovery.Artifacts) != 1 || result.Recovery.Artifacts[0].Kind != "staged_file" {
		t.Fatalf("recovery artifacts = %#v", result.Recovery.Artifacts)
	}
	if len(result.Recovery.Constraints) != 1 || result.Recovery.Constraints[0].InvocationID == "" {
		t.Fatalf("recovery constraints = %#v", result.Recovery.Constraints)
	}
}

func TestDuplicateTargetsExecutedOnce(t *testing.T) {
	backend := &recordingBackend{}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	results, err := e.Run(context.Background(), operationalOpts(t, "10.0.0.1", "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	executions := 0
	for _, event := range backend.events {
		if strings.HasPrefix(event, "execute:") {
			executions++
		}
	}
	if executions != 1 {
		t.Fatalf("executions = %d, want 1", executions)
	}
}

func TestUnsupportedPayloadTypeFailsBeforePreflight(t *testing.T) {
	backend := &recordingBackend{}
	e := Engine{Registry: testRegistry(t), Planner: testPlanner{}, Backend: backend}
	opts := operationalOpts(t, "10.0.0.1")
	opts.Payload.Kind = payload.Service
	if _, err := e.Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(backend.events) != 0 {
		t.Fatalf("backend was contacted: %v", backend.events)
	}
}
