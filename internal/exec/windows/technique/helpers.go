package technique

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
)

// verificationWindow bounds readiness polling; poll also honors the caller
// context deadline so tests and cancellations cut it short.
var verificationWindow = 5 * time.Second

const pollInterval = 250 * time.Millisecond

var (
	clsidPattern        = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)
	providerNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

const (
	kindStagedFile       = "staged_file"
	kindProcess          = "process_invocation"
	kindTask             = "scheduled_task"
	kindServicePath      = "service_path"
	kindServiceRun       = "service_start"
	kindTemporaryService = "temporary_service"
	kindProvider         = "wmi_provider"
	kindRegistryKey      = "registry_key"
	kindMarker           = "verify_marker"
)

func poll(ctx context.Context, condition func() (bool, error)) (bool, error) {
	deadline := time.Now().Add(verificationWindow)
	for {
		ok, err := condition()
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-time.After(pollInterval):
		}
	}
}

func appendArtifact(artifacts []model.Artifact, artifact model.Artifact) []model.Artifact {
	if artifact.Location == "" {
		return artifacts
	}
	return append(artifacts, artifact)
}

func snapshotEntry(snapshot RecoverySnapshot, identifier string) (engine.SnapshotEntry, bool) {
	for _, entry := range snapshot.Entries {
		if entry.Identifier == identifier {
			return entry, true
		}
	}
	return engine.SnapshotEntry{}, false
}

func firstSnapshotOfKind(snapshot RecoverySnapshot, kind string) (engine.SnapshotEntry, bool) {
	for _, entry := range snapshot.Entries {
		if entry.Kind == kind {
			return entry, true
		}
	}
	return engine.SnapshotEntry{}, false
}

// stagePayload journals the staging, writes the payload, and verifies the
// write with a read-back digest before marking the entry applied.
func stagePayload(ctx context.Context, s Session, req Request, j Journal) (model.Artifact, error) {
	artifact := model.Artifact{Kind: kindStagedFile, Location: req.StagedPath, Digest: "sha256:" + req.Digest, Original: "absent", Recovery: "Delete " + req.StagedPath + " only if its SHA-256 digest still matches"}
	entry, err := j.Append(ctx, journal.Entry{
		RunID: req.RunID, Target: req.Target, Technique: req.Technique.Name,
		ArtifactKind: kindStagedFile, Identifier: req.StagedPath, Original: "absent",
		Mutation: "stage payload", Rollback: "remove_staged_file", Digest: req.Digest,
	})
	if err != nil {
		return model.Artifact{}, errs.Wrap(errs.Execution, err)
	}
	written, err := s.WriteFile(ctx, req.StagedPath, req.Payload)
	if err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	if written != req.Digest {
		return artifact, errs.New(errs.Execution, "digest mismatch after staging %s", req.StagedPath)
	}
	if err := j.UpdateState(ctx, req.RunID, entry.Sequence, journal.StateApplied); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	return artifact, nil
}

// rollbackStagedFile compares current content with the journal digest and
// refuses to overwrite third-party changes.
func rollbackStagedFile(ctx context.Context, s Session, snapshot RecoverySnapshot, artifact model.Artifact) error {
	entry, ok := snapshotEntry(snapshot, artifact.Location)
	if !ok {
		return errs.New(errs.Cleanup, "no journal entry describes %s; refusing to touch it", artifact.Location)
	}
	exists, err := s.FileExists(ctx, artifact.Location)
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	if !exists {
		return nil
	}
	content, err := s.ReadFile(ctx, artifact.Location)
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	if Digest(content) != entry.Digest {
		return errs.New(errs.Conflict, "%s changed outside this run; refusing to overwrite a third-party change", artifact.Location)
	}
	return s.RemoveFile(ctx, artifact.Location)
}

// waitProcessExit polls until no process matching the invocation remains.
func waitProcessExit(ctx context.Context, s Session, image, needle string) error {
	exited, err := poll(ctx, func() (bool, error) {
		ids, err := s.ProcessFind(ctx, image, needle)
		if err != nil {
			return false, err
		}
		return len(ids) == 0, nil
	})
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	if !exited {
		return errs.New(errs.Cleanup, "loader process %s (%s) is still running; do not delete the staged file while it is loaded", needle, image)
	}
	return nil
}

func waitInvocationExit(ctx context.Context, s Session, artifact model.Artifact, needle string) error {
	if artifact.RelatedProcessID != 0 {
		exited, err := poll(ctx, func() (bool, error) {
			exists, err := s.ProcessExists(ctx, artifact.RelatedProcessID)
			return !exists, err
		})
		if err != nil {
			return errs.Wrap(errs.Cleanup, err)
		}
		if !exited {
			return errs.New(errs.Cleanup, "related process PID %d is still running; injection cannot be generically reversed", artifact.RelatedProcessID)
		}
	}
	if artifact.ProcessID != 0 {
		exited, err := poll(ctx, func() (bool, error) {
			exists, err := s.ProcessExists(ctx, artifact.ProcessID)
			return !exists, err
		})
		if err != nil {
			return errs.Wrap(errs.Cleanup, err)
		}
		if !exited {
			return errs.New(errs.Cleanup, "launcher process PID %d is still running", artifact.ProcessID)
		}
		return nil
	}
	if artifact.Program == "" {
		return errs.New(errs.Cleanup, "process artifact %s has no program or process id", artifact.InvocationID)
	}
	return waitProcessExit(ctx, s, artifact.Program, needle)
}

func imageOfCommand(commandLine string) string {
	token, _ := splitCommand(commandLine)
	if i := strings.LastIndexAny(token, `\/`); i >= 0 {
		token = token[i+1:]
	}
	return token
}

func marshalServiceConfig(c ServiceConfig) string {
	return strings.Join([]string{
		"name=" + url.QueryEscape(c.Name),
		"display_name=" + url.QueryEscape(c.DisplayName),
		"path=" + url.QueryEscape(c.PathName),
		"start_mode=" + url.QueryEscape(c.StartMode),
		"start_name=" + url.QueryEscape(c.StartName),
		"state=" + url.QueryEscape(c.State),
	}, "|")
}

func unmarshalServiceConfig(v string) (ServiceConfig, error) {
	var c ServiceConfig
	assign := map[string]*string{
		"name": &c.Name, "display_name": &c.DisplayName, "path": &c.PathName,
		"start_mode": &c.StartMode, "start_name": &c.StartName, "state": &c.State,
	}
	for _, part := range strings.Split(v, "|") {
		key, value, _ := strings.Cut(part, "=")
		raw, err := url.QueryUnescape(value)
		if err != nil {
			return c, errs.New(errs.Cleanup, "corrupt service snapshot: %v", err)
		}
		if field, ok := assign[key]; ok {
			*field = raw
		}
	}
	return c, nil
}

// preflightStaging is the shared adapter preflight: validate inputs, confirm
// the staging destination is clear, and record every rollback value.
func preflightStaging(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	evidence := Evidence{}
	snapshot := RecoverySnapshot{Technique: req.Technique.Name, Target: req.Target}
	if req.RunID == "" || req.StagedPath == "" || len(req.Payload) == 0 || req.Digest == "" {
		evidence = append(evidence, engine.Check{Name: "staging_inputs", Passed: false, Detail: "run id, staging path, payload, and digest are required"})
		return evidence, snapshot, errs.New(errs.Validation, "%s: staging inputs are incomplete", req.Technique.Name)
	}
	collision, err := s.FileExists(ctx, req.StagedPath)
	if err != nil {
		return evidence, snapshot, errs.Wrap(errs.Reachability, err)
	}
	evidence = append(evidence, engine.Check{Name: "staging_no_collision", Passed: !collision, Detail: req.StagedPath})
	snapshot.Entries = append(snapshot.Entries, engine.SnapshotEntry{Kind: kindStagedFile, Identifier: req.StagedPath, Original: "absent", Digest: req.Digest})
	evidence = append(evidence, engine.Check{Name: "rollback_values_readable", Passed: true, Detail: fmt.Sprintf("%d rollback values recorded", len(snapshot.Entries))})
	if collision {
		return evidence, snapshot, errs.New(errs.Conflict, "%s already exists", req.StagedPath)
	}
	return evidence, snapshot, nil
}

func preflightExecution(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	if req.PayloadKind != payload.Command {
		evidence, snapshot, err := preflightStaging(ctx, s, req)
		if err != nil || req.ProcessID == 0 {
			return evidence, snapshot, err
		}
		exists, err := s.ProcessExists(ctx, req.ProcessID)
		if err != nil {
			return evidence, snapshot, errs.Wrap(errs.Reachability, err)
		}
		evidence = append(evidence, engine.Check{Name: "launcher_process", Passed: exists, Detail: fmt.Sprintf("process id %d exists=%t", req.ProcessID, exists)})
		if !exists {
			return evidence, snapshot, errs.New(errs.Validation, "launcher process id %d does not exist", req.ProcessID)
		}
		return evidence, snapshot, nil
	}
	evidence := Evidence{}
	snapshot := RecoverySnapshot{Technique: req.Technique.Name, Target: req.Target}
	command := strings.TrimSpace(req.Command)
	valid := req.RunID != "" && command != "" && !strings.ContainsAny(command, "\x00\r\n") && len(command) <= 32767
	evidence = append(evidence, engine.Check{Name: "command_input", Passed: valid, Detail: "direct command supplied; no file staging required"})
	if !valid {
		return evidence, snapshot, errs.New(errs.Validation, "%s: command payload must be a non-empty single command line of at most 32767 bytes", req.Technique.Name)
	}
	return evidence, snapshot, nil
}

func commandLine(req Request) string {
	if req.PayloadKind == payload.Command {
		return strings.TrimSpace(req.Command)
	}
	if req.PayloadKind == payload.Executable {
		executable := req.StagedPath
		if strings.ContainsAny(executable, " \t") {
			executable = `"` + executable + `"`
		}
		if strings.TrimSpace(req.Arguments) != "" {
			return executable + " " + strings.TrimSpace(req.Arguments)
		}
		return executable
	}
	return req.LoaderCommand
}

// serviceImagePath quotes the executable path stored in a service
// configuration. The staged-file path remains unquoted for file operations.
func serviceImagePath(path string) string {
	return `"` + strings.Trim(path, `"`) + `"`
}
