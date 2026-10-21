package technique

import (
	"context"
	"fmt"
	"strings"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
)

// WMIExec invokes a staged DLL/executable or direct command through Win32_Process.Create.
type WMIExec struct{}

func (WMIExec) Name() string { return "WMIExec" }

func (WMIExec) Preflight(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	return preflightExecution(ctx, s, req)
}

func (WMIExec) Apply(ctx context.Context, s Session, req Request, j Journal) ([]model.Artifact, error) {
	var artifacts []model.Artifact
	if req.PayloadKind != payload.Command {
		staged, err := stagePayload(ctx, s, req, j)
		if err != nil {
			return appendArtifact(artifacts, staged), err
		}
		artifacts = append(artifacts, staged)
	}
	commandLine := commandLine(req)
	invoked, err := invokeViaProcessCreate(ctx, s, req, j, commandLine)
	artifacts = appendArtifact(artifacts, invoked)
	if err != nil {
		return artifacts, err
	}
	return artifacts, nil
}

func (WMIExec) Rollback(ctx context.Context, s Session, snapshot RecoverySnapshot, artifacts []model.Artifact) error {
	return rollbackExecution(ctx, s, snapshot, artifacts)
}

// WSManExec invokes a staged DLL/executable or direct command through a WSMan shell.
type WSManExec struct{}

func (WSManExec) Name() string { return "WSManExec" }

func (WSManExec) Preflight(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	return preflightExecution(ctx, s, req)
}

func (WSManExec) Apply(ctx context.Context, s Session, req Request, j Journal) ([]model.Artifact, error) {
	var artifacts []model.Artifact
	if req.PayloadKind != payload.Command {
		staged, err := stagePayload(ctx, s, req, j)
		if err != nil {
			return appendArtifact(artifacts, staged), err
		}
		artifacts = append(artifacts, staged)
	}
	commandLine := commandLine(req)
	invoked, err := invokeViaProcessStart(ctx, s, req, j, commandLine)
	artifacts = appendArtifact(artifacts, invoked)
	if err != nil {
		return artifacts, err
	}
	return artifacts, nil
}

func (WSManExec) Rollback(ctx context.Context, s Session, snapshot RecoverySnapshot, artifacts []model.Artifact) error {
	return rollbackExecution(ctx, s, snapshot, artifacts)
}

// DCOMShellExecute invokes a staged DLL/executable or direct command through
// the remote Shell IShellDispatch2.ShellExecute method.
type DCOMShellExecute struct{}

func (DCOMShellExecute) Name() string { return "DCOMIShellDispatch2" }

func (DCOMShellExecute) Preflight(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	evidence, snapshot, err := preflightExecution(ctx, s, req)
	if err != nil {
		return evidence, snapshot, err
	}
	if err := s.ShellAvailable(ctx); err != nil {
		evidence = append(evidence, engine.Check{Name: "shell_automation", Passed: false, Detail: err.Error()})
		return evidence, snapshot, errs.Wrap(errs.Authorization, fmt.Errorf("remote shell automation interface is not accessible: %w", err))
	}
	evidence = append(evidence, engine.Check{Name: "shell_automation", Passed: true, Detail: "IShellDispatch2 resolved through the active Explorer session"})
	return evidence, snapshot, nil
}

func (DCOMShellExecute) Apply(ctx context.Context, s Session, req Request, j Journal) ([]model.Artifact, error) {
	var artifacts []model.Artifact
	if req.PayloadKind != payload.Command {
		staged, err := stagePayload(ctx, s, req, j)
		if err != nil {
			return appendArtifact(artifacts, staged), err
		}
		artifacts = append(artifacts, staged)
	}
	commandLine := commandLine(req)
	exe, args := splitCommand(commandLine)
	invoked, err := invokeViaShellExecute(ctx, s, req, j, commandLine, exe, args)
	artifacts = appendArtifact(artifacts, invoked)
	if err != nil {
		return artifacts, err
	}
	return artifacts, nil
}

func (DCOMShellExecute) Rollback(ctx context.Context, s Session, snapshot RecoverySnapshot, artifacts []model.Artifact) error {
	return rollbackExecution(ctx, s, snapshot, artifacts)
}

// invokeViaProcessCreate journals and performs Win32_Process.Create. The
// verification condition is the Create response itself: return code 0 with a
// process id.
func invokeViaProcessCreate(ctx context.Context, s Session, req Request, j Journal, commandLine string) (model.Artifact, error) {
	return invokeJournalled(ctx, s, req, j, commandLine, invocationMutation(req, "Win32_Process.Create"), func() (uint32, error) {
		return s.ProcessCreate(ctx, commandLine)
	})
}

// invokeViaProcessStart journals and performs an in-session process start.
// The native WSMan implementation waits for CommandState/Done and verifies a
// zero exit code. The API does not report a process ID, and a short-lived
// loader may exit before an independent WMI observation.
func invokeViaProcessStart(ctx context.Context, s Session, req Request, j Journal, commandLine string) (model.Artifact, error) {
	exe, args := splitCommand(commandLine)
	return invokeJournalled(ctx, s, req, j, commandLine, invocationMutation(req, "WSMan shell"), func() (uint32, error) {
		return s.ProcessStart(ctx, exe, args)
	})
}

// invokeViaShellExecute journals and performs IShellDispatch2.ShellExecute.
// The verification condition is the successful COM invocation.
func invokeViaShellExecute(ctx context.Context, s Session, req Request, j Journal, commandLine, exe, args string) (model.Artifact, error) {
	return invokeJournalled(ctx, s, req, j, commandLine, invocationMutation(req, "Shell IShellDispatch2.ShellExecute"), func() (uint32, error) {
		if err := s.ShellExecute(ctx, exe, args); err != nil {
			return 0, err
		}
		return 0, nil
	})
}

func invokeJournalled(ctx context.Context, s Session, req Request, j Journal, commandLine, mutation string, invoke func() (uint32, error)) (model.Artifact, error) {
	program := imageOfCommand(commandLine)
	invocationID := "launcher:sha256:" + Digest([]byte(commandLine))
	location := req.StagedPath
	recovery := fmt.Sprintf("Confirm %s has exited, then delete %s", program, req.StagedPath)
	if req.PayloadKind == payload.Command {
		invocationID = "command:sha256:" + Digest([]byte(commandLine))
		location = invocationID
		recovery = "No persistent remoteexec artifact; review endpoint process state if the command was long-running"
	} else if req.PayloadKind == payload.Executable {
		recovery = fmt.Sprintf("Confirm %s has exited, then delete %s", program, req.StagedPath)
	}
	if req.ProcessID != 0 {
		recovery = fmt.Sprintf("Review injected process PID %d; injection cannot be generically reversed. Delete %s only after that process exits or the module is unloaded", req.ProcessID, req.StagedPath)
	}
	artifact := model.Artifact{
		Kind: kindProcess, Location: location, InvocationID: invocationID, Program: program,
		Recovery: recovery, RelatedProcessID: req.ProcessID,
	}
	rollback := "no_persistent_artifact"
	if req.StagedPath != "" {
		rollback = "wait_loader_exit"
	}
	entry, err := j.Append(ctx, journal.Entry{
		RunID: req.RunID, Target: req.Target, Technique: req.Technique.Name,
		ArtifactKind: kindProcess, Identifier: invocationID, Location: location,
		InvocationID: invocationID, Program: program, RelatedProcessID: req.ProcessID, Original: "absent",
		Mutation: mutation, Rollback: rollback,
	})
	if err != nil {
		return model.Artifact{}, errs.Wrap(errs.Execution, err)
	}
	pid, err := invoke()
	if err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	artifact.ProcessID = pid
	// Bounded observation of the created process; acceptance is already
	// proven by the invocation response above.
	if pid > 0 {
		_, _ = poll(ctx, func() (bool, error) { return s.ProcessExists(ctx, pid) })
	}
	if err := j.UpdateState(ctx, req.RunID, entry.Sequence, journal.StateApplied); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	return artifact, nil
}

func invocationMutation(req Request, mechanism string) string {
	if req.PayloadKind == payload.Command {
		return "execute direct command via " + mechanism
	}
	return "invoke staged loader via " + mechanism
}

// rollbackExecution walks artifacts in reverse: wait for the loader process
// to exit, then remove the staged file after verifying its digest.
func rollbackExecution(ctx context.Context, s Session, snapshot RecoverySnapshot, artifacts []model.Artifact) error {
	for i := len(artifacts) - 1; i >= 0; i-- {
		artifact := artifacts[i]
		switch artifact.Kind {
		case kindProcess:
			if _, staged := firstSnapshotOfKind(snapshot, kindStagedFile); !staged {
				continue
			}
			needle := ""
			if staged, ok := firstSnapshotOfKind(snapshot, kindStagedFile); ok {
				needle = staged.Identifier
			}
			if err := waitInvocationExit(ctx, s, artifact, needle); err != nil {
				return err
			}
		case kindStagedFile:
			if err := rollbackStagedFile(ctx, s, snapshot, artifact); err != nil {
				return err
			}
		}
	}
	return nil
}

func splitCommand(commandLine string) (exe, args string) {
	if i := indexCommandSeparator(commandLine); i >= 0 {
		return unquoteExecutable(commandLine[:i]), trimLeading(commandLine[i+1:])
	}
	return unquoteExecutable(commandLine), ""
}

func unquoteExecutable(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

func indexCommandSeparator(commandLine string) int {
	inQuotes := false
	for i := 0; i < len(commandLine); i++ {
		switch commandLine[i] {
		case '"':
			inQuotes = !inQuotes
		case ' ', '\t':
			if !inQuotes {
				return i
			}
		}
	}
	return -1
}

func trimLeading(v string) string {
	for len(v) > 0 && (v[0] == ' ' || v[0] == '\t') {
		v = v[1:]
	}
	return v
}
