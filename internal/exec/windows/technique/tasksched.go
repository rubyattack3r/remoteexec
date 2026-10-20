package technique

import (
	"context"
	"fmt"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
)

// TaskSchedExec registers a temporary task through the Task Scheduler COM
// service, runs it, and removes both the task and the staged loader.
type TaskSchedExec struct{}

func (TaskSchedExec) Name() string { return "TaskSchedExec" }

func (TaskSchedExec) Preflight(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	evidence, snapshot, err := preflightExecution(ctx, s, req)
	if err != nil {
		return evidence, snapshot, err
	}
	taskName := "remoteexec-" + req.RunID
	exists, err := s.TaskExists(ctx, taskName)
	if err != nil {
		return evidence, snapshot, errs.Wrap(errs.Reachability, err)
	}
	evidence = append(evidence, engine.Check{Name: "task_no_collision", Passed: !exists, Detail: taskName})
	snapshot.Entries = append(snapshot.Entries, engine.SnapshotEntry{Kind: kindTask, Identifier: taskName, Original: "absent"})
	if exists {
		return evidence, snapshot, errs.New(errs.Conflict, "task %s already exists", taskName)
	}
	return evidence, snapshot, nil
}

func (TaskSchedExec) Apply(ctx context.Context, s Session, req Request, j Journal) ([]model.Artifact, error) {
	var artifacts []model.Artifact
	if req.PayloadKind != payload.Command {
		staged, err := stagePayload(ctx, s, req, j)
		if err != nil {
			return appendArtifact(artifacts, staged), err
		}
		artifacts = append(artifacts, staged)
	}

	taskName := "remoteexec-" + req.RunID
	commandLine := commandLine(req)
	exe, args := splitCommand(commandLine)

	registered, err := registerTask(ctx, s, req, j, taskName, exe, args)
	artifacts = appendArtifact(artifacts, registered)
	if err != nil {
		return artifacts, err
	}
	invoked, err := runTask(ctx, s, req, j, commandLine, taskName)
	artifacts = appendArtifact(artifacts, invoked)
	if err != nil {
		return artifacts, err
	}
	return artifacts, nil
}

func (TaskSchedExec) Rollback(ctx context.Context, s Session, snapshot RecoverySnapshot, artifacts []model.Artifact) error {
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
		case kindTask:
			exists, err := s.TaskExists(ctx, artifact.Location)
			if err != nil {
				return errs.Wrap(errs.Cleanup, err)
			}
			if !exists {
				continue
			}
			if err := s.TaskDelete(ctx, artifact.Location); err != nil {
				return errs.Wrap(errs.Cleanup, err)
			}
			if exists, err := s.TaskExists(ctx, artifact.Location); err != nil {
				return errs.Wrap(errs.Cleanup, err)
			} else if exists {
				return errs.New(errs.Cleanup, "task %s still present after deletion", artifact.Location)
			}
		case kindStagedFile:
			if err := rollbackStagedFile(ctx, s, snapshot, artifact); err != nil {
				return err
			}
		}
	}
	return nil
}

func registerTask(ctx context.Context, s Session, req Request, j Journal, taskName, exe, args string) (model.Artifact, error) {
	artifact := model.Artifact{Kind: kindTask, Location: taskName, Original: "absent", Recovery: fmt.Sprintf("Delete the scheduled task '%s' if it is still registered", taskName)}
	entry, err := j.Append(ctx, journal.Entry{
		RunID: req.RunID, Target: req.Target, Technique: req.Technique.Name,
		ArtifactKind: kindTask, Identifier: taskName, Original: "absent",
		Mutation: "register temporary task", Rollback: "delete_scheduled_task",
	})
	if err != nil {
		return model.Artifact{}, errs.Wrap(errs.Execution, err)
	}
	if err := s.TaskCreate(ctx, taskName, exe, args); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	// Verification condition: the task must be observable in the registry.
	exists, err := poll(ctx, func() (bool, error) { return s.TaskExists(ctx, taskName) })
	if err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	if !exists {
		return artifact, errs.New(errs.Execution, "task %s was not observed after registration", taskName)
	}
	if err := j.UpdateState(ctx, req.RunID, entry.Sequence, journal.StateApplied); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	return artifact, nil
}

func runTask(ctx context.Context, s Session, req Request, j Journal, commandLine, taskName string) (model.Artifact, error) {
	program := imageOfCommand(commandLine)
	invocationID := "launcher:sha256:" + Digest([]byte(commandLine))
	location := req.StagedPath
	recovery := fmt.Sprintf("Confirm %s launched by task '%s' has exited, then delete %s", program, taskName, req.StagedPath)
	rollback := "no_persistent_process_artifact"
	if req.PayloadKind == payload.Command {
		invocationID = "command:sha256:" + Digest([]byte(commandLine))
		location = invocationID
		recovery = fmt.Sprintf("Delete the temporary task '%s'; no payload file was staged", taskName)
	} else if req.PayloadKind == payload.Executable {
		recovery = fmt.Sprintf("Delete temporary task '%s', confirm %s exited, then delete %s", taskName, program, req.StagedPath)
	}
	if req.StagedPath != "" {
		rollback = "wait_loader_exit"
	}
	if req.ProcessID != 0 {
		recovery = fmt.Sprintf("Delete temporary task '%s' and review injected process PID %d; injection cannot be generically reversed. Delete %s only after that process exits or the module is unloaded", taskName, req.ProcessID, req.StagedPath)
	}
	artifact := model.Artifact{Kind: kindProcess, Location: location, InvocationID: invocationID, Program: program, Recovery: recovery, RelatedProcessID: req.ProcessID}
	entry, err := j.Append(ctx, journal.Entry{
		RunID: req.RunID, Target: req.Target, Technique: req.Technique.Name,
		ArtifactKind: kindProcess, Identifier: invocationID, Location: location,
		InvocationID: invocationID, Program: program, RelatedProcessID: req.ProcessID, Original: "absent",
		Mutation: "run temporary task", Rollback: rollback,
	})
	if err != nil {
		return model.Artifact{}, errs.Wrap(errs.Execution, err)
	}
	if err := s.TaskRun(ctx, taskName); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	// Bounded observation of the invoked loader.
	var observedPID uint32
	_, _ = poll(ctx, func() (bool, error) {
		ids, err := s.ProcessFind(ctx, program, req.StagedPath)
		if err != nil {
			return false, err
		}
		if len(ids) > 0 {
			observedPID = ids[0]
		}
		return len(ids) > 0, nil
	})
	artifact.ProcessID = observedPID
	if err := j.UpdateState(ctx, req.RunID, entry.Sequence, journal.StateApplied); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	return artifact, nil
}
