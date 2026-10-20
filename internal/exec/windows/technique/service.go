package technique

import (
	"context"
	"fmt"
	"strings"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
)

func serviceNameFromLocation(location string) string {
	return strings.TrimSuffix(location, ":start")
}

// ServiceAdapter temporarily reconfigures and starts an existing service,
// restoring the recorded configuration afterwards. WMIService drives
// Win32_Service over WMI; SCMChangeService drives the Service Control
// Manager API.
type ServiceAdapter struct {
	NameValue string
	Mechanism Mechanism
}

func (a ServiceAdapter) Name() string { return a.NameValue }

func (a ServiceAdapter) Preflight(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	evidence, snapshot, err := preflightStaging(ctx, s, req)
	if err != nil {
		return evidence, snapshot, err
	}
	if req.ServiceName == "" {
		evidence = append(evidence, engine.Check{Name: "technique_state", Passed: false, Detail: "service name is required"})
		return evidence, snapshot, errs.New(errs.Validation, "%s: --service-name is required", a.NameValue)
	}
	config, err := s.ServiceGet(ctx, req.ServiceName)
	if err != nil {
		evidence = append(evidence, engine.Check{Name: "technique_state", Passed: false, Detail: err.Error()})
		return evidence, snapshot, errs.New(errs.Validation, "%s: service %s is absent", a.NameValue, req.ServiceName)
	}
	serialized := marshalServiceConfig(config)
	evidence = append(evidence, engine.Check{Name: "technique_state", Passed: true, Detail: fmt.Sprintf("service %s is %s with path %s", config.Name, config.State, config.PathName)})
	snapshot.Entries = append(snapshot.Entries, engine.SnapshotEntry{Kind: kindServicePath, Identifier: req.ServiceName, Original: serialized, Digest: Digest([]byte(serialized))})
	snapshot.Entries = append(snapshot.Entries, engine.SnapshotEntry{Kind: kindServiceRun, Identifier: req.ServiceName + ":start", Original: config.State})
	evidence = append(evidence, engine.Check{Name: "rollback_values_readable", Passed: true, Detail: "service configuration snapshot recorded"})
	return evidence, snapshot, nil
}

func (a ServiceAdapter) Apply(ctx context.Context, s Session, req Request, j Journal) ([]model.Artifact, error) {
	var artifacts []model.Artifact
	config, err := s.ServiceGet(ctx, req.ServiceName)
	if err != nil {
		return artifacts, errs.Wrap(errs.Execution, err)
	}
	serialized := marshalServiceConfig(config)

	staged, err := stagePayload(ctx, s, req, j)
	if err != nil {
		return appendArtifact(artifacts, staged), err
	}
	artifacts = append(artifacts, staged)

	changed, err := a.changePath(ctx, s, req, j, serialized)
	artifacts = appendArtifact(artifacts, changed)
	if err != nil {
		return artifacts, err
	}
	started, err := a.start(ctx, s, req, j, config.State)
	artifacts = appendArtifact(artifacts, started)
	if err != nil {
		return artifacts, err
	}
	return artifacts, nil
}

func (a ServiceAdapter) changePath(ctx context.Context, s Session, req Request, j Journal, original string) (model.Artifact, error) {
	binaryPath := serviceImagePath(req.StagedPath)
	artifact := model.Artifact{Kind: kindServicePath, Location: req.ServiceName, Original: original, Recovery: fmt.Sprintf("Restore service %s to the configuration in original", req.ServiceName)}
	entry, err := j.Append(ctx, journal.Entry{
		RunID: req.RunID, Target: req.Target, Technique: req.Technique.Name,
		ArtifactKind: kindServicePath, Identifier: req.ServiceName, Original: original,
		Mutation: fmt.Sprintf("reconfigure service to %s via %s", binaryPath, a.Mechanism),
		Rollback: "restore_service_configuration", Digest: Digest([]byte(original)),
	})
	if err != nil {
		return model.Artifact{}, errs.Wrap(errs.Execution, err)
	}
	if err := s.ServiceChangePath(ctx, req.ServiceName, binaryPath, a.Mechanism); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	// Verification condition: the service configuration must report the new path.
	observed, err := poll(ctx, func() (bool, error) {
		current, err := s.ServiceGet(ctx, req.ServiceName)
		if err != nil {
			return false, err
		}
		return current.PathName == binaryPath, nil
	})
	if err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	if !observed {
		return artifact, errs.New(errs.Execution, "service %s did not report the new configuration", req.ServiceName)
	}
	if err := j.UpdateState(ctx, req.RunID, entry.Sequence, journal.StateApplied); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	return artifact, nil
}

func (a ServiceAdapter) start(ctx context.Context, s Session, req Request, j Journal, originalState string) (model.Artifact, error) {
	artifact := model.Artifact{Kind: kindServiceRun, Location: req.ServiceName + ":start", Original: originalState, Recovery: fmt.Sprintf("Restore service %s to its original run state", req.ServiceName)}
	entry, err := j.Append(ctx, journal.Entry{
		RunID: req.RunID, Target: req.Target, Technique: req.Technique.Name,
		ArtifactKind: kindServiceRun, Identifier: req.ServiceName + ":start", Original: originalState,
		Mutation: "start service", Rollback: "stop_service_if_started",
	})
	if err != nil {
		return model.Artifact{}, errs.Wrap(errs.Execution, err)
	}
	if err := s.ServiceStart(ctx, req.ServiceName, a.Mechanism); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	// Verification condition: the service must reach the Running state.
	observed, err := poll(ctx, func() (bool, error) {
		current, err := s.ServiceGet(ctx, req.ServiceName)
		if err != nil {
			return false, err
		}
		return current.State == "Running", nil
	})
	if err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	if !observed {
		return artifact, errs.New(errs.Execution, "service %s did not reach the Running state", req.ServiceName)
	}
	if err := j.UpdateState(ctx, req.RunID, entry.Sequence, journal.StateApplied); err != nil {
		return artifact, errs.Wrap(errs.Execution, err)
	}
	return artifact, nil
}

func (a ServiceAdapter) Rollback(ctx context.Context, s Session, snapshot RecoverySnapshot, artifacts []model.Artifact) error {
	for i := len(artifacts) - 1; i >= 0; i-- {
		artifact := artifacts[i]
		switch artifact.Kind {
		case kindServiceRun:
			if err := a.rollbackStart(ctx, s, snapshot, artifact); err != nil {
				return err
			}
		case kindServicePath:
			if err := a.rollbackPath(ctx, s, snapshot, artifact); err != nil {
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

func (a ServiceAdapter) rollbackStart(ctx context.Context, s Session, snapshot RecoverySnapshot, artifact model.Artifact) error {
	original, ok := snapshotEntry(snapshot, artifact.Location)
	if !ok {
		return errs.New(errs.Cleanup, "no journal entry describes %s; refusing to touch it", artifact.Location)
	}
	if original.Original == "Running" {
		return nil
	}
	current, err := s.ServiceGet(ctx, serviceNameFromLocation(artifact.Location))
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	if current.State != "Running" {
		return nil
	}
	if err := s.ServiceStop(ctx, serviceNameFromLocation(artifact.Location), a.Mechanism); err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	stopped, err := poll(ctx, func() (bool, error) {
		state, err := s.ServiceGet(ctx, serviceNameFromLocation(artifact.Location))
		if err != nil {
			return false, err
		}
		return state.State != "Running" && state.State != "Stop Pending", nil
	})
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	if !stopped {
		return errs.New(errs.Cleanup, "service %s did not stop", serviceNameFromLocation(artifact.Location))
	}
	return nil
}

func (a ServiceAdapter) rollbackPath(ctx context.Context, s Session, snapshot RecoverySnapshot, artifact model.Artifact) error {
	entry, ok := snapshotEntry(snapshot, artifact.Location)
	if !ok {
		return errs.New(errs.Cleanup, "no journal entry describes %s; refusing to touch it", artifact.Location)
	}
	original, err := unmarshalServiceConfig(entry.Original)
	if err != nil {
		return err
	}
	staged := ""
	if stagedEntry, ok := firstSnapshotOfKind(snapshot, kindStagedFile); ok {
		staged = serviceImagePath(stagedEntry.Identifier)
	}
	current, err := s.ServiceGet(ctx, serviceNameFromLocation(artifact.Location))
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	if current.PathName == original.PathName {
		return nil
	}
	if staged == "" || current.PathName != staged {
		return errs.New(errs.Conflict, "service %s changed outside this run; refusing to overwrite a third-party change", serviceNameFromLocation(artifact.Location))
	}
	if err := s.ServiceChangePath(ctx, serviceNameFromLocation(artifact.Location), original.PathName, a.Mechanism); err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	restored, err := poll(ctx, func() (bool, error) {
		state, err := s.ServiceGet(ctx, serviceNameFromLocation(artifact.Location))
		if err != nil {
			return false, err
		}
		return state.PathName == original.PathName, nil
	})
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	if !restored {
		return errs.New(errs.Cleanup, "service %s did not report the restored configuration", serviceNameFromLocation(artifact.Location))
	}
	return nil
}
