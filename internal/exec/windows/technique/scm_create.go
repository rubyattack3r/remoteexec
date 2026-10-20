package technique

import (
	"context"
	"fmt"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
)

// SCMCreateService implements the PsExec-style primitive: stage a service
// executable, create and start a temporary service, then remove both.
type SCMCreateService struct{}

func (SCMCreateService) Name() string { return "SCMCreateService" }

func (SCMCreateService) Preflight(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	evidence, snapshot, err := preflightStaging(ctx, s, req)
	if err != nil {
		return evidence, snapshot, err
	}
	if req.ServiceName == "" {
		return evidence, snapshot, errs.New(errs.Validation, "SCMCreateService: --service-name is required")
	}
	exists, err := s.ServiceExists(ctx, req.ServiceName)
	if err != nil {
		return evidence, snapshot, errs.Wrap(errs.Reachability, err)
	}
	evidence = append(evidence, engine.Check{Name: "service_no_collision", Passed: !exists, Detail: req.ServiceName})
	snapshot.Entries = append(snapshot.Entries, engine.SnapshotEntry{Kind: kindTemporaryService, Identifier: req.ServiceName, Original: "absent"})
	if exists {
		return evidence, snapshot, errs.New(errs.Conflict, "service %s already exists", req.ServiceName)
	}
	return evidence, snapshot, nil
}

func (SCMCreateService) Apply(ctx context.Context, s Session, req Request, j Journal) ([]model.Artifact, error) {
	var artifacts []model.Artifact
	staged, err := stagePayload(ctx, s, req, j)
	if err != nil {
		return appendArtifact(artifacts, staged), err
	}
	artifacts = append(artifacts, staged)

	artifact := model.Artifact{Kind: kindTemporaryService, Location: req.ServiceName, Original: "absent", Recovery: fmt.Sprintf("Stop and delete temporary service %s", req.ServiceName)}
	entry, err := j.Append(ctx, journal.Entry{
		RunID: req.RunID, Target: req.Target, Technique: req.Technique.Name,
		ArtifactKind: kindTemporaryService, Identifier: req.ServiceName, Original: "absent",
		Mutation: "create and start temporary SCM service", Rollback: "stop_and_delete_service",
	})
	if err != nil {
		return appendArtifact(artifacts, artifact), errs.Wrap(errs.Execution, err)
	}
	if err := s.ServiceCreate(ctx, req.ServiceName, serviceImagePath(req.StagedPath)); err != nil {
		return appendArtifact(artifacts, artifact), errs.Wrap(errs.Execution, err)
	}
	artifacts = append(artifacts, artifact)
	if exists, err := s.ServiceExists(ctx, req.ServiceName); err != nil || !exists {
		return artifacts, errs.New(errs.Execution, "temporary service %s was not observed after creation", req.ServiceName)
	}
	if err := s.ServiceStart(ctx, req.ServiceName, MechanismSCM); err != nil {
		return artifacts, errs.Wrap(errs.Execution, err)
	}
	if err := j.UpdateState(ctx, req.RunID, entry.Sequence, journal.StateApplied); err != nil {
		return artifacts, errs.Wrap(errs.Execution, err)
	}
	return artifacts, nil
}

func (SCMCreateService) Rollback(ctx context.Context, s Session, snapshot RecoverySnapshot, artifacts []model.Artifact) error {
	for i := len(artifacts) - 1; i >= 0; i-- {
		artifact := artifacts[i]
		switch artifact.Kind {
		case kindTemporaryService:
			exists, err := s.ServiceExists(ctx, artifact.Location)
			if err != nil {
				return errs.Wrap(errs.Cleanup, err)
			}
			if !exists {
				continue
			}
			_ = s.ServiceStop(ctx, artifact.Location, MechanismSCM)
			if err := s.ServiceDelete(ctx, artifact.Location); err != nil {
				return errs.Wrap(errs.Cleanup, err)
			}
			deleted, err := poll(ctx, func() (bool, error) {
				exists, err := s.ServiceExists(ctx, artifact.Location)
				return !exists, err
			})
			if err != nil {
				return errs.Wrap(errs.Cleanup, err)
			}
			if !deleted {
				return errs.New(errs.Cleanup, "temporary service %s still exists after deletion", artifact.Location)
			}
		case kindStagedFile:
			if err := rollbackStagedFile(ctx, s, snapshot, artifact); err != nil {
				return err
			}
		}
	}
	return nil
}
