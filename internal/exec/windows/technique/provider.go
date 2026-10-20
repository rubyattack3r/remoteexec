package technique

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
)

// WMIProvider stages a provider DLL and registers its __Win32Provider
// metadata in the WMI repository through the WMI COM API.
type WMIProvider struct{}

func (WMIProvider) Name() string { return "WMIProvider" }

func (WMIProvider) Preflight(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	evidence, snapshot, err := preflightStaging(ctx, s, req)
	if err != nil {
		return evidence, snapshot, err
	}
	if !providerNamePattern.MatchString(req.ProviderName) {
		evidence = append(evidence, engine.Check{Name: "provider_inputs", Passed: false, Detail: req.ProviderName})
		return evidence, snapshot, errs.New(errs.Validation, "WMIProvider: --provider-name must match %s", providerNamePattern)
	}
	if !clsidPattern.MatchString(req.ProviderCLSID) {
		evidence = append(evidence, engine.Check{Name: "provider_inputs", Passed: false, Detail: req.ProviderCLSID})
		return evidence, snapshot, errs.New(errs.Validation, "WMIProvider: --provider-clsid must be a COM class identifier like {00000000-0000-0000-0000-000000000000}")
	}
	exists, err := s.ProviderExists(ctx, req.ProviderName)
	if err != nil {
		return evidence, snapshot, errs.Wrap(errs.Reachability, err)
	}
	evidence = append(evidence, engine.Check{Name: "provider_no_collision", Passed: !exists, Detail: req.ProviderName})
	snapshot.Entries = append(snapshot.Entries, engine.SnapshotEntry{Kind: kindProvider, Identifier: req.ProviderName, Original: "absent"})
	if exists {
		return evidence, snapshot, errs.New(errs.Conflict, "provider %s already exists", req.ProviderName)
	}
	comExists, err := s.ProviderCOMExists(ctx, req.ProviderCLSID)
	if err != nil {
		return evidence, snapshot, errs.Wrap(errs.Reachability, err)
	}
	registryPath := providerRegistryPath(req.ProviderCLSID)
	evidence = append(evidence, engine.Check{Name: "provider_com_no_collision", Passed: !comExists, Detail: registryPath})
	snapshot.Entries = append(snapshot.Entries, engine.SnapshotEntry{Kind: kindRegistryKey, Identifier: registryPath, Original: "absent"})
	if comExists {
		return evidence, snapshot, errs.New(errs.Conflict, "provider COM registration %s already exists", req.ProviderCLSID)
	}
	evidence = append(evidence, engine.Check{Name: "rollback_values_readable", Passed: true, Detail: fmt.Sprintf("%d rollback values recorded", len(snapshot.Entries))})
	return evidence, snapshot, nil
}

func (WMIProvider) Apply(ctx context.Context, s Session, req Request, j Journal) ([]model.Artifact, error) {
	var artifacts []model.Artifact
	staged, err := stagePayload(ctx, s, req, j)
	if err != nil {
		return appendArtifact(artifacts, staged), err
	}
	artifacts = append(artifacts, staged)

	registryPath := providerRegistryPath(req.ProviderCLSID)
	registryArtifact := model.Artifact{Kind: kindRegistryKey, Location: registryPath, Original: "absent", Recovery: fmt.Sprintf("Delete %s after confirming it still points to %s", registryPath, req.StagedPath)}
	registryEntry, err := j.Append(ctx, journal.Entry{
		RunID: req.RunID, Target: req.Target, Technique: req.Technique.Name,
		ArtifactKind: kindRegistryKey, Identifier: registryPath, Original: "absent",
		Mutation: "register provider DLL as an in-process COM server", Rollback: "delete_provider_com_registration",
	})
	if err != nil {
		return appendArtifact(artifacts, registryArtifact), errs.Wrap(errs.Execution, err)
	}
	if err := s.ProviderCOMRegister(ctx, req.ProviderCLSID, req.StagedPath); err != nil {
		return appendArtifact(artifacts, registryArtifact), errs.Wrap(errs.Execution, err)
	}
	artifacts = append(artifacts, registryArtifact)
	if err := j.UpdateState(ctx, req.RunID, registryEntry.Sequence, journal.StateApplied); err != nil {
		return artifacts, errs.Wrap(errs.Execution, err)
	}

	artifact := model.Artifact{Kind: kindProvider, Location: req.ProviderName, Original: "absent", Recovery: fmt.Sprintf("Delete the __Win32Provider instance '%s' in root\\default through the WMI API", req.ProviderName)}
	entry, err := j.Append(ctx, journal.Entry{
		RunID: req.RunID, Target: req.Target, Technique: req.Technique.Name,
		ArtifactKind: kindProvider, Identifier: req.ProviderName, Original: "absent",
		Mutation: "register __Win32Provider metadata", Rollback: "delete_provider_registration",
	})
	if err != nil {
		return appendArtifact(artifacts, artifact), errs.Wrap(errs.Execution, err)
	}
	if err := s.ProviderRegister(ctx, req.ProviderName, req.ProviderCLSID); err != nil {
		return appendArtifact(artifacts, artifact), errs.Wrap(errs.Execution, err)
	}
	// Verification condition: the provider instance must be observable.
	observed, err := poll(ctx, func() (bool, error) { return s.ProviderExists(ctx, req.ProviderName) })
	if err != nil {
		return appendArtifact(artifacts, artifact), errs.Wrap(errs.Execution, err)
	}
	if !observed {
		return appendArtifact(artifacts, artifact), errs.New(errs.Execution, "provider %s was not observed after registration", req.ProviderName)
	}
	if err := j.UpdateState(ctx, req.RunID, entry.Sequence, journal.StateApplied); err != nil {
		return appendArtifact(artifacts, artifact), errs.Wrap(errs.Execution, err)
	}
	if err := s.ProviderLoad(ctx, `root\default`, req.ProviderName); err != nil {
		return appendArtifact(artifacts, artifact), errs.Wrap(errs.Execution, err)
	}
	return append(artifacts, artifact), nil
}

func (WMIProvider) Rollback(ctx context.Context, s Session, snapshot RecoverySnapshot, artifacts []model.Artifact) error {
	var cleanupErrors []error
	for i := len(artifacts) - 1; i >= 0; i-- {
		artifact := artifacts[i]
		switch artifact.Kind {
		case kindProvider:
			if err := s.ProviderUnload(ctx, `root\default`, artifact.Location); err != nil {
				cleanupErrors = append(cleanupErrors, errs.Wrap(errs.Cleanup, err))
			}
			exists, err := s.ProviderExists(ctx, artifact.Location)
			if err != nil {
				cleanupErrors = append(cleanupErrors, errs.Wrap(errs.Cleanup, err))
				continue
			}
			if !exists {
				continue
			}
			if err := s.ProviderDelete(ctx, artifact.Location); err != nil {
				cleanupErrors = append(cleanupErrors, errs.Wrap(errs.Cleanup, err))
				continue
			}
			if exists, err := s.ProviderExists(ctx, artifact.Location); err != nil {
				cleanupErrors = append(cleanupErrors, errs.Wrap(errs.Cleanup, err))
			} else if exists {
				cleanupErrors = append(cleanupErrors, errs.New(errs.Cleanup, "provider %s still present after deletion", artifact.Location))
			}
		case kindRegistryKey:
			if err := s.ProviderCOMDelete(ctx, clsidFromProviderRegistryPath(artifact.Location)); err != nil {
				cleanupErrors = append(cleanupErrors, errs.Wrap(errs.Cleanup, err))
				continue
			}
			exists, err := s.ProviderCOMExists(ctx, clsidFromProviderRegistryPath(artifact.Location))
			if err != nil {
				cleanupErrors = append(cleanupErrors, errs.Wrap(errs.Cleanup, err))
				continue
			}
			if exists {
				cleanupErrors = append(cleanupErrors, errs.New(errs.Cleanup, "provider COM registration %s still present after deletion", artifact.Location))
			}
		case kindStagedFile:
			if err := rollbackProviderFile(ctx, s, snapshot, artifact); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			}
		}
	}
	return errors.Join(cleanupErrors...)
}

func rollbackProviderFile(ctx context.Context, s Session, snapshot RecoverySnapshot, artifact model.Artifact) error {
	for {
		err := rollbackStagedFile(ctx, s, snapshot, artifact)
		if err == nil {
			return nil
		}
		message := strings.ToLower(err.Error())
		if !strings.Contains(message, "access is denied") && !strings.Contains(message, "sharing violation") && !strings.Contains(message, "used by another process") {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func providerRegistryPath(clsid string) string {
	return `HKLM\SOFTWARE\Classes\CLSID\` + clsid + `\InprocServer32`
}

func clsidFromProviderRegistryPath(path string) string {
	prefix := `HKLM\SOFTWARE\Classes\CLSID\`
	return strings.TrimSuffix(strings.TrimPrefix(path, prefix), `\InprocServer32`)
}
