package windows

import (
	"context"
	"os"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	adapter "github.com/rubyattack3r/remoteexec/internal/exec/windows/technique"
)

func (b Backend) mutationRequest(prepared engine.Prepared) (adapter.Request, error) {
	req := adapter.Request{
		RunID:         prepared.Report.RunID,
		Target:        prepared.Target,
		Technique:     prepared.Technique,
		ServiceName:   selectedServiceName(prepared),
		StagingRoot:   prepared.Delivery.StagingRoot,
		StagedPath:    firstStagedPath(prepared),
		PayloadKind:   prepared.Payload.Kind,
		Command:       prepared.Payload.Command,
		Arguments:     prepared.Payload.Arguments,
		Export:        prepared.Payload.EntryPoint,
		ProcessID:     prepared.Payload.ProcessID,
		LoaderCommand: loaderCommandOf(prepared),
		ProviderName:  prepared.Provider.Name,
		ProviderCLSID: prepared.Provider.CLSID,
	}
	if prepared.Payload.LocalPath != "" {
		payload, err := os.ReadFile(prepared.Payload.LocalPath)
		if err != nil {
			return req, errs.New(errs.Validation, "execution backend: read payload: %v", err)
		}
		req.Payload = payload
		req.Digest = adapter.Digest(payload)
	}
	return req, nil
}

func selectedServiceName(prepared engine.Prepared) string {
	for _, step := range prepared.Delivery.Steps {
		if step.Action == "snapshot_service_configuration" || step.Action == "verify_service_absent" {
			return step.Artifact
		}
	}
	return ""
}

// runMutation dispatches to the registered adapter for the technique and
// applies it through the native session. Returned artifacts are the
// operator's recovery record; the engine does not roll them back.
func (b Backend) runMutation(ctx context.Context, prepared engine.Prepared, sess adapter.Session, jrn journal.Journal) ([]model.Artifact, error) {
	registry, err := adapter.Mutations()
	if err != nil {
		return nil, err
	}
	registration, ok := registry.Get(prepared.Technique.Name)
	if !ok {
		return nil, errs.New(errs.Validation, "execution backend: no mutation adapter for technique %q", prepared.Technique.Name)
	}
	req, err := b.mutationRequest(prepared)
	if err != nil {
		return nil, err
	}
	return registration.Adapter.Apply(ctx, sess, req, jrn)
}

// rollbackMutation rebuilds the recovery snapshot from the journal, walks
// artifacts in reverse order through the adapter, and records the outcome of
// every journaled mutation.
func (b Backend) rollbackMutation(ctx context.Context, prepared engine.Prepared, sess adapter.Session, jrn journal.Journal, artifacts []model.Artifact) error {
	if len(artifacts) == 0 {
		return nil
	}
	registry, err := adapter.Mutations()
	if err != nil {
		return err
	}
	registration, ok := registry.Get(prepared.Technique.Name)
	if !ok {
		return errs.New(errs.Cleanup, "execution backend: no mutation adapter for technique %q", prepared.Technique.Name)
	}
	runID := prepared.Report.RunID
	entries, err := jrn.Entries(ctx, runID)
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	snapshot := snapshotFromJournal(entries)
	rollbackErr := registration.Adapter.Rollback(ctx, sess, snapshot, artifacts)
	for _, artifact := range artifacts {
		identifier := artifact.Location
		if artifact.InvocationID != "" {
			identifier = artifact.InvocationID
		}
		entry, found := latestPreparedEntry(entries, identifier)
		if !found {
			continue
		}
		state := journal.StateRolledBack
		if rollbackErr != nil {
			state = journal.StateRollbackFailed
		}
		if err := jrn.UpdateState(ctx, runID, entry.Sequence, state); err != nil {
			return errs.Wrap(errs.Cleanup, err)
		}
	}
	return rollbackErr
}

// snapshotFromJournal rebuilds the rollback snapshot from the prepared
// events, which carry the original values and digests.
func snapshotFromJournal(entries []journal.Entry) engine.RecoverySnapshot {
	var snapshot engine.RecoverySnapshot
	seen := map[uint64]bool{}
	for _, entry := range entries {
		if entry.Mutation == "" || seen[entry.Sequence] {
			continue
		}
		seen[entry.Sequence] = true
		snapshot.Entries = append(snapshot.Entries, engine.SnapshotEntry{
			Kind:       entry.ArtifactKind,
			Identifier: entry.Identifier,
			Original:   entry.Original,
			Digest:     entry.Digest,
		})
	}
	return snapshot
}

func latestPreparedEntry(entries []journal.Entry, identifier string) (journal.Entry, bool) {
	var found journal.Entry
	ok := false
	for _, entry := range entries {
		if entry.Identifier == identifier && entry.Mutation != "" {
			found = entry
			ok = true
		}
	}
	return found, ok
}

func artifactsFromJournal(entries []journal.Entry) []model.Artifact {
	artifacts := make([]model.Artifact, 0)
	seen := make(map[uint64]bool)
	for _, entry := range entries {
		if entry.Mutation == "" || seen[entry.Sequence] {
			continue
		}
		seen[entry.Sequence] = true
		location := entry.Location
		if location == "" {
			location = entry.Identifier
		}
		artifacts = append(artifacts, model.Artifact{
			Kind: entry.ArtifactKind, Location: location, InvocationID: entry.InvocationID,
			Program: entry.Program, Digest: entry.Digest, Original: entry.Original,
			ProcessID: entry.ProcessID, RelatedProcessID: entry.RelatedProcessID,
		})
	}
	return artifacts
}

func firstStagedPath(prepared engine.Prepared) string {
	if paths := stagedArtifacts(prepared.Delivery); len(paths) > 0 {
		return paths[0]
	}
	return ""
}

func loaderCommandOf(prepared engine.Prepared) string {
	for _, step := range prepared.Delivery.Steps {
		if step.Action == "invoke_loader" {
			return step.Artifact
		}
	}
	return ""
}
