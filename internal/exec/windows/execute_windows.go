//go:build windows

package windows

import (
	"context"
	"fmt"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	"github.com/rubyattack3r/remoteexec/internal/exec/windows/native"
	adapter "github.com/rubyattack3r/remoteexec/internal/exec/windows/technique"
)

// closeSession releases backend-owned resources (the impersonation token)
// when the concrete session supports it.
func closeSession(sess adapter.Session) {
	if closer, ok := sess.(interface{ Close() }); ok {
		closer.Close()
	}
}

// adapterPreflight runs every technique-specific read-only check during the
// engine's all-target preflight phase, before the first target can mutate.
func (b Backend) adapterPreflight(ctx context.Context, prepared engine.Prepared, creds credentials.Credentials, report *engine.PreflightReport) error {
	registry, err := adapter.Mutations()
	if err != nil {
		return err
	}
	registration, ok := registry.Get(prepared.Technique.Name)
	if !ok {
		return fmt.Errorf("execution backend: no mutation adapter for technique %q", prepared.Technique.Name)
	}
	req, err := b.mutationRequest(prepared)
	if err != nil {
		return err
	}
	sess, err := native.NewSession(prepared.Target, creds, prepared.Auth, prepared.Runtime)
	if err != nil {
		return err
	}
	defer closeSession(sess)
	evidence, snapshot, err := registration.Adapter.Preflight(ctx, sess, req)
	report.Evidence = append(report.Evidence, evidence...)
	report.Snapshot.Entries = append(report.Snapshot.Entries, snapshot.Entries...)
	if err != nil {
		return fmt.Errorf("execution backend: %s preflight: %w", registration.Adapter.Name(), err)
	}
	return nil
}

func (b Backend) Execute(ctx context.Context, prepared engine.Prepared, creds credentials.Credentials) (artifacts []model.Artifact, err error) {
	jrn := journal.NewMemory(b.clockValue())
	defer func() {
		if recovered := recover(); recovered != nil {
			if entries, journalErr := jrn.Entries(context.Background(), prepared.Report.RunID); journalErr == nil {
				recoveredArtifacts := artifactsFromJournal(entries)
				if len(recoveredArtifacts) > len(artifacts) {
					artifacts = recoveredArtifacts
				}
			}
			err = fmt.Errorf("execution backend panic: %v", recovered)
		}
	}()
	sess, err := native.NewSession(prepared.Target, creds, prepared.Auth, prepared.Runtime)
	if err != nil {
		return nil, err
	}
	defer closeSession(sess)
	return b.runMutation(ctx, prepared, sess, jrn)
}
