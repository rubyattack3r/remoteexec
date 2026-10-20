package technique

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
)

const (
	// VerifyMarkerSelector is the stable selector of the benign verification
	// adapter.
	VerifyMarkerSelector = "VerifyMarker"

	markerPrefix = "remoteexec-verify-"
	markerSuffix = ".marker"
	markerKind   = "verify_marker"
)

// MarkerPath is the exact verification marker location for a run.
func MarkerPath(root, runID string) string {
	return root + `\` + markerPrefix + runID + markerSuffix
}

// MarkerPattern matches every verification marker inside a staging root.
func MarkerPattern(root string) string {
	return root + `\` + markerPrefix + "*" + markerSuffix
}

// MarkerContent is the fixed, secret-free payload of the verification marker.
func MarkerContent(runID, target string) []byte {
	return []byte(fmt.Sprintf("remoteexec benign verification marker\nrun_id: %s\ntarget: %s\n", runID, target))
}

// Digest is the hex sha256 digest used for integrity verification.
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// VerifyMarker performs the fixed benign verification action: it stages a
// small marker file whose presence, content, and removal are asserted
// automatically. It never touches the user-supplied loader or binary.
type VerifyMarker struct{}

func (VerifyMarker) Name() string { return VerifyMarkerSelector }

func (VerifyMarker) Preflight(ctx context.Context, s Session, req Request) (Evidence, RecoverySnapshot, error) {
	evidence := Evidence{}
	existing, err := s.Glob(ctx, MarkerPattern(req.StagingRoot))
	if err != nil {
		return evidence, RecoverySnapshot{}, errs.Wrap(errs.Reachability, err)
	}
	collision := len(existing) == 0
	detail := "no verification marker present in " + req.StagingRoot
	if !collision {
		detail = fmt.Sprintf("%d existing verification marker(s) in %s", len(existing), req.StagingRoot)
	}
	evidence = append(evidence, engine.Check{Name: "staging_no_collision", Passed: collision, Detail: detail})
	snapshot := RecoverySnapshot{
		Technique: req.Technique.Name,
		Target:    req.Target,
		Entries: []engine.SnapshotEntry{{
			Kind:       markerKind,
			Identifier: MarkerPath(req.StagingRoot, req.RunID),
			Original:   "absent",
		}},
	}
	evidence = append(evidence, engine.Check{Name: "rollback_values_readable", Passed: true, Detail: "verification marker is absent; rollback removes it"})
	if !collision {
		return evidence, snapshot, errs.New(errs.Conflict, "%s already contains a verification marker", req.StagingRoot)
	}
	return evidence, snapshot, nil
}

func (VerifyMarker) Apply(ctx context.Context, s Session, req Request, j Journal) ([]model.Artifact, error) {
	if req.RunID == "" {
		return nil, errs.New(errs.Validation, "verification marker: run id is required")
	}
	artifactPath := MarkerPath(req.StagingRoot, req.RunID)
	content := MarkerContent(req.RunID, req.Target)
	digest := Digest(content)
	entry, err := j.Append(ctx, journal.Entry{
		RunID:        req.RunID,
		Target:       req.Target,
		Technique:    req.Technique.Name,
		ArtifactKind: markerKind,
		Identifier:   artifactPath,
		Original:     "absent",
		Mutation:     "stage verification marker",
		Rollback:     "remove_staged_marker",
		Digest:       digest,
	})
	if err != nil {
		return nil, errs.Wrap(errs.Execution, err)
	}
	artifact := model.Artifact{
		Kind:     markerKind,
		Location: artifactPath,
		Recovery: "Delete the verification marker file " + artifactPath,
	}
	written, err := s.WriteFile(ctx, artifactPath, content)
	if err != nil {
		return []model.Artifact{artifact}, errs.Wrap(errs.Execution, err)
	}
	if written != digest {
		return []model.Artifact{artifact}, errs.New(errs.Execution, "staged %s but read back digest %s", artifactPath, written)
	}
	readBack, err := s.ReadFile(ctx, artifactPath)
	if err != nil {
		return []model.Artifact{artifact}, errs.Wrap(errs.Execution, err)
	}
	if Digest(readBack) != digest {
		return []model.Artifact{artifact}, errs.New(errs.Execution, "verification condition for %s was not observed", artifactPath)
	}
	if err := j.UpdateState(ctx, req.RunID, entry.Sequence, journal.StateApplied); err != nil {
		return []model.Artifact{artifact}, errs.Wrap(errs.Execution, err)
	}
	return []model.Artifact{artifact}, nil
}

func (VerifyMarker) Rollback(ctx context.Context, s Session, snapshot RecoverySnapshot, artifacts []model.Artifact) error {
	for i := len(artifacts) - 1; i >= 0; i-- {
		artifact := artifacts[i]
		if artifact.Kind != markerKind {
			continue
		}
		exists, err := s.FileExists(ctx, artifact.Location)
		if err != nil {
			return errs.Wrap(errs.Cleanup, err)
		}
		if !exists {
			continue
		}
		if err := rollbackStagedFile(ctx, s, snapshot, artifact); err != nil {
			return err
		}
		still, err := s.FileExists(ctx, artifact.Location)
		if err != nil {
			return errs.Wrap(errs.Cleanup, err)
		}
		if still {
			return errs.New(errs.Cleanup, "%s still present after removal", artifact.Location)
		}
	}
	return nil
}
