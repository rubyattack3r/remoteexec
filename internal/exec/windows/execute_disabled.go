//go:build !windows || !remoteexec_experimental

package windows

import (
	"context"
	"errors"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
)

// MutationEnabled reports whether this build may perform technique
// mutations. Public builds are validation-only.
func MutationEnabled() bool { return false }

func (Backend) adapterPreflight(context.Context, engine.Prepared, credentials.Credentials, *engine.PreflightReport) error {
	return nil
}

func (Backend) Execute(context.Context, engine.Prepared, credentials.Credentials) ([]model.Artifact, error) {
	return nil, errors.New("mutation is not available in this build and requires the Windows experimental build; use --dry-run to validate plans")
}
