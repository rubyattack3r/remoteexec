//go:build !windows

package windows

import (
	"context"
	"errors"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
)

func (Backend) adapterPreflight(context.Context, engine.Prepared, credentials.Credentials, *engine.PreflightReport) error {
	return nil
}

func (Backend) Execute(context.Context, engine.Prepared, credentials.Credentials) ([]model.Artifact, error) {
	return nil, errors.New("Windows-native execution requires running the Windows build of remoteexec")
}
