//go:build !windows

// Package native implements the direct Windows execution path: remoteexec
// runs on Windows and drives Win32 and COM against authorized targets.
// This file is the non-Windows stub that keeps the public cross-platform
// build green.
package native

import (
	"context"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	adapter "github.com/rubyattack3r/remoteexec/internal/exec/windows/technique"
)

// NewSession returns an error off Windows; the native backend never compiles
// into non-Windows builds.
func NewSession(target string, creds credentials.Credentials, auth engine.Auth, runtime engine.RuntimeOptions) (adapter.Session, error) {
	return nil, errs.New(errs.Reachability, "the native backend requires a Windows host; rebuild on Windows")
}

// Close releases no resources in the stub.
func (Probes) Close() {}

var _ = context.Background
