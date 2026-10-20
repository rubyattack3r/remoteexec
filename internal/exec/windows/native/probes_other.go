//go:build !windows

package native

import (
	"context"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
)

// Probes performs no direct checks off Windows.
type Probes struct{}

func (Probes) Authenticate(ctx context.Context, target string, creds credentials.Credentials) error {
	return errs.New(errs.Reachability, "direct preflight checks require a Windows host")
}

func (Probes) LocalAdmin(ctx context.Context, target string, creds credentials.Credentials) (bool, error) {
	return false, errs.New(errs.Reachability, "direct preflight checks require a Windows host")
}

func (Probes) ServiceState(ctx context.Context, target, name string, creds credentials.Credentials) (string, bool, error) {
	return "", false, errs.New(errs.Reachability, "direct preflight checks require a Windows host")
}

func (Probes) ServiceImagePath(ctx context.Context, target, name string, creds credentials.Credentials) (string, bool, error) {
	return "", false, errs.New(errs.Reachability, "direct preflight checks require a Windows host")
}

func (Probes) ActiveSession(ctx context.Context, target string, creds credentials.Credentials) (bool, error) {
	return false, errs.New(errs.Reachability, "direct preflight checks require a Windows host")
}

func (Probes) DiskFree(ctx context.Context, target, path string, creds credentials.Credentials) (uint64, error) {
	return 0, errs.New(errs.Reachability, "direct preflight checks require a Windows host")
}

func (Probes) FileExists(ctx context.Context, target, path string, creds credentials.Credentials) (bool, error) {
	return false, errs.New(errs.Reachability, "direct preflight checks require a Windows host")
}

func (Probes) Glob(ctx context.Context, target, pattern string, creds credentials.Credentials) ([]string, error) {
	return nil, errs.New(errs.Reachability, "direct preflight checks require a Windows host")
}
