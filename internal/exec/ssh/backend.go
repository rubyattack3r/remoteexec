// Package ssh implements platform-neutral authenticated SSH command execution.
// It intentionally does not retain or verify host keys.
package ssh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	sshtechnique "github.com/rubyattack3r/remoteexec/internal/exec/ssh/technique"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

type Session interface {
	Run(context.Context, string) error
	Close() error
}

type Connector interface {
	Connect(context.Context, string, int, credentials.Credentials) (Session, error)
}

type Backend struct {
	Connector Connector
	newRunID  func() string
}

func (b Backend) connector() Connector {
	if b.Connector != nil {
		return b.Connector
	}
	return NativeConnector{}
}

func (b Backend) runID() string {
	if b.newRunID != nil {
		return b.newRunID()
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}

func (b Backend) Preflight(ctx context.Context, prepared engine.Prepared, creds credentials.Credentials) (engine.PreflightReport, error) {
	report := engine.PreflightReport{RunID: b.runID(), Target: prepared.Target, Evidence: []engine.Check{}}
	session, err := b.connector().Connect(ctx, prepared.Target, prepared.Runtime.SSHPort, creds)
	if err != nil {
		report.Evidence = append(report.Evidence, engine.Check{Name: "ssh_session", Passed: false, Detail: "connection or authentication failed"})
		return report, err
	}
	defer session.Close()
	report.Evidence = append(report.Evidence, engine.Check{Name: "ssh_session", Passed: true, Detail: "identity authenticated; server host key not verified"})
	report.Capabilities = technique.Capabilities{SSH: true}
	return report, nil
}

func (b Backend) Execute(ctx context.Context, prepared engine.Prepared, creds credentials.Credentials) ([]model.Artifact, error) {
	session, err := b.connector().Connect(ctx, prepared.Target, prepared.Runtime.SSHPort, creds)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	return sshtechnique.Execute(ctx, session, sshtechnique.Request{Command: prepared.Payload.Command})
}
