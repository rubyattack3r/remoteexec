package ssh

import (
	"context"
	"testing"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

type fakeConnector struct {
	session *fakeSession
	err     error
	port    int
}

func (c *fakeConnector) Connect(_ context.Context, _ string, port int, _ credentials.Credentials) (Session, error) {
	c.port = port
	if c.err != nil {
		return nil, c.err
	}
	return c.session, nil
}

type fakeSession struct {
	command string
	runErr  error
}

func (s *fakeSession) Run(_ context.Context, command string) error {
	s.command = command
	return s.runErr
}
func (s *fakeSession) Close() error { return nil }

func prepared(command string) engine.Prepared {
	return engine.Prepared{
		Target: "unix01",
		Technique: technique.Descriptor{
			Name: "SSHExec",
		},
		Payload: payload.Spec{Kind: payload.Command, Command: command},
		Runtime: engine.RuntimeOptions{SSHPort: 2222},
	}
}

func TestPreflightAuthenticates(t *testing.T) {
	connector := &fakeConnector{session: &fakeSession{}}
	backend := Backend{Connector: connector, newRunID: func() string { return "run-1" }}
	report, err := backend.Preflight(context.Background(), prepared("id"), credentials.Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if report.RunID != "run-1" || !report.Capabilities.SSH || connector.port != 2222 {
		t.Fatalf("report = %#v connector = %#v", report, connector)
	}
}

func TestExecuteDelegatesToSSHExecTechnique(t *testing.T) {
	session := &fakeSession{}
	backend := Backend{Connector: &fakeConnector{session: session}}
	artifacts, err := backend.Execute(context.Background(), prepared("id"), credentials.Credentials{})
	if err != nil || session.command != "id" || len(artifacts) != 1 {
		t.Fatalf("command = %q artifacts = %#v err = %v", session.command, artifacts, err)
	}
}
