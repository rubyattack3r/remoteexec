package technique

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeSession struct {
	command string
	err     error
}

func (s *fakeSession) Run(_ context.Context, command string) error {
	s.command = command
	return s.err
}

func TestExecuteReturnsRedactedInvocationArtifact(t *testing.T) {
	session := &fakeSession{}
	command := "printf highly-sensitive-value"
	artifacts, err := Execute(context.Background(), session, Request{Command: command})
	if err != nil {
		t.Fatal(err)
	}
	if session.command != command || len(artifacts) != 1 {
		t.Fatalf("command = %q artifacts = %#v", session.command, artifacts)
	}
	encoded := artifacts[0].Location + artifacts[0].InvocationID + artifacts[0].Recovery
	if strings.Contains(encoded, command) || !strings.HasPrefix(artifacts[0].InvocationID, "command:sha256:") {
		t.Fatalf("artifact exposed command: %#v", artifacts[0])
	}
}

func TestExecuteReturnsArtifactWhenRemoteCommandFails(t *testing.T) {
	session := &fakeSession{err: errors.New("exit status 7")}
	artifacts, err := Execute(context.Background(), session, Request{Command: "false"})
	if err == nil || len(artifacts) != 1 {
		t.Fatalf("artifacts = %#v err = %v", artifacts, err)
	}
}
