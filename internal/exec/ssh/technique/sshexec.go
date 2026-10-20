// Package technique owns SSH technique invocation and artifact contracts.
package technique

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
)

type Session interface {
	Run(context.Context, string) error
}

type Request struct {
	Command string
}

// Execute sends one command through an authenticated SSH session and returns
// the shared redacted invocation artifact regardless of the remote exit code.
func Execute(ctx context.Context, session Session, request Request) ([]model.Artifact, error) {
	command := strings.TrimSpace(request.Command)
	sum := sha256.Sum256([]byte(command))
	invocationID := "command:sha256:" + hex.EncodeToString(sum[:])
	artifact := model.Artifact{
		Kind:         "process_invocation",
		Location:     invocationID,
		InvocationID: invocationID,
		Original:     "absent",
		Recovery:     "No remoteexec-managed persistent artifact; review endpoint process state and command-specific effects",
	}
	if err := session.Run(ctx, command); err != nil {
		return []model.Artifact{artifact}, errs.Wrap(errs.Execution, fmt.Errorf("ssh execution request failed: %w", err))
	}
	return []model.Artifact{artifact}, nil
}
