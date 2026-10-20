// Package delivery builds command execution plans for SSH transports.
package delivery

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/plan"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

type Planner struct{}

func (Planner) Build(descriptor technique.Descriptor, opts plan.DeliveryOptions) (plan.Plan, string, error) {
	if opts.Payload.Kind != payload.Command || !descriptor.SupportsPayload(payload.Command) {
		return plan.Plan{}, opts.Payload.LocalPath, fmt.Errorf("delivery validation: %s currently supports command payloads only", descriptor.Name)
	}
	command := strings.TrimSpace(opts.Payload.Command)
	if command == "" {
		return plan.Plan{}, "", errors.New("delivery validation: --command is required for command payloads")
	}
	if strings.ContainsAny(command, "\x00\r\n") || len(command) > 32767 {
		return plan.Plan{}, "", errors.New("delivery validation: --command must be a single command line of at most 32767 bytes")
	}
	if opts.Payload.LocalPath != "" || opts.Payload.RemotePath != "" || opts.Payload.Arguments != "" || opts.Payload.LOLBin != "" || opts.Payload.LauncherProgram != "" || opts.Payload.LauncherArguments != "" || opts.Payload.ProcessID != 0 {
		return plan.Plan{}, "", errors.New("delivery validation: SSH command payloads accept --command only")
	}
	return plan.Plan{Kind: string(payload.Command), Steps: []plan.Step{{Action: "execute_command", Artifact: "SSH exec request"}}, Recovery: []plan.Step{}}, "", nil
}
