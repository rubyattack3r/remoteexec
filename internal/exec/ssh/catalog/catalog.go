// Package catalog owns the stable SSH technique inventory.
package catalog

import (
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/target"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

// Descriptors returns the Unix inventory for composition with other platform
// catalogs at the CLI boundary.
func Descriptors() []technique.Descriptor {
	return []technique.Descriptor{{
		Name:          "SSHExec",
		Title:         "SSH Command Execution",
		Mechanism:     "Authenticates an SSH session and requests execution of a command without allocating a PTY",
		Prerequisites: []string{"SSH reachable", "Valid password or private key"},
		Requirements:  []technique.Requirement{technique.RequireSSH},
		Privilege:     "Authenticated account; command privileges are those of that account",
		Surface:       []string{"SSH TCP 22 by default (configurable)"},
		Platforms:     []target.Platform{target.Windows, target.Linux, target.Darwin},
		Transport:     target.SSH,
		FileDelivery:  technique.DeliveryNone,
		Invocations:   map[payload.Kind]technique.InvocationMode{payload.Command: technique.InvocationDirect},
		Payloads:      []payload.Kind{payload.Command},
		Recovery:      "Command mode creates no remoteexec-managed persistent artifact; review command-specific effects separately",
		OPSEC:         "medium",
		Detection:     "SSH authentication, session creation, command execution, and resulting processes may be logged; no PTY or file-transfer subsystem is requested.",
	}}
}

func Registry() *technique.Registry {
	r, err := technique.NewRegistry(Descriptors()...)
	if err != nil {
		panic(err)
	}
	return r
}
