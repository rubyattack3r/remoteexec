// Package plan defines platform-neutral execution and recovery plans.
package plan

import "github.com/rubyattack3r/remoteexec/internal/exec/payload"

type Step struct {
	Action   string `json:"action" yaml:"action"`
	Artifact string `json:"artifact,omitempty" yaml:"artifact,omitempty"`
}

type Plan struct {
	Kind        string `json:"kind" yaml:"kind"`
	StagingRoot string `json:"staging_root" yaml:"staging_root"`
	Steps       []Step `json:"steps" yaml:"steps"`
	Recovery    []Step `json:"recovery" yaml:"recovery"`
}

// DeliveryOptions contains platform-neutral loader inputs supplied by the CLI.
type DeliveryOptions struct {
	Payload     payload.Spec
	ServiceName string
}
