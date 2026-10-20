// Package model contains the stable output contract shared by all techniques.
package model

import (
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
)

const (
	// SchemaVersion is the pre-1.0 Result contract. Until 1.0, incompatible
	// changes bump the minor component and compatible changes bump the patch.
	SchemaVersion = "0.1.0"
	// SignalType tags the Signal envelope and tracks the schema major version.
	SignalType = "remoteexec.result.v0"
)

type Status string

const (
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusPlanned   Status = "planned"
)

type Artifact struct {
	Kind             string `json:"kind" yaml:"kind"`
	Location         string `json:"location" yaml:"location"`
	InvocationID     string `json:"invocation_id,omitempty" yaml:"invocation_id,omitempty"`
	Program          string `json:"program,omitempty" yaml:"program,omitempty"`
	Digest           string `json:"digest,omitempty" yaml:"digest,omitempty"`
	Original         string `json:"original,omitempty" yaml:"original,omitempty"`
	Recovery         string `json:"recovery,omitempty" yaml:"recovery,omitempty"`
	ProcessID        uint32 `json:"process_id,omitempty" yaml:"process_id,omitempty"`
	RelatedProcessID uint32 `json:"related_process_id,omitempty" yaml:"related_process_id,omitempty"`
}

// Result is emitted once for every target, regardless of technique.
type Result struct {
	SchemaVersion string        `json:"schema_version" yaml:"schema_version"`
	Technique     string        `json:"technique" yaml:"technique"`
	Target        string        `json:"target" yaml:"target"`
	RunID         string        `json:"run_id,omitempty" yaml:"run_id,omitempty"`
	PayloadType   payload.Kind  `json:"payload_type" yaml:"payload_type"`
	Status        Status        `json:"status" yaml:"status"`
	StartedAt     time.Time     `json:"started_at" yaml:"started_at"`
	FinishedAt    time.Time     `json:"finished_at" yaml:"finished_at"`
	Artifacts     []Artifact    `json:"artifacts" yaml:"artifacts"`
	Error         string        `json:"error,omitempty" yaml:"error,omitempty"`
	ErrorKind     errs.Category `json:"error_kind,omitempty" yaml:"error_kind,omitempty"`
}
