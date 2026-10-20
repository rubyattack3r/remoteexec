// Package journal defines the process-local mutation event stream used while
// constructing operator-visible recovery artifacts. It performs no disk I/O.
package journal

import (
	"context"
	"time"
)

const SchemaVersion = 1

type State string

const (
	StatePrepared       State = "prepared"
	StateApplied        State = "applied"
	StateRolledBack     State = "rolled_back"
	StateRollbackFailed State = "rollback_failed"
)

func validState(state State) bool {
	switch state {
	case StatePrepared, StateApplied, StateRolledBack, StateRollbackFailed:
		return true
	default:
		return false
	}
}

// Entry describes one mutation without credentials, payload contents, or raw
// command text.
type Entry struct {
	RunID            string    `json:"run_id"`
	SchemaVersion    int       `json:"schema_version"`
	Sequence         uint64    `json:"sequence"`
	Timestamp        time.Time `json:"timestamp"`
	Target           string    `json:"target"`
	Technique        string    `json:"technique"`
	ArtifactKind     string    `json:"artifact_kind"`
	Identifier       string    `json:"identifier"`
	Location         string    `json:"location,omitempty"`
	InvocationID     string    `json:"invocation_id,omitempty"`
	Program          string    `json:"program,omitempty"`
	ProcessID        uint32    `json:"process_id,omitempty"`
	RelatedProcessID uint32    `json:"related_process_id,omitempty"`
	Original         string    `json:"original,omitempty"`
	Mutation         string    `json:"mutation"`
	Rollback         string    `json:"rollback"`
	State            State     `json:"state"`
	Digest           string    `json:"digest,omitempty"`
}

type Journal interface {
	Append(context.Context, Entry) (Entry, error)
	UpdateState(context.Context, string, uint64, State) error
	Entries(context.Context, string) ([]Entry, error)
}

func CurrentState(entries []Entry, sequence uint64) State {
	var state State
	for _, entry := range entries {
		if entry.Sequence == sequence {
			state = entry.State
		}
	}
	return state
}
