package journal

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Memory records mutation events for the duration of one execution without
// creating a local artifact. It exists so adapters can preserve their
// write-before-mutate sequencing while stdout remains the operator's record.
type Memory struct {
	mu       sync.Mutex
	clock    func() time.Time
	sequence uint64
	entries  []Entry
}

func NewMemory(clock func() time.Time) *Memory {
	if clock == nil {
		clock = time.Now
	}
	return &Memory{clock: clock}
}

func (m *Memory) Append(_ context.Context, entry Entry) (Entry, error) {
	if entry.RunID == "" || entry.Identifier == "" || entry.Mutation == "" {
		return Entry{}, errors.New("mutation record requires run id, identifier, and mutation")
	}
	if entry.State == "" {
		entry.State = StatePrepared
	}
	if !validState(entry.State) {
		return Entry{}, fmt.Errorf("invalid mutation state %q", entry.State)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sequence++
	entry.SchemaVersion = SchemaVersion
	entry.Sequence = m.sequence
	entry.Timestamp = m.clock().UTC()
	m.entries = append(m.entries, entry)
	return entry, nil
}

func (m *Memory) UpdateState(_ context.Context, runID string, sequence uint64, state State) error {
	if runID == "" || sequence == 0 {
		return errors.New("mutation state requires run id and sequence")
	}
	if !validState(state) {
		return fmt.Errorf("invalid mutation state %q", state)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, Entry{RunID: runID, SchemaVersion: SchemaVersion, Sequence: sequence, Timestamp: m.clock().UTC(), State: state})
	return nil
}

func (m *Memory) Entries(_ context.Context, runID string) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entry, 0, len(m.entries))
	for _, entry := range m.entries {
		if runID == "" || entry.RunID == runID {
			out = append(out, entry)
		}
	}
	return out, nil
}
