package journal

import (
	"context"
	"testing"
	"time"
)

func TestMemoryRecordsAndFiltersEvents(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j := NewMemory(func() time.Time { return fixed })
	first, err := j.Append(context.Background(), Entry{RunID: "run1", Identifier: "a", Mutation: "create"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || first.State != StatePrepared || first.Timestamp != fixed {
		t.Fatalf("first entry = %#v", first)
	}
	if err := j.UpdateState(context.Background(), "run1", first.Sequence, StateApplied); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(context.Background(), Entry{RunID: "run2", Identifier: "b", Mutation: "create"}); err != nil {
		t.Fatal(err)
	}
	entries, err := j.Entries(context.Background(), "run1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || CurrentState(entries, first.Sequence) != StateApplied {
		t.Fatalf("entries = %#v", entries)
	}
}

func TestMemoryRejectsInvalidEvents(t *testing.T) {
	j := NewMemory(nil)
	if _, err := j.Append(context.Background(), Entry{Identifier: "x", Mutation: "m"}); err == nil {
		t.Fatal("missing run id accepted")
	}
	if _, err := j.Append(context.Background(), Entry{RunID: "r", Identifier: "x", Mutation: "m", State: "invalid"}); err == nil {
		t.Fatal("invalid state accepted")
	}
	if err := j.UpdateState(context.Background(), "r", 1, "invalid"); err == nil {
		t.Fatal("invalid state transition accepted")
	}
}
