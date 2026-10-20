package technique

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
)

func shortContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func errMissing(what string) error {
	return errors.New("missing " + what)
}

type engineSnapshotEntry engine.SnapshotEntry

func (e engineSnapshotEntry) toEngine() engine.SnapshotEntry {
	return engine.SnapshotEntry(e)
}
