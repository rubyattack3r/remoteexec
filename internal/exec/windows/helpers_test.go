package windows

import (
	"context"
	"testing"
	"time"
)

func shortExecContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}
