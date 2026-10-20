package catalog

import (
	"testing"

	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/target"
)

func TestSSHExecContract(t *testing.T) {
	descriptor, ok := Registry().Get("SSHExec")
	if !ok {
		t.Fatal("SSHExec is not registered")
	}
	if descriptor.Transport != target.SSH || !descriptor.SupportsPlatform(target.Windows) || !descriptor.SupportsPlatform(target.Linux) || !descriptor.SupportsPlatform(target.Darwin) || !descriptor.SupportsPayload(payload.Command) {
		t.Fatalf("descriptor = %#v", descriptor)
	}
}
