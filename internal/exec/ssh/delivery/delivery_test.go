// Package delivery tests the platform-neutral SSH command plan.
package delivery

import (
	"strings"
	"testing"

	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/plan"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

func TestPlannerBuildsCommandOnlyPlan(t *testing.T) {
	descriptor := technique.Descriptor{Name: "SSHExec", Payloads: []payload.Kind{payload.Command}}
	resolved, local, err := (Planner{}).Build(descriptor, plan.DeliveryOptions{Payload: payload.Spec{Kind: payload.Command, Command: "id"}})
	if err != nil || local != "" || resolved.Kind != "command" || len(resolved.Steps) != 1 {
		t.Fatalf("plan = %#v local = %q err = %v", resolved, local, err)
	}
}

func TestPlannerRejectsFileInputs(t *testing.T) {
	descriptor := technique.Descriptor{Name: "SSHExec", Payloads: []payload.Kind{payload.Command}}
	_, _, err := (Planner{}).Build(descriptor, plan.DeliveryOptions{Payload: payload.Spec{Kind: payload.Command, Command: "id", RemotePath: "/tmp/x"}})
	if err == nil || !strings.Contains(err.Error(), "accept --command only") {
		t.Fatalf("expected command-only validation, got %v", err)
	}
}
