package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResultSchemaSeparatesExecutionAndRecovery(t *testing.T) {
	result := Result{
		SchemaVersion: SchemaVersion,
		Execution: Execution{
			Disposition: DispositionCompleted,
			Evidence: []ExecutionEvidence{{
				Kind: "process_invocation", Source: "WSMan command", Outcome: "completed",
				ProcessIDStatus: "not_provided_by_api", ExitCode: intPointer(0), Detail: "completed",
			}},
		},
		Recovery: Recovery{Artifacts: []Artifact{}, Constraints: []RecoveryConstraint{}},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, want := range []string{`"schema_version":"0.2.0"`, `"execution":`, `"exit_code":0`, `"recovery":`, `"artifacts":[]`, `"constraints":[]`} {
		if !strings.Contains(text, want) {
			t.Fatalf("result missing %s: %s", want, text)
		}
	}
	if strings.Contains(text, `"process_id":`) {
		t.Fatalf("unavailable process id must not be fabricated: %s", text)
	}
}

func intPointer(value int) *int { return &value }
