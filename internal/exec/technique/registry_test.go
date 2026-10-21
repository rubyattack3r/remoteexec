package technique

import (
	"testing"

	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/target"
)

func completeDescriptor() Descriptor {
	return Descriptor{Name: "x", Title: "x", Platforms: []target.Platform{target.Windows}, Transport: target.Native, Prerequisites: []string{"x"}, Requirements: []Requirement{RequireLocalAdmin}, Privilege: "x", Surface: []string{"x"}, FileDelivery: DeliveryNone, Invocations: map[payload.Kind]InvocationMode{payload.Command: InvocationDirect}, Payloads: []payload.Kind{payload.Command}, Recovery: "x", Telemetry: "x"}
}

func TestRegistryRejectsIncompleteAndDuplicateDescriptors(t *testing.T) {
	complete := completeDescriptor()
	if _, err := NewRegistry(complete, complete); err == nil {
		t.Fatal("expected duplicate selector error")
	}
	if _, err := NewRegistry(Descriptor{Name: "incomplete"}); err == nil {
		t.Fatal("expected incomplete descriptor error")
	}
	duplicatePayload := completeDescriptor()
	duplicatePayload.Payloads = []payload.Kind{payload.Command, payload.Command}
	if _, err := NewRegistry(duplicatePayload); err == nil {
		t.Fatal("expected duplicate payload type error")
	}
	fileWithoutDelivery := completeDescriptor()
	fileWithoutDelivery.Payloads = []payload.Kind{payload.DLL}
	fileWithoutDelivery.Invocations = map[payload.Kind]InvocationMode{payload.DLL: InvocationNative}
	fileWithoutDelivery.FileDelivery = DeliveryNone
	if _, err := NewRegistry(fileWithoutDelivery); err == nil {
		t.Fatal("expected missing file delivery error")
	}
	commandOnly := completeDescriptor()
	commandOnly.FileDelivery = DeliveryNone
	if _, err := NewRegistry(commandOnly); err != nil {
		t.Fatalf("command-only technique should not require file delivery: %v", err)
	}
	invalidDelivery := completeDescriptor()
	invalidDelivery.FileDelivery = DeliveryMode("invalid")
	if _, err := NewRegistry(invalidDelivery); err == nil {
		t.Fatal("expected invalid file delivery error")
	}
	dllWithoutInvocation := completeDescriptor()
	dllWithoutInvocation.Payloads = []payload.Kind{payload.DLL}
	dllWithoutInvocation.FileDelivery = DeliveryStaged
	if _, err := NewRegistry(dllWithoutInvocation); err == nil {
		t.Fatal("expected missing payload invocation contract error")
	}
	invocationWithoutPayload := completeDescriptor()
	invocationWithoutPayload.Invocations[payload.DLL] = InvocationLauncher
	if _, err := NewRegistry(invocationWithoutPayload); err == nil {
		t.Fatal("expected invocation without payload error")
	}
}

func TestEveryTechniqueValidatesTypedPrerequisites(t *testing.T) {
	all := Capabilities{LocalAdmin: true, WMI: true, RemoteRegistry: true, WinRM: true, DCOM: true, TaskScheduler: true, ActiveShell: true, SCM: true, ExistingService: true, ServiceSnapshot: true}
	for _, descriptor := range []Descriptor{completeDescriptor()} {
		t.Run(descriptor.Name, func(t *testing.T) {
			if err := descriptor.ValidatePrerequisites(all); err != nil {
				t.Fatal(err)
			}
			if err := descriptor.ValidatePrerequisites(Capabilities{}); err == nil {
				t.Fatal("expected actionable missing-prerequisite error")
			}
		})
	}
}
