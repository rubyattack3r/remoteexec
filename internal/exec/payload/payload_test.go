package payload

import "testing"

func TestKindClassification(t *testing.T) {
	for _, kind := range []Kind{DLL, Executable, Service, Command} {
		if !kind.Valid() {
			t.Errorf("%q should be valid", kind)
		}
		if got, want := kind.RequiresFile(), kind != Command; got != want {
			t.Errorf("%q RequiresFile() = %t, want %t", kind, got, want)
		}
	}
	if ParseKind(" Executable ") != Executable {
		t.Fatal("payload type parsing did not normalize input")
	}
}
