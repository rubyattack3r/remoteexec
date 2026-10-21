package credentials

import "testing"

func TestValidateSSHRequiresExactlyOneMethod(t *testing.T) {
	valid := []Credentials{
		{Username: "operator", Password: "secret"},
		{Username: "operator", PrivateKeyPath: "key"},
	}
	for _, creds := range valid {
		if err := creds.ValidateSSH(); err != nil {
			t.Errorf("valid credentials rejected: %v", err)
		}
	}
	invalid := []Credentials{
		{},
		{Username: "operator"},
		{Username: "operator", Password: "secret", PrivateKeyPath: "key"},
		{Username: "operator", Password: "secret", Domain: "EXAMPLE"},
	}
	for _, creds := range invalid {
		if err := creds.ValidateSSH(); err == nil {
			t.Errorf("invalid credentials accepted: %#v", creds)
		}
	}
}

func TestValidateWindowsRejectsSSHKey(t *testing.T) {
	creds := Credentials{Username: "operator", Password: "secret", PrivateKeyPath: "key"}
	if err := creds.ValidateWindows(); err == nil {
		t.Fatal("expected SSH-only option rejection")
	}
}
