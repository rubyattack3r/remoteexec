package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommandTree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := NewRootCommand(&stdout, &stderr)
	root.SetArgs([]string{"exec", "techniques", "--output", "json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"WMIProvider", "WMIService", "WMIExec", "WSManExec", "TaskSchedExec", "DCOMIShellDispatch2", "SCMChangeService", "SCMCreateService", "SSHExec"} {
		if !strings.Contains(stdout.String(), selector) {
			t.Errorf("inventory missing %s", selector)
		}
	}
}

func TestVersionIsInjectedByBuild(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := newRootCommand(&stdout, &stderr, "v1.2.3")
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "v1.2.3") {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestCommandSurfaceHasNoAutomaticCleanupOrJournalFlags(t *testing.T) {
	root := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	if root.PersistentFlags().Lookup("cleanup") != nil {
		t.Fatal("automatic cleanup flag must not be exposed")
	}
	execCommand, _, err := root.Find([]string{"exec", "technique"})
	if err != nil {
		t.Fatal(err)
	}
	if execCommand.Flags().Lookup("journal-dir") != nil {
		t.Fatal("journal directory flag must not be exposed")
	}
}

func TestSSHSurfaceDoesNotExposeHostKeyState(t *testing.T) {
	root := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	execCommand, _, err := root.Find([]string{"exec", "technique"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"known-hosts", "host-key-sha256", "accept-new"} {
		if execCommand.Flags().Lookup(name) != nil {
			t.Fatalf("SSH host-key state flag %q must not be exposed", name)
		}
	}
}

func TestTechniqueReadsPasswordFromStdin(t *testing.T) {
	loader := filepath.Join(t.TempDir(), "loader.dll")
	if err := os.WriteFile(loader, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	root := NewRootCommand(&stdout, &stderr)
	root.SetIn(strings.NewReader("stdin-secret\n"))
	root.SetArgs([]string{
		"exec", "technique", "--dry-run", "--targets", "127.0.0.1",
		"--technique", "WMIExec", "--payload-type", "dll", "--payload", loader,
		"--remote-path", `C:\Windows\Temp\loader.dll`, "--lolbin", "rundll32.exe",
		"--username", "operator", "--password-stdin",
	})
	err := root.Execute()
	// Windows hosts run live preflight, so the fixture identity fails to log
	// on; the secret must stay out of that error too.
	if err != nil && runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "stdin-secret") || strings.Contains(stderr.String(), "stdin-secret") || (err != nil && strings.Contains(err.Error(), "stdin-secret")) {
		t.Fatal("password was emitted")
	}
}

func TestPasswordStdinRejectsAnotherSecretSource(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := NewRootCommand(&stdout, &stderr)
	root.SetIn(strings.NewReader("stdin-secret\n"))
	root.SetArgs([]string{
		"exec", "technique", "--dry-run", "--targets", "127.0.0.1",
		"--technique", "WMIExec", "--payload-type", "dll", "--payload", "fixture.dll",
		"--username", "operator", "--password", "flag-secret", "--password-stdin",
	})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("unexpected error: %v", err)
	}
}
