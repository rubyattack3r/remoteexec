// Package payload defines the platform-neutral input executed by a technique.
package payload

import "strings"

// Kind identifies how execution input is delivered.
type Kind string

const (
	DLL        Kind = "dll"
	CPL        Kind = "cpl"
	Managed    Kind = "managed"
	Executable Kind = "executable"
	Service    Kind = "service"
	Command    Kind = "command"
)

// Spec is the normalized payload contract shared by planners and backends.
// Command payloads have no local or remote file.
type Spec struct {
	Kind       Kind   `json:"type" yaml:"type"`
	LocalPath  string `json:"local_path,omitempty" yaml:"local_path,omitempty"`
	RemotePath string `json:"remote_path,omitempty" yaml:"remote_path,omitempty"`
	Command    string `json:"command,omitempty" yaml:"command,omitempty"`
	Arguments  string `json:"arguments,omitempty" yaml:"arguments,omitempty"`
	EntryPoint string `json:"entry_point,omitempty" yaml:"entry_point,omitempty"`
	ProcessID  uint32 `json:"process_id,omitempty" yaml:"process_id,omitempty"`
	LOLBin     string `json:"lolbin,omitempty" yaml:"lolbin,omitempty"`
	// LauncherProgram and LauncherArguments define an operator-supplied payload
	// launcher when LOLBin is "custom", or override a built-in program path.
	// LauncherArguments is a custom template whose
	// required {remote_path} placeholder is resolved by the delivery planner.
	LauncherProgram   string `json:"launcher_program,omitempty" yaml:"launcher_program,omitempty"`
	LauncherArguments string `json:"launcher_arguments,omitempty" yaml:"launcher_arguments,omitempty"`
}

// Valid reports whether kind is part of the stable payload vocabulary.
func (kind Kind) Valid() bool {
	switch kind {
	case DLL, CPL, Managed, Executable, Service, Command:
		return true
	default:
		return false
	}
}

// RequiresFile reports whether the payload has local source and remote
// staging lifecycles.
func (kind Kind) RequiresFile() bool {
	return kind == DLL || kind == CPL || kind == Managed || kind == Executable || kind == Service
}

// UsesLauncher reports whether a staged file is executed by a launcher
// contract rather than directly by a technique.
func (kind Kind) UsesLauncher() bool { return kind == DLL || kind == CPL || kind == Managed }

// ParseKind normalizes a CLI payload type.
func ParseKind(value string) Kind {
	return Kind(strings.ToLower(strings.TrimSpace(value)))
}
