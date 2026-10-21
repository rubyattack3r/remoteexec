// Package adapter defines the technique adapter boundary, its registry, and
// the technique mutations. Adapters call fixed Session primitives; techniques
// that advertise the command payload type may pass a validated command line
// to their execution primitive without staging a file.
package technique

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/journal"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

// Evidence is the read-only proof an adapter collects before any mutation.
type Evidence = []engine.Check

// RecoverySnapshot is the engine snapshot carried through rollback.
type RecoverySnapshot = engine.RecoverySnapshot

// Mechanism distinguishes the remote API used for service techniques.
type Mechanism string

const (
	MechanismWMI Mechanism = "wmi"
	MechanismSCM Mechanism = "scm"
)

// ServiceConfig is the configuration snapshot of one Windows service.
type ServiceConfig struct {
	Name            string
	DisplayName     string
	PathName        string
	StartMode       string
	StartName       string
	State           string
	DesktopInteract bool
}

// Session exposes the remote operations an adapter may use. Native
// implementations drive Win32 and COM directly.
type Session interface {
	WriteFile(ctx context.Context, path string, content []byte) (string, error)
	ReadFile(ctx context.Context, path string) ([]byte, error)
	RemoveFile(ctx context.Context, path string) error
	FileExists(ctx context.Context, path string) (bool, error)
	Glob(ctx context.Context, pattern string) ([]string, error)

	ProcessCreate(ctx context.Context, commandLine string) (uint32, error)
	ProcessStart(ctx context.Context, path, args string) (uint32, error)
	ShellAvailable(ctx context.Context) error
	ShellExecute(ctx context.Context, path, args string) error
	ProcessFind(ctx context.Context, imageName, commandLineContains string) ([]uint32, error)
	ProcessExists(ctx context.Context, pid uint32) (bool, error)
	ProcessImage(ctx context.Context, pid uint32) (string, error)

	ServiceGet(ctx context.Context, name string) (ServiceConfig, error)
	ServiceExists(ctx context.Context, name string) (bool, error)
	ServiceCreate(ctx context.Context, name, pathName string) error
	ServiceDelete(ctx context.Context, name string) error
	ServiceChangePath(ctx context.Context, name, pathName string, mechanism Mechanism) error
	ServiceStart(ctx context.Context, name string, mechanism Mechanism) error
	ServiceStop(ctx context.Context, name string, mechanism Mechanism) error

	TaskCreate(ctx context.Context, name, path, args string) error
	TaskRun(ctx context.Context, name string) error
	TaskDelete(ctx context.Context, name string) error
	TaskExists(ctx context.Context, name string) (bool, error)

	ProviderRegister(ctx context.Context, name, clsid string) error
	ProviderDelete(ctx context.Context, name string) error
	ProviderExists(ctx context.Context, name string) (bool, error)
	ProviderCOMRegister(ctx context.Context, clsid, dllPath string) error
	ProviderCOMDelete(ctx context.Context, clsid string) error
	ProviderCOMExists(ctx context.Context, clsid string) (bool, error)
	ProviderLoad(ctx context.Context, namespace, name string) error
	ProviderUnload(ctx context.Context, namespace, name string) error
}

// Request carries the validated, technique-scoped inputs for one target.
type Request struct {
	RunID         string
	Target        string
	Technique     technique.Descriptor
	ServiceName   string
	StagingRoot   string
	StagedPath    string
	Payload       []byte
	PayloadKind   payload.Kind
	Digest        string
	Command       string
	Arguments     string
	Export        string
	ProcessID     uint32
	LoaderCommand string
	ProviderName  string
	ProviderCLSID string
}

// Journal is a process-local mutation recorder. It performs no disk I/O and
// exists only while one execution result is being constructed.
type Journal interface {
	Append(ctx context.Context, entry journal.Entry) (journal.Entry, error)
	UpdateState(ctx context.Context, runID string, sequence uint64, state journal.State) error
}

// Adapter is a technique-specific mutation paired with its read-only
// preflight. Apply must not report success until its fixed verification
// condition is observed. Rollback remains an internal recovery primitive and
// is not invoked automatically by the CLI.
type Adapter interface {
	Name() string
	Preflight(context.Context, Session, Request) (Evidence, RecoverySnapshot, error)
	Apply(context.Context, Session, Request, Journal) ([]model.Artifact, error)
	Rollback(context.Context, Session, RecoverySnapshot, []model.Artifact) error
}

var selectorPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

// Registration binds one adapter to a stable technique selector together with
// the recovery metadata required by the registry.
type Registration struct {
	Selector string
	Adapter  Adapter
	Recovery string
}

// Registry holds validated adapter registrations.
type Registry struct {
	entries map[string]Registration
}

// NewRegistry rejects duplicate names, missing adapters, incomplete recovery
// metadata, and mismatches between the adapter name and its stable selector.
func NewRegistry(registrations ...Registration) (*Registry, error) {
	r := &Registry{entries: make(map[string]Registration, len(registrations))}
	for _, reg := range registrations {
		if reg.Adapter == nil {
			return nil, fmt.Errorf("adapter registry: selector %q has no adapter", reg.Selector)
		}
		if !selectorPattern.MatchString(reg.Selector) {
			return nil, fmt.Errorf("adapter registry: selector %q is not a stable selector", reg.Selector)
		}
		if strings.TrimSpace(reg.Recovery) == "" {
			return nil, fmt.Errorf("adapter registry: selector %q has incomplete recovery metadata", reg.Selector)
		}
		if reg.Adapter.Name() != reg.Selector {
			return nil, fmt.Errorf("adapter registry: adapter name %q does not match selector %q", reg.Adapter.Name(), reg.Selector)
		}
		if _, exists := r.entries[reg.Selector]; exists {
			return nil, fmt.Errorf("adapter registry: duplicate selector %q", reg.Selector)
		}
		r.entries[reg.Selector] = reg
	}
	return r, nil
}

// Get returns the registration for a selector.
func (r *Registry) Get(selector string) (Registration, bool) {
	reg, ok := r.entries[selector]
	return reg, ok
}

// Selectors lists registered selectors in stable order.
func (r *Registry) Selectors() []string {
	out := make([]string, 0, len(r.entries))
	for selector := range r.entries {
		out = append(out, selector)
	}
	sort.Strings(out)
	return out
}
