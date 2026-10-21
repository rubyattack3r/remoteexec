// Package technique is the registry boundary between Cobra and execution backends.
package technique

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/target"
)

// DeliveryMode identifies the file-transfer lifecycle used by a technique.
// Command payloads do not use file delivery.
type DeliveryMode string

const (
	DeliveryNone          DeliveryMode = "none"
	DeliveryStaged        DeliveryMode = "staged"
	DeliveryServiceChange DeliveryMode = "service"
	DeliveryServiceCreate DeliveryMode = "service_create"
)

func (mode DeliveryMode) Valid() bool {
	switch mode {
	case DeliveryNone, DeliveryStaged, DeliveryServiceChange, DeliveryServiceCreate:
		return true
	default:
		return false
	}
}

// InvocationMode identifies how a technique executes one supported payload.
// It is separate from file delivery because staging and invocation have
// different validation and operator inputs.
type InvocationMode string

const (
	InvocationDirect   InvocationMode = "direct"
	InvocationNative   InvocationMode = "native"
	InvocationLauncher InvocationMode = "launcher"
	InvocationService  InvocationMode = "service"
)

func (invocation InvocationMode) Valid() bool {
	switch invocation {
	case InvocationDirect, InvocationNative, InvocationLauncher, InvocationService:
		return true
	default:
		return false
	}
}

type Descriptor struct {
	Name          string                          `json:"name" yaml:"name"`
	Title         string                          `json:"title" yaml:"title"`
	Mechanism     string                          `json:"mechanism" yaml:"mechanism"`
	Prerequisites []string                        `json:"prerequisites" yaml:"prerequisites"`
	Privilege     string                          `json:"privilege" yaml:"privilege"`
	Surface       []string                        `json:"surface" yaml:"surface"`
	Platforms     []target.Platform               `json:"platforms" yaml:"platforms"`
	Transport     target.Transport                `json:"transport" yaml:"transport"`
	FileDelivery  DeliveryMode                    `json:"file_delivery" yaml:"file_delivery"`
	Invocations   map[payload.Kind]InvocationMode `json:"invocations" yaml:"invocations"`
	Payloads      []payload.Kind                  `json:"payload_types" yaml:"payload_types"`
	Recovery      string                          `json:"recovery" yaml:"recovery"`
	Telemetry     string                          `json:"telemetry" yaml:"telemetry"`
	Requirements  []Requirement                   `json:"-" yaml:"-"`
}

type Registry struct{ entries map[string]Descriptor }

func NewRegistry(descriptors ...Descriptor) (*Registry, error) {
	r := &Registry{entries: make(map[string]Descriptor, len(descriptors))}
	for _, d := range descriptors {
		if err := validateDescriptor(d); err != nil {
			return nil, err
		}
		if _, exists := r.entries[d.Name]; exists {
			return nil, fmt.Errorf("duplicate technique selector %q", d.Name)
		}
		r.entries[d.Name] = d
	}
	return r, nil
}

func (r *Registry) Get(name string) (Descriptor, bool) {
	d, ok := r.entries[name]
	return d, ok
}

func (r *Registry) List() []Descriptor {
	out := make([]Descriptor, 0, len(r.entries))
	for _, d := range r.entries {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func validateDescriptor(d Descriptor) error {
	if strings.TrimSpace(d.Name) == "" || strings.TrimSpace(d.Title) == "" {
		return errors.New("technique descriptor requires name and title")
	}
	if len(d.Prerequisites) == 0 || len(d.Requirements) == 0 || d.Privilege == "" || len(d.Surface) == 0 || d.Recovery == "" || d.Telemetry == "" {
		return fmt.Errorf("technique %q has incomplete prerequisite, surface, recovery, or telemetry metadata", d.Name)
	}
	if len(d.Platforms) == 0 || !d.FileDelivery.Valid() || len(d.Payloads) == 0 {
		return fmt.Errorf("technique %q has incomplete platform, transport, or delivery metadata", d.Name)
	}
	seenPlatforms := make(map[target.Platform]bool, len(d.Platforms))
	for _, platform := range d.Platforms {
		if !platform.Valid() || d.Transport == "" || seenPlatforms[platform] {
			return fmt.Errorf("technique %q has invalid or duplicate platform %q", d.Name, platform)
		}
		seenPlatforms[platform] = true
	}
	seenPayloads := map[payload.Kind]bool{}
	requiresFileDelivery := false
	for _, kind := range d.Payloads {
		if !kind.Valid() || seenPayloads[kind] {
			return fmt.Errorf("technique %q has invalid or duplicate payload type %q", d.Name, kind)
		}
		seenPayloads[kind] = true
		requiresFileDelivery = requiresFileDelivery || kind.RequiresFile()
		mode, ok := d.Invocations[kind]
		if !ok || !mode.Valid() {
			return fmt.Errorf("technique %q has no valid invocation for payload type %q", d.Name, kind)
		}
	}
	if requiresFileDelivery && d.FileDelivery == DeliveryNone {
		return fmt.Errorf("technique %q supports file payloads but has no file delivery mode", d.Name)
	}
	for kind := range d.Invocations {
		if !seenPayloads[kind] {
			return fmt.Errorf("technique %q declares invocation for unsupported payload type %q", d.Name, kind)
		}
	}
	return nil
}

// SupportsPlatform reports whether the descriptor can execute on platform.
func (d Descriptor) SupportsPlatform(platform target.Platform) bool {
	for _, supported := range d.Platforms {
		if supported == platform {
			return true
		}
	}
	return false
}

// InvocationFor returns the validated invocation contract for kind.
func (d Descriptor) InvocationFor(kind payload.Kind) (InvocationMode, bool) {
	mode, ok := d.Invocations[kind]
	return mode, ok
}

// SupportsPayload reports whether the descriptor accepts kind.
func (d Descriptor) SupportsPayload(kind payload.Kind) bool {
	for _, supported := range d.Payloads {
		if supported == kind {
			return true
		}
	}
	return false
}
