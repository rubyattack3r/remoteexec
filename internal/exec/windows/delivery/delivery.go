// Package delivery builds typed command and transactional file-delivery plans.
package delivery

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/plan"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

type Kind string

const (
	Service       Kind = "service"
	ServiceCreate Kind = "service_create"
	Staged        Kind = "staged"
	LOLBAS        Kind = "lolbas" // retained internally for older plan fixtures
)

type Request struct {
	Kind        Kind
	Payload     payload.Spec
	ServiceName string
	Invocation  technique.InvocationMode
}

type Step = plan.Step
type Plan = plan.Plan

func Build(req Request) (Plan, error) {
	if req.Payload.Kind == payload.Command {
		if req.Kind != Staged && req.Kind != LOLBAS {
			return Plan{}, errors.New("delivery validation: command payloads are not supported by service techniques")
		}
		if strings.TrimSpace(req.Payload.Command) == "" {
			return Plan{}, errors.New("delivery validation: --command is required for command payloads")
		}
		if strings.ContainsAny(req.Payload.Command, "\x00\r\n") || len(req.Payload.Command) > 32767 {
			return Plan{}, errors.New("delivery validation: --command must be a single command line of at most 32767 bytes")
		}
		if req.Payload.LocalPath != "" || req.Payload.RemotePath != "" {
			return Plan{}, errors.New("delivery validation: command payloads cannot use --payload or --remote-path")
		}
		if req.Payload.Arguments != "" {
			return Plan{}, errors.New("delivery validation: command payloads include arguments in --command, not --arguments")
		}
		if hasLauncherOptions(req.Payload) {
			return Plan{}, errors.New("delivery validation: launcher options are only valid with dll, cpl, or managed payloads")
		}
		return Plan{Kind: string(payload.Command), Steps: []Step{{Action: "execute_command", Artifact: "direct command"}}, Recovery: []Step{}}, nil
	}
	if !req.Payload.Kind.RequiresFile() {
		return Plan{}, fmt.Errorf("delivery validation: unsupported payload type %q", req.Payload.Kind)
	}
	if req.Payload.LocalPath == "" {
		return Plan{}, errors.New("delivery validation: --payload is required for file payloads")
	}
	if strings.TrimSpace(req.Payload.Command) != "" {
		return Plan{}, errors.New("delivery validation: --command is only valid with --payload-type command")
	}
	if req.Payload.Kind != payload.Executable && req.Payload.Arguments != "" {
		return Plan{}, errors.New("delivery validation: --arguments is only valid with --payload-type executable")
	}
	if !req.Payload.Kind.UsesLauncher() && hasLauncherOptions(req.Payload) {
		return Plan{}, errors.New("delivery validation: --lolbin, --launcher-program, and --launcher-arguments require a dll, cpl, or managed payload")
	}
	if !req.Payload.Kind.UsesLauncher() && req.Payload.ProcessID != 0 {
		return Plan{}, errors.New("delivery validation: --process-id requires a launcher payload")
	}
	if strings.ContainsAny(req.Payload.Arguments, "\x00\r\n") || len(req.Payload.Arguments) > 32767 {
		return Plan{}, errors.New("delivery validation: --arguments must be a single argument line of at most 32767 bytes")
	}
	name := filepath.Base(req.Payload.LocalPath)
	if name == "." || name == string(filepath.Separator) {
		return Plan{}, errors.New("delivery validation: invalid local path")
	}
	remote, root, err := resolveRemotePath(req.Payload.RemotePath)
	if err != nil {
		return Plan{}, err
	}
	switch req.Kind {
	case Service:
		if req.Payload.Kind != payload.Service {
			return Plan{}, errors.New("delivery validation: service techniques require --payload-type service")
		}
		if strings.TrimSpace(req.ServiceName) == "" {
			return Plan{}, errors.New("delivery validation: --service-name is required for service techniques")
		}
		return Plan{Kind: string(Service), StagingRoot: root, Steps: []Step{
			{Action: "snapshot_service_configuration", Artifact: req.ServiceName},
			{Action: "stage_binary", Artifact: remote},
			{Action: "replace_service_binary_path", Artifact: req.ServiceName},
			{Action: "start_service", Artifact: req.ServiceName},
		}, Recovery: []Step{
			{Action: "restore_service_configuration", Artifact: req.ServiceName},
			{Action: "remove_staged_binary", Artifact: remote},
		}}, nil
	case ServiceCreate:
		if req.Payload.Kind != payload.Service {
			return Plan{}, errors.New("delivery validation: service creation requires --payload-type service")
		}
		if strings.TrimSpace(req.ServiceName) == "" {
			return Plan{}, errors.New("delivery validation: --service-name is required for service techniques")
		}
		return Plan{Kind: string(ServiceCreate), StagingRoot: root, Steps: []Step{
			{Action: "verify_service_absent", Artifact: req.ServiceName},
			{Action: "stage_binary", Artifact: remote},
			{Action: "create_service", Artifact: req.ServiceName},
			{Action: "start_service", Artifact: req.ServiceName},
		}, Recovery: []Step{
			{Action: "stop_and_delete_service", Artifact: req.ServiceName},
			{Action: "remove_staged_binary", Artifact: remote},
		}}, nil
	case Staged, LOLBAS:
		if req.Payload.Kind == payload.Executable {
			return Plan{Kind: string(payload.Executable), StagingRoot: root, Steps: []Step{
				{Action: "stage_executable", Artifact: remote},
				{Action: "execute_staged", Artifact: remote},
			}, Recovery: []Step{{Action: "remove_staged_executable", Artifact: remote}}}, nil
		}
		if !req.Payload.Kind.UsesLauncher() {
			return Plan{}, errors.New("delivery validation: staged file delivery requires a launcher-compatible payload or executable")
		}
		switch req.Invocation {
		case technique.InvocationNative:
			if hasLauncherOptions(req.Payload) {
				return Plan{}, errors.New("delivery validation: launcher options are not used when the selected technique loads the payload natively")
			}
			return Plan{Kind: string(Staged), StagingRoot: root, Steps: []Step{
				{Action: "stage_loader", Artifact: remote},
			}, Recovery: []Step{{Action: "remove_staged_loader", Artifact: remote}}}, nil
		case technique.InvocationLauncher:
			// Validate the explicit selector below.
		default:
			return Plan{}, errors.New("delivery validation: selected technique has no launcher invocation contract")
		}
		selector := req.Payload.LOLBin
		if selector == "" {
			return Plan{}, errors.New("delivery validation: --lolbin is required for launcher payloads used by this technique")
		}
		commandLine, launcherPath, err := resolveLauncher(req.Payload, remote)
		if err != nil {
			return Plan{}, err
		}
		steps := []Step{{Action: "stage_payload", Artifact: remote}}
		if launcherPath != "" {
			steps = append([]Step{{Action: "verify_launcher", Artifact: launcherPath}}, steps...)
		}
		steps = append(steps, Step{Action: "invoke_loader", Artifact: commandLine})
		return Plan{
			Kind: string(LOLBAS), StagingRoot: root, Steps: steps,
			Recovery: []Step{{Action: "remove_staged_payload", Artifact: remote}},
		}, nil
	default:
		return Plan{}, fmt.Errorf("delivery validation: unsupported delivery kind %q", req.Kind)
	}
}

// Planner translates the shared CLI inputs into a Windows-specific delivery
// plan without making the core engine depend on Windows paths or semantics.
type Planner struct{}

func (Planner) Build(descriptor technique.Descriptor, opts plan.DeliveryOptions) (plan.Plan, string, error) {
	invocation, ok := descriptor.InvocationFor(opts.Payload.Kind)
	if !ok {
		return plan.Plan{}, opts.Payload.LocalPath, fmt.Errorf("delivery validation: technique %s does not support payload type %s", descriptor.Name, opts.Payload.Kind)
	}
	result, err := Build(Request{
		Kind: Kind(descriptor.FileDelivery), Payload: opts.Payload, ServiceName: opts.ServiceName,
		Invocation: invocation,
	})
	return result, opts.Payload.LocalPath, err
}

func resolveRemotePath(configured string) (string, string, error) {
	remote := strings.TrimSpace(configured)
	if remote == "" {
		return "", "", errors.New("delivery validation: --remote-path is required for file payloads")
	}
	remote = strings.ReplaceAll(remote, "/", `\`)
	if !drivePathPattern.MatchString(remote) {
		return "", "", errors.New("delivery validation: --remote-path must be an absolute drive path such as C:\\Windows\\Temp\\loader.dll")
	}
	parts := strings.Split(remote[3:], `\`)
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `:*?"<>|`) {
			return "", "", fmt.Errorf("delivery validation: invalid --remote-path %q", configured)
		}
	}
	separator := strings.LastIndex(remote, `\`)
	if separator < 3 || separator == len(remote)-1 {
		return "", "", fmt.Errorf("delivery validation: --remote-path %q must include a file name", configured)
	}
	return remote, remote[:separator], nil
}
