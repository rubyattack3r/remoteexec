// Package engine coordinates all-target preflight and execution.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/model"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/plan"
	"github.com/rubyattack3r/remoteexec/internal/exec/target"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
)

const (
	// DefaultWinRMHTTPPort is the standard WinRM HTTP listener port.
	DefaultWinRMHTTPPort = 5985
	// DefaultWinRMHTTPSPort is the standard WinRM HTTPS listener port.
	DefaultWinRMHTTPSPort = 5986
	// DefaultStagingBytes is the minimum free staging space when not overridden.
	DefaultStagingBytes = 16 * 1024 * 1024
	// DefaultSSHPort is the standard SSH server port.
	DefaultSSHPort = 22
)

// Auth selects how the supplied identity reaches remote targets.
type Auth string

const (
	// AuthCredential logs on with the supplied identity (LogonUser) and
	// impersonates it for kernel32/advapi32 calls while passing explicit
	// credentials to COM connections.
	AuthCredential Auth = "credential"
	// AuthToken uses the identity remoteexec already runs as; no secrets are
	// handled.
	AuthToken Auth = "token"
)

type Options struct {
	Targets         []string
	Technique       string
	Payload         payload.Spec
	ServiceName     string
	ProviderName    string
	ProviderCLSID   string
	WinRMPort       int
	WinRMHTTPS      bool
	SSHPort         int
	MinStagingBytes uint64
	Auth            Auth
	Credentials     credentials.Credentials
	DryRun          bool
	Sleep           time.Duration
	Jitter          float64
}

// Provider names the WMI provider registration inputs for WMIProvider.
type Provider struct {
	Name  string
	CLSID string
}

// RuntimeOptions contains environment-specific backend settings. Technique
// identifiers and rollback behavior intentionally do not belong here.
type RuntimeOptions struct {
	WinRMPort       int
	WinRMHTTPS      bool
	MinStagingBytes uint64
	SSHPort         int
}

type Prepared struct {
	Target    string
	Technique technique.Descriptor
	Delivery  plan.Plan
	Report    PreflightReport
	Auth      Auth
	Payload   payload.Spec
	Provider  Provider
	Runtime   RuntimeOptions
}

// Check is one read-only preflight observation and its evidence.
type Check struct {
	Name   string
	Passed bool
	Detail string
}

// SnapshotEntry records one value needed to undo a mutation.
type SnapshotEntry struct {
	Kind       string
	Identifier string
	Original   string
	Digest     string
}

// RecoverySnapshot carries every value needed for rollback, read before any
// mutation.
type RecoverySnapshot struct {
	Technique string
	Target    string
	Entries   []SnapshotEntry
}

// PreflightReport is the evidence a backend must produce for each target
// before any mutation is allowed.
type PreflightReport struct {
	RunID        string
	Target       string
	Capabilities technique.Capabilities
	Evidence     []Check
	Snapshot     RecoverySnapshot
}

// Backend is intentionally technique-agnostic. Implementations must make
// Execute performs one technique invocation and returns every artifact the
// operator may need to recover. Preflight is read-only. The engine completes
// Preflight for every target before Execute runs for any target.
type Backend interface {
	Preflight(context.Context, Prepared, credentials.Credentials) (PreflightReport, error)
	Execute(context.Context, Prepared, credentials.Credentials) ([]model.Artifact, error)
}

// Planner translates shared CLI inputs into a platform-specific delivery
// plan. Keeping this outside the engine prevents Windows paths and loader
// semantics from leaking into the platform-neutral orchestration layer.
type Planner interface {
	Build(technique.Descriptor, plan.DeliveryOptions) (plan.Plan, string, error)
}

type Engine struct {
	Registry *technique.Registry
	Planner  Planner
	Backend  Backend
}

func (e Engine) Prepare(ctx context.Context, opts Options) ([]Prepared, error) {
	if e.Registry == nil {
		return nil, errors.New("engine has no technique registry")
	}
	desc, ok := e.Registry.Get(opts.Technique)
	if !ok {
		return nil, fmt.Errorf("unknown technique %q; run `remoteexec exec techniques`", opts.Technique)
	}
	auth := opts.Auth
	if auth == "" {
		auth = AuthCredential
	}
	if desc.Transport == target.SSH {
		if auth != AuthCredential {
			return nil, errors.New("credential validation: SSH requires --auth credential")
		}
		if err := opts.Credentials.ValidateSSH(); err != nil {
			return nil, err
		}
	} else if auth == AuthToken {
		if opts.Credentials.Username != "" || opts.Credentials.Password != "" || opts.Credentials.PrivateKeyPath != "" {
			return nil, errors.New("credential validation: --auth token takes no identity; unset --username/--password/--private-key")
		}
	} else if auth != AuthCredential {
		return nil, fmt.Errorf("credential validation: unsupported --auth %q (use credential or token)", auth)
	} else if err := opts.Credentials.Validate(); err != nil {
		return nil, err
	}
	if len(opts.Targets) == 0 {
		return nil, errors.New("target validation: --targets is required")
	}
	if e.Planner == nil {
		return nil, errors.New("engine has no platform planner")
	}
	if !opts.Payload.Kind.Valid() {
		return nil, fmt.Errorf("payload validation: --payload-type must be one of dll, cpl, managed, executable, service, or command")
	}
	if !desc.SupportsPayload(opts.Payload.Kind) {
		return nil, fmt.Errorf("payload validation: technique %s does not support payload type %q (supported: %s)", desc.Name, opts.Payload.Kind, payloadKinds(desc.Payloads))
	}
	winRMPort := opts.WinRMPort
	if winRMPort == 0 {
		winRMPort = DefaultWinRMHTTPPort
		if opts.WinRMHTTPS {
			winRMPort = DefaultWinRMHTTPSPort
		}
	}
	if winRMPort < 1 || winRMPort > 65535 {
		return nil, fmt.Errorf("configuration validation: --winrm-port must be between 1 and 65535")
	}
	sshPort := opts.SSHPort
	if sshPort == 0 {
		sshPort = DefaultSSHPort
	}
	if sshPort < 1 || sshPort > 65535 {
		return nil, fmt.Errorf("configuration validation: --ssh-port must be between 1 and 65535")
	}
	minStagingBytes := opts.MinStagingBytes
	if minStagingBytes == 0 {
		minStagingBytes = DefaultStagingBytes
	}
	resolvedPlan, localPath, err := e.Planner.Build(desc, plan.DeliveryOptions{
		Payload: opts.Payload, ServiceName: opts.ServiceName,
	})
	if err != nil {
		return nil, err
	}
	if localPath != "" {
		info, err := os.Stat(localPath)
		if err != nil {
			return nil, fmt.Errorf("delivery validation: cannot read %q: %w", localPath, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("delivery validation: %q is not a regular file", localPath)
		}
	}
	seen := make(map[string]struct{}, len(opts.Targets))
	prepared := make([]Prepared, 0, len(opts.Targets))
	for _, raw := range opts.Targets {
		for _, target := range strings.Split(raw, ",") {
			target = strings.TrimSpace(target)
			if err := validateTarget(target); err != nil {
				return nil, err
			}
			if _, exists := seen[target]; exists {
				continue
			}
			seen[target] = struct{}{}
			prepared = append(prepared, Prepared{
				Target:    target,
				Technique: desc,
				Delivery:  resolvedPlan,
				Auth:      auth,
				Payload:   opts.Payload,
				Provider:  Provider{Name: opts.ProviderName, CLSID: opts.ProviderCLSID},
				Runtime: RuntimeOptions{
					WinRMPort:       winRMPort,
					WinRMHTTPS:      opts.WinRMHTTPS,
					MinStagingBytes: minStagingBytes,
					SSHPort:         sshPort,
				},
			})
		}
	}
	// Preflight every target before executing any target. This is the no-partial-execution boundary.
	if !opts.DryRun && e.Backend == nil {
		return nil, errors.New("execution backend unavailable on this platform; use --dry-run to validate plans")
	}
	if e.Backend != nil {
		digest := ""
		if localPath != "" {
			var err error
			digest, err = fileDigest(localPath)
			if err != nil {
				return nil, err
			}
		}
		for i := range prepared {
			p := &prepared[i]
			report, err := e.Backend.Preflight(ctx, *p, opts.Credentials)
			if err != nil {
				return nil, fmt.Errorf("preflight %s (%s): %w", p.Target, p.Technique.Name, err)
			}
			if report.Target != p.Target {
				return nil, fmt.Errorf("preflight %s (%s): backend returned evidence for %q", p.Target, p.Technique.Name, report.Target)
			}
			if err := p.Technique.ValidatePrerequisites(report.Capabilities); err != nil {
				return nil, fmt.Errorf("preflight %s: %w", p.Target, err)
			}
			if digest != "" {
				report.Evidence = append(report.Evidence, Check{Name: "payload_digest_recorded", Passed: true, Detail: "sha256:" + digest})
			}
			report.Snapshot.Technique = p.Technique.Name
			report.Snapshot.Target = p.Target
			p.Report = report
		}
	}
	return prepared, nil
}

func payloadKinds(kinds []payload.Kind) string {
	values := make([]string, len(kinds))
	for i, kind := range kinds {
		values[i] = string(kind)
	}
	return strings.Join(values, ", ")
}

func (e Engine) Run(ctx context.Context, opts Options) ([]model.Result, error) {
	prepared, err := e.Prepare(ctx, opts)
	if err != nil {
		return nil, err
	}
	results := make([]model.Result, 0, len(prepared))
	for index, p := range prepared {
		started := time.Now().UTC()
		result := newResult(p, started)
		if opts.DryRun {
			result.Status = model.StatusPlanned
			result.FinishedAt = time.Now().UTC()
			results = append(results, result)
			continue
		}
		artifacts, execErr := e.Backend.Execute(ctx, p, opts.Credentials)
		result.Status = model.StatusSucceeded
		if execErr != nil {
			result.Status = model.StatusFailed
			result.Error = executionError(execErr)
			result.ErrorKind = errs.CategoryOf(execErr)
		}
		result.Execution, result.Recovery = classifyOutcome(p.Technique.Name, artifacts, execErr)
		result.FinishedAt = time.Now().UTC()
		results = append(results, result)
		if index < len(prepared)-1 && opts.Sleep > 0 {
			delta := (rand.Float64()*2 - 1) * opts.Jitter
			select {
			case <-time.After(time.Duration(float64(opts.Sleep) * (1 + delta))):
			case <-ctx.Done():
				return append(results, notAttempted(prepared[index+1:], ctx.Err())...), ctx.Err()
			}
		}
	}
	return results, nil
}

func newResult(p Prepared, started time.Time) model.Result {
	return model.Result{
		SchemaVersion: model.SchemaVersion, Technique: p.Technique.Name, Target: p.Target, RunID: p.Report.RunID,
		PayloadType: p.Payload.Kind, StartedAt: started,
		Execution: model.Execution{Disposition: model.DispositionPlanned, Evidence: []model.ExecutionEvidence{}},
		Recovery:  model.Recovery{Artifacts: []model.Artifact{}, Constraints: []model.RecoveryConstraint{}},
	}
}

// notAttempted keeps the one-document-per-target contract when a run stops
// before reaching every prepared target. No mutation happened for these.
func notAttempted(prepared []Prepared, cause error) []model.Result {
	now := time.Now().UTC()
	results := make([]model.Result, 0, len(prepared))
	for _, p := range prepared {
		result := newResult(p, now)
		result.Status = model.StatusFailed
		result.Error = "not attempted: " + executionError(cause)
		result.ErrorKind = errs.Execution
		result.Execution.Disposition = model.DispositionNotAttempted
		result.FinishedAt = now
		results = append(results, result)
	}
	return results
}

func classifyOutcome(selector string, artifacts []model.Artifact, execErr error) (model.Execution, model.Recovery) {
	execution := model.Execution{Disposition: model.DispositionDispatched, Evidence: []model.ExecutionEvidence{}}
	recovery := model.Recovery{Artifacts: []model.Artifact{}, Constraints: []model.RecoveryConstraint{}}
	if execErr != nil {
		execution.Disposition = model.DispositionFailed
	}
	for _, artifact := range artifacts {
		if artifact.Kind != "process_invocation" {
			recovery.Artifacts = append(recovery.Artifacts, artifact)
			continue
		}
		evidence := invocationEvidence(selector, artifact, execErr)
		execution.Evidence = append(execution.Evidence, evidence)
		if artifact.Recovery != "" &&
			!strings.HasPrefix(artifact.Recovery, "No persistent remoteexec artifact") &&
			!strings.HasPrefix(artifact.Recovery, "No remoteexec-managed persistent artifact") {
			recovery.Constraints = append(recovery.Constraints, model.RecoveryConstraint{
				Kind: "process_state", InvocationID: artifact.InvocationID, Program: artifact.Program,
				ProcessID: artifact.ProcessID, RelatedProcessID: artifact.RelatedProcessID,
				Description: artifact.Recovery,
			})
		}
	}
	if execErr == nil {
		switch selector {
		case "WSManExec", "SSHExec":
			execution.Disposition = model.DispositionCompleted
		case "WMIProvider":
			execution.Evidence = append(execution.Evidence, model.ExecutionEvidence{
				Kind: "api_result", Source: "MSFT_Providers.Load", Outcome: "accepted",
				ProcessIDStatus: "not_provided_by_api", Detail: "provider load method returned successfully; payload-defined work is not independently observed",
			})
		case "WMIService", "SCMChangeService", "SCMCreateService":
			execution.Evidence = append(execution.Evidence, model.ExecutionEvidence{
				Kind: "service_state", Source: selector, Outcome: "accepted",
				ProcessIDStatus: "not_provided_by_api", Detail: "service start was accepted; payload-defined completion is not independently observed",
			})
		}
	}
	recovery.Required = len(recovery.Artifacts) > 0
	return execution, recovery
}

func invocationEvidence(selector string, artifact model.Artifact, execErr error) model.ExecutionEvidence {
	source := map[string]string{
		"WMIExec": "Win32_Process.Create", "WSManExec": "WSMan command",
		"TaskSchedExec": "Task Scheduler Run", "DCOMIShellDispatch2": "IShellDispatch2.ShellExecute",
		"SSHExec": "SSH exec request",
	}[selector]
	if source == "" {
		source = selector
	}
	evidence := model.ExecutionEvidence{
		Kind: "process_invocation", Source: source, Outcome: "accepted",
		InvocationID: artifact.InvocationID, Program: artifact.Program,
		ProcessID: artifact.ProcessID, RelatedProcessID: artifact.RelatedProcessID,
		ProcessIDStatus: "not_provided_by_api",
		Detail:          "remote API accepted the invocation; payload completion is not independently observed",
	}
	if artifact.ProcessID != 0 {
		evidence.ProcessIDStatus = "returned_or_observed"
		evidence.Detail = "remote API accepted the invocation and returned or exposed the process identifier; payload completion is not independently observed"
	}
	if execErr != nil {
		evidence.Outcome = "failed"
		evidence.Detail = "the invocation attempt failed; see the result error"
		return evidence
	}
	if selector == "WSManExec" || selector == "SSHExec" {
		zero := 0
		evidence.Outcome = "completed"
		evidence.ExitCode = &zero
		evidence.ProcessIDStatus = "not_provided_by_api"
		evidence.Detail = "remote command completed with exit code 0; this API does not provide a portable process identifier"
	}
	return evidence
}

// executionError keeps timeouts and missing responses from ever reading as
// success.
func executionError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Sprintf("timeout: execution did not complete before its deadline: %v", err)
	}
	return err.Error()
}

func validateTarget(target string) error {
	if target == "" {
		return errors.New("target validation: empty target")
	}
	if strings.ContainsAny(target, `/\\:@[]`) {
		if net.ParseIP(target) == nil {
			return fmt.Errorf("target validation: %q must be a hostname or IP address without a URL, port, or path", target)
		}
	}
	if len(target) > 253 {
		return fmt.Errorf("target validation: %q is too long", target)
	}
	return nil
}

func fileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("delivery validation: cannot read %q: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
