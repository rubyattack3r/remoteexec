// Package windows implements read-only preflight and technique mutations from
// a Windows host.
package windows

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	"github.com/rubyattack3r/remoteexec/internal/exec/plan"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
	"github.com/rubyattack3r/remoteexec/internal/exec/windows/native"
	adapter "github.com/rubyattack3r/remoteexec/internal/exec/windows/technique"
)

// prober performs the direct preflight checks from the host remoteexec runs
// on. The default implementation drives Win32; tests replace it.
type prober interface {
	Authenticate(ctx context.Context, target string, creds credentials.Credentials) error
	LocalAdmin(ctx context.Context, target string, creds credentials.Credentials) (bool, error)
	ServiceState(ctx context.Context, target, name string, creds credentials.Credentials) (string, bool, error)
	ServiceImagePath(ctx context.Context, target, name string, creds credentials.Credentials) (string, bool, error)
	ActiveSession(ctx context.Context, target string, creds credentials.Credentials) (bool, error)
	DiskFree(ctx context.Context, target, path string, creds credentials.Credentials) (uint64, error)
	FileExists(ctx context.Context, target, path string, creds credentials.Credentials) (bool, error)
	Glob(ctx context.Context, target, pattern string, creds credentials.Credentials) ([]string, error)
}

// Backend implements engine.Backend. Probes, clock, run id, dial, and
// adapter check fields are injection points for deterministic tests.
type Backend struct {
	Probes prober

	clock        func() time.Time
	newRunID     func() string
	dialPort     func(ctx context.Context, target string, port int) error
	adapterCheck func(ctx context.Context, prepared engine.Prepared, creds credentials.Credentials, report *engine.PreflightReport) error
}

func (b Backend) probesValue() prober {
	if b.Probes != nil {
		return b.Probes
	}
	return &native.Probes{}
}

func (b Backend) clockValue() func() time.Time {
	if b.clock != nil {
		return b.clock
	}
	return time.Now
}

func (b Backend) newRunIDValue() string {
	if b.newRunID != nil {
		return b.newRunID()
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(raw[:])
}

func (b Backend) adapterCheckValue() func(ctx context.Context, prepared engine.Prepared, creds credentials.Credentials, report *engine.PreflightReport) error {
	if b.adapterCheck != nil {
		return b.adapterCheck
	}
	return b.adapterPreflight
}

func (b Backend) dialPortValue() func(ctx context.Context, target string, port int) error {
	if b.dialPort != nil {
		return b.dialPort
	}
	return func(ctx context.Context, target string, port int) error {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}
}

// Preflight is read-only. It collects and retains evidence for
// authentication, authorization, reachability, staging state,
// technique-specific state, and every value needed for rollback.
func (b Backend) Preflight(ctx context.Context, prepared engine.Prepared, creds credentials.Credentials) (engine.PreflightReport, error) {
	report := engine.PreflightReport{RunID: b.newRunIDValue(), Target: prepared.Target, Evidence: []engine.Check{}}
	probe := b.probesValue()
	if closer, ok := probe.(interface{ Close() }); ok {
		defer closer.Close()
	}
	if err := probe.Authenticate(ctx, prepared.Target, creds); err != nil {
		addEvidence(&report, "authentication", false, err.Error())
		return report, fmt.Errorf("execution backend: authentication to %s: %w", prepared.Target, err)
	}
	addEvidence(&report, "authentication", true, "identity authenticated to "+prepared.Target)

	var caps technique.Capabilities
	winRMPort := prepared.Runtime.WinRMPort
	if winRMPort == 0 {
		winRMPort = engine.DefaultWinRMHTTPPort
		if prepared.Runtime.WinRMHTTPS {
			winRMPort = engine.DefaultWinRMHTTPSPort
		}
	}
	ports := requiredPorts(prepared.Technique.Name, winRMPort, prepared.Payload.Kind)
	smbRequired := false
	for _, port := range ports {
		if port == 445 {
			// The ADMIN$ authorization probe below performs an authenticated
			// SMB round trip. A preceding raw TCP connect to the SMB listener
			// can disrupt the Windows redirector's next authenticated UNC open,
			// so use the protocol-level probe as the reachability evidence.
			smbRequired = true
			continue
		}
		if err := b.dialPortValue()(ctx, prepared.Target, port); err != nil {
			addEvidence(&report, "network_surface", false, fmt.Sprintf("TCP %d: %v", port, err))
			return report, errs.Wrap(errs.Reachability, fmt.Errorf("execution backend: %s is not reachable on TCP %d", prepared.Target, port))
		}
		switch port {
		case 135:
			caps.WMI, caps.DCOM = true, true
		}
	}
	if prepared.Technique.Name == "WSManExec" {
		caps.WinRM = true
	}
	admin, err := probe.LocalAdmin(ctx, prepared.Target, creds)
	if err != nil {
		addEvidence(&report, "administrative_authorization", false, err.Error())
		return report, fmt.Errorf("execution backend: administrative check on %s: %w", prepared.Target, err)
	}
	caps.LocalAdmin = admin
	addEvidence(&report, "administrative_authorization", admin, fmt.Sprintf("local administrator=%t", admin))
	if !admin {
		return report, errs.New(errs.Authorization, "execution backend: identity lacks local administrator on %s", prepared.Target)
	}
	if smbRequired {
		caps.SCM = true
	}
	addEvidence(&report, "network_surface", true, fmt.Sprintf("required surfaces %v reachable; SMB validated through ADMIN$", ports))

	svcName := serviceNameOf(prepared)
	if svcName != "" {
		state, found, err := probe.ServiceState(ctx, prepared.Target, svcName, creds)
		if err != nil {
			addEvidence(&report, "technique_state", false, err.Error())
			return report, fmt.Errorf("execution backend: service query on %s: %w", prepared.Target, err)
		}
		caps.ExistingService = found
		addEvidence(&report, "technique_state", found, fmt.Sprintf("service %s found=%t state=%s", svcName, found, state))
		if !found {
			return report, errs.New(errs.Validation, "execution backend: service %s is absent on %s", svcName, prepared.Target)
		}
		imagePath, readable, err := probe.ServiceImagePath(ctx, prepared.Target, svcName, creds)
		if err != nil || !readable {
			caps.ServiceSnapshot = false
			addEvidence(&report, "rollback_values_readable", false, "service configuration is not readable")
			return report, errs.New(errs.Validation, "execution backend: service %s configuration is not readable", svcName)
		}
		caps.ServiceSnapshot = true
		report.Snapshot.Entries = append(report.Snapshot.Entries, engine.SnapshotEntry{Kind: "service_path", Identifier: svcName, Original: imagePath})
	} else if createName := createdServiceNameOf(prepared); createName != "" {
		_, found, err := probe.ServiceState(ctx, prepared.Target, createName, creds)
		if err != nil {
			addEvidence(&report, "technique_state", false, err.Error())
			return report, fmt.Errorf("execution backend: temporary service collision check on %s: %w", prepared.Target, err)
		}
		addEvidence(&report, "technique_state", !found, fmt.Sprintf("temporary service %s absent=%t", createName, !found))
		if found {
			return report, errs.New(errs.Conflict, "execution backend: temporary service %s already exists on %s", createName, prepared.Target)
		}
		report.Snapshot.Entries = append(report.Snapshot.Entries, engine.SnapshotEntry{Kind: "temporary_service", Identifier: createName, Original: "absent"})
	} else if requires(prepared.Technique, technique.RequireActiveShell) {
		shell, err := probe.ActiveSession(ctx, prepared.Target, creds)
		if err != nil {
			addEvidence(&report, "technique_state", false, err.Error())
			return report, fmt.Errorf("execution backend: session query on %s: %w", prepared.Target, err)
		}
		caps.ActiveShell = shell
		addEvidence(&report, "technique_state", true, fmt.Sprintf("active interactive session=%t", shell))
	}
	if state, found, err := probe.ServiceState(ctx, prepared.Target, "RemoteRegistry", creds); err == nil {
		caps.RemoteRegistry = found && state == "Running"
	}
	if state, found, err := probe.ServiceState(ctx, prepared.Target, "Schedule", creds); err == nil {
		caps.TaskScheduler = found && state == "Running"
	}
	addEvidence(&report, "technique_state", true, techniqueStateDetail(caps))
	for _, step := range prepared.Delivery.Steps {
		if step.Action != "verify_launcher" {
			continue
		}
		exists, err := probe.FileExists(ctx, prepared.Target, step.Artifact, creds)
		if err != nil {
			return report, fmt.Errorf("execution backend: launcher program check for %s: %w", step.Artifact, err)
		}
		addEvidence(&report, "launcher_program", exists, step.Artifact)
		if !exists {
			return report, errs.New(errs.Validation, "execution backend: launcher program %s does not exist on %s", step.Artifact, prepared.Target)
		}
	}

	if prepared.Payload.Kind.RequiresFile() {
		stagingRoot := prepared.Delivery.StagingRoot
		if stagingRoot == "" {
			return report, errs.New(errs.Validation, "execution backend: delivery plan has no staging root")
		}
		rootExists, err := probe.FileExists(ctx, prepared.Target, stagingRoot, creds)
		if err != nil {
			return report, fmt.Errorf("execution backend: staging directory check for %s: %w", stagingRoot, err)
		}
		if !rootExists {
			addEvidence(&report, "staging_directory", false, stagingRoot+" does not exist")
			return report, errs.New(errs.Validation, "execution backend: remote staging directory %s does not exist", stagingRoot)
		}
		addEvidence(&report, "staging_directory", true, stagingRoot)
		free, err := probe.DiskFree(ctx, prepared.Target, stagingRoot, creds)
		if err != nil {
			addEvidence(&report, "staging_space", false, err.Error())
			return report, fmt.Errorf("execution backend: staging space check on %s: %w", prepared.Target, err)
		}
		minimum := prepared.Runtime.MinStagingBytes
		if minimum == 0 {
			minimum = engine.DefaultStagingBytes
		}
		spaceOK := free >= minimum
		addEvidence(&report, "staging_space", spaceOK, fmt.Sprintf("%d bytes free in %s; minimum %d", free, stagingRoot, minimum))
		collisions := 0
		detail := []string{}
		for _, path := range stagedArtifacts(prepared.Delivery) {
			exists, err := probe.FileExists(ctx, prepared.Target, path, creds)
			if err != nil {
				return report, fmt.Errorf("execution backend: staging collision check for %s: %w", path, err)
			}
			if exists {
				collisions++
				detail = append(detail, "staging path "+path+" already exists")
				report.Snapshot.Entries = append(report.Snapshot.Entries, engine.SnapshotEntry{Kind: "staged_file", Identifier: path, Original: "present"})
			} else {
				report.Snapshot.Entries = append(report.Snapshot.Entries, engine.SnapshotEntry{Kind: "staged_file", Identifier: path, Original: "absent"})
			}
		}
		markerNames, err := probe.Glob(ctx, prepared.Target, adapter.MarkerPattern(stagingRoot), creds)
		if err != nil {
			return report, fmt.Errorf("execution backend: marker collision check: %w", err)
		}
		if len(markerNames) > 0 {
			collisions += len(markerNames)
			detail = append(detail, fmt.Sprintf("%d verification marker collision(s)", len(markerNames)))
		}
		noCollision := collisions == 0
		addEvidence(&report, "staging_no_collision", noCollision, strings.Join(detail, "; "))
		if !spaceOK {
			return report, errs.New(errs.Validation, "execution backend: %s has insufficient free space for staging", stagingRoot)
		}
		if !noCollision {
			return report, errs.New(errs.Conflict, "execution backend: staging destination already contains conflicting files")
		}
		report.Snapshot.Entries = append(report.Snapshot.Entries, engine.SnapshotEntry{Kind: "verify_marker", Identifier: adapter.MarkerPath(stagingRoot, report.RunID), Original: "absent"})
	}
	if prepared.Payload.Kind == payload.Command {
		addEvidence(&report, "rollback_values_readable", true, "command mode has no staged-file rollback values")
	} else {
		addEvidence(&report, "rollback_values_readable", len(report.Snapshot.Entries) > 0, fmt.Sprintf("%d rollback values recorded", len(report.Snapshot.Entries)))
	}
	report.Snapshot.Technique = prepared.Technique.Name
	report.Snapshot.Target = prepared.Target
	report.Capabilities = caps
	prepared.Report = report
	if err := b.adapterCheckValue()(ctx, prepared, creds, &report); err != nil {
		addEvidence(&report, "adapter_preflight", false, err.Error())
		return report, err
	}
	addEvidence(&report, "adapter_preflight", true, prepared.Technique.Name+" mutation inputs and recovery state validated")
	return report, nil
}

func requires(descriptor technique.Descriptor, wanted technique.Requirement) bool {
	for _, requirement := range descriptor.Requirements {
		if requirement == wanted {
			return true
		}
	}
	return false
}

func techniqueStateDetail(caps technique.Capabilities) string {
	parts := []string{}
	if caps.RemoteRegistry {
		parts = append(parts, "RemoteRegistry running")
	}
	if caps.TaskScheduler {
		parts = append(parts, "Task Scheduler running")
	}
	if caps.ActiveShell {
		parts = append(parts, "active interactive session")
	}
	if len(parts) == 0 {
		return "no additional technique state"
	}
	return strings.Join(parts, "; ")
}

func addEvidence(report *engine.PreflightReport, name string, passed bool, detail string) {
	report.Evidence = append(report.Evidence, engine.Check{Name: name, Passed: passed, Detail: detail})
}

func stagedArtifacts(plan plan.Plan) []string {
	var out []string
	for _, step := range plan.Steps {
		if strings.HasPrefix(step.Action, "stage_") {
			out = append(out, step.Artifact)
		}
	}
	return out
}

func serviceNameOf(prepared engine.Prepared) string {
	for _, step := range prepared.Delivery.Steps {
		if step.Action == "snapshot_service_configuration" {
			return step.Artifact
		}
	}
	return ""
}

func createdServiceNameOf(prepared engine.Prepared) string {
	for _, step := range prepared.Delivery.Steps {
		if step.Action == "verify_service_absent" {
			return step.Artifact
		}
	}
	return ""
}

func requiredPorts(name string, winRMPort int, kind payload.Kind) []int {
	switch name {
	case "WSManExec":
		if winRMPort == 0 {
			winRMPort = engine.DefaultWinRMHTTPPort
		}
		if kind == payload.Command {
			return []int{winRMPort}
		}
		return []int{445, winRMPort}
	case "SCMChangeService":
		return []int{135, 445}
	default:
		if kind == payload.Command {
			return []int{135}
		}
		return []int{135, 445}
	}
}
