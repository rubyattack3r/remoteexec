package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/config"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/payload"
	sshexecution "github.com/rubyattack3r/remoteexec/internal/exec/ssh"
	sshcatalog "github.com/rubyattack3r/remoteexec/internal/exec/ssh/catalog"
	sshdelivery "github.com/rubyattack3r/remoteexec/internal/exec/ssh/delivery"
	"github.com/rubyattack3r/remoteexec/internal/exec/target"
	"github.com/rubyattack3r/remoteexec/internal/exec/technique"
	execution "github.com/rubyattack3r/remoteexec/internal/exec/windows"
	windowscatalog "github.com/rubyattack3r/remoteexec/internal/exec/windows/catalog"
	"github.com/rubyattack3r/remoteexec/internal/exec/windows/delivery"
	"github.com/rubyattack3r/remoteexec/internal/output"
	"github.com/spf13/cobra"
)

func newTechniqueCommand(globals *config.RootFlags) *cobra.Command {
	var opts engine.Options
	var passwordStdin bool
	var payloadType string
	cmd := &cobra.Command{
		Use:   "technique",
		Short: "Validate and execute a named technique against one or more targets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.Payload.Kind = payload.ParseKind(payloadType)
			if err := output.Validate(globals.Output); err != nil {
				return err
			}
			if passwordStdin {
				if opts.Credentials.Password != "" || opts.Credentials.NTHash != "" || opts.Credentials.PrivateKeyPath != "" {
					return fmt.Errorf("credential validation: --password-stdin cannot be combined with --password, --nt-hash, or --private-key")
				}
				password, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if err != nil && len(password) == 0 {
					return fmt.Errorf("credential validation: read password from stdin: %w", err)
				}
				opts.Credentials.Password = strings.TrimRight(password, "\r\n")
				if opts.Credentials.Password == "" {
					return fmt.Errorf("credential validation: password from stdin is empty")
				}
			}
			opts.Sleep = globals.Sleep
			opts.Jitter = globals.Jitter
			opts.Auth = engine.Auth(globals.Auth)
			registry := combinedRegistry()
			descriptor, ok := registry.Get(opts.Technique)
			if !ok {
				return fmt.Errorf("unknown technique %q; run `remoteexec exec techniques`", opts.Technique)
			}
			if descriptor.Transport == target.Native && !opts.DryRun && !execution.MutationEnabled() {
				return fmt.Errorf("mutation requires the Windows experimental build (remoteexec_experimental); use --dry-run to validate plans")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), globals.Timeout*time.Duration(max(1, len(opts.Targets))))
			defer cancel()
			runner := engine.Engine{Registry: registry}
			switch descriptor.Transport {
			case target.SSH:
				runner.Planner = sshdelivery.Planner{}
				runner.Backend = sshexecution.Backend{}
			case target.Native:
				runner.Planner = delivery.Planner{}
				if execution.Supported() {
					runner.Backend = execution.Backend{}
				}
			}
			results, err := runner.Run(ctx, opts)
			// Emit whatever ran before an interruption so recovery records for
			// already-mutated targets reach stdout.
			if writeErr := output.Results(cmd.OutOrStdout(), output.Format(globals.Output), results); writeErr != nil {
				return errors.Join(err, writeErr)
			}
			return err
		},
	}
	cmd.Flags().StringSliceVar(&opts.Targets, "targets", nil, "target hostname or IP (repeatable or comma-separated)")
	cmd.Flags().StringVar(&opts.Technique, "technique", "", "stable technique selector")
	cmd.Flags().StringVar(&payloadType, "payload-type", "", "execution input type: dll, cpl, managed, executable, service, or command")
	cmd.Flags().StringVar(&opts.Payload.LocalPath, "payload", "", "local payload file")
	cmd.Flags().StringVar(&opts.Payload.Arguments, "arguments", "", "raw argument string for an executable payload")
	cmd.Flags().StringVar(&opts.Payload.Command, "command", "", "command line for a command payload")
	cmd.Flags().StringVar(&opts.Payload.LOLBin, "lolbin", "", "launcher selector for dll, cpl, or managed payloads")
	cmd.Flags().StringVar(&opts.Payload.LauncherProgram, "launcher-program", "", `absolute remote executable path for a custom launcher or built-in path override`)
	cmd.Flags().StringVar(&opts.Payload.LauncherArguments, "launcher-arguments", "", `custom argument template; supports {remote_path}, {entry_point}, and {process_id}`)
	cmd.Flags().Uint32Var(&opts.Payload.ProcessID, "process-id", 0, "existing remote process ID required by process-bound launchers")
	cmd.Flags().StringVar(&opts.ServiceName, "service-name", "", "existing service to reconfigure or temporary service to create")
	cmd.Flags().StringVar(&opts.Payload.EntryPoint, "entry-point", "ServiceMain", "DLL export passed to rundll32 invocation")
	cmd.Flags().StringVar(&opts.ProviderName, "provider-name", "", "WMI provider registration name (WMIProvider)")
	cmd.Flags().StringVar(&opts.ProviderCLSID, "provider-clsid", "", "WMI provider COM class identifier, e.g. {GUID}")
	cmd.Flags().StringVar(&opts.Payload.RemotePath, "remote-path", "", `absolute remote destination path (required for file payloads)`)
	cmd.Flags().IntVar(&opts.WinRMPort, "winrm-port", 0, "WinRM listener port (default 5985 for HTTP or 5986 for HTTPS)")
	cmd.Flags().BoolVar(&opts.WinRMHTTPS, "winrm-https", false, "use HTTPS rather than HTTP for WSManExec (default port 5986)")
	cmd.Flags().Uint64Var(&opts.MinStagingBytes, "min-staging-bytes", engine.DefaultStagingBytes, "minimum free bytes required in the remote staging directory")
	cmd.Flags().IntVar(&opts.SSHPort, "ssh-port", engine.DefaultSSHPort, "SSH server port")
	cmd.Flags().StringVar(&globals.Auth, "auth", "credential", "identity source: credential, or token for Windows current-identity execution")
	cmd.Flags().StringVar(&opts.Credentials.Domain, "domain", "", "Windows domain (empty for a local account)")
	cmd.Flags().StringVar(&opts.Credentials.Username, "username", "", "account username")
	cmd.Flags().StringVar(&opts.Credentials.Password, "password", "", "account password (prefer a protected environment integration)")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the account password from standard input")
	cmd.Flags().StringVar(&opts.Credentials.NTHash, "nt-hash", "", "NT hash alternative to a password")
	cmd.Flags().StringVar(&opts.Credentials.PrivateKeyPath, "private-key", "", "unencrypted OpenSSH private key used for SSH authentication")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "validate all prerequisites and emit plans without remote changes")
	_ = cmd.MarkFlagRequired("targets")
	_ = cmd.MarkFlagRequired("technique")
	_ = cmd.MarkFlagRequired("payload-type")
	return cmd
}

func newTechniquesCommand(globals *config.RootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "techniques",
		Short: "List technique prerequisites, surfaces, recovery, and detectability",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := output.Validate(globals.Output); err != nil {
				return err
			}
			return output.Value(cmd.OutOrStdout(), output.Format(globals.Output), combinedRegistry().List())
		},
	}
}

func combinedRegistry() *technique.Registry {
	descriptors := windowscatalog.Registry().List()
	descriptors = append(descriptors, sshcatalog.Descriptors()...)
	registry, err := technique.NewRegistry(descriptors...)
	if err != nil {
		panic(err)
	}
	return registry
}

func newBinariesCommand(globals *config.RootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "binaries",
		Short: "List supported LOLBins and their typed payload contracts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := output.Validate(globals.Output); err != nil {
				return err
			}
			return output.Value(cmd.OutOrStdout(), output.Format(globals.Output), delivery.Binaries())
		},
	}
}
