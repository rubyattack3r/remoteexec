// Package cmd defines the remoteexec Cobra command tree.
package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/config"
	"github.com/spf13/cobra"
)

func Execute() error { return ExecuteVersion("development") }

func ExecuteVersion(version string) error {
	return newRootCommand(os.Stdout, os.Stderr, version).Execute()
}

func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	return newRootCommand(stdout, stderr, "development")
}

func newRootCommand(stdout, stderr io.Writer, version string) *cobra.Command {
	globals := &config.RootFlags{}
	root := &cobra.Command{
		Use:           "remoteexec",
		Short:         "Authorized remote execution assessment tooling",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if globals.Jitter < 0 || globals.Jitter > 1 {
				return fmt.Errorf("--jitter must be between 0 and 1")
			}
			if globals.Timeout <= 0 {
				return fmt.Errorf("--timeout must be greater than zero")
			}
			return nil
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().StringVar(&globals.Output, "output", "json", "output format: json, yaml, or signal")
	root.PersistentFlags().DurationVar(&globals.Timeout, "timeout", 30*time.Second, "per-target timeout")
	root.PersistentFlags().DurationVar(&globals.Sleep, "sleep", 0, "delay between targets")
	root.PersistentFlags().Float64Var(&globals.Jitter, "jitter", 0, "randomize sleep by this fraction (0-1)")
	root.PersistentFlags().BoolVarP(&globals.Verbose, "verbose", "v", false, "enable verbose diagnostics on stderr")
	root.AddCommand(newExecCommand(globals))
	return root
}
