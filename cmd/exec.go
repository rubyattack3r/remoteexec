package cmd

import (
	"github.com/rubyattack3r/remoteexec/internal/config"
	"github.com/spf13/cobra"
)

func newExecCommand(globals *config.RootFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "exec", Short: "Execute or inventory remote execution techniques"}
	cmd.AddCommand(newTechniqueCommand(globals), newTechniquesCommand(globals), newBinariesCommand(globals))
	return cmd
}
