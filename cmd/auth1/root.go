package main

import (
	"os"

	"github.com/spf13/cobra"
)

// newRootCmd builds the auth1 command tree. Subcommands are added here as they are built.
func newRootCmd(info buildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:           "auth1",
		Short:         "auth1 identity service",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd(info), newConfigCmd(os.Environ))
	return root
}
