package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/arafat-hasan/auth1/migrations"
)

// newRootCmd builds the auth1 command tree. Subcommands are added here as they are built.
func newRootCmd(info buildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:           "auth1",
		Short:         "auth1 identity service",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd(info), newConfigCmd(os.Environ), newServeCmd(os.Environ, info, defaultServeDeps()),
		newMigrateCmd(os.Environ, migrations.FS))
	return root
}
