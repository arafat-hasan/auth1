package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Set at build time with -ldflags "-X main.version=… -X main.commit=…".
var (
	version = "dev"
	commit  = "unknown"
)

// buildInfo identifies the running binary.
type buildInfo struct {
	Version   string
	Commit    string
	GoVersion string
}

// defaultBuildInfo returns the build information linked into this binary.
func defaultBuildInfo() buildInfo {
	return buildInfo{Version: version, Commit: commit, GoVersion: runtime.Version()}
}

func newVersionCmd(info buildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version, commit and Go version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "version: %s\ncommit: %s\ngo: %s\n",
				info.Version, info.Commit, info.GoVersion)
			return err
		},
	}
}
