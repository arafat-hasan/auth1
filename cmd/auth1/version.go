package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

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
	bi, _ := debug.ReadBuildInfo()
	return resolveBuildInfo(version, commit, bi)
}

// resolveBuildInfo prefers the -ldflags values and falls back to what the Go toolchain stamped
// into the binary (module version, VCS revision), so "go install …@vX" reports vX.
func resolveBuildInfo(version, commit string, bi *debug.BuildInfo) buildInfo {
	info := buildInfo{Version: version, Commit: commit, GoVersion: runtime.Version()}
	if bi == nil {
		return info
	}
	if info.Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		info.Version = bi.Main.Version
	}
	if info.Commit == "unknown" {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				info.Commit = s.Value
			}
		}
	}
	return info
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
