package main

import (
	"bytes"
	"runtime"
	"runtime/debug"
	"testing"
)

func TestVersionPrintsBuildInfo(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd(buildInfo{Version: "v1.2.3", Commit: "abc123", GoVersion: "go1.27.3"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute version: %v", err)
	}

	want := "version: v1.2.3\ncommit: abc123\ngo: go1.27.3\n"
	if got := out.String(); got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}

func TestDefaultBuildInfo(t *testing.T) {
	t.Parallel()

	info := defaultBuildInfo()
	if info.Version != "dev" {
		t.Errorf("Version = %q, want %q", info.Version, "dev")
	}
	if info.Commit != "unknown" {
		t.Errorf("Commit = %q, want %q", info.Commit, "unknown")
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
}

func TestResolveBuildInfo(t *testing.T) {
	t.Parallel()

	stamped := &debug.BuildInfo{
		Main:     debug.Module{Version: "v1.0.0"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef"}},
	}
	tests := []struct {
		name            string
		version, commit string
		bi              *debug.BuildInfo
		want            buildInfo
	}{
		{
			name: "no build info", version: "dev", commit: "unknown",
			want: buildInfo{Version: "dev", Commit: "unknown"},
		},
		{
			name: "devel build without VCS", version: "dev", commit: "unknown",
			bi:   &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			want: buildInfo{Version: "dev", Commit: "unknown"},
		},
		{
			name: "stamped by the toolchain", version: "dev", commit: "unknown", bi: stamped,
			want: buildInfo{Version: "v1.0.0", Commit: "0123456789abcdef"},
		},
		{
			name: "ldflags win", version: "v2.0.0", commit: "abc123", bi: stamped,
			want: buildInfo{Version: "v2.0.0", Commit: "abc123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.want.GoVersion = runtime.Version()
			if got := resolveBuildInfo(tt.version, tt.commit, tt.bi); got != tt.want {
				t.Errorf("resolveBuildInfo = %+v, want %+v", got, tt.want)
			}
		})
	}
}
