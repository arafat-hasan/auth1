package main

import (
	"bytes"
	"runtime"
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
