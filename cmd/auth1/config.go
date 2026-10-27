package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/arafat-hasan/auth1/internal/config"
)

// errConfigInvalid is returned by "config check" after it has printed the problems.
var errConfigInvalid = errors.New("configuration invalid")

// newConfigCmd builds "auth1 config". environ supplies the AUTH1_ overrides (os.Environ in main).
func newConfigCmd(environ func() []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration commands",
	}

	var path string
	check := &cobra.Command{
		Use:   "check",
		Short: "Load and validate a configuration and its secret files, then exit",
		Long: "Load a configuration file with its AUTH1_ environment overrides, apply every rule " +
			"and security floor, and check that each secret file exists and is readable. " +
			"Exits 0 when the configuration is valid and 1 otherwise.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return checkConfig(cmd, path, environ())
		},
	}
	check.Flags().StringVar(&path, "config", "", "configuration file (YAML)")
	_ = check.MarkFlagRequired("config")
	cmd.AddCommand(check)
	return cmd
}

// checkConfig prints "configuration OK" or every problem from loading and validating, one per
// line. A file that cannot be read or parsed is returned as an error.
func checkConfig(cmd *cobra.Command, path string, environ []string) error {
	cfg, err := config.Load(path, environ)
	problems := config.Problems(err)
	if err != nil && len(problems) == 0 {
		return err
	}
	if cfg != nil {
		problems = append(problems, config.Problems(cfg.Validate())...)
	}

	out := cmd.OutOrStdout()
	if len(problems) == 0 {
		_, err := fmt.Fprintln(out, "configuration OK")
		return err
	}
	if _, err := fmt.Fprintf(out, "configuration has %d problem(s):\n", len(problems)); err != nil {
		return err
	}
	for _, p := range problems {
		if _, err := fmt.Fprintf(out, "  - %s\n", p); err != nil {
			return err
		}
	}
	return errConfigInvalid
}
