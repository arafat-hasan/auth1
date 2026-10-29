package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/arafat-hasan/auth1/internal/adapters/keyring"
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
			"and security floor, check that each secret file exists and is readable, and validate " +
			"the signing keyring (without the database). " +
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
	cfg, problems, err := loadConfig(path, environ)
	if err != nil {
		return err
	}
	if len(problems) == 0 {
		problems = keyringProblems(cfg)
	}
	out := cmd.OutOrStdout()
	if len(problems) == 0 {
		_, err := fmt.Fprintln(out, "configuration OK")
		return err
	}
	return printProblems(out, problems)
}

// keyringProblems loads and validates the signing keyring, without the database, and returns
// one problem per failure.
func keyringProblems(cfg *config.Config) []*config.Problem {
	_, err := keyring.Load(cfg.Keys.KeyringFile.Path())
	if err == nil {
		return nil
	}
	var out []*config.Problem
	for _, line := range strings.Split(err.Error(), "\n") {
		out = append(out, &config.Problem{Path: "keys.keyring_file", Message: line})
	}
	return out
}

// loadConfig loads path with its environ overrides and validates it. It returns the problems
// found, or an error when the file cannot be read or parsed.
func loadConfig(path string, environ []string) (*config.Config, []*config.Problem, error) {
	cfg, err := config.Load(path, environ)
	problems := config.Problems(err)
	if err != nil && len(problems) == 0 {
		return nil, nil, err
	}
	if cfg != nil {
		problems = append(problems, config.Problems(cfg.Validate())...)
	}
	return cfg, problems, nil
}

// printProblems writes the problem count and each problem to out, and returns errConfigInvalid.
func printProblems(out io.Writer, problems []*config.Problem) error {
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
