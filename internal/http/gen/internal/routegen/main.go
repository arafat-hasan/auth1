package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	spec := flag.String("spec", "", "the OpenAPI document")
	out := flag.String("routes", "", "the route metadata file to write")
	flag.Parse()
	if err := run(*spec, *out); err != nil {
		fmt.Fprintln(os.Stderr, "routegen:", err)
		os.Exit(1)
	}
}

func run(spec, out string) error {
	raw, err := os.ReadFile(spec) //nolint:gosec // the path comes from the go:generate line
	if err != nil {
		return fmt.Errorf("read the document: %w", err)
	}
	ops, err := operations(raw)
	if err != nil {
		return err
	}
	src, err := routes(ops)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, src, 0o644); err != nil { //nolint:gosec // generated source is world-readable
		return fmt.Errorf("write %s: %w", out, err)
	}
	return nil
}
