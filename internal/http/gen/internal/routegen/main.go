package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	spec := flag.String("spec", "", "the OpenAPI document")
	routesOut := flag.String("routes", "", "the route metadata file to write")
	stubOut := flag.String("stub", "", "the stub file to write")
	flag.Parse()
	if err := run(*spec, *routesOut, *stubOut); err != nil {
		fmt.Fprintln(os.Stderr, "routegen:", err)
		os.Exit(1)
	}
}

func run(spec, routesOut, stubOut string) error {
	raw, err := os.ReadFile(spec) //nolint:gosec // the path comes from the go:generate line
	if err != nil {
		return fmt.Errorf("read the document: %w", err)
	}
	ops, err := operations(raw)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		path   string
		source func([]op) ([]byte, error)
	}{{routesOut, routes}, {stubOut, stub}} {
		src, err := f.source(ops)
		if err != nil {
			return err
		}
		if err := os.WriteFile(f.path, src, 0o644); err != nil { //nolint:gosec // generated source is world-readable
			return fmt.Errorf("write %s: %w", f.path, err)
		}
	}
	return nil
}
