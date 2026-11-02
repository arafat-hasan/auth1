package dockertest

import (
	"errors"
	"io"
	"net"
	"testing"
)

func TestGate(t *testing.T) {
	t.Parallel()
	down := errors.New("no docker")
	for _, tc := range []struct {
		name       string
		health     error
		require    bool
		skip, fail bool
	}{
		{"healthy", nil, false, false, false},
		{"healthy, required", nil, true, false, false},
		{"unhealthy", down, false, true, false},
		{"unhealthy, required", down, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			skip, fail := gate(tc.health, tc.require)
			if skip != tc.skip || fail != tc.fail {
				t.Errorf("gate = %v, %v; want %v, %v", skip, fail, tc.skip, tc.fail)
			}
		})
	}
}

// echo serves one connection at a time, writing back prefix and what it reads.
func echo(t *testing.T, prefix string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.WriteString(c, prefix)
			}()
		}
	}()
	return ln.Addr().String()
}

func read(t *testing.T, addr string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	b, _ := io.ReadAll(c)
	return string(b)
}

func TestProxyFollowsTarget(t *testing.T) {
	t.Parallel()
	p, err := NewProxy(echo(t, "a"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if got := read(t, p.Addr()); got != "a" {
		t.Fatalf("first target answered %q, want a", got)
	}
	p.SetTarget(echo(t, "b"))
	if got := read(t, p.Addr()); got != "b" {
		t.Fatalf("after SetTarget answered %q, want b", got)
	}
}
