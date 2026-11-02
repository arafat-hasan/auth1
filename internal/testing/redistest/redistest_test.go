package redistest

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

func ping(addr string) error {
	c := goredis.NewClient(&goredis.Options{Addr: addr, MaxRetries: -1, DialTimeout: time.Second})
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return c.Ping(ctx).Err()
}

func TestAddrPings(t *testing.T) {
	t.Parallel()
	if err := ping(Addr(t)); err != nil {
		t.Fatalf("PING: %v", err)
	}
}

func TestPrefixUnique(t *testing.T) {
	t.Parallel()
	a, b := Prefix(t), Prefix(t)
	if a == b || a == "" {
		t.Fatalf("Prefix gave %q and %q, want two distinct non-empty prefixes", a, b)
	}
}

func TestServerStopStart(t *testing.T) {
	t.Parallel()
	s := NewServer(t)
	if err := ping(s.Addr()); err != nil {
		t.Fatalf("PING before stop: %v", err)
	}
	s.Stop(t)
	if err := ping(s.Addr()); err == nil {
		t.Fatal("PING after stop succeeded")
	}
	s.Start(t)
	if err := ping(s.Addr()); err != nil {
		t.Fatalf("PING after start: %v", err)
	}
}
