package account_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

func TestThrottleDelay(t *testing.T) {
	t.Parallel()
	p := account.ThrottlePolicy{Threshold: 5, FirstDelay: time.Second, MaxDelay: 15 * time.Minute}
	for _, tt := range []struct {
		failures int
		want     time.Duration
	}{
		{-1, 0}, {0, 0}, {1, 0}, {4, 0},
		{5, time.Second}, {6, 2 * time.Second}, {7, 4 * time.Second},
		{14, 512 * time.Second}, {15, 15 * time.Minute}, {64, 15 * time.Minute},
		{10_000, 15 * time.Minute}, {int(^uint(0) >> 1), 15 * time.Minute},
	} {
		if got := p.Delay(tt.failures); got != tt.want {
			t.Errorf("Delay(%d) = %v, want %v", tt.failures, got, tt.want)
		}
	}
}

func TestThrottleDelayZeroPolicy(t *testing.T) {
	t.Parallel()
	if got := (account.ThrottlePolicy{}).Delay(100); got != 0 {
		t.Errorf("zero policy Delay(100) = %v, want 0", got)
	}
}

func TestBuckets(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("019a4f5e-0000-7000-8000-000000000001")
	if got := account.DeviceBucket(id); got != "device:019a4f5e-0000-7000-8000-000000000001" {
		t.Errorf("DeviceBucket = %q", got)
	}
	if account.UntrustedBucket != "untrusted" {
		t.Errorf("UntrustedBucket = %q", account.UntrustedBucket)
	}
}
