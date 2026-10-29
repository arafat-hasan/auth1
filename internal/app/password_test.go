package app_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
)

// TestErrOverloaded: a wrapped ErrOverloaded is still ErrOverloaded, and it is UNAVAILABLE with a
// one-second Retry-After (TDD-03 §1.4 step 1).
func TestErrOverloaded(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("sign in: %w", app.ErrOverloaded)
	if !errors.Is(err, app.ErrOverloaded) {
		t.Error("errors.Is does not find ErrOverloaded")
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatal("ErrOverloaded is not a *domain.Error")
	}
	if de.Code != domain.CodeUnavailable || de.RetryAfter != time.Second {
		t.Errorf("ErrOverloaded = %s, retry after %s; want UNAVAILABLE, 1s", de.Code, de.RetryAfter)
	}
}
