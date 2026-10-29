package account

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// checkError fails the test unless err is a *domain.Error with the code and field errors given.
func checkError(t *testing.T, err error, code domain.Code, fields []domain.FieldError) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want a *domain.Error with code %s", err, code)
	}
	if de.Code != code {
		t.Errorf("code = %s, want %s", de.Code, code)
	}
	if diff := cmp.Diff(fields, de.Fields); diff != "" {
		t.Errorf("fields (-want +got):\n%s", diff)
	}
}
