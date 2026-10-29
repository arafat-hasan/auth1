package app_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
)

func TestNewPlace(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("0190A5D3-7B2C-7E01-8F00-0123456789AB")
	got := app.NewPlace("accounts", "display_name", id)
	want := app.Place{Table: "accounts", Column: "display_name", Row: "0190a5d3-7b2c-7e01-8f00-0123456789ab"}
	if got != want {
		t.Errorf("NewPlace = %+v, want %+v", got, want)
	}
}

func TestNewKeyPlace(t *testing.T) {
	t.Parallel()
	got := app.NewKeyPlace("refresh_tokens", "successor_enc", []byte{0x00, 0xAB, 0xFF})
	want := app.Place{Table: "refresh_tokens", Column: "successor_enc", Row: "00abff"}
	if got != want {
		t.Errorf("NewKeyPlace = %+v, want %+v", got, want)
	}
}
