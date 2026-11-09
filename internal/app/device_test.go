package app_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// hmacDevice is the device-cookie MAC under a fixed key, as crypto.DeviceMAC computes it.
type hmacDevice []byte

func (k hmacDevice) Device(msg []byte) []byte {
	h := hmac.New(sha256.New, k)
	h.Write(msg)
	return h.Sum(nil)
}

var deviceStart = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func newDeviceCookies(t *testing.T, key string) (*app.DeviceCookies, *fakes.Clock) {
	t.Helper()
	clock := fakes.NewClock(deviceStart)
	d, err := app.NewDeviceCookies(hmacDevice(key), clock, fakes.NewIDs())
	if err != nil {
		t.Fatal(err)
	}
	return d, clock
}

func TestDeviceCookieRoundTrip(t *testing.T) {
	t.Parallel()
	d, clock := newDeviceCookies(t, "key one")
	value, id := d.Issue()
	if id != fakes.ID(1) {
		t.Errorf("id %v, want the first new id", id)
	}
	if len(value) != 75 {
		t.Errorf("value is %d characters, want 75", len(value))
	}
	clock.Advance(app.DeviceCookieMaxAge - time.Second)
	got, ok := d.Parse(value)
	if !ok || got != id {
		t.Errorf("Parse = %v, %v; want %v, true", got, ok, id)
	}
}

func TestDeviceCookieRefused(t *testing.T) {
	t.Parallel()
	d, clock := newDeviceCookies(t, "key one")
	value, _ := d.Issue()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) string {
		b := append([]byte(nil), raw...)
		b[i] ^= 1
		return base64.RawURLEncoding.EncodeToString(b)
	}
	other, _ := newDeviceCookies(t, "key two")
	otherValue, _ := other.Issue()
	future, futureClock := newDeviceCookies(t, "key one")
	futureClock.Advance(time.Minute)
	futureValue, _ := future.Issue()

	for name, v := range map[string]string{
		"flipped MAC byte":  flip(len(raw) - 1),
		"flipped id byte":   flip(0),
		"flipped time byte": flip(20),
		"other key":         otherValue,
		"issued in future":  futureValue,
		"padded base64":     value + "=",
		"standard base64":   base64.StdEncoding.EncodeToString(raw),
		"truncated":         value[:74],
		"extended":          value + "A",
		"empty":             "",
	} {
		if _, ok := d.Parse(v); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	clock.Advance(app.DeviceCookieMaxAge + time.Second)
	if _, ok := d.Parse(value); ok {
		t.Error("a cookie older than a year was accepted")
	}
}

func TestNewDeviceCookiesRefusesMissing(t *testing.T) {
	t.Parallel()
	if _, err := app.NewDeviceCookies(nil, fakes.NewClock(deviceStart), fakes.NewIDs()); err == nil {
		t.Error("no MAC accepted")
	}
}

// TestDeviceCookieSkew checks a cookie issued by a replica whose clock is up to 30 s ahead is
// accepted.
func TestDeviceCookieSkew(t *testing.T) {
	t.Parallel()
	ahead, clock := newDeviceCookies(t, "key one")
	clock.Advance(25 * time.Second)
	value, id := ahead.Issue()
	here, _ := newDeviceCookies(t, "key one")
	if got, ok := here.Parse(value); !ok || got != id {
		t.Errorf("cookie issued 25 s ahead: %v, %v; want accepted", got, ok)
	}
}
