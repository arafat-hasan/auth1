package app

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"

	"github.com/google/uuid"
)

// DeviceMAC computes the MAC of the device cookie under its own key,
// encryption.device_cookie_key_file (SDD D-18, TDD-07 §4): HMAC-SHA256(device_key, msg).
type DeviceMAC interface {
	Device(msg []byte) []byte
}

// The device cookie (TDD-07 §4).
const (
	// DeviceCookieName is the cookie's name; it is set with Path=/, Secure, HttpOnly and
	// SameSite=Strict.
	DeviceCookieName = "__Host-auth1_dev"
	// DeviceCookieMaxAge is how long a device cookie is set for, and how long one is accepted.
	DeviceCookieMaxAge = 365 * 24 * time.Hour
)

// deviceCookieSkew is how far in the future a cookie's issue time may be: another replica's clock.
const deviceCookieSkew = 30 * time.Second

// The parts of a device cookie: device_id ‖ issued_at (Unix seconds, big-endian) ‖ MAC.
const (
	deviceIDLen   = 16
	deviceTimeLen = 8
	deviceMACLen  = 32
	deviceLen     = deviceIDLen + deviceTimeLen + deviceMACLen
)

// DeviceCookies issues and checks device cookies: base64url(device_id ‖ issued_at ‖
// HMAC-SHA256(device_key, device_id ‖ issued_at)), without padding (TDD-07 §4).
type DeviceCookies struct {
	mac   DeviceMAC
	clock Clock
	ids   IDGenerator
}

// NewDeviceCookies returns the device cookies under mac, or an error for a missing dependency.
func NewDeviceCookies(mac DeviceMAC, clock Clock, ids IDGenerator) (*DeviceCookies, error) {
	if mac == nil || clock == nil || ids == nil {
		return nil, errors.New("device cookies: missing a dependency")
	}
	return &DeviceCookies{mac: mac, clock: clock, ids: ids}, nil
}

// Issue returns the value of a new device cookie and its new device id.
func (d *DeviceCookies) Issue() (value string, id uuid.UUID) {
	id = d.ids.New()
	b := make([]byte, deviceIDLen+deviceTimeLen, deviceLen)
	copy(b, id[:])
	binary.BigEndian.PutUint64(b[deviceIDLen:], uint64(d.clock.Now().Unix())) //nolint:gosec // after 1970: not negative
	b = append(b, d.mac.Device(b)...)
	return base64.RawURLEncoding.EncodeToString(b), id
}

// Parse returns the device id of value when it is a valid device cookie: exact unpadded
// base64url of the right length, a MAC that matches, and issued no more than DeviceCookieMaxAge
// ago (and not after now, allowing for clock skew). Anything else is ok false.
func (d *DeviceCookies) Parse(value string) (id uuid.UUID, ok bool) {
	if base64.RawURLEncoding.EncodedLen(deviceLen) != len(value) {
		return uuid.UUID{}, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != deviceLen {
		return uuid.UUID{}, false
	}
	signed := b[:deviceIDLen+deviceTimeLen]
	if subtle.ConstantTimeCompare(d.mac.Device(signed), b[len(signed):]) != 1 {
		return uuid.UUID{}, false
	}
	issued := int64(binary.BigEndian.Uint64(b[deviceIDLen:])) //nolint:gosec // MAC'd: written by Issue from a positive time
	now := d.clock.Now()
	if issued < now.Add(-DeviceCookieMaxAge).Unix() || issued > now.Add(deviceCookieSkew).Unix() {
		return uuid.UUID{}, false
	}
	copy(id[:], b[:deviceIDLen])
	return id, true
}
