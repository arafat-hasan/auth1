package account

import (
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// The records below are the account aggregate as the accounts repository stores it (TDD-01 §4):
// plaintext only, never ciphertext. Identifier values are normalised by the caller; the
// repository stores what it is given. Times the repository writes are the database's.

// Account is a row of accounts.
type Account struct {
	ID                  uuid.UUID
	Status              Status
	StatusReason        string     // empty unless suspended or banned
	StatusUntil         *time.Time // suspended only
	StatusChangedAt     time.Time
	DisplayName         string
	Locale              string
	RegisteredVia       string // client id, or "invitation"
	FactorFailures      int
	FactorFailuresSince *time.Time
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Identifier is a row of identifiers. Type is an identifier type name (TDD-01 §2.1); Value is the
// normalised value. VerifiedAt and RetiredAt are nil while unverified and current.
type Identifier struct {
	ID         uuid.UUID
	AccountID  uuid.UUID
	Type       string
	Value      string
	VerifiedAt *time.Time
	RetiredAt  *time.Time
	CreatedAt  time.Time
}

// PasswordCredential is an account's password: the PHC string and the id of the pepper key it
// was made with, which the repository treats as opaque text.
type PasswordCredential struct {
	Hash      string
	PepperKID string
	ChangedAt time.Time
}

// Role is a role an account holds, with when and by whom it was granted.
type Role struct {
	Name      string
	GrantedAt time.Time
	GrantedBy string // empty when not recorded
}

// TOTPFactor is an account's TOTP factor (TDD-03 §3.1, §4). ConfirmedAt is nil while enrolling;
// LastStep is the last time step accepted, nil before any (I-19). It never prints Secret.
type TOTPFactor struct {
	Secret      []byte
	ConfirmedAt *time.Time
	LastStep    *int64
	CreatedAt   time.Time
}

// String describes the factor without its secret.
func (f TOTPFactor) String() string {
	last := "none"
	if f.LastStep != nil {
		last = strconv.FormatInt(*f.LastStep, 10)
	}
	return fmt.Sprintf("TOTPFactor{confirmed: %t, last step: %s, secret: [redacted]}", f.ConfirmedAt != nil, last)
}

// GoString is String, so %#v does not print the secret.
func (f TOTPFactor) GoString() string { return f.String() }

// Format writes String for every verb.
func (f TOTPFactor) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, f.String()) }

// LogValue is String, so slog does not print the secret.
func (f TOTPFactor) LogValue() slog.Value { return slog.StringValue(f.String()) }

// RecoveryCode is one stored recovery code: its id and its MAC (TDD-03 §3.2).
type RecoveryCode struct {
	ID  uuid.UUID
	MAC []byte
}

// NewIdentifier is an identifier to insert. Verified stores it verified now.
type NewIdentifier struct {
	ID       uuid.UUID
	Type     string
	Value    string
	Verified bool
}

// NewAccount is a pending account to create, with its identifiers, password and roles.
type NewAccount struct {
	ID            uuid.UUID
	DisplayName   string
	Locale        string
	RegisteredVia string
	Identifiers   []NewIdentifier
	Password      PasswordCredential // ChangedAt is ignored: the repository stores now
	Roles         []string
	GrantedBy     string // the actor granting Roles; empty when not recorded
}
