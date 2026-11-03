package tokens

import (
	"errors"

	"github.com/arafat-hasan/auth1/internal/app"
)

// ErrInvalid matches every refusal of Validate.
var ErrInvalid = errors.New("tokens: invalid access token")

// Validator validates access tokens (TDD-04 §6 steps 1–2).
type Validator struct {
	cfg   Config
	keys  app.PublicKeys
	clock app.Clock
}

// NewValidator returns a validator over the published keys.
func NewValidator(cfg Config, keys app.PublicKeys, clock app.Clock) *Validator {
	return &Validator{cfg: cfg, keys: keys, clock: clock}
}

// Validate returns the claims of token.
func (v *Validator) Validate(_ string) (Claims, error) {
	return Claims{}, ErrInvalid
}
