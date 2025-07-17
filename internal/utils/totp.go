package utils

import (
	"fmt"
	"net/url"
	"time"

	"github.com/pquerna/otp/totp"
)

type TOTPManager struct {
	issuer string
}

func NewTOTPManager(issuer string) *TOTPManager {
	return &TOTPManager{
		issuer: issuer,
	}
}

func (t *TOTPManager) GenerateSecret(accountName string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", err
	}

	return key.Secret(), nil
}

func (t *TOTPManager) GenerateQRCodeURL(accountName, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		url.QueryEscape(t.issuer),
		url.QueryEscape(accountName),
		secret,
		url.QueryEscape(t.issuer),
	)
}

func (t *TOTPManager) ValidateCode(code, secret string) bool {
	return totp.Validate(code, secret)
}

func (t *TOTPManager) GenerateCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}
