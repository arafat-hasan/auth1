package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Password hashing functions
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// OTP generation and validation functions
func GenerateOTP(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("OTP length must be positive")
	}

	otp := make([]byte, length)
	for i := range otp {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		otp[i] = byte('0' + num.Int64())
	}

	return string(otp), nil
}

func HashOTP(otp string) string {
	hash := sha256.Sum256([]byte(otp))
	return hex.EncodeToString(hash[:])
}

func ValidateOTP(otp, hashedOTP string) bool {
	return HashOTP(otp) == hashedOTP
}

// Generate random string for tokens
func GenerateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}

	return string(result), nil
}

// Validate email format (basic validation)
func IsValidEmail(email string) bool {
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

// Validate phone format (basic validation)
func IsValidPhone(phone string) bool {
	if phone == "" {
		return false
	}

	// Remove common phone number characters
	cleaned := strings.ReplaceAll(phone, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")
	cleaned = strings.ReplaceAll(cleaned, "+", "")

	// Check if remaining characters are all digits and reasonable length
	if len(cleaned) < 10 || len(cleaned) > 15 {
		return false
	}

	_, err := strconv.Atoi(cleaned)
	return err == nil
}
