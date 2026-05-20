package utils

import (
	"fmt"
	"regexp"
	"unicode"
)

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

// DefaultPasswordPolicy returns the default password policy
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: false,
	}
}

// ValidatePassword validates a password against the policy
func (p *PasswordPolicy) ValidatePassword(password string) error {
	if len(password) < p.MinLength {
		return fmt.Errorf("password must be at least %d characters long", p.MinLength)
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if p.RequireUpper && !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if p.RequireLower && !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if p.RequireNumber && !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}

	if p.RequireSpecial && !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// ValidateEmail validates an email address format
func ValidateEmail(email string) error {
	// RFC 5322 compliant regex (simplified)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ValidatePhone validates a phone number format
// This is a simple validation, adjust based on your requirements
func ValidatePhone(phone string) error {
	// Remove common formatting characters
	phoneRegex := regexp.MustCompile(`^[+]?[0-9]{10,15}$`)
	cleanPhone := regexp.MustCompile(`[\s\-\(\)]`).ReplaceAllString(phone, "")
	
	if !phoneRegex.MatchString(cleanPhone) {
		return fmt.Errorf("invalid phone number format")
	}
	return nil
}

// CalculatePasswordStrength calculates password strength (0-100)
func CalculatePasswordStrength(password string) int {
	score := 0
	
	// Length score (max 30 points)
	lengthScore := len(password) * 2
	if lengthScore > 30 {
		lengthScore = 30
	}
	score += lengthScore
	
	// Character variety (max 40 points)
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	if hasUpper {
		score += 10
	}
	if hasLower {
		score += 10
	}
	if hasNumber {
		score += 10
	}
	if hasSpecial {
		score += 10
	}
	
	// Uniqueness score (max 30 points)
	uniqueChars := make(map[rune]bool)
	for _, char := range password {
		uniqueChars[char] = true
	}
	uniquenessRatio := float64(len(uniqueChars)) / float64(len(password))
	score += int(uniquenessRatio * 30)
	
	if score > 100 {
		score = 100
	}
	
	return score
}
