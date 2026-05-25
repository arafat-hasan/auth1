package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/auth1/internal/app/model/domain"
	"github.com/arafat-hasan/auth1/internal/utils"
)

func (s *authServiceImpl) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
	}).Info("Starting login process")

	// Get IP address (handle nil pointer)
	ipAddress := ""
	if req.IPAddress != nil {
		ipAddress = *req.IPAddress
	}

	// 1. Check if email-based account is locked
	if ipAddress != "" {
		locked, unlockTime, err := s.redisRepo.IsAccountLocked(ctx, req.Email, "email")
		if err != nil {
			s.logger.WithError(err).Warn("Failed to check email lockout status - continuing")
		} else if locked {
			s.logger.WithFields(logrus.Fields{
				"email":        req.Email,
				"locked_until": unlockTime,
			}).Warn("Login attempt on locked account")

			return nil, fmt.Errorf("account locked until %s due to too many failed attempts", unlockTime.Format("2006-01-02 15:04:05"))
		}

		// 2. Check if IP-based lockout
		locked, unlockTime, err = s.redisRepo.IsAccountLocked(ctx, ipAddress, "ip")
		if err != nil {
			s.logger.WithError(err).Warn("Failed to check IP lockout status - continuing")
		} else if locked {
			s.logger.WithFields(logrus.Fields{
				"email":        req.Email,
				"ip":           ipAddress,
				"locked_until": unlockTime,
			}).Warn("Login attempt from locked IP")

			return nil, fmt.Errorf("too many failed attempts from this IP, account locked until %s", unlockTime.Format("2006-01-02 15:04:05"))
		}
	}

	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}
	if s.config.RequireEmailVerification && !user.IsVerified {
		return nil, fmt.Errorf("email address not verified")
	}

	// Check password
	if user.PasswordHash == nil || !utils.CheckPasswordHash(req.Password, *user.PasswordHash) {
		// Increment attempts for both email and IP
		if ipAddress != "" {
			emailAttempts, emailErr := s.redisRepo.IncrementLoginAttempts(ctx, req.Email, "email")
			ipAttempts, ipErr := s.redisRepo.IncrementLoginAttempts(ctx, ipAddress, "ip")

			if emailErr != nil {
				s.logger.WithError(emailErr).Warn("Failed to increment email login attempts")
			}
			if ipErr != nil {
				s.logger.WithError(ipErr).Warn("Failed to increment IP login attempts")
			}

			s.logger.WithFields(logrus.Fields{
				"email":          req.Email,
				"ip":             ipAddress,
				"email_attempts": emailAttempts,
				"ip_attempts":    ipAttempts,
			}).Warn("Failed login attempt")

			// Lock account if max attempts exceeded (5 for email, 10 for IP)
			if emailErr == nil && emailAttempts >= int64(s.config.MaxLoginAttempts) {
				lockErr := s.redisRepo.LockAccount(ctx, req.Email, "email", s.config.LockoutDuration)
				if lockErr != nil {
					s.logger.WithError(lockErr).Error("Failed to lock account by email")
				} else {
					s.logger.WithFields(logrus.Fields{
						"email":    req.Email,
						"attempts": emailAttempts,
					}).Warn("Account locked due to failed attempts")
				}
			}

			if ipErr == nil && ipAttempts >= int64(s.config.MaxLoginAttempts*2) {
				lockErr := s.redisRepo.LockAccount(ctx, ipAddress, "ip", s.config.LockoutDuration)
				if lockErr != nil {
					s.logger.WithError(lockErr).Error("Failed to lock IP")
				} else {
					s.logger.WithFields(logrus.Fields{
						"ip":       ipAddress,
						"attempts": ipAttempts,
					}).Warn("IP locked due to failed attempts")
				}
			}
		}

		return nil, fmt.Errorf("invalid credentials")
	}

	// Reset login attempts on successful authentication
	if ipAddress != "" {
		if err := s.redisRepo.ResetLoginAttempts(ctx, req.Email, "email"); err != nil {
			s.logger.WithError(err).Warn("Failed to reset email login attempts")
		}
		if err := s.redisRepo.ResetLoginAttempts(ctx, ipAddress, "ip"); err != nil {
			s.logger.WithError(err).Warn("Failed to reset IP login attempts")
		}
	}

	if user.Is2FAEnabled {
		challengeToken, err := generateChallengeToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate 2FA challenge: %w", err)
		}
		if err := s.redisRepo.StoreTwoFAChallenge(ctx, challengeToken, user.ID, s.config.TOTPChallengeTTL); err != nil {
			return nil, fmt.Errorf("failed to store 2FA challenge: %w", err)
		}
		s.logger.WithFields(logrus.Fields{
			"email":   req.Email,
			"user_id": user.ID,
		}).Info("2FA challenge issued for login")
		return &LoginResponse{
			RequiresTwoFactor: true,
			ChallengeToken:    challengeToken,
		}, nil
	}

	tokens, err := s.generateTokens(ctx, user.ID, user.Email, user.Role, derefStr(req.IPAddress), derefStr(req.UserAgent))
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.userRepo.UpdateLastLogin(ctx, user.ID)

	s.logger.WithFields(logrus.Fields{
		"email":   req.Email,
		"user_id": user.ID,
	}).Info("Login completed successfully")

	return &LoginResponse{
		Tokens:            tokens,
		User:              user,
		RequiresTwoFactor: false,
	}, nil
}

func (s *authServiceImpl) LoginWithPhone(ctx context.Context, req *LoginWithPhoneRequest) (*LoginResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"phone": req.Phone,
	}).Info("Starting phone login process")

	// Get IP address (handle nil pointer)
	ipAddress := ""
	if req.IPAddress != nil {
		ipAddress = *req.IPAddress
	}

	// 1. Check if phone-based account is locked
	if ipAddress != "" {
		locked, unlockTime, err := s.redisRepo.IsAccountLocked(ctx, req.Phone, "phone")
		if err != nil {
			s.logger.WithError(err).Warn("Failed to check phone lockout status - continuing")
		} else if locked {
			s.logger.WithFields(logrus.Fields{
				"phone":        req.Phone,
				"locked_until": unlockTime,
			}).Warn("Login attempt on locked account")

			return nil, fmt.Errorf("account locked until %s due to too many failed attempts", unlockTime.Format("2006-01-02 15:04:05"))
		}

		// 2. Check if IP-based lockout
		locked, unlockTime, err = s.redisRepo.IsAccountLocked(ctx, ipAddress, "ip")
		if err != nil {
			s.logger.WithError(err).Warn("Failed to check IP lockout status - continuing")
		} else if locked {
			s.logger.WithFields(logrus.Fields{
				"phone":        req.Phone,
				"ip":           ipAddress,
				"locked_until": unlockTime,
			}).Warn("Login attempt from locked IP")

			return nil, fmt.Errorf("too many failed attempts from this IP, account locked until %s", unlockTime.Format("2006-01-02 15:04:05"))
		}
	}

	user, err := s.userRepo.GetByPhone(ctx, req.Phone)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}
	if s.config.RequirePhoneVerification && user.PhoneVerifiedAt == nil {
		return nil, fmt.Errorf("phone number not verified")
	}

	// Check password
	if user.PasswordHash == nil || !utils.CheckPasswordHash(req.Password, *user.PasswordHash) {
		// Increment attempts for both phone and IP
		if ipAddress != "" {
			phoneAttempts, phoneErr := s.redisRepo.IncrementLoginAttempts(ctx, req.Phone, "phone")
			ipAttempts, ipErr := s.redisRepo.IncrementLoginAttempts(ctx, ipAddress, "ip")

			if phoneErr != nil {
				s.logger.WithError(phoneErr).Warn("Failed to increment phone login attempts")
			}
			if ipErr != nil {
				s.logger.WithError(ipErr).Warn("Failed to increment IP login attempts")
			}

			s.logger.WithFields(logrus.Fields{
				"phone":          req.Phone,
				"ip":             ipAddress,
				"phone_attempts": phoneAttempts,
				"ip_attempts":    ipAttempts,
			}).Warn("Failed phone login attempt")

			// Lock account if max attempts exceeded (5 for phone, 10 for IP)
			if phoneErr == nil && phoneAttempts >= int64(s.config.MaxLoginAttempts) {
				lockErr := s.redisRepo.LockAccount(ctx, req.Phone, "phone", s.config.LockoutDuration)
				if lockErr != nil {
					s.logger.WithError(lockErr).Error("Failed to lock account by phone")
				} else {
					s.logger.WithFields(logrus.Fields{
						"phone":    req.Phone,
						"attempts": phoneAttempts,
					}).Warn("Account locked due to failed attempts")
				}
			}

			if ipErr == nil && ipAttempts >= int64(s.config.MaxLoginAttempts*2) {
				lockErr := s.redisRepo.LockAccount(ctx, ipAddress, "ip", s.config.LockoutDuration)
				if lockErr != nil {
					s.logger.WithError(lockErr).Error("Failed to lock IP")
				} else {
					s.logger.WithFields(logrus.Fields{
						"ip":       ipAddress,
						"attempts": ipAttempts,
					}).Warn("IP locked due to failed attempts")
				}
			}
		}

		return nil, fmt.Errorf("invalid credentials")
	}

	// Reset login attempts on successful authentication
	if ipAddress != "" {
		if err := s.redisRepo.ResetLoginAttempts(ctx, req.Phone, "phone"); err != nil {
			s.logger.WithError(err).Warn("Failed to reset phone login attempts")
		}
		if err := s.redisRepo.ResetLoginAttempts(ctx, ipAddress, "ip"); err != nil {
			s.logger.WithError(err).Warn("Failed to reset IP login attempts")
		}
	}

	if user.Is2FAEnabled {
		challengeToken, err := generateChallengeToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate 2FA challenge: %w", err)
		}
		if err := s.redisRepo.StoreTwoFAChallenge(ctx, challengeToken, user.ID, s.config.TOTPChallengeTTL); err != nil {
			return nil, fmt.Errorf("failed to store 2FA challenge: %w", err)
		}
		return &LoginResponse{
			RequiresTwoFactor: true,
			ChallengeToken:    challengeToken,
		}, nil
	}

	tokens, err := s.generateTokens(ctx, user.ID, user.Email, user.Role, derefStr(req.IPAddress), derefStr(req.UserAgent))
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.userRepo.UpdateLastLogin(ctx, user.ID)

	s.logger.WithFields(logrus.Fields{
		"phone":   req.Phone,
		"user_id": user.ID,
	}).Info("Phone login completed successfully")

	return &LoginResponse{
		Tokens:            tokens,
		User:              user,
		RequiresTwoFactor: false,
	}, nil
}

func generateChallengeToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *authServiceImpl) RequestOTP(ctx context.Context, req *RequestOTPRequest) error {
	s.logger.WithFields(logrus.Fields{
		"email":   req.Email,
		"purpose": req.Purpose,
	}).Info("Requesting OTP")

	if req.Purpose == "login" {
		user, err := s.userRepo.GetByEmail(ctx, req.Email)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
		if user == nil {
			return fmt.Errorf("user not found")
		}
	}

	if err := s.generateAndSendOTP(ctx, req.Email, req.Purpose); err != nil {
		return fmt.Errorf("failed to generate and send OTP: %w", err)
	}

	return nil
}

func (s *authServiceImpl) VerifyLoginOTP(ctx context.Context, req *VerifyLoginRequest) (*domain.TokenPair, error) {
	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
	}).Info("Verifying login OTP")

	if !s.verifyOTP(ctx, req.Email, "login", req.OTP) {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}
	if s.config.RequireEmailVerification && !user.IsVerified {
		return nil, fmt.Errorf("email address not verified")
	}

	tokens, err := s.generateTokens(ctx, user.ID, user.Email, user.Role, derefStr(req.IPAddress), derefStr(req.UserAgent))
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.redisRepo.DeleteOTP(ctx, req.Email, "login")
	s.userRepo.UpdateLastLogin(ctx, user.ID)

	s.logger.WithFields(logrus.Fields{
		"email":   req.Email,
		"user_id": user.ID,
	}).Info("Login OTP verified successfully")

	return tokens, nil
}
