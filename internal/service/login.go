package service

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/model/domain"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/utils"
)

func (s *authServiceImpl) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
	}).Info("Starting login process")

	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if user.PasswordHash == nil || !utils.CheckPasswordHash(req.Password, *user.PasswordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	if user.Is2FAEnabled {
		s.logger.WithFields(logrus.Fields{
			"email":   req.Email,
			"user_id": user.ID,
		}).Info("2FA required for login")
		return &LoginResponse{
			User:              user,
			RequiresTwoFactor: true,
		}, nil
	}

	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.userRepo.UpdateLastLogin(ctx, user.ID, req.IPAddress, req.UserAgent)

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

	user, err := s.userRepo.GetByPhone(ctx, req.Phone)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if user.PasswordHash == nil || !utils.CheckPasswordHash(req.Password, *user.PasswordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	if user.Is2FAEnabled {
		return &LoginResponse{
			User:              user,
			RequiresTwoFactor: true,
		}, nil
	}

	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.userRepo.UpdateLastLogin(ctx, user.ID, req.IPAddress, req.UserAgent)

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

	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.redisRepo.DeleteOTP(ctx, req.Email, "login")
	s.userRepo.UpdateLastLogin(ctx, user.ID, nil, nil)

	s.logger.WithFields(logrus.Fields{
		"email":   req.Email,
		"user_id": user.ID,
	}).Info("Login OTP verified successfully")

	return tokens, nil
}
