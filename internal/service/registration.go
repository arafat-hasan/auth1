package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/model/domain"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/utils"
)

func (s *authServiceImpl) Signup(ctx context.Context, req *SignupRequest) error {
	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
		"name":  req.Name,
	}).Info("Starting signup process")

	exists, err := s.userRepo.EmailExists(ctx, req.Email)
	if err != nil {
		return fmt.Errorf("failed to check email existence: %w", err)
	}
	if exists {
		return fmt.Errorf("user with email %s already exists", req.Email)
	}

	if req.Phone != nil && *req.Phone != "" {
		exists, err := s.userRepo.PhoneExists(ctx, *req.Phone)
		if err != nil {
			return fmt.Errorf("failed to check phone existence: %w", err)
		}
		if exists {
			return fmt.Errorf("user with phone %s already exists", *req.Phone)
		}
	}

	var hashedPassword *string
	if req.Password != nil && *req.Password != "" {
		hashed, err := utils.HashPassword(*req.Password)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		hashedPassword = &hashed
	}

	pendingUser := &domain.PendingUser{
		Email:     req.Email,
		Phone:     req.Phone,
		Password:  hashedPassword,
		Name:      req.Name,
		ExpiresAt: time.Now().Add(s.config.PendingUserTTL),
	}

	if err = s.redisRepo.SetPendingUser(ctx, req.Email, pendingUser, s.config.PendingUserTTL); err != nil {
		return fmt.Errorf("failed to store pending user: %w", err)
	}

	if err = s.generateAndSendOTP(ctx, req.Email, "signup"); err != nil {
		return fmt.Errorf("failed to generate and send OTP: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
	}).Info("Signup process completed, OTP sent")

	return nil
}

func (s *authServiceImpl) VerifySignup(ctx context.Context, req *VerifySignupRequest) (*domain.TokenPair, error) {
	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
	}).Info("Verifying signup OTP")

	if !s.verifyOTP(ctx, req.Email, "signup", req.OTP) {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	pendingUser, err := s.redisRepo.GetPendingUser(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending user: %w", err)
	}
	if pendingUser == nil {
		return nil, fmt.Errorf("pending user not found")
	}

	user := &domain.User{
		ID:           uuid.New(),
		Email:        pendingUser.Email,
		Name:         pendingUser.Name,
		Phone:        pendingUser.Phone,
		PasswordHash: pendingUser.Password,
		IsVerified:   true,
		Is2FAEnabled: false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err = s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.redisRepo.DeletePendingUser(ctx, req.Email)
	s.redisRepo.DeleteOTP(ctx, req.Email, "signup")
	s.userRepo.UpdateLastLogin(ctx, user.ID, nil, nil)

	s.logger.WithFields(logrus.Fields{
		"email":   req.Email,
		"user_id": user.ID,
	}).Info("User signup completed successfully")

	return tokens, nil
}

func (s *authServiceImpl) SignupWithPhone(ctx context.Context, req *SignupWithPhoneRequest) error {
	s.logger.WithFields(logrus.Fields{
		"phone": req.Phone,
		"name":  req.Name,
	}).Info("Starting phone signup process")

	exists, err := s.userRepo.PhoneExists(ctx, req.Phone)
	if err != nil {
		return fmt.Errorf("failed to check phone existence: %w", err)
	}
	if exists {
		return fmt.Errorf("user with phone %s already exists", req.Phone)
	}

	var hashedPassword *string
	if req.Password != nil && *req.Password != "" {
		hashed, err := utils.HashPassword(*req.Password)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		hashedPassword = &hashed
	}

	phone := req.Phone
	pendingUser := &domain.PendingUser{
		Phone:     &phone,
		Password:  hashedPassword,
		Name:      req.Name,
		ExpiresAt: time.Now().Add(s.config.PendingUserTTL),
	}

	if err = s.redisRepo.SetPendingUser(ctx, req.Phone, pendingUser, s.config.PendingUserTTL); err != nil {
		return fmt.Errorf("failed to store pending user: %w", err)
	}

	otp, err := utils.GenerateOTP(s.config.OTPLength)
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	hashedOTP := utils.HashOTP(otp)
	if err = s.redisRepo.SetOTP(ctx, req.Phone, "signup", hashedOTP, s.config.OTPTTL); err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"phone": req.Phone,
	}).Info("Phone signup OTP generated")

	return nil
}

func (s *authServiceImpl) VerifyPhoneSignup(ctx context.Context, req *VerifyPhoneSignupRequest) (*domain.TokenPair, error) {
	s.logger.WithFields(logrus.Fields{
		"phone": req.Phone,
	}).Info("Verifying phone signup OTP")

	if !s.verifyOTP(ctx, req.Phone, "signup", req.OTP) {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	pendingUser, err := s.redisRepo.GetPendingUser(ctx, req.Phone)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending user: %w", err)
	}
	if pendingUser == nil {
		return nil, fmt.Errorf("pending user not found")
	}

	user := &domain.User{
		ID:           uuid.New(),
		Phone:        pendingUser.Phone,
		Name:         pendingUser.Name,
		PasswordHash: pendingUser.Password,
		IsVerified:   true,
		Is2FAEnabled: false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err = s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.redisRepo.DeletePendingUser(ctx, req.Phone)
	s.redisRepo.DeleteOTP(ctx, req.Phone, "signup")
	s.userRepo.UpdateLastLogin(ctx, user.ID, nil, nil)

	s.logger.WithFields(logrus.Fields{
		"phone":   req.Phone,
		"user_id": user.ID,
	}).Info("Phone signup completed successfully")

	return tokens, nil
}
