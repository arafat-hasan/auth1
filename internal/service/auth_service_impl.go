package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth1/internal/app/model/domain"
	"auth1/internal/app/repo"
	"auth1/internal/client/email"
	"auth1/internal/utils"
)

// authServiceImpl implements the AuthService interface
type authServiceImpl struct {
	userRepo    repo.UserRepository
	redisRepo   repo.RedisRepository
	emailClient *email.Client
	jwtManager  *utils.JWTManager
	totpManager *utils.TOTPManager
	logger      *logrus.Logger
	config      *Config
}

// NewAuthService creates a new instance of AuthService
func NewAuthService(
	userRepo repo.UserRepository,
	redisRepo repo.RedisRepository,
	emailClient *email.Client,
	jwtManager *utils.JWTManager,
	totpManager *utils.TOTPManager,
	logger *logrus.Logger,
	config *Config,
) AuthService {
	return &authServiceImpl{
		userRepo:    userRepo,
		redisRepo:   redisRepo,
		emailClient: emailClient,
		jwtManager:  jwtManager,
		totpManager: totpManager,
		logger:      logger,
		config:      config,
	}
}

func (s *authServiceImpl) Signup(ctx context.Context, req *SignupRequest) error {
	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
		"name":  req.Name,
	}).Info("Starting signup process")

	// Check if user already exists
	exists, err := s.userRepo.EmailExists(ctx, req.Email)
	if err != nil {
		return fmt.Errorf("failed to check email existence: %w", err)
	}
	if exists {
		return fmt.Errorf("user with email %s already exists", req.Email)
	}

	// Check if phone already exists (if provided)
	if req.Phone != nil && *req.Phone != "" {
		exists, err := s.userRepo.PhoneExists(ctx, *req.Phone)
		if err != nil {
			return fmt.Errorf("failed to check phone existence: %w", err)
		}
		if exists {
			return fmt.Errorf("user with phone %s already exists", *req.Phone)
		}
	}

	// Hash password if provided
	var hashedPassword *string
	if req.Password != nil && *req.Password != "" {
		hashed, err := utils.HashPassword(*req.Password)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		hashedPassword = &hashed
	}

	// Create pending user
	pendingUser := &domain.PendingUser{
		Email:     req.Email,
		Phone:     req.Phone,
		Password:  hashedPassword,
		Name:      req.Name,
		ExpiresAt: time.Now().Add(s.config.PendingUserTTL),
	}

	// Store pending user in Redis
	err = s.redisRepo.SetPendingUser(ctx, req.Email, pendingUser, s.config.PendingUserTTL)
	if err != nil {
		return fmt.Errorf("failed to store pending user: %w", err)
	}

	// Generate and send OTP
	err = s.generateAndSendOTP(ctx, req.Email, "signup")
	if err != nil {
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

	// Verify OTP
	if !s.verifyOTP(ctx, req.Email, "signup", req.OTP) {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	// Get pending user
	pendingUser, err := s.redisRepo.GetPendingUser(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending user: %w", err)
	}
	if pendingUser == nil {
		return nil, fmt.Errorf("pending user not found")
	}

	// Create user in database
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

	err = s.userRepo.Create(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate tokens
	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Clean up Redis
	s.redisRepo.DeletePendingUser(ctx, req.Email)
	s.redisRepo.DeleteOTP(ctx, req.Email, "signup")

	// Update last login
	s.userRepo.UpdateLastLogin(ctx, user.ID)

	s.logger.WithFields(logrus.Fields{
		"email":   req.Email,
		"user_id": user.ID,
	}).Info("User signup completed successfully")

	return tokens, nil
}

func (s *authServiceImpl) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
	}).Info("Starting login process")

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check password
	if user.PasswordHash == nil || !utils.CheckPasswordHash(req.Password, *user.PasswordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if 2FA is enabled
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

	// Generate tokens
	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login
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

func (s *authServiceImpl) RequestOTP(ctx context.Context, req *RequestOTPRequest) error {
	s.logger.WithFields(logrus.Fields{
		"email":   req.Email,
		"purpose": req.Purpose,
	}).Info("Requesting OTP")

	// For login OTP, verify user exists
	if req.Purpose == "login" {
		user, err := s.userRepo.GetByEmail(ctx, req.Email)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
		if user == nil {
			return fmt.Errorf("user not found")
		}
	}

	// Generate and send OTP
	err := s.generateAndSendOTP(ctx, req.Email, req.Purpose)
	if err != nil {
		return fmt.Errorf("failed to generate and send OTP: %w", err)
	}

	return nil
}

func (s *authServiceImpl) VerifyLoginOTP(ctx context.Context, req *VerifyLoginRequest) (*domain.TokenPair, error) {
	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
	}).Info("Verifying login OTP")

	// Verify OTP
	if !s.verifyOTP(ctx, req.Email, "login", req.OTP) {
		return nil, fmt.Errorf("invalid or expired OTP")
	}

	// Get user
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate tokens
	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Clean up OTP
	s.redisRepo.DeleteOTP(ctx, req.Email, "login")

	// Update last login
	s.userRepo.UpdateLastLogin(ctx, user.ID)

	s.logger.WithFields(logrus.Fields{
		"email":   req.Email,
		"user_id": user.ID,
	}).Info("Login OTP verified successfully")

	return tokens, nil
}

func (s *authServiceImpl) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*domain.TokenPair, error) {
	s.logger.Info("Refreshing token")

	// Validate refresh token
	claims, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token: %w", err)
	}

	// Check if refresh token exists in Redis
	exists, err := s.redisRepo.GetRefreshToken(ctx, userID, claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check refresh token: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("refresh token not found or expired")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Delete old refresh token
	s.redisRepo.DeleteRefreshToken(ctx, userID, claims.ID)

	// Generate new tokens
	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": user.ID,
	}).Info("Token refreshed successfully")

	return tokens, nil
}

func (s *authServiceImpl) Logout(ctx context.Context, req *LogoutRequest) error {
	s.logger.Info("Logging out user")

	// Validate refresh token
	claims, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return fmt.Errorf("invalid user ID in token: %w", err)
	}

	// Delete refresh token from Redis
	err = s.redisRepo.DeleteRefreshToken(ctx, userID, claims.ID)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("User logged out successfully")

	return nil
}

func (s *authServiceImpl) Setup2FA(ctx context.Context, userID uuid.UUID) (*domain.TOTPSetupData, error) {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Setting up 2FA")

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate TOTP secret
	secret, err := s.totpManager.GenerateSecret(user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Store secret temporarily in Redis
	err = s.redisRepo.SetTOTPSecret(ctx, userID, secret, s.config.TOTPSecretTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	// Generate QR code URL
	qrCodeURL := s.totpManager.GenerateQRCodeURL(user.Email, secret)

	return &domain.TOTPSetupData{
		Secret:    secret,
		QRCodeURL: qrCodeURL,
	}, nil
}

func (s *authServiceImpl) Verify2FA(ctx context.Context, req *Verify2FARequest) (*domain.TokenPair, error) {
	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserID,
	}).Info("Verifying 2FA")

	// Get user
	user, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	var secret string
	if user.Is2FAEnabled && user.TOTPSecret != nil {
		// User already has 2FA enabled, use stored secret
		secret = *user.TOTPSecret
	} else {
		// User is setting up 2FA, get secret from Redis
		secret, err = s.redisRepo.GetTOTPSecret(ctx, req.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get TOTP secret: %w", err)
		}
		if secret == "" {
			return nil, fmt.Errorf("2FA setup not found or expired")
		}
	}

	// Verify TOTP code
	if !s.totpManager.ValidateCode(req.TwoFACode, secret) {
		return nil, fmt.Errorf("invalid 2FA code")
	}

	// If this is setup verification, enable 2FA for the user
	if !user.Is2FAEnabled {
		err = s.userRepo.Enable2FA(ctx, req.UserID, secret)
		if err != nil {
			return nil, fmt.Errorf("failed to enable 2FA: %w", err)
		}

		// Clean up temporary secret
		s.redisRepo.DeleteTOTPSecret(ctx, req.UserID)
	}

	// Generate tokens
	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login
	s.userRepo.UpdateLastLogin(ctx, req.UserID)

	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserID,
	}).Info("2FA verified successfully")

	return tokens, nil
}

func (s *authServiceImpl) Disable2FA(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Disabling 2FA")

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if !user.Is2FAEnabled {
		return fmt.Errorf("2FA is not enabled for this user")
	}

	// Disable 2FA
	err = s.userRepo.Disable2FA(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	// Revoke all refresh tokens for security
	err = s.redisRepo.DeleteAllRefreshTokens(ctx, userID)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("Failed to revoke refresh tokens after disabling 2FA")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("2FA disabled successfully")

	return nil
}

func (s *authServiceImpl) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

func (s *authServiceImpl) GetPublicKey() string {
	return s.config.PublicKeyPEM
}

// Private helper methods
func (s *authServiceImpl) generateAndSendOTP(ctx context.Context, email, purpose string) error {
	// Check if OTP already exists (prevent spam)
	exists, err := s.redisRepo.OTPExists(ctx, email, purpose)
	if err != nil {
		return fmt.Errorf("failed to check OTP existence: %w", err)
	}
	if exists {
		return fmt.Errorf("OTP already sent, please wait before requesting another")
	}

	// Generate OTP
	otp, err := utils.GenerateOTP(s.config.OTPLength)
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Hash and store OTP
	hashedOTP := utils.HashOTP(otp)
	err = s.redisRepo.SetOTP(ctx, email, purpose, hashedOTP, s.config.OTPTTL)
	if err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	// Send OTP via email
	err = s.emailClient.SendOTPEmail(ctx, email, otp, purpose)
	if err != nil {
		// Clean up OTP if email sending fails
		s.redisRepo.DeleteOTP(ctx, email, purpose)
		return fmt.Errorf("failed to send OTP email: %w", err)
	}

	return nil
}

func (s *authServiceImpl) verifyOTP(ctx context.Context, email, purpose, otp string) bool {
	// Get stored OTP hash
	storedHash, err := s.redisRepo.GetOTP(ctx, email, purpose)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"email":   email,
			"purpose": purpose,
			"error":   err.Error(),
		}).Error("Failed to get OTP from Redis")
		return false
	}

	if storedHash == "" {
		return false
	}

	// Verify OTP
	return utils.ValidateOTP(otp, storedHash)
}

func (s *authServiceImpl) generateTokens(ctx context.Context, userID uuid.UUID, email string) (*domain.TokenPair, error) {
	// Generate access token
	accessToken, err := s.jwtManager.GenerateAccessToken(userID, email, []string{"user"})
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, jti, err := s.jwtManager.GenerateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in Redis
	err = s.redisRepo.SetRefreshToken(ctx, userID, jti, s.config.RefreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.jwtManager.GetAccessTokenTTL().Seconds()),
	}, nil
}
