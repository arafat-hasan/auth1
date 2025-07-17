package utils

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTClaims struct {
	UserID uuid.UUID `json:"sub"`
	Email  string    `json:"email"`
	Roles  []string  `json:"roles"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewJWTManager(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, accessTokenTTL, refreshTokenTTL int) *JWTManager {
	return &JWTManager{
		privateKey:      privateKey,
		publicKey:       publicKey,
		accessTokenTTL:  time.Duration(accessTokenTTL) * time.Second,
		refreshTokenTTL: time.Duration(refreshTokenTTL) * time.Second,
	}
}

func (j *JWTManager) GenerateAccessToken(userID uuid.UUID, email string, roles []string) (string, error) {
	now := time.Now()
	jti := uuid.New().String()

	claims := &JWTClaims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "auth1",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(j.privateKey)
}

func (j *JWTManager) GenerateRefreshToken(userID uuid.UUID) (string, string, error) {
	now := time.Now()
	jti := uuid.New().String()

	claims := &jwt.RegisteredClaims{
		ID:        jti,
		Subject:   userID.String(),
		ExpiresAt: jwt.NewNumericDate(now.Add(j.refreshTokenTTL)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    "auth1",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", "", err
	}

	return signedToken, jti, nil
}

func (j *JWTManager) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (j *JWTManager) ValidateRefreshToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (j *JWTManager) GetAccessTokenTTL() time.Duration {
	return j.accessTokenTTL
}

func (j *JWTManager) GetRefreshTokenTTL() time.Duration {
	return j.refreshTokenTTL
}
