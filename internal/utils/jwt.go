package utils

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWK is a single JSON Web Key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet is the JSON Web Key Set returned at /.well-known/jwks.json.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

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

// GetJWKS returns the public key as a JWKS document.
// The kid is derived from an 8-byte SHA-256 fingerprint of the DER-encoded key
// so it changes automatically on key rotation.
func (j *JWTManager) GetJWKS() *JWKSet {
	der, _ := x509.MarshalPKIXPublicKey(j.publicKey)
	h := sha256.Sum256(der)
	kid := base64.RawURLEncoding.EncodeToString(h[:8])

	n := base64.RawURLEncoding.EncodeToString(j.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(j.publicKey.E)).Bytes())

	return &JWKSet{
		Keys: []JWK{{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kid,
			N:   n,
			E:   e,
		}},
	}
}
