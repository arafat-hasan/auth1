package service

import (
	"context"

	"github.com/arafat-hasan/auth1/internal/utils"
)

func (s *authServiceImpl) GetJWKS() *utils.JWKSet {
	return s.jwtManager.GetJWKS()
}

// IntrospectToken validates an access token and checks all Redis blacklists.
// It returns active=false for any token that is expired, structurally invalid,
// individually blacklisted (logout), or covered by a user-level blacklist
// (password change / logout-all). Errors from Redis are logged and treated as
// active=false to fail secure.
func (s *authServiceImpl) IntrospectToken(ctx context.Context, tokenStr string) (*IntrospectResult, error) {
	claims, err := s.jwtManager.ValidateAccessToken(tokenStr)
	if err != nil {
		return &IntrospectResult{Active: false}, nil
	}

	blacklisted, err := s.redisRepo.IsJWTBlacklisted(ctx, claims.ID)
	if err != nil {
		s.logger.WithError(err).WithField("jti", claims.ID).Error("introspect: Redis blacklist check failed")
		return &IntrospectResult{Active: false}, nil
	}
	if blacklisted {
		return &IntrospectResult{Active: false}, nil
	}

	userBlacklistTs, err := s.redisRepo.IsUserTokensBlacklisted(ctx, claims.UserID.String())
	if err != nil {
		s.logger.WithError(err).WithField("user_id", claims.UserID).Error("introspect: Redis user-level blacklist check failed")
		return &IntrospectResult{Active: false}, nil
	}
	if userBlacklistTs > 0 && claims.IssuedAt.Unix() < userBlacklistTs {
		return &IntrospectResult{Active: false}, nil
	}

	return &IntrospectResult{
		Active: true,
		Sub:    claims.UserID.String(),
		Email:  claims.Email,
		Roles:  claims.Roles,
		Exp:    claims.ExpiresAt.Unix(),
		Iat:    claims.IssuedAt.Unix(),
		Iss:    claims.Issuer,
		JTI:    claims.ID,
	}, nil
}
