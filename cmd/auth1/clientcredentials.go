package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/adapters/clientkeys"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/app/clientcreds"
	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/http/handlers"
	"github.com/arafat-hasan/auth1/internal/http/middleware/caller"
)

// clientCredentialsOn reports whether service_auth.mode accepts client credentials.
func clientCredentialsOn(cfg *config.Config) bool {
	m := cfg.ServiceAuth.Mode
	return m == config.ServiceAuthClientCredentials || m == config.ServiceAuthBoth
}

// loadClientKeys builds the service clients' key store (TDD-05 §2) when service_auth.mode accepts
// client credentials, and nil otherwise. config check and serve refuse a jwks_file it reports as a
// problem: one that cannot be read or holds no usable key. hc fetches jwks_uri; nil is
// clientkeys.HTTPClient.
func loadClientKeys(cfg *config.Config, hc *http.Client, logger *slog.Logger) (*clientkeys.Store, []*config.Problem) {
	if !clientCredentialsOn(cfg) {
		return nil, nil
	}
	clock := system.Clock{}
	var clients []clientkeys.Client
	var problems []*config.Problem
	for i, sc := range cfg.ServiceAuth.ClientCredentials.Clients {
		c := clientkeys.Client{ID: sc.ID, File: sc.JWKSFile, URI: sc.JWKSURI}
		if c.File != "" {
			if _, err := clientkeys.New(clientkeys.Options{Clients: []clientkeys.Client{c}, Clock: clock, Logger: logger}); err != nil {
				problems = append(problems, &config.Problem{
					Path: fmt.Sprintf("service_auth.client_credentials.clients[%d].jwks_file", i), Message: err.Error(),
				})
				continue
			}
		}
		clients = append(clients, c)
	}
	if len(problems) > 0 {
		return nil, problems
	}
	store, err := clientkeys.New(clientkeys.Options{Clients: clients, HTTP: hc, Clock: clock, Logger: logger})
	if err != nil {
		return nil, []*config.Problem{{Path: "service_auth.client_credentials.clients", Message: err.Error()}}
	}
	return store, nil
}

// signingKeys signs tokens and publishes the keys that verify them: the keyring.
type signingKeys interface {
	app.TokenSigner
	app.PublicKeys
}

// newClientCredentials builds the grant of POST /v1/oauth/token over keys and the service-token
// verifier the caller middleware uses (TDD-05 §2, §3).
func newClientCredentials(cfg *config.Config, db *bun.DB, keys *clientkeys.Store, kr signingKeys,
	tracing trace.TracerProvider, logger *slog.Logger,
) (*clientcreds.Service, caller.TokenVerifier, error) {
	cc := cfg.ServiceAuth.ClientCredentials
	tc := tokens.Config{
		Issuer: cfg.HTTP.Issuer, SelfAudience: cfg.Tokens.SelfAudience, AccessTTL: cfg.Tokens.AccessTTL,
		ServiceAudience: cc.Audience, ServiceTTL: cc.TokenTTL,
	}
	for _, c := range cfg.Clients {
		if !slices.Contains(tc.ClientAudiences, c.Audience) {
			tc.ClientAudiences = append(tc.ClientAudiences, c.Audience)
		}
	}
	ids, clock := system.UUIDv7{}, system.Clock{}
	issuer, err := tokens.NewIssuer(tc, kr, clock, ids)
	if err != nil {
		return nil, nil, err
	}
	validator, err := tokens.NewValidator(tc, kr, clock)
	if err != nil {
		return nil, nil, err
	}
	endpoint, err := handlers.TokenEndpoint(cfg.HTTP.Issuer, cfg.HTTP.BasePath)
	if err != nil {
		return nil, nil, err
	}
	// A client's scopes are its service_auth.callers entry; loadServiceAuth refuses a client without one.
	clients := make(map[string][]string, len(cc.Clients))
	for _, sc := range cc.Clients {
		for _, c := range cfg.ServiceAuth.Callers {
			if c.Identity == sc.ID {
				clients[sc.ID] = c.Scopes
			}
		}
	}
	grant, err := clientcreds.New(clientcreds.Options{
		Keys: keys, Assertions: postgres.NewClientAssertions(db),
		UnitOfWork: postgres.NewUnitOfWork(db, cfg.Database.AcquireTimeout, tracing),
		Issuer:     issuer, Clock: clock, Audiences: []string{endpoint, cfg.HTTP.Issuer}, Clients: clients, Logger: logger,
	})
	if err != nil {
		return nil, nil, err
	}
	return grant, serviceTokens{v: validator, logger: logger}, nil
}

// serviceTokens implements caller.TokenVerifier with tokens.Validator.ValidateService.
type serviceTokens struct {
	v      *tokens.Validator
	logger *slog.Logger
}

// VerifyServiceToken returns the token's client and scopes. A published key that cannot verify
// is a keyring fault, logged as an error; the caller is refused either way.
func (s serviceTokens) VerifyServiceToken(ctx context.Context, token string) (caller.Caller, error) {
	c, err := s.v.ValidateService(token)
	if err != nil {
		if errors.Is(err, tokens.ErrKeyUnusable) {
			s.logger.LogAttrs(ctx, slog.LevelError, "service token: published key unusable", slog.String("error", err.Error()))
		}
		return caller.Caller{}, err
	}
	return caller.Caller{Kind: caller.KindClient, ID: c.ClientID, Scopes: c.Scopes}, nil
}
