package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/arafat-hasan/auth1/internal/app/clientcreds"
	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/gen"
)

// ClientCredentials is the client-credentials grant (TDD-05 §2), clientcreds.Service.
type ClientCredentials interface {
	Issue(ctx context.Context, r clientcreds.Request) (tokens.Service, error)
}

// WithClientCredentials returns a with the grant cc serving POST /v1/oauth/token. Without it the
// endpoint answers 404, as when service_auth.mode does not include client credentials.
func (a *API) WithClientCredentials(cc ClientCredentials) *API {
	a.clientCredentials = cc
	return a
}

// errNoClientCredentials is the endpoint's answer when client credentials are off.
var errNoClientCredentials = &domain.Error{Code: domain.CodeNotFound, Detail: "Client credentials are not enabled."}

// IssueServiceToken serves POST /v1/oauth/token. A refusal is an RFC 6749 §5.2 error with its
// code alone; any other failure goes to the problem writer (503 for UNAVAILABLE).
func (a *API) IssueServiceToken(ctx context.Context, req gen.IssueServiceTokenRequestObject) (gen.IssueServiceTokenResponseObject, error) {
	if a.clientCredentials == nil {
		return nil, errNoClientCredentials
	}
	b := req.Body
	tok, err := a.clientCredentials.Issue(ctx, clientcreds.Request{
		GrantType: string(b.GrantType), AssertionType: string(b.ClientAssertionType),
		Assertion: b.ClientAssertion, Scope: b.Scope,
	})
	var oe *clientcreds.Error
	if errors.As(err, &oe) {
		return oauthError{code: oe.Code}, nil
	}
	if err != nil {
		return nil, err
	}
	return serviceToken{gen.ServiceToken{
		AccessToken: tok.Token, TokenType: gen.ServiceTokenTokenTypeBearer, ExpiresIn: int(tok.ExpiresIn.Seconds()),
		Scope: strings.Join(tok.Scopes, " "),
	}}, nil
}

// serviceToken is the 200 answer, with the cache headers of RFC 6749 §5.1.
type serviceToken struct{ body gen.ServiceToken }

func (r serviceToken) VisitIssueServiceTokenResponse(w http.ResponseWriter) error {
	return writeOAuth(w, http.StatusOK, r.body)
}

// oauthError is an RFC 6749 §5.2 error: invalid_client is 401, any other 400. It has no
// error_description, so no two invalid_client answers differ, and no WWW-Authenticate: the
// client authenticates in the body, not with the Authorization header.
type oauthError struct{ code clientcreds.OAuthCode }

func (r oauthError) VisitIssueServiceTokenResponse(w http.ResponseWriter) error {
	status := http.StatusBadRequest
	if r.code == clientcreds.InvalidClient {
		status = http.StatusUnauthorized
	}
	return writeOAuth(w, status, gen.OAuthError{Error: gen.OAuthErrorError(r.code)})
}

// writeOAuth writes body as JSON with status and Cache-Control: no-store, Pragma: no-cache.
func writeOAuth(w http.ResponseWriter, status int, body any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, err := buf.WriteTo(w)
	return err
}
