package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/http/clientip"
	"github.com/arafat-hasan/auth1/internal/http/gen"
)

// SignIn is the sign-in the handlers call (TDD-02 §5): app.SignIn.
type SignIn interface {
	Password(ctx context.Context, cmd app.SignInPassword) (app.SignInResult, error)
}

// refreshCookieName is the refresh token's cookie (TDD-04 §4.1).
const refreshCookieName = "__Secure-auth1_rt"

// SignIn serves POST /v1/sessions.
func (a *API) SignIn(ctx context.Context, req gen.SignInRequestObject) (gen.SignInResponseObject, error) {
	if a.signIn == nil {
		return nil, gen.ErrNotImplemented
	}
	b := req.Body
	cmd := app.SignInPassword{ClientID: b.ClientId, Type: string(b.Identifier.Type), Value: b.Identifier.Value,
		Password: flow.Secret(b.Password), IP: clientip.From(ctx)}
	if p := req.Params.UnderscoreUnderscoreHostAuth1Dev; p != nil {
		cmd.DeviceCookie = *p
	}
	if p := req.Params.UserAgent; p != nil {
		cmd.UserAgent = *p
	}
	res, err := a.signIn.Password(ctx, cmd)
	if err != nil {
		return nil, err
	}
	if s := res.Step; s != nil {
		return signInStep{gen.MfaStep{Code: gen.MfaStepCode(s.Code), FlowId: s.FlowID, Handle: string(s.Handle),
			ExpiresAt: s.ExpiresAt}}, nil
	}
	return a.tokens(res.Tokens), nil
}

// tokens is the token response of a completed sign-in (TDD-04 §1) with its cookies: the refresh
// cookie for a browser client, the refresh token in the body for a native one, and a new device
// cookie when one was issued.
func (a *API) tokens(s *app.SignedIn) signInTokens {
	t := signInTokens{body: gen.TokenResponse{
		AccessToken: s.Access.Token, TokenType: gen.TokenResponseTokenTypeBearer, ExpiresIn: int(s.ExpiresIn.Seconds()),
		SessionId: s.SessionID, AccountStatus: gen.SessionStatus(s.Status), StatusUntil: s.StatusUntil,
	}}
	if s.BodyTransport {
		refresh := string(s.Refresh)
		t.body.RefreshToken = &refresh
	} else {
		t.cookies = append(t.cookies, (&http.Cookie{
			Name: refreshCookieName, Value: string(s.Refresh), Path: a.basePath + "/v1/sessions",
			MaxAge: int(s.RefreshMaxAge.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		}).String())
	}
	if s.DeviceCookie != "" {
		t.cookies = append(t.cookies, (&http.Cookie{
			Name: app.DeviceCookieName, Value: s.DeviceCookie, Path: "/", MaxAge: int(app.DeviceCookieMaxAge.Seconds()),
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		}).String())
	}
	return t
}

// signInTokens is the 200 answer of a sign-in. The generated response sets one Set-Cookie
// header; a sign-in may set two.
type signInTokens struct {
	body    gen.TokenResponse
	cookies []string
}

// VisitSignInResponse writes the answer.
func (t signInTokens) VisitSignInResponse(w http.ResponseWriter) error {
	return writeJSON(w, http.StatusOK, t.body, t.cookies)
}

// signInStep is the 202 answer of a sign-in that continues with a second step. Its handle is a
// secret, so it too is sent with Cache-Control: no-store.
type signInStep struct{ body gen.MfaStep }

// VisitSignInResponse writes the answer.
func (s signInStep) VisitSignInResponse(w http.ResponseWriter) error {
	return writeJSON(w, http.StatusAccepted, s.body, nil)
}

// writeJSON writes body as JSON with status, Cache-Control: no-store and the cookies.
func writeJSON(w http.ResponseWriter, status int, body any, cookies []string) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return err
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	for _, c := range cookies {
		h.Add("Set-Cookie", c)
	}
	w.WriteHeader(status)
	_, err := buf.WriteTo(w)
	return err
}
