package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/http/clientip"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/handlers"
	"github.com/arafat-hasan/auth1/internal/http/health"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/server"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
)

// fakeRegistration records the commands it gets and answers with err, or with its results.
type fakeRegistration struct {
	err      error
	start    app.StartRegistration
	verify   app.VerifyRegistrationCode
	resend   app.ResendRegistration
	confirm  app.ConfirmLink
	started  app.RegistrationStarted
	progress app.RegistrationProgress
	link     app.LinkConfirmed
	request  app.RequestResume
	resume   app.VerifyResume
	resumed  app.FlowResumed
}

func (f *fakeRegistration) Start(_ context.Context, c app.StartRegistration) (app.RegistrationStarted, error) {
	f.start = c
	return f.started, f.err
}

func (f *fakeRegistration) VerifyCode(_ context.Context, c app.VerifyRegistrationCode) (app.RegistrationProgress, error) {
	f.verify = c
	return f.progress, f.err
}

func (f *fakeRegistration) Resend(_ context.Context, c app.ResendRegistration) error {
	f.resend = c
	return f.err
}

func (f *fakeRegistration) ConfirmLink(_ context.Context, c app.ConfirmLink) (app.LinkConfirmed, error) {
	f.confirm = c
	return f.link, f.err
}

func regRouter(t *testing.T, reg handlers.Registration) http.Handler {
	t.Helper()
	return flowRouter(t, defaultMetadata, reg, nil)
}

// flowRouter is the router serving the API with the registration and sign-in given.
func flowRouter(t *testing.T, m handlers.MetadataOptions, reg handlers.Registration, signIn handlers.SignIn) http.Handler {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	hist, err := noop.NewMeterProvider().Meter("test").Float64Histogram("d")
	if err != nil {
		t.Fatal(err)
	}
	api, err := handlers.NewAPI(keySet{}, m, reg, signIn)
	if err != nil {
		t.Fatal(err)
	}
	ips, err := clientip.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	problems := problem.New(logger)
	return server.NewRouter(server.Options{
		Logger: logger, Problems: problems, ClientIP: ips,
		TracerProvider: tracenoop.NewTracerProvider(), Propagator: propagation.TraceContext{},
		RequestDuration: hist, Health: health.New(logger), Routes: gen.Routes(api, problems), BasePath: m.BasePath,
	})
}

// post serves POST path with body and checks the exchange against the contract.
func post(t *testing.T, h http.Handler, path, body string) response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.7:4242"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	contractReq := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	contractReq.Header.Set("Content-Type", "application/json")
	apitest.New(t).Check(t, contractReq, resp)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: b}
}

var (
	addrs      = cmpopts.EquateComparable(netip.Addr{})
	testFlow   = uuid.MustParse("01920000-0000-7000-8000-0000000000f1")
	testHandle = strings.Repeat("h", 43)
	clientAddr = netip.MustParseAddr("192.0.2.7")
)

const registrationBody = `{"client_id":"web","display_name":"Someone","locale":"en",` +
	`"identifiers":{"email":"someone@example.com"},"password":"correct horse battery staple"}`

func TestStartRegistrationHandler(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	reg := &fakeRegistration{started: app.RegistrationStarted{
		FlowID: testFlow, Handle: flow.Secret(testHandle), PendingTypes: []string{"email"}, ExpiresAt: expires,
	}}
	resp := post(t, regRouter(t, reg), "/v1/registrations", registrationBody)
	if resp.status != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	var got gen.RegistrationStarted
	if err := json.Unmarshal(resp.body, &got); err != nil {
		t.Fatal(err)
	}
	want := gen.RegistrationStarted{FlowId: testFlow, Handle: testHandle, PendingTypes: []string{"email"}, ExpiresAt: expires}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
	wantCmd := app.StartRegistration{ClientID: "web", DisplayName: "Someone", Locale: "en",
		Identifiers: map[string]string{"email": "someone@example.com"}, Password: flow.Secret("correct horse battery staple"),
		IP: clientAddr}
	if diff := cmp.Diff(wantCmd, reg.start, addrs); diff != "" {
		t.Errorf("command (-want +got):\n%s", diff)
	}
}

func TestVerifyRegistrationCodeHandler(t *testing.T) {
	t.Parallel()
	reg := &fakeRegistration{progress: app.RegistrationProgress{PendingTypes: []string{}}}
	resp := post(t, regRouter(t, reg), "/v1/registrations/"+testFlow.String()+"/verify",
		`{"handle":"`+testHandle+`","identifier_type":"phone","code":"123456"}`)
	if resp.status != http.StatusOK || string(resp.body) != `{"pending_types":[]}`+"\n" {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	want := app.VerifyRegistrationCode{FlowID: testFlow, Handle: flow.Secret(testHandle), IdentifierType: "phone",
		Code: flow.Secret("123456"), IP: clientAddr}
	if diff := cmp.Diff(want, reg.verify, addrs); diff != "" {
		t.Errorf("command (-want +got):\n%s", diff)
	}
}

func TestResendRegistrationHandler(t *testing.T) {
	t.Parallel()
	reg := &fakeRegistration{}
	resp := post(t, regRouter(t, reg), "/v1/registrations/"+testFlow.String()+"/resend",
		`{"handle":"`+testHandle+`","identifier_type":"phone"}`)
	if resp.status != http.StatusAccepted {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	want := app.ResendRegistration{FlowID: testFlow, Handle: flow.Secret(testHandle), IdentifierType: "phone", IP: clientAddr}
	if diff := cmp.Diff(want, reg.resend, addrs); diff != "" {
		t.Errorf("command (-want +got):\n%s", diff)
	}
}

func TestConfirmVerificationLinkHandler(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("t", 43)
	reg := &fakeRegistration{link: app.LinkConfirmed{
		Purpose: flow.PurposeVerifyIdentifier, FlowID: testFlow, Complete: false, PendingTypes: []string{"phone"},
	}}
	resp := post(t, regRouter(t, reg), "/v1/verification-links/confirm", `{"token":"`+token+`"}`)
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	want := `{"complete":false,"flow_id":"` + testFlow.String() + `","pending_types":["phone"],"purpose":"verify_identifier"}` + "\n"
	if string(resp.body) != want {
		t.Errorf("body %s; want %s", resp.body, want)
	}
	if string(reg.confirm.Token) != token || reg.confirm.IP != clientAddr {
		t.Errorf("command = %+v", reg.confirm)
	}
}

// TestRegistrationErrors answers each code the four operations may give (TDD-02 §10) and checks
// every answer against the contract.
func TestRegistrationErrors(t *testing.T) {
	t.Parallel()
	left := 2
	errs := []struct {
		err    error
		status int
	}{
		{&domain.Error{Code: domain.CodeValidationFailed, Detail: "x",
			Fields: []domain.FieldError{{Field: "client_id", Code: domain.FieldUnknown}}}, 422},
		{&domain.Error{Code: domain.CodeIdentifierNotAllowed, Detail: "x"}, 422},
		{&domain.Error{Code: domain.CodeIdentifierTaken, Detail: "x"}, 409},
		{&domain.Error{Code: domain.CodePasswordRejected, Detail: "x", Reasons: []string{"too_short"}}, 422},
		{&domain.Error{Code: domain.CodeRateLimited, Detail: "x", RetryAfter: time.Hour}, 429},
		{app.ErrOverloaded, 503},
		{&domain.Error{Code: domain.CodeCodeInvalid, Detail: "x", AttemptsLeft: &left}, 400},
		{&domain.Error{Code: domain.CodeChallengeClosed, Detail: "x"}, 410},
		{&domain.Error{Code: domain.CodeResendTooSoon, Detail: "x", RetryAfter: time.Minute}, 429},
	}
	ops := []struct {
		path, body string
		codes      []domain.Code // the codes of TDD-02 §10 the operation gives
	}{
		{"/v1/registrations", registrationBody, []domain.Code{domain.CodeValidationFailed, domain.CodeIdentifierNotAllowed,
			domain.CodeIdentifierTaken, domain.CodePasswordRejected, domain.CodeRateLimited, domain.CodeUnavailable}},
		{"/v1/registrations/" + testFlow.String() + "/verify", `{"handle":"` + testHandle + `","identifier_type":"phone","code":"123456"}`,
			[]domain.Code{domain.CodeCodeInvalid, domain.CodeChallengeClosed, domain.CodeIdentifierTaken, domain.CodeRateLimited}},
		{"/v1/registrations/" + testFlow.String() + "/resend", `{"handle":"` + testHandle + `","identifier_type":"phone"}`,
			[]domain.Code{domain.CodeChallengeClosed, domain.CodeResendTooSoon, domain.CodeRateLimited}},
		{"/v1/verification-links/confirm", `{"token":"` + strings.Repeat("t", 43) + `"}`,
			[]domain.Code{domain.CodeChallengeClosed, domain.CodeIdentifierTaken, domain.CodeRateLimited}},
	}
	for _, op := range ops {
		for _, e := range errs {
			var de *domain.Error
			_ = errors.As(e.err, &de)
			if !slices.Contains(op.codes, de.Code) {
				continue
			}
			t.Run(op.path+" "+string(de.Code), func(t *testing.T) {
				t.Parallel()
				resp := post(t, regRouter(t, &fakeRegistration{err: e.err}), op.path, op.body)
				if resp.status != e.status || !strings.Contains(string(resp.body), `"code":"`+string(de.Code)+`"`) {
					t.Errorf("status %d, body %s; want %d %s", resp.status, resp.body, e.status, de.Code)
				}
				if de.RetryAfter > 0 && resp.header.Get("Retry-After") == "" {
					t.Error("no Retry-After header")
				}
			})
		}
	}
}

// TestRegistrationUnboundRequest is a body the contract refuses: 422 before any use case runs.
func TestRegistrationUnboundRequest(t *testing.T) {
	t.Parallel()
	reg := &fakeRegistration{}
	req := httptest.NewRequest(http.MethodPost, "/v1/registrations/not-a-uuid/verify", strings.NewReader(`{"handle":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	regRouter(t, reg).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || reg.verify.FlowID != uuid.Nil {
		t.Errorf("status %d; want 422 without calling the use case", rec.Code)
	}
}
