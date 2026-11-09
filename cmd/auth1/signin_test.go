package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
	"github.com/arafat-hasan/auth1/internal/testing/redistest"
)

// The sign-in API tests register accounts through the API, confirm their email link, and make
// them active with the web client's default role in SQL, as completing the registration
// (TDD-02 §3, WP-54) will.

// secureClient is a client with mfa: required, added to the example's configuration.
const secureClient = `  - id: secure
    audience: example-secure
    allowed_roles: [user]
    default_roles: [user]
    first_factors: [password]
    mfa: required
    otp_channel: sms
    self_registration: false
    refresh_transport: cookie
    origins: [https://secure.example.com]
    link_base_url: https://secure.example.com/account
`

// withSecureClient adds secureClient after the example's clients.
func withSecureClient(t *testing.T, cfg string) string {
	t.Helper()
	out := strings.Replace(cfg, "\nidentifiers:", "\n"+secureClient+"\nidentifiers:", 1)
	if out == cfg {
		t.Fatal("the example has no identifiers section after its clients; update the test")
	}
	return out
}

// signInServer is serve on a fresh database and a Redis of its own, with the secure client, the
// new-sign-in notice on and room for many registrations and sign-ins from the test's address.
type signInServer struct {
	regServer
	redis *redistest.Server
}

func startSignInServer(t *testing.T, environ ...string) signInServer {
	t.Helper()
	rds := redistest.NewServer(t)
	s := startRegServerEdit(t, withSecureClient, append([]string{
		"AUTH1_REDIS_ADDRESS=" + rds.Addr(), "AUTH1_DELIVERY_NOTICES_NEW_SIGN_IN=true",
		"AUTH1_RATE_LIMITS_REGISTRATION_IP_LIMIT=100", "AUTH1_RATE_LIMITS_SIGN_IN_IP_LIMIT=1000",
		"AUTH1_RATE_LIMITS_SEND_IP_LIMIT=100", "AUTH1_RATE_LIMITS_VERIFY_IP_LIMIT=100",
	}, environ...)...)
	return signInServer{regServer: s, redis: rds}
}

// account registers email through the API, confirms its link, and makes the account active with
// the role user; it returns the account id.
func (s signInServer) account(t *testing.T, email string) uuid.UUID {
	t.Helper()
	flowID, _ := s.register(t, `{"email":"`+email+`"}`)
	link := variable(t, s.messages(t, email, 1)[0], "link")
	s.post(t, "/v1/verification-links/confirm", `{"token":"`+link+`"}`).want(t, http.StatusOK, "")
	var id uuid.UUID
	if err := s.db.QueryRowContext(t.Context(), "SELECT account_id FROM flows WHERE id = $1", flowID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	s.exec(t, "UPDATE accounts SET status = 'active', status_changed_at = now() WHERE id = $1", id)
	s.exec(t, "INSERT INTO account_roles (account_id, role, granted_at) VALUES ($1, 'user', now())", id)
	return id
}

func (s signInServer) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

// confirmTOTP gives the account a confirmed TOTP factor, sealed as the repository seals it.
func (s signInServer) confirmTOTP(t *testing.T, id uuid.UUID) {
	t.Helper()
	sealed, err := s.fc.Seal(app.NewPlace("totp_factors", "secret", id), []byte("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}
	s.exec(t, "INSERT INTO totp_factors (account_id, secret, confirmed_at, created_at) VALUES ($1, $2, now(), now())", id, sealed)
}

// signIn posts a sign-in with the device cookie, if any, and checks the exchange against the
// contract.
func (s signInServer) signIn(t *testing.T, client, email, password, device string) answer {
	t.Helper()
	body := fmt.Sprintf(`{"client_id":%q,"identifier":{"type":"email","value":%q},"password":%q}`, client, email, password)
	build := func(base string) *http.Request {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/v1/sessions", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SignInTest/1.0")
		// The client's cookie jar would not send a __Host- cookie over http; the header carries it.
		if device != "" {
			req.Header.Set("Cookie", app.DeviceCookieName+"="+device)
		}
		return req
	}
	resp, err := http.DefaultClient.Do(build(s.api))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	apitest.New(t).Check(t, build(""), resp)
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	a := answer{status: resp.StatusCode, header: resp.Header, raw: raw}
	if err := json.Unmarshal(raw, &a.body); err != nil {
		t.Fatalf("sign-in body %s: %v", raw, err)
	}
	return a
}

// cookie returns the value of the Set-Cookie named name in a, or "".
func (a answer) cookie(name string) string {
	for _, c := range a.header.Values("Set-Cookie") {
		if v, ok := strings.CutPrefix(c, name+"="); ok {
			return v[:strings.IndexByte(v, ';')]
		}
	}
	return ""
}

// claims decodes the access token's claims, without checking it.
func claims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("access token has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

var (
	refreshCookie = regexp.MustCompile(`^__Secure-auth1_rt=[A-Za-z0-9_-]{43}; Path=/v1/sessions; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict$`)
	deviceCookie  = regexp.MustCompile(`^__Host-auth1_dev=[A-Za-z0-9_-]{75}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Strict$`)
)

// TestSignInThroughAPI signs in on the optional client: 200 with the tokens (amr ["pwd"], T-30),
// the refresh and device cookies, a session that records the device and user agent, and the
// new-sign-in notice.
func TestSignInThroughAPI(t *testing.T) {
	s := startSignInServer(t)
	id := s.account(t, "ada@example.org")

	a := s.signIn(t, "web", "Ada@Example.org", regPassword, "")
	a.want(t, http.StatusOK, "")
	cookies := a.header.Values("Set-Cookie")
	if len(cookies) != 2 || !refreshCookie.MatchString(cookies[0]) || !deviceCookie.MatchString(cookies[1]) {
		t.Errorf("Set-Cookie = %q", cookies)
	}
	if a.header.Get("Cache-Control") != "no-store" || a.body["refresh_token"] != nil {
		t.Errorf("Cache-Control %q, body %s", a.header.Get("Cache-Control"), a.raw)
	}
	c := claims(t, a.body["access_token"].(string))
	if fmt.Sprint(c["amr"]) != "[pwd]" || c["aud"] != "example-web" || c["sub"] != id.String() ||
		c["sid"] != a.body["session_id"] || fmt.Sprint(c["roles"]) != "[user]" {
		t.Errorf("claims %v", c)
	}

	var device, agent string
	if err := s.db.QueryRowContext(t.Context(), "SELECT device_id::text, user_agent FROM sessions WHERE id = $1",
		a.body["session_id"]).Scan(&device, &agent); err != nil {
		t.Fatal(err)
	}
	if agent != "SignInTest/1.0" || device == "" {
		t.Errorf("session device %q, user agent %q", device, agent)
	}

	msgs := s.messages(t, "ada@example.org", 2)
	if msgs[0]["type"] != "auth.notice_new_sign_in" || variable(t, msgs[0], "client_id") != "web" {
		t.Errorf("newest message %v, want the new-sign-in notice", msgs[0])
	}

	// With the device cookie it was given, the browser gets no new one.
	again := s.signIn(t, "web", "ada@example.org", regPassword, a.cookie(app.DeviceCookieName))
	again.want(t, http.StatusOK, "")
	if got := again.cookie(app.DeviceCookieName); got != "" {
		t.Errorf("a new device cookie for a known browser")
	}
}

// TestT30ThroughAPI is T-30's first-factor answers.
func TestT30ThroughAPI(t *testing.T) {
	s := startSignInServer(t)
	s.account(t, "plain@example.org")
	totp := s.account(t, "totp@example.org")
	s.confirmTOTP(t, totp)

	for _, tt := range []struct {
		client, email, code string
	}{
		{"web", "totp@example.org", "MFA_REQUIRED"},
		{"secure", "totp@example.org", "MFA_REQUIRED"},
		{"secure", "plain@example.org", "MFA_ENROLMENT_REQUIRED"},
	} {
		a := s.signIn(t, tt.client, tt.email, regPassword, "")
		a.want(t, http.StatusAccepted, "")
		if a.body["code"] != tt.code || len(a.header.Values("Set-Cookie")) != 0 {
			t.Errorf("%s on %s: %s, cookies %v; want %s", tt.email, tt.client, a.raw, a.header.Values("Set-Cookie"), tt.code)
		}
	}
	var sessions, flows int
	if err := s.db.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM sessions),
		(SELECT count(*) FROM flows WHERE kind = 'sign_in' AND completed_at IS NULL)`).Scan(&sessions, &flows); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || flows != 3 {
		t.Errorf("%d sessions, %d open sign-in flows; want none and 3 (I-16)", sessions, flows)
	}
}

// TestT16DelaysWithRedisStopped is T-16: with Redis stopped, the per-IP limit fails open and the
// per-account delay in PostgreSQL still holds. The first delay is a minute, not the default
// second, so slow requests (the race detector, Redis timeouts) cannot outlast it.
func TestT16DelaysWithRedisStopped(t *testing.T) {
	s := startSignInServer(t, "AUTH1_RATE_LIMITS_SIGN_IN_FAILURES_FIRST_DELAY=1m")
	s.account(t, "ada@example.org")
	s.redis.Stop(t)
	for range 5 {
		s.signIn(t, "web", "ada@example.org", "wrong password", "").want(t, http.StatusUnauthorized, "INVALID_CREDENTIALS")
	}
	a := s.signIn(t, "web", "ada@example.org", regPassword, "")
	a.want(t, http.StatusTooManyRequests, "SIGN_IN_DELAYED")
	if r, err := strconv.Atoi(a.header.Get("Retry-After")); err != nil || r < 1 || r > 60 {
		t.Errorf("Retry-After %q, want 1 to 60 seconds", a.header.Get("Retry-After"))
	}
}

// TestT34KnownDeviceSignsIn is T-34: failures from elsewhere delay the untrusted bucket, and the
// owner's browser, with its device cookie, still signs in.
func TestT34KnownDeviceSignsIn(t *testing.T) {
	s := startSignInServer(t, "AUTH1_RATE_LIMITS_SIGN_IN_FAILURES_FIRST_DELAY=1m") // as T-16
	s.account(t, "ada@example.org")
	first := s.signIn(t, "web", "ada@example.org", regPassword, "")
	first.want(t, http.StatusOK, "")
	device := first.cookie(app.DeviceCookieName)

	for range 6 {
		a := s.signIn(t, "web", "ada@example.org", "wrong password", "")
		if a.status != http.StatusUnauthorized && a.status != http.StatusTooManyRequests {
			t.Fatalf("attacker's attempt: %d %s", a.status, a.raw)
		}
	}
	s.signIn(t, "web", "ada@example.org", regPassword, "").want(t, http.StatusTooManyRequests, "SIGN_IN_DELAYED")
	s.signIn(t, "web", "ada@example.org", regPassword, device).want(t, http.StatusOK, "")
}

// TestSignInStatusRowsThroughAPI is SDD §8.1's sign-in row through the API.
func TestSignInStatusRowsThroughAPI(t *testing.T) {
	s := startSignInServer(t)
	set := func(email, query string) {
		t.Helper()
		id := s.account(t, email)
		s.exec(t, query, id)
	}
	set("pending@example.org", "UPDATE accounts SET status = 'pending' WHERE id = $1")
	set("suspended@example.org", "UPDATE accounts SET status = 'suspended', status_reason = 'admin_action' WHERE id = $1")
	set("banned@example.org", "UPDATE accounts SET status = 'banned', status_reason = 'policy_violation' WHERE id = $1")
	set("deleted@example.org", "UPDATE accounts SET status = 'deleted' WHERE id = $1")
	set("noroles@example.org", "DELETE FROM account_roles WHERE account_id = $1")

	for _, tt := range []struct {
		email  string
		status int
		code   string
	}{
		{"pending@example.org", http.StatusForbidden, "REGISTRATION_INCOMPLETE"},
		{"deleted@example.org", http.StatusUnauthorized, "INVALID_CREDENTIALS"},
		{"noroles@example.org", http.StatusForbidden, "ROLE_NOT_PERMITTED"},
		{"nobody@example.org", http.StatusUnauthorized, "INVALID_CREDENTIALS"},
	} {
		s.signIn(t, "web", tt.email, regPassword, "").want(t, tt.status, tt.code)
	}
	for _, email := range []string{"suspended@example.org", "banned@example.org"} {
		a := s.signIn(t, "web", email, regPassword, "")
		a.want(t, http.StatusOK, "")
		c := claims(t, a.body["access_token"].(string))
		if c["aud"] == "example-web" || fmt.Sprint(c["roles"]) != "[]" || a.body["account_status"] == "active" {
			t.Errorf("%s: claims %v, body %s; want a restricted token", email, c, a.raw)
		}
	}
}

// TestSignInRestrictedRefused is SDD §8.1 with statuses.restricted_sign_in off.
func TestSignInRestrictedRefused(t *testing.T) {
	s := startSignInServer(t, "AUTH1_STATUSES_RESTRICTED_SIGN_IN=false")
	id := s.account(t, "ada@example.org")
	s.exec(t, "UPDATE accounts SET status = 'suspended', status_reason = 'admin_action' WHERE id = $1", id)
	s.signIn(t, "web", "ada@example.org", regPassword, "").want(t, http.StatusForbidden, "ACCOUNT_RESTRICTED")
}
