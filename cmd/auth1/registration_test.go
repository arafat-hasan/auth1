package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
	"github.com/arafat-hasan/auth1/internal/testing/redistest"
)

// dbResolver resolves delivery references from the database, as the resolver hook will (TDD-06 §6),
// for the tests until WP-43: an identifier's value, and an open challenge's code or link token.
// It answers only references that are open; a link resolves to its bare token.
type dbResolver struct {
	db *sql.DB
	fc *crypto.FieldCrypto
}

func (r dbResolver) Resolve(ctx context.Context, _ string, refs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, ref := range refs {
		kind, rawID, _ := strings.Cut(strings.TrimPrefix(ref, "auth1:"), ":")
		id, err := uuid.Parse(rawID)
		if err != nil {
			continue
		}
		var (
			query string
			place app.Place
		)
		switch kind {
		case "identifier":
			query, place = "SELECT value FROM identifiers WHERE id = $1 AND retired_at IS NULL", app.NewPlace("identifiers", "value", id)
		case "secret", "link":
			query, place = "SELECT secret FROM challenges WHERE id = $1 AND closed_at IS NULL", app.NewPlace("challenges", "secret", id)
		default:
			continue
		}
		var sealed []byte
		if err := r.db.QueryRowContext(ctx, query, id).Scan(&sealed); errors.Is(err, sql.ErrNoRows) || sealed == nil {
			continue
		} else if err != nil {
			return nil, err
		}
		v, err := r.fc.Open(place, sealed)
		if err != nil {
			return nil, err
		}
		out[ref] = string(v)
	}
	return out, nil
}

// regServer is serve with the capture adapter on a fresh database, with phones under +44 allowed.
type regServer struct {
	api string
	db  *sql.DB             // superuser
	fc  *crypto.FieldCrypto // the example's field keyring, to seal rows a test writes
}

// startRegServer starts serve on the example configuration with phones allowed for +44, and the
// test resolver, with environ added.
func startRegServer(t *testing.T, environ ...string) regServer {
	t.Helper()
	return startRegServerWith(t, nil, environ...)
}

// startRegServerWith is startRegServer with opts adjusting testDeps.
func startRegServerWith(t *testing.T, opts []func(*serveDeps), environ ...string) regServer {
	t.Helper()
	return startRegServerFull(t, nil, opts, environ...)
}

// startRegServerEdit is startRegServer with edit applied to the configuration as well.
func startRegServerEdit(t *testing.T, edit func(t *testing.T, cfg string) string, environ ...string) regServer {
	t.Helper()
	return startRegServerFull(t, edit, nil, environ...)
}

// startRegServerFull is startRegServer with edit applied to the configuration and opts adjusting
// testDeps; either may be nil.
func startRegServerFull(t *testing.T, edit func(t *testing.T, cfg string) string, opts []func(*serveDeps), environ ...string) regServer {
	t.Helper()
	dsn := pgtest.DSN(t)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile(filepath.Join(root, "config.example.yaml")) //nolint:gosec // the repository's example
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(example),
		"phone: { required: false, verify: sms_otp, sign_in: false, calling_codes: [] }",
		`phone: { required: false, verify: sms_otp, sign_in: false, calling_codes: ["44"] }`, 1)
	if cfg == string(example) {
		t.Fatal("the example's phone policy line changed; update the test")
	}
	if edit != nil {
		cfg = edit(t, cfg)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil { //nolint:gosec // a test file in a temporary directory
		t.Fatal(err)
	}
	keys, err := crypto.NewWatchedKeyring(filepath.Join(root, "testdata/example/secrets/fields/keyring.yaml"), crypto.StateDecrypt, nil)
	if err != nil {
		t.Fatal(err)
	}
	fc := crypto.NewFieldCrypto(keys)
	resolver := dbResolver{db: db, fc: fc}
	api, _ := startServeConfig(t, path, append(append(dsnEnv(t, dsn), promoteAtOnce), environ...),
		append([]func(*serveDeps){func(d *serveDeps) { d.resolver = resolver }}, opts...)...)
	return regServer{api: api, db: db, fc: fc}
}

// answer is a served response, its body read.
type answer struct {
	status int
	header http.Header
	body   map[string]any
	raw    []byte
}

// post sends body to path and checks the exchange against the contract.
func (s regServer) post(t *testing.T, path, body string) answer {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.api+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	contract, err := http.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	contract.Header.Set("Content-Type", "application/json")
	apitest.New(t).Check(t, contract, resp)
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	a := answer{status: resp.StatusCode, header: resp.Header, raw: raw}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a.body); err != nil {
			t.Fatalf("POST %s: body %s: %v", path, raw, err)
		}
	}
	return a
}

// want fails the test unless the answer has status and, for a problem, code.
func (a answer) want(t *testing.T, status int, code string) {
	t.Helper()
	if a.status != status || (code != "" && a.body["code"] != code) {
		t.Fatalf("answer %d %s; want %d %s", a.status, a.raw, status, code)
	}
}

// messages waits until at least n messages to "to" are captured, and returns them, newest first.
func (s regServer) messages(t *testing.T, to string, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body := get(t, s.api+"/dev/messages?to="+url.QueryEscape(to))
		var got struct {
			Messages []map[string]any `json:"messages"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("/dev/messages: %s: %v", body, err)
		}
		if len(got.Messages) >= n {
			return got.Messages
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d messages to %s; want %d", len(got.Messages), to, n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// variable returns the variable name of the message m.
func variable(t *testing.T, m map[string]any, name string) string {
	t.Helper()
	vars, _ := m["variables"].(map[string]any)
	v, ok := vars[name].(string)
	if !ok {
		t.Fatalf("message %v has no %s", m, name)
	}
	return v
}

// register starts a registration with the identifiers and returns its flow id and handle.
func (s regServer) register(t *testing.T, identifiers string) (flowID, handle string) {
	t.Helper()
	a := s.post(t, "/v1/registrations", `{"client_id":"web","display_name":"Someone","locale":"en",`+
		`"identifiers":`+identifiers+`,"password":"`+regPassword+`"}`)
	a.want(t, http.StatusCreated, "")
	return a.body["flow_id"].(string), a.body["handle"].(string)
}

func (s regServer) verify(t *testing.T, flowID, handle, code string) answer {
	t.Helper()
	return s.post(t, "/v1/registrations/"+flowID+"/verify",
		`{"handle":"`+handle+`","identifier_type":"phone","code":"`+code+`"}`)
}

func (s regServer) resend(t *testing.T, flowID, handle, typ string) answer {
	t.Helper()
	return s.post(t, "/v1/registrations/"+flowID+"/resend", `{"handle":"`+handle+`","identifier_type":"`+typ+`"}`)
}

const (
	regPassword = "correct horse battery staple"
	regPhone    = "+447400123456"
)

// TestRegistrationThroughAPI registers with an email and a phone, reads the code and the link from
// the capture adapter, and verifies both, checking every answer against the contract.
func TestRegistrationThroughAPI(t *testing.T) {
	s := startRegServer(t)
	flowID, handle := s.register(t, `{"email":"Ada@Example.org","phone":"+44 7400 123456"}`)

	code := variable(t, s.messages(t, regPhone, 1)[0], "code")
	link := variable(t, s.messages(t, "ada@example.org", 1)[0], "link")

	// Within 60 s of the send: RESEND_TOO_SOON with retry_after and Retry-After.
	a := s.resend(t, flowID, handle, "phone")
	a.want(t, http.StatusTooManyRequests, "RESEND_TOO_SOON")
	if a.body["retry_after"] == nil || a.header.Get("Retry-After") == "" {
		t.Errorf("RESEND_TOO_SOON without retry_after and Retry-After: %s", a.raw)
	}

	a = s.verify(t, flowID, handle, wrong(code))
	a.want(t, http.StatusBadRequest, "CODE_INVALID")
	if a.body["attempts_left"] != float64(2) {
		t.Errorf("attempts_left = %v; want 2", a.body["attempts_left"])
	}

	// I-4: of eight concurrent tries with the right code, exactly one verifies.
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses []int
	)
	for range 8 {
		wg.Go(func() {
			a := s.verify(t, flowID, handle, code)
			mu.Lock()
			statuses = append(statuses, a.status)
			mu.Unlock()
		})
	}
	wg.Wait()
	slices.Sort(statuses)
	if !slices.Equal(statuses, []int{200, 410, 410, 410, 410, 410, 410, 410}) {
		t.Errorf("statuses = %v; want one 200 and seven 410", statuses)
	}

	a = s.post(t, "/v1/verification-links/confirm", `{"token":"`+link+`"}`)
	a.want(t, http.StatusOK, "")
	if a.body["purpose"] != "verify_identifier" || a.body["flow_id"] != flowID || a.body["complete"] != true {
		t.Errorf("confirmed = %s", a.raw)
	}
	s.post(t, "/v1/verification-links/confirm", `{"token":"`+link+`"}`).want(t, http.StatusGone, "CHALLENGE_CLOSED")

	// I-5: closed challenges hold no secret.
	var open, secrets int
	if err := s.db.QueryRowContext(t.Context(), `SELECT count(*) FILTER (WHERE closed_at IS NULL),
		count(*) FILTER (WHERE secret IS NOT NULL) FROM challenges`).Scan(&open, &secrets); err != nil {
		t.Fatal(err)
	}
	if open != 0 || secrets != 0 {
		t.Errorf("%d open challenges, %d secrets; want none", open, secrets)
	}

	// account.identifier_verified, once per identifier, with exactly the contract's data.
	rows, err := s.db.QueryContext(t.Context(), `SELECT body FROM outbox WHERE destination = 'event'
		AND type = 'account.identifier_verified' ORDER BY account_version`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var types []string
	for rows.Next() {
		var data map[string]any
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			t.Fatal(err)
		}
		keys := []string{}
		for k := range data {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"account_id", "actor", "identifier_id", "identifier_type"}) {
			t.Errorf("event data keys %v", keys)
		}
		types = append(types, data["identifier_type"].(string))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(types, []string{"phone", "email"}) {
		t.Errorf("verified events for %v; want [phone email]", types)
	}

	// G-6, T-9: no value, password, code, token or handle in any outbox row or audit entry.
	var dump string
	if err := s.db.QueryRowContext(t.Context(), `SELECT coalesce(string_agg(body::text, ' '), '') FROM outbox`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	var audit string
	if err := s.db.QueryRowContext(t.Context(), `SELECT coalesce(string_agg(details::text || coalesce(client_id, ''), ' '), '')
		FROM auth_audit`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if audit == "" {
		t.Error("nothing audited")
	}
	for _, secret := range []string{"ada@example.org", "Ada@Example.org", regPhone, "7400123456", regPassword, code, link, handle} {
		if strings.Contains(dump, secret) || strings.Contains(audit, secret) {
			t.Errorf("a secret or value is in the outbox or the audit log")
		}
	}
}

// wrong returns a code that is not code.
func wrong(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

// TestT1SamePhoneSecondVerifierTaken is acceptance test T-1 (I-1): two pending accounts register
// one phone; the first to verify gets it, the second gets IDENTIFIER_TAKEN, and its challenge is
// consumed. The second registration's send falls in the first's short window (I-21), so it is
// sent by a resend once the window has passed.
func TestT1SamePhoneSecondVerifierTaken(t *testing.T) {
	s := startRegServer(t, "AUTH1_OTP_RESEND_AFTER=1s")
	flowA, handleA := s.register(t, `{"email":"a@example.org","phone":"`+regPhone+`"}`)
	codeA := variable(t, s.messages(t, regPhone, 1)[0], "code")
	flowB, handleB := s.register(t, `{"email":"b@example.org","phone":"`+regPhone+`"}`)
	sent := len(s.messages(t, regPhone, 1))
	time.Sleep(1100 * time.Millisecond)
	s.resend(t, flowB, handleB, "phone").want(t, http.StatusAccepted, "")
	codeB := variable(t, s.messages(t, regPhone, sent+1)[0], "code")

	s.verify(t, flowA, handleA, codeA).want(t, http.StatusOK, "")
	s.verify(t, flowB, handleB, codeB).want(t, http.StatusConflict, "IDENTIFIER_TAKEN")
	s.verify(t, flowB, handleB, codeB).want(t, http.StatusGone, "CHALLENGE_CLOSED")

	var verified int
	if err := s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM identifiers WHERE type = 'phone'
		AND verified_at IS NOT NULL`).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if verified != 1 {
		t.Errorf("%d verified phones; want 1", verified)
	}
}

// TestRegistrationI21SharedBudget: two registrations of one email within the short window both
// start, but only the first is sent; the second account's resend meets the same budget (I-21).
func TestRegistrationI21SharedBudget(t *testing.T) {
	s := startRegServer(t)
	s.register(t, `{"email":"shared@example.org"}`)
	flowB, handleB := s.register(t, `{"email":"shared@example.org"}`)
	s.resend(t, flowB, handleB, "email").want(t, http.StatusTooManyRequests, "RESEND_TOO_SOON")
	time.Sleep(500 * time.Millisecond) // the relay would have sent a second message by now
	if n := len(s.messages(t, "shared@example.org", 1)); n != 1 {
		t.Errorf("%d messages to the shared address; want 1", n)
	}
}

// TestRegistrationErrorRows answers each code of TDD-02 §10 for registration, verify and resend
// through the API; every answer is checked against the contract.
func TestRegistrationErrorRows(t *testing.T) {
	rds := redistest.NewServer(t)
	s := startRegServer(t, "AUTH1_REDIS_ADDRESS="+rds.Addr(), "AUTH1_RATE_LIMITS_REGISTRATION_IP_LIMIT=8")
	body := func(fields string) string {
		return `{"client_id":"web","display_name":"Someone","locale":"en","password":"` + regPassword + `",` + fields + `}`
	}

	// A verified email, for IDENTIFIER_TAKEN.
	flowID, handle := s.register(t, `{"email":"taken@example.org","phone":"`+regPhone+`"}`)
	link := variable(t, s.messages(t, "taken@example.org", 1)[0], "link")
	s.post(t, "/v1/verification-links/confirm", `{"token":"`+link+`"}`).want(t, http.StatusOK, "")

	registrations := []struct {
		name, body, code string
		status           int
	}{
		{"unknown client", strings.Replace(body(`"identifiers":{"email":"x@example.org"}`), `"web"`, `"nope"`, 1),
			"VALIDATION_FAILED", 422},
		{"required type missing", body(`"identifiers":{"phone":"+447400123457"}`), "VALIDATION_FAILED", 422},
		{"phone outside +44", body(`"identifiers":{"email":"x@example.org","phone":"+12025550100"}`), "IDENTIFIER_NOT_ALLOWED", 422},
		{"value taken", body(`"identifiers":{"email":"Taken@example.org"}`), "IDENTIFIER_TAKEN", 409},
		{"password holds the email", strings.Replace(body(`"identifiers":{"email":"someone.long@example.org"}`),
			regPassword, "someone.long@example.org", 1), "PASSWORD_REJECTED", 422},
		{"L-4: the fifth registration from this IP in an hour", body(`"identifiers":{"email":"y@example.org"}`),
			"RATE_LIMITED", 429},
	}
	// Every registration that passes the client check counts against L-4: the one above, three
	// more here and the four refusals below fill the eight; the last is refused.
	for i := range 3 {
		s.register(t, `{"email":"fill`+string(rune('0'+i))+`@example.org"}`)
	}
	for _, r := range registrations {
		a := s.post(t, "/v1/registrations", r.body)
		if a.status != r.status || a.body["code"] != r.code {
			t.Errorf("%s: %d %s; want %d %s", r.name, a.status, a.raw, r.status, r.code)
		}
	}

	// I-20: a wrong handle, an unknown flow and an expired flow answer alike.
	other := "0192f000-0000-7000-8000-000000000000"
	misses := []answer{
		s.verify(t, flowID, strings.Repeat("A", 43), "123456"),
		s.verify(t, other, handle, "123456"),
		s.resend(t, other, handle, "phone"),
	}
	if _, err := s.db.ExecContext(t.Context(), `UPDATE flows SET expires_at = now() - interval '1 second' WHERE id = $1`, flowID); err != nil {
		t.Fatal(err)
	}
	misses = append(misses, s.verify(t, flowID, handle, "123456"), s.resend(t, flowID, handle, "phone"))
	for i, a := range misses {
		a.want(t, http.StatusGone, "CHALLENGE_CLOSED")
		delete(a.body, "instance")
		delete(misses[0].body, "instance")
		if !bytes.Equal(mustJSON(t, a.body), mustJSON(t, misses[0].body)) {
			t.Errorf("miss %d answers %s; want the same as %s (I-20)", i, a.raw, misses[0].raw)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVerifyAttemptsCommit (I-4, I-5): each wrong code's try is stored although the answer is an
// error, so the third closes the challenge and the right code after it is refused; the closed
// challenge holds no secret.
func TestVerifyAttemptsCommit(t *testing.T) {
	s := startRegServer(t)
	flowID, handle := s.register(t, `{"email":"tries@example.org","phone":"`+regPhone+`"}`)
	code := variable(t, s.messages(t, regPhone, 1)[0], "code")
	for i, want := range []int{http.StatusBadRequest, http.StatusBadRequest, http.StatusGone} {
		if a := s.verify(t, flowID, handle, wrong(code)); a.status != want {
			t.Fatalf("wrong code %d: %d %s; want %d", i+1, a.status, a.raw, want)
		}
	}
	s.verify(t, flowID, handle, code).want(t, http.StatusGone, "CHALLENGE_CLOSED")

	var (
		attempts         int
		closed, consumed bool
		secret           bool
	)
	if err := s.db.QueryRowContext(t.Context(), `SELECT attempts, closed_at IS NOT NULL, consumed_at IS NOT NULL,
		secret IS NOT NULL FROM challenges WHERE method = 'sms_otp'`).Scan(&attempts, &closed, &consumed, &secret); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || !closed || consumed || secret {
		t.Errorf("challenge: attempts %d, closed %v, consumed %v, secret kept %v; want 3, closed unconsumed, no secret",
			attempts, closed, consumed, secret)
	}
}

// TestCooldownAcrossAccounts (L-9): once a code to a phone has run out of attempts, no new code
// goes to that phone for the cooldown, whichever account asks.
func TestCooldownAcrossAccounts(t *testing.T) {
	s := startRegServer(t, "AUTH1_OTP_RESEND_AFTER=1s")
	flowA, handleA := s.register(t, `{"email":"first@example.org","phone":"`+regPhone+`"}`)
	code := variable(t, s.messages(t, regPhone, 1)[0], "code")
	for range 3 {
		s.verify(t, flowA, handleA, wrong(code))
	}
	time.Sleep(1100 * time.Millisecond) // past the short window
	flowB, handleB := s.register(t, `{"email":"second@example.org","phone":"`+regPhone+`"}`)
	a := s.resend(t, flowB, handleB, "phone")
	a.want(t, http.StatusTooManyRequests, "RESEND_TOO_SOON")
	if retry, _ := a.body["retry_after"].(float64); retry < 800 || retry > 900 {
		t.Errorf("retry_after = %v; want the rest of the 15-minute cooldown", a.body["retry_after"])
	}
	var unsent string
	if err := s.db.QueryRowContext(t.Context(), `SELECT details->>'unsent_types' FROM auth_audit
		WHERE action = 'registration.start' AND outcome = 'success' ORDER BY at DESC LIMIT 1`).Scan(&unsent); err != nil {
		t.Fatal(err)
	}
	if unsent != `["phone"]` {
		t.Errorf("the second registration's audit lists unsent %s; want [\"phone\"]", unsent)
	}
}

// TestResendRefusedRollsBack: a resend that would replace an expired code, but whose send the
// address's hour budget refuses, changes nothing: the old challenge is not closed and no new one
// is opened. The code expires by back-dating its row, not by waiting, so the first resend always
// finds it live, however slow the run.
func TestResendRefusedRollsBack(t *testing.T) {
	s := startRegServer(t, "AUTH1_OTP_RESEND_AFTER=1s", "AUTH1_OTP_MAX_SENDS_PER_HOUR=2")
	flowID, handle := s.register(t, `{"email":"budget@example.org","phone":"`+regPhone+`"}`)
	time.Sleep(1100 * time.Millisecond)                                   // past otp.resend_after: waiting longer changes nothing
	s.resend(t, flowID, handle, "phone").want(t, http.StatusAccepted, "") // the second send: the budget is used

	var id string
	if err := s.db.QueryRowContext(t.Context(), `UPDATE challenges SET expires_at = now() - interval '1 second'
		WHERE method = 'sms_otp' AND closed_at IS NULL RETURNING id`).Scan(&id); err != nil {
		t.Fatalf("expire the code: %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // past the short window too, so only the hour budget refuses
	s.resend(t, flowID, handle, "phone").want(t, http.StatusTooManyRequests, "RATE_LIMITED")

	var challenges, open, sends int
	var only string
	if err := s.db.QueryRowContext(t.Context(), `SELECT count(*), count(*) FILTER (WHERE closed_at IS NULL),
		max(sends), max(id::text) FROM challenges WHERE method = 'sms_otp'`).Scan(&challenges, &open, &sends, &only); err != nil {
		t.Fatal(err)
	}
	if challenges != 1 || open != 1 || only != id || sends != 2 {
		t.Errorf("%d phone challenges, %d open, sends %d; want the one (%s), still open, sent twice", challenges, open, sends, id)
	}
}
