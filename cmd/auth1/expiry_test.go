package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// fastJobs runs every job every 100 ms instead of at its TDD-08 §7 interval.
func fastJobs(d *serveDeps) { d.jobEvery = 100 * time.Millisecond }

// TestT18ExpiryReleasesIdentifiers checks T-18 through serve and its job: an abandoned
// registration's identifiers are retired at expiry (I-12), and a new registration with the same
// values succeeds. The phone is verified first, so the values are held until expiry releases them.
func TestT18ExpiryReleasesIdentifiers(t *testing.T) {
	s := startRegServerWith(t, []func(*serveDeps){fastJobs})
	identifiers := `{"email":"t18@example.org","phone":"` + regPhone + `"}`
	flowID, handle := s.register(t, identifiers)
	code := variable(t, s.messages(t, regPhone, 1)[0], "code")
	s.verify(t, flowID, handle, code).want(t, http.StatusOK, "")

	again := `{"client_id":"web","display_name":"Someone","locale":"en","identifiers":` + identifiers +
		`,"password":"` + regPassword + `"}`
	s.post(t, "/v1/registrations", again).want(t, http.StatusConflict, "IDENTIFIER_TAKEN")

	var accountID string
	if err := s.db.QueryRowContext(t.Context(), "SELECT account_id FROM flows WHERE id = $1", flowID).Scan(&accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(t.Context(),
		"UPDATE flows SET expires_at = now() - interval '1 second' WHERE id = $1", flowID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var status string
		if err := s.db.QueryRowContext(t.Context(), "SELECT status FROM accounts WHERE id = $1", accountID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "deleted" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("account %s still %s; the expiry job did not run", accountID, status)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var current, events int
	if err := s.db.QueryRowContext(t.Context(), `
		SELECT (SELECT count(*) FROM identifiers WHERE account_id = $1 AND retired_at IS NULL),
		       (SELECT count(*) FROM outbox WHERE subject = $1 AND type = 'account.registration_expired')`,
		accountID).Scan(&current, &events); err != nil {
		t.Fatal(err)
	}
	if current != 0 || events != 1 {
		t.Errorf("I-12: %d current identifiers, %d expiry events; want 0, 1", current, events)
	}

	s.post(t, "/v1/registrations", again).want(t, http.StatusCreated, "")
}

// TestServeRecordsJobSuccess checks that serve runs the flow-expiry job and records
// auth1_job_last_success_timestamp{job="flow-expiry"} on its metrics.
func TestServeRecordsJobSuccess(t *testing.T) {
	_, metrics := startServeWithMetrics(t, append(dsnEnv(t, pgtest.DSN(t)), promoteAtOnce), fastJobs)
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body := get(t, metrics+"/metrics")
		if strings.Contains(body, `auth1_job_last_success_timestamp{job="flow-expiry"`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no auth1_job_last_success_timestamp for flow-expiry")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
