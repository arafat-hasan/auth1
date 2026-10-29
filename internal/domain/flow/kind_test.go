package flow

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/migrations"
)

// checkList returns the values of the CHECK (column IN (…)) list of migration 000001.
func checkList(t *testing.T, column string) []string {
	t.Helper()
	sql, err := migrations.FS.ReadFile("000001_init.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`CHECK \(` + column + ` IN \(([^)]*)\)\)`)
	m := re.FindSubmatch(sql)
	if m == nil {
		t.Fatalf("no CHECK (%s IN (…)) in 000001_init.up.sql", column)
	}
	var values []string
	for _, v := range strings.Split(string(m[1]), ",") {
		values = append(values, strings.Trim(strings.TrimSpace(v), "'"))
	}
	return values
}

func TestKindsMatchMigration(t *testing.T) {
	t.Parallel()

	var got []string
	for _, k := range Kinds() {
		got = append(got, string(k))
	}
	if diff := cmp.Diff(checkList(t, "kind"), got); diff != "" {
		t.Errorf("Kinds() against flows.kind CHECK (-check +got):\n%s", diff)
	}
	constants := []Kind{KindRegistration, KindInvitation, KindSignIn, KindPasswordReset,
		KindEmailChange, KindPhoneChange, KindTOTPReplacement}
	if diff := cmp.Diff(Kinds(), constants); diff != "" {
		t.Errorf("constants (-Kinds +constants):\n%s", diff)
	}
}

func TestMethodsMatchMigration(t *testing.T) {
	t.Parallel()

	var got []string
	for _, m := range Methods() {
		got = append(got, string(m))
	}
	if diff := cmp.Diff(checkList(t, "method"), got); diff != "" {
		t.Errorf("Methods() against challenges.method CHECK (-check +got):\n%s", diff)
	}
	constants := []Method{MethodSMSOTP, MethodEmailLink, MethodEmailCode}
	if diff := cmp.Diff(Methods(), constants); diff != "" {
		t.Errorf("constants (-Methods +constants):\n%s", diff)
	}
}

// TestPurposes pins the purposes to TDD-02 §2.3: challenges.purpose has no CHECK.
func TestPurposes(t *testing.T) {
	t.Parallel()

	want := []Purpose{"verify_identifier", "resume", "invitation", "sign_in", "reset_link",
		"reset_step_up", "email_change_old", "email_change_new", "phone_change"}
	if diff := cmp.Diff(want, Purposes()); diff != "" {
		t.Errorf("Purposes() (-want +got):\n%s", diff)
	}
	constants := []Purpose{PurposeVerifyIdentifier, PurposeResume, PurposeInvitation, PurposeSignIn,
		PurposeResetLink, PurposeResetStepUp, PurposeEmailChangeOld, PurposeEmailChangeNew, PurposePhoneChange}
	if diff := cmp.Diff(want, constants); diff != "" {
		t.Errorf("constants (-want +got):\n%s", diff)
	}
}

// TestCloseReasons pins the close reasons to TDD-02 §2.1: flows.close_reason has no CHECK.
func TestCloseReasons(t *testing.T) {
	t.Parallel()

	want := []CloseReason{"replaced", "expired", "account_closed", "attempts"}
	if diff := cmp.Diff(want, CloseReasons()); diff != "" {
		t.Errorf("CloseReasons() (-want +got):\n%s", diff)
	}
	constants := []CloseReason{CloseReplaced, CloseExpired, CloseAccountClosed, CloseAttempts}
	if diff := cmp.Diff(want, constants); diff != "" {
		t.Errorf("constants (-want +got):\n%s", diff)
	}
}

func TestListsReturnCopies(t *testing.T) {
	t.Parallel()

	Kinds()[0] = "changed"
	Purposes()[0] = "changed"
	Methods()[0] = "changed"
	CloseReasons()[0] = "changed"
	if Kinds()[0] != KindRegistration || Purposes()[0] != PurposeVerifyIdentifier ||
		Methods()[0] != MethodSMSOTP || CloseReasons()[0] != CloseReplaced {
		t.Error("a caller's change to a returned list changed the package's list")
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	for _, k := range Kinds() {
		if got, err := ParseKind(string(k)); err != nil || got != k {
			t.Errorf("ParseKind(%q) = %q, %v", k, got, err)
		}
	}
	for _, p := range Purposes() {
		if got, err := ParsePurpose(string(p)); err != nil || got != p {
			t.Errorf("ParsePurpose(%q) = %q, %v", p, got, err)
		}
	}
	for _, m := range Methods() {
		if got, err := ParseMethod(string(m)); err != nil || got != m {
			t.Errorf("ParseMethod(%q) = %q, %v", m, got, err)
		}
	}
	for _, r := range CloseReasons() {
		if got, err := ParseCloseReason(string(r)); err != nil || got != r {
			t.Errorf("ParseCloseReason(%q) = %q, %v", r, got, err)
		}
	}

	parsers := []struct {
		field string
		parse func(string) (string, error)
		near  string // a near miss of a valid value
	}{
		{"kind", func(s string) (string, error) { v, err := ParseKind(s); return string(v), err }, "signin"},
		{"purpose", func(s string) (string, error) { v, err := ParsePurpose(s); return string(v), err }, "Resume"},
		{"method", func(s string) (string, error) { v, err := ParseMethod(s); return string(v), err }, "sms"},
		{"close_reason", func(s string) (string, error) { v, err := ParseCloseReason(s); return string(v), err }, "exhausted"},
	}
	for _, p := range parsers {
		for _, in := range []string{"", " " + p.near, p.near, strings.ToUpper(p.near)} {
			got, err := p.parse(in)
			if got != "" {
				t.Errorf("parse %s %q = %q, want the zero value", p.field, in, got)
			}
			checkError(t, err, domain.CodeValidationFailed,
				[]domain.FieldError{{Field: p.field, Code: domain.FieldUnknown}})
		}
	}
}

func TestExpiresAt(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	l := Lifetimes{
		Registration:    1 * time.Minute,
		Invitation:      2 * time.Minute,
		SignIn:          3 * time.Minute,
		PasswordReset:   4 * time.Minute,
		EmailChange:     5 * time.Minute,
		PhoneChange:     6 * time.Minute,
		TOTPReplacement: 7 * time.Minute,
	}
	want := map[Kind]time.Duration{
		KindRegistration: 1 * time.Minute, KindInvitation: 2 * time.Minute, KindSignIn: 3 * time.Minute,
		KindPasswordReset: 4 * time.Minute, KindEmailChange: 5 * time.Minute, KindPhoneChange: 6 * time.Minute,
		KindTOTPReplacement: 7 * time.Minute,
	}
	for _, k := range Kinds() {
		got, err := ExpiresAt(k, now, l)
		if err != nil || !got.Equal(now.Add(want[k])) {
			t.Errorf("ExpiresAt(%s) = %v, %v; want %v", k, got, err, now.Add(want[k]))
		}
	}

	if _, err := ExpiresAt("unknown", now, l); !errors.Is(err, ErrLifetimeInvalid) {
		t.Error("ExpiresAt of an unknown kind: not ErrLifetimeInvalid")
	}
	zero := l
	zero.PhoneChange = 0
	if _, err := ExpiresAt(KindPhoneChange, now, zero); !errors.Is(err, ErrLifetimeInvalid) {
		t.Error("ExpiresAt with a zero lifetime: not ErrLifetimeInvalid")
	}
	negative := l
	negative.SignIn = -time.Second
	if _, err := ExpiresAt(KindSignIn, now, negative); !errors.Is(err, ErrLifetimeInvalid) {
		t.Error("ExpiresAt with a negative lifetime: not ErrLifetimeInvalid")
	}
}
