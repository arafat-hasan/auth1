package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

const phone = "+447700900123"

// identifierTimes ignores the times the database sets.
var identifierTimes = cmpopts.IgnoreFields(account.Identifier{}, "VerifiedAt", "RetiredAt", "CreatedAt")

// verify verifies the identifier id in its own transaction.
func (e *accountsEnv) verify(t *testing.T, id uuid.UUID) error {
	t.Helper()
	return e.uow.Do(t.Context(), func(ctx context.Context) error { return e.repo.VerifyIdentifier(ctx, id) })
}

// TestT1SecondVerificationTaken checks T-1 at the repository: two pending accounts hold one phone
// unverified; the first to verify it gets it, and the second gets IDENTIFIER_TAKEN (I-1).
func TestT1SecondVerificationTaken(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	first, second := e.newAccount(phone, ""), e.newAccount(phone, "")
	e.create(t, first)
	e.create(t, second)

	if err := e.verify(t, first.Identifiers[0].ID); err != nil {
		t.Fatalf("first verification: %v", err)
	}
	err := e.verify(t, second.Identifiers[0].ID)
	checkCode(t, err, domain.CodeIdentifierTaken)
	if strings.Contains(err.Error(), "447700900123") || strings.Contains(err.Error(), `\x`) {
		t.Errorf("error %q holds the value or its index", err)
	}

	got, err := e.repo.FindVerified(t.Context(), "phone", phone)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountID != first.ID || got.ID != first.Identifiers[0].ID || got.VerifiedAt == nil {
		t.Errorf("verified holder = %+v, want the first account's identifier", got)
	}
}

// TestIdentifierTakenKeepsTransaction checks that IDENTIFIER_TAKEN leaves the use case's
// transaction usable: on it the use case still consumes the challenge and commits (TDD-02 §3).
// Here it bumps the version instead, which must be committed.
func TestIdentifierTakenKeepsTransaction(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	first, second := e.newAccount(phone, ""), e.newAccount(phone, "")
	e.create(t, first)
	e.create(t, second)
	if err := e.verify(t, first.Identifiers[0].ID); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name  string
		taken func(ctx context.Context) error
	}{
		{"verify", func(ctx context.Context) error { return e.repo.VerifyIdentifier(ctx, second.Identifiers[0].ID) }},
		{"add verified", func(ctx context.Context) error {
			if err := e.repo.RetireIdentifier(ctx, second.Identifiers[0].ID); err != nil {
				return err
			}
			return e.repo.AddIdentifier(ctx, second.ID, account.NewIdentifier{ID: e.ids.New(), Type: "phone", Value: phone, Verified: true})
		}},
	} {
		before, err := e.repo.Get(t.Context(), second.ID)
		if err != nil {
			t.Fatal(err)
		}
		e.do(t, func(ctx context.Context) error {
			checkCode(t, c.taken(ctx), domain.CodeIdentifierTaken)
			_, err := e.repo.BumpVersion(ctx, second.ID, 1)
			return err
		})
		after, err := e.repo.Get(t.Context(), second.ID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Version != before.Version+1 {
			t.Errorf("%s: version %d after the transaction, want %d", c.name, after.Version, before.Version+1)
		}
	}
	// The retirement in "add verified" committed with the bump, and the refused insert did not.
	if ids, err := e.repo.Identifiers(t.Context(), second.ID); err != nil || len(ids) != 0 {
		t.Errorf("second's identifiers = %v, %v; want none", ids, err)
	}
}

func TestFindCurrentReturnsEveryPendingHolder(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	a, b, other := e.newAccount(phone, ""), e.newAccount(phone, ""), e.newAccount("+447700900999", "")
	for _, na := range []account.NewAccount{a, b, other} {
		e.create(t, na)
	}
	got, err := e.repo.FindCurrent(t.Context(), "phone", phone)
	if err != nil {
		t.Fatal(err)
	}
	want := []account.Identifier{
		{ID: a.Identifiers[0].ID, AccountID: a.ID, Type: "phone", Value: phone},
		{ID: b.Identifiers[0].ID, AccountID: b.ID, Type: "phone", Value: phone},
	}
	if diff := cmp.Diff(want, got, identifierTimes); diff != "" {
		t.Errorf("current holders (-want +got):\n%s", diff)
	}
	if got, err := e.repo.FindCurrent(t.Context(), "email", phone); err != nil || len(got) != 0 {
		t.Errorf("another type: %v, %v; want none", got, err)
	}
}

func TestFindVerifiedIgnoresUnverifiedAndRetired(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount(phone, "")
	e.create(t, na)
	id := na.Identifiers[0].ID

	_, err := e.repo.FindVerified(t.Context(), "phone", phone)
	checkCode(t, err, domain.CodeNotFound)
	if err := e.verify(t, id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.FindVerified(t.Context(), "phone", phone); err != nil {
		t.Fatalf("verified: %v", err)
	}
	if err := e.repo.RetireIdentifier(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	_, err = e.repo.FindVerified(t.Context(), "phone", phone)
	checkCode(t, err, domain.CodeNotFound)
}

// TestRetireReleasesValue checks that a retired value is free for another account to verify.
func TestRetireReleasesValue(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	a, b := e.newAccount(phone, ""), e.newAccount(phone, "")
	e.create(t, a)
	e.create(t, b)
	if err := e.verify(t, a.Identifiers[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := e.repo.RetireIdentifier(t.Context(), a.Identifiers[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := e.verify(t, b.Identifiers[0].ID); err != nil {
		t.Errorf("verification after release: %v", err)
	}
	err := e.repo.RetireIdentifier(t.Context(), a.Identifiers[0].ID)
	checkCode(t, err, domain.CodeNotFound)
}

func TestRetireIdentifiers(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount(phone, "ada@example.org")
	e.create(t, na)
	if err := e.repo.RetireIdentifiers(t.Context(), na.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := e.repo.Identifiers(t.Context(), na.ID); err != nil || len(got) != 0 {
		t.Errorf("current identifiers after retiring all: %v, %v", got, err)
	}
}

// TestIdentifiers checks that an account's current identifiers come back decrypted, sorted by
// type, without retired ones.
func TestIdentifiers(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount(phone, "ada@example.org")
	e.create(t, na)
	if err := e.repo.RetireIdentifier(t.Context(), na.Identifiers[1].ID); err != nil {
		t.Fatal(err)
	}
	newEmail := account.NewIdentifier{ID: e.ids.New(), Type: "email", Value: "lovelace@example.org", Verified: true}
	if err := e.repo.AddIdentifier(t.Context(), na.ID, newEmail); err != nil {
		t.Fatal(err)
	}
	got, err := e.repo.Identifiers(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []account.Identifier{
		{ID: newEmail.ID, AccountID: na.ID, Type: "email", Value: "lovelace@example.org"},
		{ID: na.Identifiers[0].ID, AccountID: na.ID, Type: "phone", Value: phone},
	}
	if diff := cmp.Diff(want, got, identifierTimes); diff != "" {
		t.Errorf("identifiers (-want +got):\n%s", diff)
	}
	if got[0].VerifiedAt == nil || got[1].VerifiedAt != nil {
		t.Errorf("verified = %v, %v; want the new email only", got[0].VerifiedAt, got[1].VerifiedAt)
	}
}

// TestAddVerifiedIdentifierTaken checks that inserting a verified value another account holds
// verified is IDENTIFIER_TAKEN.
func TestAddVerifiedIdentifierTaken(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	a, b := e.newAccount(phone, ""), e.newAccount("", "")
	e.create(t, a)
	e.create(t, b)
	if err := e.verify(t, a.Identifiers[0].ID); err != nil {
		t.Fatal(err)
	}
	err := e.repo.AddIdentifier(t.Context(), b.ID, account.NewIdentifier{ID: e.ids.New(), Type: "phone", Value: phone, Verified: true})
	checkCode(t, err, domain.CodeIdentifierTaken)
}

// TestSecondCurrentIdentifierIsInternal checks that breaking I-2, a caller's bug, is an internal
// error and not a domain failure.
func TestSecondCurrentIdentifierIsInternal(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount(phone, "")
	e.create(t, na)
	err := e.repo.AddIdentifier(t.Context(), na.ID, account.NewIdentifier{ID: e.ids.New(), Type: "phone", Value: "+447700900999"})
	var de *domain.Error
	if err == nil || errors.As(err, &de) {
		t.Errorf("second current phone: %v, want an internal error", err)
	}
	if err != nil && strings.Contains(err.Error(), "447700900") {
		t.Errorf("error %q holds a value", err)
	}
}

func TestVerifyTwiceNotFound(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount(phone, "")
	e.create(t, na)
	if err := e.verify(t, na.Identifiers[0].ID); err != nil {
		t.Fatal(err)
	}
	checkCode(t, e.verify(t, na.Identifiers[0].ID), domain.CodeNotFound)
	checkCode(t, e.verify(t, e.ids.New()), domain.CodeNotFound)
}
