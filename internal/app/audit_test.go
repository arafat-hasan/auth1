package app_test

import (
	"errors"
	"testing"

	"github.com/arafat-hasan/auth1/internal/app"
)

func TestActorKindValid(t *testing.T) {
	t.Parallel()
	for _, k := range []app.ActorKind{app.ActorAccount, app.ActorService, app.ActorOperator, app.ActorSystem, app.ActorAnonymous} {
		if !k.Valid() {
			t.Errorf("%q is not valid", k)
		}
	}
	for _, k := range []app.ActorKind{"", "servce", "Account"} {
		if k.Valid() {
			t.Errorf("%q is valid", k)
		}
	}
}

func TestOutcomeValid(t *testing.T) {
	t.Parallel()
	for _, o := range []app.Outcome{app.OutcomeSuccess, app.OutcomeFailure} {
		if !o.Valid() {
			t.Errorf("%q is not valid", o)
		}
	}
	for _, o := range []app.Outcome{"", "sucess", "denied"} {
		if o.Valid() {
			t.Errorf("%q is valid", o)
		}
	}
}

func TestAuditEntryCheck(t *testing.T) {
	t.Parallel()
	ok := app.AuditEntry{ActorKind: app.ActorSystem, Action: "x", Outcome: app.OutcomeSuccess}
	if err := ok.Check(); err != nil {
		t.Errorf("Check(valid) = %v", err)
	}
	for name, mutate := range map[string]func(*app.AuditEntry){
		"actor kind": func(e *app.AuditEntry) { e.ActorKind = "servce" },
		"outcome":    func(e *app.AuditEntry) { e.Outcome = "" },
		"action":     func(e *app.AuditEntry) { e.Action = "" },
	} {
		e := ok
		mutate(&e)
		if err := e.Check(); !errors.Is(err, app.ErrAuditEntryInvalid) {
			t.Errorf("%s: Check = %v, want ErrAuditEntryInvalid", name, err)
		}
	}
}
