package postgres_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// codes returns n recovery codes with distinct MACs.
func (e *accountsEnv) codes(n int, prefix string) []account.RecoveryCode {
	out := make([]account.RecoveryCode, n)
	for i := range out {
		out[i] = account.RecoveryCode{ID: e.ids.New(), MAC: []byte(prefix + string(rune('a'+i)))}
	}
	return out
}

// replaceCodes replaces the account's batch in its own transaction.
func (e *accountsEnv) replaceCodes(t *testing.T, accountID uuid.UUID, codes []account.RecoveryCode) {
	t.Helper()
	e.do(t, func(ctx context.Context) error {
		return e.repo.ReplaceRecoveryCodes(ctx, accountID, e.ids.New(), codes)
	})
}

// unused returns the account's unused recovery codes, failing the test on an error.
func (e *accountsEnv) unused(t *testing.T, accountID uuid.UUID) int {
	t.Helper()
	n, err := e.repo.UnusedRecoveryCodes(t.Context(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestUseRecoveryCodeOnce checks I-18: a recovery code is accepted at most once.
func TestUseRecoveryCodeOnce(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	codes := e.codes(3, "mac-")
	e.replaceCodes(t, na.ID, codes)

	for i, want := range []bool{true, false} {
		got, err := e.repo.UseRecoveryCode(t.Context(), na.ID, codes[1].MAC)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("use %d = %t, want %t", i+1, got, want)
		}
	}
	if n := e.unused(t, na.ID); n != 2 {
		t.Errorf("unused = %d, want 2", n)
	}
	if got, err := e.repo.UseRecoveryCode(t.Context(), na.ID, []byte("unknown")); err != nil || got {
		t.Errorf("unknown code = %t, %v; want refused", got, err)
	}
}

func TestUseRecoveryCodeOtherAccount(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	a, b := e.newAccount("", "ada@example.org"), e.newAccount("", "")
	e.create(t, a)
	e.create(t, b)
	codes := e.codes(1, "mac-")
	e.replaceCodes(t, a.ID, codes)
	if got, err := e.repo.UseRecoveryCode(t.Context(), b.ID, codes[0].MAC); err != nil || got {
		t.Errorf("another account's code = %t, %v; want refused", got, err)
	}
	if n := e.unused(t, a.ID); n != 1 {
		t.Errorf("unused = %d, want 1", n)
	}
}

// TestReplaceRecoveryCodesDropsOldBatch checks that a regeneration replaces the batch, used codes
// included (TDD-03 §5.3, TDD-01 §5), and that an old code no longer works.
func TestReplaceRecoveryCodesDropsOldBatch(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	old := e.codes(3, "old-")
	e.replaceCodes(t, na.ID, old)
	if _, err := e.repo.UseRecoveryCode(t.Context(), na.ID, old[0].MAC); err != nil {
		t.Fatal(err)
	}
	// The new batch reuses a MAC of the old one, which recovery_codes_mac allows only once the
	// old rows are gone.
	fresh := append(e.codes(2, "new-"), account.RecoveryCode{ID: e.ids.New(), MAC: old[0].MAC})
	e.replaceCodes(t, na.ID, fresh)

	var rows int
	if err := e.su.QueryRowContext(t.Context(), "SELECT count(*) FROM recovery_codes WHERE account_id = ?", na.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 3 || e.unused(t, na.ID) != 3 {
		t.Errorf("rows = %d, unused = %d; want 3 and 3", rows, e.unused(t, na.ID))
	}
	if got, err := e.repo.UseRecoveryCode(t.Context(), na.ID, old[1].MAC); err != nil || got {
		t.Errorf("old code = %t, %v; want refused", got, err)
	}
}

func TestDeleteRecoveryCodes(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	e.replaceCodes(t, na.ID, e.codes(2, "mac-"))
	if err := e.repo.DeleteRecoveryCodes(t.Context(), na.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.unused(t, na.ID); n != 0 {
		t.Errorf("unused after delete = %d", n)
	}
}

func TestReplaceRecoveryCodesOutsideTransaction(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	if err := e.repo.ReplaceRecoveryCodes(t.Context(), na.ID, e.ids.New(), e.codes(1, "m")); err == nil {
		t.Error("replacing outside a transaction succeeded")
	}
}
