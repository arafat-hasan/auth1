package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// maxResumeFlows is how many flows a resume sends to, and how many candidates a resume code is
// tried against (TDD-02 §4).
const maxResumeFlows = 3

// The audit actions of resume.
const (
	auditResumeRequest = "registration.resume_request"
	auditResume        = "registration.resume"
)

// RequestResume asks for a resume message for every open registration or invitation holding a
// value (POST /v1/registrations/resume). It formats and logs as its client and type only: never
// the value.
type RequestResume struct {
	ClientID       string
	IdentifierType string
	Value          string // raw
	IP             netip.Addr
}

// String describes the request without its value.
func (c RequestResume) String() string {
	return fmt.Sprintf("RequestResume{client: %s, type: %s}", c.ClientID, c.IdentifierType)
}

// GoString is String.
func (c RequestResume) GoString() string { return c.String() }

// Format writes String for every verb.
func (c RequestResume) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }

// LogValue implements slog.LogValuer with String.
func (c RequestResume) LogValue() slog.Value { return slog.StringValue(c.String()) }

// RequestResume sends a resume message to the value for each open registration or invitation flow
// holding it, at most 3, newest first (TDD-02 §4). It answers nil whatever it finds, so it does not
// tell whether a flow holds the value: an unknown client is the only refusal (VALIDATION_FAILED),
// and a store failure the only other error. L-14 and then L-8 count the request first, and refuse
// it silently. A value that does not normalise, or of a type not configured, sends nothing. In one
// transaction, the flows' accounts are locked by id, then the flows, then their challenges (G-5);
// each flow reuses its open resume challenge on the identifier, or opens one, closing an expired
// one, so a flow has at most one open resume code; then the messages share one check of the send
// limits (Challenges.SendBatch), which takes the address lock last. A refused send leaves the
// challenges open, unsent, as at registration (TDD-02 §3 step 5). Each flow is audited with its
// id, its kind and whether its message went.
func (r *Registration) RequestResume(ctx context.Context, cmd RequestResume) error {
	const op = "request resume"
	if _, ok := r.o.Clients[cmd.ClientID]; !ok {
		return r.fail(ctx, AuditEntry{ActorKind: ActorAnonymous, Action: auditResumeRequest, ClientID: cmd.ClientID, IP: cmd.IP},
			op, invalidField("client_id", domain.FieldUnknown))
	}
	if err := r.d.Limits.CheckIP(ctx, RuleResumeIP, cmd.IP); err != nil {
		return nil //nolint:nilerr // always 202: the per-IP limit refuses silently (L-14)
	}
	if err := r.d.Limits.CheckIP(ctx, RuleSendIP, cmd.IP); err != nil {
		return nil //nolint:nilerr // as L-14 (L-8)
	}
	t, tok := r.d.Registry.Type(cmd.IdentifierType)
	p, pok := r.d.Registry.Policy(cmd.IdentifierType)
	if !tok || !pok {
		return nil
	}
	value, err := r.d.Registry.Normalise(cmd.IdentifierType, cmd.Value)
	if err != nil {
		return nil //nolint:nilerr // always 202 (TDD-02 §4 step 1)
	}
	targets, err := r.d.Flows.Resumable(ctx, cmd.IdentifierType, value, maxResumeFlows)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	fs := make([]flow.Flow, 0, len(targets))
	for _, tg := range targets {
		fs = append(fs, tg.Flow)
	}
	err = r.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		ls, err := r.lockAll(ctx, fs)
		if err != nil {
			return err
		}
		var out []Outgoing
		for _, tg := range targets {
			l, ok := ls[tg.Flow.ID]
			if !ok {
				continue
			}
			id, ok := l.identifier(tg.IdentifierID)
			if !ok || id.Type != cmd.IdentifierType || id.Value != value {
				continue
			}
			ch, err := r.resumeChallenge(ctx, l, id, p.Verify)
			if err != nil {
				return err
			}
			out = append(out, Outgoing{Account: l.account, Challenge: ch, IdentifierID: id.ID})
		}
		sent, err := r.d.Challenges.SendBatch(ctx, cmd.IdentifierType, value, t.Channel(), out)
		if hasCode(err, domain.CodeResendTooSoon, domain.CodeRateLimited) {
			sent, err = 0, nil
		}
		if err != nil {
			return err
		}
		for i, o := range out {
			e := AuditEntry{ActorKind: ActorAnonymous, Action: auditResumeRequest, IP: cmd.IP,
				AccountID: o.Account.ID, Outcome: OutcomeSuccess}
			e.withFlow(ls[o.Challenge.FlowID].flow)
			e.Details["sent"] = i < sent
			if err := r.d.Audit.Write(ctx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// resumeChallenge returns the flow's open resume challenge on id, or opens one by method m,
// closing an open one past its expiry first. The flow and its challenges must be locked.
func (r *Registration) resumeChallenge(ctx context.Context, l locked, id account.Identifier, m flow.Method) (flow.ChallengeRecord, error) {
	for i := len(l.challenges) - 1; i >= 0; i-- {
		c := l.challenges[i]
		if c.Purpose != flow.PurposeResume || c.IdentifierID == nil || *c.IdentifierID != id.ID || c.ClosedAt != nil {
			continue
		}
		if c.End(r.d.Clock.Now()) == flow.EndOpen {
			return c, nil
		}
		if _, err := r.d.Flows.CloseChallenge(ctx, c.ID, false); err != nil {
			return flow.ChallengeRecord{}, err
		}
	}
	return r.d.Challenges.OpenResume(ctx, l.flow.ID, id, m)
}

// lockAll locks the flows fs, as a finder returned them, in the order of G-5: their accounts by
// id, then the flows by id, then each flow's challenges; and reads each account's identifiers. It
// returns the flows still open under their locks, by id: a flow or account gone since it was
// found is left out. It runs inside UnitOfWork.Do.
func (r *Registration) lockAll(ctx context.Context, fs []flow.Flow) (map[uuid.UUID]locked, error) {
	byID := func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }
	var accountIDs []uuid.UUID
	for _, f := range fs {
		accountIDs = append(accountIDs, f.AccountID)
	}
	slices.SortFunc(accountIDs, byID)
	accountIDs = slices.Compact(accountIDs)
	accounts := map[uuid.UUID]account.Account{}
	ids := map[uuid.UUID][]account.Identifier{}
	for _, id := range accountIDs {
		a, err := r.d.Accounts.GetForUpdate(ctx, id)
		if hasCode(err, domain.CodeNotFound) {
			continue
		} else if err != nil {
			return nil, err
		}
		accounts[id] = a
	}
	fs = slices.Clone(fs)
	slices.SortFunc(fs, func(a, b flow.Flow) int { return byID(a.ID, b.ID) })
	out := map[uuid.UUID]locked{}
	for _, f := range fs {
		a, ok := accounts[f.AccountID]
		if !ok {
			continue
		}
		lf, err := r.d.Flows.LockFlow(ctx, f)
		if hasCode(err, domain.CodeChallengeClosed) {
			continue
		} else if err != nil {
			return nil, err
		}
		out[lf.ID] = locked{account: a, flow: lf}
	}
	for _, f := range fs {
		l, ok := out[f.ID]
		if !ok {
			continue
		}
		chs, err := r.d.Flows.LockChallenges(ctx, l.flow.ID)
		if err != nil {
			return nil, err
		}
		if _, read := ids[l.account.ID]; !read {
			if ids[l.account.ID], err = r.d.Accounts.Identifiers(ctx, l.account.ID); err != nil {
				return nil, err
			}
		}
		l.challenges, l.ids = chs, ids[l.account.ID]
		out[f.ID] = l
	}
	return out, nil
}

// VerifyResume is a resume code with the identifier it was sent to, and no flow id
// (POST /v1/registrations/resume/verify): the code picks the flow. It formats and logs as its type
// only: never the value or the code.
type VerifyResume struct {
	IdentifierType string
	Value          string // raw
	Code           flow.Secret
	IP             netip.Addr
}

// String describes the request without its value and code.
func (c VerifyResume) String() string {
	return fmt.Sprintf("VerifyResume{type: %s}", c.IdentifierType)
}

// GoString is String.
func (c VerifyResume) GoString() string { return c.String() }

// Format writes String for every verb.
func (c VerifyResume) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }

// LogValue implements slog.LogValuer with String.
func (c VerifyResume) LogValue() slog.Value { return slog.StringValue(c.String()) }

// FlowResumed is a resumed registration or invitation: the flow, its new handle (returned once,
// stored as its SHA-256), the types it still needs verified and when it expires. Accepted is set
// for an invitation only: whether it was accepted already.
type FlowResumed struct {
	FlowID       uuid.UUID
	Kind         flow.Kind
	Accepted     *bool
	Handle       flow.Secret
	PendingTypes []string
	ExpiresAt    time.Time
}

// VerifyResume resumes the flow whose resume code to the value this is (TDD-02 §4). L-12 counts
// the attempt first. The candidates are the open resume challenges by code to the value whose
// flows are open, at most 3, newest first, found without locks; the code's MAC is computed for 3,
// padded with fresh ids, so the work does not tell how many there are. In one transaction their
// accounts are locked by id, then the flows, then their challenges (G-5), and each candidate is
// checked again under the locks. The try counts on every candidate (I-4), so several open flows
// give no more guesses than one; a candidate whose tries run out closes, erasing its secret (I-5).
// A candidate whose account has reached L-11 is not compared. The newest match is consumed: its
// identifier is verified if it was not (IDENTIFIER_TAKEN when another account verified the value
// first, the challenge staying consumed), and the flow's handle is replaced, so the old one finds
// nothing (I-20); the other candidates stay open. With no match, the failure counts against each
// candidate's account (L-11), and the answer is CODE_INVALID without attempts left, whether there
// were candidates, open or exhausted, or none (I-20). Counted tries commit whatever the answer.
func (r *Registration) VerifyResume(ctx context.Context, cmd VerifyResume) (FlowResumed, error) {
	const op = "verify resume code"
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditResume, IP: cmd.IP}
	if err := r.d.Limits.CheckIP(ctx, RuleVerifyIP, cmd.IP); err != nil {
		return FlowResumed{}, err
	}
	var cands []ResumeCandidate
	if value, err := r.d.Registry.Normalise(cmd.IdentifierType, cmd.Value); err == nil {
		if cands, err = r.d.Flows.ResumeCandidates(ctx, cmd.IdentifierType, value, maxResumeFlows); err != nil {
			return FlowResumed{}, fmt.Errorf("%s: %w", op, err)
		}
	}
	matches := make([]bool, len(cands))
	for i := range maxResumeFlows {
		id, want := r.d.IDs.New(), []byte(nil)
		if i < len(cands) {
			id, want = cands[i].Challenge.ID, cands[i].Challenge.SecretMAC
		}
		eq := subtle.ConstantTimeCompare(r.d.MAC.OTP(id, cmd.Code), want) == 1
		if i < len(cands) {
			matches[i] = eq
		}
	}
	fs := make([]flow.Flow, 0, len(cands))
	for _, c := range cands {
		fs = append(fs, c.Flow)
	}
	var (
		answer  error
		out     FlowResumed
		matched flow.Flow
	)
	err := r.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		ls, err := r.lockAll(ctx, fs)
		if err != nil {
			return err
		}
		now := r.d.Clock.Now()
		pick := -1
		for i, c := range cands {
			l, ok := ls[c.Flow.ID]
			if !ok {
				continue
			}
			ch, ok := l.challenge(c.Challenge.ID)
			if !ok || ch.ClosedAt != nil || ch.End(now) != flow.EndOpen {
				continue
			}
			attempts, ok, err := r.d.Flows.Attempt(ctx, ch.ID)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if pick < 0 && matches[i] && !r.o.FactorLimit.Reached(l.account, now) {
				pick = i
				continue
			}
			if attempts >= ch.MaxAttempts {
				if _, err := r.d.Flows.CloseChallenge(ctx, ch.ID, false); err != nil {
					return err
				}
			}
		}
		if pick < 0 {
			return r.failFactors(ctx, ls, &answer)
		}
		l := ls[cands[pick].Flow.ID]
		ch, _ := l.challenge(cands[pick].Challenge.ID)
		var id account.Identifier
		ok := ch.IdentifierID != nil
		if ok {
			id, ok = l.identifier(*ch.IdentifierID)
		}
		if !ok {
			return r.failFactors(ctx, ls, &answer)
		}
		matched = l.flow
		out, answer, err = r.resumeFlow(ctx, l, id, ch)
		if hasCode(answer, domain.CodeChallengeClosed) {
			answer = codeInvalid()
		}
		if err != nil || answer != nil {
			return err
		}
		e := entry
		e.withFlow(l.flow)
		return r.auditSuccess(ctx, e, l.account.ID)
	})
	if err != nil {
		return FlowResumed{}, fmt.Errorf("%s: %w", op, err)
	}
	if answer == nil {
		return out, nil
	}
	if hasCode(answer, domain.CodeCodeInvalid) {
		return FlowResumed{}, r.failCandidates(ctx, entry, op, cands, answer)
	}
	entry.AccountID = matched.AccountID
	entry.withFlow(matched)
	return FlowResumed{}, r.fail(ctx, entry, op, answer)
}

// failFactors counts a second-factor failure against each locked candidate's account once (L-11)
// and sets answer to CODE_INVALID.
func (r *Registration) failFactors(ctx context.Context, ls map[uuid.UUID]locked, answer *error) error {
	counted := map[uuid.UUID]bool{}
	for _, l := range ls {
		if counted[l.account.ID] {
			continue
		}
		counted[l.account.ID] = true
		if _, err := r.d.Accounts.FailFactor(ctx, l.account.ID, r.o.FactorLimit.Window); err != nil {
			return err
		}
	}
	*answer = codeInvalid()
	return nil
}

// failCandidates audits a resume code that resumed nothing: once per candidate, with its account,
// flow id and kind, or once without when there were none; and returns answer.
func (r *Registration) failCandidates(ctx context.Context, e AuditEntry, op string, cands []ResumeCandidate, answer error) error {
	if len(cands) == 0 {
		return r.fail(ctx, e, op, answer)
	}
	for _, c := range cands {
		ce := e
		ce.Details = nil
		ce.AccountID = c.Flow.AccountID
		ce.withFlow(c.Flow)
		_ = r.fail(ctx, ce, op, answer)
	}
	return answer
}

// resumeFlow resumes the locked flow l by its resume challenge ch on the identifier id (TDD-02 §4):
// it consumes ch, verifies id if it is not, dropping its type from the pending types and emitting
// account.identifier_verified, and replaces the flow's handle. Otherwise answer is
// CHALLENGE_CLOSED when ch has closed already or id is no longer current, or IDENTIFIER_TAKEN when
// another account holds the value verified; both commit, ch staying consumed for the latter, and
// the handle is not replaced. err is a failure of the stores.
func (r *Registration) resumeFlow(ctx context.Context, l locked, id account.Identifier, ch flow.ChallengeRecord) (FlowResumed, error, error) {
	ok, err := r.d.Flows.CloseChallenge(ctx, ch.ID, true)
	if err != nil {
		return FlowResumed{}, nil, err
	}
	if !ok {
		return FlowResumed{}, challengeClosed(), nil
	}
	state := l.flow.State
	if id.VerifiedAt == nil {
		switch err := r.d.Accounts.VerifyIdentifier(ctx, id.ID); {
		case hasCode(err, domain.CodeIdentifierTaken):
			return FlowResumed{}, err, nil
		case hasCode(err, domain.CodeNotFound):
			return FlowResumed{}, challengeClosed(), nil
		case err != nil:
			return FlowResumed{}, nil, err
		}
		state = withVerified(state, id.Type)
		if err := r.d.Flows.Update(ctx, l.flow.ID, state, l.flow.Attempts); err != nil {
			return FlowResumed{}, nil, err
		}
		if err := r.d.Outbox.Event(ctx, EventIdentifierVerified, l.account.ID, IdentifierVerified{
			AccountID: l.account.ID, IdentifierID: id.ID, IdentifierType: id.Type, Actor: AccountActor(l.account.ID),
		}); err != nil {
			return FlowResumed{}, nil, err
		}
	}
	handle, err := flow.NewHandle(r.d.Rand)
	if err != nil {
		return FlowResumed{}, nil, err
	}
	h := sha256.Sum256(handle)
	if err := r.d.Flows.ReplaceHandle(ctx, l.flow.ID, h[:]); err != nil {
		return FlowResumed{}, nil, err
	}
	out := FlowResumed{FlowID: l.flow.ID, Kind: l.flow.Kind, Handle: handle, PendingTypes: pendingTypes(state),
		ExpiresAt: l.flow.ExpiresAt}
	if st, ok := state.(flow.InvitationState); ok {
		accepted := st.Accepted
		out.Accepted = &accepted
	}
	return out, nil, nil
}

// codeInvalid is the answer to every resume code that resumes nothing (I-20): no attempts left
// are told, as they would tell whether a flow holds the value.
func codeInvalid() error {
	return &domain.Error{Code: domain.CodeCodeInvalid, Detail: "the code is wrong"}
}
