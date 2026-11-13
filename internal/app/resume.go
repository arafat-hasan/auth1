package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"

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
