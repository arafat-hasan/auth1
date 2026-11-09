package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/domain/session"
)

// ErrMFANotPassed is Complete's refusal of a sign-in whose amr lacks mfa, for an account with a
// confirmed TOTP factor or on a client with mfa: required (I-16). The caller decided the second
// step wrongly: it is a fault, never an answer.
var ErrMFANotPassed = errors.New("sign-in: the second factor is required (I-16)")

// ErrCompletionMismatch is Complete's refusal of a flow that is not a sign_in flow of the
// completion's account and client: a fault in the caller, never an answer.
var ErrCompletionMismatch = errors.New("sign-in: the flow is not this account's sign-in on this client")

// Completion is a sign-in to complete (TDD-02 §5.3): the account, locked by the caller in this
// transaction; the client; the sign_in flow, locked, or nil when there was no second step; the
// factors passed; the device of a valid device cookie, presented now or kept in the flow, or nil.
type Completion struct {
	Account   account.Account
	ClientID  string
	Flow      *flow.Flow
	First     flow.FirstFactor
	Second    flow.SecondFactor
	DeviceID  *uuid.UUID
	UserAgent string
	IP        netip.Addr
}

// SignedIn is a completed sign-in: the token response (TDD-04 §1) and what the HTTP layer sets
// as cookies. Refresh goes in the body for a native client, else in the refresh cookie, whose
// Max-Age is RefreshMaxAge. DeviceCookie is a new device cookie's value, empty when the request
// presented a valid one or the client is native. It formats and logs without its tokens.
type SignedIn struct {
	Access        AccessToken
	ExpiresIn     time.Duration
	SessionID     uuid.UUID
	Status        account.Status
	StatusUntil   *time.Time
	Refresh       session.Secret
	RefreshMaxAge time.Duration
	BodyTransport bool
	DeviceCookie  string
}

// LogValue implements slog.LogValuer with String, so no handler encodes the fields.
func (s SignedIn) LogValue() slog.Value { return slog.StringValue(s.String()) }

// String describes the sign-in without its tokens or cookie.
func (s SignedIn) String() string {
	return fmt.Sprintf("app.SignedIn{SessionID: %s, Status: %s, Restricted: %t}", s.SessionID, s.Status, s.Access.Restricted)
}

// GoString is String.
func (s SignedIn) GoString() string { return s.String() }

// Format writes String for every verb.
func (s SignedIn) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// Complete completes a sign-in (TDD-02 §5.3) inside the caller's transaction, under the caller's
// account lock and, when there is a flow, its flow lock. It refuses a flow that is not the
// account's sign_in on the client (ErrCompletionMismatch), decides SDD §8.1 again on the locked
// account and re-reads its roles and TOTP factor, refuses a session without mfa where I-16 needs
// one, completes the flow, creates the session (full or restricted at each token, from the status)
// with its first refresh token, issues the access token, audits sign_in and writes the optional
// new-sign-in notice. A refusal is a *domain.Error. WP-53 and WP-54 call it after the second
// factor.
func (s *SignIn) Complete(ctx context.Context, c Completion) (SignedIn, error) {
	cl, ok := s.o.Clients[c.ClientID]
	if !ok {
		return SignedIn{}, fmt.Errorf("complete sign-in: client %q is not configured", c.ClientID)
	}
	a := c.Account
	if f := c.Flow; f != nil && (f.Kind != flow.KindSignIn || f.AccountID != a.ID || f.ClientID != cl.ID) {
		return SignedIn{}, ErrCompletionMismatch
	}
	if answer, err := s.decide(ctx, a, cl); err != nil || answer != nil {
		if err == nil {
			err = answer
		}
		return SignedIn{}, err
	}
	amr, err := flow.AMR(c.First, c.Second)
	if err != nil {
		return SignedIn{}, err
	}
	totp, err := s.confirmedTOTP(ctx, a.ID)
	if err != nil {
		return SignedIn{}, err
	}
	if (totp || cl.MFARequired) && !slices.Contains(amr, "mfa") {
		return SignedIn{}, ErrMFANotPassed
	}
	roles, err := s.roleNames(ctx, a.ID)
	if err != nil {
		return SignedIn{}, err
	}
	if c.Flow != nil {
		if err := s.d.Flows.Complete(ctx, c.Flow.ID); err != nil {
			return SignedIn{}, err
		}
	}

	out := SignedIn{SessionID: s.d.IDs.New(), Status: a.Status, StatusUntil: a.StatusUntil,
		RefreshMaxAge: s.o.AbsoluteTTL, BodyTransport: cl.BodyTransport}
	device := c.DeviceID
	if cl.BodyTransport {
		device = nil
	} else if device == nil {
		var id uuid.UUID
		out.DeviceCookie, id = s.d.Devices.Issue()
		device = &id
	}
	if out.Refresh, err = refreshToken(s.d.Rand); err != nil {
		return SignedIn{}, err
	}
	ua := userAgent(c.UserAgent)
	now := s.d.Clock.Now()
	h := sha256.Sum256(out.Refresh)
	if err := s.d.Sessions.Create(ctx, session.NewSession{
		ID: out.SessionID, AccountID: a.ID, ClientID: cl.ID, AMR: amr, AuthTime: now, DeviceID: device,
		UserAgent: ua, IdleTTL: s.o.IdleTTL, AbsoluteTTL: s.o.AbsoluteTTL,
	}, h[:]); err != nil {
		return SignedIn{}, err
	}
	if out.Access, err = s.d.Access.Issue(AccessGrant{
		SessionID: out.SessionID, ClientID: cl.ID, AMR: amr, AuthTime: now, AccountID: a.ID, Status: a.Status,
		Roles: roles, Audience: cl.Audience, Allowed: cl.AllowedRoles,
	}); err != nil {
		return SignedIn{}, err
	}
	out.ExpiresIn = out.Access.ExpiresAt.Sub(now)

	details := map[string]any{"session_id": out.SessionID.String(), "amr": amr, "restricted": out.Access.Restricted}
	if c.Flow != nil {
		details["flow_id"], details["kind"] = c.Flow.ID.String(), string(c.Flow.Kind)
	}
	if err := s.d.Audit.Write(ctx, AuditEntry{AccountID: a.ID, ActorKind: ActorAccount, ActorID: a.ID.String(),
		Action: auditSignIn, Outcome: OutcomeSuccess, ClientID: cl.ID, IP: c.IP, UserAgent: ua, Details: details}); err != nil {
		return SignedIn{}, err
	}
	if _, err := s.d.Notices.Send(ctx, a, Notice{Purpose: message.NoticeNewSignIn, Variables: map[string]any{
		"client_id": cl.ID, "user_agent": ua, "occurred_at": now.Format(time.RFC3339),
	}}); err != nil {
		return SignedIn{}, err
	}
	return out, nil
}

// refreshToken draws a refresh token: 32 random bytes, base64url without padding.
func refreshToken(r io.Reader) (session.Secret, error) {
	var b [32]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, fmt.Errorf("refresh token: read random: %w", err)
	}
	t := make(session.Secret, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(t, b[:])
	return t, nil
}
