package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/message"
)

// ChallengeRules are the configured limits of the challenges a flow opens and sends (TDD-02 §2,
// TDD-07 §5): the OTP's length and tries, how long a code and a link live, the per-address send
// limits (L-7): at most MaxShort sends in Windows.Short and MaxLong in Windows.Long, and the pause
// after a challenge's attempts run out (L-9). Windows.Short is also the earliest resend of one
// challenge (otp.resend_after).
type ChallengeRules struct {
	OTPLength   int
	MaxAttempts int
	OTPTTL      time.Duration
	LinkTTL     time.Duration
	Windows     SendWindows
	MaxShort    int
	MaxLong     int
	Cooldown    time.Duration
}

// check returns what is wrong with r, or nil.
func (r ChallengeRules) check() error {
	var errs []error
	if r.OTPLength < flow.MinOTPLength {
		errs = append(errs, fmt.Errorf("OTP length %d is below %d", r.OTPLength, flow.MinOTPLength))
	}
	if r.MaxAttempts < 1 {
		errs = append(errs, fmt.Errorf("max attempts %d is below 1", r.MaxAttempts))
	}
	if r.OTPTTL <= 0 || r.LinkTTL <= 0 {
		errs = append(errs, errors.New("code and link lifetimes must be above 0"))
	}
	if r.Windows.Short <= 0 || r.Windows.Short > r.Windows.Long {
		errs = append(errs, errors.New("the short send window must be above 0 and not longer than the long one"))
	}
	if r.MaxShort < 1 || r.MaxLong < r.MaxShort {
		errs = append(errs, fmt.Errorf("sends per window %d / %d: want 1 or more, the long at least the short", r.MaxShort, r.MaxLong))
	}
	if r.Cooldown < 0 {
		errs = append(errs, errors.New("the cooldown must not be negative"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("challenge rules: %w", err)
	}
	return nil
}

// Challenges opens and sends the challenges of a flow (TDD-02 §2.2–§2.4), shared by the flow
// families. Every method runs inside the caller's UnitOfWork.Do, with the flow locked or opened in
// it (OpenVerification) and the challenge locked or opened in it (Send), in the order of G-5.
type Challenges struct {
	flows Flows
	out   OutboxWriter
	msgs  *Messages
	mac   MAC
	ids   IDGenerator
	clock Clock
	rand  io.Reader
	rules ChallengeRules
}

// NewChallenges returns the component, or an error when rules are not usable. rand is
// crypto/rand.Reader outside tests.
func NewChallenges(flows Flows, out OutboxWriter, msgs *Messages, mac MAC, ids IDGenerator, clock Clock,
	rand io.Reader, rules ChallengeRules,
) (*Challenges, error) {
	if err := rules.check(); err != nil {
		return nil, err
	}
	return &Challenges{flows: flows, out: out, msgs: msgs, mac: mac, ids: ids, clock: clock, rand: rand, rules: rules}, nil
}

// ResendRules returns the per-challenge resend rules (TDD-02 §2.4): the short send window as the
// earliest resend, and the cooldown.
func (c *Challenges) ResendRules() flow.ResendRules {
	return flow.ResendRules{ResendAfter: c.rules.Windows.Short, Cooldown: c.rules.Cooldown}
}

// OpenVerification opens a verify_identifier challenge on the identifier id in the flow, sent by
// method m: a fresh OTP for a code method, stored as its MAC bound to the challenge, or a fresh
// link token for email_link, stored as its SHA-256. The flow must be locked. The record returned
// is the challenge as opened, never sent.
func (c *Challenges) OpenVerification(ctx context.Context, flowID uuid.UUID, id account.Identifier, m flow.Method) (flow.ChallengeRecord, error) {
	return c.open(ctx, flow.PurposeVerifyIdentifier, flowID, id, m)
}

// OpenResume is OpenVerification for a resume challenge (TDD-02 §4).
func (c *Challenges) OpenResume(ctx context.Context, flowID uuid.UUID, id account.Identifier, m flow.Method) (flow.ChallengeRecord, error) {
	return c.open(ctx, flow.PurposeResume, flowID, id, m)
}

// open opens a challenge of purpose p on the identifier id in the flow, by method m.
func (c *Challenges) open(ctx context.Context, p flow.Purpose, flowID uuid.UUID, id account.Identifier, m flow.Method) (flow.ChallengeRecord, error) {
	chID := c.ids.New()
	var (
		secret flow.Secret
		mac    []byte
		ttl    time.Duration
		err    error
	)
	if m == flow.MethodEmailLink {
		if secret, err = flow.NewLinkToken(c.rand); err != nil {
			return flow.ChallengeRecord{}, fmt.Errorf("open challenge: %w", err)
		}
		h := sha256.Sum256(secret)
		mac, ttl = h[:], c.rules.LinkTTL
	} else {
		if secret, err = flow.NewOTP(c.rand, c.rules.OTPLength); err != nil {
			return flow.ChallengeRecord{}, fmt.Errorf("open challenge: %w", err)
		}
		mac, ttl = c.mac.OTP(chID, secret), c.rules.OTPTTL
	}
	idID := id.ID
	nc := flow.NewChallengeRecord{
		ID: chID, FlowID: flowID, Purpose: p, Method: m, IdentifierID: &idID,
		TargetType: id.Type, TargetValue: id.Value, SecretMAC: mac, Secret: secret,
		MaxAttempts: c.rules.MaxAttempts, ExpiresAt: c.clock.Now().Add(ttl),
	}
	if err := c.flows.OpenChallenge(ctx, nc); err != nil {
		return flow.ChallengeRecord{}, fmt.Errorf("open challenge: %w", err)
	}
	return flow.ChallengeRecord{
		ID: chID, FlowID: flowID, Purpose: nc.Purpose, Method: m, IdentifierID: &idID, SecretMAC: mac,
		Challenge: flow.Challenge{MaxAttempts: nc.MaxAttempts, ExpiresAt: nc.ExpiresAt},
	}, nil
}

// Send sends the open verify_identifier or resume challenge ch to the identifier id of account a,
// by channel, the identifier type's (TDD-02 §2.4): it is SendBatch of the one challenge.
func (c *Challenges) Send(ctx context.Context, a account.Account, ch flow.ChallengeRecord, id account.Identifier, channel message.Channel) error {
	_, err := c.SendBatch(ctx, id.Type, id.Value, channel, []Outgoing{{Account: a, Challenge: ch, IdentifierID: id.ID}})
	return err
}

// Outgoing is one message of a batch to an address: the open challenge, the account it is for and
// that account's identifier holding the address, the recipient.
type Outgoing struct {
	Account      account.Account
	Challenge    flow.ChallengeRecord
	IdentifierID uuid.UUID
}

// SendBatch sends the open challenges of out, each to its account's identifier holding the address
// value of type idType, by channel (TDD-02 §2.4, §4): it checks the per-address limits once for the
// batch, then counts each send and writes its delivery request, in order, while the long window
// has room. It returns how many, from the first, it sent. Under the address lock SendCounts takes,
// it refuses the whole batch with RESEND_TOO_SOON while a challenge to the address, of any account
// or flow, closed exhausted less than the cooldown ago (L-9), with the rest of the cooldown as the
// retry time; then with RESEND_TOO_SOON, the short window as the retry time, when the short window
// is full, and RATE_LIMITED, the long one, when the long window is (L-7, I-21, TDD-07 §5). A
// refusal counts and writes nothing. An empty batch checks the limits as any other, so it takes
// the same time, and sends nothing. The challenges must be locked or opened in the transaction.
func (c *Challenges) SendBatch(ctx context.Context, idType, value string, channel message.Channel, out []Outgoing) (int, error) {
	counts, err := c.flows.SendCounts(ctx, idType, value, c.rules.Windows)
	if err != nil {
		return 0, fmt.Errorf("send challenge: %w", err)
	}
	if c.rules.Cooldown > 0 {
		closed, err := c.flows.ExhaustedSince(ctx, idType, value, c.rules.Cooldown)
		if err != nil {
			return 0, fmt.Errorf("send challenge: %w", err)
		}
		if closed != nil {
			if wait := closed.Add(c.rules.Cooldown).Sub(c.clock.Now()); wait > 0 && len(out) > 0 {
				return 0, &domain.Error{Code: domain.CodeResendTooSoon, Detail: "wait before asking for another code",
					RetryAfter: (wait + time.Second - 1).Truncate(time.Second)}
			}
		}
	}
	switch {
	case len(out) == 0:
		return 0, nil
	case counts.Short >= c.rules.MaxShort:
		return 0, &domain.Error{Code: domain.CodeResendTooSoon, Detail: "wait before asking for another code",
			RetryAfter: c.rules.Windows.Short}
	case counts.Long >= c.rules.MaxLong:
		return 0, &domain.Error{Code: domain.CodeRateLimited, Detail: "Too many requests; try again later.",
			RetryAfter: c.rules.Windows.Long}
	}
	n := min(len(out), c.rules.MaxLong-counts.Long)
	for _, o := range out[:n] {
		if err := c.send(ctx, o, channel); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// send counts one send of o's challenge and writes its delivery request.
func (c *Challenges) send(ctx context.Context, o Outgoing, channel message.Channel) error {
	ch := o.Challenge
	sends, err := c.flows.RecordSend(ctx, ch.ID)
	if err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}
	mc := Challenge{ID: ch.ID, Send: sends, ExpiresAt: ch.ExpiresAt}
	to := ToIdentifier(o.IdentifierID, channel)
	var req DeliveryRequest
	switch {
	case ch.Purpose == flow.PurposeResume && ch.Method == flow.MethodEmailLink:
		req, err = c.msgs.ChallengeLink(message.RegistrationResume, mc, o.Account.Locale, to)
	case ch.Purpose == flow.PurposeResume:
		req, err = c.msgs.ChallengeCode(message.RegistrationResume, mc, o.Account.Locale, to)
	case ch.Method == flow.MethodEmailLink:
		req, err = c.msgs.ChallengeLink(message.EmailVerificationLink, mc, o.Account.Locale, to)
	case ch.Method == flow.MethodEmailCode:
		req, err = c.msgs.ChallengeCode(message.EmailVerificationCode, mc, o.Account.Locale, to)
	case ch.Method == flow.MethodSMSOTP:
		req, err = c.msgs.ChallengeCode(message.PhoneVerificationCode, mc, o.Account.Locale, to)
	default:
		err = fmt.Errorf("%w: no message for a %s challenge by %q", ErrMessageInvalid, ch.Purpose, ch.Method)
	}
	if err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}
	if err := c.out.Delivery(ctx, o.Account.ID, req); err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}
	return nil
}
