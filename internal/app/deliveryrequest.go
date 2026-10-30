package app

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/message"
)

// ErrMessageInvalid is returned by the request builders for a request they will not build: a
// caller's bug. The error names the purpose and the variable, never a value.
var ErrMessageInvalid = errors.New("delivery request invalid")

// refPrefix starts every reference (TDD-06 §5).
const refPrefix = "auth1:"

// IdentifierRef returns the reference to an identifier's value: auth1:identifier:<id>.
func IdentifierRef(id uuid.UUID) string { return refPrefix + "identifier:" + id.String() }

// ChallengeTargetRef returns the reference to a challenge's target value, an address under
// change: auth1:challenge-target:<challenge id>.
func ChallengeTargetRef(challengeID uuid.UUID) string {
	return refPrefix + "challenge-target:" + challengeID.String()
}

// SecretRef returns the reference to a challenge's OTP: auth1:secret:<challenge id>.
func SecretRef(challengeID uuid.UUID) string { return refPrefix + "secret:" + challengeID.String() }

// LinkRef returns the reference to a challenge's link with its token: auth1:link:<challenge id>.
func LinkRef(challengeID uuid.UUID) string { return refPrefix + "link:" + challengeID.String() }

// Recipient is who a message goes to: the reference of the address, and the channel that reaches
// it (the identifier type's). An empty Channel takes the purpose's.
type Recipient struct {
	Ref     string
	Channel message.Channel
}

// ToIdentifier returns the recipient that is the identifier id, reached by ch.
func ToIdentifier(id uuid.UUID, ch message.Channel) Recipient {
	return Recipient{Ref: IdentifierRef(id), Channel: ch}
}

// ToChallengeTarget returns the recipient that is the challenge's target value, reached by ch.
func ToChallengeTarget(challengeID uuid.UUID, ch message.Channel) Recipient {
	return Recipient{Ref: ChallengeTargetRef(challengeID), Channel: ch}
}

// Challenge is what a challenge message needs of its challenge: the id, the send number (1 for
// the first send) and the expiry.
type Challenge struct {
	ID        uuid.UUID
	Send      int
	ExpiresAt time.Time
}

// Messages builds delivery requests, one builder per shape (TDD-06 §5): a challenge code, a
// challenge link and a notice. The type comes from the purpose's entry in Types.
type Messages struct {
	types *message.Types
}

// NewMessages returns the builders with the message types of types.
func NewMessages(types *message.Types) *Messages { return &Messages{types: types} }

// ChallengeCode builds the message that carries challenge c's OTP for purpose p, as the code
// variable. Its request_id is "<challenge id>:<send number>" and its deadline the expiry.
func (m *Messages) ChallengeCode(p message.Purpose, c Challenge, locale string, to Recipient) (DeliveryRequest, error) {
	return m.challenge(p, message.Code, "code", SecretRef(c.ID), c, locale, to)
}

// ChallengeLink builds the message that carries challenge c's link for purpose p, as the link
// variable; a link goes only by email. Its request_id is "<challenge id>:<send number>" and its deadline the expiry.
func (m *Messages) ChallengeLink(p message.Purpose, c Challenge, locale string, to Recipient) (DeliveryRequest, error) {
	return m.challenge(p, message.Link, "link", LinkRef(c.ID), c, locale, to)
}

func (m *Messages) challenge(p message.Purpose, secret message.Secret, name, ref string, c Challenge,
	locale string, to Recipient,
) (DeliveryRequest, error) {
	spec, ch, err := m.check(p, locale, to, false)
	if err != nil {
		return DeliveryRequest{}, err
	}
	if spec.Secret != secret && spec.Secret != message.CodeOrLink {
		return DeliveryRequest{}, invalid(p, "does not carry a %s", name)
	}
	if secret == message.Link && ch != message.Email {
		return DeliveryRequest{}, invalid(p, "sends a link by email, not %s", ch)
	}
	if c.ID == uuid.Nil || c.Send < 1 || c.ExpiresAt.IsZero() {
		return DeliveryRequest{}, invalid(p, "needs a challenge id, a send number from 1 and an expiry")
	}
	deadline := c.ExpiresAt.UTC()
	return DeliveryRequest{
		RequestID: c.ID.String() + ":" + strconv.Itoa(c.Send),
		Type:      m.types.Type(p),
		Channel:   string(ch),
		Locale:    locale,
		Recipient: to.Ref,
		Variables: map[string]any{name: ref},
		Deadline:  &deadline,
	}, nil
}

// Notice builds the security notice p with plain variables vars: strings or integers, exactly the
// ones the purpose lists, none of them a reference or a secret. The request_id is left empty, for
// the outbox to make it the row's id, and there is no deadline. It goes by the recipient's channel
// when given, so the purpose's email channel is not enforced here: with no email type, notices go
// to another identifier (TDD-06 §7), and Notices decides when that is allowed.
func (m *Messages) Notice(p message.Purpose, locale string, to Recipient, vars map[string]any) (DeliveryRequest, error) {
	spec, ch, err := m.check(p, locale, to, true)
	if err != nil {
		return DeliveryRequest{}, err
	}
	if spec.Secret != message.NoSecret {
		return DeliveryRequest{}, invalid(p, "is not a notice")
	}
	for _, name := range spec.Variables {
		if _, ok := vars[name]; !ok {
			return DeliveryRequest{}, invalid(p, "needs variable %q", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(vars)) {
		if !slices.Contains(spec.Variables, name) {
			return DeliveryRequest{}, invalid(p, "has no variable %q", name)
		}
		switch v := vars[name].(type) {
		case int, int64:
		case string:
			if strings.HasPrefix(v, refPrefix) {
				return DeliveryRequest{}, invalid(p, "variable %q is a reference; notices carry plain values", name)
			}
		default:
			return DeliveryRequest{}, invalid(p, "variable %q is a %T; want a string or an integer", name, v)
		}
	}
	plain := make(map[string]any, len(vars))
	maps.Copy(plain, vars)
	return DeliveryRequest{
		Type:      m.types.Type(p),
		Channel:   string(ch),
		Locale:    locale,
		Recipient: to.Ref,
		Variables: plain,
	}, nil
}

// check returns p's spec and the channel of the message to the recipient: the purpose's, which the
// recipient's must match unless recipientWins.
func (m *Messages) check(p message.Purpose, locale string, to Recipient, recipientWins bool) (message.Spec, message.Channel, error) {
	spec, ok := message.SpecOf(p)
	if !ok {
		return message.Spec{}, "", invalid(p, "is not a purpose")
	}
	if m.types.Type(p) == "" {
		return message.Spec{}, "", invalid(p, "has no message type")
	}
	if locale == "" || to.Ref == "" {
		return message.Spec{}, "", invalid(p, "needs a locale and a recipient")
	}
	if !strings.HasPrefix(to.Ref, refPrefix+"identifier:") && !strings.HasPrefix(to.Ref, refPrefix+"challenge-target:") {
		return message.Spec{}, "", invalid(p, "needs an identifier or challenge-target reference as its recipient")
	}
	ch := spec.Channel
	switch {
	case ch == "" && to.Channel == "":
		return message.Spec{}, "", invalid(p, "needs the recipient's channel")
	case ch == "" || (recipientWins && to.Channel != ""):
		ch = to.Channel
	case to.Channel != "" && to.Channel != ch:
		return message.Spec{}, "", invalid(p, "is sent by %s, not %s", ch, to.Channel)
	}
	return spec, ch, nil
}

func invalid(p message.Purpose, format string, args ...any) error {
	return fmt.Errorf("%w: %s %s", ErrMessageInvalid, p, fmt.Sprintf(format, args...))
}
