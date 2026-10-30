package app

import (
	"context"
	"fmt"
	"time"

	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
	"github.com/arafat-hasan/auth1/internal/domain/message"
)

// NoticeOptions configures Notices: delivery.retired_address_window and
// delivery.notices.new_sign_in.
type NoticeOptions struct {
	// RetiredAddressWindow is how long after retirement an identifier may still receive a notice.
	RetiredAddressWindow time.Duration
	// NewSignIn turns the new-sign-in notice on.
	NewSignIn bool
}

// Notice is a security notice to write (SDD D-16, TDD-06 §7).
type Notice struct {
	// Purpose is a notice purpose.
	Purpose message.Purpose
	// Variables are plain values: strings or integers, never an identifier value or a secret.
	Variables map[string]any
	// To is an explicit recipient, such as the old address after a change; nil sends to the
	// account's default recipient.
	To *account.Identifier
}

// NoticeSkip says why Notices.Send wrote no row, for the use case's audit; empty when it wrote one.
// It holds no value (G-6).
type NoticeSkip string

// The reasons a notice is not written.
const (
	// NoticeOff: the purpose is turned off (delivery.notices.new_sign_in).
	NoticeOff NoticeSkip = "notice off"
	// NoticeNoRecipient: the account has no verified identifier the notice may go to, or the
	// explicit one is unverified or of a type the deployment no longer has.
	NoticeNoRecipient NoticeSkip = "no verified recipient"
	// NoticeRetired: the explicit recipient was retired at least delivery.retired_address_window ago.
	NoticeRetired NoticeSkip = "recipient retired"
	// NoticeNotOwned: the explicit recipient is not the account's.
	NoticeNotOwned NoticeSkip = "recipient not the account's"
)

// Notices writes security notices as delivery rows, in the caller's transaction (TDD-06 §7). It
// chooses the recipient. An explicit one is used while current or retired less than the window
// ago, and otherwise the notice is skipped: there is no fallback. With none, the notice goes to the
// account's current verified email or, only when the deployment has no email type, to the
// account's first verified identifier by type name. Notices go by email whenever the deployment
// has an email type. A notice is best-effort: with no recipient, or with the new-sign-in notice
// off, it writes nothing and says why.
type Notices struct {
	accounts Accounts
	outbox   OutboxWriter
	messages *Messages
	registry *identifier.Registry
	clock    Clock
	opts     NoticeOptions
}

// NewNotices returns the notices writer.
func NewNotices(accounts Accounts, outbox OutboxWriter, messages *Messages, registry *identifier.Registry,
	clock Clock, opts NoticeOptions,
) *Notices {
	return &Notices{accounts: accounts, outbox: outbox, messages: messages, registry: registry, clock: clock, opts: opts}
}

// Send writes notice n about account a. It runs inside UnitOfWork.Do, the use case's transaction;
// the message goes in a's locale. It returns why no row was written, if none was. An error is a
// caller's bug (ErrMessageInvalid) or the outbox's. notice.To must come from the use case's locked
// read of a, so that its retirement and verification are current.
func (n *Notices) Send(ctx context.Context, a account.Account, notice Notice) (NoticeSkip, error) {
	if !notice.Purpose.Notice() {
		return "", fmt.Errorf("%w: %s is not a notice", ErrMessageInvalid, notice.Purpose)
	}
	if notice.Purpose == message.NoticeNewSignIn && !n.opts.NewSignIn {
		return NoticeOff, nil
	}
	to, skip, err := n.recipient(ctx, a, notice)
	if err != nil || skip != "" {
		return skip, err
	}
	req, err := n.messages.Notice(notice.Purpose, a.Locale, to, notice.Variables)
	if err != nil {
		return "", err
	}
	if err := n.outbox.Delivery(ctx, a.ID, req); err != nil {
		return "", fmt.Errorf("write notice: %w", err)
	}
	return "", nil
}

// recipient returns the notice's recipient, or why there is none.
func (n *Notices) recipient(ctx context.Context, a account.Account, notice Notice) (Recipient, NoticeSkip, error) {
	email := (identifier.Email{}).Name()
	_, hasEmail := n.registry.Type(email)
	if notice.To != nil {
		to, skip := n.reach(*notice.To, a)
		if skip == "" && hasEmail && to.Channel != message.Email {
			return Recipient{}, "", fmt.Errorf("%w: %s goes by email, not to a %s identifier",
				ErrMessageInvalid, notice.Purpose, notice.To.Type)
		}
		return to, skip, nil
	}
	ids, err := n.accounts.Identifiers(ctx, a.ID)
	if err != nil {
		return Recipient{}, "", fmt.Errorf("notice recipient: %w", err)
	}
	types := n.registry.Types()
	if hasEmail {
		types = []string{email}
	}
	for _, typ := range types {
		for _, id := range ids {
			if id.Type == typ && id.VerifiedAt != nil {
				to, skip := n.reach(id, a)
				return to, skip, nil
			}
		}
	}
	return Recipient{}, NoticeNoRecipient, nil
}

// reach returns the recipient that is id, if it may receive a notice about a: it is a's, verified,
// of a configured type, and current or retired less than the window ago. Otherwise it says why not.
func (n *Notices) reach(id account.Identifier, a account.Account) (Recipient, NoticeSkip) {
	if id.AccountID != a.ID {
		return Recipient{}, NoticeNotOwned
	}
	if id.VerifiedAt == nil {
		return Recipient{}, NoticeNoRecipient
	}
	if id.RetiredAt != nil && n.clock.Now().Sub(*id.RetiredAt) >= n.opts.RetiredAddressWindow {
		return Recipient{}, NoticeRetired
	}
	typ, ok := n.registry.Type(id.Type)
	if !ok {
		return Recipient{}, NoticeNoRecipient
	}
	return ToIdentifier(id.ID, typ.Channel()), ""
}
