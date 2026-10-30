package app

import (
	"context"
	"fmt"
	"slices"
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

// Notices writes security notices as delivery rows, in the caller's transaction (TDD-06 §7). It
// chooses the recipient: the explicit one while current, or retired less than the window ago;
// else the account's current verified email; or, when the deployment has no email type, the
// account's first verified identifier by type name. A notice is best-effort: with no recipient,
// or with the new-sign-in notice off, it writes nothing and returns nil.
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
// the message goes in a's locale. An error is a caller's bug (ErrMessageInvalid) or the outbox's.
func (n *Notices) Send(ctx context.Context, a account.Account, notice Notice) error {
	if !notice.Purpose.Notice() {
		return fmt.Errorf("%w: %s is not a notice", ErrMessageInvalid, notice.Purpose)
	}
	if notice.Purpose == message.NoticeNewSignIn && !n.opts.NewSignIn {
		return nil
	}
	to, ok, err := n.recipient(ctx, a, notice.To)
	if err != nil || !ok {
		return err
	}
	req, err := n.messages.Notice(notice.Purpose, a.Locale, to, notice.Variables)
	if err != nil {
		return err
	}
	if err := n.outbox.Delivery(ctx, a.ID, req); err != nil {
		return fmt.Errorf("write notice: %w", err)
	}
	return nil
}

// recipient returns the notice's recipient, and false when there is none.
func (n *Notices) recipient(ctx context.Context, a account.Account, explicit *account.Identifier) (Recipient, bool, error) {
	if explicit != nil {
		return n.reach(*explicit, a)
	}
	ids, err := n.accounts.Identifiers(ctx, a.ID)
	if err != nil {
		return Recipient{}, false, fmt.Errorf("notice recipient: %w", err)
	}
	types := n.registry.Types()
	if email := (identifier.Email{}).Name(); slices.Contains(types, email) {
		types = []string{email}
	}
	for _, typ := range types {
		for _, id := range ids {
			if id.Type == typ && id.VerifiedAt != nil {
				return n.reach(id, a)
			}
		}
	}
	return Recipient{}, false, nil
}

// reach returns the recipient that is id, if it may receive a notice about a: it is a's, verified,
// of a configured type, and current or retired less than the window ago.
func (n *Notices) reach(id account.Identifier, a account.Account) (Recipient, bool, error) {
	if id.AccountID != a.ID || id.VerifiedAt == nil {
		return Recipient{}, false, nil
	}
	if id.RetiredAt != nil && n.clock.Now().Sub(*id.RetiredAt) >= n.opts.RetiredAddressWindow {
		return Recipient{}, false, nil
	}
	typ, ok := n.registry.Type(id.Type)
	if !ok {
		return Recipient{}, false, nil
	}
	return ToIdentifier(id.ID, typ.Channel()), true, nil
}
