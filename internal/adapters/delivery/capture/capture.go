package capture

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
)

// Capacity is how many messages the inbox keeps; the oldest is dropped first.
const Capacity = 1000

// refPrefix starts every reference (TDD-06 §5).
const refPrefix = "auth1:"

// Message is a captured message, its references resolved.
type Message struct {
	RequestID  string         `json:"request_id"`
	Type       string         `json:"type"`
	Channel    string         `json:"channel"`
	Locale     string         `json:"locale"`
	To         string         `json:"to"`
	Variables  map[string]any `json:"variables"`
	Deadline   *time.Time     `json:"deadline,omitempty"`
	CapturedAt time.Time      `json:"captured_at"`
}

// Inbox implements app.MessageDelivery by keeping the messages in memory. It is safe for
// concurrent use.
type Inbox struct {
	resolver app.DeliveryResolver
	clock    app.Clock

	mu   sync.Mutex
	ring []Message // at most Capacity; next is the slot written next once full
	next int
}

// New returns an empty inbox that resolves references through resolver.
func New(resolver app.DeliveryResolver, clock app.Clock) *Inbox {
	return &Inbox{resolver: resolver, clock: clock, ring: make([]Message, 0, Capacity)}
}

// Send implements app.MessageDelivery. It resolves the recipient and every reference among the
// variables in one call, as the notification service would at send time, and keeps the message.
// A reference the resolver omits is closed, so the message is dropped (TDD-06 §6).
func (in *Inbox) Send(ctx context.Context, row app.DeliveryRow) app.DeliveryOutcome {
	req := row.Request
	refs := []string{req.Recipient}
	for _, v := range req.Variables {
		if s, ok := v.(string); ok && strings.HasPrefix(s, refPrefix) {
			refs = append(refs, s)
		}
	}
	values, err := in.resolver.Resolve(ctx, req.RequestID, refs)
	switch {
	case errors.Is(err, app.ErrResolverUnavailable):
		return app.DeliveryOutcome{Result: app.DeliveryRetry, Reason: "capture: resolver unavailable"}
	case err != nil:
		return app.DeliveryOutcome{Result: app.DeliveryRetry, Reason: "capture: resolver failed"}
	}
	for _, ref := range refs {
		if _, ok := values[ref]; !ok {
			// A reference holds an id, never a value, so the reason may name it.
			return app.DeliveryOutcome{Result: app.DeliveryDropped, Reason: "capture: " + ref + " is closed"}
		}
	}
	vars := make(map[string]any, len(req.Variables))
	for k, v := range req.Variables {
		if s, ok := v.(string); ok && strings.HasPrefix(s, refPrefix) {
			v = values[s]
		}
		vars[k] = v
	}
	m := Message{
		RequestID: req.RequestID, Type: req.Type, Channel: req.Channel, Locale: req.Locale,
		To: values[req.Recipient], Variables: vars, CapturedAt: in.clock.Now(),
	}
	if req.Deadline != nil {
		d := *req.Deadline
		m.Deadline = &d
	}
	in.keep(m)
	return app.DeliveryOutcome{Result: app.DeliverySent}
}

// keep adds m, dropping the oldest message when the inbox is full.
func (in *Inbox) keep(m Message) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.ring) < Capacity {
		in.ring = append(in.ring, m)
		return
	}
	in.ring[in.next] = m
	in.next = (in.next + 1) % Capacity
}

// Messages returns copies of the messages sent to to, newest first; every message when to is
// empty.
func (in *Inbox) Messages(to string) []Message {
	in.mu.Lock()
	defer in.mu.Unlock()
	var out []Message
	n := len(in.ring)
	for i := range n {
		// The newest message is the one before next.
		m := in.ring[(in.next-1-i+2*n)%n]
		if to != "" && m.To != to {
			continue
		}
		m.Variables = maps.Clone(m.Variables)
		if m.Deadline != nil {
			d := *m.Deadline
			m.Deadline = &d
		}
		out = append(out, m)
	}
	return out
}

// Routes registers GET /dev/messages?to=<value> on r: the messages sent to the value, newest
// first. The answer holds resolved values, so it is never cached.
func (in *Inbox) Routes(r chi.Router) {
	r.Get("/dev/messages", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		to := req.URL.Query().Get("to")
		if to == "" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			// The status is sent; an encoding error can only be a gone client.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type": "about:blank", "title": http.StatusText(http.StatusUnprocessableEntity),
				"status": http.StatusUnprocessableEntity, "code": domain.CodeValidationFailed,
				"detail": "The to parameter is required.",
			})
			return
		}
		msgs := in.Messages(to)
		if msgs == nil {
			msgs = []Message{}
		}
		w.Header().Set("Content-Type", "application/json")
		// Messages hold only strings and integers, so encoding fails only on a gone client.
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": msgs})
	})
}
