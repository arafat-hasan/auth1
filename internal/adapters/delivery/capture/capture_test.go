package capture_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/adapters/delivery/capture"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// resolver answers from values; err, when set, fails every call. It records the calls.
type resolver struct {
	mu     sync.Mutex
	values map[string]string
	err    error
	calls  [][]string
}

func (r *resolver) Resolve(_ context.Context, requestID string, refs []string) (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{requestID}, refs...))
	if r.err != nil {
		return nil, r.err
	}
	out := map[string]string{}
	for _, ref := range refs {
		if v, ok := r.values[ref]; ok {
			out[ref] = v
		}
	}
	return out, nil
}

var (
	idRef     = app.IdentifierRef(fakes.ID(2))
	secretRef = app.SecretRef(fakes.ID(1))
	deadline  = now.Add(5 * time.Minute)
)

func codeRow(n int, to string) app.DeliveryRow {
	return app.DeliveryRow{ID: fakes.ID(100 + n), Request: app.DeliveryRequest{
		RequestID: fmt.Sprintf("%s:%d", fakes.ID(1), n), Type: "auth.sign_in_code", Channel: "sms",
		Locale: "en", Recipient: to, Variables: map[string]any{"code": secretRef, "n": 3},
		Deadline: &deadline,
	}}
}

func newInbox(r *resolver) *capture.Inbox { return capture.New(r, fakes.NewClock(now)) }

func TestSendResolvesAndStores(t *testing.T) {
	t.Parallel()
	r := &resolver{values: map[string]string{idRef: "+447700900123", secretRef: "123456"}}
	in := newInbox(r)
	if got := in.Send(t.Context(), codeRow(1, idRef)); got.Result != app.DeliverySent {
		t.Fatalf("Send = %+v, want sent", got)
	}
	want := []capture.Message{{
		RequestID: fakes.ID(1).String() + ":1", Type: "auth.sign_in_code", Channel: "sms", Locale: "en",
		To: "+447700900123", Variables: map[string]any{"code": "123456", "n": 3}, Deadline: &deadline,
		CapturedAt: now,
	}}
	if diff := cmp.Diff(want, in.Messages("+447700900123")); diff != "" {
		t.Errorf("Messages (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([][]string{{fakes.ID(1).String() + ":1", idRef, secretRef}}, r.calls); diff != "" {
		t.Errorf("resolver calls (-want +got):\n%s", diff)
	}
	if got := in.Messages("+440000000000"); len(got) != 0 {
		t.Errorf("Messages(other) = %v, want none", got)
	}
}

// TestSendDropsClosedReference: a reference the resolver omits is closed; nothing is stored.
func TestSendDropsClosedReference(t *testing.T) {
	t.Parallel()
	in := newInbox(&resolver{values: map[string]string{idRef: "+447700900123"}})
	got := in.Send(t.Context(), codeRow(1, idRef))
	if got.Result != app.DeliveryDropped || got.Reason == "" {
		t.Errorf("Send = %+v, want dropped with a reason", got)
	}
	if strings.Contains(got.Reason, "+44") {
		t.Errorf("reason %q holds a value", got.Reason)
	}
	if m := in.Messages("+447700900123"); len(m) != 0 {
		t.Errorf("Messages = %v, want none", m)
	}
}

func TestSendRetriesOnResolverError(t *testing.T) {
	t.Parallel()
	in := newInbox(&resolver{err: errors.New("down")})
	if got := in.Send(t.Context(), codeRow(1, idRef)); got.Result != app.DeliveryRetry {
		t.Errorf("Send = %+v, want retry", got)
	}
}

// TestRingEvictsOldest: the inbox keeps the last Capacity messages.
func TestRingEvictsOldest(t *testing.T) {
	t.Parallel()
	values := map[string]string{secretRef: "123456"}
	for i := range capture.Capacity + 1 {
		values[app.IdentifierRef(fakes.ID(1000+i))] = fmt.Sprintf("to-%d", i)
	}
	in := newInbox(&resolver{values: values})
	for i := range capture.Capacity + 1 {
		in.Send(t.Context(), codeRow(i+1, app.IdentifierRef(fakes.ID(1000+i))))
	}
	if got := in.Messages("to-0"); len(got) != 0 {
		t.Errorf("the oldest message is still kept: %v", got)
	}
	for _, i := range []int{1, capture.Capacity} {
		if got := in.Messages(fmt.Sprintf("to-%d", i)); len(got) != 1 {
			t.Errorf("message %d: %d kept, want 1", i, len(got))
		}
	}
	if got := len(in.Messages("")); got != capture.Capacity {
		t.Errorf("Messages(\"\") = %d messages, want %d", got, capture.Capacity)
	}
}

func TestConcurrentSendAndRead(t *testing.T) {
	t.Parallel()
	in := newInbox(&resolver{values: map[string]string{idRef: "a@example.org", secretRef: "1"}})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 50 {
				in.Send(t.Context(), codeRow(i*100+j+1, idRef))
				_ = in.Messages("a@example.org")
			}
		})
	}
	wg.Wait()
	if got := len(in.Messages("a@example.org")); got != 400 {
		t.Errorf("%d messages, want 400", got)
	}
}

// TestMessagesIsACopy: changing a returned message changes nothing kept.
func TestMessagesIsACopy(t *testing.T) {
	t.Parallel()
	in := newInbox(&resolver{values: map[string]string{idRef: "a@example.org", secretRef: "1"}})
	in.Send(t.Context(), codeRow(1, idRef))
	in.Messages("a@example.org")[0].Variables["code"] = "changed"
	if got := in.Messages("a@example.org")[0].Variables["code"]; got != "1" {
		t.Errorf("code = %v after changing a copy, want 1", got)
	}
}

func TestMessagesHandler(t *testing.T) {
	t.Parallel()
	values := map[string]string{secretRef: "1", idRef: "a@example.org", app.IdentifierRef(fakes.ID(3)): "b@example.org"}
	in := newInbox(&resolver{values: values})
	in.Send(t.Context(), codeRow(1, idRef))
	in.Send(t.Context(), codeRow(2, app.IdentifierRef(fakes.ID(3))))
	in.Send(t.Context(), codeRow(3, idRef))
	r := chi.NewRouter()
	in.Routes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dev/messages?to=a@example.org", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" ||
		rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET = %d, %v", rec.Code, rec.Header())
	}
	var got struct {
		Messages []struct {
			RequestID string         `json:"request_id"`
			To        string         `json:"to"`
			Variables map[string]any `json:"variables"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range got.Messages {
		ids = append(ids, m.RequestID)
	}
	want := []string{fakes.ID(1).String() + ":3", fakes.ID(1).String() + ":1"} // newest first
	if diff := cmp.Diff(want, ids); diff != "" {
		t.Errorf("request ids (-want +got):\n%s", diff)
	}
	if got.Messages[0].Variables["code"] != "1" {
		t.Errorf("code = %v, want the resolved value", got.Messages[0].Variables["code"])
	}

	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dev/messages", nil))
	if rec.Code != http.StatusUnprocessableEntity || rec.Header().Get("Content-Type") != "application/problem+json" ||
		!strings.Contains(rec.Body.String(), `"code":"VALIDATION_FAILED"`) {
		t.Errorf("GET without to = %d %s, want 422 VALIDATION_FAILED", rec.Code, rec.Header().Get("Content-Type"))
	}
}
