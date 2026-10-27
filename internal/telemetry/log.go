package telemetry

import (
	"context"
	"io"
	"log/slog"
	"slices"

	"go.opentelemetry.io/otel/trace"
)

// BuildInfo identifies the running binary in logs and in the telemetry resource.
type BuildInfo struct {
	Version string
}

// NewHandler returns a JSON slog handler writing one object per line to w with the TDD-08 §5.1
// fields: ts, level, msg, service, version, and trace_id and span_id when the record's context
// holds a valid span. Those fields stay at the top level whatever groups the logger has.
func NewHandler(w io.Writer, service, version string) slog.Handler {
	inner := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: replaceAttr,
	}).WithAttrs([]slog.Attr{slog.String("service", service), slog.String("version", version)})
	return &handler{base: inner, plain: inner}
}

// replaceAttr renames slog's time key to ts and redacts secret and personal values (TDD-08 §5.1).
// slog calls it for every attribute that is not a group, at any depth, after resolving LogValuers.
func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		a.Key = "ts"
		return a
	}
	return redact(groups, a)
}

// handler adds the trace ids ahead of the logger's own groups and attributes. It records each
// WithGroup and WithAttrs so that, for a record with a span, it can add the ids to the base
// handler first and replay the rest on top.
type handler struct {
	base  slog.Handler // the JSON handler with service and version
	plain slog.Handler // base with ops applied, used for records without a span
	ops   []op
}

// op is one WithGroup (group set) or WithAttrs (attrs set) call.
type op struct {
	group string
	attrs []slog.Attr
}

func (o op) apply(h slog.Handler) slog.Handler {
	if o.group != "" {
		return h.WithGroup(o.group)
	}
	return h.WithAttrs(o.attrs)
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return h.plain.Handle(ctx, r)
	}
	out := h.base.WithAttrs([]slog.Attr{
		slog.String("trace_id", sc.TraceID().String()),
		slog.String("span_id", sc.SpanID().String()),
	})
	for _, o := range h.ops {
		out = o.apply(out)
	}
	return out.Handle(ctx, r)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return h.with(op{attrs: slices.Clone(attrs)})
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return h.with(op{group: name})
}

func (h *handler) with(o op) *handler {
	return &handler{base: h.base, plain: o.apply(h.plain), ops: append(slices.Clip(h.ops), o)}
}

// RequestID is the request_id log attribute.
func RequestID(id string) slog.Attr { return slog.String("request_id", id) }

// AccountID is the account_id log attribute.
func AccountID(id string) slog.Attr { return slog.String("account_id", id) }

// ClientID is the client_id log attribute.
func ClientID(id string) slog.Attr { return slog.String("client_id", id) }

// Caller is the caller log attribute: the calling service's name.
func Caller(name string) slog.Attr { return slog.String("caller", name) }

// Event is the event log attribute.
func Event(name string) slog.Attr { return slog.String("event", name) }

// Err is the error log attribute holding err's message. For a nil err it is the empty Attr,
// which handlers drop.
func Err(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	return slog.String("error", err.Error())
}
