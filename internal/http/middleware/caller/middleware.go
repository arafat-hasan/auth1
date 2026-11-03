package caller

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/clientip"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/requestid"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

// ActionDenied is the audit action of a service call refused for a missing scope.
const ActionDenied = "service_call_denied"

// actorHeader is the header naming the person a calling service acts for (SDD D-13).
const actorHeader = "Auth1-Actor"

// unknownCaller is the caller label of a denial to an identity that service_auth.callers does not
// name, so the label's values stay those of the configuration.
const unknownCaller = "unknown"

// The refusals' details.
const (
	noCallerDetail   = "No valid service credential."
	notAllowedDetail = "The caller lacks the operation's scope."
	actorDetail      = "Auth1-Actor must be one value of 1 to 128 printable ASCII characters."
)

// Middleware authenticates the callers of service operations (TDD-05 §3) and passes every other
// request on untouched. It is installed with Use, before Chi dispatches, and finds the operation
// through Options.Match. For a service operation:
//   - no accepted credential answers 401 TOKEN_INVALID;
//   - a caller without the operation's x-auth1-scope answers 403 CALLER_NOT_ALLOWED, and the denial
//     is counted, audited and logged; a failed audit write is logged and the call still refused;
//   - a malformed Auth1-Actor answers 422 VALIDATION_FAILED;
//
// otherwise the handler runs with the Caller in the context (From).
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id, op, ok := r.o.Match(req)
		if !ok || !op.IsService() {
			next.ServeHTTP(w, req)
			return
		}
		c, ok := r.resolve(req, op)
		if !ok {
			r.o.Problems.Write(w, req, &domain.Error{Code: domain.CodeTokenInvalid, Detail: noCallerDetail})
			return
		}
		act, actOK := actorOf(req.Header)
		if !c.Has(op.Scope) {
			r.deny(req, id, op, c, act)
			r.o.Problems.Write(w, req, &domain.Error{Code: domain.CodeCallerNotAllowed, Detail: notAllowedDetail})
			return
		}
		if !actOK {
			r.o.Problems.Write(w, req, &domain.Error{Code: domain.CodeValidationFailed, Detail: actorDetail})
			return
		}
		c.Actor = act
		next.ServeHTTP(w, req.WithContext(with(req.Context(), c)))
	})
}

// resolve returns the request's caller, by the credentials that both the mode and the operation's
// security accept.
func (r *Resolver) resolve(req *http.Request, op gen.Operation) (Caller, bool) {
	mode := r.o.Mode
	if (mode == ModeMesh || mode == ModeBoth) && slices.Contains(op.Security, "workload") {
		if id, ok := r.workloadIdentity(req); ok {
			return Caller{Kind: KindWorkload, ID: id, Scopes: slices.Clone(r.o.Callers[id])}, true
		}
	}
	if (mode == ModeClientCredentials || mode == ModeBoth) && slices.Contains(op.Security, "serviceToken") && r.o.Tokens != nil {
		scheme, token, _ := strings.Cut(req.Header.Get("Authorization"), " ")
		if strings.EqualFold(scheme, "Bearer") && token != "" {
			if c, err := r.o.Tokens.VerifyServiceToken(req.Context(), token); err == nil && c.Kind == KindClient && c.ID != "" {
				return c, true
			}
		}
	}
	return Caller{}, false
}

// deny counts, audits and logs the refusal of c on operation id. act is the Auth1-Actor if valid.
// The log line holds the route pattern and the decision only (G-6).
func (r *Resolver) deny(req *http.Request, id string, op gen.Operation, c Caller, act string) {
	// The refusal is recorded even if the caller hangs up.
	ctx := context.WithoutCancel(req.Context())
	label := c.ID
	if _, known := r.o.Callers[c.ID]; c.Kind == KindWorkload && !known {
		label = unknownCaller
	}
	r.o.Denied.Add(ctx, 1, metric.WithAttributes(attribute.String("caller", label), attribute.String("scope", op.Scope)))
	route := slog.String("route", r.o.BasePath+op.Path)
	rid := telemetry.RequestID(requestid.From(ctx))
	r.o.Logger.LogAttrs(ctx, slog.LevelWarn, "service call denied", rid, route, slog.String("decision", "denied"))
	err := r.o.Audit.Write(ctx, app.AuditEntry{
		ActorKind: app.ActorService,
		ActorID:   c.ID,
		OnBehalf:  act,
		Action:    ActionDenied,
		Outcome:   app.OutcomeFailure,
		IP:        clientip.From(ctx),
		UserAgent: req.UserAgent(),
		Details:   map[string]any{"operation": id, "scope": op.Scope},
	})
	if err != nil {
		r.o.Logger.LogAttrs(ctx, slog.LevelError, "service call denial not audited", rid, route, telemetry.Err(err))
	}
}

// actorOf returns the request's Auth1-Actor: "" and true without one, false for a malformed one
// (TDD-05 §3: one value of 1 to 128 printable ASCII characters).
func actorOf(h http.Header) (string, bool) {
	values := h.Values(actorHeader)
	switch len(values) {
	case 0:
		return "", true
	case 1:
	default:
		return "", false
	}
	v := values[0]
	if len(v) == 0 || len(v) > 128 {
		return "", false
	}
	for i := range len(v) {
		if v[i] < 0x20 || v[i] > 0x7e {
			return "", false
		}
	}
	return v, true
}
