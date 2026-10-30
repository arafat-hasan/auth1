package main

import (
	"context"
	"fmt"

	"github.com/go-chi/chi/v5"

	"github.com/arafat-hasan/auth1/internal/adapters/delivery/capture"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
)

// newDelivery builds the delivery adapter delivery.adapter names (SDD D-16), with the
// development-only routes it serves, if any. The capture adapter exists only in development: it
// is refused here as well as by Validate (T-17). The notification and direct adapters arrive with
// WP-44 and WP-45; until then there is no adapter for them and the MessageDelivery is nil, which
// the relay (WP-42) must refuse at start-up rather than run without.
func newDelivery(cfg *config.Config, resolver app.DeliveryResolver, clock app.Clock) (app.MessageDelivery, func(chi.Router), error) {
	if cfg.Delivery.Adapter != config.DeliveryCapture {
		return nil, nil, nil
	}
	if cfg.App.Environment != config.EnvDevelopment {
		return nil, nil, fmt.Errorf("delivery.adapter: capture is for development only, not %s", cfg.App.Environment)
	}
	inbox := capture.New(resolver, clock)
	return inbox, inbox.Routes, nil
}

// unavailableResolver stands in for the delivery resolver until WP-43 builds it: every call fails
// with ErrResolverUnavailable, so a send is retried.
type unavailableResolver struct{}

func (unavailableResolver) Resolve(context.Context, string, []string) (map[string]string, error) {
	return nil, app.ErrResolverUnavailable
}
