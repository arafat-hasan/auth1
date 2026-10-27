package telemetry

import (
	"maps"
	"slices"
)

// Kind is the kind of a catalogue instrument.
type Kind int

// The instrument kinds of TDD-08 §5.2.
const (
	KindCounter Kind = iota + 1
	KindGauge
	KindHistogram
)

// String returns the kind's name.
func (k Kind) String() string {
	switch k {
	case KindCounter:
		return "counter"
	case KindGauge:
		return "gauge"
	case KindHistogram:
		return "histogram"
	}
	return "unknown"
}

// catalogue is TDD-08 §5.2: every metric name auth1 may expose, with its kind. Instruments are
// created only when a package asks for one; a name not listed here cannot be created.
var catalogue = map[string]Kind{
	"auth1_sign_ins_total":             KindCounter,
	"auth1_refresh_total":              KindCounter,
	"auth1_registrations_total":        KindCounter,
	"auth1_challenges_total":           KindCounter,
	"auth1_second_factor_total":        KindCounter,
	"auth1_resolver_requests_total":    KindCounter,
	"auth1_outbox_age_seconds":         KindGauge,
	"auth1_outbox_parked":              KindGauge,
	"auth1_introspections_total":       KindCounter,
	"auth1_service_calls_denied_total": KindCounter,
	"auth1_hash_duration_seconds":      KindHistogram,
	"auth1_hash_queue_seconds":         KindHistogram,
	"auth1_hash_rejected_total":        KindCounter,
	"auth1_rate_limited_total":         KindCounter,
	"auth1_rate_limiter_errors_total":  KindCounter,
	"auth1_sms_sent_total":             KindCounter,
	"auth1_sms_budget_remaining":       KindGauge,
	"auth1_jwks_keys":                  KindGauge,
	"auth1_job_last_success_timestamp": KindGauge,
}

// InstrumentNames returns the catalogue's metric names, sorted.
func InstrumentNames() []string {
	return slices.Sorted(maps.Keys(catalogue))
}
