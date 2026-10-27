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

// spec describes a catalogue instrument: its kind and, for some, its unit and histogram buckets.
type spec struct {
	kind    Kind
	unit    string    // UCUM unit; "s" makes the exporter add _seconds
	buckets []float64 // explicit histogram boundaries; nil for the SDK default
}

// httpDurationBuckets are the OpenTelemetry semantic-convention boundaries for
// http.server.request.duration, in seconds.
var httpDurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}

// catalogue is TDD-08 §5.2: every metric name auth1 may expose, with its kind. Instruments are
// created only when a package asks for one; a name not listed here cannot be created.
// http.server.request.duration is the standard HTTP server metric of §5.2 and the one name
// without the auth1_ prefix.
var catalogue = map[string]spec{
	"auth1_sign_ins_total":             {kind: KindCounter},
	"auth1_refresh_total":              {kind: KindCounter},
	"auth1_registrations_total":        {kind: KindCounter},
	"auth1_challenges_total":           {kind: KindCounter},
	"auth1_second_factor_total":        {kind: KindCounter},
	"auth1_resolver_requests_total":    {kind: KindCounter},
	"auth1_outbox_age_seconds":         {kind: KindGauge},
	"auth1_outbox_parked":              {kind: KindGauge},
	"auth1_introspections_total":       {kind: KindCounter},
	"auth1_service_calls_denied_total": {kind: KindCounter},
	"auth1_hash_duration_seconds":      {kind: KindHistogram},
	"auth1_hash_queue_seconds":         {kind: KindHistogram},
	"auth1_hash_rejected_total":        {kind: KindCounter},
	"auth1_rate_limited_total":         {kind: KindCounter},
	"auth1_rate_limiter_errors_total":  {kind: KindCounter},
	"auth1_sms_sent_total":             {kind: KindCounter},
	"auth1_sms_budget_remaining":       {kind: KindGauge},
	"auth1_jwks_keys":                  {kind: KindGauge},
	"auth1_job_last_success_timestamp": {kind: KindGauge},
	"http.server.request.duration":     {kind: KindHistogram, unit: "s", buckets: httpDurationBuckets},
}

// InstrumentNames returns the catalogue's metric names, sorted.
func InstrumentNames() []string {
	return slices.Sorted(maps.Keys(catalogue))
}
