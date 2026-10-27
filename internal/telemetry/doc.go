// Package telemetry builds the logger, tracer provider and meter provider (TDD-08 §5.1–§5.3):
// JSON logs with redaction, OpenTelemetry traces exported over OTLP, and metrics exposed for
// Prometheus on an internal listener.
//
// It is imported by cmd/auth1, internal/http, internal/adapters and internal/worker, never by
// internal/domain or internal/app, which receive a *slog.Logger and the OpenTelemetry API
// interfaces instead. Nothing here sets global state.
package telemetry
