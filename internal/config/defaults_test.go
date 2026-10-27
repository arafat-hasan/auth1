package config

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestDefault pins every default to its TDD-08 §3 value. Keys with no default (the issuer, the
// service-auth mode, the TOTP issuer and the example lists) are zero.
func TestDefault(t *testing.T) {
	t.Parallel()

	want := map[string]any{ //nolint:gosec // key names such as password_file, not credentials
		"app.environment": EnvProduction,

		"http.listen":          ":8080",
		"http.base_path":       "",
		"http.issuer":          "",
		"http.trusted_proxies": []string(nil),

		"keys.keyring_file":           NewSecretFile("/secrets/signing/keyring.yaml"),
		"keys.min_publish_before_use": 15 * time.Minute,

		"encryption.keyring_file":           NewSecretFile("/secrets/fields/keyring.yaml"),
		"encryption.blind_index_key_file":   NewSecretFile("/secrets/fields/bidx.key"),
		"encryption.mac_key_file":           NewSecretFile("/secrets/mac/mac.key"),
		"encryption.device_cookie_key_file": NewSecretFile("/secrets/mac/device.key"),

		"tokens.access_ttl":           15 * time.Minute,
		"tokens.self_audience":        "",
		"tokens.refresh_idle_ttl":     168 * time.Hour,
		"tokens.refresh_absolute_ttl": 720 * time.Hour,
		"tokens.refresh_reuse_grace":  10 * time.Second,

		"clients": []Client(nil),

		"identifiers.email.required":      true,
		"identifiers.email.verify":        VerifyEmailLink,
		"identifiers.email.sign_in":       true,
		"identifiers.email.calling_codes": []string(nil),
		"identifiers.phone.required":      false,
		"identifiers.phone.verify":        VerifySMSOTP,
		"identifiers.phone.sign_in":       false,
		"identifiers.phone.calling_codes": []string{},

		"passwords.min_length":            12,
		"passwords.max_length":            128,
		"passwords.deny_list_file":        "/config/common-passwords.txt",
		"passwords.pepper_keyring_file":   NewSecretFile("/secrets/pepper/keyring.yaml"),
		"passwords.argon2.memory":         64 * MiB,
		"passwords.argon2.iterations":     2,
		"passwords.argon2.parallelism":    1,
		"passwords.argon2.max_concurrent": 4,
		"passwords.argon2.queue_timeout":  2 * time.Second,

		"mfa.totp.issuer":       "",
		"mfa.totp.label":        TOTPLabelEmail,
		"mfa.totp.skew_steps":   1,
		"mfa.recovery_codes":    10,
		"mfa.attempts_per_flow": 5,
		"mfa.sign_in_flow_ttl":  10 * time.Minute,

		"otp.length":             6,
		"otp.ttl":                5 * time.Minute,
		"otp.max_attempts":       3,
		"otp.cooldown":           15 * time.Minute,
		"otp.resend_after":       60 * time.Second,
		"otp.max_sends_per_hour": 5,

		"links.verification_ttl": 24 * time.Hour,
		"links.reset_ttl":        30 * time.Minute,
		"links.invitation_ttl":   72 * time.Hour,

		"flows.pending_registration_ttl": 24 * time.Hour,

		"recovery.via":         "email",
		"recovery.sms_step_up": false,

		"identifier_changes.confirm_old_email": ConfirmOldRequired,

		"roles.catalog":                    []string{"user", "admin"},
		"roles.revoke_sessions_on_removal": true,

		"bootstrap.roles":       []string{"admin"},
		"bootstrap.emails_file": NewSecretFile("/secrets/bootstrap/emails.txt"),

		"statuses.reason_codes":       []string{"policy_violation", "admin_action"},
		"statuses.restricted_sign_in": true,

		"locales.allowed": []string{"en"},
		"locales.default": "en",

		"delivery.adapter":                   DeliveryNotification,
		"delivery.notification.request_url":  "http://notification/v1/requests",
		"delivery.direct.smtp.host":          "",
		"delivery.direct.smtp.port":          587,
		"delivery.direct.smtp.from":          "",
		"delivery.direct.smtp.username":      "",
		"delivery.direct.smtp.password_file": NewSecretFile(""),
		"delivery.direct.sms.url":            "",
		"delivery.direct.sms.sender":         "",
		"delivery.direct.sms.token_file":     NewSecretFile(""),
		"delivery.direct.templates_dir":      "/config/templates",
		"delivery.retired_address_window":    168 * time.Hour,
		"delivery.notices.new_sign_in":       false,
		"delivery.types":                     map[string]string{},

		"service_auth.mode":                         ServiceAuthMode(""),
		"service_auth.mesh.source":                  MeshSourceHeader,
		"service_auth.mesh.header":                  "x-forwarded-client-cert",
		"service_auth.mesh.format":                  MeshFormatXFCC,
		"service_auth.mesh.trusted_sidecar_cidrs":   []string{"127.0.0.1/32", "::1/128"},
		"service_auth.mesh.ca_file":                 "",
		"service_auth.client_credentials.audience":  "auth1-services",
		"service_auth.client_credentials.token_ttl": 5 * time.Minute,
		"service_auth.client_credentials.clients":   []ServiceClient(nil),
		"service_auth.callers":                      []Caller(nil),

		"rate_limits.global_ip.limit":              600,
		"rate_limits.global_ip.window":             time.Minute,
		"rate_limits.sign_in_ip.limit":             30,
		"rate_limits.sign_in_ip.window":            5 * time.Minute,
		"rate_limits.registration_ip.limit":        5,
		"rate_limits.registration_ip.window":       time.Hour,
		"rate_limits.reset_ip.limit":               10,
		"rate_limits.reset_ip.window":              time.Hour,
		"rate_limits.reset_account.limit":          3,
		"rate_limits.reset_account.window":         time.Hour,
		"rate_limits.send_ip.limit":                20,
		"rate_limits.send_ip.window":               time.Hour,
		"rate_limits.verify_ip.limit":              30,
		"rate_limits.verify_ip.window":             time.Hour,
		"rate_limits.resume_ip.limit":              10,
		"rate_limits.resume_ip.window":             time.Hour,
		"rate_limits.token_client.limit":           60,
		"rate_limits.token_client.window":          time.Minute,
		"rate_limits.factor_failures.limit":        10,
		"rate_limits.factor_failures.window":       time.Hour,
		"rate_limits.sign_in_failures.threshold":   5,
		"rate_limits.sign_in_failures.first_delay": time.Second,
		"rate_limits.sign_in_failures.max_delay":   15 * time.Minute,
		"rate_limits.sms_budget_per_hour":          0,

		"events.exchange": "auth1.events",
		"events.source":   "/auth1",

		"outbox.poll_interval":   200 * time.Millisecond,
		"outbox.batch_size":      100,
		"outbox.max_attempts":    20,
		"outbox.publish_timeout": 5 * time.Second,

		"database.dsn_file":        NewSecretFile("/secrets/db/dsn"),
		"database.max_conns":       20,
		"database.acquire_timeout": 2 * time.Second,

		"redis.address":       "redis:6379",
		"redis.prefix":        "auth1:",
		"redis.password_file": NewSecretFile(""),

		"amqp.url_file": NewSecretFile("/secrets/amqp/url"),

		"retention.expired_registrations": 168 * time.Hour,
		"retention.closed_challenges":     720 * time.Hour,
		"retention.revoked_sessions":      2160 * time.Hour,
		"retention.idempotency_keys":      24 * time.Hour,
		"retention.published_outbox":      168 * time.Hour,
		"retention.audit_client_details":  2160 * time.Hour,

		"telemetry.otlp_endpoint": "",
		"telemetry.service_name":  "auth1",
	}

	got := flatten(Default())
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(SecretFile{})); diff != "" {
		t.Errorf("Default() mismatch (-want +got):\n%s", diff)
	}
}
