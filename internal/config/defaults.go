package config

import "time"

// Default returns the defaults of TDD-08 §3. The issuer, service_auth.mode, mfa.totp.issuer and
// the example lists (clients, service clients, callers, trusted proxies) have no default.
func Default() Config {
	return Config{
		App:  App{Environment: EnvProduction},
		HTTP: HTTP{Listen: ":8080"},
		Keys: Keys{
			KeyringFile:         NewSecretFile("/secrets/signing/keyring.yaml"),
			MinPublishBeforeUse: 15 * time.Minute,
		},
		Encryption: Encryption{
			KeyringFile:         NewSecretFile("/secrets/fields/keyring.yaml"),
			BlindIndexKeyFile:   NewSecretFile("/secrets/fields/bidx.key"),
			MACKeyFile:          NewSecretFile("/secrets/mac/mac.key"),
			DeviceCookieKeyFile: NewSecretFile("/secrets/mac/device.key"),
		},
		Tokens: Tokens{
			AccessTTL:          15 * time.Minute,
			RefreshIdleTTL:     168 * time.Hour,
			RefreshAbsoluteTTL: 720 * time.Hour,
			RefreshReuseGrace:  10 * time.Second,
		},
		Identifiers: map[string]IdentifierPolicy{
			"email": {Required: true, Verify: VerifyEmailLink, SignIn: true},
			"phone": {Verify: VerifySMSOTP, CallingCodes: []string{}},
		},
		Passwords: Passwords{
			MinLength:         12,
			MaxLength:         128,
			DenyListFile:      "/config/common-passwords.txt",
			PepperKeyringFile: NewSecretFile("/secrets/pepper/keyring.yaml"),
			Argon2: Argon2{
				Memory:        64 * MiB,
				Iterations:    2,
				Parallelism:   1,
				MaxConcurrent: 4,
				QueueTimeout:  2 * time.Second,
			},
		},
		MFA: MFA{
			TOTP:            TOTP{Label: TOTPLabelEmail, SkewSteps: 1},
			RecoveryCodes:   10,
			AttemptsPerFlow: 5,
			SignInFlowTTL:   10 * time.Minute,
		},
		OTP: OTP{
			Length:          6,
			TTL:             5 * time.Minute,
			MaxAttempts:     3,
			Cooldown:        15 * time.Minute,
			ResendAfter:     60 * time.Second,
			MaxSendsPerHour: 5,
		},
		Links: Links{
			VerificationTTL: 24 * time.Hour,
			ResetTTL:        30 * time.Minute,
			InvitationTTL:   72 * time.Hour,
		},
		Flows:             Flows{PendingRegistrationTTL: 24 * time.Hour},
		Recovery:          Recovery{Via: "email"},
		IdentifierChanges: IdentifierChanges{ConfirmOldEmail: ConfirmOldRequired},
		Roles:             Roles{Catalog: []string{"user", "admin"}, RevokeSessionsOnRemoval: true},
		Bootstrap: Bootstrap{
			Roles:      []string{"admin"},
			EmailsFile: NewSecretFile("/secrets/bootstrap/emails.txt"),
		},
		Statuses: Statuses{
			ReasonCodes:      []string{"policy_violation", "admin_action"},
			RestrictedSignIn: true,
		},
		Locales: Locales{Allowed: []string{"en"}, Default: "en"},
		Delivery: Delivery{
			Adapter:      DeliveryNotification,
			Notification: Notification{RequestURL: "http://notification/v1/requests"},
			Direct: Direct{
				SMTP:         SMTP{Port: 587},
				TemplatesDir: "/config/templates",
			},
			RetiredAddressWindow: 168 * time.Hour,
			Types:                map[string]string{},
		},
		ServiceAuth: ServiceAuth{
			Mesh: Mesh{
				Source:              MeshSourceHeader,
				Header:              "x-forwarded-client-cert",
				Format:              MeshFormatXFCC,
				TrustedSidecarCIDRs: []string{"127.0.0.1/32", "::1/128"},
			},
			ClientCredentials: ClientCredentials{
				Audience: "auth1-services",
				TokenTTL: 5 * time.Minute,
			},
		},
		RateLimits: RateLimits{
			GlobalIP:       RateLimit{Limit: 600, Window: time.Minute},
			SignInIP:       RateLimit{Limit: 30, Window: 5 * time.Minute},
			RegistrationIP: RateLimit{Limit: 5, Window: time.Hour},
			ResetIP:        RateLimit{Limit: 10, Window: time.Hour},
			ResetAccount:   RateLimit{Limit: 3, Window: time.Hour},
			SendIP:         RateLimit{Limit: 20, Window: time.Hour},
			VerifyIP:       RateLimit{Limit: 30, Window: time.Hour},
			ResumeIP:       RateLimit{Limit: 10, Window: time.Hour},
			TokenClient:    RateLimit{Limit: 60, Window: time.Minute},
			FactorFailures: RateLimit{Limit: 10, Window: time.Hour},
			SignInFailures: Backoff{Threshold: 5, FirstDelay: time.Second, MaxDelay: 15 * time.Minute},
		},
		Events: Events{Exchange: "auth1.events", Source: "/auth1"},
		Outbox: Outbox{
			PollInterval:   200 * time.Millisecond,
			BatchSize:      100,
			MaxAttempts:    20,
			PublishTimeout: 5 * time.Second,
		},
		Database: Database{
			DSNFile:        NewSecretFile("/secrets/db/dsn"),
			MaxConns:       20,
			AcquireTimeout: 2 * time.Second,
		},
		Redis: Redis{Address: "redis:6379", Prefix: "auth1:"},
		AMQP:  AMQP{URLFile: NewSecretFile("/secrets/amqp/url")},
		Retention: Retention{
			ExpiredRegistrations: 168 * time.Hour,
			ClosedChallenges:     720 * time.Hour,
			RevokedSessions:      2160 * time.Hour,
			IdempotencyKeys:      24 * time.Hour,
			PublishedOutbox:      168 * time.Hour,
			AuditClientDetails:   2160 * time.Hour,
		},
		Telemetry: Telemetry{ServiceName: "auth1"},
	}
}
