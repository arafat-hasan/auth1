package config

import "time"

// Config is the whole configuration (TDD-08 §3). Keys are the koanf tags. Secrets are never values:
// SecretFile fields name the files that hold them.
type Config struct {
	App               App                         `koanf:"app"`
	HTTP              HTTP                        `koanf:"http"`
	Keys              Keys                        `koanf:"keys"`
	Encryption        Encryption                  `koanf:"encryption"`
	Tokens            Tokens                      `koanf:"tokens"`
	Clients           []Client                    `koanf:"clients"`
	Identifiers       map[string]IdentifierPolicy `koanf:"identifiers"`
	Passwords         Passwords                   `koanf:"passwords"`
	MFA               MFA                         `koanf:"mfa"`
	OTP               OTP                         `koanf:"otp"`
	Links             Links                       `koanf:"links"`
	Flows             Flows                       `koanf:"flows"`
	Recovery          Recovery                    `koanf:"recovery"`
	IdentifierChanges IdentifierChanges           `koanf:"identifier_changes"`
	Roles             Roles                       `koanf:"roles"`
	Bootstrap         Bootstrap                   `koanf:"bootstrap"`
	Statuses          Statuses                    `koanf:"statuses"`
	Locales           Locales                     `koanf:"locales"`
	Delivery          Delivery                    `koanf:"delivery"`
	ServiceAuth       ServiceAuth                 `koanf:"service_auth"`
	RateLimits        RateLimits                  `koanf:"rate_limits"`
	Events            Events                      `koanf:"events"`
	Outbox            Outbox                      `koanf:"outbox"`
	Database          Database                    `koanf:"database"`
	Redis             Redis                       `koanf:"redis"`
	AMQP              AMQP                        `koanf:"amqp"`
	Retention         Retention                   `koanf:"retention"`
	Telemetry         Telemetry                   `koanf:"telemetry"`
}

// App is the app section.
type App struct {
	Environment Environment `koanf:"environment"`
}

// HTTP is the http section.
type HTTP struct {
	Listen         string   `koanf:"listen"`
	BasePath       string   `koanf:"base_path"`
	Issuer         string   `koanf:"issuer"`
	TrustedProxies []string `koanf:"trusted_proxies"`
}

// Keys is the keys section: the signing keyring.
type Keys struct {
	KeyringFile         SecretFile    `koanf:"keyring_file"`
	MinPublishBeforeUse time.Duration `koanf:"min_publish_before_use"`
}

// Encryption is the encryption section: field encryption and MAC keys.
type Encryption struct {
	KeyringFile         SecretFile `koanf:"keyring_file"`
	BlindIndexKeyFile   SecretFile `koanf:"blind_index_key_file"`
	MACKeyFile          SecretFile `koanf:"mac_key_file"`
	DeviceCookieKeyFile SecretFile `koanf:"device_cookie_key_file"`
}

// Tokens is the tokens section.
type Tokens struct {
	AccessTTL          time.Duration `koanf:"access_ttl"`
	SelfAudience       string        `koanf:"self_audience"` // empty: the issuer
	RefreshIdleTTL     time.Duration `koanf:"refresh_idle_ttl"`
	RefreshAbsoluteTTL time.Duration `koanf:"refresh_absolute_ttl"`
	RefreshReuseGrace  time.Duration `koanf:"refresh_reuse_grace"`
}

// Client is one entry of clients (SDD D-6).
type Client struct {
	ID               string           `koanf:"id"`
	Audience         string           `koanf:"audience"`
	AllowedRoles     []string         `koanf:"allowed_roles"`
	DefaultRoles     []string         `koanf:"default_roles"`
	FirstFactors     []Factor         `koanf:"first_factors"`
	MFA              MFAPolicy        `koanf:"mfa"`
	OTPChannel       OTPChannel       `koanf:"otp_channel"`
	SelfRegistration bool             `koanf:"self_registration"`
	RefreshTransport RefreshTransport `koanf:"refresh_transport"`
	Origins          []string         `koanf:"origins"`
	LinkBaseURL      string           `koanf:"link_base_url"`
}

// IdentifierPolicy is the policy of one identifier type, keyed by type name in identifiers.
type IdentifierPolicy struct {
	Required     bool         `koanf:"required"`
	Verify       VerifyMethod `koanf:"verify"`
	SignIn       bool         `koanf:"sign_in"`
	CallingCodes []string     `koanf:"calling_codes"`
}

// Passwords is the passwords section (SDD D-7).
type Passwords struct {
	MinLength         int        `koanf:"min_length"`
	MaxLength         int        `koanf:"max_length"`
	DenyListFile      string     `koanf:"deny_list_file"`
	PepperKeyringFile SecretFile `koanf:"pepper_keyring_file"`
	Argon2            Argon2     `koanf:"argon2"`
}

// Argon2 holds the Argon2id parameters and the hashing semaphore.
type Argon2 struct {
	Memory        ByteSize      `koanf:"memory"`
	Iterations    int           `koanf:"iterations"`
	Parallelism   int           `koanf:"parallelism"`
	MaxConcurrent int           `koanf:"max_concurrent"`
	QueueTimeout  time.Duration `koanf:"queue_timeout"`
}

// MFA is the mfa section (SDD D-8).
type MFA struct {
	TOTP            TOTP          `koanf:"totp"`
	RecoveryCodes   int           `koanf:"recovery_codes"`
	AttemptsPerFlow int           `koanf:"attempts_per_flow"`
	SignInFlowTTL   time.Duration `koanf:"sign_in_flow_ttl"`
}

// TOTP holds the TOTP settings.
type TOTP struct {
	Issuer    string    `koanf:"issuer"`
	Label     TOTPLabel `koanf:"label"`
	SkewSteps int       `koanf:"skew_steps"`
}

// OTP is the otp section: one-time codes sent by SMS or email.
type OTP struct {
	Length          int           `koanf:"length"`
	TTL             time.Duration `koanf:"ttl"`
	MaxAttempts     int           `koanf:"max_attempts"`
	Cooldown        time.Duration `koanf:"cooldown"`
	ResendAfter     time.Duration `koanf:"resend_after"`
	MaxSendsPerHour int           `koanf:"max_sends_per_hour"`
}

// Links is the links section: lifetimes of emailed links.
type Links struct {
	VerificationTTL time.Duration `koanf:"verification_ttl"`
	ResetTTL        time.Duration `koanf:"reset_ttl"`
	InvitationTTL   time.Duration `koanf:"invitation_ttl"`
}

// Flows is the flows section.
type Flows struct {
	PendingRegistrationTTL time.Duration `koanf:"pending_registration_ttl"`
}

// Recovery is the recovery section (SDD D-10).
type Recovery struct {
	Via       string `koanf:"via"`
	SMSStepUp bool   `koanf:"sms_step_up"`
}

// IdentifierChanges is the identifier_changes section (SDD D-11).
type IdentifierChanges struct {
	ConfirmOldEmail ConfirmOld `koanf:"confirm_old_email"`
}

// Roles is the roles section.
type Roles struct {
	Catalog                 []string `koanf:"catalog"`
	RevokeSessionsOnRemoval bool     `koanf:"revoke_sessions_on_removal"`
}

// Bootstrap is the bootstrap section.
type Bootstrap struct {
	Roles      []string   `koanf:"roles"`
	EmailsFile SecretFile `koanf:"emails_file"`
}

// Statuses is the statuses section.
type Statuses struct {
	ReasonCodes      []string `koanf:"reason_codes"`
	RestrictedSignIn bool     `koanf:"restricted_sign_in"`
}

// Locales is the locales section.
type Locales struct {
	Allowed []string `koanf:"allowed"`
	Default string   `koanf:"default"`
}

// Delivery is the delivery section.
type Delivery struct {
	Adapter              DeliveryAdapter   `koanf:"adapter"`
	Notification         Notification      `koanf:"notification"`
	Direct               Direct            `koanf:"direct"`
	RetiredAddressWindow time.Duration     `koanf:"retired_address_window"`
	Notices              Notices           `koanf:"notices"`
	Types                map[string]string `koanf:"types"` // purpose -> message type
}

// Notification configures the notification-service adapter.
type Notification struct {
	RequestURL string `koanf:"request_url"`
}

// Direct configures the direct SMTP and SMS adapter.
type Direct struct {
	SMTP         SMTP   `koanf:"smtp"`
	SMS          SMS    `koanf:"sms"`
	TemplatesDir string `koanf:"templates_dir"`
}

// SMTP is the direct adapter's mail server.
type SMTP struct {
	Host         string     `koanf:"host"`
	Port         int        `koanf:"port"`
	From         string     `koanf:"from"`
	Username     string     `koanf:"username"`
	PasswordFile SecretFile `koanf:"password_file"`
}

// SMS is the direct adapter's SMS gateway.
type SMS struct {
	URL       string     `koanf:"url"`
	Sender    string     `koanf:"sender"`
	TokenFile SecretFile `koanf:"token_file"`
}

// Notices switches optional notices on.
type Notices struct {
	NewSignIn bool `koanf:"new_sign_in"`
}

// ServiceAuth is the service_auth section.
type ServiceAuth struct {
	Mode              ServiceAuthMode   `koanf:"mode"`
	Mesh              Mesh              `koanf:"mesh"`
	ClientCredentials ClientCredentials `koanf:"client_credentials"`
	Callers           []Caller          `koanf:"callers"`
}

// Mesh configures workload identity from a service mesh.
type Mesh struct {
	Source              MeshSource `koanf:"source"`
	Header              string     `koanf:"header"`
	Format              MeshFormat `koanf:"format"`
	TrustedSidecarCIDRs []string   `koanf:"trusted_sidecar_cidrs"`
	CAFile              string     `koanf:"ca_file"` // peer_cert only
}

// ClientCredentials configures the client-credentials grant for services.
type ClientCredentials struct {
	Audience string          `koanf:"audience"`
	TokenTTL time.Duration   `koanf:"token_ttl"`
	Clients  []ServiceClient `koanf:"clients"`
}

// ServiceClient is a service that signs client assertions with keys from a JWKS.
type ServiceClient struct {
	ID       string `koanf:"id"`
	JWKSFile string `koanf:"jwks_file"`
	JWKSURI  string `koanf:"jwks_uri"`
}

// Caller grants scopes to a service identity.
type Caller struct {
	Identity string   `koanf:"identity"`
	Scopes   []string `koanf:"scopes"`
}

// RateLimit is a limit per window.
type RateLimit struct {
	Limit  int           `koanf:"limit"`
	Window time.Duration `koanf:"window"`
}

// Backoff is a delay that starts after threshold failures and grows to a maximum.
type Backoff struct {
	Threshold  int           `koanf:"threshold"`
	FirstDelay time.Duration `koanf:"first_delay"`
	MaxDelay   time.Duration `koanf:"max_delay"`
}

// RateLimits is the rate_limits section (TDD-07).
type RateLimits struct {
	GlobalIP         RateLimit `koanf:"global_ip"`
	SignInIP         RateLimit `koanf:"sign_in_ip"`
	RegistrationIP   RateLimit `koanf:"registration_ip"`
	ResetIP          RateLimit `koanf:"reset_ip"`
	ResetAccount     RateLimit `koanf:"reset_account"`
	SendIP           RateLimit `koanf:"send_ip"`
	VerifyIP         RateLimit `koanf:"verify_ip"`
	ResumeIP         RateLimit `koanf:"resume_ip"`
	TokenClient      RateLimit `koanf:"token_client"`
	FactorFailures   RateLimit `koanf:"factor_failures"`
	SignInFailures   Backoff   `koanf:"sign_in_failures"`
	SMSBudgetPerHour int       `koanf:"sms_budget_per_hour"`
}

// Events is the events section.
type Events struct {
	Exchange string `koanf:"exchange"`
	Source   string `koanf:"source"`
}

// Outbox is the outbox section.
type Outbox struct {
	PollInterval   time.Duration `koanf:"poll_interval"`
	BatchSize      int           `koanf:"batch_size"`
	MaxAttempts    int           `koanf:"max_attempts"`
	PublishTimeout time.Duration `koanf:"publish_timeout"`
}

// Database is the database section.
type Database struct {
	DSNFile        SecretFile    `koanf:"dsn_file"`
	MaxConns       int           `koanf:"max_conns"`
	AcquireTimeout time.Duration `koanf:"acquire_timeout"`
}

// Redis is the redis section.
type Redis struct {
	Address      string     `koanf:"address"`
	Prefix       string     `koanf:"prefix"`
	PasswordFile SecretFile `koanf:"password_file"`
}

// AMQP is the amqp section.
type AMQP struct {
	URLFile SecretFile `koanf:"url_file"`
}

// Retention is the retention section: how long closed records are kept.
type Retention struct {
	ExpiredRegistrations time.Duration `koanf:"expired_registrations"`
	ClosedChallenges     time.Duration `koanf:"closed_challenges"`
	RevokedSessions      time.Duration `koanf:"revoked_sessions"`
	IdempotencyKeys      time.Duration `koanf:"idempotency_keys"`
	PublishedOutbox      time.Duration `koanf:"published_outbox"`
	AuditClientDetails   time.Duration `koanf:"audit_client_details"`
}

// Telemetry is the telemetry section.
type Telemetry struct {
	OTLPEndpoint  string `koanf:"otlp_endpoint"` // collector base URL, spans to /v1/traces; empty: no trace export
	ServiceName   string `koanf:"service_name"`
	MetricsListen string `koanf:"metrics_listen"` // internal listener for /metrics
}
