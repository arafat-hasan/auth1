package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// validConfig returns a production configuration that passes Validate, with every file it names
// created under dir.
func validConfig(t *testing.T, dir string) Config {
	t.Helper()
	file := func(name string) string {
		path := filepath.Join(dir, name)
		writeFile(t, path, "placeholder", 0o600)
		return path
	}
	c := Default()
	c.HTTP.Issuer = "https://id.example.test"
	c.Keys.KeyringFile = NewSecretFile(file("signing.yaml"))
	c.Encryption.KeyringFile = NewSecretFile(file("fields.yaml"))
	c.Encryption.BlindIndexKeyFile = NewSecretFile(file("bidx.key"))
	c.Encryption.MACKeyFile = NewSecretFile(file("mac.key"))
	c.Encryption.DeviceCookieKeyFile = NewSecretFile(file("device.key"))
	c.Passwords.DenyListFile = file("common-passwords.txt")
	c.Passwords.PepperKeyringFile = NewSecretFile(file("pepper.yaml"))
	c.Bootstrap.EmailsFile = NewSecretFile(file("emails.txt"))
	c.Database.DSNFile = NewSecretFile(file("dsn"))
	c.AMQP.URLFile = NewSecretFile(file("amqp-url"))
	c.Clients = []Client{{
		ID:               "web",
		Audience:         "web",
		AllowedRoles:     []string{"user"},
		DefaultRoles:     []string{"user"},
		FirstFactors:     []Factor{FactorPassword},
		MFA:              MFAOptional,
		SelfRegistration: true,
		RefreshTransport: RefreshCookie,
		Origins:          []string{"https://www.example.test"},
		LinkBaseURL:      "https://www.example.test/account",
	}}
	c.ServiceAuth.Mode = ServiceAuthMesh
	c.RateLimits.SMSBudgetPerHour = 100
	return c
}

// problemPaths validates c and returns the path of each problem.
func problemPaths(t *testing.T, c *Config) []string {
	t.Helper()
	var paths []string
	for _, p := range Problems(c.Validate()) {
		paths = append(paths, p.Path)
	}
	return paths
}

// validateCase changes a valid configuration and expects exactly the problems at want (none
// when want is empty). dir holds the valid configuration's files and is free for new ones.
type validateCase struct {
	name   string
	change func(c *Config, dir string)
	want   []string
}

func runValidateCases(t *testing.T, tests []validateCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			c := validConfig(t, dir)
			tt.change(&c, dir)
			if diff := cmp.Diff(tt.want, problemPaths(t, &c), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("problem paths (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidConfigPasses(t *testing.T) {
	t.Parallel()

	c := validConfig(t, t.TempDir())
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRequired(t *testing.T) {
	t.Parallel()

	missing := func(dir string) string { return filepath.Join(dir, "absent") }
	tests := []validateCase{
		{name: "no issuer", change: func(c *Config, _ string) { c.HTTP.Issuer = "" }, want: []string{"http.issuer"}},
		{name: "relative issuer", change: func(c *Config, _ string) { c.HTTP.Issuer = "/id" }, want: []string{"http.issuer"}},
		{name: "issuer not a URL", change: func(c *Config, _ string) { c.HTTP.Issuer = "https://%zz" }, want: []string{"http.issuer"}},
		{name: "no clients", change: func(c *Config, _ string) { c.Clients = nil }, want: []string{"clients"}},
		{name: "client without id", change: func(c *Config, _ string) { c.Clients[0].ID = "" }, want: []string{"clients[0].id"}},
		{name: "client without audience", change: func(c *Config, _ string) { c.Clients[0].Audience = "" }, want: []string{"clients[0].audience"}},
		{name: "duplicate client id", change: func(c *Config, _ string) {
			c.Clients = append(c.Clients, c.Clients[0])
		}, want: []string{"clients[1].id"}},
		{name: "no identifier policy", change: func(c *Config, _ string) { c.Identifiers = nil }, want: []string{"identifiers"}},

		{name: "bootstrap emails not configured", change: func(c *Config, _ string) { c.Bootstrap.EmailsFile = NewSecretFile("") }},
		{name: "bootstrap emails missing", change: func(c *Config, dir string) {
			c.Bootstrap.EmailsFile = NewSecretFile(missing(dir))
		}, want: []string{"bootstrap.emails_file"}},
		{name: "redis password missing", change: func(c *Config, dir string) {
			c.Redis.PasswordFile = NewSecretFile(missing(dir))
		}, want: []string{"redis.password_file"}},

		{name: "direct delivery", change: func(c *Config, dir string) {
			c.Delivery.Adapter = DeliveryDirect
			c.Delivery.Direct.TemplatesDir = dir
		}},
		{name: "direct delivery without templates", change: func(c *Config, dir string) {
			c.Delivery.Adapter = DeliveryDirect
			c.Delivery.Direct.TemplatesDir = missing(dir)
		}, want: []string{"delivery.direct.templates_dir"}},
		{name: "direct delivery with a file for templates", change: func(c *Config, _ string) {
			c.Delivery.Adapter = DeliveryDirect
			c.Delivery.Direct.TemplatesDir = c.Passwords.DenyListFile
		}, want: []string{"delivery.direct.templates_dir"}},
		{name: "direct delivery SMTP password missing", change: func(c *Config, dir string) {
			c.Delivery.Adapter = DeliveryDirect
			c.Delivery.Direct.TemplatesDir = dir
			c.Delivery.Direct.SMTP.PasswordFile = NewSecretFile(missing(dir))
		}, want: []string{"delivery.direct.smtp.password_file"}},
		{name: "direct delivery SMS token missing", change: func(c *Config, dir string) {
			c.Delivery.Adapter = DeliveryDirect
			c.Delivery.Direct.TemplatesDir = dir
			c.Delivery.Direct.SMS.TokenFile = NewSecretFile(missing(dir))
		}, want: []string{"delivery.direct.sms.token_file"}},
		{name: "templates ignored without direct delivery", change: func(c *Config, dir string) {
			c.Delivery.Direct.TemplatesDir = missing(dir)
		}},

		{name: "peer certificates without a CA", change: func(c *Config, _ string) {
			c.ServiceAuth.Mesh.Source = MeshSourcePeerCert
		}, want: []string{"service_auth.mesh.ca_file"}},
		{name: "peer certificates with a missing CA", change: func(c *Config, dir string) {
			c.ServiceAuth.Mesh.Source = MeshSourcePeerCert
			c.ServiceAuth.Mesh.CAFile = missing(dir)
		}, want: []string{"service_auth.mesh.ca_file"}},

		{name: "service client with a JWKS file", change: func(c *Config, _ string) {
			c.ServiceAuth.ClientCredentials.Clients = []ServiceClient{{ID: "svc", JWKSFile: c.Passwords.DenyListFile}}
		}},
		{name: "service client with a JWKS URI", change: func(c *Config, _ string) {
			c.ServiceAuth.ClientCredentials.Clients = []ServiceClient{{ID: "svc", JWKSURI: "https://svc.example.test/jwks"}}
		}},
		{name: "service client with both", change: func(c *Config, _ string) {
			c.ServiceAuth.ClientCredentials.Clients = []ServiceClient{{ID: "svc", JWKSFile: c.Passwords.DenyListFile, JWKSURI: "https://svc.example.test/jwks"}}
		}, want: []string{"service_auth.client_credentials.clients[0]"}},
		{name: "service client with neither", change: func(c *Config, _ string) {
			c.ServiceAuth.ClientCredentials.Clients = []ServiceClient{{ID: "svc"}}
		}, want: []string{"service_auth.client_credentials.clients[0]"}},
		{name: "service client JWKS file missing", change: func(c *Config, dir string) {
			c.ServiceAuth.ClientCredentials.Clients = []ServiceClient{{ID: "svc", JWKSFile: missing(dir)}}
		}, want: []string{"service_auth.client_credentials.clients[0].jwks_file"}},
		{name: "service client without id", change: func(c *Config, _ string) {
			c.ServiceAuth.ClientCredentials.Clients = []ServiceClient{{JWKSURI: "https://svc.example.test/jwks"}}
		}, want: []string{"service_auth.client_credentials.clients[0].id"}},
	}

	required := map[string]func(c *Config) *SecretFile{
		"keys.keyring_file":                 func(c *Config) *SecretFile { return &c.Keys.KeyringFile },
		"encryption.keyring_file":           func(c *Config) *SecretFile { return &c.Encryption.KeyringFile },
		"encryption.blind_index_key_file":   func(c *Config) *SecretFile { return &c.Encryption.BlindIndexKeyFile },
		"encryption.mac_key_file":           func(c *Config) *SecretFile { return &c.Encryption.MACKeyFile },
		"encryption.device_cookie_key_file": func(c *Config) *SecretFile { return &c.Encryption.DeviceCookieKeyFile },
		"passwords.pepper_keyring_file":     func(c *Config) *SecretFile { return &c.Passwords.PepperKeyringFile },
		"database.dsn_file":                 func(c *Config) *SecretFile { return &c.Database.DSNFile },
		"amqp.url_file":                     func(c *Config) *SecretFile { return &c.AMQP.URLFile },
	}
	for path, field := range required {
		tests = append(tests,
			validateCase{name: path + " empty", change: func(c *Config, _ string) { *field(c) = NewSecretFile("") }, want: []string{path}},
			validateCase{name: path + " missing", change: func(c *Config, dir string) {
				*field(c) = NewSecretFile(missing(dir))
			}, want: []string{path}},
		)
	}
	tests = append(tests,
		validateCase{name: "deny list empty", change: func(c *Config, _ string) { c.Passwords.DenyListFile = "" }, want: []string{"passwords.deny_list_file"}},
		validateCase{name: "deny list a directory", change: func(c *Config, dir string) { c.Passwords.DenyListFile = dir }, want: []string{"passwords.deny_list_file"}},
	)
	runValidateCases(t, tests)
}

func TestValidateAllAtOnce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := validConfig(t, dir)
	c.HTTP.Issuer = ""
	c.Clients[0].Audience = ""
	if err := os.Remove(c.Database.DSNFile.Path()); err != nil {
		t.Fatal(err)
	}
	want := []string{"clients[0].audience", "database.dsn_file", "http.issuer"}
	if diff := cmp.Diff(want, problemPaths(t, &c)); diff != "" {
		t.Errorf("problem paths (-want +got):\n%s", diff)
	}
}

// TestValidateFloors covers every security floor of TDD-08 §3.1: the floor itself passes, one step
// past it is refused outside development, and development relaxes it.
func TestValidateFloors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path        string
		floor, past func(c *Config)
	}{
		{"tokens.access_ttl",
			func(c *Config) { c.Tokens.AccessTTL = 15 * time.Minute },
			func(c *Config) { c.Tokens.AccessTTL = 15*time.Minute + time.Second }},
		{"tokens.refresh_reuse_grace",
			func(c *Config) { c.Tokens.RefreshReuseGrace = 60 * time.Second },
			func(c *Config) { c.Tokens.RefreshReuseGrace = 61 * time.Second }},
		{"passwords.min_length",
			func(c *Config) { c.Passwords.MinLength = 8 },
			func(c *Config) { c.Passwords.MinLength = 7 }},
		{"passwords.max_length",
			func(c *Config) { c.Passwords.MaxLength = 64 },
			func(c *Config) { c.Passwords.MaxLength = 63 }},
		{"passwords.argon2.memory",
			func(c *Config) { c.Passwords.Argon2.Memory = 19 * MiB },
			func(c *Config) { c.Passwords.Argon2.Memory = 19*MiB - KiB }},
		{"passwords.argon2.iterations",
			func(c *Config) { c.Passwords.Argon2.Iterations = 2 },
			func(c *Config) { c.Passwords.Argon2.Iterations = 1 }},
		{"otp.length",
			func(c *Config) { c.OTP.Length = 6 },
			func(c *Config) { c.OTP.Length = 5 }},
		{"otp.max_attempts",
			func(c *Config) { c.OTP.MaxAttempts = 5 },
			func(c *Config) { c.OTP.MaxAttempts = 6 }},
		{"mfa.totp.skew_steps",
			func(c *Config) { c.MFA.TOTP.SkewSteps = 2 },
			func(c *Config) { c.MFA.TOTP.SkewSteps = 3 }},
		{"links.reset_ttl",
			func(c *Config) { c.Links.ResetTTL = 2 * time.Hour },
			func(c *Config) { c.Links.ResetTTL = 2*time.Hour + time.Second }},
		{"service_auth.client_credentials.token_ttl",
			func(c *Config) { c.ServiceAuth.ClientCredentials.TokenTTL = 15 * time.Minute },
			func(c *Config) { c.ServiceAuth.ClientCredentials.TokenTTL = 15*time.Minute + time.Second }},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			for _, run := range []struct {
				name   string
				env    Environment
				change func(c *Config)
				want   []string
			}{
				{"at the floor", EnvProduction, tt.floor, nil},
				{"past the floor", EnvProduction, tt.past, []string{tt.path}},
				{"past the floor in staging", EnvStaging, tt.past, []string{tt.path}},
				{"past the floor in development", EnvDevelopment, tt.past, nil},
			} {
				c := validConfig(t, t.TempDir())
				c.App.Environment = run.env
				run.change(&c)
				if diff := cmp.Diff(run.want, problemPaths(t, &c), cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("%s: problem paths (-want +got):\n%s", run.name, diff)
				}
			}
		})
	}
}

// TestValidateRules covers every other rule: each violation alone is reported at its path, in
// production and, unless the rule is production-only, in development too.
func TestValidateRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		change     func(c *Config)
		want       []string
		devRelaxed bool
	}{
		// Production-only rules (TDD-08 §3.1).
		{name: "capture delivery", change: func(c *Config) { c.Delivery.Adapter = DeliveryCapture },
			want: []string{"delivery.adapter"}, devRelaxed: true},
		{name: "no service auth mode", change: func(c *Config) { c.ServiceAuth.Mode = "" },
			want: []string{"service_auth.mode"}, devRelaxed: true},
		{name: "plain http origin", change: func(c *Config) {
			c.Clients[0].Origins = []string{"https://a.example.test", "http://b.example.test"}
		}, want: []string{"clients[0].origins[1]"}, devRelaxed: true},

		// Origins and JWKS URIs: http only in development.
		{name: "origin with a path", change: func(c *Config) { c.Clients[0].Origins = []string{"https://a.example.test/login"} },
			want: []string{"clients[0].origins[0]"}},
		{name: "origin with a trailing slash", change: func(c *Config) { c.Clients[0].Origins = []string{"https://a.example.test/"} },
			want: []string{"clients[0].origins[0]"}},
		{name: "origin with a query", change: func(c *Config) { c.Clients[0].Origins = []string{"https://a.example.test?x=1"} },
			want: []string{"clients[0].origins[0]"}},
		{name: "origin without a scheme", change: func(c *Config) { c.Clients[0].Origins = []string{"a.example.test"} },
			want: []string{"clients[0].origins[0]"}},
		{name: "origin with a port", change: func(c *Config) { c.Clients[0].Origins = []string{"https://a.example.test:8443"} }},
		{name: "plain http jwks uri", change: func(c *Config) {
			c.ServiceAuth.ClientCredentials.Clients = []ServiceClient{{ID: "svc", JWKSURI: "http://svc.example.test/jwks"}}
		}, want: []string{"service_auth.client_credentials.clients[0].jwks_uri"}, devRelaxed: true},
		{name: "relative jwks uri", change: func(c *Config) {
			c.ServiceAuth.ClientCredentials.Clients = []ServiceClient{{ID: "svc", JWKSURI: "jwks.json"}}
		}, want: []string{"service_auth.client_credentials.clients[0].jwks_uri"}},

		// Ranges, in every environment.
		{name: "negative duration under a floor", change: func(c *Config) { c.Tokens.AccessTTL = -time.Hour },
			want: []string{"tokens.access_ttl"}},
		{name: "negative duration without a floor", change: func(c *Config) { c.RateLimits.GlobalIP.Window = -time.Second },
			want: []string{"rate_limits.global_ip.window"}},
		{name: "negative count", change: func(c *Config) { c.OTP.MaxAttempts = -3 },
			want: []string{"otp.max_attempts"}},
		{name: "negative size", change: func(c *Config) { c.Passwords.Argon2.Memory = -MiB },
			want: []string{"passwords.argon2.memory"}},
		{name: "negative length", change: func(c *Config) { c.Passwords.MinLength = -1 },
			want: []string{"passwords.min_length"}},
		{name: "zero access ttl", change: func(c *Config) { c.Tokens.AccessTTL = 0 },
			want: []string{"tokens.access_ttl"}},
		{name: "zero reset ttl", change: func(c *Config) { c.Links.ResetTTL = 0 },
			want: []string{"links.reset_ttl"}},
		{name: "zero service token ttl", change: func(c *Config) { c.ServiceAuth.ClientCredentials.TokenTTL = 0 },
			want: []string{"service_auth.client_credentials.token_ttl"}},
		{name: "zero otp attempts", change: func(c *Config) { c.OTP.MaxAttempts = 0 },
			want: []string{"otp.max_attempts"}},
		{name: "zero database connections", change: func(c *Config) { c.Database.MaxConns = 0 },
			want: []string{"database.max_conns"}},
		{name: "zero acquire timeout", change: func(c *Config) { c.Database.AcquireTimeout = 0 },
			want: []string{"database.acquire_timeout"}},
		{name: "zero argon2 memory", change: func(c *Config) { c.Passwords.Argon2.Memory = 0 },
			want: []string{"passwords.argon2.memory"}},
		{name: "zero argon2 iterations", change: func(c *Config) { c.Passwords.Argon2.Iterations = 0 },
			want: []string{"passwords.argon2.iterations"}},
		{name: "zero argon2 parallelism", change: func(c *Config) { c.Passwords.Argon2.Parallelism = 0 },
			want: []string{"passwords.argon2.parallelism"}},
		{name: "zero argon2 max concurrent", change: func(c *Config) { c.Passwords.Argon2.MaxConcurrent = 0 },
			want: []string{"passwords.argon2.max_concurrent"}},
		{name: "zero argon2 queue timeout", change: func(c *Config) { c.Passwords.Argon2.QueueTimeout = 0 },
			want: []string{"passwords.argon2.queue_timeout"}},

		// Argon2id bounds a stored hash may carry (TDD-03 §1.3), in every environment.
		{name: "argon2 memory 1GiB", change: func(c *Config) { c.Passwords.Argon2.Memory = GiB }},
		{name: "argon2 memory above 1GiB", change: func(c *Config) { c.Passwords.Argon2.Memory = GiB + KiB },
			want: []string{"passwords.argon2.memory"}},
		{name: "argon2 memory not whole KiB", change: func(c *Config) { c.Passwords.Argon2.Memory = 64*MiB + 1 },
			want: []string{"passwords.argon2.memory"}},
		{name: "argon2 iterations 16", change: func(c *Config) { c.Passwords.Argon2.Iterations = 16 }},
		{name: "argon2 iterations 17", change: func(c *Config) { c.Passwords.Argon2.Iterations = 17 },
			want: []string{"passwords.argon2.iterations"}},
		{name: "argon2 parallelism 16", change: func(c *Config) { c.Passwords.Argon2.Parallelism = 16 }},
		{name: "argon2 parallelism 17", change: func(c *Config) { c.Passwords.Argon2.Parallelism = 17 },
			want: []string{"passwords.argon2.parallelism"}},

		// Roles.
		{name: "allowed role outside the catalog", change: func(c *Config) {
			c.Clients[0].AllowedRoles = []string{"user", "ghost"}
		}, want: []string{"clients[0].allowed_roles[1]"}},
		{name: "default role outside the catalog", change: func(c *Config) {
			c.Clients[0].DefaultRoles = []string{"ghost"}
		}, want: []string{"clients[0].default_roles[0]"}},
		{name: "default role not allowed", change: func(c *Config) {
			c.Clients[0].DefaultRoles = []string{"user", "admin"}
		}, want: []string{"clients[0].default_roles[1]"}},

		// Values that must be one of a set.
		{name: "environment capitalised", change: func(c *Config) { c.App.Environment = "Production" },
			want: []string{"app.environment"}},
		{name: "environment abbreviated", change: func(c *Config) { c.App.Environment = "dev" },
			want: []string{"app.environment"}},
		{name: "client mfa", change: func(c *Config) { c.Clients[0].MFA = "sometimes" },
			want: []string{"clients[0].mfa"}},
		{name: "first factors without password", change: func(c *Config) {
			c.Clients[0].FirstFactors = []Factor{FactorOTP}
			c.Clients[0].OTPChannel = OTPChannelEmail
		}, want: []string{"clients[0].first_factors"}},
		{name: "first factors unknown", change: func(c *Config) {
			c.Clients[0].FirstFactors = []Factor{FactorPassword, "magic"}
		}, want: []string{"clients[0].first_factors"}},
		{name: "first factors empty", change: func(c *Config) { c.Clients[0].FirstFactors = nil },
			want: []string{"clients[0].first_factors"}},
		{name: "otp without a channel", change: func(c *Config) {
			c.Clients[0].FirstFactors = []Factor{FactorPassword, FactorOTP}
		}, want: []string{"clients[0].otp_channel"}},
		{name: "otp with an unknown channel", change: func(c *Config) {
			c.Clients[0].FirstFactors = []Factor{FactorPassword, FactorOTP}
			c.Clients[0].OTPChannel = "pigeon"
		}, want: []string{"clients[0].otp_channel"}},
		{name: "unknown channel without otp", change: func(c *Config) { c.Clients[0].OTPChannel = "smss" },
			want: []string{"clients[0].otp_channel"}},
		{name: "otp by email", change: func(c *Config) {
			c.Clients[0].FirstFactors = []Factor{FactorOTP, FactorPassword}
			c.Clients[0].OTPChannel = OTPChannelEmail
		}},
		{name: "refresh transport", change: func(c *Config) { c.Clients[0].RefreshTransport = "" },
			want: []string{"clients[0].refresh_transport"}},
		{name: "totp label", change: func(c *Config) { c.MFA.TOTP.Label = "phone" },
			want: []string{"mfa.totp.label"}},
		{name: "confirm old email", change: func(c *Config) { c.IdentifierChanges.ConfirmOldEmail = "maybe" },
			want: []string{"identifier_changes.confirm_old_email"}},
		{name: "delivery adapter", change: func(c *Config) { c.Delivery.Adapter = "pigeon" },
			want: []string{"delivery.adapter"}},
		{name: "service auth mode", change: func(c *Config) { c.ServiceAuth.Mode = "trust" },
			want: []string{"service_auth.mode"}},
		{name: "mesh source", change: func(c *Config) { c.ServiceAuth.Mesh.Source = "dns" },
			want: []string{"service_auth.mesh.source"}},
		{name: "mesh format", change: func(c *Config) { c.ServiceAuth.Mesh.Format = "json" },
			want: []string{"service_auth.mesh.format"}},

		// Identifier policy, structurally (the type registry is WP-20's).
		{name: "identifier without verify", change: func(c *Config) { setVerify(c, "phone", "") },
			want: []string{"identifiers.phone.verify"}},
		{name: "identifier with an unknown method", change: func(c *Config) { setVerify(c, "phone", "fax") },
			want: []string{"identifiers.phone.verify"}},
		{name: "calling codes well-formed", change: func(c *Config) { setCallingCodes(c, "1", "44", "880") }},
		{name: "calling code with a plus", change: func(c *Config) { setCallingCodes(c, "44", "+44") },
			want: []string{"identifiers.phone.calling_codes[1]"}},
		{name: "calling code with a leading zero", change: func(c *Config) { setCallingCodes(c, "044") },
			want: []string{"identifiers.phone.calling_codes[0]"}},
		{name: "calling code too long", change: func(c *Config) { setCallingCodes(c, "1234") },
			want: []string{"identifiers.phone.calling_codes[0]"}},

		// SMS budget.
		{name: "no sms method and no budget", change: func(c *Config) {
			delete(c.Identifiers, "phone")
			c.RateLimits.SMSBudgetPerHour = 0
		}},
		{name: "sms identifier and no budget", change: func(c *Config) { c.RateLimits.SMSBudgetPerHour = 0 },
			want: []string{"rate_limits.sms_budget_per_hour"}},
		{name: "sms sign-in and no budget", change: func(c *Config) {
			delete(c.Identifiers, "phone")
			c.RateLimits.SMSBudgetPerHour = 0
			c.Clients[0].FirstFactors = []Factor{FactorPassword, FactorOTP}
			c.Clients[0].OTPChannel = OTPChannelSMS
		}, want: []string{"rate_limits.sms_budget_per_hour"}},
		{name: "sms step-up and no budget", change: func(c *Config) {
			delete(c.Identifiers, "phone")
			c.RateLimits.SMSBudgetPerHour = 0
			c.Recovery.SMSStepUp = true
		}, want: []string{"rate_limits.sms_budget_per_hour"}},

		// Client credentials.
		{name: "client credentials without an audience", change: func(c *Config) {
			c.ServiceAuth.Mode = ServiceAuthClientCredentials
			c.ServiceAuth.ClientCredentials.Audience = ""
		}, want: []string{"service_auth.client_credentials.audience"}},
		{name: "both modes without an audience", change: func(c *Config) {
			c.ServiceAuth.Mode = ServiceAuthBoth
			c.ServiceAuth.ClientCredentials.Audience = ""
		}, want: []string{"service_auth.client_credentials.audience"}},
		{name: "mesh only without an audience", change: func(c *Config) {
			c.ServiceAuth.ClientCredentials.Audience = ""
		}},

		// Telemetry, in every environment.
		{name: "metrics listen without a colon", change: func(c *Config) { c.Telemetry.MetricsListen = "9090" },
			want: []string{"telemetry.metrics_listen"}},
		{name: "metrics listen with a named port", change: func(c *Config) { c.Telemetry.MetricsListen = ":x" },
			want: []string{"telemetry.metrics_listen"}},
		{name: "metrics listen on port 0", change: func(c *Config) { c.Telemetry.MetricsListen = ":0" },
			want: []string{"telemetry.metrics_listen"}},
		{name: "metrics listen above the port range", change: func(c *Config) { c.Telemetry.MetricsListen = ":65536" },
			want: []string{"telemetry.metrics_listen"}},
		{name: "empty metrics listen", change: func(c *Config) { c.Telemetry.MetricsListen = "" },
			want: []string{"telemetry.metrics_listen"}},
		{name: "metrics listen on the http listener", change: func(c *Config) { c.Telemetry.MetricsListen = c.HTTP.Listen },
			want: []string{"telemetry.metrics_listen"}},

		// HTTP listener and base path.
		{name: "http listen without a colon", change: func(c *Config) { c.HTTP.Listen = "8080" },
			want: []string{"http.listen"}},
		{name: "http listen with a named port", change: func(c *Config) { c.HTTP.Listen = ":x" },
			want: []string{"http.listen"}},
		{name: "empty http listen", change: func(c *Config) { c.HTTP.Listen = "" },
			want: []string{"http.listen"}},
		{name: "http listen with a host", change: func(c *Config) { c.HTTP.Listen = "127.0.0.1:8080" }},
		{name: "base path without a leading slash", change: func(c *Config) { c.HTTP.BasePath = "auth" },
			want: []string{"http.base_path"}},
		{name: "base path with a trailing slash", change: func(c *Config) { c.HTTP.BasePath = "/auth/" },
			want: []string{"http.base_path"}},
		{name: "base path of a slash", change: func(c *Config) { c.HTTP.BasePath = "/" },
			want: []string{"http.base_path"}},
		{name: "base path with an empty segment", change: func(c *Config) { c.HTTP.BasePath = "/a//b" },
			want: []string{"http.base_path"}},
		{name: "base path with a parameter", change: func(c *Config) { c.HTTP.BasePath = "/{id}" },
			want: []string{"http.base_path"}},
		{name: "base path with a wildcard", change: func(c *Config) { c.HTTP.BasePath = "/a*" },
			want: []string{"http.base_path"}},
		{name: "base path with a query", change: func(c *Config) { c.HTTP.BasePath = "/a?b" },
			want: []string{"http.base_path"}},
		{name: "base path with a space", change: func(c *Config) { c.HTTP.BasePath = "/a b" },
			want: []string{"http.base_path"}},
		{name: "base path with a dot segment", change: func(c *Config) { c.HTTP.BasePath = "/a/.." },
			want: []string{"http.base_path"}},
		{name: "base path of one segment", change: func(c *Config) { c.HTTP.BasePath = "/auth" }},
		{name: "base path of two segments", change: func(c *Config) { c.HTTP.BasePath = "/id/v1" }},
		{name: "metrics listen with an IPv4 host", change: func(c *Config) { c.Telemetry.MetricsListen = "127.0.0.1:9090" }},
		{name: "metrics listen with an IPv6 host", change: func(c *Config) { c.Telemetry.MetricsListen = "[::1]:9090" }},
		{name: "otlp endpoint without a scheme", change: func(c *Config) { c.Telemetry.OTLPEndpoint = "collector:4318" },
			want: []string{"telemetry.otlp_endpoint"}},
		{name: "otlp endpoint with another scheme", change: func(c *Config) { c.Telemetry.OTLPEndpoint = "ftp://c:4318" },
			want: []string{"telemetry.otlp_endpoint"}},
		{name: "relative otlp endpoint", change: func(c *Config) { c.Telemetry.OTLPEndpoint = "/v1/traces" },
			want: []string{"telemetry.otlp_endpoint"}},
		{name: "otlp endpoint with a query", change: func(c *Config) { c.Telemetry.OTLPEndpoint = "http://c:4318?x=1" },
			want: []string{"telemetry.otlp_endpoint"}},
		{name: "otlp endpoint with an empty query", change: func(c *Config) { c.Telemetry.OTLPEndpoint = "http://c:4318?" },
			want: []string{"telemetry.otlp_endpoint"}},
		{name: "otlp endpoint with a fragment", change: func(c *Config) { c.Telemetry.OTLPEndpoint = "http://c:4318#f" },
			want: []string{"telemetry.otlp_endpoint"}},
		{name: "otlp endpoint with a path", change: func(c *Config) { c.Telemetry.OTLPEndpoint = "http://c:4318/otel/" }},
		{name: "http otlp endpoint", change: func(c *Config) { c.Telemetry.OTLPEndpoint = "http://collector:4318" }},
		{name: "https otlp endpoint", change: func(c *Config) { c.Telemetry.OTLPEndpoint = "https://c.example.test:4318" }},
		{name: "empty service name", change: func(c *Config) { c.Telemetry.ServiceName = "" },
			want: []string{"telemetry.service_name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := validConfig(t, t.TempDir())
			tt.change(&c)
			if diff := cmp.Diff(tt.want, problemPaths(t, &c), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("production: problem paths (-want +got):\n%s", diff)
			}

			c = validConfig(t, t.TempDir())
			c.App.Environment = EnvDevelopment
			tt.change(&c)
			want := tt.want
			if tt.devRelaxed {
				want = nil
			}
			if diff := cmp.Diff(want, problemPaths(t, &c), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("development: problem paths (-want +got):\n%s", diff)
			}
		})
	}
}

func setVerify(c *Config, name string, method VerifyMethod) {
	p := c.Identifiers[name]
	p.Verify = method
	c.Identifiers[name] = p
}

func setCallingCodes(c *Config, codes ...string) {
	p := c.Identifiers["phone"]
	p.CallingCodes = codes
	c.Identifiers["phone"] = p
}

// TestT17Production is acceptance test T-17 at unit level: production refuses capture delivery,
// a missing service-auth mode and a setting below a floor; development accepts all three.
func TestT17Production(t *testing.T) {
	t.Parallel()

	changes := map[string]func(c *Config){
		"delivery.adapter":  func(c *Config) { c.Delivery.Adapter = DeliveryCapture },
		"service_auth.mode": func(c *Config) { c.ServiceAuth.Mode = "" },
		"tokens.access_ttl": func(c *Config) { c.Tokens.AccessTTL = time.Hour },
	}
	for path, change := range changes {
		for _, env := range []Environment{EnvProduction, EnvDevelopment} {
			c := validConfig(t, t.TempDir())
			c.App.Environment = env
			change(&c)
			err := c.Validate()
			if env == EnvProduction && (err == nil || problemPaths(t, &c)[0] != path) {
				t.Errorf("production with a bad %s: Validate = %v, want it refused", path, err)
			}
			if env == EnvDevelopment && err != nil {
				t.Errorf("development with a bad %s: Validate = %v, want nil", path, err)
			}
		}
	}
}
