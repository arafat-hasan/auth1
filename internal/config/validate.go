package config

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Validate applies the rules and security floors of TDD-08 §3.1 and returns every problem at once,
// joined with errors.Join and sorted by key path, or nil. The floors and the production-only rules
// are relaxed only when app.environment is development (SDD C-3).
//
// Files are checked to exist and be readable; their contents are not read. Rules about what a file
// holds (such as a keyring's single active key) belong to the packages that parse it.
func (c *Config) Validate() error {
	v := &validator{c: c, dev: c.App.Environment == EnvDevelopment}
	v.required()
	v.files()
	v.ranges()
	v.floors()
	v.productionOnly()
	v.enums()
	v.clients()
	v.identifiers()
	v.smsBudget()
	return joinProblems(v.problems)
}

type validator struct {
	c        *Config
	dev      bool
	problems []*Problem
}

func (v *validator) add(path, format string, args ...any) {
	v.problems = append(v.problems, &Problem{Path: path, Message: fmt.Sprintf(format, args...)})
}

func index(prefix string, i int) string { return prefix + "[" + strconv.Itoa(i) + "]" }

// required checks the values that have no usable default.
func (v *validator) required() {
	c := v.c
	if c.HTTP.Issuer == "" {
		v.add("http.issuer", "required")
	} else if u, err := url.Parse(c.HTTP.Issuer); err != nil || !u.IsAbs() || u.Host == "" {
		v.add("http.issuer", "%q is not an absolute URL", c.HTTP.Issuer)
	}

	if len(c.Clients) == 0 {
		v.add("clients", "at least one client is required")
	}
	ids := map[string]bool{}
	for i, cl := range c.Clients {
		p := index("clients", i)
		switch {
		case cl.ID == "":
			v.add(p+".id", "required")
		case ids[cl.ID]:
			v.add(p+".id", "duplicate client id %q", cl.ID)
		}
		ids[cl.ID] = true
		if cl.Audience == "" {
			v.add(p+".audience", "required")
		}
	}

	if len(c.Identifiers) == 0 {
		v.add("identifiers", "an identifier policy is required")
	}

	for i, sc := range c.ServiceAuth.ClientCredentials.Clients {
		p := index("service_auth.client_credentials.clients", i)
		if sc.ID == "" {
			v.add(p+".id", "required")
		}
		if (sc.JWKSFile == "") == (sc.JWKSURI == "") {
			v.add(p, "set exactly one of jwks_file and jwks_uri")
		}
		if sc.JWKSURI != "" {
			u, ok := webURL(sc.JWKSURI)
			switch {
			case !ok:
				v.add(p+".jwks_uri", "%q is not an absolute http or https URL", sc.JWKSURI)
			case u.Scheme != "https" && !v.dev:
				v.add(p+".jwks_uri", "%q is not an https URL", sc.JWKSURI)
			}
		}
	}
}

// webURL parses raw as an absolute http or https URL with a host and no user information.
func webURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, false
	}
	return u, true
}

// files checks that every configured file exists and can be read.
func (v *validator) files() {
	c := v.c
	for path, f := range map[string]SecretFile{
		"keys.keyring_file":                 c.Keys.KeyringFile,
		"encryption.keyring_file":           c.Encryption.KeyringFile,
		"encryption.blind_index_key_file":   c.Encryption.BlindIndexKeyFile,
		"encryption.mac_key_file":           c.Encryption.MACKeyFile,
		"encryption.device_cookie_key_file": c.Encryption.DeviceCookieKeyFile,
		"passwords.pepper_keyring_file":     c.Passwords.PepperKeyringFile,
		"database.dsn_file":                 c.Database.DSNFile,
		"amqp.url_file":                     c.AMQP.URLFile,
	} {
		v.requiredFile(path, f.Path())
	}
	v.requiredFile("passwords.deny_list_file", c.Passwords.DenyListFile)

	v.optionalFile("redis.password_file", c.Redis.PasswordFile.Path())
	v.optionalFile("bootstrap.emails_file", c.Bootstrap.EmailsFile.Path())

	if c.Delivery.Adapter == DeliveryDirect {
		d := c.Delivery.Direct
		v.optionalFile("delivery.direct.smtp.password_file", d.SMTP.PasswordFile.Path())
		v.optionalFile("delivery.direct.sms.token_file", d.SMS.TokenFile.Path())
		if d.TemplatesDir == "" {
			v.add("delivery.direct.templates_dir", "required with the direct adapter")
		} else if err := checkDir(d.TemplatesDir); err != nil {
			v.add("delivery.direct.templates_dir", "%v", err)
		}
	}
	if c.ServiceAuth.Mesh.Source == MeshSourcePeerCert {
		v.requiredFile("service_auth.mesh.ca_file", c.ServiceAuth.Mesh.CAFile)
	}
	for i, sc := range c.ServiceAuth.ClientCredentials.Clients {
		v.optionalFile(index("service_auth.client_credentials.clients", i)+".jwks_file", sc.JWKSFile)
	}
}

func (v *validator) requiredFile(path, file string) {
	if file == "" {
		v.add(path, "required")
		return
	}
	v.optionalFile(path, file)
}

func (v *validator) optionalFile(path, file string) {
	if file == "" {
		return
	}
	if err := checkFile(file); err != nil {
		v.add(path, "%v", err)
	}
}

// ranges refuses a negative number anywhere, and zero for the settings whose floor is only an
// upper bound, where zero would mean an unusable lifetime or no attempts at all. These apply in
// every environment.
func (v *validator) ranges() {
	for path, val := range flatten(*v.c) {
		var negative bool
		switch n := val.(type) {
		case time.Duration:
			negative = n < 0
		case ByteSize:
			negative = n < 0
		case int:
			negative = n < 0
		}
		if negative {
			v.add(path, "%v must not be negative", val)
		}
	}
	c := v.c
	for path, d := range map[string]time.Duration{
		"tokens.access_ttl":                         c.Tokens.AccessTTL,
		"links.reset_ttl":                           c.Links.ResetTTL,
		"service_auth.client_credentials.token_ttl": c.ServiceAuth.ClientCredentials.TokenTTL,
	} {
		if d == 0 {
			v.add(path, "must be above 0")
		}
	}
	if c.OTP.MaxAttempts == 0 {
		v.add("otp.max_attempts", "must be above 0")
	}
}

// floors applies the security floors of TDD-08 §3.1 outside development.
func (v *validator) floors() {
	if v.dev {
		return
	}
	c := v.c
	atMost := func(path string, got, limit time.Duration) {
		if got > limit {
			v.add(path, "%s is above the floor of at most %s", got, limit)
		}
	}
	// A negative value is the range check's to report.
	atLeast := func(path string, got, limit int) {
		if got >= 0 && got < limit {
			v.add(path, "%d is below the floor of at least %d", got, limit)
		}
	}
	atMost("tokens.access_ttl", c.Tokens.AccessTTL, 15*time.Minute)
	atMost("tokens.refresh_reuse_grace", c.Tokens.RefreshReuseGrace, 60*time.Second)
	atLeast("passwords.min_length", c.Passwords.MinLength, 8)
	atLeast("passwords.max_length", c.Passwords.MaxLength, 64)
	if m := c.Passwords.Argon2.Memory; m >= 0 && m < 19*MiB {
		v.add("passwords.argon2.memory", "%s is below the floor of at least %s", c.Passwords.Argon2.Memory, 19*MiB)
	}
	atLeast("passwords.argon2.iterations", c.Passwords.Argon2.Iterations, 2)
	atLeast("otp.length", c.OTP.Length, 6)
	if c.OTP.MaxAttempts > 5 {
		v.add("otp.max_attempts", "%d is above the floor of at most 5", c.OTP.MaxAttempts)
	}
	if c.MFA.TOTP.SkewSteps > 2 {
		v.add("mfa.totp.skew_steps", "%d is above the floor of at most 2", c.MFA.TOTP.SkewSteps)
	}
	atMost("links.reset_ttl", c.Links.ResetTTL, 2*time.Hour)
	atMost("service_auth.client_credentials.token_ttl", c.ServiceAuth.ClientCredentials.TokenTTL, 15*time.Minute)
}

// productionOnly applies the rules that development relaxes, other than the floors and the
// http origins and JWKS URIs it also allows.
func (v *validator) productionOnly() {
	if v.dev {
		return
	}
	c := v.c
	if c.Delivery.Adapter == DeliveryCapture {
		v.add("delivery.adapter", "capture is for development only")
	}
	if c.ServiceAuth.Mode == "" {
		v.add("service_auth.mode", "required outside development")
	}
}

// oneOf reports a value outside its set. An empty value is allowed only when allowEmpty is set.
func oneOf[T ~string](v *validator, path string, got T, allowEmpty bool, want ...T) {
	if (got == "" && allowEmpty) || slices.Contains(want, got) {
		return
	}
	names := make([]string, len(want))
	for i, w := range want {
		names[i] = string(w)
	}
	v.add(path, "%q is not one of %s", got, strings.Join(names, ", "))
}

// enums checks every value that must be one of a set. These apply in every environment.
func (v *validator) enums() {
	c := v.c
	oneOf(v, "app.environment", c.App.Environment, false, EnvDevelopment, EnvTest, EnvStaging, EnvProduction)
	oneOf(v, "mfa.totp.label", c.MFA.TOTP.Label, false, TOTPLabelEmail, TOTPLabelDisplayName, TOTPLabelNone)
	oneOf(v, "identifier_changes.confirm_old_email", c.IdentifierChanges.ConfirmOldEmail, false, ConfirmOldRequired, ConfirmOldNotify)
	oneOf(v, "delivery.adapter", c.Delivery.Adapter, false, DeliveryNotification, DeliveryDirect, DeliveryCapture)
	// An empty mode is the production-only rule's to report.
	oneOf(v, "service_auth.mode", c.ServiceAuth.Mode, true, ServiceAuthMesh, ServiceAuthClientCredentials, ServiceAuthBoth)
	oneOf(v, "service_auth.mesh.source", c.ServiceAuth.Mesh.Source, false, MeshSourceHeader, MeshSourcePeerCert)
	oneOf(v, "service_auth.mesh.format", c.ServiceAuth.Mesh.Format, false, MeshFormatXFCC, MeshFormatPlain)

	if m := c.ServiceAuth.Mode; (m == ServiceAuthClientCredentials || m == ServiceAuthBoth) && c.ServiceAuth.ClientCredentials.Audience == "" {
		v.add("service_auth.client_credentials.audience", "required when service_auth.mode is %s", m)
	}
}

// clients checks each client's policy (SDD D-6).
func (v *validator) clients() {
	catalog := v.c.Roles.Catalog
	for i, cl := range v.c.Clients {
		p := index("clients", i)
		oneOf(v, p+".mfa", cl.MFA, false, MFAOptional, MFARequired)
		oneOf(v, p+".refresh_transport", cl.RefreshTransport, false, RefreshCookie, RefreshBody)

		factors := slices.Clone(cl.FirstFactors)
		slices.Sort(factors)
		withOTP := false
		switch {
		case slices.Equal(factors, []Factor{FactorPassword}):
		case slices.Equal(factors, []Factor{FactorOTP, FactorPassword}):
			withOTP = true
		default:
			v.add(p+".first_factors", "%v is not [password] or [password, otp]", cl.FirstFactors)
		}
		// Required with OTP sign-in, and checked whenever it is set.
		oneOf(v, p+".otp_channel", cl.OTPChannel, !withOTP, OTPChannelSMS, OTPChannelEmail)

		// An origin is exactly a scheme and host; http is allowed only in development.
		for j, origin := range cl.Origins {
			op := index(p+".origins", j)
			u, ok := webURL(origin)
			switch {
			case !ok || origin != u.Scheme+"://"+u.Host:
				v.add(op, "%q is not an origin: a scheme and host, with no path", origin)
			case u.Scheme != "https" && !v.dev:
				v.add(op, "%q is not an https origin", origin)
			}
		}

		for j, role := range cl.AllowedRoles {
			if !slices.Contains(catalog, role) {
				v.add(index(p+".allowed_roles", j), "role %q is not in roles.catalog", role)
			}
		}
		for j, role := range cl.DefaultRoles {
			switch {
			case !slices.Contains(catalog, role):
				v.add(index(p+".default_roles", j), "role %q is not in roles.catalog", role)
			case !slices.Contains(cl.AllowedRoles, role):
				v.add(index(p+".default_roles", j), "role %q is not in allowed_roles", role)
			}
		}
	}
}

// identifiers checks the identifier policy's structure. Whether each type exists is checked
// against the identifier-type registry, which this package does not know.
func (v *validator) identifiers() {
	for name, policy := range v.c.Identifiers {
		p := "identifiers." + name
		oneOf(v, p+".verify", policy.Verify, false, VerifyEmailLink, VerifyEmailCode, VerifySMSOTP)
		for i, code := range policy.CallingCodes {
			if !validCallingCode(code) {
				v.add(index(p+".calling_codes", i), "%q is not a calling code: 1 to 3 digits, no leading 0 or +", code)
			}
		}
	}
}

func validCallingCode(code string) bool {
	if len(code) < 1 || len(code) > 3 || code[0] == '0' {
		return false
	}
	return strings.Trim(code, "0123456789") == ""
}

// smsBudget requires an SMS budget when any SMS method is configured.
func (v *validator) smsBudget() {
	if v.c.RateLimits.SMSBudgetPerHour <= 0 && v.c.usesSMS() {
		v.add("rate_limits.sms_budget_per_hour", "must be above 0 when an SMS method is configured")
	}
}

// usesSMS reports whether any SMS method is configured: an identifier verified by SMS, OTP sign-in
// by SMS, or the SMS step-up of password reset.
func (c *Config) usesSMS() bool {
	for _, policy := range c.Identifiers {
		if policy.Verify == VerifySMSOTP {
			return true
		}
	}
	for _, cl := range c.Clients {
		if slices.Contains(cl.FirstFactors, FactorOTP) && cl.OTPChannel == OTPChannelSMS {
			return true
		}
	}
	return c.Recovery.SMSStepUp
}
