package config

import (
	"os"
	"path/filepath"
	"testing"

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
